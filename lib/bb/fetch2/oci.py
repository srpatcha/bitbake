"""
BitBake OCI container registry fetcher.

Fetches OCI / Docker container image layers from compliant registries.
Supports content-addressable caching, token-based authentication, mirror
fallback, and hash verification.

URI format:
    oci://<registry>/<repository>:<tag>
    oci://<registry>/<repository>@<digest>
"""

# Copyright (C) 2024 Contributors to the OpenEmbedded project
#
# SPDX-License-Identifier: GPL-2.0-only

import os
import json
import hashlib
import logging
import tarfile
import tempfile
import urllib.request
import urllib.error
import urllib.parse

import bb
from bb.fetch2 import FetchMethod, FetchError, MissingParameterError
from bb.fetch2 import logger, runfetchcmd

# OCI media types
MANIFEST_V2 = "application/vnd.oci.image.manifest.v1+json"
MANIFEST_DOCKER_V2 = "application/vnd.docker.distribution.manifest.v2+json"
LAYER_TAR_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
LAYER_DOCKER_TAR_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"

# Default registry when none is specified
DEFAULT_REGISTRY = "registry-1.docker.io"
DEFAULT_AUTH_URL = "https://auth.docker.io/token"
DEFAULT_AUTH_SERVICE = "registry.docker.io"


class OCI(FetchMethod):
    """Fetch OCI / Docker container image layers from a registry."""

    # -----------------------------------------------------------------
    # FetchMethod interface
    # -----------------------------------------------------------------

    def supports(self, ud, d):
        return ud.type in ("oci",)

    def urldata_init(self, ud, d):
        """Parse the OCI URI into registry, repository, tag/digest."""
        # Expected: oci://registry/repo:tag  or  oci://registry/repo@sha256:...
        host = ud.host or DEFAULT_REGISTRY
        path = ud.path.lstrip("/")

        if "@" in path:
            repo, digest = path.rsplit("@", 1)
            tag = None
        elif ":" in path.rsplit("/", 1)[-1]:
            parts = path.rsplit(":", 1)
            repo = parts[0]
            tag = parts[1]
            digest = None
        else:
            repo = path
            tag = "latest"
            digest = None

        # Docker Hub short names (e.g. "library/alpine")
        if host == DEFAULT_REGISTRY and "/" not in repo:
            repo = "library/" + repo

        ud.registry = host
        ud.repo = repo
        ud.tag = tag
        ud.digest = digest
        ud.localfile = "oci_%s_%s_%s.tar.gz" % (
            repo.replace("/", "_"),
            tag or "none",
            (digest or "latest").replace(":", "_"),
        )

    def download(self, ud, d):
        """Download the OCI image layers and combine into a single tarball."""
        registry_url = "https://%s" % ud.registry
        token = self._authenticate(ud, d)
        manifest = self._fetch_manifest(registry_url, ud, token, d)

        layers = manifest.get("layers", [])
        if not layers:
            raise FetchError("OCI manifest contains no layers for %s" % ud.url)

        dl_dir = d.getVar("DL_DIR") or tempfile.gettempdir()
        cache_dir = os.path.join(dl_dir, "oci-cache", ud.repo.replace("/", "_"))
        bb.utils.mkdirhier(cache_dir)

        layer_paths = []
        for layer in layers:
            digest = layer["digest"]
            size = layer.get("size", 0)
            cached = os.path.join(cache_dir, digest.replace(":", "_"))

            if os.path.exists(cached) and self._verify_hash(cached, digest):
                logger.info("OCI: using cached layer %s", digest)
            else:
                self._download_layer(
                    registry_url, ud, token, digest, cached, size, d
                )
                if not self._verify_hash(cached, digest):
                    os.remove(cached)
                    raise FetchError(
                        "Hash mismatch for layer %s of %s" % (digest, ud.url)
                    )
            layer_paths.append(cached)

        # Combine layers into a single archive.
        target = os.path.join(dl_dir, ud.localfile)
        self._combine_layers(layer_paths, target)
        return True

    def checkstatus(self, fetch, ud, d, try_again=True):
        """Verify that the image manifest is accessible."""
        registry_url = "https://%s" % ud.registry
        token = self._authenticate(ud, d)
        try:
            self._fetch_manifest(registry_url, ud, token, d)
            return True
        except FetchError:
            return False

    # -----------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------

    def _authenticate(self, ud, d):
        """Obtain a Bearer token from the registry's token endpoint."""
        registry_url = "https://%s" % ud.registry

        # Try anonymous access first by probing the manifest.
        try:
            url = "%s/v2/%s/manifests/%s" % (
                registry_url,
                ud.repo,
                ud.tag or ud.digest,
            )
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("Accept", MANIFEST_V2)
            urllib.request.urlopen(req, timeout=30)
            return None  # anonymous access works
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise FetchError("OCI registry error %d for %s" % (exc.code, ud.url))
            www_auth = exc.headers.get("Www-Authenticate", "")

        # Parse the Www-Authenticate header for Bearer realm.
        if "Bearer" not in www_auth:
            # Might be Basic auth – try credentials from netrc / env.
            return self._basic_auth_token(ud, d)

        params = {}
        for part in www_auth.split("Bearer ", 1)[1].split(","):
            key, _, val = part.partition("=")
            params[key.strip()] = val.strip('"')

        realm = params.get("realm", DEFAULT_AUTH_URL)
        service = params.get("service", DEFAULT_AUTH_SERVICE)
        scope = params.get("scope", "repository:%s:pull" % ud.repo)

        token_url = "%s?service=%s&scope=%s" % (
            realm,
            urllib.parse.quote(service),
            urllib.parse.quote(scope),
        )
        try:
            resp = urllib.request.urlopen(token_url, timeout=30)
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("token") or data.get("access_token")
        except Exception as exc:
            raise FetchError("OCI auth failed for %s: %s" % (ud.url, exc))

    def _basic_auth_token(self, ud, d):
        """Return a Basic auth header value from environment variables."""
        user = d.getVar("OCI_REGISTRY_USER")
        passwd = d.getVar("OCI_REGISTRY_PASSWORD")
        if user and passwd:
            import base64

            creds = base64.b64encode(("%s:%s" % (user, passwd)).encode()).decode()
            return "Basic " + creds
        return None

    # -----------------------------------------------------------------
    # Manifest & layer downloads
    # -----------------------------------------------------------------

    def _fetch_manifest(self, registry_url, ud, token, d):
        """Download and return the parsed OCI image manifest."""
        ref = ud.tag or ud.digest
        url = "%s/v2/%s/manifests/%s" % (registry_url, ud.repo, ref)

        req = urllib.request.Request(url)
        req.add_header("Accept", "%s, %s" % (MANIFEST_V2, MANIFEST_DOCKER_V2))
        if token:
            if token.startswith("Basic "):
                req.add_header("Authorization", token)
            else:
                req.add_header("Authorization", "Bearer %s" % token)

        mirrors = (d.getVar("OCI_MIRRORS") or "").split()
        urls_to_try = [url] + [
            "%s/v2/%s/manifests/%s" % (m, ud.repo, ref) for m in mirrors
        ]

        last_err = None
        for try_url in urls_to_try:
            try:
                req_copy = urllib.request.Request(try_url)
                for hdr, val in req.header_items():
                    req_copy.add_header(hdr, val)
                resp = urllib.request.urlopen(req_copy, timeout=60)
                return json.loads(resp.read().decode("utf-8"))
            except Exception as exc:
                last_err = exc
                logger.warning("OCI: manifest fetch failed from %s: %s", try_url, exc)

        raise FetchError(
            "Unable to fetch OCI manifest for %s: %s" % (ud.url, last_err)
        )

    def _download_layer(self, registry_url, ud, token, digest, dest, size, d):
        """Download a single layer blob and write it to *dest*."""
        url = "%s/v2/%s/blobs/%s" % (registry_url, ud.repo, digest)
        req = urllib.request.Request(url)
        if token:
            if token.startswith("Basic "):
                req.add_header("Authorization", token)
            else:
                req.add_header("Authorization", "Bearer %s" % token)

        logger.info("OCI: downloading layer %s (%d bytes)", digest, size)

        tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(dest))
        try:
            resp = urllib.request.urlopen(req, timeout=300)
            with os.fdopen(tmp_fd, "wb") as out:
                while True:
                    chunk = resp.read(1024 * 1024)  # 1 MiB
                    if not chunk:
                        break
                    out.write(chunk)
            os.rename(tmp_path, dest)
        except BaseException:
            # Clean up partial download.
            try:
                os.close(tmp_fd)
            except OSError:
                pass
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    # -----------------------------------------------------------------
    # Hash verification
    # -----------------------------------------------------------------

    @staticmethod
    def _verify_hash(filepath, digest):
        """Verify *filepath* matches the OCI digest (``algo:hex``)."""
        if ":" not in digest:
            return True  # No algorithm specified – skip.
        algo, expected = digest.split(":", 1)
        h = hashlib.new(algo)
        with open(filepath, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        actual = h.hexdigest()
        if actual != expected:
            logger.warning(
                "OCI: hash mismatch for %s: expected %s, got %s",
                filepath,
                expected,
                actual,
            )
            return False
        return True

    # -----------------------------------------------------------------
    # Layer combination
    # -----------------------------------------------------------------

    @staticmethod
    def _combine_layers(layer_paths, target):
        """Combine downloaded layer blobs into a single tarball."""
        tmp_path = target + ".tmp"
        try:
            with tarfile.open(tmp_path, "w:gz") as tar:
                for idx, lp in enumerate(layer_paths):
                    arcname = "layer_%03d.tar.gz" % idx
                    tar.add(lp, arcname=arcname)
            os.rename(tmp_path, target)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise
