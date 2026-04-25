#
# BitBake Tests for the OCI container registry fetcher (fetch2/oci.py)
#
# Copyright (C) 2024 Contributors to the OpenEmbedded project
#
# SPDX-License-Identifier: GPL-2.0-only
#

import hashlib
import json
import os
import tarfile
import tempfile
import unittest
import unittest.mock

import bb
from bb.fetch2.oci import OCI, MANIFEST_V2


class FakeUrlData:
    """Minimal stand-in for the URLData object passed by bb.fetch2."""

    def __init__(self, registry="registry.example.com", repo="library/alpine",
                 tag="latest", digest=None):
        self.type = "oci"
        self.host = registry
        self.path = "/%s:%s" % (repo, tag) if tag else "/%s@%s" % (repo, digest)
        self.url = "oci://%s/%s:%s" % (registry, repo, tag or "latest")
        self.parm = {}
        # These will be filled by urldata_init:
        self.registry = None
        self.repo = None
        self.tag = None
        self.digest = None
        self.localfile = None


class FakeData:
    """Minimal stand-in for the BitBake DataSmart dict."""

    def __init__(self, values=None):
        self._values = values or {}

    def getVar(self, key):
        return self._values.get(key)


class TestOCISupports(unittest.TestCase):
    """Test the supports() method."""

    def setUp(self):
        self.fetcher = OCI()

    def test_supports_oci_type(self):
        ud = FakeUrlData()
        self.assertTrue(self.fetcher.supports(ud, FakeData()))

    def test_rejects_http_type(self):
        ud = FakeUrlData()
        ud.type = "http"
        self.assertFalse(self.fetcher.supports(ud, FakeData()))

    def test_rejects_git_type(self):
        ud = FakeUrlData()
        ud.type = "git"
        self.assertFalse(self.fetcher.supports(ud, FakeData()))


class TestOCIUrldataInit(unittest.TestCase):
    """Test URI parsing in urldata_init()."""

    def setUp(self):
        self.fetcher = OCI()

    def test_parse_tag(self):
        ud = FakeUrlData(repo="myrepo/image", tag="v1.0")
        self.fetcher.urldata_init(ud, FakeData())
        self.assertEqual(ud.registry, "registry.example.com")
        self.assertEqual(ud.repo, "myrepo/image")
        self.assertEqual(ud.tag, "v1.0")
        self.assertIsNone(ud.digest)

    def test_parse_digest(self):
        ud = FakeUrlData()
        ud.host = "ghcr.io"
        ud.path = "/myorg/app@sha256:abcdef1234567890"
        self.fetcher.urldata_init(ud, FakeData())
        self.assertEqual(ud.registry, "ghcr.io")
        self.assertEqual(ud.repo, "myorg/app")
        self.assertIsNone(ud.tag)
        self.assertEqual(ud.digest, "sha256:abcdef1234567890")

    def test_default_tag_latest(self):
        ud = FakeUrlData()
        ud.path = "/myrepo/image"  # no tag, no digest
        self.fetcher.urldata_init(ud, FakeData())
        self.assertEqual(ud.tag, "latest")

    def test_dockerhub_short_name(self):
        ud = FakeUrlData()
        ud.host = "registry-1.docker.io"
        ud.path = "/alpine:3.18"
        self.fetcher.urldata_init(ud, FakeData())
        self.assertEqual(ud.repo, "library/alpine")
        self.assertEqual(ud.tag, "3.18")

    def test_localfile_format(self):
        ud = FakeUrlData(repo="ns/img", tag="latest")
        self.fetcher.urldata_init(ud, FakeData())
        self.assertIn("ns_img", ud.localfile)
        self.assertTrue(ud.localfile.endswith(".tar.gz"))


class TestOCIVerifyHash(unittest.TestCase):
    """Test the static _verify_hash method."""

    def test_valid_sha256(self):
        content = b"hello world\n"
        digest_hex = hashlib.sha256(content).hexdigest()
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            tmp.flush()
            path = tmp.name
        try:
            self.assertTrue(OCI._verify_hash(path, "sha256:" + digest_hex))
        finally:
            os.unlink(path)

    def test_invalid_sha256(self):
        content = b"hello world\n"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            tmp.flush()
            path = tmp.name
        try:
            self.assertFalse(OCI._verify_hash(path, "sha256:0000bad"))
        finally:
            os.unlink(path)

    def test_no_algorithm_skips(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"data")
            tmp.flush()
            path = tmp.name
        try:
            self.assertTrue(OCI._verify_hash(path, "nodash"))
        finally:
            os.unlink(path)


class TestOCICombineLayers(unittest.TestCase):
    """Test the _combine_layers helper."""

    def test_creates_tarball(self):
        layers = []
        for i in range(3):
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz")
            tmp.write(b"layer-%d-data" % i)
            tmp.flush()
            tmp.close()
            layers.append(tmp.name)

        target = tempfile.mktemp(suffix=".tar.gz")
        try:
            OCI._combine_layers(layers, target)
            self.assertTrue(os.path.exists(target))
            with tarfile.open(target, "r:gz") as tar:
                names = tar.getnames()
                self.assertEqual(len(names), 3)
                for name in names:
                    self.assertTrue(name.startswith("layer_"))
        finally:
            for lp in layers:
                os.unlink(lp)
            if os.path.exists(target):
                os.unlink(target)

    def test_empty_layers_creates_empty_tar(self):
        target = tempfile.mktemp(suffix=".tar.gz")
        try:
            OCI._combine_layers([], target)
            self.assertTrue(os.path.exists(target))
            with tarfile.open(target, "r:gz") as tar:
                self.assertEqual(len(tar.getnames()), 0)
        finally:
            if os.path.exists(target):
                os.unlink(target)


class TestOCIBasicAuth(unittest.TestCase):
    """Test _basic_auth_token helper."""

    def test_returns_none_without_creds(self):
        fetcher = OCI()
        ud = FakeUrlData()
        self.assertIsNone(fetcher._basic_auth_token(ud, FakeData()))

    def test_returns_basic_header_with_creds(self):
        fetcher = OCI()
        ud = FakeUrlData()
        d = FakeData({"OCI_REGISTRY_USER": "user", "OCI_REGISTRY_PASSWORD": "pass"})
        result = fetcher._basic_auth_token(ud, d)
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("Basic "))
