"""Regression tests for strict alt-chain policy, module origins and cache claims."""
from dataclasses import replace
from pathlib import Path
import sys

import pytest

BASE = Path(__file__).resolve().parents[1]
ROOT = BASE if (BASE / "tools/native.py").is_file() else BASE.parent
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(ROOT))

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tls.config import HybridTLSConfig
from tls.credentials import ServerCredentials
from tls.errors import BackendUnavailableError, HandshakeError
from tls.handshake.connection import HybridConnection, load_trusted_root
from tls.pki import build_test_chain
from tls.pq.slhdsa_sm3 import PROJECT_ROOT, SlhDsaSm3


def test_pinned_alt_algorithm_cannot_be_downgraded_to_classical_chain():
    config = HybridTLSConfig(x509=True, pq_signer="ml-dsa-44", alt_chain="ml-dsa-44",
                             require_alt_chain=False)
    assert config.require_alt_chain is True
    credentials = ServerCredentials(replace(config, alt_chain=None, require_alt_chain=False))
    root = x509.load_der_x509_certificate(credentials.chain.root_der)
    with pytest.raises(HandshakeError) as error:
        HybridConnection.run(config, credentials=credentials, trusted_root=root)
    assert error.value.step == "certificate_alt"


@pytest.mark.parametrize("field,value", [
    ("pq_enabled", "false"), ("x509", 1), ("require_alt_chain", 0),
    ("alt_require_native", "false"), ("alt_force_python", 1),
    ("alt_backend", 2.0), ("alt_backend", True), ("alt_threads", True),
])
def test_config_policy_rejects_coercible_wrong_types(field, value):
    kwargs = {"x509": True, "alt_fixture": "fixture", field: value}
    with pytest.raises(ValueError):
        HybridTLSConfig(**kwargs)


def test_trusted_root_accepts_der_pem_bytes_and_paths(tmp_path):
    chain = build_test_chain()
    root = x509.load_der_x509_certificate(chain.root_der)
    pem = root.public_bytes(serialization.Encoding.PEM)
    path = tmp_path / "root.pem"
    path.write_bytes(pem)
    for value in (chain.root_der, pem, path):
        loaded = load_trusted_root(value)
        assert loaded.public_bytes(serialization.Encoding.DER) == chain.root_der


def test_slhdsa_adapter_resolves_its_own_tree_without_sys_path_cross_talk():
    assert (PROJECT_ROOT / "tools/native.py").is_file()
    reference = SlhDsaSm3._local_module("reference/__init__.py", "reference")
    native = SlhDsaSm3._local_module("tools/native.py", "native")
    assert Path(reference.__file__).resolve() == (PROJECT_ROOT / "reference/__init__.py").resolve()
    assert Path(native.__file__).resolve() == (PROJECT_ROOT / "tools/native.py").resolve()


class FakeNative:
    library_path = "fake-native"
    backend = 2

    def __init__(self):
        self.cache_builds = 0
        self.cache_loads = 0
        self.sign_calls = 0
        self.closed = False

    def bind_key(self, secret):
        self.secret = bytes(secret)

    def set_cache_level(self, level):
        self.level = level

    def cache_build(self, secret, level):
        self.cache_builds += 1

    def cache_save(self, path):
        self.saved = path

    def cache_load(self, path, public):
        self.cache_loads += 1
        assert bytes(public) == self.secret[32:64]

    def sign(self, message, secret, context=b""):
        self.sign_calls += 1
        return b"signature"

    def close(self):
        self.closed = True


def _signer_with_fake_native(monkeypatch):
    signer = SlhDsaSm3()
    native = FakeNative()
    monkeypatch.setattr(signer, "_native", lambda: native)
    return signer, native


def test_binding_without_cache_does_not_satisfy_require_cache(monkeypatch):
    signer, native = _signer_with_fake_native(monkeypatch)
    secret = b"s" * 32 + b"p" * 32
    signer.bind_signing_context(secret)
    with pytest.raises(BackendUnavailableError, match="not a cache"):
        signer.sign(secret, b"message", require_cache=True)
    assert native.sign_calls == 0
    assert signer.last_cache["mode"] == "bound"


def test_explicit_cache_build_enables_cached_signing(monkeypatch, tmp_path):
    signer, native = _signer_with_fake_native(monkeypatch)
    secret = b"s" * 32 + b"p" * 32
    signer.bind_signing_context(secret, public_key=secret[32:64])
    signer.cache_build(secret, 6, save_path=tmp_path / "cache.bin", public_key=secret[32:64])
    assert signer.sign(secret, b"message", require_cache=True) == b"signature"
    assert native.cache_builds == 1 and native.sign_calls == 1
    assert signer.last_signing["cache_ready"] is True


def test_cache_load_rejects_wrong_public_key_and_nul_path(monkeypatch):
    signer, native = _signer_with_fake_native(monkeypatch)
    secret = b"s" * 32 + b"p" * 32
    with pytest.raises(ValueError, match="differs from the signing secret"):
        signer.bind_signing_context(secret, cache_path="cache.bin", public_key=b"x" * 32)
    with pytest.raises(ValueError, match="NUL"):
        signer.bind_signing_context(secret, cache_path="bad\0cache", public_key=secret[32:])
    assert native.cache_loads == 0
