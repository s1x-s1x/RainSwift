"""Contract tests for the acceptance driver itself.

These are deliberately cheap: no native library, no real PQ key generation and
no fixture signing. They pin the predicates that decide whether a real run is
allowed to report success, so a predicate regression fails before the expensive
Linux gate.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest

BASE = Path(__file__).resolve().parents[1]
ROOT = BASE if (BASE / "tools" / "ds_acceptance.py").is_file() else BASE.parent
for entry in (str(ROOT), str(BASE)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

_spec = importlib.util.spec_from_file_location("ds_acceptance_contracts", ROOT / "tools" / "ds_acceptance.py")
ds = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ds)

LIB = "a" * 64
ROOT_SHA = "b" * 64
SCHEME = 0x0F51


def _verifier(edge=0, **overrides):
    row = {
        "edge": edge, "mode": "native", "algorithm": ds.SLH, "passed": True,
        "library_sha256": LIB, "configured_threads": 8,
        "configured_backend": 2, "backend": 2,
    }
    row.update(overrides)
    return row


def _strict_evidence():
    return {
        "checked_edges": 2,
        "legacy_edges": 0,
        "complete": True,
        "algorithms": [ds.SLH, ds.SLH],
        "verifiers": [_verifier(0), _verifier(1)],
        "certificate_verify": {
            "classic_ok": True, "pq_ok": True, "accepted": True, "pq_scheme": SCHEME,
        },
        "application_ok": True,
        "exporters_match": True,
        "trusted_root_sha256": ROOT_SHA,
    }


def _strict(evidence):
    return ds.strict_p2_ok(evidence, library_sha=LIB, threads=8, requested_backend=2,
                           scheme_id=SCHEME, root_sha=ROOT_SHA)


def _tcp_evidence():
    return {
        "error": None,
        "server_error": None,
        "application_ok": True,
        "exporters_match": True,
        "checked_edges": 2,
        "legacy_edges": 0,
        "complete": True,
        "verifiers": [_verifier(0), _verifier(1)],
        "certificate_verify_result": {
            "classic_ok": True, "pq_ok": True, "accepted": True, "pq_scheme": SCHEME,
        },
        "trusted_root_sha256": ROOT_SHA,
    }


def _tcp(evidence):
    return ds.tcp_ok(evidence, library_sha=LIB, threads=8, requested_backend=2,
                     scheme_id=SCHEME, root_sha=ROOT_SHA)


def test_expect_failure_requires_exact_type_stage_and_reason():
    recorder = ds.Recorder()

    def ok():
        raise ds.HandshakeError("certificate_alt", "alternative signature verification failed")

    recorder.expect_failure("ok", ok, stage="certificate_alt",
                            reason_contains="verification failed")
    recorder.expect_failure("wrong-stage", ok, stage="certificate_verify")
    recorder.expect_failure("wrong-reason", ok, stage="certificate_alt",
                            reason_contains="absent")
    recorder.expect_failure("wrong-type",
                            lambda: (_ for _ in ()).throw(TypeError("same stage")),
                            stage="certificate_alt")
    statuses = {case["name"]: case["status"] for case in recorder.cases}
    assert statuses == {
        "ok": "passed",
        "wrong-stage": "failed",
        "wrong-reason": "failed",
        "wrong-type": "failed",
    }


@pytest.mark.parametrize("mutation", [
    lambda ev: ev.update({"checked_edges": 1}),
    lambda ev: ev.update({"legacy_edges": 1}),
    lambda ev: ev.update({"complete": False}),
    lambda ev: ev["algorithms"].__setitem__(0, "slh-dsa-sm3-128s"),
    lambda ev: ev.update({"verifiers": []}),
    lambda ev: ev["verifiers"][0].update({"mode": "python"}),
    lambda ev: ev["verifiers"][0].update({"algorithm": "ml-dsa-44"}),
    lambda ev: ev["verifiers"][0].update({"passed": False}),
    lambda ev: ev["verifiers"][0].update({"library_sha256": "c" * 64}),
    lambda ev: ev["verifiers"][0].update({"configured_threads": 4}),
    lambda ev: ev["verifiers"][0].update({"backend": 1}),
    lambda ev: ev["verifiers"][1].update({"edge": 0}),
    lambda ev: ev["certificate_verify"].update({"classic_ok": False}),
    lambda ev: ev["certificate_verify"].update({"pq_ok": False}),
    lambda ev: ev["certificate_verify"].update({"accepted": False}),
    lambda ev: ev["certificate_verify"].update({"pq_scheme": 1}),
    lambda ev: ev.update({"application_ok": False}),
    lambda ev: ev.update({"exporters_match": False}),
    lambda ev: ev.update({"trusted_root_sha256": "c" * 64}),
])
def test_strict_p2_predicate_rejects_each_mutation(mutation):
    evidence = _strict_evidence()
    ok, reasons = _strict(evidence)
    assert ok and not reasons
    mutation(evidence)
    ok, reasons = _strict(evidence)
    assert not ok and reasons


@pytest.mark.parametrize("mutation", [
    lambda ev: ev.update({"error": "boom"}),
    lambda ev: ev.update({"server_error": "boom"}),
    lambda ev: ev.update({"application_ok": False}),
    lambda ev: ev.update({"exporters_match": False}),
    lambda ev: ev.update({"complete": False}),
    lambda ev: ev.update({"checked_edges": 1}),
    lambda ev: ev.update({"legacy_edges": 1}),
    lambda ev: ev["verifiers"][0].update({"mode": "python"}),
    lambda ev: ev["verifiers"][0].update({"library_sha256": "c" * 64}),
    lambda ev: ev["certificate_verify_result"].update({"classic_ok": False}),
    lambda ev: ev["certificate_verify_result"].update({"pq_ok": False}),
    lambda ev: ev["certificate_verify_result"].update({"accepted": False}),
    lambda ev: ev["certificate_verify_result"].update({"pq_scheme": 1}),
    lambda ev: ev.update({"trusted_root_sha256": "c" * 64}),
])
def test_tcp_predicate_rejects_each_mutation(mutation):
    evidence = _tcp_evidence()
    ok, reasons = _tcp(evidence)
    assert ok and not reasons
    mutation(evidence)
    ok, reasons = _tcp(evidence)
    assert not ok and reasons


def _empty_configs():
    return {code: SimpleNamespace(alt_fixture=None) for code in ds.REQUIRED_FULL}


def test_full_profile_set_fails_when_p3_p4_are_missing(tmp_path):
    recorder = ds.Recorder()
    args = SimpleNamespace(output=tmp_path, profile_set="full", library=tmp_path / "missing.so")
    ds.phase_e1(recorder, args, tmp_path / "fixtures", _empty_configs())
    statuses = {case["name"]: case["status"] for case in recorder.cases}
    assert statuses["profile-coverage"] == "failed"
    for code in ds.REQUIRED_FULL:
        assert statuses[f"e1-{code}"] == "failed"
    assert statuses["e1-profiles"] == "failed"


def test_p2_only_records_missing_components_as_not_covered(tmp_path):
    recorder = ds.Recorder()
    args = SimpleNamespace(output=tmp_path, profile_set="p2-only", library=tmp_path / "missing.so")
    ds.phase_e1(recorder, args, tmp_path / "fixtures", _empty_configs())
    statuses = {case["name"]: case["status"] for case in recorder.cases}
    assert statuses["profile-coverage"] == "failed"  # P0-P2 are still required
    assert statuses["e1-P3"] == "not_covered"
    assert statuses["e1-P4"] == "not_covered"
    assert statuses["e1-profiles"] == "failed"


def test_empty_profile_set_is_never_a_pass(tmp_path):
    recorder = ds.Recorder()
    args = SimpleNamespace(output=tmp_path, profile_set="full", library=tmp_path / "missing.so")
    ds.phase_e1(recorder, args, tmp_path / "fixtures", {})
    assert recorder.cases
    assert any(case["status"] == "failed" for case in recorder.cases)
    assert not all(case["status"] == "passed" for case in recorder.cases)


def test_phase_exception_creates_failure_case_and_junit_node(tmp_path):
    recorder = ds.Recorder()
    result = ds.run_phase(recorder, "fixture-verification",
                          lambda: (_ for _ in ()).throw(RuntimeError("fixture verify exploded")))
    assert result["status"] == "failed"
    assert recorder.cases[-1]["name"] == "phase-fixture-verification"
    assert recorder.cases[-1]["status"] == "failed"
    counts = recorder.junit(tmp_path / "junit.xml")
    assert counts["failed"] == 1
    root = ET.parse(tmp_path / "junit.xml").getroot()
    failure = root.find(".//failure")
    assert failure is not None
    assert "fixture verify exploded" in (failure.get("message") or "")


def test_main_writes_report_when_fixture_phase_raises(tmp_path, monkeypatch):
    import tools.alt_chain_fixtures as fixture_tools

    monkeypatch.setattr(fixture_tools, "verify",
                        lambda args: (_ for _ in ()).throw(RuntimeError("fixture verify exploded")))
    monkeypatch.setattr(ds, "phase_e1", lambda *a, **k: None)
    monkeypatch.setattr(ds, "phase_strict", lambda *a, **k: None)
    monkeypatch.setattr(ds, "phase_tcp", lambda *a, **k: None)
    monkeypatch.setattr(ds, "run_negative", lambda *a, **k: None)
    real_config = ds.HybridTLSConfig(x509=True, alt_chain=ds.SLH,
                                     alt_fixture=str(tmp_path / "fixture"),
                                     alt_require_native=True)
    monkeypatch.setattr(ds, "profiles", lambda *a, **k: {"P2": real_config})
    output = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", [
        "ds_acceptance.py", "--fixtures", str(tmp_path / "fixtures"),
        "--library", str(tmp_path / "missing.so"), "--output", str(output),
        "--profile-set", "p2-only",
    ])
    assert ds.main() == 1
    report = __import__("json").loads((output / "acceptance.json").read_text())
    assert report["passed"] is False
    assert report["phase_failures"]
    assert (output / "junit.xml").is_file()
    assert "fixture verify exploded" in (output / "acceptance.json").read_text()


def test_cache_names_are_campaign_edge_and_key_scoped():
    from tls.alt_chain import cache_filename
    names = {
        cache_filename("campaign-a", ds.SLH, "root", b"\x01" * 32),
        cache_filename("campaign-b", ds.SLH, "root", b"\x01" * 32),
        cache_filename("campaign-a", ds.SLH, "intermediate", b"\x01" * 32),
        cache_filename("campaign-a", ds.SLH, "root", b"\x02" * 32),
    }
    assert len(names) == 4
    assert all(len(name) < 200 for name in names)


class _FakeCacheSigner:
    name = ds.SLH
    pid = 3

    def __init__(self):
        self.calls = []

    def bind_signing_context(self, secret, *, cache_path, public_key, level):
        self.calls.append((bytes(secret), Path(cache_path), bytes(public_key), level))
        self.last_cache = {"mode": "loaded"}


def _cache_fixture(tmp_path):
    from tls.alt_chain import CACHE_SCHEMA, cache_metadata_path, write_cache_metadata
    secret = b"s" * 32 + b"p" * 32
    public = secret[32:]
    cache = tmp_path / "campaign-a-128-24-root-deadbeef.cache"
    cache.write_bytes(b"cache-bytes")
    metadata = {
        "schema": CACHE_SCHEMA, "campaign": "campaign-a", "algorithm": ds.SLH,
        "pid": 3, "edge": "root",
        "public_key_sha256": hashlib.sha256(public).hexdigest(),
        "library_sha256": LIB, "backend": 2, "threads": 8, "cache_level": 6,
        "cache_file_sha256": hashlib.sha256(b"cache-bytes").hexdigest(),
    }
    write_cache_metadata(cache, metadata)
    return secret, public, cache, metadata, cache_metadata_path(cache)


def test_cache_metadata_rejects_wrong_public_library_campaign_and_corruption(tmp_path):
    from tls.alt_chain import load_ca_cache
    secret, public, cache, metadata, metadata_path = _cache_fixture(tmp_path)
    signer = _FakeCacheSigner()
    assert load_ca_cache(signer, secret, cache, public, expected_library_sha256=LIB,
                         expected_campaign="campaign-a", expected_edge="root")
    assert signer.calls

    with pytest.raises(ValueError, match="public key digest"):
        load_ca_cache(signer, secret, cache, b"x" * 32, expected_library_sha256=LIB)
    with pytest.raises(ValueError, match="library digest"):
        load_ca_cache(signer, secret, cache, public, expected_library_sha256="c" * 64)
    with pytest.raises(ValueError, match="campaign"):
        load_ca_cache(signer, secret, cache, public, expected_campaign="campaign-b")
    with pytest.raises(ValueError, match="edge"):
        load_ca_cache(signer, secret, cache, public, expected_edge="intermediate")
    cache.write_bytes(b"corrupted")
    with pytest.raises(ValueError, match="hash differs"):
        load_ca_cache(signer, secret, cache, public, expected_library_sha256=LIB)
    metadata_path.unlink()
    with pytest.raises(ValueError, match="metadata is missing"):
        load_ca_cache(signer, secret, cache, public)
    with pytest.raises(ValueError, match="NUL"):
        load_ca_cache(signer, secret, "bad\0cache", public)


def test_native_abi_mismatch_is_backend_unavailable(monkeypatch, tmp_path):
    import tools.native as native

    class Version:
        def __init__(self):
            self.argtypes = None
            self.restype = None

        def __call__(self):
            return 0xDEADBEEF

    class FakeLibrary:
        def __init__(self):
            self.slh_abi_version = Version()

    image = tmp_path / "libfake.so"
    image.write_bytes(b"not a real library")
    monkeypatch.setattr(native.ct, "CDLL", lambda path: FakeLibrary())
    with pytest.raises(RuntimeError, match="ABI mismatch"):
        native.NativeSlhDsa(pid=3, library=image)
    from tls.pq.slhdsa_sm3 import SlhDsaSm3
    signer = SlhDsaSm3(library=str(image), require_native=True)
    with pytest.raises(ds.BackendUnavailableError, match="ABI mismatch"):
        signer._native()


def test_native_cache_paths_reject_nul_bytes():
    import tools.native as native
    adapter = native.NativeSlhDsa.__new__(native.NativeSlhDsa)
    adapter.ctx = 1
    adapter.lib = SimpleNamespace(slh_ctx_free=lambda ctx: None)
    with pytest.raises(ValueError, match="NUL"):
        adapter.cache_save("bad\0path")
    with pytest.raises(ValueError, match="NUL"):
        adapter.cache_load("bad\0path", b"p" * 32)
    adapter.ctx = 0
