"""DS acceptance for the forced post-quantum certificate chain.

This driver records *field-level* evidence, not just "handshake succeeded":

* every negative case names the expected exception type, TLS stage and a stable
  reason fragment; a TypeError/ValueError with the same stage is a failure;
* strict P2 is checked by a pure predicate over both CA edges, backends,
  library hash, thread count, CertificateVerify halves and the independent root;
* TCP is checked separately for server errors, exporter agreement, CV fields and
  the root digest;
* ``--profile-set full`` requires P0-P4 and the large-certificate case;
  ``--profile-set p2-only`` records the missing components as ``not_covered``
  (JUnit ``skipped``) instead of shrinking the denominator;
* every phase is wrapped so a fixture/verify traceback still produces a failed
  test case, ``acceptance.json`` and ``junit.xml``;
* source, library, fixture and module hashes are captured before and after.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import traceback
from types import SimpleNamespace
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT if (ROOT / "tls").is_dir() else ROOT / "base_tls"
for entry in (str(ROOT), str(BASE)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import tls  # noqa: E402  (dependency path initialisation)
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from tls.alt_chain import (  # noqa: E402
    ALT_SIGNATURE_ALGORITHM, ALT_SIGNATURE_VALUE,
    issue_alt_certificate, public_key_info,
)
from tls.alt_fixtures import load_fixture  # noqa: E402
from tls.alt_profiles import e1_record, profiles  # noqa: E402
from tls.config import HybridTLSConfig  # noqa: E402
from tls.credentials import CertificateAuthority, ServerCredentials  # noqa: E402
from tls.der import (  # noqa: E402
    algorithm_identifier, bit_string, bit_string_bytes, elements, extension_fields,
    oid, single, tlv,
)
from tls.errors import BackendUnavailableError, HandshakeError  # noqa: E402
from tls.handshake.certificate_verify import HybridCertificateVerify  # noqa: E402
from tls.handshake.client import HybridClient, ServerFlightLimits  # noqa: E402
from tls.handshake.connection import HybridConnection, load_trusted_root  # noqa: E402
from tls.handshake.messages import CertificateVerify  # noqa: E402
from tls.handshake.server import HybridServer  # noqa: E402
from tls.metrics import Metrics  # noqa: E402
from tls.pki import CertificateChain  # noqa: E402
from tls.pq.signature import get_pq_signer  # noqa: E402
from tls.transport.tcp import run_over_tcp  # noqa: E402
from tls.wire import split_handshake_message  # noqa: E402

SLH = "slh-dsa-sm3-128-24"
REQUIRED_FULL = ("P0", "P1", "P2", "P3", "P4")
REQUIRED_P2 = ("P0", "P1", "P2")
VALID_ACTUAL_BACKENDS = (1, 2, 5)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    return sha(Path(path).read_bytes())


def tree_hashes(root: Path) -> dict[str, str]:
    root = Path(root)
    if not root.is_dir():
        return {}
    return {p.relative_to(root).as_posix(): sha(p.read_bytes())
            for p in sorted(root.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}


def _files_under(path: Path, suffixes: set[str]) -> list[Path]:
    path = Path(path)
    if not path.exists():
        return []
    if path.is_file():
        return [path] if path.suffix in suffixes else []
    return [p for p in path.rglob("*") if p.is_file() and p.suffix in suffixes
            and "__pycache__" not in p.parts]


def source_hashes() -> dict[str, str]:
    paths: set[Path] = set()
    paths.update(_files_under(BASE / "tls", {".py"}))
    paths.update(_files_under(ROOT / "tools", {".py"}))
    paths.update(_files_under(BASE / "tools", {".py"}))
    paths.update(_files_under(ROOT / "reference", {".py"}))
    paths.update(_files_under(ROOT / "third_party/py-acvp-pqc", {".py"}))
    paths.update(_files_under(ROOT / "c", {".c", ".h"}))
    paths.update(_files_under(ROOT / "native", {".c", ".h", ".cpp", ".hpp", ".py", ".sh"}))
    return {str(p.relative_to(ROOT)): sha(p.read_bytes())
            for p in sorted(paths) if p.is_file() and "__pycache__" not in p.parts}


def module_origins() -> dict[str, dict]:
    """Record the file each module actually loaded, not just the name."""
    candidates = {
        "tls": BASE / "tls/__init__.py",
        "native_adapter": ROOT / "tools/native.py",
        "reference": ROOT / "reference/__init__.py",
        "fips205": ROOT / "third_party/py-acvp-pqc/fips205.py",
        "acceptance_driver": Path(__file__).resolve(),
    }
    result: dict[str, dict] = {}
    for label, path in candidates.items():
        result[label] = {
            "path": str(path.resolve()) if path.is_file() else None,
            "sha256": file_sha(path) if path.is_file() else None,
        }
    try:
        import tools.native as native_module
        result["native_adapter"]["imported_file"] = str(Path(native_module.__file__).resolve())
    except Exception as error:  # noqa: BLE001 - recorded, not hidden
        result["native_adapter"]["import_error"] = f"{type(error).__name__}: {error}"
    try:
        import reference as reference_module
        result["reference"]["imported_file"] = str(Path(reference_module.__file__).resolve())
    except Exception as error:  # noqa: BLE001
        result["reference"]["import_error"] = f"{type(error).__name__}: {error}"
    return result


def load_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def modify_certificate(blob: bytes, issuer_key, changes, *, resign=True) -> bytes:
    """Schema-guided mutation; unrelated DER fields retain their raw bytes."""
    outer = elements(single(blob, 0x30).value)
    fields = elements(single(outer[0].encoded, 0x30).value)
    new_fields = []
    for field in fields:
        if field.tag != 0xA3:
            new_fields.append(field.encoded)
            continue
        extensions = []
        for ext in elements(single(field.value, 0x30).value):
            identifier, critical, value = extension_fields(ext.encoded)
            if identifier not in changes:
                extensions.append(ext.encoded)
                continue
            replacement = changes[identifier]
            if replacement is None:
                continue
            value = replacement(value) if callable(replacement) else replacement
            extensions.append(tlv(0x30, oid(identifier) + (tlv(1, b"\xff") if critical else b"") + tlv(4, value)))
        if extensions:
            new_fields.append(tlv(0xA3, tlv(0x30, b"".join(extensions))))
    tbs = tlv(0x30, b"".join(new_fields))
    signature = bit_string(issuer_key.sign(tbs, ec.ECDSA(hashes.SHA256()))) if resign else outer[2].encoded
    return tlv(0x30, tbs + outer[1].encoded + signature)


def flip_last(data: bytes) -> bytes:
    if not data:
        return data
    return data[:-1] + bytes([data[-1] ^ 1])


class Recorder:
    def __init__(self):
        self.cases: list[dict] = []

    def add(self, name, passed, *, stage=None, detail=None, evidence=None,
            status=None, reason=None):
        if status is None:
            status = "passed" if passed else "failed"
        if status != "passed":
            passed = False
        self.cases.append({
            "name": name, "status": status, "passed": bool(passed),
            "stage": stage, "detail": detail, "reason": reason,
            "evidence": evidence or {},
        })
        print(json.dumps({"case": name, "status": status, "stage": stage}), flush=True)

    def not_covered(self, name, reason, *, stage=None, evidence=None):
        self.add(name, False, stage=stage, detail=reason, evidence=evidence,
                 status="not_covered", reason=reason)

    def expect_failure(self, name, fn, *, stage=None, error_types=(HandshakeError,),
                       reason_contains=None):
        try:
            fn()
        except Exception as error:  # noqa: BLE001 - this is the assertion boundary
            actual_stage = getattr(error, "step", None)
            type_ok = isinstance(error, error_types)
            stage_ok = stage is None or actual_stage == stage
            reason_ok = reason_contains is None or reason_contains in str(error)
            self.add(
                name, type_ok and stage_ok and reason_ok,
                stage=actual_stage or type(error).__name__,
                detail=f"{type(error).__name__}: {error}",
                evidence={
                    "expected_error_types": [t.__name__ for t in error_types],
                    "actual_error_type": type(error).__name__,
                    "expected_stage": stage,
                    "actual_stage": actual_stage,
                    "expected_reason_contains": reason_contains,
                    "type_ok": type_ok, "stage_ok": stage_ok, "reason_ok": reason_ok,
                },
            )
            return error
        self.add(name, False, stage=stage, detail="the operation unexpectedly succeeded",
                 evidence={"expected_error_types": [t.__name__ for t in error_types],
                           "expected_stage": stage,
                           "expected_reason_contains": reason_contains})
        return None

    def summary(self) -> dict[str, int]:
        counts = {"passed": 0, "failed": 0, "not_covered": 0, "skipped": 0}
        for case in self.cases:
            counts[case["status"]] = counts.get(case["status"], 0) + 1
        return {"tests": len(self.cases), **counts}

    def junit(self, path: Path):
        counts = self.summary()
        suite = ET.Element("testsuite", name="ds-acceptance",
                           tests=str(counts["tests"]),
                           failures=str(counts["failed"]),
                           errors="0",
                           skipped=str(counts["not_covered"] + counts["skipped"]))
        for case in self.cases:
            node = ET.SubElement(suite, "testcase", name=case["name"],
                                 classname="ds-acceptance")
            if case["status"] == "failed":
                failure = ET.SubElement(node, "failure", message=case.get("detail") or "failed")
                failure.text = json.dumps(case, ensure_ascii=False, indent=2)
            elif case["status"] in ("not_covered", "skipped"):
                ET.SubElement(node, "skipped", message=case.get("reason") or case.get("detail") or "not covered")
        ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)
        return counts


def policy(config: HybridTLSConfig, args) -> HybridTLSConfig:
    return replace(config, alt_require_native=True, alt_force_python=False,
                   alt_library=str(args.library), alt_threads=args.threads,
                   alt_backend=args.backend)


def root_for(fixtures: Path, algorithm: str) -> x509.Certificate:
    return x509.load_der_x509_certificate((fixtures / algorithm / "root.der").read_bytes())


def drive_with_filter(config, trusted_root, frame_filter):
    """One in-process handshake with a rewrite hook on server plaintext frames."""
    metrics = Metrics()
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config)
    certificate = credentials.bind_to(authority)
    client = HybridClient(config, authority, metrics=metrics, trusted_root=trusted_root,
                          trusted_name="server.example")
    server = HybridServer(config, credentials, certificate, metrics=metrics)
    client.receive_server_hello(server.receive_client_hello(client.create_client_hello()))
    flight = server.send_authenticated_flight(frame_filter=frame_filter)
    client.receive_server_flight([record for _name, record, _frame in flight])
    return client, server


def cv_filter(mutator):
    def apply(name, frame):
        if name != "CertificateVerify":
            return frame
        _kind, body = split_handshake_message(frame)
        payload = HybridCertificateVerify.decode(CertificateVerify.decode(body).payload)
        return CertificateVerify(payload=mutator(payload).encode()).to_message()
    return apply


def strict_p2_ok(evidence: dict, *, library_sha: str, threads: int,
                 requested_backend: int, scheme_id: int, root_sha: str) -> tuple[bool, list[str]]:
    """Pure field predicate; every mutation must fail one of these checks."""
    reasons: list[str] = []

    def check(condition, message):
        if not condition:
            reasons.append(message)

    check(evidence.get("checked_edges") == 2, "checked_edges != 2")
    check(evidence.get("legacy_edges") == 0, "legacy_edges != 0")
    check(evidence.get("complete") is True, "complete is not true")
    check(evidence.get("algorithms") == [SLH, SLH], "algorithms differ from two 128-24 edges")
    verifiers = evidence.get("verifiers")
    check(isinstance(verifiers, list) and len(verifiers) == 2, "verifiers must contain exactly two entries")
    if isinstance(verifiers, list) and len(verifiers) == 2:
        check({row.get("edge") for row in verifiers} == {0, 1}, "verifier edges differ from {0,1}")
        for row in verifiers:
            edge = row.get("edge")
            check(row.get("mode") == "native", f"edge {edge} mode is not native")
            check(row.get("algorithm") == SLH, f"edge {edge} algorithm differs")
            check(row.get("passed") is True, f"edge {edge} did not pass")
            check(row.get("library_sha256") == library_sha, f"edge {edge} library hash differs")
            check(row.get("configured_threads") == threads, f"edge {edge} configured threads differ")
            actual = row.get("backend")
            if requested_backend != 0:
                check(actual == requested_backend, f"edge {edge} backend {actual} != requested {requested_backend}")
            else:
                check(row.get("configured_backend") == 0, f"edge {edge} configured backend is not auto")
                check(actual in VALID_ACTUAL_BACKENDS, f"edge {edge} actual backend {actual} is not valid")
    cv = evidence.get("certificate_verify") or {}
    check(cv.get("classic_ok") is True, "classical CertificateVerify half is not true")
    check(cv.get("pq_ok") is True, "post-quantum CertificateVerify half is not true")
    check(cv.get("accepted") is True, "CertificateVerify was not accepted")
    check(cv.get("pq_scheme") == scheme_id, f"CertificateVerify scheme {cv.get('pq_scheme')} != {scheme_id}")
    check(evidence.get("application_ok") is True, "application data did not round-trip")
    check(evidence.get("exporters_match") is True, "exporter secrets differ")
    check(evidence.get("trusted_root_sha256") == root_sha, "trusted root digest differs")
    return not reasons, reasons


def tcp_ok(report: dict, *, library_sha: str, threads: int,
           requested_backend: int, scheme_id: int, root_sha: str) -> tuple[bool, list[str]]:
    """TCP-specific predicate, including server_error and exporter agreement."""
    reasons: list[str] = []

    def check(condition, message):
        if not condition:
            reasons.append(message)

    check(report.get("error") is None, "client-side TCP error is not null")
    check(report.get("server_error") is None, "server-side TCP error is not null")
    check(report.get("application_ok") is True, "TCP application data did not round-trip")
    check(report.get("exporters_match") is True, "TCP exporter secrets differ")
    check(report.get("complete") is True, "TCP alt chain is not complete")
    check(report.get("checked_edges") == 2, "TCP checked_edges != 2")
    check(report.get("legacy_edges") == 0, "TCP legacy_edges != 0")
    verifiers = report.get("verifiers")
    check(isinstance(verifiers, list) and len(verifiers) == 2, "TCP verifiers must contain exactly two entries")
    if isinstance(verifiers, list) and len(verifiers) == 2:
        check({row.get("edge") for row in verifiers} == {0, 1}, "TCP verifier edges differ from {0,1}")
        for row in verifiers:
            edge = row.get("edge")
            check(row.get("mode") == "native", f"TCP edge {edge} mode is not native")
            check(row.get("algorithm") == SLH, f"TCP edge {edge} algorithm differs")
            check(row.get("passed") is True, f"TCP edge {edge} did not pass")
            check(row.get("library_sha256") == library_sha, f"TCP edge {edge} library hash differs")
            check(row.get("configured_threads") == threads, f"TCP edge {edge} configured threads differ")
            actual = row.get("backend")
            if requested_backend != 0:
                check(actual == requested_backend, f"TCP edge {edge} backend {actual} != requested {requested_backend}")
            else:
                check(row.get("configured_backend") == 0, f"TCP edge {edge} configured backend is not auto")
                check(actual in VALID_ACTUAL_BACKENDS, f"TCP edge {edge} actual backend {actual} is not valid")
    cv = report.get("certificate_verify_result") or {}
    check(cv.get("classic_ok") is True, "TCP classical CV half is not true")
    check(cv.get("pq_ok") is True, "TCP post-quantum CV half is not true")
    check(cv.get("accepted") is True, "TCP CV was not accepted")
    check(cv.get("pq_scheme") == scheme_id, f"TCP CV scheme {cv.get('pq_scheme')} != {scheme_id}")
    check(report.get("trusted_root_sha256") == root_sha, "TCP trusted root digest differs")
    return not reasons, reasons


def strict_evidence(result, library_sha: str) -> dict:
    alt = result.client.alt_chain_verification
    verification = result.client.verification
    return {
        "checked_edges": alt.checked_edges,
        "legacy_edges": alt.legacy_edges,
        "complete": alt.complete,
        "algorithms": list(alt.algorithms),
        "verifiers": list(alt.verifiers),
        "certificate_verify": {
            "classic_ok": verification.classic_ok,
            "pq_ok": verification.pq_ok,
            "accepted": verification.accepted,
            "pq_scheme": result.client.certificate_verify.pq_scheme,
        },
        "application_ok": result.application_payload_ok,
        "exporters_match": result.exporters_match,
        "trusted_root_sha256": sha(result.client.trusted_root.public_bytes(serialization.Encoding.DER)),
        "chain_der_sha256": [sha(blob) for blob in result.server.credentials.chain.chain_der],
        "library_sha256": library_sha,
        "policy": result.config.alt_policy() if hasattr(result, "config") else None,
        "handshake_bytes": result.handshake_bytes,
        "server_flight_bytes": result.server_bytes,
    }


def tcp_evidence(tcp) -> dict:
    alt = tcp.alt_chain_verification
    return {
        "error": tcp.error,
        "server_error": tcp.server_error,
        "application_ok": tcp.application_ok,
        "exporters_match": tcp.exporters_match,
        "checked_edges": getattr(alt, "checked_edges", None),
        "legacy_edges": getattr(alt, "legacy_edges", None),
        "complete": getattr(alt, "complete", None),
        "algorithms": list(getattr(alt, "algorithms", ()) or ()),
        "verifiers": list(getattr(alt, "verifiers", ()) or ()),
        "certificate_verify_result": tcp.certificate_verify_result,
        "certificate_verify_accepted": tcp.certificate_verify_accepted,
        "trusted_root_sha256": tcp.trusted_root_sha256,
        "client_waits": tcp.client_waits,
        "waits_to_authenticated": tcp.waits_to_authenticated,
        "client_wall_ms": tcp.client_wall_ms,
        "server_wall_ms": tcp.server_wall_ms,
        "client_bytes_sent": tcp.client_bytes_sent,
        "server_bytes_sent": tcp.server_bytes_sent,
        "records": [(m.name, m.message_bytes, m.record_count) for m in tcp.messages],
    }


def run_negative(rec: Recorder, args, fixtures: Path, configs, p2, profile_set: str):
    fixtures = fixtures.resolve()
    fixture_root = root_for(fixtures, SLH)
    other_root = (root_for(fixtures, "slh-dsa-sm3-128s")
                  if (fixtures / "slh-dsa-sm3-128s/root.der").is_file() else None)
    intermediate_key = load_key(fixtures / SLH / "intermediate-test-key.pem")
    root_key = load_key(fixtures / SLH / "root-test-key.pem")
    chain = ServerCredentials(p2).chain
    leaf, intermediate = chain.chain_der

    # 1. Root replacement. The fixtures share one classical root key, so the
    #    swapped anchor reaches the PQ edge and is rejected there.
    if other_root is not None:
        rec.expect_failure(
            "negative-root-replacement",
            lambda: HybridConnection.run(p2, trusted_root=other_root),
            stage="certificate_alt",
            reason_contains="configured algorithm differs",
        )
    elif profile_set == "p2-only":
        rec.not_covered("negative-root-replacement",
                        "campaign issued only the 128-24 anchor; no 128s anchor to swap")
    else:
        rec.add("negative-root-replacement", False, stage="fixture",
                detail="required 128s anchor is missing in full profile set")

    # 1b. A wholly unrelated root fails in the classical chain first.
    unrelated_key = ec.generate_private_key(ec.SECP256R1())
    unrelated_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "unrelated root")])
    unrelated = (x509.CertificateBuilder().subject_name(unrelated_name)
                 .issuer_name(unrelated_name).public_key(unrelated_key.public_key())
                 .serial_number(1).not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
                 .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                 .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
                 .sign(unrelated_key, hashes.SHA256()))
    rec.expect_failure(
        "negative-unrelated-root-replacement",
        lambda: HybridConnection.run(p2, trusted_root=unrelated),
        stage="certificate",
        reason_contains="not signed by",
    )

    # 2. Local root with the same classical key but a different PQ key.
    #    A deterministic 32-byte value is enough: verification must fail before
    #    the key is ever used to sign.
    attacker_public = bytes.fromhex("11" * 32)
    replaced_root_der = modify_certificate(
        chain.root_der, root_key,
        {"2.5.29.72": public_key_info(SLH, attacker_public)})
    replaced_root = x509.load_der_x509_certificate(replaced_root_der)
    rec.expect_failure(
        "negative-root-pq-key-replacement",
        lambda: HybridConnection.run(p2, trusted_root=replaced_root),
        stage="certificate_alt",
        reason_contains="alternative signature verification failed",
    )

    # 3. Strip the leaf's advertised alternative pair; the classical chain still passes.
    stripped_leaf = modify_certificate(
        leaf, intermediate_key,
        {str(ALT_SIGNATURE_ALGORITHM.dotted_string): None,
         str(ALT_SIGNATURE_VALUE.dotted_string): None})
    stripped_chain = CertificateChain((stripped_leaf, intermediate), chain.root_der,
                                      chain.root_public_key, stripped_leaf)
    def stripped_run():
        credentials = ServerCredentials(p2)
        credentials.chain = stripped_chain
        HybridConnection.run(p2, credentials=credentials, trusted_root=fixture_root)
    rec.expect_failure("negative-leaf-alt-stripped", stripped_run, stage="certificate_alt",
                       reason_contains="required alternative signature extensions are absent")

    # 4. Corrupt the leaf's PQ signature bytes after re-signing the classical outer layer.
    corrupted_leaf = modify_certificate(
        leaf, intermediate_key,
        {str(ALT_SIGNATURE_VALUE.dotted_string):
         lambda value: bit_string(flip_last(bit_string_bytes(value)))})
    corrupted_chain = CertificateChain((corrupted_leaf, intermediate), chain.root_der,
                                       chain.root_public_key, corrupted_leaf)
    def corrupted_run():
        credentials = ServerCredentials(p2)
        credentials.chain = corrupted_chain
        HybridConnection.run(p2, credentials=credentials, trusted_root=fixture_root)
    rec.expect_failure("negative-leaf-signature-corrupt", corrupted_run, stage="certificate_alt",
                       reason_contains="alternative signature verification failed")

    # 5. Replace the advertised algorithm OID with the 128s profile.
    swapped_leaf = modify_certificate(
        leaf, intermediate_key,
        {str(ALT_SIGNATURE_ALGORITHM.dotted_string):
         algorithm_identifier("1.3.6.1.4.1.99999.2.1")})
    swapped_chain = CertificateChain((swapped_leaf, intermediate), chain.root_der,
                                     chain.root_public_key, swapped_leaf)
    def swapped_run():
        credentials = ServerCredentials(p2)
        credentials.chain = swapped_chain
        HybridConnection.run(p2, credentials=credentials, trusted_root=fixture_root)
    rec.expect_failure("negative-algorithm-oid-swap", swapped_run, stage="certificate_alt",
                       reason_contains="alternative signature algorithm differs from issuer SPKI")

    # 6. CertificateVerify: one half wrong, then the PQ half absent.
    rec.expect_failure(
        "negative-cv-classical-signature",
        lambda: drive_with_filter(p2, fixture_root, cv_filter(
            lambda payload: replace(payload, classic_signature=flip_last(payload.classic_signature)))),
        stage="certificate_verify", reason_contains="classical signature invalid")
    rec.expect_failure(
        "negative-cv-pq-signature",
        lambda: drive_with_filter(p2, fixture_root, cv_filter(
            lambda payload: replace(payload, pq_signature=flip_last(payload.pq_signature)))),
        stage="certificate_verify", reason_contains="post-quantum signature invalid")
    rec.expect_failure(
        "negative-cv-pq-absent",
        lambda: drive_with_filter(p2, fixture_root, cv_filter(
            lambda payload: replace(payload, pq_scheme=None, pq_signature=None))),
        stage="certificate_verify", reason_contains="PQ half is absent")

    # 7. Native backend missing / invalid image: environment failures, not bad signatures.
    missing = replace(p2, alt_library=str(ROOT / "build/does-not-exist/libslhdsa_sm3.so"),
                      alt_require_native=True)
    rec.expect_failure(
        "negative-native-library-missing",
        lambda: ServerCredentials(missing),
        error_types=(BackendUnavailableError,), reason_contains="unavailable")
    invalid_image = replace(p2, alt_library=str(fixtures / SLH / "fixture.json"),
                            alt_require_native=True)
    rec.expect_failure(
        "negative-invalid-native-image",
        lambda: ServerCredentials(invalid_image),
        error_types=(BackendUnavailableError,), reason_contains="unavailable")

    # 8. 128-24 must never be accepted as the online CertificateVerify signer.
    rec.expect_failure(
        "negative-online-128-24-injection",
        lambda: HybridTLSConfig(pq_signer=SLH),
        error_types=(ValueError,), reason_contains="reserved for offline CA signing")

    # 9. Flight limits: a large authenticated flight over a small byte budget.
    def budget_run():
        metrics = Metrics()
        authority = CertificateAuthority(p2.classical())
        credentials = ServerCredentials(p2)
        certificate = credentials.bind_to(authority)
        client = HybridClient(p2, authority, metrics=metrics, trusted_root=fixture_root,
                              trusted_name="server.example",
                              flight_limits=ServerFlightLimits(max_records=1024, max_bytes=128))
        server = HybridServer(p2, credentials, certificate, metrics=metrics)
        client.receive_server_hello(server.receive_client_hello(client.create_client_hello()))
        flight = server.send_authenticated_flight()
        client.receive_server_flight([record for _name, record, _frame in flight])
    rec.expect_failure("negative-flight-byte-budget", budget_run, stage="server_flight",
                       reason_contains="exceeds byte budget")

    # 10. Truncated authenticated flight.
    def truncated_run():
        metrics = Metrics()
        authority = CertificateAuthority(p2.classical())
        credentials = ServerCredentials(p2)
        certificate = credentials.bind_to(authority)
        client = HybridClient(p2, authority, metrics=metrics, trusted_root=fixture_root,
                              trusted_name="server.example")
        server = HybridServer(p2, credentials, certificate, metrics=metrics)
        client.receive_server_hello(server.receive_client_hello(client.create_client_hello()))
        flight = server.send_authenticated_flight()
        client.receive_server_flight([record for _name, record, _frame in flight[:-1]])
    rec.expect_failure("negative-flight-truncated", truncated_run, stage="server_flight",
                       reason_contains="truncated authenticated handshake flight")

    # 11. Budget identity and exhaustion: independent ledgers and deterministic keys.
    from tools.signing_budget import BudgetError, SigningBudget
    unique = SigningBudget(args.output / "negative-budget-unique.sqlite")
    unique_public = bytes(range(32))
    first = unique.reserve(SLH, unique_public, b"first", limit=2,
                           operation_id="neg:unique", case_identity="neg:unique")
    rec.add("budget-unique-first", True, stage="budget",
            evidence={"receipt": first, "public_key_sha256": sha(unique_public)})
    rec.expect_failure(
        "budget-operation-identity-is-unique",
        lambda: unique.reserve(SLH, unique_public, b"different", limit=2,
                               operation_id="neg:unique", case_identity="neg:unique"),
        error_types=(BudgetError,), reason_contains="already charged")
    unique_rows = [row for row in unique.status() if row["algorithm"] == SLH]
    rec.add("budget-unique-usage-remains-one",
            bool(unique_rows) and unique_rows[0]["used"] == 1,
            stage="budget", evidence={"keys": unique_rows})

    exhaust = SigningBudget(args.output / "negative-budget-exhaust.sqlite")
    exhaust_public = bytes([0x42]) * 32
    exhaust.reserve(SLH, exhaust_public, b"first", limit=1,
                    operation_id="neg:exhaust", case_identity="neg:exhaust")
    rec.expect_failure(
        "budget-exhaustion-refuses-second",
        lambda: exhaust.reserve(SLH, exhaust_public, b"second", limit=1,
                                operation_id="neg:exhaust2", case_identity="neg:exhaust2"),
        error_types=(BudgetError,), reason_contains="exhausted")

    # 12. A refused reservation must not reach signing. No real keygen/sign here.
    sign_calls = {"count": 0}
    class CountingSigner:
        name = SLH
        signature_bytes = 3856
        def sign(self, *a, **k):
            sign_calls["count"] += 1
            return b"\x00" * 3856
        def verify(self, *a, **k):
            return True
    now = datetime.now(timezone.utc)
    rec.expect_failure(
        "budget-reserve-failure-stops-sign",
        lambda: issue_alt_certificate(
            name=SLH, signer=CountingSigner(), secret_key=b"s" * 32 + b"p" * 32,
            issuer_public_key=b"p" * 32,
            before_sign=lambda *a, **k: (_ for _ in ()).throw(BudgetError("exhausted")),
            after_sign=lambda *a, **k: None,
            subject="test", issuer=tls.alt_chain._name("test"),
            subject_key=ec.generate_private_key(ec.SECP256R1()).public_key(),
            issuer_key=ec.generate_private_key(ec.SECP256R1()),
            ca=True, path_length=0, serial=99,
            valid_from=now - timedelta(days=1), valid_to=now + timedelta(days=365)),
        error_types=(BudgetError,), reason_contains="exhausted")
    rec.add("budget-refusal-left-sign-uncalled", sign_calls["count"] == 0, stage="budget",
            evidence={"sign_calls": sign_calls["count"]})


def _run_one_e1(rec: Recorder, code: str, config, stream, library_sha: str):
    try:
        record = e1_record(code, config)
        record.update({"generated_at_utc": datetime.now(timezone.utc).isoformat(),
                       "library_sha256": library_sha})
        stream.write(json.dumps(record, sort_keys=True) + "\n")
        stream.flush()
        rec.add(f"e1-{code}", record["passed"], stage="handshake",
                evidence={"server_flight_bytes": record["server_flight_bytes"],
                          "alt_extension_bytes": record["alt_extension_bytes"]})
        return record
    except Exception as error:  # noqa: BLE001 - per-case failure, phase continues
        rec.add(f"e1-{code}", False, stage="e1",
                detail=f"{type(error).__name__}: {error}",
                evidence={"traceback": traceback.format_exc(), "profile": code})
        return None


def phase_e1(rec: Recorder, args, fixtures: Path, configs):
    available = {
        code: config for code, config in configs.items()
        if config.alt_fixture and (Path(config.alt_fixture) / "fixture.json").is_file()
    }
    required = REQUIRED_FULL if args.profile_set == "full" else REQUIRED_P2
    missing = [code for code in required if code not in available]
    rec.add("profile-coverage", not missing, stage="coverage",
            evidence={"profile_set": args.profile_set, "required": list(required),
                      "available": sorted(available), "missing": missing})
    with (args.output / "e1-wire-bytes.jsonl").open("x", encoding="utf-8") as stream:
        rows = []
        for code in required:
            if code not in available:
                rec.add(f"e1-{code}", False, stage="e1",
                        detail="required fixture directory is missing")
                continue
            record = _run_one_e1(rec, code, available[code], stream, file_sha(args.library))
            if record is not None:
                rows.append(record)
        if args.profile_set == "p2-only":
            for code in ("P3", "P4"):
                rec.not_covered(f"e1-{code}", "campaign issued only P0-P2")
        rec.add("e1-profiles",
                len(rows) == len(required) and all(row["passed"] for row in rows),
                stage="handshake", evidence={"profiles": [row["profile"] for row in rows],
                                             "required": list(required)})


def phase_strict(rec: Recorder, args, fixtures: Path, p2, client_root, library_sha: str):
    if client_root is None:
        rec.add("strict-p2-in-process", False, stage="trust",
                detail="strict P2 requires an explicit --client-root")
        return
    result = HybridConnection.run(p2, trusted_root=client_root, expected_name="server.example")
    evidence = strict_evidence(result, library_sha)
    evidence["trusted_root_source"] = str(args.client_root or "fixture-provisioned test anchor")
    ok, reasons = strict_p2_ok(
        evidence, library_sha=library_sha, threads=args.threads,
        requested_backend=args.backend, scheme_id=p2.pq().scheme_id,
        root_sha=sha(load_trusted_root(client_root).public_bytes(serialization.Encoding.DER)),
    )
    evidence["predicate_reasons"] = reasons
    (args.output / "strict-p2.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rec.add("strict-p2-in-process", ok, stage="handshake", evidence=evidence)


def phase_tcp(rec: Recorder, args, fixtures: Path, configs, p2, client_root, library_sha: str):
    if client_root is None:
        rec.add("strict-p2-loopback-tcp", False, stage="trust",
                detail="strict TCP requires an explicit --client-root")
        return
    root_sha = sha(load_trusted_root(client_root).public_bytes(serialization.Encoding.DER))
    tcp = run_over_tcp(p2, trusted_root=client_root, expected_name="server.example")
    report = tcp_evidence(tcp)
    ok, reasons = tcp_ok(
        report, library_sha=library_sha, threads=args.threads,
        requested_backend=args.backend, scheme_id=p2.pq().scheme_id, root_sha=root_sha,
    )
    report["predicate_reasons"] = reasons
    (args.output / "tcp-p2.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rec.add("strict-p2-loopback-tcp", ok, stage="tcp", evidence=report)

    if args.profile_set == "full":
        if not (fixtures / "slh-dsa-sm3-128s/root.der").is_file():
            rec.add("large-certificate-fragmentation", False, stage="tcp",
                    detail="full profile set requires the 128s fixture")
            return
        p3_root = root_for(fixtures, "slh-dsa-sm3-128s")
        tcp3 = run_over_tcp(configs["P3"], trusted_root=p3_root, expected_name="server.example")
        records = [m for m in tcp3.messages if m.name == "Certificate"]
        rec.add("large-certificate-fragmentation",
                tcp3.error is None and tcp3.server_error is None and tcp3.application_ok
                and tcp3.exporters_match is True and len(records) > 1,
                stage="tcp", evidence={"certificate_records": len(records),
                                       "certificate_bytes": sum(m.message_bytes for m in records),
                                       "server_error": tcp3.server_error,
                                       "exporters_match": tcp3.exporters_match})
    else:
        rec.not_covered("large-certificate-fragmentation",
                        "campaign issued only P0-P2; no 128s certificate to fragment")


def phase_fixture(rec: Recorder, args, fixtures: Path, library_sha: str):
    from tools.alt_chain_fixtures import verify as verify_fixtures
    verify_fixtures(SimpleNamespace(fixtures=fixtures, library=args.library,
                                    output=args.output / "fixture-verification.json",
                                    threads=args.threads, backend=args.backend))
    payload = json.loads((args.output / "fixture-verification.json").read_text(encoding="utf-8"))
    rows = payload.get("rows") or []
    by_key = {(row.get("algorithm"), row.get("verifier")): row for row in rows}
    if args.profile_set == "full":
        expected = {(SLH, "native"), (SLH, "python"),
                    ("slh-dsa-sm3-128s", "native"), ("slh-dsa-sm3-128s", "python"),
                    ("ml-dsa-44", "provider")}
    else:
        expected = {(SLH, "native"), (SLH, "python")}
        for key in (("slh-dsa-sm3-128s", "native"), ("slh-dsa-sm3-128s", "python"),
                    ("ml-dsa-44", "provider")):
            rec.not_covered(f"fixture-{key[0]}-{key[1]}",
                            "campaign issued only the 128-24 fixture set")
    for key in sorted(expected):
        row = by_key.get(key)
        if row is None:
            rec.add(f"fixture-{key[0]}-{key[1]}", False, stage="fixture-verification",
                    detail="required fixture verification row is missing")
            continue
        rec.add(f"fixture-{key[0]}-{key[1]}",
                row.get("checked_edges") == 2 and row.get("passed") is True,
                stage="fixture-verification",
                evidence={"checked_edges": row.get("checked_edges"),
                          "verifiers": row.get("verifiers")})
    rec.add("fixture-verification-rows", len(rows) >= len(expected),
            stage="fixture-verification",
            evidence={"rows": len(rows), "expected": len(expected),
                      "library_sha256": payload.get("sources_sha256", {})})


def run_phase(rec: Recorder, name: str, action) -> dict:
    try:
        action()
        return {"phase": name, "status": "passed"}
    except Exception as error:  # noqa: BLE001 - the phase boundary records it
        detail = f"{type(error).__name__}: {error}"
        trace = traceback.format_exc()
        rec.add(f"phase-{name}", False, stage=name, detail=detail,
                evidence={"phase": name, "traceback": trace,
                          "tls_module": str(Path(tls.__file__).resolve())})
        print(json.dumps({"phase": name, "status": "failed", "error": detail}), flush=True)
        return {"phase": name, "status": "failed", "error": detail, "traceback": trace}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--client-root", type=Path,
                        help="independent client root; required by --profile-set full")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--backend", type=int, default=0, choices=(0, 1, 2, 5))
    parser.add_argument("--handshake-signer", default="falcon-512")
    parser.add_argument("--profile-set", choices=("full", "p2-only"), default="full")
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    args.library = args.library.resolve()
    fixtures = args.fixtures.resolve()
    client_root = args.client_root.resolve() if args.client_root else None
    client_root_source = "explicit --client-root" if client_root is not None else None

    recorder = Recorder()
    if args.profile_set == "full" and client_root is None:
        recorder.add("client-root-required", False, stage="trust",
                     detail="full strict acceptance requires an explicit --client-root")
    elif client_root is None:
        client_root = fixtures / SLH / "root.der"
        client_root_source = "fixture-provisioned test anchor"
        recorder.add("client-root-source", True, stage="trust",
                     evidence={"source": client_root_source, "path": str(client_root)})

    source_before = source_hashes()
    fixture_before = tree_hashes(fixtures)
    library_before = file_sha(args.library) if args.library.is_file() else None

    configs = {code: policy(config, args)
               for code, config in profiles(fixtures, handshake_signer=args.handshake_signer).items()}
    p2 = configs["P2"]
    library_sha = library_before or ""

    phases = [
        ("fixture-verification", lambda: phase_fixture(recorder, args, fixtures, library_sha)),
        ("positive", lambda: phase_e1(recorder, args, fixtures, configs)),
        ("strict-p2", lambda: phase_strict(recorder, args, fixtures, p2, client_root, library_sha)),
        ("tcp", lambda: phase_tcp(recorder, args, fixtures, configs, p2, client_root, library_sha)),
        ("negative", lambda: run_negative(recorder, args, fixtures, configs, p2, args.profile_set)),
    ]
    phase_results = [run_phase(recorder, name, action) for name, action in phases]

    source_after = source_hashes()
    fixture_after = tree_hashes(fixtures)
    library_after = file_sha(args.library) if args.library.is_file() else None
    source_unchanged = source_before == source_after
    fixtures_unchanged = fixture_before == fixture_after
    library_unchanged = library_before is not None and library_before == library_after

    counts = recorder.junit(args.output / "junit.xml")
    failed = [case for case in recorder.cases if case["status"] == "failed"]
    unexpected_skips = [case for case in recorder.cases
                        if case["status"] in ("not_covered", "skipped")
                        and args.profile_set == "full"]
    phase_failures = [result for result in phase_results if result["status"] != "passed"]
    coverage_missing = next((case["evidence"].get("missing", []) for case in recorder.cases
                             if case["name"] == "profile-coverage"), [])
    passed = (not phase_failures and not failed and not unexpected_skips
              and not coverage_missing and source_unchanged and fixtures_unchanged
              and library_unchanged and bool(recorder.cases))
    report = {
        "schema": "a15-ds-acceptance-v2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": sys.argv,
        "passed": passed,
        "profile_set": args.profile_set,
        "required_profiles": list(REQUIRED_FULL if args.profile_set == "full" else REQUIRED_P2),
        "coverage_missing": coverage_missing,
        "client_root": str(client_root) if client_root is not None else None,
        "client_root_source": client_root_source,
        "fixtures": str(fixtures),
        "library": str(args.library),
        "library_sha256": library_after,
        "threads": args.threads,
        "requested_backend": args.backend,
        "policy": p2.alt_policy(),
        "summary": counts,
        "cases": recorder.cases,
        "not_covered": [case for case in recorder.cases
                        if case["status"] in ("not_covered", "skipped")],
        "phase_results": phase_results,
        "phase_failures": phase_failures,
        "environment": {
            "executable": sys.executable,
            "version": sys.version,
            "platform": sys.platform,
            "cwd": os.getcwd(),
            "pythonpath": os.environ.get("PYTHONPATH"),
            "sys_path": list(sys.path),
        },
        "modules": module_origins(),
        "hashes": {
            "source_before": source_before,
            "source_after": source_after,
            "fixtures_before": fixture_before,
            "fixtures_after": fixture_after,
            "library_before": library_before,
            "library_after": library_after,
        },
        "source_unchanged": source_unchanged,
        "fixtures_unchanged": fixtures_unchanged,
        "library_unchanged": library_unchanged,
        "scope": "real in-process and loopback TCP handshakes; field-level predicates; "
                 "not_covered is reported and never counted as passed",
    }
    (args.output / "acceptance.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": passed, "cases": len(recorder.cases),
                      "failed": len(failed), "not_covered": len(report["not_covered"]),
                      "output": str(args.output)}, ensure_ascii=False), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
