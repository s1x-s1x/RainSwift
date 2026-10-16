"""Rain-VOLEitH as the post-quantum half of CertificateVerify.

The tests pin what the integration claims:

* the backend reports the frozen sizes and private code points, and the code points are
  distinct from every other scheme this implementation knows;
* the six published signature KATs verify through the backend, and corrupting the signature,
  the message or the public key makes them fail;
* keys and signatures round-trip for all six sets, every signature draws fresh randomness, and
  verification never raises on malformed input;
* a secret key cannot be used with another parameter set, and its bytes stay out of ``repr``;
* a missing library is a :class:`BackendUnavailableError`, never a silent fallback;
* full handshakes complete for every Rain set over the modelled certificate and over a real
  X.509 chain, and each corruption in the v9 tamper matrix, a swapped scheme field, a stripped
  post-quantum signature, and a client/server scheme mismatch are all rejected.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest

# Shared helpers from the handshake suite, so the tamper matrix here is the same one v9 runs.
from test_handshake import TAMPER_CASES, _corrupt_server_hello_kem_ciphertext, open_session, run_session, tamper_filter

from tls.config import HybridTLSConfig
from tls.credentials import CertificateAuthority, ServerCredentials
from tls.errors import BackendUnavailableError, HandshakeError, HybridTLSError
from tls.handshake.certificate_verify import HybridCertificateVerify
from tls.handshake.client import HybridClient
from tls.handshake.connection import HybridConnection
from tls.handshake.messages import CERTIFICATE_VERIFY, CertificateVerify
from tls.handshake.server import HybridServer
from tls.pq.rain_voleith import (
    RAIN_LIB_ENV,
    RAIN_SCHEME_IDS,
    RAIN_SETS,
    RainSecretKey,
    RainVoleith,
)
from tls.pq.signature import _SCHEME_IDS, get_pq_signer
from tls.wire import split_handshake_message

VECTORS = Path(__file__).resolve().parent / "vectors" / "rain_voleith"

#: Frozen signature sizes of the six Rain sets.
SIGNATURE_BYTES = {
    "rain3-fast": 4146,
    "rain3-bal": 3706,
    "rain3-short": 3014,
    "rain4-fast": 4112,
    "rain4-bal": 4080,
    "rain4-short": 3190,
}
DEMO_SET = "rain4-bal"


def _kat(name: str) -> tuple[bytes, bytes, bytes]:
    """Return ``(public_key, message, signature)`` from the published KAT for ``name``."""
    text = (VECTORS / f"sigkat_{name.replace('-', '_')}.txt").read_text(encoding="utf-8")
    fields = dict(re.findall(r"^(sk|pk|msg|sm) = ([0-9a-f]+)$", text, re.M))
    message, signed = bytes.fromhex(fields["msg"]), bytes.fromhex(fields["sm"])
    assert signed[: len(message)] == message, "NIST layout: sm = msg || signature"
    return bytes.fromhex(fields["pk"]), message, signed[len(message) :]


def _flip(data: bytes, position: int) -> bytes:
    return data[:position] + bytes([data[position] ^ 0x01]) + data[position + 1 :]


# ---------------------------------------------------------------------------- backend


@pytest.mark.parametrize("name", RAIN_SETS)
def test_rain_voleith_backend_reports_sizes_and_code_points(name):
    signer = get_pq_signer(name)
    assert isinstance(signer, RainVoleith)
    assert signer.post_quantum is True
    assert signer.public_key_bytes == 32
    assert signer.signature_bytes == SIGNATURE_BYTES[name]
    assert signer.scheme_id == RAIN_SCHEME_IDS[name] == _SCHEME_IDS[name]


def test_rain_voleith_code_points_are_distinct_and_private():
    values = list(_SCHEME_IDS.values())
    assert len(values) == len(set(values))
    xmss_range = set(range(0xFE00 + 1, 0xFE00 + 33))  # XMSS uses 0xFE00 + height, height 1..32
    assert not xmss_range & set(RAIN_SCHEME_IDS.values())
    assert all(0xFE00 <= value <= 0xFFFF for value in RAIN_SCHEME_IDS.values())


@pytest.mark.parametrize("name", RAIN_SETS)
def test_rain_voleith_published_kat_verifies(name):
    public_key, message, signature = _kat(name)
    assert len(signature) == SIGNATURE_BYTES[name]
    assert get_pq_signer(name).verify(public_key, message, signature) is True


@pytest.mark.parametrize("name", RAIN_SETS)
def test_rain_voleith_corrupted_kat_is_rejected(name):
    signer = get_pq_signer(name)
    public_key, message, signature = _kat(name)
    for position in (0, len(signature) // 2, len(signature) - 1):
        assert signer.verify(public_key, message, _flip(signature, position)) is False
    assert signer.verify(public_key, _flip(message, 0), signature) is False
    assert signer.verify(_flip(public_key, 0), message, signature) is False  # the Rain input
    assert signer.verify(_flip(public_key, 31), message, signature) is False  # the Rain output


@pytest.mark.parametrize("name", RAIN_SETS)
def test_rain_voleith_round_trip_is_randomized(name):
    signer = get_pq_signer(name)
    secret_key, public_key = signer.keygen()
    other_secret, other_public = signer.keygen()
    message = b"hybrid CertificateVerify input " + name.encode()
    first, second = signer.sign(secret_key, message), signer.sign(secret_key, message)

    assert len(public_key) == signer.public_key_bytes and len(first) == signer.signature_bytes
    assert first != second, "each signature draws fresh randomness"
    assert signer.verify(public_key, message, first) and signer.verify(public_key, message, second)
    assert signer.verify(public_key, message + b"!", first) is False
    assert signer.verify(other_public, message, first) is False
    assert public_key != other_public and secret_key != other_secret
    assert signer.verify(public_key, b"", signer.sign(secret_key, b"")) is True


@pytest.mark.parametrize(
    ("public_key", "message", "signature"),
    [
        pytest.param(None, b"m", b"s", id="none-key"),
        pytest.param(b"\0" * 32, None, b"s", id="none-message"),
        pytest.param(b"\0" * 32, b"m", None, id="none-signature"),
        pytest.param(b"\0" * 31, b"m", b"\0" * SIGNATURE_BYTES[DEMO_SET], id="short-key"),
        pytest.param(b"\0" * 32, b"m", b"\0" * (SIGNATURE_BYTES[DEMO_SET] - 1), id="short-signature"),
        pytest.param(b"\0" * 32, b"m", b"\0" * (SIGNATURE_BYTES[DEMO_SET] + 1), id="long-signature"),
        pytest.param(b"\0" * 32, b"m", b"\0" * SIGNATURE_BYTES[DEMO_SET], id="zero-signature"),
        pytest.param("not bytes", b"m", b"s", id="text-key"),
    ],
)
def test_rain_voleith_verify_never_raises(public_key, message, signature):
    assert get_pq_signer(DEMO_SET).verify(public_key, message, signature) is False


def test_rain_voleith_signature_of_another_set_is_rejected():
    rain3, rain4 = get_pq_signer("rain3-bal"), get_pq_signer(DEMO_SET)
    secret_key, public_key = rain3.keygen()
    signature = rain3.sign(secret_key, b"m")
    assert rain4.verify(public_key, b"m", signature) is False


def test_rain_voleith_secret_key_is_bound_to_its_set():
    rain3, rain4 = get_pq_signer("rain3-fast"), get_pq_signer(DEMO_SET)
    secret_key, _ = rain3.keygen()
    with pytest.raises(ValueError):
        rain4.sign(secret_key, b"m")
    with pytest.raises(ValueError):
        rain3.sign(secret_key.key, b"m")
    assert isinstance(secret_key, RainSecretKey)
    assert secret_key.key.hex() not in repr(secret_key)


def test_rain_voleith_missing_library_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv(RAIN_LIB_ENV, str(tmp_path / "absent" / "rain_voleith_tls.dll"))
    with pytest.raises(BackendUnavailableError):
        get_pq_signer(DEMO_SET)
    with pytest.raises(BackendUnavailableError):
        HybridConnection.run(HybridTLSConfig(pq_signer=DEMO_SET))


def test_rain_voleith_unknown_set_is_unavailable():
    with pytest.raises(BackendUnavailableError):
        RainVoleith("rain5-fast")


# --------------------------------------------------------------------------- handshake


@pytest.mark.parametrize("x509", [False, True], ids=["modelled-certificate", "x509-chain"])
@pytest.mark.parametrize("name", RAIN_SETS)
def test_rain_voleith_handshake_completes(name, x509):
    result = HybridConnection.run(HybridTLSConfig(kem="ml-kem-768", pq_signer=name, x509=x509))

    assert result.application_payload_ok is True
    assert result.exporters_match is True
    assert result.client.verification is not None
    assert result.client.verification.classic_ok and result.client.verification.pq_ok
    assert result.client.server_pq_public == result.server.credentials.pq_public
    assert len(result.server.credentials.pq_public) == 32
    if x509:
        assert result.client.chain is not None and len(result.client.chain.chain) == 2


@pytest.mark.parametrize(("tamper", "expected_step"), TAMPER_CASES)
def test_rain_voleith_tampered_handshake_is_rejected(tamper, expected_step):
    config = HybridTLSConfig(kem="ml-kem-768", pq_signer=DEMO_SET)
    with pytest.raises(HybridTLSError) as excinfo:
        run_session(
            config,
            frame_filter=tamper_filter(tamper),
            server_hello_filter=_corrupt_server_hello_kem_ciphertext if tamper == "kem-ciphertext" else None,
        )
    assert isinstance(excinfo.value, HandshakeError)
    assert excinfo.value.step == expected_step


def _rewrite_pq_half(**changes):
    """A frame filter that rewrites fields of the post-quantum half of CertificateVerify."""

    def rewrite(name: str, frame: bytes) -> bytes:
        if name != "CertificateVerify":
            return frame
        message_type, body = split_handshake_message(frame)
        assert message_type == CERTIFICATE_VERIFY
        payload = HybridCertificateVerify.decode(CertificateVerify.decode(body).payload)
        return CertificateVerify(payload=replace(payload, **changes).encode()).to_message()

    return rewrite


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"pq_scheme": RAIN_SCHEME_IDS["rain4-fast"]}, id="another-rain-scheme"),
        pytest.param({"pq_scheme": _SCHEME_IDS["ml-dsa-44"]}, id="ml-dsa-scheme"),
        pytest.param({"pq_signature": b""}, id="stripped-signature"),
        pytest.param({"pq_signature": b"\0" * SIGNATURE_BYTES[DEMO_SET]}, id="zero-signature"),
    ],
)
def test_rain_voleith_rewritten_pq_half_is_rejected(changes):
    config = HybridTLSConfig(kem="ml-kem-768", pq_signer=DEMO_SET)
    with pytest.raises(HybridTLSError) as excinfo:
        run_session(config, frame_filter=_rewrite_pq_half(**changes))
    assert isinstance(excinfo.value, HandshakeError)
    assert excinfo.value.step in ("certificate_verify", "decode")


def test_rain_voleith_honest_run_through_the_rewrite_helper_completes():
    """Control: the rewrite helper with no change leaves a valid handshake."""
    session = run_session(HybridTLSConfig(kem="ml-kem-768", pq_signer=DEMO_SET), frame_filter=_rewrite_pq_half())
    assert session.client.verification is not None and session.client.verification.accepted


def test_rain_voleith_scheme_mismatch_between_client_and_server_is_rejected():
    client_config = HybridTLSConfig(kem="ml-kem-768", pq_signer=DEMO_SET)
    server_config = HybridTLSConfig(kem="ml-kem-768", pq_signer="rain3-fast")
    authority = CertificateAuthority(client_config.classical())
    credentials = ServerCredentials(server_config)
    client = HybridClient(client_config, authority)
    server = HybridServer(server_config, credentials, credentials.bind_to(authority))
    with pytest.raises(HybridTLSError):
        client.receive_server_hello(server.receive_client_hello(client.create_client_hello()))
        client.receive_server_flight([record for _, record, _ in server.send_authenticated_flight(None)])


def test_rain_voleith_session_helper_shares_one_server_key():
    """Two handshakes on one credential: Rain keys are stateless, so both verify."""
    config = HybridTLSConfig(kem="ml-kem-768", pq_signer=DEMO_SET)
    first = open_session(config)
    second = open_session(config, credentials=first.credentials, certificate=first.certificate,
                          authority=first.authority)
    assert first.client.verification.accepted and second.client.verification.accepted
