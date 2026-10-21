"""Small functional resource and CA failure regressions, without SLH signing.

The local record tests exercise AES-GCM and the incremental client. The HMAC
signer below only isolates callback control flow; it is not a PQ provider.
"""

import datetime as dt
import hmac
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from tls import alt_chain
from tls.config import HybridTLSConfig
from tls.credentials import CertificateAuthority, ServerCredentials
from tls.errors import HandshakeError
from tls.handshake.client import HybridClient, ServerFlightLimits
from tls.handshake.server import HybridServer
from tls.record.aead import CONTENT_TYPE_HANDSHAKE, RecordLayer, get_aead_suite


def fragment_client(limits):
    config = HybridTLSConfig(pq_enabled=False)
    client = HybridClient(config, CertificateAuthority(config.classical()), flight_limits=limits)
    suite = get_aead_suite("aes-128-gcm")
    sender = RecordLayer(suite, bytes(16), bytes(12))
    client.server_records = RecordLayer(suite, bytes(16), bytes(12))
    client.client_records = RecordLayer(suite, bytes(16), bytes(12))
    return client, sender


def send(client, sender, payload):
    client.receive_server_record(sender.seal(CONTENT_TYPE_HANDSHAKE, payload))


@pytest.mark.parametrize("field", ["max_records", "max_bytes"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "10", None])
def test_flight_limit_requires_finite_positive_integer(field, value):
    with pytest.raises(ValueError, match=field):
        ServerFlightLimits(**{field: value})


def test_record_budget_rejects_before_another_decryption_and_bounds_metadata():
    client, sender = fragment_client(ServerFlightLimits(max_records=3, max_bytes=32))
    for payload in (b"\x08", b"\x00", b"\x00"):
        send(client, sender, payload)
    assert client.server_flight_records == len(client.server_flight_fragments) == 3
    assert client.server_flight_bytes == 3
    assert client.server_records.sequence == 3
    with pytest.raises(HandshakeError, match="record budget"):
        send(client, sender, b"\x10")
    assert client.server_records.sequence == 3
    assert len(client.server_flight_fragments) == 3
    assert client._handshake_buffer == b""
    assert not client.server_flight_complete
    with pytest.raises(HandshakeError, match="already failed"):
        send(client, sender, b"\x10")
    with pytest.raises(HandshakeError, match="already failed"):
        client.finish_server_flight()
    with pytest.raises(HandshakeError, match="already failed"):
        client.send_client_finished()


def test_byte_budget_exact_boundary_then_rejects_without_buffer_or_metadata_growth():
    client, sender = fragment_client(ServerFlightLimits(max_records=8, max_bytes=8))
    send(client, sender, b"\x08\x00\x00\x10")
    send(client, sender, bytes(4))
    assert client.server_flight_bytes == len(client._handshake_buffer) == 8
    with pytest.raises(HandshakeError, match="byte budget"):
        send(client, sender, b"x")
    assert client.server_flight_records == len(client.server_flight_fragments) == 2
    assert client.server_flight_bytes == 8
    assert client._handshake_buffer == b""
    assert client.application_client_records is None
    assert client.application_server_records is None


def test_message_limit_remains_independent_of_total_flight_budget():
    client, sender = fragment_client(ServerFlightLimits())
    # Only a header is supplied: the oversized announced body is never allocated.
    with pytest.raises(HandshakeError, match="message exceeds"):
        send(client, sender, b"\x08\x10\x00\x00")
    assert client._handshake_buffer == b""
    assert not client.server_flight_complete


def test_valid_classical_flight_accepts_exact_record_and_byte_budgets():
    config = HybridTLSConfig(pq_enabled=False)
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config)
    client = HybridClient(config, authority)
    server = HybridServer(config, credentials, credentials.bind_to(authority))
    client.receive_server_hello(server.receive_client_hello(client.create_client_hello()))
    flight = server.send_authenticated_flight()
    client.flight_limits = ServerFlightLimits(max_records=len(flight),
                                            max_bytes=sum(len(fragment) for _, _, fragment in flight))
    client.receive_server_flight([record for _, record, _ in flight])
    assert client.server_flight_complete
    assert client.server_flight_records == client.flight_limits.max_records
    assert client.server_flight_bytes == client.flight_limits.max_bytes
    assert client.transcript.hash() == server.transcript.hash()
    server.receive_client_finished(client.send_client_finished())
    assert client.exporter_secret("limits", b"") == server.exporter_secret("limits", b"")


def test_declared_end_of_truncated_flight_is_terminal():
    client, sender = fragment_client(ServerFlightLimits())
    send(client, sender, b"\x08")
    with pytest.raises(HandshakeError, match="truncated"):
        client.finish_server_flight()
    with pytest.raises(HandshakeError, match="already failed"):
        send(client, sender, b"\x00")


class CallbackTestSigner:
    name = "ml-dsa-44"
    signature_bytes = 32

    def sign(self, secret, message):
        return hmac.digest(secret, message, "sha256")

    def verify(self, public, message, signature):
        return hmac.compare_digest(self.sign(public, message), signature)


def issue_options(ledger, signer, finalizer):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    return dict(name=signer.name, signer=signer, secret_key=b"callback-test-key",
                issuer_public_key=b"callback-test-key", before_sign=ledger.reserve,
                after_sign=finalizer, subject="callback-test", issuer=alt_chain._name("callback-test"),
                subject_key=key.public_key(), issuer_key=key, ca=True, path_length=0, serial=456,
                valid_from=now - dt.timedelta(days=1), valid_to=now + dt.timedelta(days=1))


def new_ledger(tmp_path):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from tools.signing_budget import SigningBudget
    return SigningBudget(tmp_path / "callback-test.sqlite")


@pytest.mark.parametrize("stage", ["sign", "verify", "assemble"])
@pytest.mark.parametrize("finalization_error", [RuntimeError, KeyboardInterrupt])
def test_ca_finalizer_error_preserves_original_failure_and_consumed_reservation(tmp_path, monkeypatch, stage,
                                                                               finalization_error):
    ledger = new_ledger(tmp_path)
    signer = CallbackTestSigner()
    original = ValueError(f"primary {stage} failure")
    if stage == "sign":
        def sign(*args):
            raise original
        monkeypatch.setattr(signer, "sign", sign)
    elif stage == "verify":
        def verify(*args):
            raise original
        monkeypatch.setattr(signer, "verify", verify)
    else:
        assemble = alt_chain._issue_fixed
        def broken_assembly(**kwargs):
            if any(getattr(ext, "oid", None) == alt_chain.ALT_SIGNATURE_VALUE
                   for ext in kwargs.get("extra", ())):
                raise original
            return assemble(**kwargs)
        monkeypatch.setattr(alt_chain, "_issue_fixed", broken_assembly)
    attempts = []
    def finalizer(receipt, signature):
        attempts.append((receipt, signature))
        raise finalization_error("test ledger write failure")
    with pytest.raises(ValueError) as raised:
        alt_chain.issue_alt_certificate(**issue_options(ledger, signer, finalizer))
    assert raised.value is original
    assert len(attempts) == 1 and attempts[0][1] is None
    assert original.__notes__ == ["CA budget finalization also failed: " + finalization_error.__name__
                                 + ": test ledger write failure"]
    state = ledger.status()[0]
    assert state["used"] == 1 and state["count_reconciled"]
    assert state["states"] == {"reserved": 1}


def test_ca_signing_interrupt_is_preserved_if_failure_finalizer_also_fails(tmp_path, monkeypatch):
    ledger = new_ledger(tmp_path)
    signer = CallbackTestSigner()
    original = KeyboardInterrupt("test signing cancellation")
    def sign(*args):
        raise original
    monkeypatch.setattr(signer, "sign", sign)
    def finalizer(receipt, signature):
        raise RuntimeError("test ledger write failure")
    with pytest.raises(KeyboardInterrupt) as raised:
        alt_chain.issue_alt_certificate(**issue_options(ledger, signer, finalizer))
    assert raised.value is original and original.__notes__
    state = ledger.status()[0]
    assert state["used"] == 1 and state["states"] == {"reserved": 1}


def test_ca_successful_signature_finalizer_failure_returns_no_certificate_and_stays_charged(tmp_path):
    ledger = new_ledger(tmp_path)
    signer = CallbackTestSigner()
    attempts = []
    def finalizer(receipt, signature):
        attempts.append((receipt, signature))
        raise RuntimeError("test ledger commit failure")
    with pytest.raises(RuntimeError, match="commit failure"):
        alt_chain.issue_alt_certificate(**issue_options(ledger, signer, finalizer))
    assert len(attempts) == 1 and len(attempts[0][1]) == signer.signature_bytes
    state = ledger.status()[0]
    assert state["used"] == 1 and state["states"] == {"reserved": 1}
