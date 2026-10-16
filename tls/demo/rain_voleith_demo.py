"""Rain-VOLEitH as the post-quantum signature of the hybrid handshake, end to end.

Usage:
    python demo/rain_voleith_demo.py                    # rain4-bal
    python demo/rain_voleith_demo.py --pq rain3-fast

What it shows, in order:

1. the native library and the six Rain-VOLEitH parameter sets this machine can use;
2. a full handshake over a real X.509 chain (root, intermediate, leaf) whose leaf carries the
   32-byte Rain public key in the PQ-key extension: X25519 + ML-KEM-768 key exchange, ECDSA
   P-256 *and* Rain over the same CertificateVerify input, then one application-data exchange;
3. the same profile over a loopback TCP socket, counting how often the client blocks before the
   server is authenticated (1 means the handshake still takes one round trip);
4. the v9 tamper matrix with Rain in the PQ slot: each corrupted field is rejected at a named step.

Output hygiene follows demo/run_handshake.py: algorithms, lengths, timings and verdicts only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_handshake import run_tampered  # noqa: E402  (the v9 tamper driver, reused unchanged)

from tls.config import HybridTLSConfig  # noqa: E402
from tls.errors import BackendUnavailableError  # noqa: E402
from tls.handshake.connection import HybridConnection  # noqa: E402
from tls.pq.rain_voleith import RAIN_SETS, rain_library_path  # noqa: E402
from tls.pq.signature import get_pq_signer  # noqa: E402
from tls.transport.tcp import run_over_tcp  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pq", default="rain4-bal", choices=RAIN_SETS, help="Rain-VOLEitH parameter set")
    parser.add_argument("--kem", default="ml-kem-768", help="post-quantum KEM")
    return parser.parse_args(argv)


def show_library() -> None:
    """Print where the library came from and what it provides."""
    path = rain_library_path()
    root = Path(__file__).resolve().parents[1]
    shown = path.relative_to(root) if path.is_relative_to(root) else path.name  # no local paths in the output
    print(f"library: {shown}")
    for name in RAIN_SETS:
        signer = get_pq_signer(name)
        print(f"  {name:<12} scheme {signer.scheme_id:#06x}  public key {signer.public_key_bytes} B"
              f"  signature {signer.signature_bytes} B")


def show_handshake(config: HybridTLSConfig) -> bool:
    """One in-process handshake over the X.509 chain, with the per-message byte account."""
    result = HybridConnection.run(config)
    verification = result.client.verification
    print(f"\nhandshake over a real X.509 chain ({config.kem} + ecdsa-p256 + {config.pq_signer}):")
    print(f"  chain length: {len(result.client.chain.chain) if result.client.chain else 0} certificates;"
          f" leaf PQ key {len(result.server.credentials.pq_public)} B")
    for name, sender, plain, protection in result.flight_table():
        print(f"  {name:<20}{sender:<8}{plain:>7} B  (+{protection} B record protection)")
    print(f"  handshake bytes: {result.handshake_bytes}")
    print(f"  classical signature ok: {verification.classic_ok}; Rain signature ok: {verification.pq_ok};"
          f" accepted: {verification.accepted}")
    print(f"  application data round trip: {'ok' if result.application_payload_ok else 'FAILED'};"
          f" exporter secrets agree: {'yes' if result.exporters_match else 'NO'}")
    return bool(verification.accepted and result.application_payload_ok and result.exporters_match)


def show_tcp(config: HybridTLSConfig) -> bool:
    """The same profile over loopback TCP; the client's waits are counted on the socket."""
    sample = run_over_tcp(config)
    print("\nloopback TCP:")
    print(f"  client waits before the server is authenticated: {sample.waits_to_authenticated}"
          f" ({'one round trip' if sample.waits_to_authenticated == 1 else 'MORE than one round trip'})")
    print(f"  authenticated after {sample.authenticated_ms:.2f} ms; application data"
          f" {'ok' if sample.application_ok else 'FAILED'}; {sample.handshake_bytes} handshake bytes")
    return bool(sample.waits_to_authenticated == 1 and sample.application_ok and sample.error is None)


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    try:
        show_library()
    except BackendUnavailableError as error:
        print(f"Rain-VOLEitH is not available here: {error}")
        return 2
    config = HybridTLSConfig(kem=args.kem, pq_signer=args.pq, x509=True)
    ok = show_handshake(config)
    ok = show_tcp(config) and ok
    print("\ntamper matrix (modelled certificate, as in demo/run_handshake.py --tamper):")
    modelled = HybridTLSConfig(kem=args.kem, pq_signer=args.pq)
    for tamper in ("pq-signature", "classic-signature", "certificate", "kem-ciphertext"):
        print(f"  {tamper:<18}", end="", flush=True)
        ok = (run_tampered(modelled, tamper, modelled.classical()) == 0) and ok
    print("\nall steps behaved as expected" if ok else "\nSOMETHING UNEXPECTED HAPPENED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
