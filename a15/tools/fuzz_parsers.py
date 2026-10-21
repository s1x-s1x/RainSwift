"""Bounded deterministic DER/handshake parser fuzz smoke; no network or keys.

This entry can also be called by a coverage-guided runner via fuzz_one_input.
It is a reproducible parser check, not a claim of exhaustive fuzz coverage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "base_tls"))
from tls import der
from tls.errors import DecodeError
from tls.wire import handshake_message, split_handshake_message

MAX_INPUT_BYTES = 4096


def fuzz_one_input(data):
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("fuzz input exceeds the local test budget")
    outcomes = {}
    try:
        items = der.elements(data)
    except der.DerError:
        outcomes["der"] = "rejected"
    else:
        assert b"".join(item.encoded for item in items) == data
        assert all(der.tlv(item.tag, item.value) == item.encoded for item in items)
        outcomes["der"] = "accepted"
    try:
        kind, body = split_handshake_message(data)
    except DecodeError:
        outcomes["handshake"] = "rejected"
    else:
        assert handshake_message(kind, body) == data
        outcomes["handshake"] = "accepted"
    # Specialized DER paths must return a typed value or a declared parse error.
    for name, parser in (("oid", der.oid_text), ("algorithm", der.algorithm_oid),
                         ("bit_string", der.bit_string_bytes), ("extension", der.extension_fields)):
        try:
            parser(data)
        except der.DerError:
            outcomes[name] = "rejected"
        else:
            outcomes[name] = "accepted"
    return outcomes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20261004)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 100000:
        parser.error("iterations must be 1..100000")
    rng = random.Random(args.seed)
    corpus = [b"", b"\x30\x00", der.oid("2.5.29.74"), der.bit_string(b"test"),
              der.algorithm_identifier("2.5.29.73"),
              der.tlv(0x30, der.oid("2.5.29.74") + der.tlv(4, b"test")),
              handshake_message(8, b"\0\0"), handshake_message(20, bytes(32)),
              b"\x30\x80", b"\x30\x82\0\x80", b"\x08\xff\xff\xff"]
    counts = {name: {"accepted": 0, "rejected": 0} for name in ("der", "handshake", "oid", "algorithm", "bit_string", "extension")}
    inputs_hash = hashlib.sha256()
    for index in range(args.iterations):
        if index % 3 == 0:
            data = rng.randbytes(rng.randrange(513))
        else:
            data = bytearray(rng.choice(corpus))
            if index % 3 == 1:
                for _ in range(rng.randrange(1, 5)):
                    if data:
                        data[rng.randrange(len(data))] ^= rng.randrange(1, 256)
                data.extend(rng.randbytes(rng.randrange(5)))
            data = bytes(data)
        inputs_hash.update(len(data).to_bytes(4, "big") + data)
        for name, outcome in fuzz_one_input(data).items():
            counts[name][outcome] += 1
    result = {"schema": "a15-bounded-parser-fuzz-v1", "passed": True,
              "iterations": args.iterations, "seed": args.seed, "max_input_bytes": MAX_INPUT_BYTES,
              "input_stream_sha256": inputs_hash.hexdigest(), "outcomes": counts,
              "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in (Path(__file__), ROOT / "base_tls/tls/der.py", ROOT / "base_tls/tls/wire.py")},
              "native_slh_calls": 0, "formal_performance_samples": 0,
              "scope": "Bounded randomized parser validation only; no exhaustive or coverage percentage claim"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps({"passed": True, "iterations": args.iterations, "parsers": len(counts)}))


if __name__ == "__main__":
    main()
