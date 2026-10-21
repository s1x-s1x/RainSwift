"""Validate prehash/digest equivalence against a freshly built native library."""
import argparse
import hashlib
import json
from pathlib import Path

from native import NativeSlhDsa


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest_for(name, message):
    if name == "shake128":
        return hashlib.shake_128(message).digest(32)
    if name == "shake256":
        return hashlib.shake_256(message).digest(64)
    return hashlib.new(name, message).digest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    library_hash = hashlib.sha256(args.library.read_bytes()).hexdigest()
    records = []
    # Public deterministic test-only seeds; never a production key or fixture.
    seeds = hashlib.shake_256(b"A1-5 local digest API regression 20261004").digest(48)
    message, context, randomness = b"local prehash/digest equivalence", b"API-boundary", bytes(16)
    for backend in (1, 2):
        with NativeSlhDsa(pid=201, threads=2, flags=backend | 0x100, library=args.library) as native:
            public, secret = native.keygen_internal(seeds[:16], seeds[16:32], seeds[32:])
            for name, expected_length in (("sha256", 32), ("sha512", 64), ("shake128", 32), ("shake256", 64), ("sm3", 32)):
                digest = digest_for(name, message)
                require(native.backend == backend, "requested native backend was not selected")
                require(native.lib.slh_prehash_bytes({"sha256": 1, "sha512": 2, "shake128": 3, "shake256": 4, "sm3": 5}[name]) == expected_length,
                        "native digest length differs for " + name)
                signature = native.sign_digest(digest, secret, hash_alg=name, context=context, addrnd=randomness)
                counterpart = native.sign_prehash(message, secret, hash_alg=name, context=context, addrnd=randomness)
                require(signature == counterpart, f"backend {backend} {name}: prehash/digest signature mismatch")
                require(native.verify_digest(digest, signature, public, hash_alg=name, context=context), "digest signature rejected")
                require(native.verify_prehash(message, signature, public, hash_alg=name, context=context), "prehash signature rejected")
                corrupted = bytes([digest[0] ^ 1]) + digest[1:]
                require(not native.verify_digest(corrupted, signature, public, hash_alg=name, context=context), "changed digest accepted")
                require(not native.verify_digest(digest, signature, public, hash_alg=name, context=b"wrong"), "changed context accepted")
                records.append({"backend_requested": backend, "backend_actual": native.backend,
                                "algorithm": name, "digest_bytes": len(digest),
                                "prehash_digest_equal": True, "verified": True,
                                "changed_digest_rejected": True, "changed_context_rejected": True})
    unchanged = library_hash == hashlib.sha256(args.library.read_bytes()).hexdigest()
    result = {"schema": "a15-local-digest-native-v1", "passed": len(records) == 10 and unchanged,
              "pid": 201, "scope": "Real native API equivalence and negative validation, toy parameter only",
              "library_sha256": library_hash, "library_unchanged": unchanged,
              "signing_calls": 20, "formal_performance_samples": 0, "rows": records}
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps({"passed": result["passed"], "algorithm_backend_pairs": len(records), "signing_calls": 20}))
    return int(not result["passed"] or not result["library_unchanged"])


if __name__ == "__main__":
    raise SystemExit(main())
