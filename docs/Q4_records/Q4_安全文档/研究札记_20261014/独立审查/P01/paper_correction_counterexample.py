"""A finite algebra counterexample to literal rFAEST p10 Ext Step (4).

This is not a signature forgery and does not modify the protocol.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import time
from datetime import datetime, timezone
from pathlib import Path


def linear_hash(mask: int, value: int) -> int:
    return (mask & value).bit_count() & 1


def main() -> None:
    started = time.monotonic()
    configs = 0
    opening_checks = 0
    raw_u_abort_configs = 0
    first = None
    for flat in itertools.product(range(4), repeat=4):
        messages = (flat[:2], flat[2:])
        raw_u = tuple(pair[0] ^ pair[1] for pair in messages)
        raw_v = tuple(pair[1] for pair in messages)
        correction = (0, raw_u[0] ^ raw_u[1])
        corrected_u = tuple(raw_u[t] ^ correction[t] for t in range(2))
        assert corrected_u[0] == corrected_u[1]
        for hash_mask in range(4):
            configs += 1
            utilde = linear_hash(hash_mask, raw_u[0])
            vtilde = tuple(linear_hash(hash_mask, v) for v in raw_v)
            all_openings = []
            for beta in itertools.product(range(2), repeat=2):
                q = tuple(messages[t][beta[t] ^ 1] ^ (correction[t] if beta[t] else 0)
                          for t in range(2))
                accepted = all(linear_hash(hash_mask, q[t]) == (vtilde[t] ^ (beta[t] * utilde))
                               for t in range(2))
                assert accepted
                assert all(q[t] == (raw_v[t] ^ (raw_u[0] if beta[t] else 0)) for t in range(2))
                all_openings.append({"beta": beta, "q": q, "vhash_accepts": accepted})
                opening_checks += 1
            if raw_u[0] != raw_u[1]:
                raw_u_abort_configs += 1
                if first is None and hash_mask == 1:
                    first = {"messages": messages, "raw_u": raw_u, "raw_v": raw_v,
                             "c": correction, "corrected_u": corrected_u,
                             "hash": "low bit, H(x)=x&1", "utilde": utilde,
                             "vtilde": vtilde, "openings": all_openings,
                             "literal_paper_step4": "bottom_abort: raw u values unequal",
                             "new_extractor": "free trees agree on a_t=U_t xor c_t"}
            if time.monotonic() - started > 10:
                raise TimeoutError("10 second review-check budget exceeded")
    assert configs == 1024
    assert opening_checks == 4096
    assert raw_u_abort_configs == 768
    assert first is not None
    report = {
        "kind": "AI internal independent refutation check",
        "scope": "rFAEST p10 section4.4 Ext Step(4) omitted correction, not a signature attack",
        "configs": configs, "opening_checks": opening_checks,
        "literal_step4_abort_despite_all_openings_valid": raw_u_abort_configs,
        "first_counterexample": first,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "status": "PASS: literal-paper counterexample reproduced; corrected affine relation holds"
    }
    target = Path(__file__).with_name("paper_correction_counterexample_20261014.json")
    with target.open("x", encoding="utf-8") as out:
        json.dump(report, out, ensure_ascii=False, indent=2)
        out.write("\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
