"""Independent bounded toy counterexample attempts; not a security proof.

GF(4) inverse constraint, one-field QS/VHash masks, and 4-counter grinding.
Only creates a new requested output path, never overwrites prior evidence.
"""
from __future__ import annotations
import argparse
from collections import Counter
from fractions import Fraction
from itertools import product
import hashlib
import json
from pathlib import Path
import time


def mul(a: int, b: int) -> int:
    z = 0
    while b:
        if b & 1:
            z ^= a
        b >>= 1
        a <<= 1
        if a & 4:
            a ^= 7  # x^2+x+1
    return z


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    dest = args.output.resolve()
    if not dest.is_relative_to(Path(__file__).resolve().parent):
        raise ValueError("output outside independent review directory")
    if dest.exists():
        raise FileExistsError(dest)
    start = time.monotonic()
    checks = 0
    contexts = 0
    eta_cases = ((0, 0, 0), (1, 1, 1), (1, 2, 3), (3, 2, 1))
    # Each context enumerates every underlying hidden mask, checking the full
    # joint output permutation, not three separate marginal uniformity claims.
    for delta, q0, q1, q2, theta, wx in product(range(4), range(4), range(4), range(4), range(4), range(1, 4)):
        wy = next(y for y in range(1, 4) if mul(wx, y) == 1)
        for eta in eta_cases:
            seen = set()
            for u0, u1, uqs, uvh in product(range(4), repeat=4):
                v0, v1 = q0 ^ mul(delta, u0), q1 ^ mul(delta, u1)
                vqs = q2 ^ mul(delta, uqs)
                d0, d1 = wx ^ u0, wy ^ u1
                z1 = mul(theta, mul(wy, v0) ^ mul(wx, v1))
                a = z1 ^ uqs
                ut = mul(eta[0], u0) ^ mul(eta[1], u1) ^ mul(eta[2], uqs) ^ uvh
                b_real = mul(theta, mul(v0, v1)) ^ vqs
                qc0, qc1 = q0 ^ mul(delta, d0), q1 ^ mul(delta, d1)
                b_verify = mul(theta, mul(qc0, qc1) ^ mul(delta, delta)) ^ q2 ^ mul(delta, a)
                assert b_real == b_verify
                seen.add((d0, d1, a, ut))
                checks += 1
            assert len(seen) == 4**4
            contexts += 1
        if time.monotonic() - start > 115:
            raise TimeoutError("120 second evidence budget")

    # All 4 x4 rows are generated. The lower challenge bit is the successful
    # output; the upper bit determines grinding acceptance.
    real = Counter()
    simulated = Counter()
    for raw in product(range(4), repeat=4):
        first = next((j for j, x in enumerate(raw) if x < 2), None)
        event = (first, raw)
        real[event] += 1
        for chosen_delta in range(2):
            rows = list(raw)
            if first is not None:
                rows[first] = chosen_delta
            simulated[(first, tuple(rows))] += 1
    assert set(real) == set(simulated)
    assert all(Fraction(real[k], 4**4) == Fraction(simulated[k], 2 * 4**4) for k in real)

    # Why the verifier's public zero dummy key belongs in the hiding events.
    # Normalize E_0(X_com)=0. For s=0 it forces com=0; for s!=0 com is uniform.
    M = 8
    real_dummy_match = Fraction(M + M - 1, M * M)
    sim_dummy_match = Fraction(1, M)
    dummy_gap = real_dummy_match - sim_dummy_match
    assert dummy_gap == Fraction(M - 1, M * M)

    result = {
        "status": "PASS",
        "scope": "AI internal independent toy counterexample attempts; no full-scheme distribution claim",
        "joint_mask": {
            "field": "GF(4), x^2+x+1",
            "valid_relation": "wx*wy=1",
            "contexts": contexts,
            "mask_instances": checks,
            "all_joint_maps_bijective": True,
            "all_real_b_equal_pk_verifier_b": True,
            "fixed_fields": ["delta", "q0", "q1", "q2", "theta", "VH coefficients", "valid witness"],
        },
        "grinding": {
            "lambda_bits": 2,
            "grind_bits": 1,
            "counter_count": 4,
            "real_outcomes": len(real),
            "sim_coin_outcomes": 2 * 4**4,
            "exact_joint_counter_and_x4_rows_equal": True,
            "exhaustion_mass": "1/16",
            "fixed_counter_zero_counterexample": "real P[ctr>0 | success]=7/15, fixed-zero simulator gives 0",
        },
        "dummy_key_counterexample": {
            "M": M,
            "real_match_probability": str(real_dummy_match),
            "sim_match_probability": str(sim_dummy_match),
            "distinguishing_gap": str(dummy_gap),
            "event_needed": "hidden leaf seed equals known key 0; public Verify itself queries it",
            "scope": "refutes a zero-loss lemma omitting dummy known key, not the current broad collision bound",
        },
        "elapsed_seconds": time.monotonic() - start,
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    dest.parent.mkdir(exist_ok=True, parents=True)
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
