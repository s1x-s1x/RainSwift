"""Independent exact C7 transcription from reviewed 00b / 02 / 03.

Written before opening the main ledger or its producing script.  No import from
the main implementation is permitted.  This file computes reduction errors,
not Rain OWF advantage or an attack work factor.
"""
from fractions import Fraction as F
from math import comb

# 00b section 2: (Rain rounds, trees, grinding bits, total leaves, maximum leaves)
SETS = {
    "rain3_fast": (3, 21, 5, 1248, 64),
    "rain3_bal": (3, 17, 7, 2432, 256),
    "rain3_short": (3, 11, 12, 17408, 2048),
    "rain4_fast": (4, 18, 6, 2048, 128),
    "rain4_bal": (4, 18, 8, 1920, 128),
    "rain4_short": (4, 11, 12, 17408, 2048),
}


def ceiling_log_two(number):
    assert isinstance(number, int) and number >= 1
    return (number - 1).bit_length()


def grinding_limit(lam, grinding_bits, signatures):
    """C3, using only integer arithmetic; includes the 32-bit counter cap."""
    assert signatures >= 0
    raw = (1 << grinding_bits) * (lam + ceiling_log_two(max(1, signatures)))
    rounded = raw + (-raw % 4)
    return min(1 << 32, rounded)


def clip_one(value):
    return min(F(1), value)


def calculate(set_name, *, ac, amu, a1, a2, adelta, a4, as_, aic, qsig):
    """B0--B9 and C1--C7; aic is the sum of both IC directions.

    adelta is the full raw adversarial challenge query count, including failed
    and extra batch attempts.  qsig is all signing requests (cache misses are
    at most this count).  Inputs are query upper bounds, not exact row counts.
    """
    arguments = (ac, amu, a1, a2, adelta, a4, as_, aic, qsig)
    assert all(isinstance(x, int) and x >= 0 for x in arguments)
    rounds, tau, grind, leaves, max_leaves = SETS[set_name]
    lam, mask_bits = 128, 48
    size = 1 << lam
    ell = rounds * lam
    tape_bits = ell + 2 * lam + mask_bits
    blocks = (tape_bits + lam - 1) // lam
    active = lam - grind
    lengths = (5 * lam + 64, 3 * lam + 64)
    # Independent reconstruction of the mixed-height forest's total leaf count.
    base, high = divmod(active, tau)
    assert leaves == high * (1 << (base + 1)) + (tau - high) * (1 << base)
    assert max_leaves == 1 << (base + bool(high))
    sign = (blocks + 3) * leaves - tau
    verify_effective = (blocks + 3) * (leaves - tau) - 2 * active
    verify = verify_effective + tau
    hidden_labels = 1 + active + tau
    planted = 2 * active + (blocks + 2) * tau
    assert verify + planted == sign + tau  # C4, including one dummy per tree.
    G = grinding_limit(lam, grind, qsig)
    tail_exponent = G // (1 << grind)
    P = aic + blocks * leaves * a1 + (qsig + 1) * verify
    PH = aic + qsig * (sign + tau) + verify
    T = 1 + PH + qsig * hidden_labels
    h = {
        "c": ac + (qsig + 1) * (tau + 1),
        "mu": amu + qsig + 1,
        "4": a4 + qsig + 1,
        "1": a1 + qsig + 1,
        "2": a2 + qsig + 1,
        "delta": adelta + qsig * G + 1,
    }
    chain = {
        "collision_c": F(comb(h["c"], 2), 1 << (2 * lam)),
        "collision_mu": F(comb(h["mu"], 2), 1 << (2 * lam)),
        "late_c": F((tau + 1) * a1 * h["c"], 1 << (2 * lam)),
        "collision_1": F(comb(h["1"], 2), 1 << lengths[0]),
        "late_1": F(a2 * h["1"], 1 << lengths[0]),
        "collision_2": F(comb(h["2"], 2), 1 << lengths[1]),
        "late_2": F(adelta * h["2"], 1 << lengths[1]),
    }
    program = {
        "iv_pre": F(qsig * h["4"], size),
        "iv": F(qsig * h["1"], size),
        "h2_prefix": F(qsig * h["2"], 1 << lengths[0]),
        "delta_prefix": F(qsig * h["delta"], 1 << lengths[1]),
    }
    n = rounds + 1
    epsilon_V_parts = {
        "uniform": F(1, 1 << (lam + mask_bits)),
        "polynomial": F((n - 1) * (2 * n - 1), 1 << (lam + 64)),
    }
    epsilon_Z_parts = {
        "uniform": F(1, size),
        "polynomial": F((rounds - 1) ** 2, 1 << (lam + 64)),
    }
    au = {k: a1 * comb(tau, 2) * v for k, v in epsilon_V_parts.items()}
    z = {k: a2 * v for k, v in epsilon_Z_parts.items()}
    challenge = {
        "all_fixed": F(adelta, size),
        "two_roots": F(2 * adelta, size),
        "last_verify": F(1, size),
    }
    pair_raw = F(P * (P - 1), 2 * (size - P)) if P < size else None
    late_raw = F(a1 * leaves * P, size - P) if P < size else None
    if qsig == 0:
        hide_raw = F(0)
    elif T < size:
        hide_raw = F(4 * T * T, size - T)
    else:
        hide_raw = None
    errors = {
        "hide": F(1) if hide_raw is None else clip_one(hide_raw),
        "program": sum(program.values(), F(0)),
        "tail": F(qsig, 1 << tail_exponent),
        "chain": sum(chain.values(), F(0)),
        "pair": F(1) if pair_raw is None else clip_one(pair_raw),
        "late": F(1) if late_raw is None else clip_one(late_raw),
        "AU": sum(au.values(), F(0)),
        "ZHash": sum(z.values(), F(0)),
        "challenge": sum(challenge.values(), F(0)),
    }
    total_raw = sum(errors.values(), F(0))
    return {
        "parameter": {"R": rounds, "tau": tau, "g": grind, "D": active,
            "N": leaves, "N_max": max_leaves, "r_blk": blocks, "lambda": lam,
            "b": mask_bits, "L1": lengths[0], "L2": lengths[1], "ell": ell,
            "L": tape_bits, "M": size},
        "counts": {"A_S": sign, "A_V_effective": verify_effective,
            "A_V": verify, "S0": hidden_labels, "J0": planted,
            "P": P, "P_H": PH, "T": T, "G": G,
            "tail_exponent": tail_exponent, "Rain_checks": as_ + a2,
            "h": h},
        "subterms": {"chain": chain, "program": program,
            "epsilon_V": epsilon_V_parts, "epsilon_Z": epsilon_Z_parts,
            "AU": au, "ZHash": z, "challenge": challenge},
        "raw_before_local_clipping": {"pair": pair_raw, "late": late_raw,
            "hide": hide_raw},
        "errors": errors,
        "raw_total": total_raw,
        "capped_total": clip_one(total_raw),
        "P_denominator_valid": P < size,
        "T_denominator_valid": T < size,
        "Rain_OWF_advantage": None,
    }
