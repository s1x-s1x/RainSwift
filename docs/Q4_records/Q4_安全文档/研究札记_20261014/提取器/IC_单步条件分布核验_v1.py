"""Finite evidence-audit of ideal-cipher row conditionals, not signature forgery.

Exhaustive toy block size is 2 bits, two key labels, at most three prior rows.
One process, 110-second wall limit, target memory below 512 MiB.
The script creates a new output and never overwrites prior raw evidence.
"""

from __future__ import annotations

from fractions import Fraction
import hashlib
import itertools
import json
from pathlib import Path
import time


START = time.monotonic()
LIMIT = 110.0
M = 4


def partial_permutations(size):
    for inputs in itertools.combinations(range(M), size):
        for outputs in itertools.permutations(range(M), size):
            yield tuple(zip(inputs, outputs))


def inspect_states():
    states_by_size = [list(partial_permutations(size)) for size in range(4)]
    result = {
        "block_bits": 2,
        "key_labels": 2,
        "maximum_prior_rows": 3,
        "prior_partial_permutations_by_size": [len(a) for a in states_by_size],
        "prefix_states_seen": 0,
        "prefix_states_without_pair_collision": 0,
        "fresh_forward_transitions": 0,
        "fresh_inverse_transitions": 0,
        "pair_collision_step_checks": 0,
        "late_target_set_checks": 0,
        "maximum_pair_step_probability": "0",
        "maximum_late_step_probability": "0",
    }
    max_pair = Fraction(0)
    max_late = Fraction(0)
    all_pairs = set(itertools.product(range(M), repeat=2))
    for total in range(4):
        for count0 in range(total + 1):
            count1 = total - count0
            for rows0, rows1 in itertools.product(states_by_size[count0], states_by_size[count1]):
                result["prefix_states_seen"] += 1
                if set(rows0) & set(rows1):
                    continue
                result["prefix_states_without_pair_collision"] += 1
                tables = [dict(rows0), dict(rows1)]
                used_pairs = set(rows0) | set(rows1)
                unseen = sorted(all_pairs - used_pairs)
                # Targets are fixed before the next random answer. Include every
                # one- and two-target choice that has no current matching row.
                target_sets = [(p,) for p in unseen]
                target_sets.extend(itertools.combinations(unseen, 2))
                for key in range(2):
                    table = tables[key]
                    inverse = {y: x for x, y in table.items()}
                    other_rows = set(tables[1 - key].items())
                    denominator = M - len(table)
                    available_x = [x for x in range(M) if x not in table]
                    available_y = [y for y in range(M) if y not in inverse]
                    for direction in ["forward", "inverse"]:
                        known_halves = available_x if direction == "forward" else available_y
                        for chosen in known_halves:
                            outcomes = ([(chosen, y) for y in available_y]
                                        if direction == "forward"
                                        else [(x, chosen) for x in available_x])
                            assert len(outcomes) == denominator
                            result[f"fresh_{direction}_transitions"] += 1
                            hits = sum(pair in other_rows for pair in outcomes)
                            probability = Fraction(hits, denominator)
                            assert probability <= Fraction(total, denominator)
                            assert hits <= len(other_rows)
                            max_pair = max(max_pair, probability)
                            result["pair_collision_step_checks"] += 1
                            possible = set(outcomes)
                            for targets in target_sets:
                                hits = sum(pair in possible for pair in targets)
                                probability = Fraction(hits, denominator)
                                assert probability <= Fraction(len(targets), denominator)
                                # Distinct (x,y) pairs make the compatible
                                # unknown halves distinct, giving the exact count.
                                direct = sum(any(pair == target for target in targets)
                                             for pair in outcomes)
                                assert direct == hits
                                max_late = max(max_late, probability)
                                result["late_target_set_checks"] += 1
                if result["prefix_states_seen"] % 64 == 0 and time.monotonic() - START > LIMIT:
                    raise TimeoutError("finite evidence-audit wall limit reached")
    result["maximum_pair_step_probability"] = str(max_pair)
    result["maximum_late_step_probability"] = str(max_late)
    return result


def inverse_counterexample():
    # Old row under key A is (x=2,y=1). A new inverse query under
    # key B fixes y=1. Outputs y coincide with probability one, but
    # the whole (x,y) pair coincides with probability 1/M.
    old = (2, 1)
    outcomes = [(x, 1) for x in range(M)]
    output_collision = Fraction(sum(y == old[1] for x, y in outcomes), M)
    pair_collision = Fraction(sum(pair == old for pair in outcomes), M)
    assert output_collision == 1
    assert pair_collision == Fraction(1, M)
    return {
        "old_row": {"key": "A", "x": 2, "y": 1},
        "new_query": {"direction": "inverse", "key": "B", "chosen_y": 1},
        "equiprobable_new_rows": outcomes,
        "Pr_same_y": str(output_collision),
        "Pr_same_x_and_y": str(pair_collision),
        "scope": "Refutes global output-collision counting for inverse queries; not a forgery.",
    }


def main():
    target = Path(__file__).parent / "原始数据" / "IC_单步条件分布核验_v1_20261014.json"
    if target.exists():
        raise FileExistsError(f"raw evidence already exists: {target}")
    result = {
        "date_local": "2026-10-14",
        "timezone": "Asia/Shanghai",
        "activity": "finite evidence-audit",
        "limits": {"wall_seconds": LIMIT, "processes": 1, "target_memory_mib": 512},
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "status": "RUNNING",
    }
    error = None
    try:
        result["exhaustive"] = inspect_states()
        result["inverse_chosen_output_counterexample"] = inverse_counterexample()
        result["status"] = "PASS_FOR_STATED_FINITE_CHECKS"
    except Exception as exc:
        error = exc
        result["status"] = "FAIL_OR_LIMIT"
        result["error"] = repr(exc)
    finally:
        result["elapsed_seconds"] = round(time.monotonic() - START, 6)
        target.parent.mkdir(exist_ok=True)
        temporary = target.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(target)
        print(json.dumps({"status": result["status"], "output": str(target),
                          "elapsed_seconds": result["elapsed_seconds"]}, ensure_ascii=False))
    if error is not None:
        raise error


if __name__ == "__main__":
    main()
