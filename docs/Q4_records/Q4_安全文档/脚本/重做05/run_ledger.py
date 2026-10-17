#!/usr/bin/env python3
"""Q4 stage 05: exact C7 accounting, guarded by reviewed-file hashes.

All probabilities use Fraction. Decimal values are presentation only.
This module does not evaluate any profile on import.
"""
from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import io
import json
import os
import platform
import sys
import time
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from fractions import Fraction
from functools import lru_cache
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve()
Q4 = SCRIPT.parent.parent.parent
RAW_ROOT = Q4 / "原始数据" / "重做05"
DEFAULT_GATE = Q4 / "原始数据" / "重做04" / "review_gate.json"
R6 = Q4 / "原始数据" / "重做00b" / "R6_六组AES调用计数" / "run_metadata.json"
VERSION = "q4-c7-exact-ledger-v1"
LAMBDA = 128
B_BITS = 48
COUNTER_CAPACITY = 1 << 32
MEMORY_LIMIT = 512 * 1024 * 1024
REQUIRED_IDS = {"00b", "01", "02", "03", "04", "review_p01", "review_p02"}
RO_DOMAINS = ("c", "mu", "s", "4", "1", "2", "delta")
PARAMETER_SEEDS = (
    ("rain3_fast", 3, 21, 5, 4146),
    ("rain3_bal", 3, 17, 7, 3706),
    ("rain3_short", 3, 11, 12, 3014),
    ("rain4_fast", 4, 18, 6, 4112),
    ("rain4_bal", 4, 18, 8, 4080),
    ("rain4_short", 4, 11, 12, 3190),
)
PROFILE_SEEDS = {
    "KO20": (20, None),
    "CMA20": (20, 10),
    "CMA32": (32, 20),
    "CMA48": (48, 32),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ResourceGuard:
    """One Python process; cooperative checks between bounded work units."""

    def __init__(self, seconds: int) -> None:
        if not 1 <= seconds <= 120:
            raise ValueError("budget_seconds must be in 1..120")
        self.start = time.perf_counter()
        self.seconds = seconds
        self.peak_bytes = 0
        self.memory_metric = ""
        self._windows_counter = None
        if os.name == "nt":
            from ctypes import wintypes

            class PMCE(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                    ("PrivateUsage", ctypes.c_size_t),
                ]

            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE, ctypes.POINTER(PMCE), wintypes.DWORD
            ]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

            def query() -> int:
                item = PMCE()
                item.cb = ctypes.sizeof(item)
                if not psapi.GetProcessMemoryInfo(
                    kernel.GetCurrentProcess(), ctypes.byref(item), item.cb
                ):
                    raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo")
                return max(item.PeakWorkingSetSize, item.PeakPagefileUsage, item.PrivateUsage)

            self._windows_counter = query
            self.memory_metric = "max(peak working set, peak pagefile, private bytes)"
        else:
            self.memory_metric = "ru_maxrss"

    def check(self) -> None:
        if time.perf_counter() - self.start > self.seconds:
            raise RuntimeError("wall-clock resource budget exceeded")
        if self._windows_counter is not None:
            current = self._windows_counter()
        else:
            import resource
            current = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if sys.platform != "darwin":
                current *= 1024
        self.peak_bytes = max(self.peak_bytes, int(current))
        if self.peak_bytes > MEMORY_LIMIT:
            raise RuntimeError("512 MiB memory budget exceeded")

    def snapshot(self) -> dict[str, Any]:
        return {
            "processes": 1,
            "elapsed_seconds": round(time.perf_counter() - self.start, 6),
            "budget_seconds": self.seconds,
            "memory_limit_bytes": MEMORY_LIMIT,
            "peak_memory_bytes": self.peak_bytes,
            "memory_metric": self.memory_metric,
            "enforcement": "cooperative checks per hash chunk, test group, and case",
        }


def sha256_file(path: Path, guard: ResourceGuard | None = None) -> str:
    if any("粘贴的" in part for part in path.parts):
        raise ValueError("excluded filename/path")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            if guard is not None:
                guard.check()
    return digest.hexdigest()


def write_new(path: Path, text: str) -> None:
    """Never overwrite evidence; create a temporary file then replace a new name."""
    if path.exists():
        raise FileExistsError(path)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    if path.exists():
        raise FileExistsError(path)
    os.replace(temporary, path)


def floor_log2_ratio(n: int, d: int) -> int:
    if n <= 0 or d <= 0:
        raise ValueError("positive ratio required")
    candidate = n.bit_length() - d.bit_length()
    if candidate >= 0:
        if n < d << candidate:
            candidate -= 1
    elif n << (-candidate) < d:
        candidate -= 1
    return candidate


@lru_cache(maxsize=8192)
def fraction_record(value: Fraction) -> dict[str, Any]:
    with localcontext() as context:
        context.prec = 48
        displayed = Decimal(value.numerator) / Decimal(value.denominator)
        minus_log = None
        if value > 0:
            minus_log = format(-displayed.ln() / Decimal(2).ln(), ".10f")
        result = {
            "numerator": str(value.numerator),
            "denominator": str(value.denominator),
            "decimal_display_only": format(displayed, ".20E"),
            "minus_log2_display_only": minus_log,
            "floor_minus_log2_exact": (
                floor_log2_ratio(value.denominator, value.numerator) if value > 0 else None
            ),
        }
    return result


def jsonify(value: Any) -> Any:
    if isinstance(value, Fraction):
        return fraction_record(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: jsonify(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonify(item) for item in value]
    return value


def write_json(path: Path, value: Any) -> None:
    write_new(path, json.dumps(jsonify(value), ensure_ascii=False, indent=2) + "\n")


def int_strings(value: dict[str, int]) -> dict[str, str]:
    return {key: str(item) for key, item in value.items()}


def ceil_log2_nonnegative(n: int) -> int:
    if n < 0:
        raise ValueError("negative query budget")
    return (max(1, n) - 1).bit_length()


def round_up_to_four(n: int) -> int:
    return 4 * ((n + 3) // 4)


def grinding_cutoff(lam: int, g: int, qsig: int) -> tuple[int, bool, int]:
    if lam < 1 or g < 0 or qsig < 0:
        raise ValueError("invalid grinding parameters")
    requested = round_up_to_four((1 << g) * (lam + ceil_log2_nonnegative(qsig)))
    return min(COUNTER_CAPACITY, requested), requested > COUNTER_CAPACITY, requested


def dyadic_tail(qsig: int, g: int, cutoff: int) -> Fraction:
    if qsig == 0:
        return Fraction(0)
    exponent = cutoff // (1 << g)
    if exponent > 1_000_000:
        raise ValueError("exact denominator exceeds this bounded accounting tool's scope")
    return Fraction(qsig, 1 << exponent)


def choose_two(n: int) -> int:
    return n * (n - 1) // 2


def bounded_pair(p: int, m: int) -> tuple[Fraction | None, Fraction, bool]:
    if p >= m:
        return None, Fraction(1), True
    raw = Fraction(p * (p - 1), 2 * (m - p))
    return raw, min(Fraction(1), raw), False


def bounded_late(a1: int, n: int, p: int, m: int) -> tuple[Fraction | None, Fraction, bool]:
    if p >= m:
        return None, Fraction(1), True
    raw = Fraction(a1 * n * p, m - p)
    return raw, min(Fraction(1), raw), False


def bounded_hide(qsig: int, t: int, m: int) -> tuple[Fraction | None, Fraction, bool]:
    if qsig == 0:
        return Fraction(0), Fraction(0), False
    if t >= m:
        return None, Fraction(1), True
    raw = Fraction(4 * t * t, m - t)
    return raw, min(Fraction(1), raw), False


def programming_loss(qsig: int, h: dict[str, int], lam: int, l1: int, l2: int) -> Fraction:
    return qsig * (
        Fraction(h["4"] + h["1"], 1 << lam)
        + Fraction(h["2"], 1 << l1)
        + Fraction(h["delta"], 1 << l2)
    )


@dataclass(frozen=True)
class Parameters:
    name: str
    rounds: int
    tau: int
    g: int
    expected_signature_bytes: int

    def derived(self) -> dict[str, Any]:
        d = LAMBDA - self.g
        low, high_count = divmod(d, self.tau)
        heights = [low + 1] * high_count + [low] * (self.tau - high_count)
        leaf_counts = [1 << k for k in heights]
        n = sum(leaf_counts)
        ell = self.rounds * LAMBDA
        length = ell + 2 * LAMBDA + B_BITS
        r = (length + LAMBDA - 1) // LAMBDA
        a_s = (r + 3) * n - self.tau
        a_v_effective = (r + 3) * (n - self.tau) - 2 * d
        a_v = a_v_effective + self.tau
        s0 = 1 + d + self.tau
        j0 = 2 * d + (r + 2) * self.tau
        signature_bytes = (
            (self.tau - 1) * (length // 8)
            + (LAMBDA + B_BITS) // 8 + ell // 8
            + LAMBDA // 8 + (d + self.tau) * (LAMBDA // 8)
            + LAMBDA // 8 + LAMBDA // 8 + 4
        )
        if signature_bytes != self.expected_signature_bytes:
            raise AssertionError("signature length disagrees with stage 00b")
        if a_s != a_v_effective + j0 or a_s + self.tau != a_v + j0:
            raise AssertionError("C4 dummy-inclusive decomposition")
        return {
            "name": self.name, "R": self.rounds, "tau": self.tau, "g": self.g,
            "lambda_bits": LAMBDA, "b_bits": B_BITS, "D": d, "N": n,
            "heights_in_source_order": heights, "leaves_per_tree": leaf_counts,
            "ell_bits": ell, "L_bits": length, "r": r,
            "L1_bits": 5 * LAMBDA + 64, "L2_bits": 3 * LAMBDA + 64,
            "A_S": a_s, "A_V_effective": a_v_effective, "A_V": a_v,
            "dummy_per_verify": self.tau, "S0": s0, "J0": j0,
            "signature_bytes": signature_bytes,
            "aes_sign_by_role": {
                "root": self.tau, "tree": 2 * (n - self.tau),
                "com": n, "tape": r * n,
            },
            "aes_verify_by_role": {
                "root": 0, "tree": 2 * (n - self.tau - d),
                "com": n, "tape": r * (n - self.tau),
            },
        }


def validate_gate(path: Path, guard: ResourceGuard) -> dict[str, Any]:
    resolved = path.resolve()
    resolved.relative_to(Q4)
    if resolved.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("gate file exceeds bounded input size")
    gate = json.loads(resolved.read_text(encoding="utf-8-sig"))
    if gate.get("schema") != "q4-review-gate-v1" or gate.get("status") != "PASS":
        raise ValueError("stage 04 gate is not PASS in the supported schema")
    if gate.get("review_kind") != "internal_ai":
        raise ValueError("review kind must accurately identify internal AI review")
    stages = gate.get("stages", {})
    if any(stages.get(stage) != "PASS" for stage in ("00b", "01", "02", "03", "04")):
        raise ValueError("a required preceding stage has not passed")
    items = gate.get("files", [])
    if not isinstance(items, list):
        raise ValueError("gate files must be a list")
    checked: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in items:
        identity = item["id"]
        if identity in seen:
            raise ValueError("duplicate gate file id")
        seen.add(identity)
        item_path = Path(item["path"])
        if not item_path.is_absolute():
            item_path = Q4 / item_path
        item_path = item_path.resolve()
        item_path.relative_to(Q4)
        actual = sha256_file(item_path, guard)
        if actual != item["sha256"].lower():
            raise ValueError(f"reviewed file changed: {identity}")
        checked.append({"id": identity, "path": str(item_path), "sha256": actual})
    if not REQUIRED_IDS.issubset(seen):
        raise ValueError(f"missing review evidence ids: {sorted(REQUIRED_IDS - seen)}")
    guard.check()
    return {
        "status": "PASS", "gate": str(resolved), "gate_sha256": sha256_file(resolved, guard),
        "review_kind": "internal_ai", "stages": stages, "files": checked,
        "checked_at_utc": utc_now(),
    }


def check_native_counts(parameters: list[dict[str, Any]], guard: ResourceGuard) -> dict[str, Any]:
    data = json.loads(R6.read_text(encoding="utf-8-sig"))
    if data.get("status") != "PASS" or data.get("source_unchanged") is not True:
        raise ValueError("R6 evidence is not an unchanged-source PASS")
    records = {(item["set"], item["phase"]): item for item in data["counts"]}
    evidence = []
    for param in parameters:
        for phase, role_key, total_key in (
            ("Sign", "aes_sign_by_role", "A_S"),
            ("Verify", "aes_verify_by_role", "A_V"),
        ):
            measured = records[(param["name"], phase)]
            formula = param[role_key]
            matches = all(measured[role] == formula[role] for role in formula)
            matches = matches and sum(formula.values()) == param[total_key]
            if not matches or measured.get("pass") is not True:
                raise AssertionError(f"R6 role counts disagree: {param['name']} {phase}")
            evidence.append({
                "set": param["name"], "phase": phase,
                "calculated": formula, "reused_measured": {
                    key: measured[key] for key in formula
                },
                "total": param[total_key], "status": "PASS",
            })
        guard.check()
    return {
        "status": "PASS", "cases": len(evidence), "r6_path": str(R6),
        "r6_sha256": sha256_file(R6, guard),
        "evidence_type": "derived counts compared with existing R6; no new native execution",
        "records": evidence,
    }


def term(raw: Fraction | None, value: Fraction, equation: str, guard_triggered: bool = False) -> dict[str, Any]:
    return {
        "equation": equation, "raw_before_local_cap": raw, "value": value,
        "denominator_guard_triggered": guard_triggered,
        "saturated": guard_triggered or (raw is not None and raw >= 1),
        "local_cap_applied": raw is not None and value != raw,
    }


def profile_budgets(name: str) -> tuple[dict[str, int], int]:
    ro_exponent, sig_exponent = PROFILE_SEEDS[name]
    common = 1 << ro_exponent
    adversary = {domain: common for domain in RO_DOMAINS}
    adversary["IC"] = common
    qsig = 0 if sig_exponent is None else 1 << sig_exponent
    return adversary, qsig


def evaluate(param: dict[str, Any], profile: str, owf: Fraction | None) -> dict[str, Any]:
    a, qsig = profile_budgets(profile)
    n, tau, r = param["N"], param["tau"], param["r"]
    m = 1 << LAMBDA
    l1, l2 = param["L1_bits"], param["L2_bits"]
    cutoff, cutoff_capped, requested = grinding_cutoff(LAMBDA, param["g"], qsig)
    h = {
        "c": a["c"] + (qsig + 1) * (tau + 1),
        "mu": a["mu"] + qsig + 1,
        "s": a["s"],
        "4": a["4"] + qsig + 1,
        "1": a["1"] + qsig + 1,
        "2": a["2"] + qsig + 1,
        "delta": a["delta"] + qsig * cutoff + 1,
    }
    extra_tape = r * n * a["1"]
    p = a["IC"] + extra_tape + (qsig + 1) * param["A_V"]
    p_h = a["IC"] + qsig * (param["A_S"] + tau) + param["A_V"]
    t = 1 + p_h + qsig * param["S0"]
    chain_parts = {
        "coll_c": Fraction(choose_two(h["c"]), 1 << (2 * LAMBDA)),
        "coll_mu": Fraction(choose_two(h["mu"]), 1 << (2 * LAMBDA)),
        "late_hash_c": Fraction((tau + 1) * a["1"] * h["c"], 1 << (2 * LAMBDA)),
        "coll_1": Fraction(choose_two(h["1"]), 1 << l1),
        "late_chall1": Fraction(a["2"] * h["1"], 1 << l1),
        "coll_2": Fraction(choose_two(h["2"]), 1 << l2),
        "late_chall2": Fraction(a["delta"] * h["2"], 1 << l2),
    }
    chain = sum(chain_parts.values(), Fraction(0))
    raw_pair, pair, guarded_pair = bounded_pair(p, m)
    raw_late, late, guarded_late = bounded_late(a["1"], n, p, m)
    raw_hide, hide, guarded_hide = bounded_hide(qsig, t, m)
    epsilon_v_parts = {
        "uniform_output": Fraction(1, 1 << (LAMBDA + B_BITS)),
        "joint_roots": Fraction(param["R"] * (2 * (param["R"] + 1) - 1), 1 << (LAMBDA + 64)),
    }
    epsilon_z_parts = {
        "uniform_output": Fraction(1, m),
        "joint_roots": Fraction((param["R"] - 1) ** 2, 1 << (LAMBDA + 64)),
    }
    epsilon_v = sum(epsilon_v_parts.values(), Fraction(0))
    epsilon_z = sum(epsilon_z_parts.values(), Fraction(0))
    program_parts = {
        "ivpre_and_iv": Fraction(qsig * (h["4"] + h["1"]), m),
        "chall1_prefix": Fraction(qsig * h["2"], 1 << l1),
        "chall2_prefix": Fraction(qsig * h["delta"], 1 << l2),
    }
    program = programming_loss(qsig, h, LAMBDA, l1, l2)
    if program != sum(program_parts.values(), Fraction(0)):
        raise AssertionError("C1 component sum")
    tail = dyadic_tail(qsig, param["g"], cutoff)
    au = a["1"] * choose_two(tau) * epsilon_v
    zhash = a["2"] * epsilon_z
    challenge = Fraction(3 * a["delta"] + 1, m)
    terms = {
        "hide": term(raw_hide, hide, "C5", guarded_hide),
        "program": term(program, program, "C1"),
        "tail_dyadic_upper": term(tail, tail, "C2/C3 certified dyadic upper"),
        "chain": term(chain, chain, "B2"),
        "pair": term(raw_pair, pair, "B3", guarded_pair),
        "late": term(raw_late, late, "B4", guarded_late),
        "vhash_au": term(au, au, "B5/B6"),
        "zhash": term(zhash, zhash, "B7"),
        "challenge": term(challenge, challenge, "B8"),
    }
    unbounded_sum = sum((item["value"] for item in terms.values()), Fraction(0))
    error = min(Fraction(1), unbounded_sum)
    all_raw = [item["raw_before_local_cap"] for item in terms.values()]
    raw_sum = None if any(item is None for item in all_raw) else sum(all_raw, Fraction(0))
    output_bits = {
        "c": 2 * LAMBDA, "mu": 2 * LAMBDA, "s": 2 * LAMBDA,
        "4": LAMBDA, "1": l1, "2": l2, "delta": LAMBDA,
    }
    payloads = {
        "H1_snapshot_tape_core_bits_a1NL": a["1"] * n * param["L_bits"],
        "H2_affine_matrix_core_bits_a2lambdaL": a["2"] * LAMBDA * param["L_bits"],
        "IC_table_triples_core_bits_3lambdaP": 3 * LAMBDA * p,
        "RO_reserved_protocol_output_bits": sum(h[key] * output_bits[key] for key in h),
        "simulated_grinding_table_rows": qsig * cutoff,
        "simulated_grinding_input_and_output_payload_bits": qsig * cutoff * (93 + 16) * 8,
        "all_signer_programmed_rows_upper": qsig * (cutoff + 2),
        "cached_signature_payload_bits": qsig * param["signature_bytes"] * 8,
        "signature_cache_entries_upper": qsig,
    }
    return {
        "parameter": param["name"], "profile": profile,
        "budget_status": "illustrative; no user-approved security target",
        "model": "single parameter, single public key, classical ROM and bidirectional ideal cipher",
        "adversary_budgets_by_domain": int_strings(a),
        "Q_sig": str(qsig),
        "budget_units": {
            "RO": "first touches of complete inputs, including malformed/short/zero-length requests",
            "IC": "forward and inverse calls combined",
            "delta": "all raw grinding queries, including failed/precomputed/batch-extra queries",
            "other_RO_domains": "0 in these illustrative profiles",
        },
        "adversary_count_sums": int_strings({
            "seven_RO_domain_upper_bounds_sum": sum(a[key] for key in RO_DOMAINS),
            "RO_plus_IC_query_upper_bounds_sum": sum(a.values()),
            "RO_plus_IC_plus_signature_request_upper_bounds_sum": sum(a.values()) + qsig,
        }),
        "count_sum_interpretation": "oracle/request counts only; heterogeneous operations are not equal-time costs",
        "grinding": {
            "G": str(cutoff), "requested_before_32bit_cap": str(requested),
            "capped_by_32bit_capacity": cutoff_capped,
            "ceil_log2_max1_Qsig": ceil_log2_nonnegative(qsig),
            "tail_exponent_floor": cutoff // (1 << param["g"]),
            "active": qsig > 0,
            "exact_tail_expression": f"{qsig}*(1-2^(-{param['g']}))^{cutoff}",
            "used_upper_expression": f"{qsig}/2^{cutoff // (1 << param['g'])}",
            "upper_bound_justification": "(1-p)^G <= 2^(-floor(G*p)); C3",
        },
        "resources": int_strings({
            "M": m, "A_S": param["A_S"], "A_V": param["A_V"],
            "A_V_effective": param["A_V_effective"], "S0": param["S0"], "J0": param["J0"],
            "P": p, "P_H": p_h, "T": t, "rN_a1_extra_tape_calls": extra_tape,
            "simulator_plus_final_verify_IC_calls": (qsig + 1) * param["A_V"],
            "hiding_per_signature_dummy_calls": qsig * tau,
            "Rain_public_relation_evaluations_as_plus_a2": a["s"] + a["2"],
            "simulated_grinding_QsigG": qsig * cutoff,
            "B_RO_domain_counts_sum": sum(h.values()),
            "B_RO_plus_IC_count_upper_sum": sum(h.values()) + p,
        }),
        "total_RO_budgets_h": int_strings(h),
        "storage_accounting": {
            "payloads_exact_integer_budget_expressions": int_strings(payloads),
            "full_storage_upper_bound_bytes": None,
            "scope": "core payload budgets, not measured memory; full tables also store inputs, metadata and XOF tails",
            "full_asymptotic_expression": (
                "O(a1*N*L + a2*lambda*L + P*(lambda+log(P+1)) "
                "+ reserved_RO_bits + total_RO_input_bits + total_XOF_extension_bits "
                "+ Qsig*signature_bits)"
            ),
            "missing_to_convert_full_expression_to_bytes": "total input/XOF-extension bits and data-structure representation",
        },
        "subterms": {
            "chain": chain_parts, "program": program_parts,
            "epsilon_V": epsilon_v, "epsilon_V_parts": epsilon_v_parts,
            "epsilon_Z": epsilon_z, "epsilon_Z_parts": epsilon_z_parts,
        },
        "C7_terms": terms,
        "unclipped_error_sum_after_required_local_caps": unbounded_sum,
        "sum_raw_rationals_before_local_caps": raw_sum,
        "raw_sum_undefined_reason": None if raw_sum is not None else "P>=M or T>=M: rational formula replaced by theorem's trivial bound",
        "error_upper_bound_capped_at_one": error,
        "global_error_saturated": unbounded_sum >= 1,
        "saturated_components": [key for key, item in terms.items() if item["saturated"]],
        "largest_charged_term": max(terms, key=lambda key: terms[key]["value"]),
        "OWF_advantage_bound": owf,
        "OWF_status": "unknown; no numeric OWF assumption supplied" if owf is None else "explicit caller-supplied rational assumption",
        "symbolic_C7_bound": "min(1, Adv^{OWF,IC}_{Rain}(B) + error_sum)",
        "numeric_EUF_CMA_bound_if_OWF_supplied": None if owf is None else min(Fraction(1), owf + unbounded_sum),
        "interpretation": "minus_log2(error bound) is an error-bound exponent, not an attack cost or security-bit claim",
    }


def boundary_selftests(guard: ResourceGuard) -> dict[str, Any]:
    groups: list[dict[str, Any]] = []

    def group(name: str, cases: list[tuple[str, bool]]) -> None:
        failures = [label for label, passed in cases if not passed]
        groups.append({"name": name, "checked": len(cases), "passed": len(cases) - len(failures),
                       "failures": failures, "status": "PASS" if not failures else "FAIL"})
        guard.check()

    values = [0, 1, 2, 3, 4, 5, 7, 8, 9, (1 << 128) - 1, 1 << 128, (1 << 128) + 1]
    expected = [0, 0, 1, 2, 2, 3, 3, 3, 4, 128, 128, 129]
    group("integer ceil(log2(max(1,Qsig)))", [
        (str(value), ceil_log2_nonnegative(value) == want) for value, want in zip(values, expected)
    ])
    group("round up to complete x4 batch", [
        (str(value), round_up_to_four(value) % 4 == 0 and value <= round_up_to_four(value) < value + 4)
        for value in range(65)
    ])
    cutoff_cases = []
    for lam, g, qsig in [(8, 0, 0), (8, 1, 3), (128, 12, 1 << 32), (128, 30, 1), (128, 32, 3)]:
        cutoff, capped, requested = grinding_cutoff(lam, g, qsig)
        cutoff_cases.append((str((lam, g, qsig)), (
            cutoff % 4 == 0 and cutoff <= COUNTER_CAPACITY
            and cutoff == min(COUNTER_CAPACITY, requested)
            and capped == (requested > COUNTER_CAPACITY)
            and requested >= (1 << g) * (lam + ceil_log2_nonnegative(qsig))
        )))
    group("C3 integer cutoff and 32-bit cap", cutoff_cases)
    group("P=M and T=M guards, including no signatures", [
        ("pair P=M", bounded_pair(16, 16) == (None, Fraction(1), True)),
        ("pair P>M", bounded_pair(17, 16) == (None, Fraction(1), True)),
        ("late P=M", bounded_late(0, 8, 16, 16) == (None, Fraction(1), True)),
        ("hide T=M", bounded_hide(1, 16, 16) == (None, Fraction(1), True)),
        ("hide Qsig=0 even T>=M", bounded_hide(0, 17, 16) == (Fraction(0), Fraction(0), False)),
        ("pair P=0", bounded_pair(0, 16) == (Fraction(0), Fraction(0), False)),
        ("pair P=M-1 clips", bounded_pair(15, 16)[1] == 1),
        ("late P=M-1 clips", bounded_late(1, 8, 15, 16)[1] == 1),
        ("hide uncapped fraction", bounded_hide(1, 1, 256)[1] == Fraction(4, 255)),
    ])
    h_toy = {"4": 2, "1": 3, "2": 4, "delta": 5}
    group("zero-signature terms", [
        ("program", programming_loss(0, h_toy, 4, 8, 8) == 0),
        ("tail", dyadic_tail(0, 2, 16) == 0),
        ("hide", bounded_hide(0, 100, 16)[1] == 0),
    ])
    tail_cases = []
    for g in range(5):
        for cutoff in range(1, 49):
            for qsig in (0, 1, 3, 8):
                true_tail = qsig * Fraction((1 << g) - 1, 1 << g) ** cutoff
                bound = dyadic_tail(qsig, g, cutoff)
                tail_cases.append((f"g={g},G={cutoff},Q={qsig}", true_tail <= bound))
    group("exact small-parameter C2 versus dyadic upper", tail_cases)
    log_cases = []
    for numerator in range(1, 33):
        for denominator in range(1, 33):
            k = floor_log2_ratio(numerator, denominator)
            ratio = Fraction(numerator, denominator)
            lower = Fraction(1 << k) if k >= 0 else Fraction(1, 1 << -k)
            log_cases.append((f"{numerator}/{denominator}", lower <= ratio < 2 * lower))
    group("display-independent exact exponent floor", log_cases)
    return {
        "status": "PASS" if all(item["status"] == "PASS" for item in groups) else "FAIL",
        "groups": groups, "checked": sum(item["checked"] for item in groups),
        "scope": "bounded arithmetic edge cases; not a cryptographic security proof",
    }


def summary_csv(cases: list[dict[str, Any]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "profile", "parameter", "Q_sig", "G", "P", "P_H", "T", "h_delta",
        "error_numerator", "error_denominator", "minus_log2_error_display_only",
        "exact_floor_minus_log2_error", "largest_term", "global_saturated", "OWF_bound",
    ])
    for item in cases:
        error = item["error_upper_bound_capped_at_one"]
        displayed = fraction_record(error)
        writer.writerow([
            item["profile"], item["parameter"], item["Q_sig"], item["grinding"]["G"],
            item["resources"]["P"], item["resources"]["P_H"], item["resources"]["T"],
            item["total_RO_budgets_h"]["delta"], error.numerator, error.denominator,
            displayed["minus_log2_display_only"], displayed["floor_minus_log2_exact"],
            item["largest_charged_term"], item["global_error_saturated"],
            "UNKNOWN" if item["OWF_advantage_bound"] is None else str(item["OWF_advantage_bound"]),
        ])
    return output.getvalue()


def parse_owf(text: str | None) -> Fraction | None:
    if text is None:
        return None
    if len(text) > 4096:
        raise ValueError("OWF rational input exceeds bounded length")
    answer = Fraction(text)
    if not 0 <= answer <= 1:
        raise ValueError("OWF advantage assumption must lie in [0,1]")
    return answer


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "self-test"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--gate", type=Path, default=DEFAULT_GATE)
    parser.add_argument("--profile", action="append", choices=tuple(PROFILE_SEEDS))
    parser.add_argument("--set", dest="sets", action="append", choices=tuple(item[0] for item in PARAMETER_SEEDS))
    parser.add_argument("--owf-bound", help="optional explicit rational bound; omitted means unknown")
    parser.add_argument("--budget-seconds", type=int, default=120)
    args = parser.parse_args()
    output = args.output.resolve()
    output.relative_to(RAW_ROOT.resolve())
    if output == RAW_ROOT.resolve():
        raise ValueError("use a new run subdirectory, not the stage root")
    if any("粘贴的" in part for part in output.parts):
        raise ValueError("excluded output name")
    guard = ResourceGuard(args.budget_seconds)
    output.mkdir(parents=True, exist_ok=False)
    started = {
        "version": VERSION, "start_utc": utc_now(), "command": args.command,
        "argv": sys.argv, "python": sys.version, "platform": platform.platform(),
        "script": str(SCRIPT), "script_sha256": sha256_file(SCRIPT, guard),
        "resource_limit": guard.snapshot(),
        "scope": "bounded mathematical evidence audit; no native rebuild or performance run",
    }
    write_json(output / "run_started.json", started)
    completed: list[dict[str, Any]] = []
    try:
        gate = None
        if args.command == "run":
            gate = validate_gate(args.gate, guard)
            write_json(output / "gate_checked_before.json", gate)
        checks = boundary_selftests(guard)
        write_json(output / "boundary_selftest.json", checks)
        if checks["status"] != "PASS":
            raise AssertionError("arithmetic boundary self-test failed")
        if args.command == "self-test":
            result = {"status": "PASS", "kind": "boundary self-test only", "checked": checks["checked"],
                      "resource_usage": guard.snapshot(), "end_utc": utc_now()}
            write_json(output / "run_finished.json", result)
            print(json.dumps(result, ensure_ascii=False))
            return 0
        names = args.sets or [item[0] for item in PARAMETER_SEEDS]
        names = list(dict.fromkeys(names))
        params = [Parameters(*item).derived() for item in PARAMETER_SEEDS if item[0] in names]
        native = check_native_counts(params, guard)
        write_json(output / "parameters_and_native_counts.json", {
            "parameters": params, "native_count_comparison": native,
        })
        owf = parse_owf(args.owf_bound)
        profiles = list(dict.fromkeys(args.profile or list(PROFILE_SEEDS)))
        for profile in profiles:
            for param in params:
                guard.check()
                item = evaluate(param, profile, owf)
                write_json(output / f"case_{profile}_{param['name']}.json", item)
                completed.append(item)
                guard.check()
        final_gate = validate_gate(args.gate, guard)
        if final_gate["gate_sha256"] != gate["gate_sha256"] or final_gate["files"] != gate["files"]:
            raise AssertionError("reviewed evidence changed during this run")
        write_json(output / "gate_checked_after.json", final_gate)
        write_new(output / "ledger_summary.csv", summary_csv(completed))
        result = {
            "status": "PASS", "meaning": "exact arithmetic and reviewed-input consistency PASS",
            "version": VERSION, "formula": "03 C7, 02 B0-B9, 03 C1-C5; C2 uses proven dyadic upper",
            "review_gate": gate, "profiles": profiles, "parameters": params,
            "cases_count": len(completed), "cases": completed,
            "boundary_selftest": checks, "native_count_comparison": native,
            "OWF_default": "unknown; no zero assumption",
            "security_target_approved": False,
            "qrom_status": "OPEN; outside this classical theorem",
            "resource_usage": guard.snapshot(), "end_utc": utc_now(),
        }
        write_json(output / "ledger.json", result)
        guard.check()
        finish = {
            "status": "PASS", "cases": len(completed), "boundary_checks": checks["checked"],
            "native_count_records": native["cases"], "resource_usage": guard.snapshot(),
            "output": str(output), "ledger_sha256": sha256_file(output / "ledger.json", guard),
            "end_utc": utc_now(),
        }
        write_json(output / "run_finished.json", finish)
        print(json.dumps(finish, ensure_ascii=False))
        return 0
    except Exception as error:
        failure = {
            "status": "FAIL", "exception": type(error).__name__, "message": str(error),
            "traceback": traceback.format_exc(), "completed_cases": len(completed),
            "resource_usage": guard.snapshot(), "end_utc": utc_now(),
            "preservation": "completed case files and any temporary files remain in this run directory",
        }
        write_json(output / "failure.json", failure)
        print(json.dumps(failure, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
