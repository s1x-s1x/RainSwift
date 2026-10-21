#!/usr/bin/env python3
"""Reproducible six-way, verify-only ablation; no signing or budget consumption.

Linux prepare and timing are deliberately separate invocations. All builds are
COUNTERS=0 releases. Counter correctness belongs to the independent acceptance
suite, never to the timed libraries. Preparation checks all supplied public
fixtures and five negative mutations under REF and the six AVX2 variants.
"""
from __future__ import annotations

import argparse
import ctypes as ct
from datetime import datetime, timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from native import NativeSlhDsa, _buffer

SCHEMA = "a15-verify-ablation-v1"
VARIANTS = [(f"wots{w}-fors{f}", w, f) for w in (0, 1, 2) for f in (0, 1)]
BASELINE = "wots0-fors0"
INPUTS = ("vectors/external-gmsm.json", "reference/evidence/python-sm3-128-24.jsonl")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def utc():
    return datetime.now(timezone.utc).isoformat()


def file_sha(path):
    return sha(Path(path).read_bytes())


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def line(stream, row):
    stream.write(canonical({"schema": SCHEMA, **row}) + "\n")


def source_hashes():
    """All library sources/headers, vendor compilation sources and runner inputs."""
    names = {"c/Makefile", "tools/native.py", "tools/bench_verify_optimization.py"}
    for directory in ("c/src", "c/include", "third_party/slhdsa-c"):
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and path.suffix in (".c", ".h", ".cu", ".cuh", ".S"):
                names.add(path.relative_to(ROOT).as_posix())
    return {name: file_sha(ROOT / name) for name in sorted(names)}


def command(argv, *, timeout=180, env=None):
    result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True,
                            timeout=timeout, env=env)
    return {"argv": argv, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def text_file(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def environment(cpu=None):
    fields = {}
    for content in (text_file("/proc/cpuinfo") or "").splitlines():
        if ":" in content:
            key, value = (p.strip() for p in content.split(":", 1))
            if key in ("model name", "vendor_id", "cpu family", "model", "stepping", "microcode", "flags"):
                fields.setdefault(key, value)
    policy = {}
    if cpu is not None:
        root = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
        for name in ("scaling_governor", "scaling_driver", "scaling_min_freq", "scaling_max_freq", "scaling_cur_freq"):
            policy[name] = text_file(root / name)
    return {"recorded_at_utc": utc(), "system": platform.platform(),
            "uname": list(platform.uname()), "python": sys.version,
            "cpu": fields, "cpu_count": os.cpu_count(),
            "affinity": sorted(os.sched_getaffinity(0)), "selected_cpu": cpu,
            "frequency_policy_observed": policy,
            "boost_observed": text_file("/sys/devices/system/cpu/cpufreq/boost"),
            "no_turbo_observed": text_file("/sys/devices/system/cpu/intel_pstate/no_turbo"),
            "loadavg_observed": text_file("/proc/loadavg"),
            "process_snapshot": command(["ps", "-eo", "pid,comm,pcpu"], timeout=10),
            "governor_or_boost_modified": False,
            "cpu_cycles_measured": False,
            "timing_clock": time.get_clock_info("perf_counter")._asdict()
                if hasattr(time.get_clock_info("perf_counter"), "_asdict") else
                vars(time.get_clock_info("perf_counter"))}


def public_fixture(case_id, pid, message, context, pk, signature, origin, kind):
    values = {"message": message, "context": context, "pk": pk, "sig": signature}
    content_hashes = {key: sha(bytes.fromhex(value)) for key, value in values.items()}
    result = {"case_id": case_id, "pid": pid, "origin": origin,
              "randomization": kind, **values, "content_sha256": content_hashes}
    result["input_sha256"] = sha(canonical({"pid": pid, **values}).encode())
    return result


def load_fixtures():
    fixtures = []
    external = read_json(ROOT / INPUTS[0])
    for case in external["cases"]:
        if case["pid"] not in (1, 2):
            continue
        for key, kind in (("deterministicSignature", "deterministic"),
                          ("randomizedSignature", "randomized")):
            fixtures.append(public_fixture(
                f"gmsm-p{case['pid']}-i{case['index']}-{kind}", case["pid"],
                case["message"], case["context"], case["pk"], case[key], INPUTS[0], kind))
    for raw in (ROOT / INPUTS[1]).read_text(encoding="utf-8-sig").splitlines():
        if not raw.strip():
            continue
        case = json.loads(raw)
        if case["pid"] != 3 or case["mode"] != "pure":
            raise ValueError("the limited-use fixture must be a real pid3 pure signature")
        fixtures.append(public_fixture(case["case_id"], 3, case["message"], case["context"],
                                       case["pk"], case["sig"], INPUTS[1], case["randomization"]))
    if len({c["case_id"] for c in fixtures}) != len(fixtures):
        raise ValueError("duplicate fixture case identity")
    for pid in (1, 2, 3):
        if len({c["message"] for c in fixtures if c["pid"] == pid}) < 3:
            raise ValueError(f"pid {pid} needs at least three distinct messages")
    return fixtures


def decoded(case):
    return tuple(bytes.fromhex(case[k]) for k in ("message", "sig", "pk", "context"))


def flip(data, offset=0):
    value = bytearray(data or b"\0")
    value[offset] ^= 1
    return bytes(value)


def checks(case):
    message, sig, pk, context = decoded(case)
    yield "valid", True, (message, sig, pk, context)
    # R is 16 bytes; the first FORS secret and first authentication node follow.
    yield "fors-secret-bit", False, (message, flip(sig, 16), pk, context)
    yield "fors-auth-bit", False, (message, flip(sig, 32), pk, context)
    yield "message-bit", False, (flip(message), sig, pk, context)
    yield "truncated", False, (message, sig[:-1], pk, context)
    yield "extra-byte", False, (message, sig + b"\0", pk, context)


def prepare(args):
    result_dir = args.output.resolve()
    build_root = args.build_root.resolve()
    result_dir.mkdir(parents=True, exist_ok=False)
    build_root.mkdir(parents=True, exist_ok=False)
    sources = source_hashes()
    source_digest = sha(canonical(sources).encode())
    input_hashes = {name: file_sha(ROOT / name) for name in INPUTS}
    fixtures = load_fixtures()
    write_json(result_dir / "fixtures.json", fixtures)
    manifest = {"schema": SCHEMA, "started_at_utc": utc(),
                "command": sys.argv, "project_root": str(ROOT),
                "source_sha256": sources, "source_manifest_sha256": source_digest,
                "input_files_sha256": input_hashes,
                "fixtures_sha256": file_sha(result_dir / "fixtures.json"),
                "fixture_count": len(fixtures), "variants": [],
                "git_head": command(["git", "rev-parse", "HEAD"]),
                "git_status": command(["git", "status", "--short"]),
                "compiler": command([args.cc, "--version"]),
                "make": command(["make", "--version"]),
                "environment": environment(),
                "counter_validation": "separate acceptance artifact; never timed here",
                "signing_calls": 0, "formal_competition_performance": False}
    write_json(result_dir / "prepare-start.json", manifest)
    build_env = {**os.environ, "LC_ALL": "C", "OMP_NUM_THREADS": "1", "OMP_DYNAMIC": "FALSE"}
    try:
        for name, wots, fors in VARIANTS:
            output = build_root / name
            argv = ["make", "-C", str(ROOT / "c"), f"OUT={output}", "COUNTERS=0",
                    "CUDA=0", "AVX2=1", f"CC={args.cc}", "CFLAGS=-O3",
                    f"WOTS_SCHEDULE={wots}", f"FORS_VERIFY_X8={fors}", "all"]
            build = command(argv, timeout=180, env=build_env)
            write_json(result_dir / f"build-{name}.json", build)
            if build["returncode"]:
                raise RuntimeError(f"build {name} failed; see preserved log")
            library = output / "libslhdsa_sm3.so"
            variant = {"name": name, "wots_schedule": wots, "fors_verify_x8": fors,
                       "library": str(library), "library_sha256": file_sha(library),
                       "command": argv, "counters": 0}
            manifest["variants"].append(variant)
            print(f"built {name}", flush=True)
        if source_hashes() != sources:
            raise RuntimeError("source changed during six-way build; start a new preparation")
        total = 0
        with (result_dir / "correctness.jsonl").open("x", encoding="utf-8") as stream:
            # Baseline REF establishes outcomes independently of all SIMD recovery paths.
            variants = [(manifest["variants"][0], 1), *[(v, 2) for v in manifest["variants"]]]
            for variant, backend in variants:
                for pid in (1, 2, 3):
                    with NativeSlhDsa(pid, threads=1, flags=backend, library=variant["library"]) as native:
                        if native.lib.slh_ctx_backend(native.ctx) != backend:
                            raise RuntimeError("requested backend was not selected")
                        for case in fixtures:
                            if case["pid"] != pid:
                                continue
                            for mutation, expected, values in checks(case):
                                accepted = native.verify(*values)
                                row = {"variant": variant["name"], "backend": backend,
                                       "pid": pid, "case_id": case["case_id"],
                                       "mutation": mutation, "expected": expected,
                                       "accepted": accepted, "pass": accepted == expected,
                                       "fixture_sha256": case["input_sha256"],
                                       "mutation_sha256": sha(canonical([v.hex() for v in values]).encode()),
                                       "library_sha256": variant["library_sha256"],
                                       "source_manifest_sha256": source_digest}
                                line(stream, row)
                                total += 1
                                if not row["pass"]:
                                    raise RuntimeError(f"correctness failed: {case['case_id']} {mutation}")
                stream.flush()
                os.fsync(stream.fileno())
                print(f"checked {variant['name']} backend={backend}", flush=True)
        if source_hashes() != sources:
            raise RuntimeError("source changed during correctness checks")
        manifest.update({"prepared_at_utc": utc(), "status": "prepared-not-timed",
                         "correctness_rows": total,
                         "correctness_sha256": file_sha(result_dir / "correctness.jsonl")})
        write_json(result_dir / "prepared.json", manifest)
        print(canonical({"status": manifest["status"], "correctness_rows": total,
                         "fixtures": len(fixtures), "output": str(result_dir)}), flush=True)
    except BaseException as error:
        write_json(result_dir / "prepare-failure.json", {"at_utc": utc(), "error": repr(error)})
        raise


def stats(values):
    q1, _, q3 = statistics.quantiles(values, n=4, method="inclusive")
    return {"n": len(values), "median": statistics.median(values), "q1": q1,
            "q3": q3, "iqr": q3 - q1, "min": min(values), "max": max(values)}


def summarize(rows):
    indexed = {(r["variant"], r["case_id"], r["round"]): r["ns_per_verify"] for r in rows}
    cases = {(r["case_id"], r["pid"]) for r in rows}
    result = {"unit": "ns per complete native slh_verify call including ctypes loop",
              "paired_ratio_definition": "baseline ns / variant ns; above 1 favors variant",
              "per_case": [], "per_pid": []}
    variants = [v[0] for v in VARIANTS]
    rounds = sorted({r["round"] for r in rows})
    for case_id, pid in sorted(cases):
        for variant in variants:
            times = [indexed[variant, case_id, r] for r in rounds]
            ratios = [indexed[BASELINE, case_id, r] / indexed[variant, case_id, r] for r in rounds]
            result["per_case"].append({"case_id": case_id, "pid": pid, "variant": variant,
                                       "latency_ns": stats(times), "paired_ratio": stats(ratios)})
    for pid in (1, 2, 3):
        ids = [case for case, case_pid in sorted(cases) if case_pid == pid]
        means = {(variant, r): statistics.mean(indexed[variant, case, r] for case in ids)
                 for variant in variants for r in rounds}
        for variant in variants:
            result["per_pid"].append({"pid": pid, "variant": variant,
                                      "distinct_fixture_count": len(ids),
                                      "round_mean_latency_ns": stats([means[variant, r] for r in rounds]),
                                      "paired_ratio": stats([means[BASELINE, r] / means[variant, r]
                                                             for r in rounds])})
    return result


def run(args):
    result_dir = args.output.resolve()
    prepared = read_json(result_dir / "prepared.json")
    if source_hashes() != prepared["source_sha256"]:
        raise RuntimeError("current source differs from prepared sources; prepare fresh builds")
    if file_sha(result_dir / "fixtures.json") != prepared["fixtures_sha256"]:
        raise RuntimeError("public fixture snapshot changed")
    if file_sha(result_dir / "correctness.jsonl") != prepared["correctness_sha256"]:
        raise RuntimeError("correctness evidence changed")
    for name, digest in prepared["input_files_sha256"].items():
        if file_sha(ROOT / name) != digest:
            raise RuntimeError(f"input file changed: {name}")
    for variant in prepared["variants"]:
        if file_sha(variant["library"]) != variant["library_sha256"]:
            raise RuntimeError(f"prepared library changed: {variant['name']}")
    fixtures = read_json(result_dir / "fixtures.json")
    old_affinity = os.sched_getaffinity(0)
    selected_cpu = args.cpu if args.cpu is not None else min(old_affinity)
    if selected_cpu not in old_affinity:
        raise ValueError("requested CPU is outside the process allowed affinity")
    os.sched_setaffinity(0, {selected_cpu})
    os.environ["OMP_NUM_THREADS"] = "1"
    os.environ["OMP_DYNAMIC"] = "FALSE"
    contexts, calls, rows = {}, {}, []
    gc_was_enabled = gc.isenabled()
    try:
        env = environment(selected_cpu)
        env_sha = sha(canonical(env).encode())
        config = {"rounds": args.rounds, "batch": args.batch, "warmup_rounds": args.warmup,
                  "seed": args.seed, "cpu": selected_cpu, "threads": 1,
                  "counters": 0, "mode": "pure", "backend": "AVX2",
                  "timing_scope": "complete native slh_verify through preallocated ctypes args; Python loop included",
                  "excluded": ["fixture decode", "buffer allocation", "context creation", "build", "correctness", "file writes"],
                  "variant_order": "fixed-seed shuffle, then rotate each round within each fixture",
                  "fixture_order": "fixed-seed shuffle once; common across all rounds",
                  "formal_competition_performance": False,
                  "virtualization_scope": "observed environment only; WSL results are local measurements",
                  "counter_acceptance": "separate correctness artifact required for final delivery",
                  "concurrent_native_workloads": "must be stopped by invoking coordinator; process snapshot retained"}
        write_json(result_dir / "timing-start.json", {"schema": SCHEMA, "at_utc": utc(),
                   "command": sys.argv, "configuration": config, "environment": env,
                   "environment_sha256": env_sha, "prepared_sha256": file_sha(result_dir / "prepared.json")})
        for variant in prepared["variants"]:
            for pid in (1, 2, 3):
                contexts[variant["name"], pid] = NativeSlhDsa(
                    pid, threads=1, flags=2, library=variant["library"])
            for case in fixtures:
                native = contexts[variant["name"], case["pid"]]
                message, sig, pk, context = decoded(case)
                calls[variant["name"], case["case_id"]] = (
                    native.lib.slh_verify,
                    (native.ctx, _buffer(sig), len(sig), _buffer(message), len(message),
                     _buffer(context), len(context), _buffer(pk, 32)))
        rng = random.Random(args.seed)
        ordered_fixtures = list(fixtures)
        rng.shuffle(ordered_fixtures)
        variant_order = list(prepared["variants"])
        rng.shuffle(variant_order)
        gc.disable()
        for _ in range(args.warmup):
            for case in ordered_fixtures:
                for variant in variant_order:
                    function, arguments = calls[variant["name"], case["case_id"]]
                    for _ in range(args.batch):
                        if function(*arguments) != 0:
                            raise RuntimeError("warmup rejected a prepared valid fixture")
        with (result_dir / "timing.jsonl").open("x", encoding="utf-8", newline="\n") as stream:
            for round_index in range(args.rounds):
                for case_index, case in enumerate(ordered_fixtures):
                    offset = (round_index + case_index) % len(variant_order)
                    order = variant_order[offset:] + variant_order[:offset]
                    for order_index, variant in enumerate(order):
                        function, arguments = calls[variant["name"], case["case_id"]]
                        rc = 0
                        start = time.perf_counter_ns()
                        for _ in range(args.batch):
                            rc |= function(*arguments)
                        elapsed = time.perf_counter_ns() - start
                        if rc:
                            raise RuntimeError("timed verifier rejected a prepared valid fixture")
                        row = {"round": round_index, "case_id": case["case_id"], "pid": case["pid"],
                               "randomization": case["randomization"], "variant": variant["name"],
                               "order_in_fixture": order_index, "batch": args.batch,
                               "elapsed_ns": elapsed, "ns_per_verify": elapsed / args.batch,
                               "library_sha256": variant["library_sha256"],
                               "input_sha256": case["input_sha256"],
                               "content_sha256": case["content_sha256"],
                               "source_manifest_sha256": prepared["source_manifest_sha256"],
                               "environment_sha256": env_sha,
                               "configuration_sha256": sha(canonical(config).encode()),
                               "native_returncode": rc}
                        rows.append(row)
                        line(stream, row)
                stream.flush()
                os.fsync(stream.fileno())
                if (round_index + 1) % 10 == 0:
                    print(f"timing round {round_index + 1}/{args.rounds}", flush=True)
        if source_hashes() != prepared["source_sha256"]:
            raise RuntimeError("source changed while timing; preserve samples as invalid")
        if any(file_sha(v["library"]) != v["library_sha256"] for v in prepared["variants"]):
            raise RuntimeError("library changed while timing; preserve samples as invalid")
        summary = summarize(rows)
        summary.update({"schema": SCHEMA, "status": "complete-local-ablation",
                        "completed_at_utc": utc(), "rows": len(rows),
                        "total_verification_calls_measured": len(rows) * args.batch,
                        "configuration": config, "environment_after": environment(selected_cpu),
                        "raw_sha256": file_sha(result_dir / "timing.jsonl"),
                        "source_manifest_sha256": prepared["source_manifest_sha256"],
                        "prepared_sha256": file_sha(result_dir / "prepared.json")})
        write_json(result_dir / "summary.json", summary)
        print(canonical({"status": summary["status"], "rows": len(rows),
                         "output": str(result_dir)}), flush=True)
    except BaseException as error:
        write_json(result_dir / "timing-failure.json", {"at_utc": utc(), "error": repr(error),
                                                       "completed_rows": len(rows)})
        raise
    finally:
        for context in contexts.values():
            context.close()
        if gc_was_enabled:
            gc.enable()
        os.sched_setaffinity(0, old_affinity)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    phase = parser.add_mutually_exclusive_group(required=True)
    phase.add_argument("--prepare-only", action="store_true")
    phase.add_argument("--run-only", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--rounds", type=int, default=100)
    parser.add_argument("--batch", type=int, default=8)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261004)
    parser.add_argument("--cpu", type=int)
    args = parser.parse_args()
    if not sys.platform.startswith("linux") or not hasattr(os, "sched_setaffinity"):
        parser.error("run under Linux/WSL; explicit CPU affinity is required")
    if args.prepare_only and args.build_root is None:
        parser.error("--prepare-only requires a fresh --build-root directory")
    if args.rounds < 2 or args.batch < 1 or args.warmup < 1:
        parser.error("rounds>=2, batch>=1 and warmup>=1 are required")
    prepare(args) if args.prepare_only else run(args)


if __name__ == "__main__":
    main()
