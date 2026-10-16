"""迭代030 Q3：单个窗口的严格审计与统计。只接受完整公开 API 原始行；本程序不启动任何实验。

由 P0 summarize_baseline_window.py（迭代028 linkfix_v3）改写：实现表与窗口表取自 q3_common.py，
校验规则逐条保留；统计在 P0 的混合中位数之外加报四分位数（statistics.quantiles，n=4，inclusive）。
不判定通过／失败；参考线比较在 q3_report.py 中只作参考。
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import statistics
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from q3_common import (API, BATCHES, BUILD_FLAGS, CHUNKS, IMPLS, RNG, SAMPLES_PER_BATCH,  # noqa: E402
                       SAMPLES_PER_CHUNK, SAMPLES_PER_IMPL, SIGNING, TREES, WARMUPS_PER_CHUNK, WINDOWS,
                       WRAP_METADATA, canonical_hash, is_int, read_json, reject_constant, require, safe_relative,
                       sha256)


def schedule(window_set, cpus):
    names = WINDOWS[window_set]
    require(len(cpus) == BATCHES, "three CPU records are required")
    result = []
    for batch in range(1, BATCHES + 1):
        for chunk in range(1, CHUNKS + 1):
            shift = (batch + chunk - 2) % len(names)
            order = names[shift:] + names[:shift]
            for name in order:
                result.append({
                    "tag": f"b{batch}_c{chunk}_{name}", "impl": name,
                    "batch": batch, "round": batch, "chunk": chunk,
                    "cpu": cpus[batch - 1]["logical_cpu"],
                    "samples": SAMPLES_PER_CHUNK, "warmup": WARMUPS_PER_CHUNK,
                    "sample_offset": (chunk - 1) * SAMPLES_PER_CHUNK,
                    "validate_only": False,
                })
    return result


def validation_schedule(window_set, cpus):
    return [{"tag": "validation_" + name, "impl": name, "batch": 0,
             "round": 0, "chunk": 0, "cpu": cpus[0]["logical_cpu"],
             "samples": 0, "warmup": 0, "sample_offset": 0,
             "validate_only": True} for name in WINDOWS[window_set]]


def parse_jsonl(text):
    require(bool(text.strip()), "empty harness output")
    return [json.loads(line, parse_constant=reject_constant)
            for line in text.splitlines() if line.strip()]


def inspect_call(rows, spec):
    """Pure validator, also called immediately after each live harness invocation."""
    expected = IMPLS[spec["impl"]]
    require(all(isinstance(row, dict) for row in rows), "harness row must be an object")
    require(len(rows) >= 2 and rows[0].get("kind") == "metadata" and
            rows[1].get("kind") == "validation", "missing ordered metadata/validation rows")
    require(all(row.get("algorithm") == expected["algorithm"] for row in rows),
            "algorithm identity mismatch")
    meta = rows[0]
    for key, value in {
        "impl_id": expected["id"], "source_commit": expected["commit"], "api": API, "signing": SIGNING,
        "rng": RNG, "clock": "CLOCK_MONOTONIC_RAW", "clock_overhead_subtracted": False,
        "message_bytes": 64, "signature_bytes_expected": expected["signature_bytes"],
        "cpu": spec["cpu"], "nice": 19, "batch": spec["batch"],
        "round": spec["round"], "chunk": spec["chunk"],
        "samples_requested": spec["samples"], "warmups_requested": spec["warmup"],
        "sample_offset": spec["sample_offset"],
    }.items():
        require(meta.get(key) == value, "metadata mismatch: " + key)
    require(meta.get("clock_overhead_subtracted") is False, "clock overhead policy mismatch")
    for key in ("public_key_bytes", "secret_key_bytes"):
        require(is_int(meta.get(key)) and meta[key] > 0, "invalid key-size metadata: " + key)
    require(isinstance(meta.get("clock_pair_median_ns"), (int, float)) and
            math.isfinite(meta["clock_pair_median_ns"]) and meta["clock_pair_median_ns"] >= 0,
            "invalid clock-overhead diagnostic")
    validation = rows[1]
    require(validation.get("passed") is True and validation.get("roundtrips") == 2 and
            validation.get("distinct_randomized_signatures") is True and
            validation.get("tamper_rejections") == 5,
            "public-API smoke validation incomplete")
    require("not a known-answer test or security proof" in validation.get("scope", ""),
            "validation scope must retain its limitations")
    if spec["validate_only"]:
        require(len(rows) == 2, "validate-only run produced unexpected rows")
        return {"metadata": meta, "samples": []}

    require(len(rows) == 3 + spec["samples"] + spec["warmup"], "raw sample count mismatch")
    require(rows[-1].get("kind") == "chunk_summary", "missing final chunk summary")
    samples = []
    for index, row in enumerate(rows[2:-1]):
        warmup = index < spec["warmup"]
        expected_index = index if warmup else spec["sample_offset"] + index - spec["warmup"]
        require(row.get("kind") == "sample", "unexpected non-sample row")
        require(row.get("warmup") is warmup, "warmup order mismatch")
        require(is_int(row.get("sample_index")) and row["sample_index"] == expected_index,
                "missing, duplicate, or reordered sample index")
        for key in ("batch", "round", "chunk"):
            require(row.get(key) == spec[key], "sample schedule mismatch: " + key)
        require(row.get("valid") is True, "invalid API sample")
        for api in ("kg", "sign", "verify"):
            require(is_int(row.get(api + "_rc")) and row[api + "_rc"] == 0,
                    "API failed: " + api)
            require(is_int(row.get(api + "_ns")) and row[api + "_ns"] > 0,
                    "missing/nonpositive measured duration: " + api)
        require(is_int(row.get("signature_bytes")) and
                row["signature_bytes"] == expected["signature_bytes"], "signature size mismatch")
        require(is_int(row.get("kg_rng_calls")) and row["kg_rng_calls"] >= 1,
                "keypair OS randomness was omitted")
        require(is_int(row.get("sign_rng_calls")) and row["sign_rng_calls"] == 1,
                "randomized signing must make its one upstream OS RNG call")
        require(is_int(row.get("verify_rng_calls")) and row["verify_rng_calls"] == 0,
                "unexpected verification randomness")
        if not warmup:
            samples.append(row)
    summary = rows[-1]
    require(summary.get("samples") == spec["samples"] and summary.get("failures") == 0 and
            summary.get("signature_bytes") == expected["signature_bytes"], "chunk summary mismatch")
    for key in ("batch", "round", "chunk"):
        require(summary.get(key) == spec[key], "chunk summary schedule mismatch")
    for api in ("kg", "sign", "verify"):
        require(summary.get(api + "_median_ns") == statistics.median(row[api + "_ns"] for row in samples),
                "reported chunk median differs from raw samples: " + api)
    return {"metadata": meta, "samples": samples}


def describe(values):
    q1, q2, q3 = statistics.quantiles(values, n=4, method="inclusive")
    median = statistics.median(values)
    require(median == q2, "quartile/median definition drift")
    return {"median": median, "q1": q1, "q3": q3, "min": min(values), "max": max(values)}


def metrics(rows):
    require(bool(rows), "no measured samples")
    stats = {api: describe([row[api + "_ns"] for row in rows]) for api in ("kg", "sign", "verify")}
    fewest_keypair_calls = min(row["kg_rng_calls"] for row in rows)
    keygen_retries = sum(1 for row in rows if row["kg_rng_calls"] > fewest_keypair_calls)
    return {"valid_nonwarmup_samples": len(rows),
            **{api + "_median_ns": stats[api]["median"] for api in stats},
            **{api + "_q1_ns": stats[api]["q1"] for api in stats},
            **{api + "_q3_ns": stats[api]["q3"] for api in stats},
            **{api + "_min_ns": stats[api]["min"] for api in stats},
            **{api + "_max_ns": stats[api]["max"] for api in stats},
            "kg_median_us": stats["kg"]["median"] / 1000,
            "sign_median_ms": stats["sign"]["median"] / 1e6,
            "verify_median_ms": stats["verify"]["median"] / 1e6,
            "keypair_rng_call_counts": sorted({row["kg_rng_calls"] for row in rows}),
            "keypair_samples_above_min_rng_calls": keygen_retries,
            "signature_bytes": rows[0]["signature_bytes"]}


def audit_window(window, live_build=None):
    window = Path(window).resolve(strict=True)
    plan = read_json(window / "window_plan.json")
    outcome = read_json(window / "window_result.json")
    require(plan.get("schema_version") == 1 and outcome.get("schema_version") == 1, "unknown window schema")
    require(outcome.get("status") == "complete", "window did not finish successfully")
    require(outcome.get("plan_sha256") == sha256(window / "window_plan.json"), "window plan hash mismatch")
    require(plan.get("parallel_work_complete_attested") is True, "parallel-work completion was not attested")
    require(plan.get("api") == API and plan.get("message_bytes") == 64, "formal API/message scope mismatch")
    require(plan.get("clock") == "CLOCK_MONOTONIC_RAW" and plan.get("samples_per_batch") == SAMPLES_PER_BATCH,
            "formal measurement scope mismatch")
    window_set = plan.get("window_set")
    require(window_set in WINDOWS, "unknown window set")
    names = WINDOWS[window_set]
    require(tuple(plan.get("implementations", ())) == names, "window implementation list differs from the frozen plan")
    cpus = plan["physical_cpus"]
    require(len(cpus) == 3 and len({c["logical_cpu"] for c in cpus}) == 3, "three distinct logical CPUs were not used")
    require(len({(c["physical_package_id"], c["core_id"]) for c in cpus}) == 3,
            "CPU choices are SMT siblings, not three physical cores")
    for cpu in cpus:
        require(is_int(cpu["logical_cpu"]) and cpu["logical_cpu"] >= 0 and
                str(cpu["physical_package_id"]).isdigit() and str(cpu["core_id"]).isdigit(),
                "invalid recorded CPU topology")
    expected_calls = validation_schedule(window_set, cpus) + schedule(window_set, cpus)
    require(plan.get("calls") == expected_calls, "window does not use the frozen rotated schedule")
    idle = plan.get("initial_project_idle_check", {})
    require(idle.get("blocking_processes") == [] and idle.get("checked_same_uid_project_processes") is True,
            "initial project-idle evidence missing")

    snapshots = plan["provenance"]["snapshots"]
    for relative, digest in snapshots.items():
        require(sha256(safe_relative(window, relative)) == digest, "provenance snapshot changed: " + relative)
    for relative in ("provenance/source_manifest.json", "provenance/artifact_manifest.json",
                     "provenance/build_inputs.json", "provenance/compatibility_patches.json",
                     "provenance/created_files.json", "provenance/q3_harness.cpp", "provenance/q3_common.py",
                     "provenance/run_q3_window.py", "provenance/summarize_q3_window.py"):
        require(relative in snapshots, "missing required provenance snapshot: " + relative)
    source = read_json(window / "provenance/source_manifest.json")
    trees = {entry["tree"]: entry for entry in source["sources"]}
    for tree, spec in TREES.items():
        require(trees[tree]["commit"] == spec["commit"] and trees[tree]["path"] == spec["source_dir"],
                "source identity mismatch: " + tree)
    source_check = plan["provenance"]["source_verification"]
    require(source_check.get("all_files_verified") is True and
            source_check.get("file_count") == len(source["files"]) and
            source_check.get("inventory_sha256") == canonical_hash(source["files"]),
            "original source inventory was not fully bound to its manifest")
    artifacts = read_json(window / "provenance/artifact_manifest.json")
    inputs = read_json(window / "provenance/build_inputs.json")
    records = {record["impl"]: record for record in artifacts["records"]}
    input_records = {record["impl"]: record for record in inputs}
    require(set(records) == set(IMPLS) and len(artifacts["records"]) == len(IMPLS) == len(inputs),
            "artifact/input records must each contain all eleven implementations")
    require(artifacts.get("flags") == BUILD_FLAGS, "build flags differ from the audited recipe")
    binaries = plan["provenance"]["binaries"]
    harness_hash = snapshots["provenance/q3_harness.cpp"]
    for name in names:
        record = records[name]
        require(all(record.get(key) == value for key, value in input_records[name].items()),
                "build inputs and artifact manifest diverged: " + name)
        require(record["impl_id"] == IMPLS[name]["id"] and record["declared_fixed_commit"] == IMPLS[name]["commit"]
                and record["tree"] == IMPLS[name]["tree"], "artifact identity mismatch: " + name)
        require(record["harness_sha256"] == harness_hash == binaries[name]["harness_sha256"],
                "harness hashes differ between implementations")
        require(record["executable_sha256"] == binaries[name]["executable_sha256"] and
                record["executable_bytes"] == binaries[name]["executable_bytes"], "binary hash/size mismatch")
        require(binaries[name].get("patched_source_files_verified") is True, "patched build source was not checked")
        metadata_files = binaries[name].get("build_metadata_files", {})
        require(set(metadata_files) <= {WRAP_METADATA}, "unexpected build-metadata exemption")
        for item in metadata_files.values():
            require(is_int(item.get("bytes")) and 0 <= item["bytes"] <= 4096 and
                    re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")) is not None,
                    "invalid Meson metadata hash record")
        if live_build is not None:
            build = Path(live_build).resolve(strict=True)
            require(sha256(safe_relative(build, record["executable"])) == record["executable_sha256"],
                    "live binary hash mismatch: " + name)
            require(sha256(build / "work" / record["tree"] / "q3_harness.cpp") == harness_hash,
                    "live harness hash mismatch: " + name)
    require(outcome.get("final_provenance_verification") == plan["provenance"]["binding"],
            "source/binary/harness provenance changed during the window")
    require(outcome.get("final_project_idle_check", {}).get("blocking_processes") == [],
            "project parallel work appeared by the end of the window")
    calls = outcome.get("runs", [])
    require(len(calls) == len(expected_calls), "window has missing or extra invocations")
    samples = {name: {batch: [] for batch in range(1, BATCHES + 1)} for name in names}
    keys = {}
    for run, spec in zip(calls, expected_calls):
        require(run.get("spec") == spec, "invocation order/affinity differs from plan")
        require(run.get("returncode") == 0 and run.get("timed_out") is False and
                run.get("resource_stop") is None, "failed or interrupted harness invocation")
        require(run.get("idle_check", {}).get("blocking_processes") == [], "project was not idle before invocation")
        require(run.get("binary_sha256") == binaries[spec["impl"]]["executable_sha256"],
                "invoked binary differs from bound artifact")
        stdout_path = safe_relative(window, run["stdout_path"])
        stderr_path = safe_relative(window, run["stderr_path"])
        require(sha256(stdout_path) == run["stdout_sha256"] and sha256(stderr_path) == run["stderr_sha256"],
                "raw invocation output hash mismatch")
        require(not stderr_path.read_text(encoding="utf-8").strip(), "harness wrote unexpected stderr")
        require(run.get("stdout_redacted") is False, "harness JSON output required redaction")
        checked = inspect_call(parse_jsonl(stdout_path.read_text(encoding="utf-8")), spec)
        meta = checked["metadata"]
        sizes = (meta["public_key_bytes"], meta["secret_key_bytes"])
        require(keys.setdefault(spec["impl"], sizes) == sizes, "key-size metadata drift")
        if not spec["validate_only"]:
            samples[spec["impl"]][spec["batch"]].extend(checked["samples"])

    results = {}
    for name in names:
        combined, per_batch = [], []
        for batch, rows in samples[name].items():
            require(len(rows) == SAMPLES_PER_BATCH and [r["sample_index"] for r in rows] == list(range(SAMPLES_PER_BATCH)),
                    "batch does not contain exactly 501 uniquely indexed raw samples")
            combined.extend(rows)
            per_batch.append({"batch": batch, "cpu": cpus[batch - 1], **metrics(rows)})
        require(len(combined) == SAMPLES_PER_IMPL, "implementation does not have 1503 samples")
        results[name] = {"impl_id": IMPLS[name]["id"], "algorithm": IMPLS[name]["algorithm"],
                         "source_commit": IMPLS[name]["commit"],
                         "public_key_bytes": keys[name][0], "secret_key_bytes": keys[name][1],
                         "batches": per_batch, "all_three_batches": metrics(combined)}
    return {"schema_version": 1, "status": "verified_complete_q3_window", "window_set": window_set,
            "window_label": plan.get("label"), "implementations": list(names),
            "evidence_kind": "measured complete randomized public APIs",
            "scope": "Q3 timing window only; not KAT, constant-time or security evidence",
            "window_plan_sha256": sha256(window / "window_plan.json"),
            "window_result_sha256": sha256(window / "window_result.json"),
            "start_utc": outcome.get("start_utc"), "end_utc": outcome.get("end_utc"),
            "cpu_busy_before": plan.get("cpu_busy_snapshot"), "cpu_busy_after": outcome.get("final_cpu_busy_snapshot"),
            "initial_resources": plan.get("initial_resources"), "final_resources": outcome.get("final_resources"),
            "message_bytes": 64, "clock": "CLOCK_MONOTONIC_RAW", "clock_overhead_subtracted": False,
            "aggregation": "per-batch and pooled raw-sample medians and inclusive quartiles; "
                           "no best-batch selection or median-of-chunk-medians",
            "samples_per_implementation": SAMPLES_PER_IMPL, "physical_cores_used_sequentially": 3,
            "concurrent_benchmark_processes": 1, "results": results,
            "known_answer_test_status": "not established by this timing harness (Q2 tests re-run separately)",
            "constant_time_status": "not established by this timing harness",
            "security_status": "not established; Lynxer is a performance/format comparator only",
            "errors": []}


def self_test():
    """In-memory parser tests only. Synthetic nanoseconds are never a benchmark."""
    import copy
    cpu = {"logical_cpu": 3, "physical_package_id": "0", "core_id": "3"}
    cpus = [cpu, {**cpu, "logical_cpu": 4, "core_id": "4"}, {**cpu, "logical_cpu": 5, "core_id": "5"}]
    for window_set, names in WINDOWS.items():
        calls = schedule(window_set, cpus)
        require(len(calls) == BATCHES * CHUNKS * len(names), "schedule size")
        for name in names:
            mine = [c for c in calls if c["impl"] == name]
            require(len(mine) == BATCHES * CHUNKS and sum(c["samples"] for c in mine) == SAMPLES_PER_IMPL,
                    "per-implementation sample plan")
        starts = {(calls[k]["batch"], calls[k]["chunk"]): calls[k]["impl"] for k in range(0, len(calls), len(names))}
        require(len({starts[(b, 1)] for b in range(1, BATCHES + 1)}) == BATCHES, "batches must start differently")
    spec = schedule("F", cpus)[0]
    expected = IMPLS[spec["impl"]]
    meta = {"kind": "metadata", "impl_id": expected["id"], "algorithm": expected["algorithm"],
            "source_commit": expected["commit"], "api": API, "signing": SIGNING, "rng": RNG,
            "clock": "CLOCK_MONOTONIC_RAW", "clock_overhead_subtracted": False, "clock_pair_median_ns": 20.0,
            "message_bytes": 64, "public_key_bytes": 32, "secret_key_bytes": 32,
            "signature_bytes_expected": expected["signature_bytes"], "cpu": spec["cpu"], "nice": 19,
            "batch": spec["batch"], "round": spec["round"], "chunk": spec["chunk"], "samples_requested": 167,
            "warmups_requested": 32, "sample_offset": 0}
    rows = [meta, {"kind": "validation", "algorithm": expected["algorithm"], "passed": True, "roundtrips": 2,
                   "distinct_randomized_signatures": True, "tamper_rejections": 5,
                   "scope": "not a known-answer test or security proof"}]
    for i in range(199):
        rows.append({"kind": "sample", "algorithm": expected["algorithm"], "batch": 1, "round": 1, "chunk": 1,
                     "sample_index": i if i < 32 else i - 32, "warmup": i < 32, "kg_ns": 1000 + i,
                     "sign_ns": 100000 + i, "verify_ns": 90000 + i, "kg_rc": 0, "sign_rc": 0, "verify_rc": 0,
                     "signature_bytes": expected["signature_bytes"], "kg_rng_calls": 1, "sign_rng_calls": 1,
                     "verify_rng_calls": 0, "valid": True})
    rows.append({"kind": "chunk_summary", "algorithm": expected["algorithm"], "batch": 1, "round": 1,
                 "chunk": 1, "samples": 167, "failures": 0, "signature_bytes": expected["signature_bytes"],
                 "kg_median_ns": 1115, "sign_median_ns": 100115, "verify_median_ns": 90115})
    require(len(inspect_call(rows, spec)["samples"]) == 167, "valid synthetic input rejected")
    stats = metrics(inspect_call(rows, spec)["samples"])
    require(stats["kg_median_ns"] == 1115 and stats["kg_q1_ns"] == 1073.5 and stats["kg_q3_ns"] == 1156.5,
            "quartile computation drift")
    mutations = {
        "omitted_sign_randomness": lambda x: x[34].update(sign_rng_calls=0),
        "missing_keypair_randomness": lambda x: x[34].update(kg_rng_calls=0),
        "wrong_cpu": lambda x: x[0].update(cpu=9),
        "wrong_impl_id": lambda x: x[0].update(impl_id=2),
        "duplicate_index": lambda x: x[35].update(sample_index=0),
        "failed_verify": lambda x: x[34].update(verify_rc=-1),
        "wrong_signature_size": lambda x: x[34].update(signature_bytes=4000),
        "truncated_samples": lambda x: x.pop(34),
        "null_timing": lambda x: x[34].update(sign_ns=None),
        "false_chunk_median": lambda x: x[-1].update(kg_median_ns=1),
    }
    for name, mutation in mutations.items():
        bad = copy.deepcopy(rows)
        mutation(bad)
        try:
            inspect_call(bad, spec)
        except (ValueError, KeyError, TypeError):
            continue
        raise ValueError("negative self-test unexpectedly accepted: " + name)
    return {"scope": "synthetic in-memory validator tests; no cryptographic execution or measurements",
            "passed": True, "positive_cases": 1, "negative_cases": list(mutations)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("window", nargs="?", type=Path)
    parser.add_argument("--live-build", type=Path, help="also check existing live binary/harness hashes")
    parser.add_argument("--output", type=Path, help="new JSON file; existing files are never overwritten")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(), ensure_ascii=False, indent=2, allow_nan=False))
        return 0
    if args.window is None:
        parser.error("window is required")
    try:
        value = audit_window(args.window, args.live_build)
        code = 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        reason = str(error)
        for path, label in ((args.window, "<WINDOW>"), (args.live_build, "<BUILD>"), (Path.home(), "<HOME>")):
            if path is not None:
                reason = reason.replace(str(path.resolve()), label)
        reason = re.sub(r"/home/[^/\s\x27\x22]+", "<HOME>", reason)
        value = {"schema_version": 1, "status": "incomplete_or_invalid", "evidence_kind": "not established",
                 "results": None, "errors": [reason]}
        code = 2
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.output is not None:
        with args.output.open("x", encoding="utf-8", newline="\n") as out:
            out.write(text)
    print(text, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
