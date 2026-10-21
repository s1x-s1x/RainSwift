"""Interrupt a real toy signing worker after one persisted sample, then resume.

This is functional failure injection using the real ABI and diagnostic timers.
It supplies no competition performance result and never signs a 128-24 key.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import bench_cpu as cpu


def worker(args):
    specification = cpu.read_json(args.output / "worker.json")
    parsed = cpu.parser().parse_args(specification["arguments"])
    if args.changed_build_record:
        parsed.build_record = args.changed_build_record
    if args.interrupt:
        append = cpu.append
        def stop_after_sample(path, row):
            append(path, row)
            if row.get("kind") == "sample" and row.get("passed"):
                # The complete sample and committed receipt have been persisted.
                # No finally block runs: the resumed process creates new contexts.
                os._exit(73)
        cpu.append = stop_after_sample
    with cpu.output_lock(parsed.output):
        cpu.worker(parsed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path)
    parser.add_argument("--build-record", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--interrupt", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--changed-build-record", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error("this acceptance check requires Python assertions enabled")
    args.output = args.output.resolve()
    if args.child:
        worker(args)
        return 0
    if args.library is None or args.build_record is None or os.name != "posix":
        parser.error("Linux, --library and --build-record are required")
    args.output.mkdir(parents=True, exist_ok=False)
    topo, _ = cpu.topology()
    selected = [row["cpu"] for row in cpu.physical_cpus(topo, 1)]
    case = cpu.case_record(201, "sign", cache="5", samples=3, family="real-recovery")
    plan = cpu.make_plan("smoke", [], [], [])
    plan["cases"] = [case]
    cpu.atomic_json(args.output / "plan.json", plan)
    arguments = ["worker", "--worker-case", case["case_id"], "--parent-pid", str(os.getpid()),
        "--library", str(args.library.resolve()), "--build-record", str(args.build_record.resolve()),
        "--plan", str(args.output / "plan.json"), "--output", str(args.output / "raw.jsonl"),
        "--fixtures", str(args.output / "fixtures"), "--budget-db", str(args.output / "budget.sqlite"),
        "--cpus", ",".join(map(str, selected))]
    cpu.atomic_json(args.output / "worker.json", {"arguments": arguments})
    env = {key: value for key, value in os.environ.items() if not key.startswith(("OMP_", "GOMP_", "KMP_"))}
    env.update(cpu.openmp_environment(1, selected), PYTHONDONTWRITEBYTECODE="1")
    steps = []
    try:
        for name, interrupted in (("interrupted", True), ("resumed", False), ("completed-skip", False)):
            command = [sys.executable, "-B", str(Path(__file__).resolve()), "--output", str(args.output), "--child"]
            if interrupted:
                command.append("--interrupt")
            with (args.output / (name + ".log")).open("xb") as stream:
                result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
            steps.append({"step": name, "command": command, "exit_code": result.returncode})
            if result.returncode != (73 if interrupted else 0):
                raise ValueError("unexpected worker exit: " + name)
            evidence = cpu.rows(args.output / "raw.jsonl")
            if interrupted:
                assert sum(row.get("kind") == "sample" and row.get("passed") for row in evidence) == 1
                assert not any(row.get("kind") == "case_complete" for row in evidence)
            if name == "resumed":
                accepted_bytes = (args.output / "raw.jsonl").read_bytes()
            if name == "completed-skip":
                assert (args.output / "raw.jsonl").read_bytes() == accepted_bytes
        # Same native code and plan, changed valid build metadata: accepting the
        # old completed case would mix two build identities in one campaign.
        changed = cpu.read_json(args.build_record)
        changed["repair_identity_probe"] = "different metadata, same native bytes"
        changed_path = args.output / "changed-build-record.json"
        cpu.atomic_json(changed_path, changed)
        command = [sys.executable, "-B", str(Path(__file__).resolve()), "--output", str(args.output), "--child",
                   "--changed-build-record", str(changed_path)]
        log = args.output / "changed-build-rejected.log"
        with log.open("xb") as stream:
            rejected = subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
        steps.append({"step": "changed-build-rejected", "command": command, "exit_code": rejected.returncode})
        assert rejected.returncode != 0 and "case resume environment/source/build differs" in log.read_text()
        assert (args.output / "raw.jsonl").read_bytes() == accepted_bytes
        starts = [row for row in evidence if row.get("kind") == "case_start"]
        assert len(starts) == 2 and starts[0]["pid_process"] != starts[1]["pid_process"]
        for start in starts:
            segment = [row for row in evidence if row.get("segment_id") == start["segment_id"]]
            warmups = [row for row in segment if row.get("kind") == "warmup" and row.get("passed")]
            assert len(warmups) == case["warmups"] == 1
            assert next(index for index, row in enumerate(segment) if row.get("kind") == "warmup") < next(
                index for index, row in enumerate(segment) if row.get("kind") == "sample")
        budget = cpu.SigningBudget(args.output / "budget.sqlite")
        assert cpu.validate_completed(evidence, case, args.output / "fixtures", budget)
        reconciliation = budget.reconcile()
        assert reconciliation["reservations"] == 6  # setup + 2 warmups + 3 samples
        result = {"schema": "a15-real-worker-recovery-v1", "passed": True, "pid": 201,
                  "scope": "controlled interruption after a persisted sample; real ABI, diagnostic timers, no formal performance",
                  "formal_performance_samples": 0, "diagnostic_timed_samples": 3, "fresh_worker_segments": 2,
                  "warmups_per_segment": 1, "completed_skip_unchanged": True,
                  "changed_build_identity_rejected": True,
                  "driver_sha256": cpu.file_sha(Path(__file__).resolve()),
                  "steps": steps, "budget_reconciliation": reconciliation,
                  "source_sha256": cpu.hashes(cpu.BUILD_FILES + cpu.TOOL_FILES),
                  "library_sha256": cpu.file_sha(args.library)}
    except Exception as error:
        result = {"schema": "a15-real-worker-recovery-v1", "passed": False, "steps": steps,
                  "error": f"{type(error).__name__}: {error}", "formal_performance_samples": 0}
    cpu.atomic_json(args.output / "summary.json", result)
    print(json.dumps(result, ensure_ascii=False))
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
