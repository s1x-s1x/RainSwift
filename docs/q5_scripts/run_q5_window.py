"""迭代030 Q5：运行一个冻结的同机同窗口计时窗口（F 或 S），只在本项目其他任务全部结束后运行（由 Q3 版本改写，规程不变）。

由 P0 run_baseline_window_v4.py（迭代028 linkfix_v3）改写；机制不变：每次调用前做本项目空闲检查、资源检查与
二进制哈希核对；计时子进程 nice 19、单逻辑 CPU、16 GiB 地址空间、父进程死亡即终止；同一时刻只有一个计时进程；
原始输出只新建不覆盖，失败窗口同样留档。Q3 的变化：实现与窗口取自 q5_common.py；来源核验覆盖四棵源码树、
兼容补丁与生成文件；窗口前后记录所用 CPU 及其 SMT 兄弟核的占用（只作背景证据，不作判定）。

示例（路径均在实验目录内）：
  python3 -I scripts/run_q5_window.py --root . --build q5-builds/b1 --source-root inputs/sources \
    --source-manifest inputs/source_manifest.json --window-set F --label F1 --cpus 16,17,18 \
    --parallel-work-complete --completed-receipt q5-builds/b1/phaseA_receipt.json
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

if sys.platform == "linux":
    import ctypes
    import resource

    _libc = ctypes.CDLL(None, use_errno=True)
    _libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    _libc.prctl.restype = ctypes.c_int

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from q5_common import (API, GATE_CANDIDATE, IMPLS, ROOT_PREFIX, SAMPLES_PER_BATCH, TREES,  # noqa: E402
                       WARMUPS_PER_CHUNK, WINDOWS, WRAP_METADATA, canonical_hash, expected_work_inventory,
                       inventory, read_json, require, safe_relative, sha256)
from summarize_q5_window import inspect_call, parse_jsonl, schedule, validation_schedule  # noqa: E402

CALL_SECONDS_CAP = 120.0


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def interrupt_on_sigterm(signum, frame):
    """Enter the existing child cleanup and failed-window evidence path."""
    raise KeyboardInterrupt("window supervisor received SIGTERM")


def arm_parent_death_signal(expected_parent_pid):
    """Child-only Linux guard: no other process is signalled or inspected."""
    if _libc.prctl(1, int(signal.SIGKILL), 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        raise OSError(ctypes.get_errno(), "PR_SET_PDEATHSIG failed")
    # Setting PDEATHSIG is not retroactive if the parent exited before prctl.
    if os.getppid() != expected_parent_pid:
        os.kill(os.getpid(), signal.SIGKILL)
        os._exit(128 + int(signal.SIGKILL))


def write_new_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def below(root, supplied):
    path = supplied if supplied.is_absolute() else root / supplied
    path = path.resolve(strict=True)
    require(path.is_relative_to(root), "input path must stay inside the experiment")
    return path


def redactor(root):
    prefixes = sorted([(str(root), "<EXPERIMENT>"), (str(Path.home()), "<HOME>")],
                      key=lambda item: -len(item[0]))
    def clean(text):
        for prefix, replacement in prefixes:
            if prefix:
                text = text.replace(prefix, replacement)
        text = re.sub(r"/home/[^/\s\x27\x22]+", "<HOME>", text)
        return re.sub(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", "<IP>", text)
    return clean


def resource_snapshot():
    memory = {line.split(":", 1)[0]: int(line.split()[1])
              for line in Path("/proc/meminfo").read_text().splitlines()}
    load = os.getloadavg()[0]
    return {"utc": utc_now(), "load1": load, "memory_available_GiB": memory["MemAvailable"] / 2**20,
            "safe_procs": max(0, min(160, int((os.cpu_count() or 1) - load - 16)))}


def resource_ok(snapshot, initial_load):
    require(snapshot["memory_available_GiB"] > 32, "available memory reached the 32 GiB reserve")
    require(snapshot["safe_procs"] >= 1, "no safe processing capacity remains")
    require(snapshot["load1"] <= initial_load + 32, "shared-server load increased beyond the frozen guard")


def disk_snapshot(root):
    values = []
    for path in (root, root.parent.parent):
        out = subprocess.check_output(["du", "-s", "-B1", str(path)], stderr=subprocess.DEVNULL, timeout=120)
        values.append(int(out.split()[0]))
    require(values[0] < 32 * 2**30 and values[1] < 100 * 2**30, "experiment/project disk cap reached")
    return {"experiment_bytes": values[0], "project_bytes": values[1]}


def cpu_busy_snapshot(cpus, seconds=1.0):
    """Busy fraction of the chosen logical CPUs and their SMT siblings over a short interval (context only)."""
    wanted = set()
    for cpu in cpus:
        for part in cpu["thread_siblings_list"].split(","):
            if "-" in part:
                low, high = map(int, part.split("-"))
                wanted.update(range(low, high + 1))
            else:
                wanted.add(int(part))
    def read():
        values = {}
        for line in Path("/proc/stat").read_text().splitlines():
            fields = line.split()
            if fields and fields[0].startswith("cpu") and fields[0][3:].isdigit() and int(fields[0][3:]) in wanted:
                numbers = list(map(int, fields[1:]))
                values[int(fields[0][3:])] = (sum(numbers[:8]), numbers[3] + numbers[4])
        return values
    first = read()
    time.sleep(seconds)
    second = read()
    busy = {}
    for cpu in sorted(wanted):
        total = second[cpu][0] - first[cpu][0]
        idle = second[cpu][1] - first[cpu][1]
        busy[str(cpu)] = None if total <= 0 else round(1 - idle / total, 4)
    return {"utc": utc_now(), "interval_seconds": seconds, "busy_fraction": busy,
            "scope": "chosen CPUs and SMT siblings; other users' load is context, not a gate"}


def process_info(pid):
    # The fields after the final ')' start with state and parent pid.
    tail = (Path("/proc") / str(pid) / "stat").read_text().rsplit(") ", 1)[1].split()
    return {"state": tail[0], "ppid": int(tail[1]), "start_ticks": int(tail[19])}


def ancestors():
    result = set()
    pid = os.getpid()
    while pid > 0 and pid not in result:
        result.add(pid)
        try:
            pid = process_info(pid)["ppid"]
        except (OSError, ValueError, IndexError):
            break
    return result


def project_idle(project):
    """Conservative live /proc check, not a lock-file or remembered-PID check."""
    excluded = ancestors()
    blocked = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) in excluded:
            continue
        try:
            status = (entry / "status").read_text()
            uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
            if int(uid_line.split()[1]) != os.geteuid():
                continue
            info = process_info(int(entry.name))
            if info["state"] in ("Z", "X"):
                continue
            argv = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
            if not argv:
                continue
            try:
                cwd_in_project = (entry / "cwd").resolve(strict=True).is_relative_to(project)
            except OSError:
                cwd_in_project = False
            if cwd_in_project or str(project) in argv:
                blocked.append({"pid": int(entry.name), "start_ticks": info["start_ticks"],
                                "reason": "other live same-uid process uses project cwd or command path"})
        except (OSError, StopIteration, ValueError, IndexError):
            # A process that exited during enumeration is not treated as a live job.
            continue
    evidence = {"utc": utc_now(), "checked_same_uid_project_processes": True,
                "scope": "live same-uid /proc cwd/argv project-anchor check; ancestors excluded; not host exclusivity",
                "blocking_processes": blocked}
    require(not blocked, "other project processes are still live: " + ",".join(str(p["pid"]) for p in blocked))
    return evidence


def topology(cpu):
    directory = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
    return {"logical_cpu": cpu,
            "physical_package_id": (directory / "physical_package_id").read_text().strip(),
            "core_id": (directory / "core_id").read_text().strip(),
            "thread_siblings_list": (directory / "thread_siblings_list").read_text().strip()}


def choose_cpus(text):
    allowed = os.sched_getaffinity(0)
    cpus = [int(value) for value in text.split(",")]
    require(len(cpus) == 3 and len(set(cpus)) == 3 and set(cpus) <= allowed,
            "--cpus needs three distinct CPUs inside inherited affinity")
    chosen = [topology(cpu) for cpu in cpus]
    require(len({(c["physical_package_id"], c["core_id"]) for c in chosen}) == 3,
            "three distinct physical cores are required")
    return chosen


def collect_provenance(build, source_root, manifest_path, window_set):
    manifest = read_json(manifest_path)
    expected_sources = manifest["files"]
    actual = inventory(source_root)
    require(actual == expected_sources, "source tree differs from the full pinned manifest")
    trees = {entry["tree"]: entry for entry in manifest["sources"]}
    for tree, spec in TREES.items():
        require(trees[tree]["commit"] == spec["commit"] and trees[tree]["path"] == spec["source_dir"],
                "source identity mismatch: " + tree)
    artifacts = read_json(build / "artifact_manifest.json")
    inputs = read_json(build / "build_inputs.json")
    patches = read_json(build / "compatibility_patches.json")
    created = read_json(build / "created_files.json")
    by_name = {record["impl"]: record for record in artifacts["records"]}
    input_by_name = {record["impl"]: record for record in inputs}
    require(set(by_name) == set(IMPLS) == set(input_by_name) and len(artifacts["records"]) == len(IMPLS) == len(inputs),
            "all eleven completed implementation artifacts are required")
    patch_paths = set()
    for patch in patches:
        require(patch["file"] not in patch_paths, "duplicate compatibility patch entry")
        patch_paths.add(patch["file"])
        require(sha256(safe_relative(build, patch["file"])) == patch["after_sha256"], "patched source hash mismatch")
        require(sha256(safe_relative(build, "backups/" + patch["file"])) == patch["before_sha256"],
                "compatibility backup hash mismatch")
    for item in created:
        require(item["file"] not in patch_paths, "created file also recorded as a patch")
        require(sha256(safe_relative(build, item["file"])) == item["sha256"], "created file hash mismatch")
    harness_hashes = {record["harness_sha256"] for record in inputs}
    require(len(harness_hashes) == 1, "implementations use different harnesses")
    harness_hash = harness_hashes.pop()
    tree_checks = {}
    for tree in TREES:
        work = build / "work" / tree
        harness_entry = {"bytes": (work / "q5_harness.cpp").stat().st_size, "sha256": sha256(work / "q5_harness.cpp")}
        require(harness_entry["sha256"] == harness_hash, "harness differs from build inputs: " + tree)
        expected_work = expected_work_inventory(tree, expected_sources, patches, created, harness_entry)
        current_work = inventory(work)
        build_metadata = {}
        # Meson may write this one non-code control file into the vendored XKCP directory (observed in P0).
        if WRAP_METADATA in current_work and WRAP_METADATA not in expected_work:
            require(current_work[WRAP_METADATA]["bytes"] <= 4096, "unexpectedly large Meson wrap metadata")
            build_metadata[WRAP_METADATA] = dict(current_work[WRAP_METADATA])
            expected_work[WRAP_METADATA] = dict(current_work[WRAP_METADATA])
        require(current_work == expected_work, "unrecorded build source changes: " + tree)
        tree_checks[tree] = {"inventory_sha256": canonical_hash(expected_work), "build_metadata_files": build_metadata}
    binaries = {}
    for name in WINDOWS[window_set]:
        record = by_name[name]
        require(record["declared_fixed_commit"] == IMPLS[name]["commit"] and record["impl_id"] == IMPLS[name]["id"]
                and record["tree"] == IMPLS[name]["tree"], "fixed implementation identity mismatch: " + name)
        require(all(record.get(k) == v for k, v in input_by_name[name].items()), "build input/artifact mismatch")
        binary = safe_relative(build, record["executable"])
        require(binary.is_file() and os.access(binary, os.X_OK), "implementation artifact is not executable")
        require(sha256(binary) == record["executable_sha256"] and binary.stat().st_size == record["executable_bytes"],
                "implementation binary differs from its build manifest")
        for key, digest in record["original_core_hashes"].items():
            require(expected_sources[TREES[record["tree"]]["source_dir"] + "/" + key]["sha256"] == digest,
                    "original core hash mismatch")
        for key, digest in record["patched_core_hashes"].items():
            require(sha256(build / "work" / record["tree"] / key) == digest, "patched core hash mismatch")
        binaries[name] = {"executable_sha256": record["executable_sha256"],
                          "executable_bytes": record["executable_bytes"], "harness_sha256": harness_hash,
                          "patched_source_files_verified": True,
                          "build_metadata_files": tree_checks[record["tree"]]["build_metadata_files"],
                          "patched_source_inventory_sha256": tree_checks[record["tree"]]["inventory_sha256"],
                          "executable_relative_to_build": record["executable"]}
    source_verification = {"all_files_verified": True, "file_count": len(actual),
                           "inventory_sha256": canonical_hash(actual)}
    binding = {"source_manifest_sha256": sha256(manifest_path),
               "artifact_manifest_sha256": sha256(build / "artifact_manifest.json"),
               "build_inputs_sha256": sha256(build / "build_inputs.json"),
               "compatibility_patches_sha256": sha256(build / "compatibility_patches.json"),
               "created_files_sha256": sha256(build / "created_files.json"),
               "source_inventory_sha256": canonical_hash(actual),
               "tree_inventories": {tree: check["inventory_sha256"] for tree, check in tree_checks.items()},
               "binaries": binaries}
    return {"source_verification": source_verification, "binaries": binaries, "binding": binding}


def receipt_evidence(root, supplied):
    records = []
    for path in supplied:
        path = below(root, path)
        receipt = read_json(path)
        require(receipt.get("exit_code") == 0 and receipt.get("stop_reason") is None,
                "a prerequisite supervisor receipt is not successful")
        require(datetime.fromisoformat(receipt["end_utc"]).timestamp() <= time.time(),
                "prerequisite receipt has no past completion time")
        records.append({"path_relative_to_experiment": path.relative_to(root).as_posix(),
                        "sha256": sha256(path), "name": receipt["name"],
                        "end_utc": receipt["end_utc"], "exit_code": receipt["exit_code"]})
    return records


def run_call(root, build, window, spec, provenance, deadline, monotonic_deadline, initial_load, clean):
    idle = project_idle(root.parent.parent)
    before_resource = resource_snapshot()
    resource_ok(before_resource, initial_load)
    record = provenance["binaries"][spec["impl"]]
    binary = safe_relative(build, record["executable_relative_to_build"])
    binary_hash = sha256(binary)
    require(binary_hash == record["executable_sha256"], "binary changed before invocation")
    seconds = min(CALL_SECONDS_CAP, deadline - time.time(), monotonic_deadline - time.monotonic())
    require(seconds > 0, "window/gate deadline reached before invocation")
    arguments = [str(binary), "--samples", str(spec["samples"]), "--warmup", str(spec["warmup"]),
                 "--batch", str(spec["batch"]), "--round", str(spec["round"]),
                 "--chunk", str(spec["chunk"]), "--sample-offset", str(spec["sample_offset"])]
    if spec["validate_only"]:
        arguments.append("--validate-only")
    env = dict(os.environ)
    env.update({key: "1" for key in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
                                     "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS")})
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    expected_parent_pid = os.getpid()
    def limits():
        arm_parent_death_signal(expected_parent_pid)
        if os.nice(0) < 19:
            os.nice(19 - os.nice(0))
        os.sched_setaffinity(0, {spec["cpu"]})
        resource.setrlimit(resource.RLIMIT_AS, (16 * 2**30, 16 * 2**30))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # The fork inherits our short spawn-time signal mask, not a permanent block.
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    start_utc, started = utc_now(), time.monotonic()
    proc = None
    timed_out, resource_stop = False, None
    try:
        # Keep cancellation pending until Popen has assigned the owned child.
        # A fatal parent exit at any point is covered by the child-only guard.
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        try:
            proc = subprocess.Popen(arguments, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True, preexec_fn=limits)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        while True:
            remaining = seconds - (time.monotonic() - started)
            if remaining <= 0:
                timed_out = True
                break
            try:
                stdout, stderr = proc.communicate(timeout=min(5.0, remaining))
                break
            except subprocess.TimeoutExpired:
                try:
                    resource_ok(resource_snapshot(), initial_load)
                except ValueError as error:
                    resource_stop = str(error)
                    break
        if timed_out or resource_stop:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                stdout, stderr = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                stdout, stderr = proc.communicate(timeout=15)
    except BaseException:
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # It exited after poll; do not replace the original failure.
            proc.communicate(timeout=15)
        raise
    original_stdout = stdout.decode("utf-8", "replace")
    stdout_text, stderr_text = clean(original_stdout), clean(stderr.decode("utf-8", "replace"))
    stdout_path = window / "raw" / (spec["tag"] + ".jsonl")
    stderr_path = window / "raw" / (spec["tag"] + ".stderr.txt")
    for path, content in ((stdout_path, stdout_text), (stderr_path, stderr_text)):
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    result = {"spec": spec, "start_utc": start_utc, "end_utc": utc_now(),
              "supervisor_wall_seconds": time.monotonic() - started,
              "returncode": proc.returncode, "timed_out": timed_out, "resource_stop": resource_stop,
              "idle_check": idle, "initial_resources": before_resource,
              "binary_sha256": binary_hash, "stdout_redacted": stdout_text != original_stdout,
              "stdout_path": stdout_path.relative_to(window).as_posix(), "stdout_sha256": sha256(stdout_path),
              "stderr_path": stderr_path.relative_to(window).as_posix(), "stderr_sha256": sha256(stderr_path)}
    # The immutable per-call receipt remains even if validation below fails.
    write_new_json(window / "receipts" / (spec["tag"] + ".json"), result)
    return result, stdout_text, stderr_text


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--window-set", choices=sorted(WINDOWS), required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--parallel-work-complete", action="store_true", required=True,
                        help="caller confirms all project compilation/test jobs have ended; /proc is checked too")
    parser.add_argument("--completed-receipt", action="append", type=Path, default=[])
    parser.add_argument("--cpus", required=True, help="three logical CPUs on distinct physical cores (frozen: 16,17,18)")
    parser.add_argument("--seconds", type=int, default=3600)
    args = parser.parse_args()
    require(sys.platform == "linux", "formal window must run on the experiment's Linux server")
    root = args.root.resolve(strict=True)
    require(root.name.startswith(ROOT_PREFIX) and root.parent.name == "build" and
            root.parent.parent.name == "pqc-a1-5", "unexpected experiment-root layout")
    require(re.fullmatch(r"[A-Za-z0-9_-]+", args.label) is not None, "invalid fresh window label")
    require(0 < args.seconds <= 21600, "window seconds outside the six-hour batch cap")
    clean = redactor(root)
    window = root / "q5-windows" / args.label
    require(not window.parent.is_symlink(), "window parent must not be a symlink")
    window.parent.mkdir(exist_ok=True)
    require(window.parent.resolve(strict=True).is_relative_to(root), "window parent leaves experiment")
    window.mkdir()  # A previously started window is never overwritten or resumed implicitly.
    for name in ("raw", "receipts", "provenance"):
        (window / name).mkdir()
    outcome = {"schema_version": 1, "status": "failed", "start_utc": utc_now(), "runs": [],
               "plan_sha256": None, "final_provenance_verification": None, "failure_reason": None}
    start = time.monotonic()
    try:
        signal.signal(signal.SIGTERM, interrupt_on_sigterm)
        gate = read_json(root / "control/gate.json")
        require(gate.get("new_compute_enabled") is True and gate.get("allow_full_benchmark") is True,
                "current gate has not opened full benchmarking")
        require(gate.get("candidate") == GATE_CANDIDATE, "gate candidate mismatch")
        require(gate.get("memory_limit_per_task_gib", 0) >= 16, "gate memory limit is below the recipe")
        deadline = datetime.fromisoformat(gate["valid_until_utc"]).timestamp()
        seconds = min(args.seconds, gate["remaining_compute_wall_seconds"], deadline - time.time())
        require(seconds > 0, "current gate is expired or has no remaining budget")
        monotonic_deadline = start + seconds
        if os.nice(0) < 19:
            os.nice(19 - os.nice(0))
        require(os.nice(0) == 19, "window supervisor must use nice 19")
        initial_resource = resource_snapshot()
        resource_ok(initial_resource, initial_resource["load1"])
        initial_disk = disk_snapshot(root)
        idle = project_idle(root.parent.parent)
        prerequisites = receipt_evidence(root, args.completed_receipt)
        cpus = choose_cpus(args.cpus)
        build = below(root, args.build)
        source_root = below(root, args.source_root)
        manifest = below(root, args.source_manifest)
        provenance = collect_provenance(build, source_root, manifest, args.window_set)
        script_dir = Path(__file__).resolve().parent
        snapshot_sources = {
            "source_manifest.json": manifest, "artifact_manifest.json": build / "artifact_manifest.json",
            "build_inputs.json": build / "build_inputs.json",
            "compatibility_patches.json": build / "compatibility_patches.json",
            "created_files.json": build / "created_files.json",
            "q5_harness.cpp": build / "work/rain/q5_harness.cpp",
            "q5_common.py": script_dir / "q5_common.py",
            "run_q5_window.py": Path(__file__).resolve(),
            "summarize_q5_window.py": script_dir / "summarize_q5_window.py",
            "gate.json": root / "control/gate.json",
        }
        snapshots = {}
        for name, original in snapshot_sources.items():
            destination = window / "provenance" / name
            with destination.open("xb") as stream:
                stream.write(original.read_bytes())
            snapshots["provenance/" + name] = sha256(destination)
        provenance["snapshots"] = snapshots
        calls = validation_schedule(args.window_set, cpus) + schedule(args.window_set, cpus)
        plan = {"schema_version": 1, "created_utc": utc_now(), "label": args.label, "window_set": args.window_set,
                "implementations": list(WINDOWS[args.window_set]), "host_label": "实验服务器（EPYC 7R32）",
                "api": API, "message_bytes": 64, "clock": "CLOCK_MONOTONIC_RAW",
                "samples_per_batch": SAMPLES_PER_BATCH, "warmups_per_chunk": WARMUPS_PER_CHUNK,
                "physical_cpus": cpus, "parallel_work_complete_attested": True,
                "initial_project_idle_check": idle, "completed_prerequisites": prerequisites,
                "initial_resources": initial_resource, "initial_disk": initial_disk,
                "cpu_busy_snapshot": cpu_busy_snapshot(cpus),
                "gate_sha256": sha256(root / "control/gate.json"), "valid_until_utc": gate["valid_until_utc"],
                "supervisor_time_cap_seconds": seconds, "call_seconds_cap": CALL_SECONDS_CAP, "calls": calls,
                "provenance": provenance,
                "scope": "Q5 same-machine same-window timing (Q3 protocol); smoke checks are neither KATs nor security proofs"}
        write_new_json(window / "window_plan.json", plan)
        outcome["plan_sha256"] = sha256(window / "window_plan.json")
        for spec in calls:
            result, stdout, stderr = run_call(root, build, window, spec, provenance, deadline,
                                              monotonic_deadline, initial_resource["load1"], clean)
            outcome["runs"].append(result)
            require(result["returncode"] == 0 and not result["timed_out"] and result["resource_stop"] is None,
                    "harness invocation failed: " + spec["tag"])
            require(not stderr.strip() and not result["stdout_redacted"], "unexpected harness diagnostics: " + spec["tag"])
            inspect_call(parse_jsonl(stdout), spec)
            print(json.dumps({"event": "completed_call", "tag": spec["tag"],
                              "nonwarmup_samples": spec["samples"], "cpu": spec["cpu"]}), flush=True)
        outcome["final_project_idle_check"] = project_idle(root.parent.parent)
        outcome["final_provenance_verification"] = collect_provenance(build, source_root, manifest,
                                                                      args.window_set)["binding"]
        require(outcome["final_provenance_verification"] == provenance["binding"], "provenance changed during window")
        outcome["final_resources"] = resource_snapshot()
        resource_ok(outcome["final_resources"], initial_resource["load1"])
        outcome["final_cpu_busy_snapshot"] = cpu_busy_snapshot(cpus)
        outcome["final_disk"] = disk_snapshot(root)
        outcome["status"] = "complete"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        outcome["failure_reason"] = clean(type(error).__name__ + ": " + str(error))
    outcome["end_utc"] = utc_now()
    outcome["supervisor_wall_seconds"] = time.monotonic() - start
    write_new_json(window / "window_result.json", outcome)
    print(json.dumps({"status": outcome["status"], "window": window.relative_to(root).as_posix(),
                      "completed_invocations": len(outcome["runs"]), "failure_reason": outcome["failure_reason"]},
                     ensure_ascii=False), flush=True)
    return 0 if outcome["status"] == "complete" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        # Keep pre-output-directory exceptions free of machine/account paths.
        print(json.dumps({"status": "preflight_failed", "error_type": type(error).__name__,
                          "reason": "invalid arguments, experiment layout, or existing output; no benchmark completed"}),
              file=sys.stderr)
        raise SystemExit(2)
