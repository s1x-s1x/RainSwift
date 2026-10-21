"""Cooperate between local performance campaigns and reject known native load.

The persistent lock inode is deliberately kept after release. Process checks
cover known project workloads; they do not prove the host has no other load.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path

NATIVE_SCRIPTS = {
    "check_optimization.py", "bench_cpu.py", "bench_cuda.py",
    "bench_local_lifecycle.py", "check_kernel_network.py",
    "bench_verify_optimization.py", "run_native_stage2.py",
    "bootstrap_local_env.py", "check_verify_optimization_signing.py",
    "reproduce_verify_optimization.py", "reproduce_project.py",
    "run_stage1.py", "generate_reference_vectors.py", "run_acceptance.py",
    "check_digest_native.py", "check_rng_native.py", "check_real_resume.py",
    "measure_cache_storage.py",
}


def fully_stopped(directory):
    """A traced/stopped leader alone does not prove all native threads stopped."""
    try:
        tasks = [p for p in (directory / "task").iterdir() if p.name.isdecimal()]
        if not tasks:
            return False
        return all(next((line.split()[1] for line in (task / "status").read_text().splitlines()
                         if line.startswith("State:")), "?") == "T" for task in tasks)
    except (OSError, ValueError):
        return False


def native_competitors(owner_pid=None, proc_root=Path("/proc"), include_stopped=False):
    """Return known competing processes, excluding the owner's descendants."""
    owner_pid = os.getpid() if owner_pid is None else owner_pid
    processes = {}
    for directory in proc_root.iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            argv = [part.decode("utf-8", errors="replace")
                    for part in (directory / "cmdline").read_bytes().split(b"\0") if part]
            status = (directory / "status").read_text()
            parent = next(int(line.split()[1]) for line in status.splitlines()
                          if line.startswith("PPid:"))
            state = next((line.split()[1] for line in status.splitlines()
                          if line.startswith("State:")), "?")
        except (OSError, StopIteration, ValueError):
            continue
        processes[int(directory.name)] = (parent, argv, state, state == "T" and fully_stopped(directory))
    owned = {owner_pid}
    while True:
        descendants = {pid for pid, (parent, _, _, _) in processes.items() if parent in owned}
        if descendants <= owned:
            break
        owned.update(descendants)
    active = []
    for pid, (_, argv, state, stopped) in sorted(processes.items()):
        if pid in owned or not argv:
            continue
        names = {Path(part).name for part in argv}
        scripts = sorted(names & NATIVE_SCRIPTS)
        native_test = Path(argv[0]).name.startswith("test_")
        pytest = "pytest" in names or "py.test" in names
        if (scripts or native_test or pytest) and (include_stopped or not stopped):
            active.append({"pid": pid, "scripts": scripts, "program": Path(argv[0]).name,
                           "state": state, "fully_stopped": stopped})
    return active


def require_quiet(owner_pid=None):
    active = native_competitors(owner_pid)
    if active:
        raise RuntimeError("overlapping native workload: " + json.dumps(active, sort_keys=True))


@contextmanager
def performance_exclusive(root, label):
    """Hold a nonblocking Linux flock throughout one cooperating campaign."""
    if os.name != "posix":
        raise RuntimeError("performance workload locking requires Linux")
    import fcntl
    path = Path(root).resolve() / "build" / "performance-workload.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            stream.seek(0)
            owner = stream.read(4096)
            raise RuntimeError("another performance campaign holds the lock: " + owner) from error
        try:
            record = {"pid": os.getpid(), "label": label,
                      "started_utc": datetime.now(timezone.utc).isoformat(), "lock_path": str(path),
                      "stopped_known_native_workloads": [p for p in native_competitors(include_stopped=True)
                                                         if p["fully_stopped"]]}
            stream.seek(0)
            stream.truncate()
            json.dump(record, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            require_quiet()
            yield record
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
