"""Measure cache file sizes and fresh-process peak RSS during real native loads.

The peak includes Python, imports, allocator, native context and cache loading.
It is neither a theoretical node count nor isolated cache allocation. No keys
are generated and no signatures or operation timers are used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from native import NativeSlhDsa, PARAM_SHAPES


def sha(path):
    state = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            state.update(block)
    return state.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def header(path):
    with path.open("rb") as stream:
        data = stream.read(96)
    require(len(data) == 96 and data[:8] == b"A15CACHE", "cache-v1 header missing")
    version, pid, level, height, n, payload_bytes = struct.unpack_from(">6I", data, 8)
    # Validate the supported height before shifting an untrusted uint32 field.
    # A malformed header must not request a multi-gigabyte Python integer.
    require(version == 1 and pid in PARAM_SHAPES and
            height == PARAM_SHAPES[pid][0] and 0 <= level <= height and n == 16,
            "invalid cache-v1 parameter fields")
    require(payload_bytes == n * (1 << (height - level)), "cache node size differs")
    require(path.stat().st_size == 96 + payload_bytes, "cache file size differs")
    return {"pid": pid, "cache_t": level, "subtree_height": height,
            "payload_bytes": payload_bytes, "file_bytes": 96 + payload_bytes,
            "public_key": data[32:64].hex()}


def sources():
    names = {"tools/measure_cache_storage.py", "tools/native.py", "c/Makefile"}
    for directory in (ROOT / "c", ROOT / "third_party/slhdsa-c"):
        names.update(p.relative_to(ROOT).as_posix() for p in directory.rglob("*")
                     if p.is_file() and p.suffix in {".c", ".h", ".cu", ".cuh"})
    return {name: sha(ROOT / name) for name in sorted(names)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--cache", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--child-pid", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(platform.system() == "Linux", "RSS units and native .so checks require Linux")
    require(args.repeats > 0, "repeats must be positive")
    if args.child_pid is not None:
        with NativeSlhDsa(args.child_pid, threads=1, flags=1,
                          library=args.library.resolve()) as native:
            require(native.backend == 1, "fresh-process cache load requires actual REF backend")
            if args.cache:
                require(len(args.cache) == 1, "a child loads exactly one cache")
                info = header(args.cache[0])
                require(info["pid"] == args.child_pid, "cache pid differs")
                native.cache_load(args.cache[0], bytes.fromhex(info["public_key"]))
            print(json.dumps({"pid": args.child_pid, "backend_actual": native.backend,
                              "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
                              "native_load_passed": True, "process_id": os.getpid()}))
        return 0
    require(args.output is not None and args.cache, "--output and at least one --cache are required")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    library_hash, before = sha(args.library), sources()
    cache_hashes = {str(p.resolve()): sha(p) for p in args.cache}
    result = {"schema": "a15-cache-storage-rss-v1", "passed": False,
              "scope": "Observed cache-v1 disk bytes and Linux fresh-process peak RSS during verified native cache load; includes interpreter/context/allocator and transient buffers",
              "platform": platform.platform(), "python": sys.version,
              "library_sha256": library_hash, "source_sha256": before,
              "cache_sha256": cache_hashes, "rows": [], "signing_calls": 0,
              "formal_performance_samples": 0, "durations_measured": False}
    env = {k: v for k, v in os.environ.items()
           if k not in {"PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE"}}
    env.update(PYTHONDONTWRITEBYTECODE="1", OMP_NUM_THREADS="1", OMP_DYNAMIC="FALSE")
    try:
        baseline = {}
        for path in args.cache:
            info = header(path)
            pid = info["pid"]
            if pid not in baseline:
                command = [sys.executable, "-B", str(Path(__file__).resolve()), "--library",
                           str(args.library.resolve()), "--child-pid", str(pid)]
                child = subprocess.run(command, env=env, capture_output=True, text=True, timeout=300)
                require(child.returncode == 0, "baseline process failed: " + child.stderr)
                baseline[pid] = json.loads(child.stdout)
            samples = []
            for repeat in range(args.repeats):
                command = [sys.executable, "-B", str(Path(__file__).resolve()), "--library",
                           str(args.library.resolve()), "--child-pid", str(pid), "--cache", str(path.resolve())]
                child = subprocess.run(command, env=env, capture_output=True, text=True, timeout=300)
                (output / f"pid{pid}-t{info['cache_t']}-repeat{repeat}.log").write_text(
                    child.stdout + child.stderr, encoding="utf-8")
                require(child.returncode == 0, "cache load child failed: " + child.stderr)
                samples.append(json.loads(child.stdout))
            result["rows"].append({**info, "cache_path": str(path.resolve()),
                                   "baseline_context_process": baseline[pid],
                                   "load_process_samples": samples,
                                   "peak_rss_min_bytes": min(s["peak_rss_bytes"] for s in samples),
                                   "peak_rss_max_bytes": max(s["peak_rss_bytes"] for s in samples)})
        result["source_unchanged"] = sources() == before
        result["library_unchanged"] = sha(args.library) == library_hash
        result["cache_unchanged"] = all(sha(Path(p)) == h for p, h in cache_hashes.items())
        result["passed"] = all(result[k] for k in ("source_unchanged", "library_unchanged", "cache_unchanged"))
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": result["passed"], "cache_configurations": len(result["rows"]),
                      "summary": str(output / "summary.json"), "error": result.get("error")}))
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
