#!/usr/bin/env python3
"""Bounded Windows GCC build of read-only Rain4 protocol evidence.

This is evidence validation, not a performance run. Source files are neither
edited nor copied back. The only platform adaptations are the upstream plain-C
Keccak backend and Windows aligned allocation/free. Output is a fresh run dir.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--budget-seconds", type=int, default=240)
    ap.add_argument("--zig", type=Path)
    args = ap.parse_args()
    if not 1 <= args.budget_seconds <= 300:
        raise ValueError("Only bounded validation up to 300 seconds is supported")
    q4 = Path(__file__).resolve().parents[2]
    iteration = q4.parent
    src = iteration / "源码" / "rain-voleith"
    xkcp = iteration.parent / "迭代028_P0基线与求解器" / "资料" / "sources" / "xkcp_v2"
    out = args.output.resolve()
    if not out.is_relative_to(q4 / "原始数据" / "重做00b"):
        raise ValueError("Output must be inside this Q4 stage's new evidence directory")
    out.mkdir(parents=True, exist_ok=False)
    obj = out / "obj"
    obj.mkdir()
    started = time.monotonic()
    frozen_files = [p for p in src.rglob("*") if p.is_file() and "粘贴的" not in p.name]
    source_before = {p.relative_to(src).as_posix(): digest(p) for p in frozen_files}
    (out / "source_sha256_before.json").write_text(json.dumps(source_before, indent=2), encoding="utf-8")
    metadata = {
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "budget_seconds": args.budget_seconds,
        "max_concurrent_compilers": 1,
        "purpose": "Q4 stage00b finite correctness evidence; no benchmarking or parameter sweep",
        "stop_conditions": ["first build/test error", "wall-clock budget", "input hash change"],
        "source": str(src), "xkcp": str(xkcp),
        "platform_adaptations": ["XKCP plain-64bits/u6 C backend for one-state Keccak", "_aligned_malloc/_aligned_free shim for Windows UCRT"],
        "cases": "Rain4 fast/bal/short: two randomized and one deterministic each",
        "steps": [],
    }
    (out / "config.h").write_bytes((src / "subprojects/packagefiles/xkcp/config.h").read_bytes())
    shim = out / "windows_alloc.hpp"
    shim.write_text("""#pragma once
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <vector>
#include <type_traits>
#include <utility>
#include <new>
#include <sys/types.h>
#include <malloc.h>
// Scope: this validation translation unit's explicit C-style aligned buffers.
// STL allocators and operator delete are unchanged.
#define aligned_alloc(alignment, ...) _aligned_malloc((__VA_ARGS__), (alignment))
#define free(pointer) _aligned_free((pointer))
""", encoding="utf-8")
    # Preserve all step-by-step assertions; change only sampled parameter sets.
    probe_original = q4 / "脚本" / "r00_dump.cpp"
    original = probe_original.read_text(encoding="utf-8")
    split = original.index("int main()")
    main_text = """int main()
{
    bool first = true;
    std::printf("[\\n");
"""
    for tier in ("fast", "bal", "short"):
        for i in range(3):
            main_text += f'    run_instance<rain_sets::rain4_{tier}>("rain4_{tier}", {i}, {"true" if i == 2 else "false"}, {"true" if i == 0 else "false"}, first);\n'
    main_text += """    std::printf("\\n]\\n");
    std::fprintf(stderr, "r00b_dump: %d checks, %d failed\\n", g_checks, g_fail);
    return g_fail != 0;
}
"""
    probe = out / "r00b_dump.cpp"
    probe.write_text(original[:split] + main_text, encoding="utf-8")
    metadata["original_probe_sha256"] = digest(probe_original)
    metadata["adapted_probe_sha256"] = digest(probe)
    incpaths = [out, src, xkcp, xkcp / "lib/common", xkcp / "lib/low/common", xkcp / "lib/high/Keccak", xkcp / "lib/high/Keccak/FIPS202",
                xkcp / "lib/low/KeccakP-1600/plain-64bits", xkcp / "lib/low/KeccakP-1600/plain-64bits/u6",
                xkcp / "lib/low/KeccakP-1600/common", xkcp / "lib/low/KeccakP-1600-times2/SIMD128",
                xkcp / "lib/low/KeccakP-1600-times2/SIMD128/SSSE3-u2", xkcp / "lib/low/KeccakP-1600-times4/AVX2",
                xkcp / "lib/low/KeccakP-1600-times4/AVX2/u12", xkcp / "lib/low/KeccakP-1600-times8/fallback-on4"]
    includes = ["-I" + str(p) for p in incpaths]
    flags = ["-O1", "-g0", "-mavx2", "-maes", "-mpclmul", "-msse4.1", "-mbmi2"]
    if args.zig:
        cc = [str(args.zig.resolve()), "cc", "-target", "x86_64-windows-gnu"]
        cxx = [str(args.zig.resolve()), "c++", "-target", "x86_64-windows-gnu"]
        metadata["zig_version"] = subprocess.check_output([str(args.zig.resolve()), "version"], text=True).strip()
        os.environ["ZIG_GLOBAL_CACHE_DIR"] = str(out / "zig-global-cache")
        os.environ["ZIG_LOCAL_CACHE_DIR"] = str(out / "zig-local-cache")
    else:
        cc_path, cxx_path = shutil.which("gcc"), shutil.which("g++")
        if not cc_path or not cxx_path:
            raise RuntimeError("GCC is not on PATH")
        cc, cxx = [cc_path], [cxx_path]
        metadata["gcc_version"] = subprocess.check_output([cxx_path, "--version"], text=True).splitlines()[0]

    def run(command, label, stdout_name=None):
        remain = args.budget_seconds - (time.monotonic() - started)
        if remain <= 0:
            raise TimeoutError("Finite wall-clock budget reached")
        t0 = time.monotonic()
        process = subprocess.run(command, capture_output=True, timeout=remain, cwd=out)
        step = {"label": label, "argv": [str(x) for x in command], "exit_code": process.returncode,
                "seconds": round(time.monotonic() - t0, 3)}
        metadata["steps"].append(step)
        with (out / "build_stdout.txt").open("ab") as stream:
            stream.write((label + "\n").encode() + process.stdout)
        with (out / "build_stderr.txt").open("ab") as stream:
            stream.write((label + "\n").encode() + process.stderr)
        if stdout_name:
            (out / stdout_name).write_bytes(process.stdout)
            (out / "r00b_dump.err").write_bytes(process.stderr)
        print(label, process.returncode, step["seconds"], flush=True)
        if process.returncode:
            raise RuntimeError(label + " failed: see build_stderr.txt")

    cfiles = [
        xkcp / "lib/high/Keccak/FIPS202/KeccakHash.c",
        xkcp / "lib/high/Keccak/KeccakSponge.c",
        xkcp / "lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c",
        xkcp / "lib/low/KeccakP-1600-times2/SIMD128/KeccakP-1600-times2-SIMD128.c",
        xkcp / "lib/low/KeccakP-1600-times4/AVX2/KeccakP-1600-times4-SIMD256.c",
        src / "sha3/KeccakHashtimes4.c", src / "sha3/KeccakSpongetimes4.c"]
    cppfiles = [src / "avx2/aes_impl.cpp", src / "polynomials_constants.cpp", src / "vector_com.cpp", probe]
    objects = []
    try:
        for index, path in enumerate(cfiles + cppfiles):
            output = obj / f"{index}_{path.stem}.o"
            cpp = path.suffix == ".cpp"
            command = [*(cxx if cpp else cc), "-std=c++23" if cpp else "-std=c2x", *flags, *includes]
            if cpp:
                command += ["-Wno-ignored-attributes", "-include", str(shim)]
            command += ["-c", str(path), "-o", str(output)]
            run(command, f"compile {path.name}")
            objects.append(output)
        executable = out / "r00b_dump.exe"
        run([*cxx, *flags, *map(str, objects), "-o", str(executable)], "link")
        run([str(executable)], "run 9 Rain4 correctness instances", "r00b_dump.json")
        metadata["status"] = "PASS"
    except Exception as error:
        metadata["status"] = "BUILD_OR_RUNTIME_BLOCKED"
        metadata["error"] = repr(error)
    finally:
        after = {p.relative_to(src).as_posix(): digest(p) for p in frozen_files}
        metadata["source_unchanged"] = source_before == after
        metadata["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (out / "run_metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({k: metadata[k] for k in ("status", "source_unchanged", "elapsed_seconds")}, ensure_ascii=False))
    return 0 if metadata["status"] == "PASS" and metadata["source_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
