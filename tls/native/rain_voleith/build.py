"""Build the Rain-VOLEitH signature library for the hybrid TLS harness (Windows DLL).

    python build.py --rain-src RAIN_SRC --xkcp-src XKCP_SRC --gcc-bin MINGW_BIN --out OUT_DIR
                    [--test-hooks] [--jobs N] [--toolchain gcc|zig] [--zig ZIG]

The library implements rain_voleith_tls.h: rain_voleith_tls.dll, built from the Rain-VOLEitH
source tree (the repository's ``src/`` directory), with the six Rain sets. XKCP_SRC is XKCP at the
revision pinned in RAIN_SRC/subprojects/xkcp.wrap.

``--test-hooks`` builds rain_voleith_tls_test.dll instead, which also exports the test entry points
of rain_voleith_tls.h (deterministic or scripted random bytes, a failing source, public key from
secret key); the production DLL does not contain them. The output directory receives the DLL and
build.json: every command, the compiler version and the SHA-256 of each input and of the result.

The default toolchain is MinGW-w64 GCC (MSYS2 UCRT64), with libgcc, libstdc++ and winpthread linked
statically so the DLL depends on system DLLs only. zig 0.13 is also supported, but a DLL it links
exports libunwind's 25 _Unwind_*/unw_* functions alongside the interface (its bundled libunwind
is compiled with __declspec(dllexport)). With GCC the assembler option -muse-unaligned-vector-move
is used: GCC cannot guarantee 32-byte stack alignment on 64-bit Windows (GCC bug 54412), so aligned
AVX spills are encoded as unaligned moves, which have the same semantics.

Options match the release build used for the published measurements (optimization 3, NDEBUG,
RAIN_SHRUNK_KEYSPACE=0); the instruction set is pinned to x86-64-v3 + AES + PCLMUL instead of
-march=native so that the DLL runs on any such processor. Three platform adaptations, none of which
edits a source file:

* win_aligned_alloc.hpp is force-included into the library's C++ units (aligned_alloc/free);
* XKCP's one-state Keccak-p uses the portable plain-64bits C code, because the AVX2 assembly
  in XKCP is written for ELF and the System V calling convention;
* rand_bytes comes from rain_voleith_tls_impl.hpp (BCryptGenRandom), not from randomness_os.c.

As in the meson build, the library units go into a static archive and the DLL links the archive,
so only the members it needs are pulled in. (Linking every object directly fails on COFF: the
explicit-instantiation units repeat the namespace-scope variable template specialisations, e.g.
TRANSPOSE_BITS_COLS_SHIFT<s128>, that the wrapper unit also defines.)
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

NAME = "rain_voleith_tls"
WRAPPER = "rain_voleith_tls.cpp"
DEFINES = ["-DRAIN_SHRUNK_KEYSPACE=0"]
LIB_CXX = ["avx2/aes_impl.cpp", "faest.cpp", "owf_proof.cpp", "polynomials_constants.cpp",
           "small_vole.cpp", "vector_com.cpp", "vole_commit.cpp"]
LIB_C = ["sha3/KeccakHashtimes4.c", "sha3/KeccakSpongetimes4.c"]
XKCP_C = ["lib/high/Keccak/FIPS202/KeccakHash.c", "lib/high/Keccak/KeccakSponge.c",
          "lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c",
          "lib/low/KeccakP-1600-times2/SIMD128/KeccakP-1600-times2-SIMD128.c",
          "lib/low/KeccakP-1600-times4/AVX2/KeccakP-1600-times4-SIMD256.c"]
XKCP_INCLUDE = ["", "lib/common", "lib/low/common", "lib/high/Keccak", "lib/high/Keccak/FIPS202",
                "lib/low/KeccakP-1600/plain-64bits", "lib/low/KeccakP-1600/plain-64bits/u6",
                "lib/low/KeccakP-1600/common", "lib/low/KeccakP-1600-times2/SIMD128",
                "lib/low/KeccakP-1600-times2/SIMD128/SSSE3-u2", "lib/low/KeccakP-1600-times4/AVX2",
                "lib/low/KeccakP-1600-times4/AVX2/u12", "lib/low/KeccakP-1600-times8/fallback-on4"]
TARGET = "x86_64-windows-gnu"
OPT = ["-O3", "-g0", "-DNDEBUG"]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--toolchain", choices=["gcc", "zig"], default="gcc")
    ap.add_argument("--gcc-bin", help="directory with gcc.exe, g++.exe and ar.exe (MSYS2 ucrt64/bin)")
    ap.add_argument("--zig", help="zig executable")
    ap.add_argument("--rain-src", required=True, help="Rain-VOLEitH source tree (the repository's src/)")
    ap.add_argument("--xkcp-src", required=True, help="XKCP at the revision pinned in src/subprojects/xkcp.wrap")
    ap.add_argument("--out", required=True)
    ap.add_argument("--test-hooks", action="store_true")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()

    env = dict(os.environ)
    if args.toolchain == "gcc":
        if not args.gcc_bin:
            ap.error("--gcc-bin is required with --toolchain gcc")
        gbin = Path(args.gcc_bin)
        cc, cxx, ar_cmd = [str(gbin / "gcc.exe")], [str(gbin / "g++.exe")], [str(gbin / "ar.exe")]
        target = []
        isa = ["-march=x86-64-v3", "-maes", "-mpclmul", "-Wa,-muse-unaligned-vector-move"]
        baseline_isa = ["-march=x86-64"]
        link_extra = ["-static", "-static-libgcc", "-static-libstdc++"]
        env["PATH"] = str(gbin) + os.pathsep + env.get("PATH", "")
        version = subprocess.run(cc + ["--version"], capture_output=True, text=True, env=env).stdout.splitlines()[0]
    else:
        if not args.zig:
            ap.error("--zig is required with --toolchain zig")
        zig = str(Path(args.zig))
        cc, cxx, ar_cmd = [zig, "cc"], [zig, "c++"], [zig, "ar"]
        target = ["-target", TARGET]
        isa = ["-march=x86_64_v3", "-maes", "-mpclmul"]
        baseline_isa = ["-march=x86_64"]
        link_extra = []
        version = "zig " + subprocess.run([zig, "version"], capture_output=True, text=True).stdout.strip()

    src_root, xkcp = Path(args.rain_src), Path(args.xkcp_src)
    out = Path(args.out)
    obj = out / "obj"
    obj.mkdir(parents=True, exist_ok=False)
    name = NAME + ("_test" if args.test_hooks else "")
    log = {"name": name, "toolchain": args.toolchain, "compiler_version": version,
           "target": TARGET, "isa": isa, "opt": OPT, "steps": []}

    def run_step(label, argv, cwd=None):
        t = time.monotonic()
        p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, cwd=cwd)
        errors = [line for line in p.stderr.splitlines() if "error" in line.lower()]
        return {"label": label, "argv": [str(a) for a in argv], "exit_code": p.returncode,
                "seconds": round(time.monotonic() - t, 3), "errors": errors[:40], "stderr": p.stderr[-4000:]}

    includes = ["-I" + str(HERE), "-I" + str(HERE / "xkcp_config"), "-I" + str(src_root)]
    includes += ["-I" + str(xkcp / sub) if sub else "-I" + str(xkcp) for sub in XKCP_INCLUDE]
    defines = DEFINES + (["-DRAIN_TLS_TEST_HOOKS=1"] if args.test_hooks else [])
    log["defines"] = defines
    c_flags = target + ["-std=c2x"] + OPT + isa + defines + includes
    cxx_flags = (target + ["-std=c++23"] + OPT + isa + defines + includes +
                 ["-Wno-ignored-attributes", "-include", str(HERE / "win_aligned_alloc.hpp")])
    if args.toolchain == "gcc":
        cxx_flags += ["-Wno-attributes", "-Wno-psabi"]
    baseline_flags = target + ["-std=c2x", "-O2", "-g0"] + baseline_isa + includes

    units = []  # (label, argv, source); objects named x*/c*/l* go into the archive, w*/p* are linked directly
    for i, rel in enumerate(XKCP_C):
        src = xkcp / rel
        units.append((rel, cc + c_flags + ["-c", str(src), "-o", str(obj / ("x%02d.o" % i))], src))
    for i, rel in enumerate(LIB_C):
        src = src_root / rel
        units.append((rel, cc + c_flags + ["-c", str(src), "-o", str(obj / ("c%02d.o" % i))], src))
    for i, rel in enumerate(LIB_CXX):
        src = src_root / rel
        units.append((rel, cxx + cxx_flags + ["-c", str(src), "-o", str(obj / ("l%02d.o" % i))], src))
    wrapper = HERE / WRAPPER
    units.append((wrapper.name, cxx + cxx_flags + ["-c", str(wrapper), "-o", str(obj / "w00.o")], wrapper))
    platform = HERE / "rain_voleith_platform.c"
    units.append(("rain_voleith_platform.c", cc + baseline_flags + ["-c", str(platform), "-o", str(obj / "p00.o")], platform))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = list(pool.map(lambda unit: run_step(unit[0], unit[1]), units))
    log["steps"].extend(results)
    failed = [r for r in results if r["exit_code"] != 0]
    if not failed:
        archive = out / "libsig_tls.a"
        members = sorted(str(p) for p in obj.glob("*.o") if p.name[0] in "xcl")
        log["steps"].append(run_step("archive", ar_cmd + ["rcs", str(archive)] + members))
        if log["steps"][-1]["exit_code"] != 0:
            failed.append(log["steps"][-1])
    if not failed:
        direct = sorted(str(p) for p in obj.glob("*.o") if p.name[0] in "wp")
        dll = out / (name + ".dll")
        log["steps"].append(run_step("link", cxx + target + ["-shared", "-O3", "-g0"] + link_extra + direct +
                                     [str(archive), "-lbcrypt", "-o", str(dll)]))
        if log["steps"][-1]["exit_code"] != 0:
            failed.append(log["steps"][-1])
        else:
            log["output"] = {"file": dll.name, "bytes": dll.stat().st_size, "sha256": sha256(dll)}
    inputs = {}
    for _, _, src in units:
        inputs[str(src)] = sha256(src)
    for extra in (HERE / "rain_voleith_tls.h", HERE / "rain_voleith_tls_impl.hpp", HERE / "win_aligned_alloc.hpp",
                  HERE / "xkcp_config" / "config.h", Path(__file__)):
        inputs[str(extra)] = sha256(extra)
    log["inputs_sha256"] = inputs
    log["status"] = "FAILED" if failed else "PASS"
    (out / "build.json").write_text(json.dumps(log, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for r in failed:
        print("FAILED:", r["label"], file=sys.stderr)
        print(r["stderr"], file=sys.stderr)
    print(log["status"], name, log.get("output"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
