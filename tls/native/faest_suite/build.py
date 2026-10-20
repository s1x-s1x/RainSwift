"""Build the FAEST v2/v3 suite signature library for the hybrid TLS harness (Windows DLL).

    python build.py --faest-src FAEST_SRC --xkcp-src XKCP_SRC --gcc-bin MINGW_BIN --out OUT_DIR
                    [--test-hooks] [--jobs N] [--toolchain gcc|zig] [--zig ZIG]

The library implements faest_suite_tls.h: faest_suite_tls.dll, built from the faest-arch-opt
source tree (its src/ directory), with eight parameter sets: FAEST v2/v3, AES-CTR and EM-AES
one-way functions. XKCP_SRC is XKCP at the revision pinned in FAEST_SRC/subprojects/xkcp.wrap
(eb5244d6b95fb1c434b211bac293093e18aa8fd1).

CRT tables: the signature code includes crt_constants.hpp -> generated_crt_constants.hpp; this
script produces the eight crt_constants_<preset>.{json,cpp,hpp} files and the umbrella header
with FAEST_SRC/tools/{vole_mult_tables.py, gen_crt_tables.py}, exactly as the meson build does.

``--test-hooks`` builds faest_suite_tls_test.dll instead, which also exports the test entry
points of faest_suite_tls.h (deterministic or scripted random bytes, a failing source, public
key from secret key); the production DLL does not contain them. The output directory receives
the DLL and build.json: every command, the compiler version and the SHA-256 of each input and
of the result.

The default toolchain is MinGW-w64 GCC (MSYS2 UCRT64), with libgcc, libstdc++ and winpthread
linked statically so the DLL depends on system DLLs only. zig 0.13 is also supported (it links
libunwind's _Unwind_* exports alongside the interface). With GCC the assembler option
-muse-unaligned-vector-move is used: GCC cannot guarantee 32-byte stack alignment on 64-bit
Windows (GCC bug 54412), so aligned AVX spills are encoded as unaligned moves.

Options match the release build used for the published measurements (optimization 3, NDEBUG);
the instruction set is pinned to x86-64-v3 + AES + PCLMUL instead of -march=native so that the
DLL runs on any such processor. Platform adaptations, none of which edits a source file:

* win_aligned_alloc.hpp is force-included into the library's C++ units (aligned_alloc/free);
* XKCP's one-state Keccak-p uses the portable plain-64bits C code, because the AVX2 assembly
  in XKCP is written for ELF and the System V calling convention;
* rand_bytes comes from faest_suite_tls_impl.hpp (BCryptGenRandom), not from randomness_os.c.

The library units go into a static archive and the DLL links the archive, so only the members
it needs are pulled in.
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

NAME = "faest_suite_tls"
WRAPPER = "faest_suite_tls.cpp"
DEFINES = []
LIB_CXX = ["aes.cpp", "faest.cpp", "owf_proof_key_sched.cpp", "owf_proof_enc_v2.cpp",
           "owf_proof_enc_v3.cpp", "owf_proof_v2.cpp", "owf_proof_v2_em.cpp",
           "owf_proof_v3.cpp", "owf_proof_v3_em.cpp", "polynomials_constants.cpp",
           "small_vole.cpp", "vector_com.cpp", "vole_commit.cpp"]
LIB_C = ["sha3/KeccakHash-times4.c", "sha3/KeccakSponge-times4.c"]
CRT_PRESETS = ["128f", "128s", "192f", "192f_em", "192s", "192s_em", "256f", "256s"]
XKCP_C = ["lib/high/Keccak/FIPS202/KeccakHash.c", "lib/high/Keccak/KeccakSponge.c",
          "lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c",
          "lib/low/KeccakP-1600-times2/SIMD128/KeccakP-1600-times2-SIMD128.c",
          "lib/low/KeccakP-1600-times4/AVX2/KeccakP-1600-times4-AVX2.c"]
XKCP_INCLUDE = ["", "lib/common", "lib/low/common", "lib/high/Keccak", "lib/high/Keccak/FIPS202",
                "lib/low/KeccakP-1600/plain-64bits", "lib/low/KeccakP-1600/plain-64bits/SnP",
                "lib/low/KeccakP-1600/plain-64bits/u6",
                "lib/low/KeccakP-1600/common",
                "lib/low/KeccakP-1600-times2/SIMD128", "lib/low/KeccakP-1600-times2/SIMD128/SnP",
                "lib/low/KeccakP-1600-times2/SIMD128/SSSE3-u2",
                "lib/low/KeccakP-1600-times4/AVX2", "lib/low/KeccakP-1600-times4/AVX2/SnP",
                "lib/low/KeccakP-1600-times4/AVX2/u12",
                "lib/low/KeccakP-1600-times8/fallback-on4"]
TARGET = "x86_64-windows-gnu"
OPT = ["-O3", "-g0", "-DNDEBUG"]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--toolchain", choices=["gcc", "zig"], default="gcc")
    ap.add_argument("--gcc-bin", help="directory with gcc.exe, g++.exe and ar.exe (MSYS2 ucrt64/bin)")
    ap.add_argument("--zig", help="zig executable")
    ap.add_argument("--faest-src", required=True, help="faest-arch-opt source tree (its src/ contents)")
    ap.add_argument("--xkcp-src", required=True, help="XKCP at the revision pinned in subprojects/xkcp.wrap")
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

    src_root, xkcp = Path(args.faest_src), Path(args.xkcp_src)
    out = Path(args.out)
    obj = out / "obj"
    obj.mkdir(parents=True, exist_ok=False)
    name = NAME + ("_test" if args.test_hooks else "")
    log = {"name": name, "toolchain": args.toolchain, "compiler_version": version,
           "target": TARGET, "isa": isa, "opt": OPT, "crt_presets": CRT_PRESETS, "steps": []}

    def run_step(label, argv, cwd=None, stdout_file=None):
        t = time.monotonic()
        if stdout_file is not None:
            with open(stdout_file, "w", encoding="utf-8") as fh:
                p = subprocess.run(argv, stdout=fh, stderr=subprocess.PIPE, text=True,
                                   encoding="utf-8", errors="replace", env=env, cwd=cwd)
            stderr = p.stderr or ""
        else:
            p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", env=env, cwd=cwd)
            stderr = p.stderr
        errors = [line for line in stderr.splitlines() if "error" in line.lower()]
        record = {"label": label, "argv": [str(a) for a in argv], "exit_code": p.returncode,
                  "seconds": round(time.monotonic() - t, 3), "errors": errors[:40], "stderr": stderr[-4000:]}
        log["steps"].append(record)
        return record

    # ---- CRT tables (as the meson build's custom_targets) ----
    py = sys.executable
    tools = src_root / "tools"
    crt_cpps = []
    for preset in CRT_PRESETS:
        jp = obj / ("crt_constants_%s.json" % preset)
        run_step("crt-json-" + preset,
                 [py, str(tools / "vole_mult_tables.py"), "--preset", preset, "--out", str(jp)])
        cp = obj / ("crt_constants_%s.cpp" % preset)
        run_step("crt-cpp-" + preset, [py, str(tools / "gen_crt_tables.py"), str(jp)], stdout_file=cp)
        hp = obj / ("crt_constants_%s.hpp" % preset)
        run_step("crt-hpp-" + preset, [py, str(tools / "gen_crt_tables.py"), "--header", str(jp)], stdout_file=hp)
        crt_cpps.append(cp)
    (obj / "generated_crt_constants.hpp").write_text(
        "".join('#include "crt_constants_%s.hpp"\n' % p for p in CRT_PRESETS), encoding="utf-8")

    includes = ["-I" + str(HERE), "-I" + str(HERE / "xkcp_config"), "-I" + str(src_root), "-I" + str(obj)]
    includes += ["-I" + str(xkcp / sub) if sub else "-I" + str(xkcp) for sub in XKCP_INCLUDE]
    defines = DEFINES + (["-DFAEST_SUITE_TLS_TEST_HOOKS=1"] if args.test_hooks else [])
    log["defines"] = defines
    c_flags = target + ["-std=c2x"] + OPT + isa + defines + includes
    cxx_flags = (target + ["-std=c++23"] + OPT + isa + defines + includes +
                 ["-Wno-ignored-attributes", "-include", str(HERE / "win_aligned_alloc.hpp")])
    if args.toolchain == "gcc":
        cxx_flags += ["-Wno-attributes", "-Wno-psabi"]
    baseline_flags = target + ["-std=c2x", "-O2", "-g0"] + baseline_isa + includes

    units = []  # (label, argv); objects x*/c*/l*/g* go into the archive, w*/p* are linked directly
    for i, rel in enumerate(XKCP_C):
        src = xkcp / rel
        units.append((rel, cc + c_flags + ["-c", str(src), "-o", str(obj / ("x%02d.o" % i))]))
    for i, rel in enumerate(LIB_C):
        src = src_root / rel
        units.append((rel, cc + c_flags + ["-c", str(src), "-o", str(obj / ("c%02d.o" % i))]))
    for i, rel in enumerate(LIB_CXX):
        src = src_root / rel
        units.append((rel, cxx + cxx_flags + ["-c", str(src), "-o", str(obj / ("l%02d.o" % i))]))
    for i, cp in enumerate(crt_cpps):
        units.append((cp.name, cxx + cxx_flags + ["-c", str(cp), "-o", str(obj / ("g%02d.o" % i))]))
    wrapper = HERE / WRAPPER
    units.append((wrapper.name, cxx + cxx_flags + ["-c", str(wrapper), "-o", str(obj / "w00.o")]))
    platform = HERE / "faest_suite_platform.c"
    units.append((platform.name, cc + baseline_flags + ["-c", str(platform), "-o", str(obj / "p00.o")]))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = list(pool.map(lambda unit: run_step(unit[0], unit[1]), units))
    failed = [r for r in results if r["exit_code"] != 0]
    if not failed:
        archive = out / "libfaest_suite_tls.a"
        members = sorted(str(p) for p in obj.glob("*.o") if p.name[0] in "xclg")
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
    for unit in units:
        argv = unit[1]
        for a in argv:
            p = Path(str(a))
            if p.is_file() and p.suffix in (".c", ".cpp", ".h", ".hpp"):
                inputs[str(p)] = sha256(p)
    for extra in (HERE / "faest_suite_tls.h", HERE / "faest_suite_tls_impl.hpp",
                  HERE / "win_aligned_alloc.hpp", HERE / "xkcp_config" / "config.h", Path(__file__)):
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
