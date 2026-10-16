#!/usr/bin/env bash
# 迭代030 Q3 阶段 A（不计时）：核对上传输入、工具链、构建 11 个实现，再用新构建重跑 Q2 测试、
# 核对库方式 KAT、对 11 个计时程序做只校验不计时的冒烟运行。任一项不过即停（冻结计划 §4.2、§5 止损 3）。
# 由 srv.py bg 在运行目录 build/research-iter030-q2q3-<UTC>/ 中以 nice 19 + timeout 启动；不用 sudo，不做系统级安装。
# 目录内容（本机打包上传）：inputs/sources/、inputs/source_manifest.json、scripts/、kat/、control/gate.json。
set -euo pipefail
umask 077
RUN="$PWD"
JOBS="${JOBS:-32}"
export HOME="$RUN/home" TMPDIR="$RUN/tmp" XDG_CACHE_HOME="$RUN/cache/xdg" PIP_CACHE_DIR="$RUN/cache/pip"
export ZIG_GLOBAL_CACHE_DIR="$RUN/cache/zig-global" ZIG_LOCAL_CACHE_DIR="$RUN/cache/zig-local" PYTHONDONTWRITEBYTECODE=1
mkdir -p home tmp cache logs out
ulimit -v $((16 * 1024 * 1024))   # 每个进程 16 GiB 虚拟内存上限
say() { echo "=== $1 $(date -u +%Y-%m-%dT%H:%M:%SZ)"; }
stop() { echo "STOP $1"; exit 3; }
START_UTC=$(date -u +%Y-%m-%dT%H:%M:%S+00:00)

say ENV
uname -srm
grep -m1 'model name' /proc/cpuinfo || true
nproc
free -g | sed -n '1,2p'
[ "$(nice)" = 19 ] || stop "NOT_NICE_19"

say INPUTS
python3 -I - "$RUN" <<'PY'
import sys
from pathlib import Path
run = Path(sys.argv[1])
sys.path.insert(0, str(run / "scripts"))
from q3_common import inventory, read_json
manifest = read_json(run / "inputs/source_manifest.json")
actual = inventory(run / "inputs/sources")
if actual != manifest["files"]:
    raise SystemExit("INPUT_MISMATCH uploaded sources differ from source_manifest.json")
print("INPUTS %d files match source_manifest.json" % len(actual))
PY

say TOOLCHAIN
bash scripts/setup_toolchain.sh > logs/toolchain.log 2>&1
tail -n 5 logs/toolchain.log

say BUILD
if ! bash scripts/q3_build.sh "$RUN" "$RUN/inputs/sources" "$JOBS" b1 > logs/q3_build.log 2>&1; then
    tail -n 40 logs/q3_build.log
    stop "BUILD_FAILED"
fi
grep -E '^BUILD_(STEP|DONE)' logs/q3_build.log
B="$RUN/q3-builds/b1"

say Q2_RETEST
mkdir -p out/q2_retest_kat
set +e
"$B/build/rain/rain_q2_test" --kat-dir out/q2_retest_kat > out/q2_retest.log 2>&1
rc=$?
set -e
echo "rc=$rc" >> out/q2_retest.log
tail -n 2 out/q2_retest.log
[ "$rc" = 0 ] && grep -q '^RESULT PASS (0 failed of' out/q2_retest.log || stop "Q2_RETEST_FAILED"
for s in rain3_fast rain3_bal rain3_short rain4_fast rain4_bal rain4_short; do
    cmp -s "kat/sigkat_$s.txt" "out/q2_retest_kat/sigkat_$s.txt" || stop "SIGKAT_DIFFERENT $s"
    echo "SIGKAT $s Q3 release build == Q2 KAT: IDENTICAL"
done

say KAT_LIBRARY_PATH
"$B/build/rain/q3_rain_kat_lib" > out/kat_lib.txt
cmp -s kat/kat_gen_q2_b0.txt out/kat_lib.txt || stop "KAT_LIB_DIFFERENT"
echo "KAT library-instantiation path == Q2 kat_gen output (frozen source == Q2 B1=0): IDENTICAL ($(wc -l < out/kat_lib.txt) lines)"

say HARNESS_SMOKE
declare -A TREE=([1]=faest_v3 [5]=faest_v3 [2]=rfaest [4]=rfaest [3]=lynxer
                 [6]=rain [7]=rain [8]=rain [9]=rain [10]=rain [11]=rain)
for id in 1 2 3 4 5 6 7 8 9 10 11; do
    bin="$B/build/${TREE[$id]}/q3_impl_$id"
    if ! python3 -I -c 'import os, sys; os.sched_setaffinity(0, {16}); os.execv(sys.argv[1], sys.argv[1:])' \
            "$bin" --validate-only > "out/smoke_$id.jsonl" 2> "out/smoke_$id.stderr"; then
        cat "out/smoke_$id.jsonl"
        stop "SMOKE_FAILED $id"
    fi
    [ ! -s "out/smoke_$id.stderr" ] || stop "SMOKE_STDERR $id"
    grep -q '"kind":"validation","algorithm":"[^"]*","passed":true' "out/smoke_$id.jsonl" || stop "SMOKE_NOT_PASSED $id"
    echo "SMOKE $id $(grep -o '"algorithm":"[^"]*"' "out/smoke_$id.jsonl" | head -n 1) validate-only passed"
done

say RECEIPT
python3 -I - "$B/phaseA_receipt.json" "$START_UTC" <<'PY'
import json, os, sys
from datetime import datetime, timezone
path, start = sys.argv[1:]
receipt = {"name": "q3_phaseA", "exit_code": 0, "stop_reason": None, "start_utc": start,
           "end_utc": datetime.now(timezone.utc).isoformat(),
           "checks": {"inputs_match_manifest": True, "build": "11 implementations + 2 auxiliary executables",
                      "q2_retest_release_build": "RESULT PASS, six signature KATs identical to Q2",
                      "kat_library_path": "identical to Q2 kat_gen output (frozen == Q2 B1=0)",
                      "harness_validate_only": "11/11 passed on CPU 16"},
           "scope": "build and correctness re-test only; no timing window was run"}
with open(path, "x", encoding="utf-8") as f:
    json.dump(receipt, f, ensure_ascii=False, indent=2)
    f.write("\n")
    f.flush()
    os.fsync(f.fileno())
print("RECEIPT written")
PY

say HASHES
(cd out && find . -type f -print0 | sort -z | xargs -0 sha256sum) > out_SHA256SUMS.txt
du -sh "$RUN" | cut -f1
say DONE
