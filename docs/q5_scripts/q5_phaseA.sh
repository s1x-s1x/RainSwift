#!/usr/bin/env bash
# 迭代030 Q5 阶段 A2（不计时）：核对上传输入、工具链、构建 11 个实现（Rain 用 Q5 工作副本），再做冻结计划第 4 节的正确性关卡：
#   D2：新构建重跑 Q2 测试 T1–T8（B1=0 与 B1=1 各一遍），六组签名 KAT（B0、B1）与 Q2 入库逐字节相同，库方式 KAT 与冻结源码一致；
#   D1：发布构建上的差分测试（新旧建钥正向计算逐位对照）；
#   D3（参考，不阻断）：与 Q3 构建比对 Rain 库各函数机器码；
#   另做建钥组件微基准（参考）与 11 个计时程序只校验不计时的冒烟运行。任一关卡不过即停（止损 3）。
# 由 srv.py bg 在运行目录 build/research-iter030-q5kg-<UTC>/ 中以 nice 19 + timeout 启动；不用 sudo，不做系统级安装。
set -euo pipefail
umask 077
RUN="$PWD"
JOBS="${JOBS:-32}"
Q3_RAIN_OBJ="${Q3_RAIN_OBJ:-}"
export HOME="$RUN/home" TMPDIR="$RUN/tmp" XDG_CACHE_HOME="$RUN/cache/xdg" PIP_CACHE_DIR="$RUN/cache/pip"
export ZIG_GLOBAL_CACHE_DIR="$RUN/cache/zig-global" ZIG_LOCAL_CACHE_DIR="$RUN/cache/zig-local" PYTHONDONTWRITEBYTECODE=1
mkdir -p home tmp cache logs out
ulimit -v $((16 * 1024 * 1024))   # 每个进程 16 GiB 虚拟内存上限
say() { echo "=== $1 $(date -u +%Y-%m-%dT%H:%M:%SZ)"; }
stop() { echo "STOP $1"; exit 3; }
START_UTC=$(date -u +%Y-%m-%dT%H:%M:%S+00:00)
SETS="rain3_fast rain3_bal rain3_short rain4_fast rain4_bal rain4_short"

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
from q5_common import inventory, read_json
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
if ! bash scripts/q5_build.sh "$RUN" "$RUN/inputs/sources" "$JOBS" b1 > logs/q5_build.log 2>&1; then
    tail -n 40 logs/q5_build.log
    stop "BUILD_FAILED"
fi
grep -E '^BUILD_(STEP|DONE)' logs/q5_build.log
B="$RUN/q5-builds/b1"

say BUILD_B1
# 同一构建副本、同一组 release 选项，另开构建目录打开 B1（缩钥开关），只构建 Q2 测试程序
export PATH="$RUN/tools/bin:$PATH" PYTHONPATH="$RUN/tools/pydeps"
export CC="$RUN/tools/bin/zig-cc" CXX="$RUN/tools/bin/zig-c++"
if ! nice -n 19 "$RUN/tools/bin/meson" setup "$B/build/rain_b1" "$B/work/rain" \
        --buildtype=release --wrap-mode=nodownload -Db_ndebug=true -Db_lto=false -Doptimization=3 \
        -Dc_std=c23 -Dcpp_std=c++23 -Drain_shrunk_keyspace=true \
        "-Dc_args=-march=native -mtune=native -g0 -ffile-prefix-map=$RUN=/experiment -fdebug-prefix-map=$RUN=/experiment" \
        "-Dcpp_args=-march=native -mtune=native -g0 -Wno-psabi -ffile-prefix-map=$RUN=/experiment -fdebug-prefix-map=$RUN=/experiment" \
        > logs/configure_rain_b1.raw 2>&1; then
    tail -n 30 logs/configure_rain_b1.raw | sed "s#$RUN#<EXPERIMENT>#g; s#/home/[^/ ]*#<HOME>#g"
    stop "CONFIGURE_B1_FAILED"
fi
if ! nice -n 19 "$RUN/tools/bin/ninja" -C "$B/build/rain_b1" -j "$JOBS" rain_q2_test > logs/compile_rain_b1.raw 2>&1; then
    tail -n 30 logs/compile_rain_b1.raw | sed "s#$RUN#<EXPERIMENT>#g; s#/home/[^/ ]*#<HOME>#g"
    stop "COMPILE_B1_FAILED"
fi
for f in configure_rain_b1 compile_rain_b1; do
    sed "s#$RUN#<EXPERIMENT>#g; s#/home/[^/ ]*#<HOME>#g" "logs/$f.raw" > "logs/$f.log" && rm -f "logs/$f.raw"
done
echo "B1 build ok"

say Q2_RETEST_B0
mkdir -p out/q2_retest_kat_b0
set +e
"$B/build/rain/rain_q2_test" --kat-dir out/q2_retest_kat_b0 > out/q2_retest_b0.log 2>&1
rc=$?
set -e
echo "rc=$rc" >> out/q2_retest_b0.log
tail -n 2 out/q2_retest_b0.log
[ "$rc" = 0 ] && grep -q '^RESULT PASS (0 failed of' out/q2_retest_b0.log || stop "Q2_RETEST_B0_FAILED"
for s in $SETS; do
    cmp -s "kat/sigkat_$s.txt" "out/q2_retest_kat_b0/sigkat_$s.txt" || stop "SIGKAT_B0_DIFFERENT $s"
    echo "SIGKAT $s (B1=0) Q5 build == Q2 KAT: IDENTICAL"
done

say Q2_RETEST_B1
mkdir -p out/q2_retest_kat_b1
set +e
"$B/build/rain_b1/rain_q2_test" --kat-dir out/q2_retest_kat_b1 > out/q2_retest_b1.log 2>&1
rc=$?
set -e
echo "rc=$rc" >> out/q2_retest_b1.log
tail -n 2 out/q2_retest_b1.log
[ "$rc" = 0 ] && grep -q '^RESULT PASS (0 failed of' out/q2_retest_b1.log || stop "Q2_RETEST_B1_FAILED"
grep -q 'B1 (RAIN_SHRUNK_KEYSPACE) = 1' out/q2_retest_b1.log || stop "B1_BUILD_NOT_B1"
for s in $SETS; do
    cmp -s "kat/sigkat_${s}_b1.txt" "out/q2_retest_kat_b1/sigkat_${s}_b1.txt" || stop "SIGKAT_B1_DIFFERENT $s"
    echo "SIGKAT $s (B1=1) Q5 build == Q2 KAT: IDENTICAL"
done

say KAT_LIBRARY_PATH
"$B/build/rain/q5_rain_kat_lib" > out/kat_lib.txt
cmp -s kat/kat_gen_q2_b0.txt out/kat_lib.txt || stop "KAT_LIB_DIFFERENT"
echo "KAT library path (Q5 keygen) == Q2 kat_gen output (frozen source == Q2 B1=0): IDENTICAL ($(wc -l < out/kat_lib.txt) lines)"

say DIFF_RELEASE
set +e
"$B/build/rain/q5_kg_test" --diff 22 > out/kg_diff_release.log 2>&1
rc=$?
set -e
echo "rc=$rc" >> out/kg_diff_release.log
tail -n 3 out/kg_diff_release.log
[ "$rc" = 0 ] && grep -q '^RESULT PASS (0 mismatches' out/kg_diff_release.log || stop "KG_DIFF_FAILED"
grep -q '^KEYGEN_CHOICE INV_CHAIN=V4 MAP_METHOD=M2$' out/kg_diff_release.log || stop "KG_CHOICE_UNEXPECTED"

say KG_BENCH_REFERENCE
python3 -I -c 'import os, sys; os.sched_setaffinity(0, {int(sys.argv[1])}); os.execv(sys.argv[2], sys.argv[2:])' \
    16 "$B/build/rain/q5_kg_test" --bench > out/kg_bench_cpu16.log 2>&1 || stop "KG_BENCH_FAILED"
grep -E 'old forward|keygen choice' out/kg_bench_cpu16.log

say DISASM_REFERENCE
if [ -n "$Q3_RAIN_OBJ" ] && [ -d "$Q3_RAIN_OBJ" ]; then
    python3 -I scripts/q5_disasm_compare.py "$Q3_RAIN_OBJ" "$B/build/rain/libfaest.a.p" out/disasm_compare.json || echo "DISASM compare failed (reference only)"
else
    echo '{"status": "unavailable", "reason": "Q3 object directory not given"}' > out/disasm_compare.json
    echo "DISASM unavailable (reference only)"
fi

say HARNESS_SMOKE
declare -A TREE=([1]=faest_v3 [5]=faest_v3 [2]=rfaest [4]=rfaest [3]=lynxer
                 [6]=rain [7]=rain [8]=rain [9]=rain [10]=rain [11]=rain)
for id in 1 2 3 4 5 6 7 8 9 10 11; do
    bin="$B/build/${TREE[$id]}/q5_impl_$id"
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
receipt = {"name": "q5_phaseA", "exit_code": 0, "stop_reason": None, "start_utc": start,
           "end_utc": datetime.now(timezone.utc).isoformat(),
           "checks": {"inputs_match_manifest": True, "build": "11 implementations + 3 auxiliary executables (+ B1=1 rain_q2_test)",
                      "q2_retest_b0": "RESULT PASS, six signature KATs identical to Q2 (B1=0)",
                      "q2_retest_b1": "RESULT PASS, six signature KATs identical to Q2 (B1=1)",
                      "kat_library_path": "identical to Q2 kat_gen output (frozen == Q2 B1=0)",
                      "kg_diff_release": "RESULT PASS on the release build (log2N=22), keygen choice V4/M2",
                      "harness_validate_only": "11/11 passed on CPU 16"},
           "scope": "build and correctness gates only; no timing window was run"}
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
