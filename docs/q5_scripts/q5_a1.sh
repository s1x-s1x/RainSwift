#!/usr/bin/env bash
# 迭代030 Q5 阶段 A1（组件测试，不是正式计时窗口）：在服务器上编译只用头文件的 q5_kg_test，
# 跑差分测试（新旧实现逐位对照，四种求逆加法链写法全覆盖）和组件微基准，用于选定建钥所用的加法链写法。
# 由 srv.py bg 在运行目录 build/research-iter030-q5kg-<UTC>/ 中以 nice 19 + timeout 启动；不用 sudo，不做系统级安装。
# 目录内容（本机打包上传）：src/rain_q5（Q5 工作副本）、scripts/。
set -euo pipefail
umask 077
RUN="$PWD"
export HOME="$RUN/home" TMPDIR="$RUN/tmp" XDG_CACHE_HOME="$RUN/cache/xdg" PIP_CACHE_DIR="$RUN/cache/pip"
export ZIG_GLOBAL_CACHE_DIR="$RUN/cache/zig-global" ZIG_LOCAL_CACHE_DIR="$RUN/cache/zig-local" PYTHONDONTWRITEBYTECODE=1
mkdir -p home tmp cache logs out bin
ulimit -v $((16 * 1024 * 1024))
say() { echo "=== $1 $(date -u +%Y-%m-%dT%H:%M:%SZ)"; }
stop() { echo "STOP $1"; exit 3; }
[ "$(nice)" = 19 ] || stop "NOT_NICE_19"

say TOOLCHAIN
bash scripts/setup_toolchain.sh > logs/toolchain.log 2>&1
export PATH="$RUN/tools/bin:$PATH" PYTHONPATH="$RUN/tools/pydeps"
CXX="$RUN/tools/bin/zig-c++"
tail -n 5 logs/toolchain.log

say BUILD
# 与 P0 release 相同的优化与目标选项（-O3、NDEBUG、本机指令集、-g0）
if ! "$CXX" -std=c++23 -O3 -march=native -mtune=native -g0 -DNDEBUG -DRAIN_SHRUNK_KEYSPACE=0 \
        -Isrc/rain_q5 src/rain_q5/q5_kg_test.cpp -o bin/q5_kg_test > logs/build.log 2>&1; then
    tail -n 30 logs/build.log
    stop "BUILD_FAILED"
fi
sha256sum bin/q5_kg_test | cut -c1-64

say DIFF
set +e
bin/q5_kg_test --diff 20 > out/diff.log 2>&1
rc=$?
set -e
echo "rc=$rc" >> out/diff.log
tail -n 2 out/diff.log
[ "$rc" = 0 ] && grep -q '^RESULT PASS (0 mismatches' out/diff.log || stop "DIFF_FAILED"

say BENCH
for cpu in 16 17 18; do
    python3 -I -c 'import os, sys; os.sched_setaffinity(0, {int(sys.argv[1])}); os.execv(sys.argv[2], sys.argv[2:])' \
        "$cpu" bin/q5_kg_test --bench > "out/bench_cpu$cpu.log" 2>&1 || stop "BENCH_FAILED $cpu"
done
cat out/bench_cpu16.log

say HASHES
(cd out && find . -type f -print0 | sort -z | xargs -0 sha256sum) > out_SHA256SUMS.txt
say DONE
