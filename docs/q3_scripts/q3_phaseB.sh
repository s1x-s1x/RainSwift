#!/usr/bin/env bash
# 迭代030 Q3 阶段 B（计时）：主窗口 F1、S1，重复窗口 F2、S2、F3、S3，依次运行，同一时刻只有一个计时进程。
# 每个窗口结束后立即用 summarize_q3_window.py 审计；任一窗口失败或审计不过即停（不自动重试）。
# 由 srv.py bg 在阶段 A 的同一运行目录中以 nice 19 + timeout 启动；运行期间不得在本项目目录内运行其他命令。
# 输出只写文件（不用管道），避免在空闲检查中出现非祖先的本项目进程。
set -euo pipefail
umask 077
RUN="$PWD"
export HOME="$RUN/home" TMPDIR="$RUN/tmp" XDG_CACHE_HOME="$RUN/cache/xdg" PYTHONDONTWRITEBYTECODE=1
mkdir -p logs
ulimit -v $((16 * 1024 * 1024))
say() { echo "=== $1 $(date -u +%Y-%m-%dT%H:%M:%SZ)"; }
[ "$(nice)" = 19 ] || { echo "STOP NOT_NICE_19"; exit 3; }
[ -f q3-builds/b1/phaseA_receipt.json ] || { echo "STOP NO_PHASE_A_RECEIPT"; exit 3; }

for label in F1 S1 F2 S2 F3 S3; do
    say "WINDOW $label"
    set_name=${label:0:1}
    if ! python3 -I scripts/run_q3_window.py --root "$RUN" --build q3-builds/b1 --source-root inputs/sources \
            --source-manifest inputs/source_manifest.json --window-set "$set_name" --label "$label" \
            --cpus 16,17,18 --parallel-work-complete --completed-receipt q3-builds/b1/phaseA_receipt.json \
            --seconds 3600 > "logs/window_$label.log" 2>&1; then
        tail -n 3 "logs/window_$label.log"
        echo "STOP WINDOW_FAILED $label"
        exit 5
    fi
    tail -n 1 "logs/window_$label.log"
    if ! python3 -I scripts/summarize_q3_window.py "q3-windows/$label" --live-build q3-builds/b1 \
            --output "q3-windows/${label}_summary.json" > "logs/audit_$label.log" 2>&1; then
        tail -n 5 "logs/audit_$label.log"
        echo "STOP AUDIT_FAILED $label"
        exit 6
    fi
    echo "AUDIT $label verified_complete_q3_window"
done

say HASHES
(cd q3-windows && find . -type f -print0 | sort -z | xargs -0 sha256sum) > q3_windows_SHA256SUMS.txt
say DONE
