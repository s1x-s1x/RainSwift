#!/usr/bin/env bash
# 栈深度补测：每实现 × 模式 × 3 次，原生运行栈涂抹探针
set -uo pipefail
W=<HOME>/rain-bench-20261016
S=$W/storage_test
mkdir -p "$S/raw" "$S/logs"
: > "$S/logs/stackpaint_failures.txt"
: > "$S/logs/stackpaint.err"
log() { echo "[$(date -u +%FT%TZ)] $*"; }

for key in $(awk -F'\t' 'NR>1{print $1}' "$S/scripts/impls.tsv"); do
  dir=$S/impls/$key
  [ -x "$dir/probe_stack_$key" ] || { echo "MISSING $key" >> "$S/logs/stackpaint_failures.txt"; continue; }
  ( cd "$dir/work" || exit 1
    if [ ! -f pk.bin ] || [ ! -f sk.bin ] || [ ! -f sm.bin ]; then
      ../probe_$key gen >/dev/null 2>&1 || { echo "GEN_FAIL $key" >> "$S/logs/stackpaint_failures.txt"; exit 1; }
    fi
    for mode in none keygen sign verify; do
      for r in 1 2 3; do
        out=$S/raw/stackpaint.$key.$mode.$r.txt
        if ! ../probe_stack_$key "stack-$mode" > "$out" 2>> "$S/logs/stackpaint.err"; then
          echo "RUN_FAIL $key $mode $r" >> "$S/logs/stackpaint_failures.txt"
        fi
      done
    done
  )
  log "stackpaint $key"
done
echo STACKPAINT_DONE
