#!/usr/bin/env bash
# 采集 14 组必测实现的存储需求：M2/M3（massif）、M4（time -v）、M5（size -A）
# 每个实现每个模式重复 3 次；探针单线程。
set -uo pipefail

W=<HOME>/rain-bench-20261016
S=$W/storage_test
VG=$W/env/bin/valgrind
REPEAT=${REPEAT:-3}
mkdir -p "$S/raw" "$S/logs" "$S/env"
export HOME=$W/home

log() { echo "[$(date -u +%FT%TZ)] $*"; }

# ---------- 环境信息 ----------
collect_env() {
  {
    echo "== lscpu =="; lscpu
    echo; echo "== uname -a =="; uname -a
    echo; echo "== os-release =="; cat /etc/os-release
    echo; echo "== valgrind =="; "$VG" --version
    echo; echo "== zig =="; "$W/工具/zig/zig" version
    echo; echo "== conda gcc =="; "$W/env/bin/x86_64-conda-linux-gnu-gcc" --version | head -1
    echo; echo "== system gcc =="; gcc --version | head -1
    echo; echo "== size =="; /usr/bin/size --version | head -1
    echo; echo "== time =="; /usr/bin/time --version 2>&1 | head -1
  } > "$S/env/environment.txt" 2>&1
}
collect_env

# ---------- M5：size -A ----------
size_for() { # $1=key
  local key=$1 dir=$S/impls/$1
  local row tree setting
  row=$(awk -F'\t' -v k="$key" '$1==k{print}' "$S/scripts/impls.tsv")
  IFS=$'\t' read -r _ _ _ _ tree _ setting _ _ _ _ <<<"$row"
  if [ "$tree" = "one-tree" ]; then
    local objs
    mapfile -t objs < "$dir/work/m5_objects.txt"
    /usr/bin/size -A "${objs[@]}" > "$S/raw/size.$key.txt" 2>&1
    /usr/bin/size -A "$dir/work/probe.o" > "$S/raw/size_probeobjs.$key.txt" 2>&1
    /usr/bin/size -A "$S/impls/_empty_gcc" > "$S/raw/size_empty.$key.txt" 2>&1
  else
    local bld=$S/build/$tree
    /usr/bin/size -A "$bld/libfaest.a" "$bld/librandomness_os.a" \
      "$bld/subprojects/xkcp/libxkcp.a" "$dir/work/api.o" > "$S/raw/size.$key.txt" 2>&1
    /usr/bin/size -A "$dir/work/probe.o" "$dir/work/rand_wrap.o" \
      > "$S/raw/size_probeobjs.$key.txt" 2>&1
    /usr/bin/size -A "$S/impls/_empty_zig" > "$S/raw/size_empty.$key.txt" 2>&1
  fi
  /usr/bin/size -A "$dir/probe_$key" > "$S/raw/size_image.$key.txt" 2>&1
  log "size -A $key"
}

# ---------- 单实现测量 ----------
measure_impl() { # $1=key
  local key=$1 dir=$S/impls/$1 probe=$S/impls/$1/probe_$1 work=$S/impls/$1/work
  [ -x "$probe" ] || { echo "MISSING_PROBE $key"; return 1; }
  size_for "$key"

  ( cd "$work" || exit 1
    rm -f pk.bin sk.bin sm.bin
    ../probe_$key gen || { echo "GEN_FAIL $key"; exit 1; }
    # M1 核对
    local pk_b sk_b sm_b
    pk_b=$(stat -c %s pk.bin); sk_b=$(stat -c %s sk.bin); sm_b=$(stat -c %s sm.bin)
    echo "$key gen pk=$pk_b sk=$sk_b sm=$sm_b" >> "$S/logs/m1_check.txt"

    for mode in none keygen sign verify; do
      for r in $(seq 1 "$REPEAT"); do
        "$VG" --tool=massif --stacks=no --peak-inaccuracy=0.0 \
          --massif-out-file="$S/raw/heap.$key.$mode.$r.out" "../probe_$key" "$mode" \
          >/dev/null 2>>"$S/logs/massif.err" || echo "HEAP_FAIL $key $mode $r" >> "$S/logs/failures.txt"
        "$VG" --tool=massif --heap=no --stacks=yes --peak-inaccuracy=0.0 \
          --massif-out-file="$S/raw/stack.$key.$mode.$r.out" "../probe_$key" "$mode" \
          >/dev/null 2>>"$S/logs/massif.err" || echo "STACK_FAIL $key $mode $r" >> "$S/logs/failures.txt"
        /usr/bin/time -v "../probe_$key" "$mode" 2> "$S/raw/time.$key.$mode.$r.txt" \
          >/dev/null || echo "TIME_FAIL $key $mode $r" >> "$S/logs/failures.txt"
      done
    done
  ) || { echo "MEASURE_FAIL $key"; return 1; }
  log "measured $key"
}

case "${1:-}" in
  env) collect_env ;;
  size) for key in $(awk -F'\t' 'NR>1{print $1}' "$S/scripts/impls.tsv"); do size_for "$key"; done ;;
  impl) measure_impl "${2:?impl key}" ;;
  all)
    while IFS=$'\t' read -r key rest; do
      [ "$key" = "key" ] && continue
      measure_impl "$key"
    done < "$S/scripts/impls.tsv"
    ;;
  *) echo "usage: $0 env|size|impl <key>|all"; exit 1 ;;
esac
echo MEASURE_STORAGE_DONE
