#!/usr/bin/env bash
# 构建栈涂抹补测探针（不影响原 probe_<key> 与 M5）
set -uo pipefail
W=<HOME>/rain-bench-20261016
S=$W/storage_test
ZCC=$W/工具/bin/zig-cc
ZCXX=$W/工具/bin/zig-c++
GCC=$W/env/bin/x86_64-conda-linux-gnu-gcc
GXX=$W/env/bin/x86_64-conda-linux-gnu-g++
export HOME=$W/home
log() { echo "[$(date -u +%FT%TZ)] $*"; }

build_one() { # $1=key
  local key=$1 dir=$S/impls/$1
  local row id scheme param tree ptype setting q7id commit compiler cflags
  row=$(awk -F'\t' -v k="$key" '$1==k{print}' "$S/scripts/impls.tsv")
  [ -n "$row" ] || { echo "unknown $key"; return 1; }
  IFS=$'\t' read -r key id scheme param tree ptype setting q7id commit compiler cflags <<<"$row"

  if [ "$tree" = "one-tree" ]; then
    $GCC -O2 -std=c11 -I"$dir/work" -c "$S/scripts/probe_stack.c" -o "$dir/work/probe_stack.o" \
      || { echo "COMPILE_FAIL $key"; return 1; }
    local AI=$W/源码/faest-one-tree/Additional_Implementations/$setting
    local objs
    objs=$(ls "$AI"/*.o | grep -vE '/catch_amalgamated\.o$|/test[^/]*\.o$|/api_test\.o$|/PQCgenKAT_sign\.o$')
    $GXX -O2 -Wl,--gc-sections -static-libstdc++ -static-libgcc \
      "$dir/work/probe_stack.o" $objs -lcrypto -lm -o "$dir/probe_stack_$key" \
      || { echo "LINK_FAIL $key"; return 1; }
  else
    $ZCC -O2 -std=c11 -I"$dir/work" -c "$S/scripts/probe_stack.c" -o "$dir/work/probe_stack.o" \
      || { echo "COMPILE_FAIL $key"; return 1; }
    local bld=$S/build/$tree
    $ZCXX -O3 -Wl,--gc-sections \
      "$dir/work/probe_stack.o" "$dir/work/api.o" "$dir/work/rand_wrap.o" \
      "$bld/libfaest.a" "$bld/librandomness_os.a" "$bld/subprojects/xkcp/libxkcp.a" \
      -lm -o "$dir/probe_stack_$key" \
      || { echo "LINK_FAIL $key"; return 1; }
  fi
  log "built probe_stack_$key"
}

if [ "${1:-}" = "all" ]; then
  while IFS=$'\t' read -r key rest; do
    [ "$key" = "key" ] && continue
    build_one "$key"
  done < "$S/scripts/impls.tsv"
else
  build_one "${1:?key}"
fi
echo BUILD_STACK_PROBES_DONE
