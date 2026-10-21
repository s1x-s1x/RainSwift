#!/usr/bin/env bash
# 构建存储需求探针：14 组必测实现（Rain 6 / rFAEST 2 / FAEST v3 2 / MandaRain 4）
# 纪律：不改实现源码；只新增探针与 API 包装；指令集固定 -march=x86-64-v3 -maes -mpclmul。
set -uo pipefail

W=<HOME>/rain-bench-20261016
S=$W/storage_test
ZCC=$W/工具/bin/zig-cc
ZCXX=$W/工具/bin/zig-c++
GCC=$W/env/bin/x86_64-conda-linux-gnu-gcc
GXX=$W/env/bin/x86_64-conda-linux-gnu-g++
Q7=$W/run55/bins
mkdir -p "$S/build" "$S/impls" "$S/logs"
export HOME=$W/home

log() { echo "[$(date -u +%FT%TZ)] $*"; }

# 空 main 基线（扣除探针骨架与链接运行时）
make_empty() {
  echo 'int main(void){return 0;}' > "$S/scripts/empty.c"
  $ZCXX -O2 -Wl,--gc-sections "$S/scripts/empty.c" -o "$S/impls/_empty_zig" || return 1
  $GXX -O2 -Wl,--gc-sections -static-libstdc++ -static-libgcc \
    "$S/scripts/empty.c" -o "$S/impls/_empty_gcc" -lcrypto || return 1
}

# ---------- 模板树 meson 配置 ----------
setup_tree() { # $1=tree-key $2=srcdir
  local key=$1 src=$2 bld=$S/build/$1
  if [ -f "$bld/build.ninja" ]; then log "build/$key already configured"; return 0; fi
  log "meson setup $key"
  ( cd "$src" && export PATH="$W/env/bin:$W/工具/bin:$PATH" && CC=$ZCC CXX=$ZCXX $W/env/bin/meson setup "$bld" . \
      --buildtype=release --wrap-mode=nodownload -Db_ndebug=true -Db_lto=false \
      -Doptimization=3 -Dc_std=c23 -Dcpp_std=c++23 \
      '-Dc_args=-march=x86_64_v3 -maes -mpclmul -g0' \
      '-Dcpp_args=-march=x86_64_v3 -maes -mpclmul -g0 -Wno-psabi' ) \
      2>&1 | tee "$S/logs/setup_$key.log" | tail -5
}

build_tree() { # $1=tree-key
  local key=$1
  log "ninja $key"
  ( cd "$S/build/$key" && $W/env/bin/ninja -j 12 libfaest.a librandomness_os.a subprojects/xkcp/libxkcp.a ) \
    2>&1 | tee "$S/logs/build_$key.log" | tail -4
}

# ---------- one-tree 单设置构建 ----------
build_onetree() { # $1=setting
  local setting=$1
  local T=$W/源码/faest-one-tree
  local AI=$T/Additional_Implementations/$setting
  if [ ! -f "$AI/api.o" ] || [ ! -f "$AI/faest.o" ]; then
    log "make $setting"
    ( cd "$T" && COMMON_LD_FLAGS="-O2 -march=x86-64-v3 -maes -mpclmul -DNDEBUG" \
        make -j 8 CC=$GCC CXX=$GXX "$setting" ) \
      2>&1 | tee "$S/logs/build_onetree_$setting.log" | tail -4
  else
    log "one-tree $setting objects exist"
  fi
}

# ---------- 单实现构建 ----------
build_impl() { # $1=key
  local key=$1
  local row
  row=$(awk -F'\t' -v k="$key" '$1==k{print}' "$S/scripts/impls.tsv")
  [ -n "$row" ] || { echo "unknown impl $key"; return 1; }
  local id scheme param tree ptype setting q7id commit compiler cflags
  IFS=$'\t' read -r key id scheme param tree ptype setting q7id commit compiler cflags <<<"$row"

  local dir=$S/impls/$key
  mkdir -p "$dir/work"

  # M1：从 A 线 q7 元数据读 API 常量，再用 gen 输出核对
  local meta
  meta=$(cd "$W" && taskset -c 0 nice -n 19 "$Q7/q7_impl_$q7id" --validate-only 2>/dev/null | head -1)
  local pk sk sig
  pk=$(printf '%s' "$meta" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key_bytes"])')
  sk=$(printf '%s' "$meta" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["secret_key_bytes"])')
  sig=$(printf '%s' "$meta" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["signature_bytes_expected"])')
  printf 'pk=%s\nsk=%s\nsig=%s\n' "$pk" "$sk" "$sig" > "$dir/work/dims.txt"
  log "$key: pk=$pk sk=$sk sig=$sig"

  # API 包装
  if [ "$tree" = "one-tree" ]; then
    local AI=$W/源码/faest-one-tree/Additional_Implementations/$setting
    cp "$AI/api.h" "$dir/work/api.h"
    cp "$AI/api.o" "$dir/work/api.o"
  else
    local src
    case "$tree" in
      rain) src=$W/q5/work/rain ;;
      rfaest) src=$W/q5/work/rfaest ;;
      faest) src=$W/q5/work/faest_v3 ;;
    esac
    /usr/bin/python3 "$S/scripts/gen_api.py" --tree "$tree" --src "$src" --out "$dir/work" \
      --param "$ptype" --name "$scheme-$param" --pk "$pk" --sk "$sk" --sig "$sig" \
      || return 1
    local xkcp=$src/subprojects/xkcp
    local incs
    incs=$( cd "$S/build/$tree" && $W/env/bin/meson introspect --targets 2>/dev/null | \
      /usr/bin/python3 -c '
import json,sys
d=json.load(sys.stdin); out=[]
for t in d:
    if t.get("name")!="faest": continue
    for s in t.get("target_sources",[]):
        for p in s.get("parameters",[]):
            if p.startswith("-I"): out.append(p)
print(" ".join(dict.fromkeys(out)))
' )
    $ZCXX -std=c++23 -O3 -DNDEBUG -march=x86_64_v3 -maes -mpclmul -g0 \
      -I"$src" -I"$S/build/$tree" -I"$xkcp" $incs \
      -c "$dir/work/api.cpp" -o "$dir/work/api.o" \
      || { echo "API_COMPILE_FAIL $key"; return 1; }
  fi

  # 探针（模板树全链用 zig，避免 conda GCC 对象与 zig libc 混链）
  if [ "$tree" = "one-tree" ]; then
    $GCC -O2 -std=c11 -I"$dir/work" -c "$S/scripts/probe.c" -o "$dir/work/probe.o" \
      || { echo "PROBE_COMPILE_FAIL $key"; return 1; }
    $GCC -O2 -std=c11 -c "$S/scripts/rand_wrap.c" -o "$dir/work/rand_wrap.o" \
      || { echo "RANDWRAP_COMPILE_FAIL $key"; return 1; }
  else
    $ZCC -O2 -std=c11 -I"$dir/work" -c "$S/scripts/probe.c" -o "$dir/work/probe.o" \
      || { echo "PROBE_COMPILE_FAIL $key"; return 1; }
    $ZCC -O2 -std=c11 -c "$S/scripts/rand_wrap.c" -o "$dir/work/rand_wrap.o" \
      || { echo "RANDWRAP_COMPILE_FAIL $key"; return 1; }
  fi

  # 链接
  if [ "$tree" = "one-tree" ]; then
    local AI=$W/源码/faest-one-tree/Additional_Implementations/$setting
    local objs
    objs=$(ls "$AI"/*.o | grep -vE '/catch_amalgamated\.o$|/test[^/]*\.o$|/api_test\.o$|/PQCgenKAT_sign\.o$')
    $GXX -O2 -Wl,--gc-sections -static-libstdc++ -static-libgcc \
      "$dir/work/probe.o" $objs -lcrypto -lm -o "$dir/probe_$key" \
      || { echo "LINK_FAIL $key"; return 1; }
    printf '%s\n' $objs > "$dir/work/m5_objects.txt"
  else
    local bld=$S/build/$tree
    $ZCXX -O3 -Wl,--gc-sections \
      "$dir/work/probe.o" "$dir/work/api.o" "$dir/work/rand_wrap.o" \
      "$bld/libfaest.a" "$bld/librandomness_os.a" "$bld/subprojects/xkcp/libxkcp.a" \
      -lm -o "$dir/probe_$key" \
      || { echo "LINK_FAIL $key"; return 1; }
  fi
  log "built $dir/probe_$key"
}

case "${1:-}" in
  setup)
    setup_tree rain "$W/q5/work/rain"
    setup_tree rfaest "$W/q5/work/rfaest"
    setup_tree faest "$W/q5/work/faest_v3"
    ;;
  libs)
    build_tree rain; build_tree rfaest; build_tree faest
    ;;
  onetree)
    for s in sec128_r3ccs_16_8_108_avx2 sec128_r3ccs_11_7_100_avx2 \
             sec128_r4ccs_16_8_110_avx2 sec128_r4ccs_11_7_101_avx2; do
      build_onetree "$s"
    done
    ;;
  impl)
    make_empty
    build_impl "${2:?impl key}"
    ;;
  all)
    make_empty
    setup_tree rain "$W/q5/work/rain"
    setup_tree rfaest "$W/q5/work/rfaest"
    setup_tree faest "$W/q5/work/faest_v3"
    build_tree rain; build_tree rfaest; build_tree faest
    for s in sec128_r3ccs_16_8_108_avx2 sec128_r3ccs_11_7_100_avx2 \
             sec128_r4ccs_16_8_110_avx2 sec128_r4ccs_11_7_101_avx2; do
      build_onetree "$s"
    done
    while IFS=$'\t' read -r key rest; do
      [ "$key" = "key" ] && continue
      build_impl "$key"
    done < "$S/scripts/impls.tsv"
    ;;
  *)
    echo "usage: $0 setup|libs|onetree|impl <key>|all"; exit 1 ;;
esac
echo BUILD_STORAGE_DONE
