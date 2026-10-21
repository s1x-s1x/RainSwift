#!/usr/bin/env bash
# run55: 构建四棵模板树的 q7 计时程序（zig 0.13/clang18 + meson 1.5.2 + ninja 1.11.1；沙箱内；nice 19）
# 目标：q7_impl_1..6（rain）、7..8（rFAEST）、9（Lynxer）、10..17（FAEST v2/v3）
set -uo pipefail
W=review-workspace/rain-bench-20261016
cd "$W"
run_sb() { bash scripts/02_run_sandbox.sh nice -n 19 bash -c "$1"; }

setup_tree() { # $1=srcdir $2=builddir $3=label
  local src=$1 bld=$2 label=$3
  if [ ! -f "$bld/build.ninja" ]; then
    echo "== [$(date -u +%FT%TZ)] setup $label"
    run_sb "cd '$src' && export CC=$W/工具/bin/zig-cc CXX=$W/工具/bin/zig-c++ && $W/工具/bin/meson setup '$bld' . --buildtype=release --wrap-mode=nodownload -Db_ndebug=true -Db_lto=false -Doptimization=3 -Dc_std=c23 -Dcpp_std=c++23 '-Dc_args=-march=native -mtune=native -g0' '-Dcpp_args=-march=native -mtune=native -g0 -Wno-psabi' 2>&1 | tail -3" || return 1
  else
    echo "== $label already configured"
  fi
}

compile() { # $1=srcdir $2=builddir $3=targets $4=label
  echo "== [$(date -u +%FT%TZ)] compile $4: $3"
  run_sb "cd '$1' && export CC=$W/工具/bin/zig-cc CXX=$W/工具/bin/zig-c++ && $W/工具/bin/ninja -C '$2' -j 12 $3 2>&1 | tail -3" || echo "COMPILE_FAIL $4"
}

setup_tree "$W/q5/work/rain"     "$W/run55/build/rain-pilot" rain || true
compile    "$W/q5/work/rain"     "$W/run55/build/rain-pilot" "q7_impl_1 q7_impl_2 q7_impl_3 q7_impl_4 q7_impl_5 q7_impl_6" rain

setup_tree "$W/q5/work/rfaest"   "$W/run55/build/rfaest" rfaest || true
compile    "$W/q5/work/rfaest"   "$W/run55/build/rfaest" "q7_impl_7 q7_impl_8" rfaest

setup_tree "$W/run55/work/lynxer" "$W/run55/build/lynxer" lynxer || true
compile    "$W/run55/work/lynxer" "$W/run55/build/lynxer" "q7_impl_9" lynxer

setup_tree "$W/q5/work/faest_v3" "$W/run55/build/faest" faest || true
compile    "$W/q5/work/faest_v3" "$W/run55/build/faest" "q7_impl_10 q7_impl_11 q7_impl_12 q7_impl_13 q7_impl_14 q7_impl_15 q7_impl_16 q7_impl_17" faest

echo "== [$(date -u +%FT%TZ)] artifacts:"
for b in rain-pilot rfaest lynxer faest; do
  ls "$W/run55/build/$b/" 2>/dev/null | grep -E "^q7_impl_" | sed "s|^|  $b/|"
done
echo BUILD55_TEMPLATES_DONE
