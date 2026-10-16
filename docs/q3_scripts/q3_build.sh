#!/usr/bin/env bash
# 迭代030 Q3：只构建，不计时。由 P0 build_baselines_v3.sh（迭代028 linkfix_v3）改写：
# 四棵源码树、11 个实现、与 P0 相同的 release 选项；准备步骤见 q3_prepare.py。
# 用法：bash q3_build.sh ROOT SOURCE_ROOT JOBS BUILD_LABEL
# 需要实验目录内的工具：ROOT/tools/bin/{meson,ninja,zig-cc,zig-c++}。
set -euo pipefail
umask 077
die() { printf 'BUILD_ERROR %s\n' "$1" >&2; exit 64; }
[[ $# == 4 ]] || die 'expected ROOT SOURCE_ROOT JOBS BUILD_LABEL'
ROOT=$(realpath -e -- "$1" 2>/dev/null) || die 'experiment root is absent'
SOURCE_ROOT=$(realpath -e -- "$2" 2>/dev/null) || die 'source root is absent'
JOBS=$3
LABEL=$4
[[ $(basename "$ROOT") == research-iter030-q2q3-* ]] || die 'experiment root name is not research-iter030-q2q3-*'
[[ "$SOURCE_ROOT" == "$ROOT/"* ]] || die 'source material must be inside experiment root'
[[ "$JOBS" =~ ^([1-9]|[12][0-9]|3[0-2])$ ]] || die 'JOBS must be 1 through 32'
[[ "$LABEL" =~ ^[A-Za-z0-9_-]+$ ]] || die 'invalid build label'
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
for f in q3_harness.cpp q3_prepare.py q3_common.py kat_gen.cpp; do
  [[ -f "$SCRIPT_DIR/$f" ]] || die "missing $f next to this script"
done
for tool in meson ninja zig-cc zig-c++; do
  [[ -x "$ROOT/tools/bin/$tool" ]] || die "missing experiment-local tool $tool"
done
RUN="$ROOT/q3-builds/$LABEL"
[[ ! -e "$RUN" ]] || die 'build label already exists; preserve it and select a fresh label'
mkdir -p -- "$RUN" "$RUN/home" "$RUN/tmp" "$RUN/logs" "$RUN/private-build-logs" "$RUN/cache"
ORIGINAL_HOME=${HOME:-}
export HOME="$RUN/home" TMPDIR="$RUN/tmp" XDG_CACHE_HOME="$RUN/cache/xdg"
export ZIG_GLOBAL_CACHE_DIR="$RUN/cache/zig-global" ZIG_LOCAL_CACHE_DIR="$RUN/cache/zig-local"
export PIP_CACHE_DIR="$RUN/cache/pip" PYTHONDONTWRITEBYTECODE=1
export PATH="$ROOT/tools/bin:$PATH"
# Meson custom commands use python -m directly under Ninja as well.
export PYTHONPATH="$ROOT/tools/pydeps${PYTHONPATH:+:$PYTHONPATH}"
export CC="$ROOT/tools/bin/zig-cc" CXX="$ROOT/tools/bin/zig-c++"
ulimit -v 16777216

# 原始构建日志只留在服务器；可导出的日志把实验目录与家目录替换为占位符，不含账号路径。
run_step() {
  local name=$1 seconds=$2 rc
  shift 2
  [[ ! -e "$RUN/private-build-logs/$name.raw" ]] || die 'step log already exists'
  set +e
  nice -n 19 timeout --signal=TERM --kill-after=30s "$seconds" "$@" >"$RUN/private-build-logs/$name.raw" 2>&1
  rc=$?
  set -e
  python3 -I - "$RUN/private-build-logs/$name.raw" "$RUN/logs/$name.log" "$ROOT" "$ORIGINAL_HOME" <<'PY'
import pathlib, re, sys
raw, dest, root, home = sys.argv[1:]
text = pathlib.Path(raw).read_text(encoding='utf-8', errors='replace')
for prefix, replacement in sorted([(root, '<EXPERIMENT>'), (home, '<HOME>')], key=lambda x: -len(x[0])):
    if prefix:
        text = text.replace(prefix, replacement)
text = re.sub(r'/home/[^/\s\x27\x22]+', '<HOME>', text)
with open(dest, 'x', encoding='utf-8') as f:
    f.write(text)
PY
  printf 'BUILD_STEP %s exit=%s\n' "$name" "$rc"
  if (( rc != 0 )); then
    tail -n 90 "$RUN/logs/$name.log"
    exit "$rc"
  fi
}

run_step prepare 600 python3 -I "$SCRIPT_DIR/q3_prepare.py" "$ROOT" "$RUN" "$SOURCE_ROOT" \
  "$SCRIPT_DIR/q3_harness.cpp" "$SCRIPT_DIR/kat_gen.cpp"
run_step compiler_version 60 "$CXX" --version
declare -A TARGETS=(
  [faest_v3]="q3_impl_1 q3_impl_5"
  [rfaest]="q3_impl_2 q3_impl_4"
  [lynxer]="q3_impl_3"
  [rain]="q3_impl_6 q3_impl_7 q3_impl_8 q3_impl_9 q3_impl_10 q3_impl_11 rain_q2_test q3_rain_kat_lib"
)
for tree in faest_v3 rfaest lynxer rain; do
  run_step "configure_$tree" 300 "$ROOT/tools/bin/meson" setup "$RUN/build/$tree" "$RUN/work/$tree" \
    --buildtype=release --wrap-mode=nodownload -Db_ndebug=true -Db_lto=false -Doptimization=3 \
    -Dc_std=c23 -Dcpp_std=c++23 \
    "-Dc_args=-march=native -mtune=native -g0 -ffile-prefix-map=$ROOT=/experiment -fdebug-prefix-map=$ROOT=/experiment" \
    "-Dcpp_args=-march=native -mtune=native -g0 -Wno-psabi -ffile-prefix-map=$ROOT=/experiment -fdebug-prefix-map=$ROOT=/experiment"
  # shellcheck disable=SC2086
  run_step "compile_$tree" 5400 "$ROOT/tools/bin/ninja" -C "$RUN/build/$tree" -j "$JOBS" ${TARGETS[$tree]}
done

run_step artifact_manifest 120 python3 -I - "$RUN" "$SCRIPT_DIR" <<'PY'
import json, pathlib, sys
run, scripts = map(pathlib.Path, sys.argv[1:])
sys.path.insert(0, str(scripts))
from q3_common import AUX_EXECUTABLES, BUILD_FLAGS, sha256
records = json.loads((run/'build_inputs.json').read_text(encoding='utf-8'))
for record in records:
    path = run/record['executable']
    record['executable_sha256'] = sha256(path)
    record['executable_bytes'] = path.stat().st_size
    record['status'] = 'built_only_not_executed'
aux = {}
for name, tree in AUX_EXECUTABLES.items():
    path = run/'build'/tree/name
    aux[name] = {'executable': 'build/%s/%s' % (tree, name), 'executable_sha256': sha256(path),
                 'executable_bytes': path.stat().st_size}
with (run/'artifact_manifest.json').open('x', encoding='utf-8') as f:
    json.dump({'records': records, 'auxiliary': aux, 'validation': 'not run by build script', 'flags': BUILD_FLAGS,
               'tests_omitted': 'Catch2 targets omitted; Q2 tests are re-run separately on the Rain build'},
              f, indent=2, ensure_ascii=False)
    f.write('\n')
print('%d implementation and %d auxiliary executable hashes recorded; nothing was executed' % (len(records), len(aux)))
PY
printf 'BUILD_DONE artifact_dir=q3-builds/%s\n' "$LABEL"
