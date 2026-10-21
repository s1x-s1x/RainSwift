#!/usr/bin/env bash
# run55: faest-one-tree 22 项计时程序构建（方案 #18-29、#42-51）
# 方式：作者 Makefile 默认选项构建（本机用 conda gcc14.4 代替其 README 的系统 GCC 11.4，报告披露）；
#       随机源计数包装通过 objcopy 改名 randomness_os.o 的符号实现（不改任何源码）；
#       计时程序为统一 q7 harness（模式 2）。42-45 为 -O3 对照（同名设置重建，先全部完成后重建）。
set -uo pipefail
W=review-workspace/rain-bench-20261016
T=$W/源码/faest-one-tree
GCC=$W/env/bin/x86_64-conda-linux-gnu-gcc
GXX=$W/env/bin/x86_64-conda-linux-gnu-g++
OBJCOPY=$W/env/bin/x86_64-conda-linux-gnu-objcopy
H=$W/run55/harness/q7_harness.cpp
BINS=$W/run55/bins
AI=$T/Additional_Implementations
export HOME=$W/home

# 预编共享件
$GCC -O2 -c $W/run55/harness/p0_getrandom.c -o $W/run55/harness/p0_getrandom.o || echo P0FAIL

build_one() { # id name setting sig wipe ldflags_override
  local ID=$1 NAME=$2 SET=$3 SIG=$4 WIPE=${5:-no} LDO=${6:-}
  local DIR=$AI/$SET
  if [ "$WIPE" = "wipe" ]; then rm -rf "$DIR"; fi
  echo "== [$(date -u +%FT%TZ)] make $SET wipe=$WIPE ldflags='$LDO'"
  if [ -n "$LDO" ]; then
    (cd $T && COMMON_LD_FLAGS="$LDO" nice -n 19 make -j 12 CC=$GCC CXX=$GXX "$SET") >/dev/null 2>&1 || echo "  warn: make non-zero for $SET" >&2
  else
    (cd $T && nice -n 19 make -j 12 CC=$GCC CXX=$GXX "$SET") >/dev/null 2>&1 || echo "  warn: make non-zero for $SET" >&2
  fi
  for f in api.o faest.o randomness_os.o; do
    [ -f "$DIR/$f" ] || { echo "MISSING_OBJ $SET $f"; return 1; }
  done
  if [ ! -f "$DIR/randomness_os.q7.o" ]; then
    $OBJCOPY --redefine-sym rand_bytes=p0_upstream_rand_bytes \
      "$DIR/randomness_os.o" "$DIR/randomness_os.q7.o" || { echo "OBJCOPY_FAIL $SET"; return 1; }
  fi
  $GXX -std=c++20 -O2 -DNDEBUG -march=native -mtune=native -Wall -Wextra -Wno-ignored-attributes \
    -I"$DIR" -DQ7_IMPL_ID=$ID -DQ7_MODE=2 -DQ7_DET=0 -DQ7_SIG=$SIG "-DQ7_NAME=\"$NAME\"" \
    -c "$H" -o "$DIR/q7_harness.o" || { echo "HARNESS_COMPILE_FAIL $ID"; return 1; }
  local OBJS=$(ls "$DIR"/*.o | grep -vE "/catch_amalgamated[.]o$|/test_bench_api[.]o$|/test_[^/]*[.]o$|/api_test[.]o$|/PQCgenKAT_sign[.]o$|/randomness_os[.]o$|/randomness_os[.]q7[.]o$|/randomness_randombytes[.]o$|/q7_harness[.]o$")
  $GXX -O2 -static-libstdc++ -static-libgcc \
    "$DIR/q7_harness.o" $OBJS "$DIR/randomness_os.q7.o" "$W/run55/harness/p0_getrandom.o" \
    -lm -o "$BINS/q7_impl_$ID" || { echo "LINK_FAIL $ID"; return 1; }
  echo "built q7_impl_$ID ($NAME) expect=$SIG"
}

# ---- 主清单 18-29（默认 -O2 选项）----
build_one 18 "FAESTER-128f"        sec128_cccs_16_8_110_avx2  6052
build_one 19 "FAESTER-128s"        sec128_cccs_11_7_102_avx2  4594
build_one 20 "FAESTER-EM-128f"     sec128_eccs_16_8_112_avx2  5444
build_one 21 "FAESTER-EM-128s"     sec128_eccs_11_7_103_avx2  4170
build_one 22 "MandaRain-3-128f"    sec128_r3ccs_16_8_108_avx2 3588
build_one 23 "MandaRain-3-128s"    sec128_r3ccs_11_7_100_avx2 2890
build_one 24 "MandaRain-4-128f"    sec128_r4ccs_16_8_110_avx2 3876
build_one 25 "MandaRain-4-128s"    sec128_r4ccs_11_7_101_avx2 3082
build_one 26 "KuMQuat-2^1-L1f"     sec128_mq1ccs_16_4_102_avx2 3028
build_one 27 "KuMQuat-2^1-L1s"     sec128_mq1ccs_11_7_99_avx2  2555
build_one 28 "KuMQuat-2^8-L1f"     sec128_mq8ccs_16_4_108_avx2 3588
build_one 29 "KuMQuat-2^8-L1s"     sec128_mq8ccs_11_7_100_avx2 2890

# ---- 对照 46-51 ----（46-49 AES 叶；50-51 f 档 w=4）
build_one 46 "MandaRain-3-128f-aesleaf" sec128_r3ccc_16_8_108_avx2 3588
build_one 47 "MandaRain-3-128s-aesleaf" sec128_r3ccc_11_7_100_avx2 2890
build_one 48 "MandaRain-4-128f-aesleaf" sec128_r4ccc_16_8_110_avx2 3876
build_one 49 "MandaRain-4-128s-aesleaf" sec128_r4ccc_11_7_101_avx2 3082
build_one 50 "MandaRain-3-128f-w4"      sec128_r3ccs_16_4_108_avx2 3588
build_one 51 "MandaRain-4-128f-w4"      sec128_r4ccs_16_4_110_avx2 3876

# ---- 对照 42-45：-O3 重建（同名设置，wipe 后以 -O3 重编；最后一轮构建状态即为 O3）----
LDO3="-O3 -march=native -mtune=native -DNDEBUG"
build_one 42 "MandaRain-3-128f-O3" sec128_r3ccs_16_8_108_avx2 3588 wipe "$LDO3"
build_one 43 "MandaRain-3-128s-O3" sec128_r3ccs_11_7_100_avx2 2890 wipe "$LDO3"
build_one 44 "MandaRain-4-128f-O3" sec128_r4ccs_16_8_110_avx2 3876 wipe "$LDO3"
build_one 45 "MandaRain-4-128s-O3" sec128_r4ccs_11_7_101_avx2 3082 wipe "$LDO3"

echo "== [$(date -u +%FT%TZ)] artifacts:"
ls $BINS/ | grep -E "^q7_impl_(1[89]|2[0-9]|4[2-9]|5[01])$" || echo "(none)"
echo BUILD55_ONETREE_DONE
