#!/usr/bin/env bash
# run55: AIMer 四项计时程序构建（#38-41）
#  v2.1（KpqC 2R avx2 实现）：直编对象 + libshake.a + q7 harness；不编 rng.c（随机源由 harness 包装 + getrandom）
#  v3.0（官方参考实现）：借其 Makefile 编对象（obj/<params>），排除 rng.o，链接 q7 harness
set -uo pipefail
W=review-workspace/rain-bench-20261016
GCC=$W/env/bin/x86_64-conda-linux-gnu-gcc
GXX=$W/env/bin/x86_64-conda-linux-gnu-g++
H=$W/run55/harness/q7_harness.cpp
BINS=$W/run55/bins
P0=$W/run55/harness/p0_getrandom.o
AD=$W/run55/adapt
export HOME=$W/home
[ -f "$P0" ] || $GCC -O2 -c $W/run55/harness/p0_getrandom.c -o $P0

A21=$W/源码/aimer21/240402_AIMer/Additional_Implementation/avx2
A30=$W/源码/AIMer-734cc76fa4695ca8c8eaa070508db8ff62205e68/aimer-zip/Reference_Implementation
NIST_W="-Wno-sign-compare -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-unused-result"

build21() { # $1=subdir $2=id $3=name $4=sig
  local D=$A21/$1 ID=$2 NAME=$3 SIG=$4
  echo "== [$(date -u +%FT%TZ)] v2.1 $1"
  (cd $D/shake && CC=$GCC nice -n 19 make -j8) >/dev/null 2>&1 || echo "  warn: shake make rc!=0" >&2
  [ -f $D/shake/libshake.a ] || { echo "SHAKE_LIB_MISSING $1"; return 1; }
  local OBJS=""
  for s in aes.c aim2.c aimer.c api.c field.c hash.c tree.c; do
    $GCC -I$D -O3 -Wall -Wextra $NIST_W -march=native -fomit-frame-pointer \
      -c $D/$s -o $D/$s.q7.o || { echo "C21_FAIL $1 $s"; return 1; }
    OBJS="$OBJS $D/$s.q7.o"
  done
  $GXX -std=c++20 -O3 -DNDEBUG -march=native -mtune=native \
    -I$D -DQ7_IMPL_ID=$ID -DQ7_MODE=2 -DQ7_DET=0 -DQ7_SIG=$SIG "-DQ7_NAME=\"$NAME\"" \
    -c $H -o $D/q7_harness.o || { echo "H21_FAIL $ID"; return 1; }
  $GXX -O3 -static-libstdc++ -static-libgcc \
    $D/q7_harness.o $OBJS $D/shake/libshake.a $P0 -lm -o $BINS/q7_impl_$ID || { echo "L21_FAIL $ID"; return 1; }
  echo "built q7_impl_$ID ($NAME) expect=$SIG"
}

build30() { # $1=params $2=id $3=name $4=sig
  local P=$1 ID=$2 NAME=$3 SIG=$4
  echo "== [$(date -u +%FT%TZ)] v3.0 $P"
  (cd $A30 && nice -n 19 make SUBMAKE=1 PARAMS=$P OBJDIR=obj/$P BUILD_DIR=build/$P all_inner) >/dev/null 2>&1 || echo "  warn: v3 make rc!=0" >&2
  local OBJS
  OBJS=$(find $A30/obj/$P -name "*.o" 2>/dev/null | grep -vE "/(rng|test_[^/]*)[.]o$" | tr "\n" " ")
  [ -n "$(echo $OBJS)" ] || { echo "NOOBJ30 $P"; return 1; }
  local NS
  NS=$(nm $A30/obj/$P/*.o 2>/dev/null | grep -oE "samsungsds_[A-Za-z0-9_]*crypto_sign_keypair" | head -1 | sed "s/_crypto_sign_keypair$//")
  [ -n "$NS" ] || NS="samsungsds_aimer_${P}_ref"
  echo "  ns=$NS"
  local INC=$AD/aimer30/$ID
  mkdir -p $INC
  sed "s/@SIG@/$SIG/" $AD/aimer30_template/api_template.h > $INC/api.h
  $GCC -O3 -DPARAMS=$P \
    -DAIMER30_KG=${NS}_crypto_sign_keypair -DAIMER30_SIGN=${NS}_crypto_sign -DAIMER30_OPEN=${NS}_crypto_sign_open \
    -c $AD/aimer30_template/shim.c -o $AD/aimer30_template/shim_$ID.o || { echo "SHIM_FAIL $ID"; return 1; }
  $GXX -std=c++20 -O3 -DNDEBUG -march=native -mtune=native -I$INC \
    -DQ7_IMPL_ID=$ID -DQ7_MODE=2 -DQ7_DET=0 -DQ7_SIG=$SIG "-DQ7_NAME=\"$NAME\"" \
    -c $H -o $A30/q7_harness_$P.o || { echo "H30_FAIL $ID"; return 1; }
  $GXX -O3 -static-libstdc++ -static-libgcc \
    $A30/q7_harness_$P.o $AD/aimer30_template/shim_$ID.o $OBJS $P0 -lm -o $BINS/q7_impl_$ID || { echo "L30_FAIL $ID"; return 1; }
  echo "built q7_impl_$ID ($NAME) expect=$SIG"
}

build21 aimer128f 38 "AIMer-v2.1-128f" 5888
build21 aimer128s 39 "AIMer-v2.1-128s" 4160
build30 128f 40 "AIMer-v3.0-128f" 6944
build30 128s 41 "AIMer-v3.0-128s" 4704

echo "== [$(date -u +%FT%TZ)] artifacts:"
ls $BINS/ | grep -E "^q7_impl_(38|39|40|41)$" || echo "(none)"
echo BUILD55_AIMER_DONE
