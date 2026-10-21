#!/usr/bin/env bash
# run55: BN++Rain / Rainier 适配层构建（直编：按作者 CMakeLists 的源清单与选项；CMake 不可用路径）
# 产出：q7_impl_30..37、52..55（12 个计时程序）
# 选项：C++17、-O3、NDEBUG、-Wall、-march=native、LTO（作者 CMake 的 IPO）；randomness.c 改名包装
set -uo pipefail
W=review-workspace/rain-bench-20261016
GCC=$W/env/bin/x86_64-conda-linux-gnu-gcc
GXX=$W/env/bin/x86_64-conda-linux-gnu-g++
BN=$W/源码/bnpp_helium_signatures-e226f1682c88825c7c434a67c3f1c5eaa3c624bd/bnpp_rain
RN=$W/sources/rainier-sigs
AD=$W/run55/adapt
H=$W/run55/harness/q7_harness.cpp
BINS=$W/run55/bins
mkdir -p $BINS "$AD/obj/bnpp" "$AD/obj/rainier" "$AD/inc" "$AD/probe"

CXXFLAGS="-std=c++17 -O3 -DNDEBUG -Wall -march=native -flto"
CFLAGS="-O3 -DNDEBUG -Wall -march=native -flto"

build_objs() { # $1=srcroot $2=objdir $3=label
  local SRC=$1 OBJ=$2 LBL=$3
  local INC="-I$SRC -I$SRC/keccak -I$SRC/keccak/avx2 -I$SRC/field"
  local FLD="-mpclmul -msse2 -msse4 -mpopcnt"
  echo "== [$(date -u +%FT%TZ)] build objects: $LBL"
  local rc=0
  $GXX $CXXFLAGS $INC -c $SRC/instances.cpp -o $OBJ/instances.o || rc=1
  $GXX $CXXFLAGS $INC -c $SRC/rain.cpp      -o $OBJ/rain.o || rc=1
  $GXX $CXXFLAGS $INC -c $SRC/signature.cpp -o $OBJ/signature.o || rc=1
  $GXX $CXXFLAGS $INC -c $SRC/tape.cpp      -o $OBJ/tape.o || rc=1
  $GXX $CXXFLAGS $INC -c $SRC/tree.cpp      -o $OBJ/tree.o || rc=1
  # 计时版随机源：改名（供 harness 包装计数）
  $GCC $CFLAGS $INC -Drand_bytes=p0_upstream_rand_bytes -c $SRC/randomness.c -o $OBJ/randomness.o || rc=1
  # 探测版随机源：原名（供 probe）
  $GCC $CFLAGS $INC -c $SRC/randomness.c -o $OBJ/randomness_plain.o || rc=1
  $GXX $CXXFLAGS $INC $FLD -c $SRC/field/field_GF2_128.cpp -o $OBJ/field128.o || rc=1
  $GXX $CXXFLAGS $INC $FLD -c $SRC/field/field_GF2_192.cpp -o $OBJ/field192.o || rc=1
  $GXX $CXXFLAGS $INC $FLD -c $SRC/field/field_GF2_256.cpp -o $OBJ/field256.o || rc=1
  $GCC $CFLAGS $INC -c $SRC/keccak/KeccakHash.c -o $OBJ/khash.o || rc=1
  $GCC $CFLAGS $INC -c $SRC/keccak/KeccakSponge.c -o $OBJ/ksponge.o || rc=1
  $GCC $CFLAGS $INC -c $SRC/keccak/KeccakSpongetimes4.c -o $OBJ/ksponge4.o || rc=1
  $GCC $CFLAGS $INC -c $SRC/keccak/KeccakHashtimes4.c -o $OBJ/khash4.o || rc=1
  $GCC $CFLAGS $INC -c $SRC/keccak/avx2/KeccakP-1600-times4-SIMD256.c -o $OBJ/ktimes4.o || rc=1
  $GCC $CFLAGS $INC -x assembler-with-cpp -c $SRC/keccak/avx2/KeccakP-1600-AVX2.s -o $OBJ/kavx2.o || rc=1
  [ $rc = 0 ] && echo "objects OK: $LBL" || echo "objects FAIL: $LBL"
  return $rc
}

probe() { # $1=objdir $2=srcroot $3=R $4=N $5=T $6=label -> prints sig bytes
  local OBJ=$1 SRC=$2 R=$3 N=$4 T=$5 LBL=$6
  local EXE=$AD/probe/probe_$LBL
  # 用未改名的 randomness_plain.o + 除 randomness 相关对象外的库对象
  local OBJS=$(ls $OBJ/*.o | grep -vE "randomness(_plain)?[.]o")
  $GXX -std=c++17 -O3 -DNDEBUG -march=native -flto -static-libstdc++ -static-libgcc \
    -DADAPT_ROUNDS=$R -DADAPT_N=$N -DADAPT_TAU=$T \
    -I$SRC -I$SRC/keccak -I$SRC/keccak/avx2 -I$SRC/field \
    $AD/probe_len.cpp $OBJS $OBJ/randomness_plain.o -lm -o $EXE || { echo "PROBE_FAIL $LBL"; return 1; }
  $EXE
}

compile_impl() { # $1=id $2=name $3=objdir $4=srcroot $5=R $6=N $7=T $8=sig
  local ID=$1 NAME=$2 OBJ=$3 SRC=$4 R=$5 N=$6 T=$7 SIG=$8
  local INC=$AD/inc/$ID
  mkdir -p $INC
  sed "s|<RUN55_SRC>|$SRC|" "$AD/adapt_api.h" > "$INC/api.h"
  printf '#define ADAPT_SIG_BYTES %s\n' "$SIG" > "$INC/adapt_sig_bytes.h"
  $GXX -std=c++17 -O3 -DNDEBUG -march=native -flto -DADAPT_ROUNDS=$R -DADAPT_N=$N -DADAPT_TAU=$T -DADAPT_SIG_BYTES=$SIG \
       -I$SRC -I$SRC/keccak -I$SRC/keccak/avx2 -I$SRC/field -c $AD/adapt.cpp -o $AD/tmp_adapt_$ID.o || { echo "ADAPT_FAIL $ID"; return 1; }
  $GXX -std=c++23 -O3 -DNDEBUG -march=native -flto -I$INC \
       -DQ7_IMPL_ID=$ID -DQ7_MODE=2 -DQ7_DET=1 -DQ7_SIG=$SIG "-DQ7_NAME=\"$NAME\"" \
       -c $H -o $AD/tmp_h_$ID.o || { echo "HARNESS_FAIL $ID"; return 1; }
  local OBJS=$(ls $OBJ/*.o | grep -v "randomness_plain.o")
  $GXX -O3 -flto -static-libstdc++ -static-libgcc $AD/tmp_adapt_$ID.o $AD/tmp_h_$ID.o $OBJS $AD/p0_getrandom.o -lm -o $BINS/q7_impl_$ID || { echo "LINK_FAIL $ID"; return 1; }
  echo "built q7_impl_$ID ($NAME)"
}

# 先编 p0_getrandom 共享对象
$GCC -O2 -c $W/run55/harness/p0_getrandom.c -o $AD/p0_getrandom.o || echo P0FAIL

# 库对象（bnpp、rainier 各一份）
build_objs $BN $AD/obj/bnpp bnpp   || true
build_objs $RN $AD/obj/rainier rainier || true

# ---- 探测签名长度（12 个参数组合） ----
declare -A SIGLEN
probe_combo() { # $1=lib(bnpp|rainier) $2=R $3=N $4=T
  local LIB=$1 R=$2 N=$3 T=$4
  local OBJ=$AD/obj/$LIB SRC=$BN
  [ $LIB = rainier ] && SRC=$RN
  local key="${LIB}_${R}_${N}_${T}"
  local out
  out=$(probe $OBJ $SRC $R $N $T "$key" 2>/dev/null) || { echo "PROBE_FAIL $key"; return 1; }
  SIGLEN[$key]=$out
  echo "sig[$key]=$out"
}

echo "== [$(date -u +%FT%TZ)] probing"
probe_combo bnpp 3 57 23    || true
probe_combo bnpp 3 1615 13  || true
probe_combo bnpp 4 57 23    || true
probe_combo bnpp 4 1615 13  || true
probe_combo bnpp 3 16 33    || true
probe_combo bnpp 4 16 33    || true
probe_combo bnpp 3 256 17   || true
probe_combo bnpp 4 256 17   || true
probe_combo rainier 3 16 33  || true
probe_combo rainier 3 256 17 || true
probe_combo rainier 4 16 33  || true
probe_combo rainier 4 256 17 || true

need() { # 取 sig；缺则 fail 该实现
  local key=$1
  if [ -z "${SIGLEN[$key]:-}" ]; then echo "MISSING_SIG $key"; return 1; fi
  echo "${SIGLEN[$key]}"
}

echo "== [$(date -u +%FT%TZ)] compiling adapt binaries"
S=$(need bnpp_3_57_23)    && compile_impl 30 "BN++Rain-3-128f"       $AD/obj/bnpp $BN 3 57 23 "$S"
S=$(need bnpp_3_1615_13)  && compile_impl 31 "BN++Rain-3-128s"       $AD/obj/bnpp $BN 3 1615 13 "$S"
S=$(need bnpp_4_57_23)    && compile_impl 32 "BN++Rain-4-128f"       $AD/obj/bnpp $BN 4 57 23 "$S"
S=$(need bnpp_4_1615_13)  && compile_impl 33 "BN++Rain-4-128s"       $AD/obj/bnpp $BN 4 1615 13 "$S"
S=$(need rainier_3_16_33) && compile_impl 34 "Rainier-3-f"           $AD/obj/rainier $RN 3 16 33 "$S"
S=$(need rainier_3_256_17)&& compile_impl 35 "Rainier-3-s"           $AD/obj/rainier $RN 3 256 17 "$S"
S=$(need rainier_4_16_33) && compile_impl 36 "Rainier-4-f"           $AD/obj/rainier $RN 4 16 33 "$S"
S=$(need rainier_4_256_17)&& compile_impl 37 "Rainier-4-s"           $AD/obj/rainier $RN 4 256 17 "$S"
S=$(need bnpp_3_16_33)    && compile_impl 52 "BN++Rain-3-128f-aimer" $AD/obj/bnpp $BN 3 16 33 "$S"
S=$(need bnpp_4_16_33)    && compile_impl 53 "BN++Rain-4-128f-aimer" $AD/obj/bnpp $BN 4 16 33 "$S"
S=$(need bnpp_3_256_17)   && compile_impl 54 "BN++Rain-3-128s-aimer" $AD/obj/bnpp $BN 3 256 17 "$S"
S=$(need bnpp_4_256_17)   && compile_impl 55 "BN++Rain-4-128s-aimer" $AD/obj/bnpp $BN 4 256 17 "$S"

echo "== [$(date -u +%FT%TZ)] artifacts:"
ls $BINS/ | grep -E "^q7_impl_(3[0-7]|5[2-5])$" || echo "(none)"
echo BUILD55_BNPP_DONE
