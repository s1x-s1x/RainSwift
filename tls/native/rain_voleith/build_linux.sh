#!/usr/bin/env bash
# Linux x86-64 build of the Rain-VOLEitH TLS library.
# The upstream build.py targets Windows (DLL, bcrypt, MSYS2 paths); this script
# uses the same source list and flags but emits librain_voleith_tls.so.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RAIN_SRC="${1:?usage: build_linux.sh RAIN_SRC XKCP_SRC OUT_DIR}"
XKCP_SRC="${2:?usage: build_linux.sh RAIN_SRC XKCP_SRC OUT_DIR}"
OUT="${3:-$(cd "$HERE/../.." && pwd)/build}"
CC="${CC:-gcc}"
CXX="${CXX:-g++}"
AR="${AR:-ar}"

mkdir -p "$OUT/rain-obj"
OBJ="$OUT/rain-obj"
DEFINES=(-DRAIN_SHRUNK_KEYSPACE=0)
INCLUDES=(-I"$HERE" -I"$HERE/xkcp_config" -I"$RAIN_SRC")
for sub in "" lib/common lib/low/common lib/high/Keccak lib/high/Keccak/FIPS202 \
           lib/low/KeccakP-1600/plain-64bits lib/low/KeccakP-1600/plain-64bits/u6 \
           lib/low/KeccakP-1600/common lib/low/KeccakP-1600-times2/SIMD128 \
           lib/low/KeccakP-1600-times2/SIMD128/SSSE3-u2 lib/low/KeccakP-1600-times4/AVX2 \
           lib/low/KeccakP-1600-times4/AVX2/u12 lib/low/KeccakP-1600-times8/fallback-on4; do
  INCLUDES+=(-I"$XKCP_SRC/$sub")
done
ISA=(-march=x86-64-v3 -maes -mpclmul -fPIC)
CFLAGS=(-std=c2x -O3 -g0 -DNDEBUG "${ISA[@]}" "${DEFINES[@]}" "${INCLUDES[@]}")
CXXFLAGS=(-std=c++23 -O3 -g0 -DNDEBUG "${ISA[@]}" -Wno-ignored-attributes -Wno-attributes -Wno-psabi "${DEFINES[@]}" "${INCLUDES[@]}")
BASE=(-std=c2x -O2 -g0 -fPIC -march=x86-64 "${INCLUDES[@]}")

XKCP_C=(lib/high/Keccak/FIPS202/KeccakHash.c lib/high/Keccak/KeccakSponge.c
        lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c
        lib/low/KeccakP-1600-times2/SIMD128/KeccakP-1600-times2-SIMD128.c
        lib/low/KeccakP-1600-times4/AVX2/KeccakP-1600-times4-SIMD256.c)
LIB_C=(sha3/KeccakHashtimes4.c sha3/KeccakSpongetimes4.c)
LIB_CXX=(avx2/aes_impl.cpp faest.cpp owf_proof.cpp polynomials_constants.cpp
         small_vole.cpp vector_com.cpp vole_commit.cpp)

compile() { "$@" ; }

i=0
for rel in "${XKCP_C[@]}"; do
  compile "$CC" "${CFLAGS[@]}" -c "$XKCP_SRC/$rel" -o "$OBJ/x$(printf '%02d' "$i").o" &
  i=$((i+1))
done
i=0
for rel in "${LIB_C[@]}"; do
  compile "$CC" "${CFLAGS[@]}" -c "$RAIN_SRC/$rel" -o "$OBJ/c$(printf '%02d' "$i").o" &
  i=$((i+1))
done
i=0
for rel in "${LIB_CXX[@]}"; do
  compile "$CXX" "${CXXFLAGS[@]}" -c "$RAIN_SRC/$rel" -o "$OBJ/l$(printf '%02d' "$i").o" &
  i=$((i+1))
done
compile "$CXX" "${CXXFLAGS[@]}" -c "$HERE/rain_voleith_tls.cpp" -o "$OBJ/w00.o" &
compile "$CC" "${BASE[@]}" -c "$HERE/rain_voleith_platform.c" -o "$OBJ/p00.o" &
wait

expected=$(( ${#XKCP_C[@]} + ${#LIB_C[@]} + ${#LIB_CXX[@]} + 2 ))
actual=$(ls "$OBJ"/*.o 2>/dev/null | wc -l)
if [ "$actual" -ne "$expected" ]; then
  echo "compilation incomplete: $actual of $expected objects" >&2
  exit 1
fi
"$AR" rcs "$OUT/libsig_tls.a" "$OBJ"/x*.o "$OBJ"/c*.o "$OBJ"/l*.o
"$CXX" -shared -O3 -g0 -o "$OUT/librain_voleith_tls.so" "$OBJ/w00.o" "$OBJ/p00.o" \
       "$OUT/libsig_tls.a" -static-libgcc -static-libstdc++
sha256sum "$OUT/librain_voleith_tls.so"
