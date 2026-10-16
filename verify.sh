#!/usr/bin/env bash
# Build Rain-VOLEitH (release, -O3, B1=0), run the Q2 tests T1-T8, run the key-generation differential test
# (optimized Rain evaluation used by key generation vs. the original implementation, bit for bit) and compare
# the six signature KATs produced by T7 byte-for-byte with KAT/.
# Usage: ./verify.sh [--quick]     (--quick: 100 instead of 1000 sign/verify roundtrips per set in T6)
set -euo pipefail
cd "$(dirname "$0")"
BUILD=${BUILD:-build}
QUICK=()
[[ "${1:-}" == "--quick" ]] && QUICK=(--quick)

for flag in avx2 aes pclmulqdq; do
  grep -qw "$flag" /proc/cpuinfo || { echo "This CPU lacks $flag; an x86-64 CPU with AVX2, AES-NI and PCLMULQDQ is required."; exit 2; }
done

if [[ ! -f "$BUILD/build.ninja" ]]; then
  meson setup "$BUILD" src --buildtype=release -Doptimization=3 -Db_ndebug=true -Db_lto=false
fi
meson compile -C "$BUILD"

OUT="$BUILD/kat_out"
rm -rf "$OUT" && mkdir -p "$OUT"
"$BUILD/rain_q2_test" --kat-dir "$OUT" "${QUICK[@]}" | tee "$BUILD/rain_q2_test.log"
grep -q '^RESULT PASS' "$BUILD/rain_q2_test.log" || { echo "VERIFY FAIL: rain_q2_test reported failures"; exit 1; }

"$BUILD/q5_kg_test" --diff 20 > "$BUILD/q5_kg_test.log" || true
grep -v '^DIFF ' "$BUILD/q5_kg_test.log" || true
grep -q '^RESULT PASS (0 mismatches' "$BUILD/q5_kg_test.log" || { echo "VERIFY FAIL: key-generation differential test reported mismatches"; exit 1; }

(cd KAT && sha256sum -c --quiet SHA256SUMS) || { echo "VERIFY FAIL: KAT/ files were modified"; exit 1; }
fail=0
for ref in KAT/sigkat_*.txt; do
  name=$(basename "$ref")
  if cmp -s "$ref" "$OUT/$name"; then echo "KAT $name: identical"; else echo "KAT $name: DIFFERENT"; fail=1; fi
done
[[ $fail == 0 ]] || { echo "VERIFY FAIL: signature KAT mismatch"; exit 1; }
echo "VERIFY PASS: T1-T8 passed, the key-generation differential test passed and all six signature KATs match byte-for-byte"
