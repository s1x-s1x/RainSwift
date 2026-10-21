// Windows only, force-included (-include) into the signature library's C++ translation units.
//
// The library allocates its large work buffers with C11 aligned_alloc and releases them with
// free. The Windows C runtime has no aligned_alloc, and memory from its replacement,
// _aligned_malloc, must be released with _aligned_free. Every free() in the source tree releases
// an aligned_alloc buffer (checked one by one: 12 allocation and 17 release sites), so the pair is
// mapped here without touching the source files.
//
// The standard headers the library uses are included first, so the function-like macros below
// cannot reach inline code in them; STL allocators and operator delete are unaffected.
#pragma once
#if defined(_WIN32)
#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <bitset>
#include <cassert>
#include <cinttypes>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <new>
#include <numeric>
#include <sstream>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>
#include <inttypes.h>
#include <malloc.h>
#include <string.h>
#include <immintrin.h>
#include <wmmintrin.h>
// The size argument is variadic because some call sites pass template argument lists with commas
// (e.g. TREES_IN_FOREST<TAU, DELTA_BITS>(true) * ...); no alignment argument contains a top-level comma.
#define aligned_alloc(alignment, ...) _aligned_malloc((__VA_ARGS__), (alignment))
#define free(pointer) _aligned_free((pointer))
#endif
