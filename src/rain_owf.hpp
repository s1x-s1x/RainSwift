// 迭代030 Q2：Rain-128-R 单向函数（Rainier 公开实例）——塔域正向计算、塔域 -> VOLE 域映射
// 常数全部来自自动生成的 rain_params.hpp（Q1 冻结参数）。常数时间：无秘密下标查表、无秘密分支
// （唯一例外是建钥时「S 盒输入为 0 就重取」，泄露的只是一个被丢弃的候选私钥）。
#ifndef RAIN_OWF_HPP
#define RAIN_OWF_HPP

#include <immintrin.h>
#include <cstdint>
#include <cstring>
#include "rain_params.hpp"

namespace faest::rain
{

struct e128 { uint64_t lo, hi; };

// ---------- GF(2^64)，x^64+x^4+x^3+x+1 ----------
static inline uint64_t r64(__m128i p)
{
    const __m128i R = _mm_set_epi64x(0, 0x1B);
    __m128i t = _mm_clmulepi64_si128(p, R, 0x01);
    __m128i u = _mm_clmulepi64_si128(t, R, 0x01);
    return (uint64_t) _mm_cvtsi128_si64(p) ^ (uint64_t) _mm_cvtsi128_si64(t) ^ (uint64_t) _mm_cvtsi128_si64(u);
}
static inline uint64_t m64(uint64_t a, uint64_t b)
{
    return r64(_mm_clmulepi64_si128(_mm_cvtsi64_si128((long long) a), _mm_cvtsi64_si128((long long) b), 0));
}
static inline uint64_t s64(uint64_t a) { return m64(a, a); }
static inline uint64_t sqn(uint64_t a, int n) { while (n--) a = s64(a); return a; }

// 多次平方是 GF(2) 线性映射：用 AVX2 掩码做常数时间矩阵乘
static inline uint64_t mapply64(const uint64_t* C, uint64_t x)
{
    const __m256i K = _mm256_set_epi64x(8, 4, 2, 1);
    __m256i acc = _mm256_setzero_si256(), X = _mm256_set1_epi64x((long long) x);
    for (int j = 0; j < 64; j += 4)
    {
        __m256i kj = _mm256_sllv_epi64(K, _mm256_set1_epi64x(j));
        __m256i msk = _mm256_cmpeq_epi64(_mm256_and_si256(X, kj), kj);
        acc = _mm256_xor_si256(acc, _mm256_and_si256(msk, _mm256_load_si256((const __m256i*) (C + j))));
    }
    __m128i h = _mm_xor_si128(_mm256_castsi256_si128(acc), _mm256_extracti128_si256(acc, 1));
    return (uint64_t) _mm_cvtsi128_si64(h) ^ (uint64_t) _mm_extract_epi64(h, 1);
}
// a^(2^64-2)，加法链 1,2,3,6,7,14,15,30,31,62,63
static inline uint64_t inv64(uint64_t a)
{
    uint64_t b1 = a, b2 = m64(s64(b1), b1), b3 = m64(s64(b2), b1), b6 = m64(sqn(b3, 3), b3), b7 = m64(s64(b6), b1);
    uint64_t b14 = m64(sqn(b7, 7), b7), b15 = m64(s64(b14), b1);
    uint64_t b30 = m64(mapply64(rain_consts::SQ15, b15), b15), b31 = m64(s64(b30), b1);
    uint64_t b62 = m64(mapply64(rain_consts::SQ31, b31), b31), b63 = m64(s64(b62), b1);
    return s64(b63);
}

// ---------- 塔域 GF(2^64)[y]/(y^2+y+β)，元素 = lo + hi·y ----------
static inline e128 tinv(e128 a)
{
    constexpr uint64_t B = rain_consts::BETA;
    uint64_t N = s64(a.lo) ^ m64(a.lo, a.hi) ^ m64(B, s64(a.hi)), Ni = inv64(N);
    return {m64(a.lo ^ a.hi, Ni), m64(a.hi, Ni)};
}

// ---------- 128×128 GF(2) 矩阵乘（按列存，C[j] = M·e_j），AVX2 常数时间 ----------
static inline e128 mapply128(const uint64_t (*C)[2], e128 x)
{
    __m256i a0 = _mm256_setzero_si256(), a1 = a0;
    for (int w = 0; w < 2; w++)
    {
        uint64_t v = w ? x.hi : x.lo;
        __m256i X = _mm256_set1_epi64x((long long) v);
        for (int j = 0; j < 64; j += 4)
        {
            __m256i k1 = _mm256_set_epi64x((long long) (1ull << (j + 1)), (long long) (1ull << (j + 1)), (long long) (1ull << j), (long long) (1ull << j));
            __m256i k2 = _mm256_set_epi64x((long long) (1ull << (j + 3)), (long long) (1ull << (j + 3)), (long long) (1ull << (j + 2)), (long long) (1ull << (j + 2)));
            __m256i m01 = _mm256_cmpeq_epi64(_mm256_and_si256(X, k1), k1), m23 = _mm256_cmpeq_epi64(_mm256_and_si256(X, k2), k2);
            a0 = _mm256_xor_si256(a0, _mm256_and_si256(m01, _mm256_load_si256((const __m256i*) C[64 * w + j])));
            a1 = _mm256_xor_si256(a1, _mm256_and_si256(m23, _mm256_load_si256((const __m256i*) C[64 * w + j + 2])));
        }
    }
    __m256i a = _mm256_xor_si256(a0, a1);
    __m128i h = _mm_xor_si128(_mm256_castsi256_si128(a), _mm256_extracti128_si256(a, 1));
    return {(uint64_t) _mm_cvtsi128_si64(h), (uint64_t) _mm_extract_epi64(h, 1)};
}

// ---------- 实例常数 ----------
template <unsigned R> struct inst;
template <> struct inst<3>
{
    static const uint64_t* rc_t(unsigned r) { return rain_consts::RC_T3[r]; }
    static const uint64_t* rc_p(unsigned r) { return rain_consts::RC_P3[r]; }
    static const uint64_t (*mc_t(unsigned r))[2] { return rain_consts::MC_T3[r]; }
    static const uint64_t (*mc_p(unsigned r))[2] { return rain_consts::MC_P3[r]; }
};
template <> struct inst<4>
{
    static const uint64_t* rc_t(unsigned r) { return rain_consts::RC_T4[r]; }
    static const uint64_t* rc_p(unsigned r) { return rain_consts::RC_P4[r]; }
    static const uint64_t (*mc_t(unsigned r))[2] { return rain_consts::MC_T4[r]; }
    static const uint64_t (*mc_p(unsigned r))[2] { return rain_consts::MC_P4[r]; }
};

// 塔域正向计算。ys[r] = 第 r 轮 S 盒输出（可为空）；*zero = 是否有 S 盒输入为 0（常数时间累积）
template <unsigned R> static inline e128 forward(e128 k, e128 pt, e128* ys, bool* zero)
{
    e128 s = pt;
    uint64_t z = 0;
    for (unsigned r = 0; r < R; r++)
    {
        s.lo ^= k.lo ^ inst<R>::rc_t(r)[0];
        s.hi ^= k.hi ^ inst<R>::rc_t(r)[1];
        z |= (uint64_t) ((s.lo | s.hi) == 0);
        s = tinv(s);
        if (ys) ys[r] = s;
        if (r + 1 < R) s = mapply128(inst<R>::mc_t(r), s);
    }
    s.lo ^= k.lo;
    s.hi ^= k.hi;
    *zero = z != 0;
    return s;
}

// 塔域编码 -> VOLE 域（多项式基）编码
static inline e128 to_p(e128 t) { return mapply128(rain_consts::PSI, t); }

static inline e128 load(const void* p) { e128 x; std::memcpy(&x, p, 16); return x; }
static inline void store(void* p, e128 x) { std::memcpy(p, &x, 16); }

} // namespace faest::rain

#endif
