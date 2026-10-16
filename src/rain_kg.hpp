// 迭代030 Q5：建钥专用的 Rain 正向计算。
// 与 rain_owf.hpp 的 rain::forward<R> 计算同一个函数：有限域中逆元唯一，线性层是固定矩阵，所以对每个输入结果逐位相同。
// 只换算法实现：
//   线性层与多次平方表：各通道预先放 x、x>>1、…，统一做立即数左移把待测位移到符号位，再按符号位常数时间选列
//     （M1：vpcmpgtq 掩码 + vpand；M2：vblendvpd），全程留在向量寄存器（原实现每次迭代在通用寄存器里构造掩码）；
//   GF(2^64) 求逆：多次平方用编译期生成的线性表；加法链有四种写法（INV_CHAIN 选定建钥所用的一种，见 inv64_v）；
//   模约化：第二次折叠不足 3 位，用寄存器内 16 项 pshufb 表代替第二次 clmul。
// 只由建钥（faest_pubkey 的 Rain 分支）调用；签发中的见证计算仍用 rain_owf.hpp。
// 常数时间：无秘密分支、无以秘密为下标的访存（唯一的“表”是寄存器内 pshufb 表）。
#ifndef RAIN_KG_HPP
#define RAIN_KG_HPP

#include <immintrin.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <utility>
#include "rain_owf.hpp"

namespace faest::rain::kg
{

// ---------- 编译期：GF(2^64)（x^64+x^4+x^3+x+1）多次平方的线性表，按列存：C[j] = (x^j)^(2^k) ----------
namespace detail
{
using mat64 = std::array<uint64_t, 64>;

constexpr uint64_t apply(const mat64& a, uint64_t v)
{
    uint64_t r = 0;
    for (int i = 0; i < 64; i++)
        if ((v >> i) & 1)
            r ^= a[i];
    return r;
}
constexpr mat64 matmul(const mat64& a, const mat64& b)
{
    mat64 c{};
    for (int j = 0; j < 64; j++)
        c[j] = apply(a, b[j]);
    return c;
}
constexpr mat64 from(const uint64_t (&t)[64])
{
    mat64 c{};
    for (int j = 0; j < 64; j++)
        c[j] = t[j];
    return c;
}
// 平方映射：S[j] = x^(2j) mod f
constexpr mat64 square_map()
{
    mat64 s{};
    uint64_t v = 1; // x^e mod f
    for (int e = 0; e <= 126; e++)
    {
        if (e % 2 == 0)
            s[e / 2] = v;
        v = (v << 1) ^ ((v >> 63) ? 0x1Bull : 0);
    }
    return s;
}
// 约化表：U[v] = v·(x^4+x^3+x+1)，v < 16（结果次数 ≤ 7，恰好一个字节）
constexpr std::array<uint8_t, 16> fold_table()
{
    std::array<uint8_t, 16> u{};
    for (unsigned v = 0; v < 16; v++)
    {
        unsigned r = 0;
        for (int i = 0; i < 4; i++)
            if ((v >> i) & 1)
                r ^= 0x1Bu << i;
        u[v] = (uint8_t) r;
    }
    return u;
}
} // namespace detail

inline constexpr detail::mat64 S1 = detail::square_map();
alignas(32) inline constexpr detail::mat64 T3 = detail::matmul(S1, detail::matmul(S1, S1));
alignas(32) inline constexpr detail::mat64 T6 = detail::matmul(T3, T3);
alignas(32) inline constexpr detail::mat64 T15 = detail::from(rain_consts::SQ15);
alignas(32) inline constexpr detail::mat64 T30 = detail::matmul(T15, T15);
alignas(32) inline constexpr detail::mat64 T7 = detail::matmul(T6, S1);
alignas(32) inline constexpr detail::mat64 T31 = detail::from(rain_consts::SQ31);
inline constexpr std::array<uint8_t, 16> U = detail::fold_table();
// 与冻结常数核对：S^15 必须等于 SQ15，S^31 必须等于 SQ31（同一个域、同一种按列存法）
static_assert(detail::matmul(T3, detail::matmul(T3, detail::matmul(T3, detail::matmul(T3, T3)))) == T15,
              "Q5: generated squaring map differs from frozen SQ15");
static_assert(detail::matmul(T30, S1) == detail::from(rain_consts::SQ31), "Q5: generated squaring map differs from frozen SQ31");

// ---------- GF(2^64)：元素放在 __m128i 的低 64 位（高 64 位不参与运算） ----------
static inline __m128i red(__m128i p) // p = 128 位无进位乘积；结果的低 64 位有效
{
    const __m128i R = _mm_set_epi64x(0, 0x1B);
    const __m128i UT = _mm_setr_epi8((char) U[0], (char) U[1], (char) U[2], (char) U[3], (char) U[4], (char) U[5],
                                     (char) U[6], (char) U[7], (char) U[8], (char) U[9], (char) U[10], (char) U[11],
                                     (char) U[12], (char) U[13], (char) U[14], (char) U[15]);
    __m128i t = _mm_clmulepi64_si128(p, R, 0x01);           // p_hi·(x^4+x^3+x+1)，次数 ≤ 66
    __m128i u = _mm_shuffle_epi8(UT, _mm_srli_si128(t, 8)); // t_hi（< 8）·(x^4+x^3+x+1)
    return _mm_xor_si128(_mm_xor_si128(p, t), u);
}
static inline __m128i mul(__m128i a, __m128i b) { return red(_mm_clmulepi64_si128(a, b, 0x00)); }
static inline __m128i sqr(__m128i a) { return red(_mm_clmulepi64_si128(a, a, 0x00)); }

// ---------- 常数时间 GF(2) 矩阵乘（按列存，C[j] = M·e_j，按 32 字节对齐） ----------
// 每组装入 4 个 64 位通道的列数据，按待测位常数时间选择；四种写法结果相同，只是指令和执行口不同：
//   M1：预移位后统一立即数左移，把待测位移到符号位，vpcmpgtq 生成掩码再 vpand；
//   M2：同样移到符号位，vblendvpd 按符号位选择；
//   M3：常数位掩码 vpand 后 vpcmpeqq 生成掩码再 vpand（不用移位）；
//   M4：偶数组用 M2、奇数组用 M3，把负载分到不同执行口。
// lane_bits 给出四个通道各自待测的位号（相对当前 64 位字）；X 为预移位后的字（通道 t 放 x >> d_t），Xb 为原字的广播。
template <int M, int B0, int B1, int B2, int B3, int G>
static inline __m256i select_group(__m256i X, __m256i Xb, const void* cols)
{
    static_assert(M >= 1 && M <= 4, "unknown column-select method");
    const __m256i c = _mm256_load_si256((const __m256i*) cols);
    constexpr int MM = (M == 4) ? ((G % 2 == 0) ? 2 : 3) : M;
    if constexpr (MM == 3)
    {
        const __m256i K = _mm256_set_epi64x((long long) (1ull << B3), (long long) (1ull << B2), (long long) (1ull << B1),
                                            (long long) (1ull << B0));
        return _mm256_and_si256(_mm256_cmpeq_epi64(_mm256_and_si256(Xb, K), K), c);
    }
    else
    {
        // 预移位约定：所有通道统一左移 63 - B0，各通道待测位 B_t 恰好落到符号位（X 的通道 t 已右移 B_t - B0）
        const __m256i s = _mm256_slli_epi64(X, 63 - B0);
        if constexpr (MM == 1)
            return _mm256_and_si256(_mm256_cmpgt_epi64(_mm256_setzero_si256(), s), c);
        else
            return _mm256_castpd_si256(_mm256_blendv_pd(_mm256_setzero_pd(), _mm256_castsi256_pd(c), _mm256_castsi256_pd(s)));
    }
}

// 64×64：第 I 组测第 4I..4I+3 位，各通道依次对应一列；X 的通道 t 放 x >> t
template <int M, std::size_t... I> static inline __m128i map64_impl(const uint64_t* C, __m128i x, std::index_sequence<I...>)
{
    const __m256i Xb = _mm256_broadcastq_epi64(x);
    const __m256i X = _mm256_srlv_epi64(Xb, _mm256_set_epi64x(3, 2, 1, 0));
    __m256i acc[4] = {_mm256_setzero_si256(), _mm256_setzero_si256(), _mm256_setzero_si256(), _mm256_setzero_si256()};
    ((acc[I & 3] = _mm256_xor_si256(
          acc[I & 3], select_group<M, 4 * (int) I, 4 * (int) I + 1, 4 * (int) I + 2, 4 * (int) I + 3, (int) I>(X, Xb, C + 4 * I))),
     ...);
    const __m256i a = _mm256_xor_si256(_mm256_xor_si256(acc[0], acc[1]), _mm256_xor_si256(acc[2], acc[3]));
    const __m128i h = _mm_xor_si128(_mm256_castsi256_si128(a), _mm256_extracti128_si256(a, 1));
    return _mm_xor_si128(h, _mm_unpackhi_epi64(h, h));
}
template <int M> static inline __m128i map64(const uint64_t* C, __m128i x)
{
    return map64_impl<M>(C, x, std::make_index_sequence<16>{});
}

template <int K> static inline __m128i sqn(__m128i a)
{
    for (int i = 0; i < K; i++)
        a = sqr(a);
    return a;
}

// a^(2^64-2)；0 映射到 0（与 rain_owf.hpp 的 inv64 相同约定）。四种加法链写法计算同一个函数：
//   V1：链 1,2,3,6,12,15,30,60,63（8 次乘法），2^3、2^6、2^15、2^30 查表；
//   V2：同链，2^3 改用 3 次平方；
//   V3：原实现的链 1,2,3,6,7,14,15,30,31,62,63（10 次乘法），2^15、2^31 查表（只换乘法与约化）；
//   V4：同 V3，另把 2^7 改为查表。
// 建钥用 INV_CHAIN 选定的一种（按服务器组件微基准选定，见 Q5 计划的追加记录）；其余只供差分测试与微基准。
template <int V, int M> static inline __m128i inv64_v(__m128i a)
{
    static_assert(V >= 1 && V <= 4, "unknown inversion chain");
    if constexpr (V == 1 || V == 2)
    {
        auto p3 = [](__m128i x) {
            if constexpr (V == 1)
                return map64<M>(T3.data(), x);
            else
                return sqn<3>(x);
        };
        const __m128i b1 = a;
        const __m128i b2 = mul(sqr(b1), b1);
        const __m128i b3 = mul(sqr(b2), b1);
        const __m128i b6 = mul(p3(b3), b3);
        const __m128i b12 = mul(map64<M>(T6.data(), b6), b6);
        const __m128i b15 = mul(p3(b12), b3);
        const __m128i b30 = mul(map64<M>(T15.data(), b15), b15);
        const __m128i b60 = mul(map64<M>(T30.data(), b30), b30);
        const __m128i b63 = mul(p3(b60), b3);
        return sqr(b63);
    }
    else
    {
        const __m128i b1 = a;
        const __m128i b2 = mul(sqr(b1), b1);
        const __m128i b3 = mul(sqr(b2), b1);
        const __m128i b6 = mul(sqn<3>(b3), b3);
        const __m128i b7 = mul(sqr(b6), b1);
        __m128i b14;
        if constexpr (V == 4)
            b14 = mul(map64<M>(T7.data(), b7), b7);
        else
            b14 = mul(sqn<7>(b7), b7);
        const __m128i b15 = mul(sqr(b14), b1);
        const __m128i b30 = mul(map64<M>(T15.data(), b15), b15);
        const __m128i b31 = mul(sqr(b30), b1);
        const __m128i b62 = mul(map64<M>(T31.data(), b31), b31);
        const __m128i b63 = mul(sqr(b62), b1);
        return sqr(b63);
    }
}
inline constexpr int INV_CHAIN = 4;  // 建钥所用的加法链写法（V1–V4）
inline constexpr int MAP_METHOD = 2; // 建钥所用的选列方式（M1–M4）
static inline __m128i inv64(__m128i a) { return inv64_v<INV_CHAIN, MAP_METHOD>(a); }

// ---------- 塔域 GF(2^64)[y]/(y^2+y+β)：一个 __m128i 放 (lo, hi) ----------
template <int V, int M> static inline __m128i tinv_v(__m128i s)
{
    const __m128i B = _mm_set_epi64x(0, (long long) rain_consts::BETA);
    const __m128i lo2 = red(_mm_clmulepi64_si128(s, s, 0x00));   // lo^2
    const __m128i lohi = red(_mm_clmulepi64_si128(s, s, 0x10));  // lo·hi
    const __m128i hi2 = red(_mm_clmulepi64_si128(s, s, 0x11));   // hi^2
    const __m128i n = _mm_xor_si128(_mm_xor_si128(lo2, lohi), mul(B, hi2));
    const __m128i ni = inv64_v<V, M>(n);
    const __m128i lx = _mm_xor_si128(s, _mm_unpackhi_epi64(s, s)); // 低 64 位 = lo ^ hi
    const __m128i rlo = mul(lx, ni);
    const __m128i rhi = red(_mm_clmulepi64_si128(s, ni, 0x01));    // hi·ni
    return _mm_unpacklo_epi64(rlo, rhi);
}
static inline __m128i tinv(__m128i s) { return tinv_v<INV_CHAIN, MAP_METHOD>(s); }

// 128×128：每组装入相邻两列（各 128 位），通道 0、1 测第 2I 位，通道 2、3 测第 2I+1 位；X 的通道 2、3 放 x_w >> 1
template <int M, std::size_t... I>
static inline void map128_word(const uint64_t (*C)[2], __m256i X, __m256i Xb, __m256i (&acc)[4], std::index_sequence<I...>)
{
    ((acc[I & 3] = _mm256_xor_si256(
          acc[I & 3], select_group<M, 2 * (int) I, 2 * (int) I, 2 * (int) I + 1, 2 * (int) I + 1, (int) I>(X, Xb, C[2 * I]))),
     ...);
}
template <int M> static inline __m128i map128(const uint64_t (*C)[2], __m128i x)
{
    const __m256i SH = _mm256_set_epi64x(1, 1, 0, 0);
    __m256i acc[4] = {_mm256_setzero_si256(), _mm256_setzero_si256(), _mm256_setzero_si256(), _mm256_setzero_si256()};
    const __m256i X0b = _mm256_broadcastq_epi64(x), X1b = _mm256_broadcastq_epi64(_mm_unpackhi_epi64(x, x));
    map128_word<M>(C, _mm256_srlv_epi64(X0b, SH), X0b, acc, std::make_index_sequence<32>{});
    map128_word<M>(C + 64, _mm256_srlv_epi64(X1b, SH), X1b, acc, std::make_index_sequence<32>{});
    const __m256i a = _mm256_xor_si256(_mm256_xor_si256(acc[0], acc[1]), _mm256_xor_si256(acc[2], acc[3]));
    return _mm_xor_si128(_mm256_castsi256_si128(a), _mm256_extracti128_si256(a, 1));
}

// 塔域正向计算：与 rain::forward<R>(k, pt, nullptr, zero) 逐位相同。*zero = 是否有 S 盒输入为 0（常数时间累积）
template <unsigned R, int V, int M> static inline e128 forward_v(e128 k, e128 pt, bool* zero)
{
    __m128i K, s;
    std::memcpy(&K, &k, 16);
    std::memcpy(&s, &pt, 16);
    int z = 0;
    for (unsigned r = 0; r < R; r++)
    {
        s = _mm_xor_si128(s, _mm_xor_si128(K, _mm_loadu_si128((const __m128i*) inst<R>::rc_t(r))));
        z |= _mm_testz_si128(s, s);
        s = tinv_v<V, M>(s);
        if (r + 1 < R)
            s = map128<M>(inst<R>::mc_t(r), s);
    }
    s = _mm_xor_si128(s, K);
    *zero = z != 0;
    e128 out;
    std::memcpy(&out, &s, 16);
    return out;
}

template <unsigned R> static inline e128 forward(e128 k, e128 pt, bool* zero)
{
    return forward_v<R, INV_CHAIN, MAP_METHOD>(k, pt, zero);
}

} // namespace faest::rain::kg

#endif
