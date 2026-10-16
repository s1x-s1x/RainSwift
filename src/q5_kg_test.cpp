// 迭代030 Q5：建钥专用实现（rain_kg.hpp）与原实现（rain_owf.hpp）的差分测试和组件微基准。
// 用法：q5_kg_test [--diff [log2N]] [--bench]（无参数等同 --diff 20）。
// 只用头文件，不链接库，不用系统随机源；输入来自确定性伪随机（splitmix64），可复现。
// 差分测试覆盖：GF(2^64) 乘法与平方（高 64 位填随机数）；六张多次平方表与四种选列方式（M1–M4）；
// 全部线性层（MC_T3、MC_T4、PSI）与四种选列方式；四种求逆加法链（V1–V4）× 四种选列方式下的 GF(2^64) 求逆、
// 塔域求逆和 R=3/4 正向计算（密文与零输入标志）；建钥实际所用组合（INV_CHAIN、MAP_METHOD）另以大样本测试；
// 外加构造用例（0、1、全 1、单位向量、第 0 轮 S 盒输入为 0 的密钥）。任何不一致即返回 1。
#include <x86intrin.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>
#include "rain_owf.hpp"
#include "rain_kg.hpp"

using namespace faest;
namespace kg = faest::rain::kg;
using rain::e128;
template <unsigned R> using UC = std::integral_constant<unsigned, R>;

static uint64_t g_state = 0x5135000000000001ull;
static uint64_t rnd()
{
    uint64_t z = (g_state += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}
static uint64_t lo64(__m128i v) { return (uint64_t) _mm_cvtsi128_si64(v); }
static __m128i v64(uint64_t a) { return _mm_set_epi64x((long long) rnd(), (long long) a); } // 高 64 位填随机数
static __m128i v128(e128 x) { __m128i v; std::memcpy(&v, &x, 16); return v; }
static e128 e(__m128i v) { e128 x; std::memcpy(&x, &v, 16); return x; }
static e128 re() { return {rnd(), rnd()}; }
static bool same(e128 a, e128 b) { return a.lo == b.lo && a.hi == b.hi; }

struct Tally
{
    std::string name;
    uint64_t n = 0, bad = 0;
    void add(bool ok) { n++; bad += !ok; }
};
static std::vector<Tally> tallies;
static Tally& T(const std::string& name) { tallies.push_back(Tally{name}); return tallies.back(); }

static const uint64_t SPECIAL64[] = {0, 1, ~0ull, 1ull << 63, 0x1B, rain_consts::BETA, 0x8000000000000001ull, 2};

struct MapCase { int k; const uint64_t* tab; const char* name; };
static const MapCase MAPS[] = {
    {3, kg::T3.data(), "T3=x^(2^3)"}, {6, kg::T6.data(), "T6=x^(2^6)"}, {7, kg::T7.data(), "T7=x^(2^7)"},
    {15, kg::T15.data(), "T15=x^(2^15)"}, {30, kg::T30.data(), "T30=x^(2^30)"}, {31, kg::T31.data(), "T31=x^(2^31)"}};
struct MatCase { const uint64_t (*C)[2]; const char* name; };
static const MatCase MATS[] = {
    {rain_consts::MC_T3[0], "MC_T3[0]"}, {rain_consts::MC_T3[1], "MC_T3[1]"}, {rain_consts::MC_T4[0], "MC_T4[0]"},
    {rain_consts::MC_T4[1], "MC_T4[1]"}, {rain_consts::MC_T4[2], "MC_T4[2]"}, {rain_consts::PSI, "PSI"}};

template <int M> static void diff_maps(uint64_t N)
{
    for (const MapCase& m : MAPS)
    {
        Tally& t = T("map64 M" + std::to_string(M) + " " + m.name);
        for (int j = 0; j < 64; j++) t.add(rain::sqn(1ull << j, m.k) == lo64(kg::map64<M>(m.tab, v64(1ull << j))));
        for (uint64_t a : SPECIAL64) t.add(rain::sqn(a, m.k) == lo64(kg::map64<M>(m.tab, v64(a))));
        for (uint64_t i = 0; i < N / 8; i++) { uint64_t a = rnd(); t.add(rain::sqn(a, m.k) == lo64(kg::map64<M>(m.tab, v64(a)))); }
    }
    for (const MatCase& m : MATS)
    {
        Tally& t = T("map128 M" + std::to_string(M) + " " + m.name);
        for (int j = 0; j < 128; j++)
        {
            e128 x{j < 64 ? 1ull << j : 0, j < 64 ? 0 : 1ull << (j - 64)};
            t.add(same(rain::mapply128(m.C, x), e(kg::map128<M>(m.C, v128(x)))));
        }
        for (e128 x : {e128{0, 0}, e128{~0ull, ~0ull}, e128{~0ull, 0}, e128{0, ~0ull}})
            t.add(same(rain::mapply128(m.C, x), e(kg::map128<M>(m.C, v128(x)))));
        for (uint64_t i = 0; i < N / 4; i++) { e128 x = re(); t.add(same(rain::mapply128(m.C, x), e(kg::map128<M>(m.C, v128(x))))); }
    }
}

template <int V, int M> static void diff_chain(uint64_t N)
{
    const std::string tag = "V" + std::to_string(V) + "M" + std::to_string(M) + " ";
    {
        Tally& t = T(tag + "gf64 inv");
        for (uint64_t a : SPECIAL64) t.add(rain::inv64(a) == lo64(kg::inv64_v<V, M>(v64(a))));
        for (uint64_t i = 0; i < N; i++) { uint64_t a = rnd(); t.add(rain::inv64(a) == lo64(kg::inv64_v<V, M>(v64(a)))); }
    }
    {
        Tally& t = T(tag + "tower inv");
        for (uint64_t a : SPECIAL64) for (uint64_t b : SPECIAL64) { e128 x{a, b}; t.add(same(rain::tinv(x), e(kg::tinv_v<V, M>(v128(x))))); }
        for (uint64_t i = 0; i < N; i++) { e128 x = re(); t.add(same(rain::tinv(x), e(kg::tinv_v<V, M>(v128(x))))); }
    }
    auto fv = [&](auto RC) {
        constexpr unsigned R = decltype(RC)::value;
        Tally& t = T(tag + "forward R=" + std::to_string(R) + " (ct, zero flag)");
        for (uint64_t i = 0; i < N; i++)
        {
            e128 k = re(), pt = re();
            bool z1 = false, z2 = true;
            e128 c1 = rain::forward<R>(k, pt, nullptr, &z1), c2 = kg::forward_v<R, V, M>(k, pt, &z2);
            t.add(same(c1, c2) && z1 == z2);
        }
        Tally& tz = T(tag + "forward R=" + std::to_string(R) + " zero at round 0");
        for (uint64_t i = 0; i < 1024; i++) // 第 0 轮 S 盒输入为 0：k = pt ^ rc_t(0)，两边都须报零
        {
            e128 pt = re(), k{pt.lo ^ rain::inst<R>::rc_t(0)[0], pt.hi ^ rain::inst<R>::rc_t(0)[1]};
            bool z1 = false, z2 = false;
            e128 c1 = rain::forward<R>(k, pt, nullptr, &z1), c2 = kg::forward_v<R, V, M>(k, pt, &z2);
            tz.add(z1 && z2 && same(c1, c2));
        }
    };
    fv(UC<3>{});
    fv(UC<4>{});
}

static int run_diff(int log2n)
{
    const uint64_t N = 1ull << log2n;
    tallies.reserve(256); // T() 返回引用：预留容量，避免扩容使引用失效
    {
        Tally& t = T("gf64 mul");
        for (uint64_t a : SPECIAL64) for (uint64_t b : SPECIAL64) t.add(rain::m64(a, b) == lo64(kg::mul(v64(a), v64(b))));
        for (uint64_t i = 0; i < N; i++) { uint64_t a = rnd(), b = rnd(); t.add(rain::m64(a, b) == lo64(kg::mul(v64(a), v64(b)))); }
    }
    {
        Tally& t = T("gf64 sqr");
        for (uint64_t a : SPECIAL64) t.add(rain::s64(a) == lo64(kg::sqr(v64(a))));
        for (uint64_t i = 0; i < N; i++) { uint64_t a = rnd(); t.add(rain::s64(a) == lo64(kg::sqr(v64(a)))); }
    }
    diff_maps<1>(N);
    diff_maps<2>(N);
    diff_maps<3>(N);
    diff_maps<4>(N);
    diff_chain<1, 1>(N / 8); diff_chain<2, 1>(N / 8); diff_chain<3, 1>(N / 8); diff_chain<4, 1>(N / 8);
    diff_chain<1, 2>(N / 8); diff_chain<2, 2>(N / 8); diff_chain<3, 2>(N / 8); diff_chain<4, 2>(N / 8);
    diff_chain<1, 3>(N / 8); diff_chain<2, 3>(N / 8); diff_chain<3, 3>(N / 8); diff_chain<4, 3>(N / 8);
    diff_chain<1, 4>(N / 8); diff_chain<2, 4>(N / 8); diff_chain<3, 4>(N / 8); diff_chain<4, 4>(N / 8);
    // 建钥实际所用组合（INV_CHAIN、MAP_METHOD）：经 kg::forward 入口，大样本
    auto fwd = [&](auto RC) {
        constexpr unsigned R = decltype(RC)::value;
        Tally& t = T("keygen path kg::forward R=" + std::to_string(R) + " (ct, zero flag)");
        for (uint64_t i = 0; i < N; i++)
        {
            e128 k = re(), pt = re();
            bool z1 = false, z2 = true;
            e128 c1 = rain::forward<R>(k, pt, nullptr, &z1), c2 = kg::forward<R>(k, pt, &z2);
            t.add(same(c1, c2) && z1 == z2);
        }
        Tally& tz = T("keygen path kg::forward R=" + std::to_string(R) + " zero at round 0");
        for (uint64_t i = 0; i < 4096; i++)
        {
            e128 pt = re(), k{pt.lo ^ rain::inst<R>::rc_t(0)[0], pt.hi ^ rain::inst<R>::rc_t(0)[1]};
            bool z1 = false, z2 = false;
            e128 c1 = rain::forward<R>(k, pt, nullptr, &z1), c2 = kg::forward<R>(k, pt, &z2);
            tz.add(z1 && z2 && same(c1, c2));
        }
    };
    fwd(UC<3>{});
    fwd(UC<4>{});

    uint64_t total = 0, bad = 0;
    for (auto& t : tallies)
    {
        std::printf("DIFF %-48s %12llu comparisons, %llu mismatches\n", t.name.c_str(), (unsigned long long) t.n,
                    (unsigned long long) t.bad);
        total += t.n;
        bad += t.bad;
    }
    std::printf("KEYGEN_CHOICE INV_CHAIN=V%d MAP_METHOD=M%d\n", kg::INV_CHAIN, kg::MAP_METHOD);
    std::printf("RESULT %s (%llu mismatches in %llu comparisons, log2N=%d)\n", bad ? "FAIL" : "PASS",
                (unsigned long long) bad, (unsigned long long) total, log2n);
    return bad ? 1 : 0;
}

// ---------- 组件微基准：链式调用（输出喂下一次输入），取 201 批中位数；只作参考 ----------
template <typename F> static void bench(const std::string& name, F f)
{
    constexpr int BATCH = 1000, REPS = 201;
    std::vector<double> ns, tk;
    for (int w = 0; w < 20; w++) f(); // 热身
    for (int r = 0; r < REPS; r++)
    {
        auto t0 = std::chrono::steady_clock::now();
        uint64_t c0 = __rdtsc();
        for (int i = 0; i < BATCH; i++) f();
        uint64_t c1 = __rdtsc();
        auto t1 = std::chrono::steady_clock::now();
        ns.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count() / BATCH);
        tk.push_back((double) (c1 - c0) / BATCH);
    }
    std::sort(ns.begin(), ns.end());
    std::sort(tk.begin(), tk.end());
    std::printf("BENCH %-30s median %8.1f ns  %8.1f TSC ticks per call\n", name.c_str(), ns[REPS / 2], tk[REPS / 2]);
}
static volatile uint64_t g_sink;
static e128 bx, bpt;
static uint64_t ba;
static __m128i bva, bvx;
static bool bz;

template <int V, int M> static void bench_chain()
{
    const std::string tag = "V" + std::to_string(V) + "M" + std::to_string(M) + " ";
    bench(tag + "forward R=3", [] { bx = kg::forward_v<3, V, M>(bx, bpt, &bz); });
    bench(tag + "forward R=4", [] { bx = kg::forward_v<4, V, M>(bx, bpt, &bz); });
    bench(tag + "tower inv", [] { bvx = _mm_or_si128(kg::tinv_v<V, M>(bvx), _mm_set_epi64x(0, 1)); });
}

static int run_bench()
{
    bx = re(); bpt = re(); ba = rnd() | 1; bva = v64(ba); bvx = v128(bx);
    bench("old forward R=3", [] { bx = rain::forward<3>(bx, bpt, nullptr, &bz); });
    bench("old forward R=4", [] { bx = rain::forward<4>(bx, bpt, nullptr, &bz); });
    bench("keygen choice forward R=3", [] { bx = kg::forward<3>(bx, bpt, &bz); });
    bench("keygen choice forward R=4", [] { bx = kg::forward<4>(bx, bpt, &bz); });
    bench_chain<1, 1>(); bench_chain<2, 1>(); bench_chain<4, 1>();
    bench_chain<1, 2>(); bench_chain<2, 2>(); bench_chain<4, 2>();
    bench_chain<1, 3>(); bench_chain<2, 3>(); bench_chain<4, 3>();
    bench_chain<1, 4>(); bench_chain<2, 4>(); bench_chain<4, 4>();
    bench("old tower inv", [] { bx = rain::tinv(bx); bx.lo |= 1; });
    bench("old gf64 inv", [] { ba = rain::inv64(ba) | 1; });
    bench("old linear layer 128x128", [] { bx = rain::mapply128(rain_consts::MC_T3[0], bx); bx.lo |= 1; });
    bench("M1 linear layer 128x128", [] { bvx = _mm_or_si128(kg::map128<1>(rain_consts::MC_T3[0], bvx), _mm_set_epi64x(0, 1)); });
    bench("M2 linear layer 128x128", [] { bvx = _mm_or_si128(kg::map128<2>(rain_consts::MC_T3[0], bvx), _mm_set_epi64x(0, 1)); });
    bench("M3 linear layer 128x128", [] { bvx = _mm_or_si128(kg::map128<3>(rain_consts::MC_T3[0], bvx), _mm_set_epi64x(0, 1)); });
    bench("M4 linear layer 128x128", [] { bvx = _mm_or_si128(kg::map128<4>(rain_consts::MC_T3[0], bvx), _mm_set_epi64x(0, 1)); });
    bench("old map64 SQ15", [] { ba = rain::mapply64(rain_consts::SQ15, ba) | 1; });
    bench("M1 map64 T15", [] { bva = _mm_or_si128(kg::map64<1>(kg::T15.data(), bva), _mm_set_epi64x(0, 1)); });
    bench("M2 map64 T15", [] { bva = _mm_or_si128(kg::map64<2>(kg::T15.data(), bva), _mm_set_epi64x(0, 1)); });
    bench("M3 map64 T15", [] { bva = _mm_or_si128(kg::map64<3>(kg::T15.data(), bva), _mm_set_epi64x(0, 1)); });
    bench("M4 map64 T15", [] { bva = _mm_or_si128(kg::map64<4>(kg::T15.data(), bva), _mm_set_epi64x(0, 1)); });
    bench("new 3 squarings", [] { bva = _mm_or_si128(kg::sqn<3>(bva), _mm_set_epi64x(0, 1)); });
    bench("old gf64 mul (chained)", [] { ba = rain::m64(ba, 0x9e3779b97f4a7c15ull) | 1; });
    bench("new gf64 mul (chained)", [] { bva = _mm_or_si128(kg::mul(bva, _mm_set_epi64x(0, (long long) 0x9e3779b97f4a7c15ull)), _mm_set_epi64x(0, 1)); });
    g_sink = bx.lo ^ bx.hi ^ ba ^ lo64(bva) ^ lo64(bvx) ^ (uint64_t) bz;
    return 0;
}

int main(int argc, char** argv)
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    int rc = 0;
    bool did = false;
    for (int i = 1; i < argc; i++)
    {
        std::string a = argv[i];
        if (a == "--diff")
        {
            int log2n = 20;
            if (i + 1 < argc && argv[i + 1][0] != '-') log2n = std::atoi(argv[++i]);
            if (log2n < 4 || log2n > 30) { std::printf("bad log2N\n"); return 2; }
            rc |= run_diff(log2n);
            did = true;
        }
        else if (a == "--bench") { rc |= run_bench(); did = true; }
        else { std::printf("usage: q5_kg_test [--diff [log2N]] [--bench]\n"); return 2; }
    }
    if (!did) rc = run_diff(20);
    return rc;
}
