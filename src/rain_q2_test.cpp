// 迭代030 Q2：交接 v2（Q2交接_v2_20261012.md）规定的 T1–T8、B1 开关分支、约束证明微基准。
// 用法：./rain_q2_test [--kat-dir 目录] [--quick]
//   --kat-dir：把 T7 的签名 KAT 写到该目录（每组一个文件），默认当前目录
//   --quick：T6 每组只做 100 次（只用于开发自检；Q2 验收必须用默认 1,000 次）
// 本程序自己提供 rand_bytes（系统随机 / 确定性 / 脚本三种模式），不链接 randomness_os。
// 编译时 -DRAIN_SHRUNK_KEYSPACE=1 即测试 B1=1 分支。
#include <sys/random.h>
#include <x86intrin.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C"
{
#include "randomness.h"
}
#include "all.inc"
#include "api.hpp"
#include "rain_kat.hpp"

using namespace faest;

// ---------------------------------------------------------------- 检查与输出
static int g_fail = 0, g_checks = 0;
#define CHECK(c)                                                                                   \
    do                                                                                             \
    {                                                                                              \
        ++g_checks;                                                                                \
        if (!(c))                                                                                  \
        {                                                                                          \
            ++g_fail;                                                                              \
            std::printf("CHECK FAILED %s:%d: %s\n", __FILE__, __LINE__, #c);                       \
        }                                                                                          \
    } while (0)

static std::string hex(const void* p, size_t n)
{
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    const uint8_t* b = (const uint8_t*) p;
    for (size_t i = 0; i < n; i++) { s += H[b[i] >> 4]; s += H[b[i] & 15]; }
    return s;
}
static int bit(const void* base, size_t i) { return (((const uint8_t*) base)[i / 8] >> (i % 8)) & 1; }

// ---------------------------------------------------------------- 随机源（API 层的 rand_bytes 由本程序提供）
enum class rng_mode { os, det, script };
static rng_mode g_mode = rng_mode::os;
static uint64_t g_det = 0;
static std::vector<std::vector<uint8_t>> g_script;
static size_t g_script_pos = 0, g_script_calls = 0;

static uint64_t splitmix64()
{
    uint64_t z = (g_det += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}
static void os_bytes(uint8_t* p, size_t n)
{
    size_t got = 0;
    while (got < n)
    {
        ssize_t r = getrandom(p + got, n - got, 0);
        if (r <= 0) std::abort();
        got += (size_t) r;
    }
}
extern "C" int rand_bytes(uint8_t* dst, size_t n)
{
    switch (g_mode)
    {
    case rng_mode::os: os_bytes(dst, n); return 0;
    case rng_mode::det:
        for (size_t i = 0; i < n; i++) dst[i] = (uint8_t) splitmix64();
        return 0;
    case rng_mode::script:
        g_script_calls++;
        if (g_script_pos >= g_script.size() || g_script[g_script_pos].size() != n)
        {
            std::printf("SCRIPT RNG misuse: call %zu wants %zu bytes\n", g_script_calls, n);
            std::abort();
        }
        std::memcpy(dst, g_script[g_script_pos++].data(), n);
        return 0;
    }
    return -1;
}
static void det_seed(uint64_t s) { g_mode = rng_mode::det; g_det = s; }
static void os_mode() { g_mode = rng_mode::os; }

// ---------------------------------------------------------------- 参数集元数据
template <typename P> struct meta;
#define META(NAME, R_, SIG_)                                                                       \
    template <> struct meta<rain_sets::NAME>                                                       \
    {                                                                                              \
        static constexpr const char* name = #NAME;                                                 \
        static constexpr unsigned R = R_;                                                          \
        static constexpr size_t sig = SIG_;                                                        \
    };
META(rain3_fast, 3, 4146)
META(rain3_bal, 3, 3706)
META(rain3_short, 3, 3014)
META(rain4_fast, 4, 4112)
META(rain4_bal, 4, 4080)
META(rain4_short, 4, 3190)
#undef META

static bool psi_low_bits_both_set(const uint8_t* k_tower16)
{
    uint8_t kp[16];
    rain::store(kp, rain::to_p(rain::load(k_tower16)));
    return (kp[0] & 1) && (kp[0] & 2);
}

// 构造一把“Rain 计算有效但 ψ(k) 第 0、1 位同为 1”的打包私钥（只在 B1=1 时用于 T4）
template <unsigned R> static void make_b1_violating_sk(uint8_t* sk)
{
    for (;;)
    {
        os_bytes(sk, 32);
        bool zero;
        rain::forward<R>(rain::load(sk + 16), rain::load(sk), nullptr, &zero);
        if (!zero && psi_low_bits_both_set(sk + 16)) return;
    }
}

// ================================================================= T1：尺寸
template <typename P> static void t1()
{
    using CP = typename P::CONSTS;
    constexpr unsigned R = meta<P>::R;
    static_assert(CP::VOLE_ROWS == 128 * R + 256 + 8 * CP::VOLE_HASH_B, "T1: VOLE_ROWS formula");
    static_assert(CP::VOLE_HASH_B == 6, "T1: VOLE_HASH_B frozen at 6 bytes");
    static_assert(FAEST_SIGNATURE_BYTES<P> == meta<P>::sig, "T1: signature length");
    static_assert(FAEST_PUBLIC_KEY_BYTES<P> == 32 && FAEST_SECRET_KEY_BYTES<P> == 32, "T1: key sizes");
    CHECK(CP::VOLE_ROWS == 128 * R + 256 + 8 * CP::VOLE_HASH_B);
    CHECK(FAEST_SIGNATURE_BYTES<P> == meta<P>::sig);
    std::printf("T1 %-12s VOLE_ROWS=%zu (=128*%u+256+8*%zu) SIG=%zu B (frozen %zu) pk=%zu sk=%zu OWF_NUM_CONSTRAINTS=%zu\n",
                meta<P>::name, (size_t) CP::VOLE_ROWS, R, (size_t) CP::VOLE_HASH_B, (size_t) FAEST_SIGNATURE_BYTES<P>,
                meta<P>::sig, (size_t) FAEST_PUBLIC_KEY_BYTES<P>, (size_t) FAEST_SECRET_KEY_BYTES<P>,
                (size_t) P::OWF_CONSTS::OWF_NUM_CONSTRAINTS);
}

// ================================================================= T2：签名方 V,u 与验证方重构 Q 逐行核对
template <typename P> static void t2(int reps)
{
    using CP = typename P::CONSTS;
    using OC = typename P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;
    constexpr size_t SIG = FAEST_SIGNATURE_BYTES<P>, PKB = FAEST_PUBLIC_KEY_BYTES<P>, SKB = FAEST_SECRET_KEY_BYTES<P>;
    constexpr size_t COLB = CP::VOLE_COL_BLOCKS * sizeof(vole_block);
    constexpr size_t R = meta<P>::R, WIT = 128 * R, QSR = WIT + 128, ROWS = CP::VOLE_ROWS;
    size_t bad_w = 0, bad_qs = 0, bad_vh = 0, bad_last = 0, pad_mismatch = 0, runs = 0;
    for (int rep = 0; rep < reps; rep++)
    {
        uint8_t sk[SKB], pk[PKB], msg[64], rho[16];
        faest_scheme<P>::crypto_sign_keypair(pk, sk);
        rand_bytes(msg, sizeof msg);
        rand_bytes(rho, sizeof rho);
        std::vector<uint8_t> sig(SIG);
        bool s = faest_sign<P>(sig.data(), msg, sizeof msg, sk, rho, 16);
        CHECK(s && faest_verify<P>(sig.data(), msg, sizeof msg, pk));

        secret_key<P> skx;
        uint8_t pkp[PKB];
        CHECK(faest_unpack_sk_and_get_pubkey<P>(pkp, sk, &skx));
        hash_state h;
        block_2secpar<S> mu;
        h.init(S); h.update(pk, PKB); h.update(msg, sizeof msg); h.update_byte(8 + 0); h.finalize(&mu, sizeof mu);
        uint8_t rsiv[32];
        h.init(S); h.update(&skx.sk, sizeof skx.sk); h.update(&mu, sizeof mu); h.update(rho, 16);
        h.update_byte(3); h.finalize(rsiv, 32);
        block_secpar<S> seed;
        block128 iv_pre, iv;
        std::memcpy(&seed, rsiv, 16);
        std::memcpy(&iv_pre, rsiv + 16, 16);
        h.init(S); h.update(&iv_pre, 16); h.update_byte(4); h.finalize(&iv, 16);

        auto* forest = (block_secpar<S>*) aligned_alloc(alignof(block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(block_secpar<S>));
        auto* hashed = (unsigned char*) aligned_alloc(alignof(block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
        auto* u = (vole_block*) aligned_alloc(alignof(vole_block), COLB);
        auto* v = (vole_block*) aligned_alloc(alignof(vole_block), P::secpar_bits * COLB);
        auto* q = (vole_block*) aligned_alloc(alignof(vole_block), P::secpar_bits * COLB);
        std::vector<uint8_t> com(CP::VOLE_COMMIT_SIZE);
        uint8_t hcom[CP::VOLE_COMMIT_CHECK_SIZE], hcom_v[CP::VOLE_COMMIT_CHECK_SIZE];
        vole_commit<P>(seed, iv, forest, hashed, u, v, com.data(), hcom);
        CHECK(std::memcmp(com.data(), sig.data(), CP::VOLE_COMMIT_SIZE) == 0);

        const uint8_t* sig_ut = sig.data() + CP::VOLE_COMMIT_SIZE;
        const uint8_t* sig_d = sig_ut + CP::VOLE_CHECK::PROOF_BYTES;
        const uint8_t* sig_qsp = sig_d + OC::WITNESS_BITS / 8;
        const uint8_t* sig_open = sig_qsp + CP::QS::PROOF_BYTES;
        const uint8_t* sig_delta = sig_open + P::bavc_t::OPEN_SIZE;
        const uint8_t* sig_ivpre = sig_delta + 16;
        CHECK(std::memcmp(&iv_pre, sig_ivpre, 16) == 0); // 同时佐证 T8：签名实际使用 H3(k‖μ‖ρ)

        std::array<uint8_t, P::delta_bits_v> delta_bytes;
        expand_bits_to_bytes(delta_bytes.data(), P::delta_bits_v, sig_delta);
        CHECK(vole_reconstruct<P>(iv, q, delta_bytes.data(), sig.data(), sig_open, hcom_v));
        CHECK(std::memcmp(hcom_v, hcom, sizeof hcom) == 0);
        for (size_t c = 0; c < P::secpar_bits; c++)
        {
            int dc = c < P::delta_bits_v ? bit(sig_delta, c) : 0;
            const uint8_t* qc = (const uint8_t*) q + c * COLB;
            const uint8_t* vc = (const uint8_t*) v + c * COLB;
            for (size_t r = 0; r < COLB * 8; r++)
            {
                bool ok = bit(qc, r) == (bit(vc, r) ^ (dc & bit(u, r)));
                if (r < WIT) bad_w += !ok;
                else if (r < QSR) bad_qs += !ok;
                else if (r < ROWS) bad_vh += !ok;
                else pad_mismatch += !ok;
                if (r == ROWS - 1) bad_last += !ok;
            }
        }
        free(forest); free(hashed); free(u); free(v); free(q);
        runs++;
    }
    CHECK(bad_w == 0 && bad_qs == 0 && bad_vh == 0 && bad_last == 0);
    std::printf("T2 %-12s %zu sigs | Q=V^Delta*u mismatches: witness[0,%zu)=%zu qs_mask[%zu,%zu)=%zu vhash_mask[%zu,%zu)=%zu last_row=%zu"
                " | padding rows [%zu,%zu) mismatching bits=%zu (ignored by all computations)\n",
                meta<P>::name, runs, WIT, bad_w, WIT, QSR, bad_qs, QSR, ROWS, bad_vh, bad_last, ROWS, COLB * 8, pad_mismatch);
}

// ================================================================= T3：零输入直接拒绝
template <typename P> static void t3()
{
    constexpr unsigned R = meta<P>::R;
    int rejected = 0, total = 0;
    for (int i = 0; i < 4; i++)
    {
        uint8_t sk[32], pk[32];
        os_bytes(sk, 16); // pt
        rain::e128 k = rain::load(sk);
        k.lo ^= rain::inst<R>::rc_t(0)[0];
        k.hi ^= rain::inst<R>::rc_t(0)[1];
        rain::store(sk + 16, k); // k = pt ⊕ rc_t(0)，第一轮 S 盒输入为 0
        bool r = faest_pubkey<P>(pk, sk);
        total++; rejected += !r;
        CHECK(!r);
    }
    std::printf("T3 %-12s zero first S-box input (k = pt xor rc_t(0)) rejected %d/%d\n", meta<P>::name, rejected, total);
}

// ================================================================= T4：建钥重试分支（脚本随机源）
template <typename P> static void t4()
{
    constexpr unsigned R = meta<P>::R;
    constexpr size_t SKB = FAEST_SECRET_KEY_BYTES<P>, PKB = FAEST_PUBLIC_KEY_BYTES<P>;
    std::vector<uint8_t> zero_sk(32), b1_sk(32), good_sk(32), good_pk(32);
    os_bytes(zero_sk.data(), 16);
    {
        rain::e128 k = rain::load(zero_sk.data());
        k.lo ^= rain::inst<R>::rc_t(0)[0];
        k.hi ^= rain::inst<R>::rc_t(0)[1];
        rain::store(zero_sk.data() + 16, k);
    }
    do os_bytes(good_sk.data(), 32); while (!faest_pubkey<P>(good_pk.data(), good_sk.data()));
    g_script.clear();
    g_script.push_back(zero_sk);
#if RAIN_SHRUNK_KEYSPACE
    make_b1_violating_sk<R>(b1_sk.data());
    g_script.push_back(b1_sk);
#else
    (void) b1_sk;
#endif
    g_script.push_back(good_sk);
    g_script_pos = 0; g_script_calls = 0;
    g_mode = rng_mode::script;
    uint8_t pk[PKB], sk[SKB];
    faest_scheme<P>::crypto_sign_keypair(pk, sk);
    os_mode();
    bool ok = std::memcmp(sk, good_sk.data(), SKB) == 0 && std::memcmp(pk, good_pk.data(), PKB) == 0 &&
              g_script_pos == g_script.size();
    CHECK(ok);
    std::vector<uint8_t> sm(FAEST_SIGNATURE_BYTES<P> + 32), m(32);
    unsigned long long smlen = 0, mlen = 0;
    uint8_t msg[32];
    os_bytes(msg, 32);
    faest_scheme<P>::crypto_sign(sm.data(), &smlen, msg, 32, sk);
    bool v = faest_scheme<P>::crypto_sign_open(m.data(), &mlen, sm.data(), smlen, pk) == 0;
    CHECK(v);
    std::printf("T4 %-12s keygen retry: script of %zu candidates consumed, returned sk = last candidate: %d, sign/verify: %d\n",
                meta<P>::name, g_script.size(), (int) ok, (int) v);
}

// ================================================================= T5：篡改
template <typename P, typename OTHER> static void t5()
{
    constexpr size_t SIG = FAEST_SIGNATURE_BYTES<P>, PKB = FAEST_PUBLIC_KEY_BYTES<P>, SKB = FAEST_SECRET_KEY_BYTES<P>;
    constexpr size_t MLEN = 64;
    uint8_t pk[PKB], sk[SKB], pk2[PKB], sk2[SKB], msg[MLEN];
    faest_scheme<P>::crypto_sign_keypair(pk, sk);
    faest_scheme<P>::crypto_sign_keypair(pk2, sk2);
    os_bytes(msg, MLEN);
    std::vector<uint8_t> sm(MLEN + SIG + 1), m(MLEN + SIG + 1);
    unsigned long long smlen = 0, mlen = 0;
    faest_scheme<P>::crypto_sign(sm.data(), &smlen, msg, MLEN, sk);
    CHECK(smlen == MLEN + SIG);
    CHECK(faest_scheme<P>::crypto_sign_open(m.data(), &mlen, sm.data(), smlen, pk) == 0 && mlen == MLEN);
    size_t accepted_flips = 0, flips = 0;
    std::vector<size_t> bad_pos;
    for (size_t i = 0; i < SIG; i++)
        for (uint8_t mask : {(uint8_t) 0x01, (uint8_t) 0x80})
        {
            sm[MLEN + i] ^= mask;
            bool acc = faest_scheme<P>::crypto_sign_open(m.data(), &mlen, sm.data(), smlen, pk) == 0;
            sm[MLEN + i] ^= mask;
            flips++;
            if (acc) { accepted_flips++; if (bad_pos.size() < 16) bad_pos.push_back(i); }
        }
    CHECK(accepted_flips == 0);
    bool trunc = faest_scheme<P>::crypto_sign_open(m.data(), &mlen, sm.data(), smlen - 1, pk) != 0;
    sm[smlen] = 0x5a;
    bool extend = faest_scheme<P>::crypto_sign_open(m.data(), &mlen, sm.data(), smlen + 1, pk) != 0;
    sm[MLEN / 2] ^= 0x10;
    bool chmsg = faest_scheme<P>::crypto_sign_open(m.data(), &mlen, sm.data(), smlen, pk) != 0;
    sm[MLEN / 2] ^= 0x10;
    bool chpk = faest_scheme<P>::crypto_sign_open(m.data(), &mlen, sm.data(), smlen, pk2) != 0;
    // 换参数集：另签一条 512 字节消息（保证长度足够另一组参数解析），交给另一组参数及其公钥、以及本组公钥去验
    constexpr size_t MLEN2 = 512;
    static_assert(MLEN2 + SIG >= FAEST_SIGNATURE_BYTES<OTHER>, "cross-set check needs enough bytes");
    uint8_t opk[FAEST_PUBLIC_KEY_BYTES<OTHER>], osk[FAEST_SECRET_KEY_BYTES<OTHER>], msg2[MLEN2];
    faest_scheme<OTHER>::crypto_sign_keypair(opk, osk);
    os_bytes(msg2, MLEN2);
    std::vector<uint8_t> sm3(MLEN2 + SIG), om(MLEN2 + SIG);
    unsigned long long smlen3 = 0, omlen = 0;
    faest_scheme<P>::crypto_sign(sm3.data(), &smlen3, msg2, MLEN2, sk);
    bool own = faest_scheme<P>::crypto_sign_open(om.data(), &omlen, sm3.data(), smlen3, pk) == 0;
    bool chset = own && faest_scheme<OTHER>::crypto_sign_open(om.data(), &omlen, sm3.data(), smlen3, opk) != 0 &&
                 faest_scheme<OTHER>::crypto_sign_open(om.data(), &omlen, sm3.data(), smlen3, pk) != 0;
    CHECK(trunc && extend && chmsg && chpk && chset);
    std::printf("T5 %-12s byte flips (0x01,0x80 at all %zu bytes): accepted %zu/%zu | truncate-1 rejected %d | extend+1 rejected %d"
                " | other msg %d | other pk %d | other set (%s) %d\n",
                meta<P>::name, SIG, accepted_flips, flips, (int) trunc, (int) extend, (int) chmsg, (int) chpk,
                meta<OTHER>::name, (int) chset);
    for (size_t p : bad_pos) std::printf("T5 %-12s ACCEPTED FLIP at signature byte %zu (report to Q4, do not change expectation)\n", meta<P>::name, p);
}

// ================================================================= T6：闭环
template <typename P> static void t6(int n)
{
    constexpr size_t SIG = FAEST_SIGNATURE_BYTES<P>, PKB = FAEST_PUBLIC_KEY_BYTES<P>, SKB = FAEST_SECRET_KEY_BYTES<P>;
    int ok = 0, diff = 0, diff_n = 0;
    std::vector<uint8_t> msg(200), sm(200 + SIG), sm2(200 + SIG), m(200 + SIG);
    for (int t = 0; t < n; t++)
    {
        uint8_t pk[PKB], sk[SKB];
        faest_scheme<P>::crypto_sign_keypair(pk, sk);
        size_t mlen = (size_t) (t * 37) % 200;
        os_bytes(msg.data(), mlen);
        unsigned long long smlen = 0, smlen2 = 0, ml = 0;
        faest_scheme<P>::crypto_sign(sm.data(), &smlen, msg.data(), mlen, sk);
        bool v = faest_scheme<P>::crypto_sign_open(m.data(), &ml, sm.data(), smlen, pk) == 0 && ml == mlen &&
                 std::memcmp(m.data(), msg.data(), mlen) == 0;
        ok += v;
        CHECK(v);
        if (t < 50) // 同一消息签两次：签名随机化，两次结果必须不同，且都能验过
        {
            faest_scheme<P>::crypto_sign(sm2.data(), &smlen2, msg.data(), mlen, sk);
            bool d = smlen2 == smlen && std::memcmp(sm.data(), sm2.data(), smlen) != 0 &&
                     faest_scheme<P>::crypto_sign_open(m.data(), &ml, sm2.data(), smlen2, pk) == 0;
            diff_n++; diff += d;
            CHECK(d);
        }
    }
    std::printf("T6 %-12s roundtrip %d/%d | same message signed twice -> different valid signatures %d/%d\n",
                meta<P>::name, ok, n, diff, diff_n);
}

// ================================================================= T7：KAT
template <typename P, size_t N> static void t7_q1(const rain_kat::kat (&K)[N])
{
    constexpr unsigned R = meta<P>::R;
    size_t ok = 0, b1_rejects = 0;
    for (size_t i = 0; i < N; i++)
    {
        uint8_t pk[32];
        bool r = faest_pubkey<P>(pk, K[i].sk);
        bool expect_reject = K[i].reject;
#if RAIN_SHRUNK_KEYSPACE
        if (!expect_reject && psi_low_bits_both_set(K[i].sk + 16)) { expect_reject = true; b1_rejects++; }
#endif
        if (expect_reject) { CHECK(!r); ok += !r; continue; }
        secret_key<P> sk;
        bool u = faest_unpack_secret_key<P>(&sk, K[i].sk);
        bool good = r && u && std::memcmp(pk, K[i].pk, 32) == 0 && std::memcmp(&sk.witness[0], K[i].wit, 16 * R) == 0;
        CHECK(good);
        ok += good;
    }
    std::printf("T7 %-12s Q1 Rain KAT (pk, witness, reject case) %zu/%zu%s\n", meta<P>::name, ok, N,
                RAIN_SHRUNK_KEYSPACE ? (" [B1=1: " + std::to_string(b1_rejects) + " KAT keys outside the shrunk key space, expected rejected]").c_str() : "");
}

template <typename P> static void t7_sig(const std::string& dir, uint64_t seed)
{
    constexpr size_t SIG = FAEST_SIGNATURE_BYTES<P>, PKB = FAEST_PUBLIC_KEY_BYTES<P>, SKB = FAEST_SECRET_KEY_BYTES<P>;
    det_seed(seed);
    uint8_t pk[PKB], sk[SKB], msg[64];
    faest_scheme<P>::crypto_sign_keypair(pk, sk);
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t) i;
    std::vector<uint8_t> sm(64 + SIG), sm2(64 + SIG), m(64 + SIG);
    unsigned long long smlen = 0, smlen2 = 0, ml = 0;
    faest_scheme<P>::crypto_sign(sm.data(), &smlen, msg, 64, sk);
    det_seed(seed);
    uint8_t pk2[PKB], sk2[SKB];
    faest_scheme<P>::crypto_sign_keypair(pk2, sk2);
    faest_scheme<P>::crypto_sign(sm2.data(), &smlen2, msg, 64, sk2);
    os_mode();
    bool same = smlen == smlen2 && std::memcmp(sm.data(), sm2.data(), smlen) == 0 && std::memcmp(pk, pk2, PKB) == 0;
    bool v = faest_scheme<P>::crypto_sign_open(m.data(), &ml, sm.data(), smlen, pk) == 0;
    CHECK(same && v);
    std::string path = dir + "/sigkat_" + meta<P>::name + (RAIN_SHRUNK_KEYSPACE ? "_b1" : "") + ".txt";
    FILE* f = std::fopen(path.c_str(), "w");
    CHECK(f != nullptr);
    if (f)
    {
        std::fprintf(f, "# iter030 Q2 T7 signature KAT, set=%s, B1=%d, det_seed=0x%016llx (splitmix64 rand_bytes)\n",
                     meta<P>::name, RAIN_SHRUNK_KEYSPACE, (unsigned long long) seed);
        std::fprintf(f, "sk = %s\npk = %s\nmsg = %s\nsm = %s\n", hex(sk, SKB).c_str(), hex(pk, PKB).c_str(),
                     hex(msg, 64).c_str(), hex(sm.data(), smlen).c_str());
        std::fclose(f);
    }
    std::printf("T7 %-12s signature KAT written to %s (reproducible=%d, verifies=%d)\n", meta<P>::name, path.c_str(), (int) same, (int) v);
}

// ================================================================= T8：H3 输入
template <typename P> static void t8()
{
    constexpr auto S = P::secpar_v;
    constexpr size_t PKB = FAEST_PUBLIC_KEY_BYTES<P>, SKB = FAEST_SECRET_KEY_BYTES<P>;
    uint8_t sk1[SKB], sk2[SKB], pk1[PKB], pk2[PKB];
    do os_bytes(sk1, SKB); while (!faest_pubkey<P>(pk1, sk1));
    do { std::memcpy(sk2, sk1, 16); os_bytes(sk2 + 16, 16); } while (!faest_pubkey<P>(pk2, sk2)); // 同一 pt，不同 k
    secret_key<P> a, b;
    uint8_t tmp[PKB];
    CHECK(faest_unpack_sk_and_get_pubkey<P>(tmp, sk1, &a) && faest_unpack_sk_and_get_pubkey<P>(tmp, sk2, &b));
    bool absorbs_k = std::memcmp(&a.sk, sk1 + 16, 16) == 0 && std::memcmp(&a.sk, sk1, 16) != 0; // sk.sk 是 k，不是 pt
    block_2secpar<S> mu;
    uint8_t rho[16];
    os_bytes((uint8_t*) &mu, sizeof mu);
    os_bytes(rho, 16);
    uint8_t ra[32], rb[32];
    hash_state h;
    h.init(S); h.update(&a.sk, sizeof a.sk); h.update(&mu, sizeof mu); h.update(rho, 16); h.update_byte(3); h.finalize(ra, 32);
    h.init(S); h.update(&b.sk, sizeof b.sk); h.update(&mu, sizeof mu); h.update(rho, 16); h.update_byte(3); h.finalize(rb, 32);
    bool differ = std::memcmp(ra, rb, 16) != 0 && std::memcmp(ra + 16, rb + 16, 16) != 0;
    CHECK(absorbs_k && differ);
    std::printf("T8 %-12s same pt, different k, same mu and rho -> (r, iv_pre) differ: %d | unpacked sk.sk == packed k (bytes 16..32), != pt: %d\n",
                meta<P>::name, (int) differ, (int) absorbs_k);
}

// ================================================================= 约束证明微基准
template <typename P> static void bench_owf()
{
    using CP = typename P::CONSTS;
    using OC = typename P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;
    constexpr unsigned R = meta<P>::R;
    uint8_t pkb[FAEST_PUBLIC_KEY_BYTES<P>], skb[FAEST_SECRET_KEY_BYTES<P>];
    faest_scheme<P>::crypto_sign_keypair(pkb, skb);
    secret_key<P> sk;
    CHECK(faest_unpack_secret_key<P>(&sk, skb));
    public_key<P> pk;
    faest_unpack_public_key<P>(&pk, pkb);
    auto* macs = (block_secpar<S>*) aligned_alloc(alignof(block_secpar<S>), CP::QUICKSILVER_ROWS_PADDED * sizeof(block_secpar<S>));
    os_bytes((uint8_t*) macs, CP::QUICKSILVER_ROWS_PADDED * sizeof(block_secpar<S>));
    std::vector<uint8_t> wit(sizeof(sk.witness) + 256, 0);
    std::memcpy(wit.data(), &sk.witness[0], sizeof(sk.witness));
    uint8_t chal[CP::QS::CHALLENGE_BYTES];
    os_bytes(chal, sizeof chal);
    block_secpar<S> delta;
    os_bytes((uint8_t*) &delta, sizeof delta);
    std::vector<double> tp, tv;
    std::vector<unsigned long long> cp, cv;
    for (int i = 0; i < 2001; i++)
    {
        quicksilver_state<S, false, OC::QS_DEGREE> qs(wit.data(), macs, OC::OWF_NUM_CONSTRAINTS, chal);
        auto t0 = std::chrono::steady_clock::now();
        unsigned long long c0 = __rdtsc();
        owf_constraints(&qs, &sk.pk);
        unsigned long long c1 = __rdtsc();
        auto t1 = std::chrono::steady_clock::now();
        tp.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count());
        cp.push_back(c1 - c0);
        quicksilver_state<S, true, OC::QS_DEGREE> qv(macs, OC::OWF_NUM_CONSTRAINTS, delta, chal);
        t0 = std::chrono::steady_clock::now();
        c0 = __rdtsc();
        owf_constraints(&qv, &pk);
        c1 = __rdtsc();
        t1 = std::chrono::steady_clock::now();
        tv.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count());
        cv.push_back(c1 - c0);
    }
    free(macs);
    auto med = [](auto v) { std::sort(v.begin(), v.end()); return v[v.size() / 2]; };
    double mp = med(tp), mv = med(tv);
    unsigned long long kp = med(cp), kv = med(cv);
    std::printf("BENCH %-12s owf_constraints only, median of 2001: prover %.0f ns / %llu TSC ticks (%.0f per round)"
                " | verifier %.0f ns / %llu TSC ticks (%.0f per round) | model: ~10000 cycles per round"
                " (TSC ticks are not core cycles when frequency scaling is active)\n",
                meta<P>::name, mp, kp, (double) kp / R, mv, kv, (double) kv / R);
}

// ================================================================= 主程序
template <typename P, typename OTHER, size_t N>
static void run_set(const rain_kat::kat (&K)[N], const std::string& kat_dir, int t6n, uint64_t kat_seed)
{
    os_mode();
    t1<P>();
    t2<P>(3);
    t3<P>();
    t4<P>();
    t5<P, OTHER>();
    t6<P>(t6n);
    t7_q1<P>(K);
    t7_sig<P>(kat_dir, kat_seed);
    t8<P>();
    bench_owf<P>();
}

int main(int argc, char** argv)
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    std::string kat_dir = ".";
    int t6n = 1000;
    for (int i = 1; i < argc; i++)
    {
        if (!std::strcmp(argv[i], "--kat-dir") && i + 1 < argc) kat_dir = argv[++i];
        else if (!std::strcmp(argv[i], "--quick")) t6n = 100;
    }
    std::printf("rain_q2_test: B1 (RAIN_SHRUNK_KEYSPACE) = %d, T6 roundtrips per set = %d\n", RAIN_SHRUNK_KEYSPACE, t6n);
    run_set<rain_sets::rain3_fast, rain_sets::rain3_bal>(rain_kat::KAT3, kat_dir, t6n, 0x0300000000000021ull);
    run_set<rain_sets::rain3_bal, rain_sets::rain3_short>(rain_kat::KAT3, kat_dir, t6n, 0x0300000000000017ull);
    run_set<rain_sets::rain3_short, rain_sets::rain4_short>(rain_kat::KAT3, kat_dir, t6n, 0x0300000000000011ull);
    run_set<rain_sets::rain4_fast, rain_sets::rain4_bal>(rain_kat::KAT4, kat_dir, t6n, 0x0400000000000018ull);
    run_set<rain_sets::rain4_bal, rain_sets::rain3_fast>(rain_kat::KAT4, kat_dir, t6n, 0x0400000000000188ull);
    run_set<rain_sets::rain4_short, rain_sets::rain3_short>(rain_kat::KAT4, kat_dir, t6n, 0x0400000000000011ull);
    std::printf("RESULT %s (%d failed of %d checks, T6=%d per set%s)\n", g_fail ? "FAIL" : "PASS", g_fail, g_checks, t6n,
                t6n < 1000 ? ", QUICK MODE - not valid for Q2 acceptance" : "");
    return g_fail ? 1 : 0;
}
