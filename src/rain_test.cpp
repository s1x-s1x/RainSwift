// 迭代030 Q2：Rain-VOLEitH 关卡测试——KAT（公钥、见证、拒绝）、正确性、篡改、签名长度、确定性签名 KAT、初步计时
// 用法：./rain_test [--time]；在当前目录写 sig_kat.txt
#include <sys/random.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "all.inc"
#include "rain_kat.hpp"

using namespace faest;
static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { ++g_fail; std::printf("CHECK FAILED %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static void trand(uint8_t* p, size_t n) { if (getrandom(p, n, 0) != (ssize_t) n) std::abort(); }
static double now_ns() { return std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
static double median(std::vector<double> v) { std::sort(v.begin(), v.end()); return v[v.size() / 2]; }
static void hexout(FILE* f, const char* k, const uint8_t* p, size_t n)
{
    std::fprintf(f, "%s = ", k);
    for (size_t i = 0; i < n; i++) std::fprintf(f, "%02x", p[i]);
    std::fprintf(f, "\n");
}

// 与 api.hpp 的 crypto_sign_keypair 相同的建钥流程
template <typename P> static void keygen(uint8_t* pk, uint8_t* sk)
{
    if constexpr (is_owf_with_zero_sboxes(P::owf_v))
    {
        constexpr auto off = FAEST_IV_BYTES<P>;
        std::memset(sk, 0, off);
        do trand(sk + off, FAEST_SECRET_KEY_BYTES<P> - off); while (!faest_seckey<P>(sk));
        trand(sk, off);
        bool ok = faest_pubkey<P>(pk, sk);
        CHECK(ok);
    }
    else
    {
        do trand(sk, FAEST_SECRET_KEY_BYTES<P>); while (!faest_pubkey<P>(pk, sk));
    }
}

// Q1 的 KAT：公钥、VOLE 域见证、拒绝用例
template <typename P, size_t N> static void kat_check(const char* name, const rain_kat::kat (&K)[N])
{
    constexpr unsigned R = rain_rounds(P::owf_v);
    size_t ok = 0;
    for (size_t i = 0; i < N; i++)
    {
        uint8_t pk[32];
        bool r = faest_pubkey<P>(pk, K[i].sk);
        if (K[i].reject) { CHECK(!r); ok += !r; continue; }
        secret_key<P> sk;
        bool u = faest_unpack_secret_key<P>(&sk, K[i].sk);
        public_key<P> pkv;
        faest_unpack_public_key<P>(&pkv, pk);
        bool good = r && u && std::memcmp(pk, K[i].pk, 32) == 0 && std::memcmp(&sk.witness[0], K[i].wit, 16 * R) == 0
                    && std::memcmp(&pkv.input_p, &sk.pk.input_p, 16) == 0 && std::memcmp(&pkv.output_p, &sk.pk.output_p, 16) == 0;
        CHECK(good);
        ok += good;
    }
    std::printf("KAT %-12s %zu/%zu (pk, witness, reject case)\n", name, ok, N);
}

template <typename P> static void test_set(const char* name, size_t expect_sig, int n_rt, bool timing)
{
    constexpr size_t SIG = FAEST_SIGNATURE_BYTES<P>, SKB = FAEST_SECRET_KEY_BYTES<P>, PKB = FAEST_PUBLIC_KEY_BYTES<P>;
    CHECK(SIG == expect_sig);
    std::vector<uint8_t> sig(SIG), sig2(SIG), msg(1000);
    uint8_t pk[PKB], sk[SKB], pk2[PKB], sk2[SKB], seed[16];
    int rt = 0, rt_n = 0, tam = 0, tam_n = 0;
    for (int t = 0; t < n_rt; t++)
    {
        keygen<P>(pk, sk);
        size_t mlen = (size_t) (t * 37) % 1000;
        trand(msg.data(), mlen);
        trand(seed, 16);
        bool s = faest_sign<P>(sig.data(), msg.data(), mlen, sk, seed, 16);
        bool v = faest_verify<P>(sig.data(), msg.data(), mlen, pk);
        rt_n++; rt += s && v; CHECK(s && v);
        for (int f = 0; f < 24; f++)   // 篡改签名：首、尾、中间字节和 21 个伪随机位置
        {
            sig2 = sig;
            size_t pos = f == 0 ? 0 : f == 1 ? SIG - 1 : f == 2 ? SIG / 2 : (size_t) (((uint64_t) t * 1000003u + (uint64_t) f * 7919u) % SIG);
            sig2[pos] ^= (uint8_t) (1u << (f % 8));
            bool bad = faest_verify<P>(sig2.data(), msg.data(), mlen, pk);
            tam_n++; tam += !bad; CHECK(!bad);
        }
        if (mlen > 0)                  // 篡改消息
        {
            msg[mlen / 2] ^= 0x10;
            bool bad = faest_verify<P>(sig.data(), msg.data(), mlen, pk);
            msg[mlen / 2] ^= 0x10;
            tam_n++; tam += !bad; CHECK(!bad);
        }
        keygen<P>(pk2, sk2);           // 换一把公钥
        bool bad = faest_verify<P>(sig.data(), msg.data(), mlen, pk2);
        tam_n++; tam += !bad; CHECK(!bad);
    }
    std::printf("SET %-14s sig %zu B (model %zu) sk %zu B pk %zu B | roundtrip %d/%d | tamper rejected %d/%d\n",
                name, SIG, expect_sig, SKB, PKB, rt, rt_n, tam, tam_n);
    if constexpr (is_owf_rain(P::owf_v))  // 确定性签名 KAT：固定私钥、消息、种子，两次签名必须逐字节相同
    {
        uint8_t dsk[SKB], dpk[PKB], dmsg[64], dseed[16] = {0};
        std::memcpy(dsk, (rain_rounds(P::owf_v) == 3 ? rain_kat::KAT3 : rain_kat::KAT4)[0].sk, SKB);
        for (int i = 0; i < 64; i++) dmsg[i] = (uint8_t) i;
        bool okp = faest_pubkey<P>(dpk, dsk);
        bool s1 = faest_sign<P>(sig.data(), dmsg, 64, dsk, dseed, 16), s2 = faest_sign<P>(sig2.data(), dmsg, 64, dsk, dseed, 16);
        bool v1 = faest_verify<P>(sig.data(), dmsg, 64, dpk);
        CHECK(okp && s1 && s2 && v1 && sig == sig2);
        FILE* f = std::fopen("sig_kat.txt", "a");
        std::fprintf(f, "set = %s\n", name);
        hexout(f, "sk", dsk, SKB); hexout(f, "pk", dpk, PKB); hexout(f, "msg", dmsg, 64); hexout(f, "seed", dseed, 16);
        hexout(f, "sig", sig.data(), SIG);
        std::fprintf(f, "\n");
        std::fclose(f);
        std::printf("DETKAT %-11s deterministic=%d verify=%d\n", name, (int) (sig == sig2), (int) v1);
    }
    if (timing)
    {
        std::vector<double> kg, sg, vf;
        for (int i = 0; i < 2001; i++) { double t0 = now_ns(); keygen<P>(pk, sk); kg.push_back(now_ns() - t0); }
        keygen<P>(pk, sk);
        int n = SIG < 3500 ? 51 : 201;
        for (int i = 0; i < n; i++)
        {
            double t0 = now_ns(); trand(seed, 16); faest_sign<P>(sig.data(), msg.data(), 64, sk, seed, 16); sg.push_back(now_ns() - t0);
            t0 = now_ns(); bool ok = faest_verify<P>(sig.data(), msg.data(), 64, pk); vf.push_back(now_ns() - t0); CHECK(ok);
        }
        std::printf("TIME %-14s keygen %7.0f ns | sign %8.1f us | verify %8.1f us (median, single core, preliminary)\n",
                    name, median(kg), median(sg) / 1e3, median(vf) / 1e3);
    }
}

// 单独计时 owf_constraints（证明方、验证方），对照 Q0 模型「每轮约 1 万周期」
template <typename P> static void time_owf(const char* name)
{
    using CP = typename P::CONSTS;
    using OC = typename P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;
    uint8_t pkb[FAEST_PUBLIC_KEY_BYTES<P>], skb[FAEST_SECRET_KEY_BYTES<P>];
    keygen<P>(pkb, skb);
    secret_key<P> sk;
    bool u = faest_unpack_secret_key<P>(&sk, skb);
    CHECK(u);
    public_key<P> pk;
    faest_unpack_public_key<P>(&pk, pkb);
    auto* macs = (block_secpar<S>*) aligned_alloc(alignof(block_secpar<S>), CP::QUICKSILVER_ROWS_PADDED * sizeof(block_secpar<S>));
    trand((uint8_t*) macs, CP::QUICKSILVER_ROWS_PADDED * sizeof(block_secpar<S>));
    std::vector<uint8_t> wit(sizeof(sk.witness) + 256, 0);
    std::memcpy(wit.data(), &sk.witness[0], sizeof(sk.witness));
    uint8_t chal[CP::QS::CHALLENGE_BYTES];
    trand(chal, sizeof chal);
    block_secpar<S> delta;
    trand((uint8_t*) &delta, sizeof delta);
    std::vector<double> tp, tv;
    for (int i = 0; i < 2001; i++)
    {
        quicksilver_state<S, false, OC::QS_DEGREE> qs(wit.data(), macs, OC::OWF_NUM_CONSTRAINTS, chal);
        double t0 = now_ns(); owf_constraints(&qs, &sk.pk); tp.push_back(now_ns() - t0);
        quicksilver_state<S, true, OC::QS_DEGREE> qv(macs, OC::OWF_NUM_CONSTRAINTS, delta, chal);
        t0 = now_ns(); owf_constraints(&qv, &pk); tv.push_back(now_ns() - t0);
    }
    free(macs);
    std::printf("OWFPROOF %-16s prover %7.0f ns  verifier %7.0f ns (owf_constraints only, median of 2001)\n", name, median(tp), median(tv));
}

int main(int argc, char** argv)
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    bool timing = argc > 1 && std::strcmp(argv[1], "--time") == 0;
    std::remove("sig_kat.txt");
    kat_check<rain_sets::rain3_fast>("rain3_fast", rain_kat::KAT3);
    kat_check<rain_sets::rain3_bal>("rain3_bal", rain_kat::KAT3);
    kat_check<rain_sets::rain3_short>("rain3_short", rain_kat::KAT3);
    kat_check<rain_sets::rain4_fast>("rain4_fast", rain_kat::KAT4);
    kat_check<rain_sets::rain4_bal>("rain4_bal", rain_kat::KAT4);
    kat_check<rain_sets::rain4_short>("rain4_short", rain_kat::KAT4);
    test_set<rain_sets::rain3_fast>("rain3_fast", 4146, 20, timing);
    test_set<rain_sets::rain3_bal>("rain3_bal", 3706, 20, timing);
    test_set<rain_sets::rain3_short>("rain3_short", 3014, 8, timing);
    test_set<rain_sets::rain4_fast>("rain4_fast", 4112, 10, timing);
    test_set<rain_sets::rain4_bal>("rain4_bal", 4080, 10, timing);
    test_set<rain_sets::rain4_short>("rain4_short", 3190, 4, timing);
    test_set<v2::faest_em_128_f>("rFAEST_em128f", 4980, 10, timing);   // 上游参数集：确认改动没有破坏 AES 路径
    if (timing)
    {
        time_owf<rain_sets::rain3_fast>("Rain-128-3");
        time_owf<rain_sets::rain4_fast>("Rain-128-4");
        time_owf<v2::faest_em_128_f>("rFAEST-EM-128f");
    }
    std::printf("RESULT %s (%d failed checks)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
