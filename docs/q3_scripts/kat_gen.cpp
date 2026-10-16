// 迭代030 Q2：协议字节等价性核对。
// 同一份源文件分别对冻结源码（源码/rain-voleith）与 Q2 工作副本（RAIN_SHRUNK_KEYSPACE=0）编译；
// 在确定性随机源下，两者输出的私钥、公钥、见证、签名消息必须逐字节相同。
// 只调用两棵源码树都有的公开接口（api.hpp 的 crypto_sign_*、faest_unpack_secret_key）。
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C"
{
#include "randomness.h"
}
#include "all.inc"
#include "api.hpp"

using namespace faest;

static uint64_t g_state = 0;
static uint64_t splitmix64()
{
    uint64_t z = (g_state += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}
extern "C" int rand_bytes(uint8_t* dst, size_t n)
{
    for (size_t i = 0; i < n; i++) dst[i] = (uint8_t) splitmix64();
    return 0;
}
static void hexline(const char* set, int i, int j, const char* key, const uint8_t* p, size_t n)
{
    std::printf("%s %d %d %s ", set, i, j, key);
    for (size_t k = 0; k < n; k++) std::printf("%02x", p[k]);
    std::printf("\n");
}

template <typename P> static void gen(const char* name, uint64_t base)
{
    constexpr unsigned R = rain_rounds(P::owf_v);
    constexpr size_t SIG = FAEST_SIGNATURE_BYTES<P>, PKB = FAEST_PUBLIC_KEY_BYTES<P>, SKB = FAEST_SECRET_KEY_BYTES<P>;
    for (int i = 0; i < 8; i++)
    {
        g_state = base + 0x100000001ull * (uint64_t) i;
        uint8_t pk[PKB], sk[SKB];
        faest_scheme<P>::crypto_sign_keypair(pk, sk);
        secret_key<P> s;
        bool u = faest_unpack_secret_key<P>(&s, sk);
        hexline(name, i, -1, "sk", sk, SKB);
        hexline(name, i, -1, "pk", pk, PKB);
        hexline(name, i, -1, "witness", (const uint8_t*) &s.witness[0], 16 * R);
        std::printf("%s %d -1 unpack %d\n", name, i, (int) u);
        for (int j = 0; j < 3; j++)
        {
            size_t mlen = (size_t) (j * 53 + i * 7) % 120;
            std::vector<uint8_t> msg(mlen + 1), sm(mlen + SIG), m(mlen + SIG);
            for (size_t k = 0; k < mlen; k++) msg[k] = (uint8_t) splitmix64();
            unsigned long long smlen = 0, ml = 0;
            faest_scheme<P>::crypto_sign(sm.data(), &smlen, msg.data(), mlen, sk);
            int ok = faest_scheme<P>::crypto_sign_open(m.data(), &ml, sm.data(), smlen, pk) == 0;
            hexline(name, i, j, "sm", sm.data(), smlen);
            std::printf("%s %d %d open %d\n", name, i, j, ok);
        }
    }
}

int main()
{
    gen<rain_sets::rain3_fast>("rain3_fast", 0x5130000000000001ull);
    gen<rain_sets::rain3_bal>("rain3_bal", 0x5130000000000002ull);
    gen<rain_sets::rain3_short>("rain3_short", 0x5130000000000003ull);
    gen<rain_sets::rain4_fast>("rain4_fast", 0x5140000000000001ull);
    gen<rain_sets::rain4_bal>("rain4_bal", 0x5140000000000002ull);
    gen<rain_sets::rain4_short>("rain4_short", 0x5140000000000003ull);
    return 0;
}
