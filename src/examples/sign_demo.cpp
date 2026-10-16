// Rain-VOLEitH usage example: key generation, signing, verification, tamper rejection.
// Build: meson compile -C build sign_demo   Run: ./build/sign_demo [message]
//
// Pick a parameter set by changing P below:
//   rain_sets::rain3_fast  rain3_bal  rain3_short  (Rain-3, 3 rounds)
//   rain_sets::rain4_fast  rain4_bal  rain4_short  (Rain-4, 4 rounds)
// The API follows the NIST signed-message convention: sm = m || signature.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "all.inc"
#include "api.hpp"

using P = faest::rain_sets::rain3_fast;
using Scheme = faest::faest_scheme<P>;

static void print_hex(const char* label, const unsigned char* p, size_t n, size_t shown = 16)
{
    std::printf("%-10s", label);
    for (size_t i = 0; i < n && i < shown; ++i) std::printf("%02x", p[i]);
    std::printf(n > shown ? "... (%zu bytes)\n" : " (%zu bytes)\n", n);
}

int main(int argc, char** argv)
{
    const std::string text = argc > 1 ? argv[1] : "hello, Rain-VOLEitH";
    const auto* m = reinterpret_cast<const unsigned char*>(text.data());
    const unsigned long long mlen = text.size();

    std::vector<unsigned char> pk(Scheme::CRYPTO_PUBLICKEYBYTES), sk(Scheme::CRYPTO_SECRETKEYBYTES);
    if (Scheme::crypto_sign_keypair(pk.data(), sk.data()) != 0) return std::puts("keypair failed"), 1;
    print_hex("pk", pk.data(), pk.size());

    std::vector<unsigned char> sm(mlen + Scheme::CRYPTO_BYTES);
    unsigned long long smlen = 0;
    if (Scheme::crypto_sign(sm.data(), &smlen, m, mlen, sk.data()) != 0) return std::puts("sign failed"), 1;
    print_hex("signature", sm.data() + mlen, smlen - mlen);

    std::vector<unsigned char> out(smlen);
    unsigned long long outlen = 0;
    const bool ok = Scheme::crypto_sign_open(out.data(), &outlen, sm.data(), smlen, pk.data()) == 0 &&
                    outlen == mlen && std::memcmp(out.data(), m, mlen) == 0;
    std::printf("verify    %s\n", ok ? "OK" : "FAILED");

    sm[mlen + 100] ^= 1; // flip one signature bit
    const bool rejected = Scheme::crypto_sign_open(out.data(), &outlen, sm.data(), smlen, pk.data()) != 0;
    std::printf("tampered  %s\n", rejected ? "rejected (OK)" : "ACCEPTED (BUG)");
    return ok && rejected ? 0 : 1;
}
