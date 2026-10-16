// Quick benchmark of the complete public API (keypair / randomized sign / open) for the six Rain sets
// and the rFAEST-EM-128f/s parameter sets compiled from the same source tree.
// Build: meson compile -C build rain_bench
// Run:   taskset -c 2 ./build/rain_bench [samples]      (default 201 samples after 32 warmups)
//
// This is a convenience tool, not the formal Q3 protocol (docs/Q3_benchmark_report.md): Q3 used an
// unmodified upstream rFAEST tree, library-instantiated Rain sets, three CPUs and three windows.
// Numbers depend on the machine; compare ratios measured in the same run only.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "all.inc"
#include "api.hpp"

using namespace faest;

struct result
{
    const char* name;
    double kg_us, sign_ms, verify_ms;
    unsigned long long sig_bytes;
};

static double now_ns()
{
    return std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

static double median(std::vector<double> v)
{
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

template <typename P> static result run(const char* name, int samples)
{
    using S = faest_scheme<P>;
    std::vector<unsigned char> pk(S::CRYPTO_PUBLICKEYBYTES), sk(S::CRYPTO_SECRETKEYBYTES);
    std::vector<unsigned char> m(64), sm(64 + S::CRYPTO_BYTES), out(64 + S::CRYPTO_BYTES);
    std::vector<double> kg, sg, vf;
    for (int i = 0; i < 32 + samples; ++i)
    {
        for (size_t j = 0; j < m.size(); ++j) m[j] = (unsigned char) (i * 31 + j);
        unsigned long long smlen = 0, outlen = 0;
        double t0 = now_ns();
        S::crypto_sign_keypair(pk.data(), sk.data());
        double t1 = now_ns();
        S::crypto_sign(sm.data(), &smlen, m.data(), m.size(), sk.data());
        double t2 = now_ns();
        int rc = S::crypto_sign_open(out.data(), &outlen, sm.data(), smlen, pk.data());
        double t3 = now_ns();
        if (rc != 0 || outlen != m.size() || std::memcmp(out.data(), m.data(), m.size()) != 0)
        {
            std::printf("%s: verification failed at sample %d\n", name, i);
            std::exit(1);
        }
        if (i >= 32)
        {
            kg.push_back(t1 - t0);
            sg.push_back(t2 - t1);
            vf.push_back(t3 - t2);
        }
    }
    result r{name, median(kg) / 1e3, median(sg) / 1e6, median(vf) / 1e6, S::CRYPTO_BYTES};
    std::printf("%-16s %10.3f %10.4f %10.4f %8llu\n", r.name, r.kg_us, r.sign_ms, r.verify_ms, r.sig_bytes);
    return r;
}

static void ratio(const result& a, const result& ref)
{
    std::printf("%-12s vs %-14s sign %.2fx faster, verify %.2fx faster, keygen time x%.2f, signature %+lld B\n",
                a.name, ref.name, ref.sign_ms / a.sign_ms, ref.verify_ms / a.verify_ms, a.kg_us / ref.kg_us,
                (long long) a.sig_bytes - (long long) ref.sig_bytes);
}

int main(int argc, char** argv)
{
    static_assert(faest_scheme<v2::faest_em_128_f>::CRYPTO_BYTES == 4980, "rFAEST-EM-128f size");
    static_assert(faest_scheme<v2::faest_em_128_s>::CRYPTO_BYTES == 4014, "rFAEST-EM-128s size");
    const int samples = argc > 1 ? std::max(1, std::atoi(argv[1])) : 201;
    std::printf("median of %d samples (after 32 warmups), 64-byte messages\n", samples);
    std::printf("%-16s %10s %10s %10s %8s\n", "scheme", "keygen/us", "sign/ms", "verify/ms", "sig/B");
    const result f = run<v2::faest_em_128_f>("rFAEST-EM-128f", samples);
    const result r3f = run<rain_sets::rain3_fast>("Rain3-fast", samples);
    const result r3b = run<rain_sets::rain3_bal>("Rain3-bal", samples);
    const result r4f = run<rain_sets::rain4_fast>("Rain4-fast", samples);
    const result r4b = run<rain_sets::rain4_bal>("Rain4-bal", samples);
    const result s = run<v2::faest_em_128_s>("rFAEST-EM-128s", samples);
    const result r3s = run<rain_sets::rain3_short>("Rain3-short", samples);
    const result r4s = run<rain_sets::rain4_short>("Rain4-short", samples);
    std::printf("\n");
    for (const result* r : {&r3f, &r3b, &r4f, &r4b}) ratio(*r, f);
    for (const result* r : {&r3s, &r4s}) ratio(*r, s);
    return 0;
}
