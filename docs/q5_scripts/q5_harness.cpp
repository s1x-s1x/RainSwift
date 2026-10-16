// P0: complete randomized public APIs; no secret material is written to logs.
// Compile separately against each fixed source tree; P0_BASELINE_ID selects it.
// 迭代030 Q5：与 Q3 的 q3_harness.cpp 相同，只把宏名改为 Q5_*、Rain 来源标识改为 Q5kg（Q3 版由 P0 的 baseline_harness.cpp 扩展）。
// 迭代030 Q3：由 P0 的 baseline_harness.cpp（迭代028 linkfix_v3，sha256 b4a84fa9…）扩展。
// 计时、校验与输出代码不变；只把实现表从 3 项扩到 11 项（编号 1–3 与 P0 相同），宏名改为 Q5_IMPL_ID，
// 并在 metadata 行加 impl_id。Rain 六组用 Q2 工作副本（B1=0），经库内显式实例化后与对照一样只经 api.hpp 调用。
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "api.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <optional>
#include <sched.h>
#include <string>
#include <sys/resource.h>
#include <time.h>
#include <vector>

#define Q5_RAIN_SOURCE "7a59c5c18b199bae427bd71d3b9fb5ea3f3b6d97+iter030-RAIN_PATCHES+Q5kg(B1=0)"
#if Q5_IMPL_ID == 1
using P = faest::v3::faest_em_128_f;
static constexpr const char* algorithm = "FAEST-v3-EM-128f-opt";
static constexpr const char* source_commit = "1d8330979cb467c54edac43ffe695da249fa3417";
static constexpr std::size_t expected_signature_bytes = 4170;
#elif Q5_IMPL_ID == 2
using P = faest::v2::faest_em_128_f;
static constexpr const char* algorithm = "rFAEST-EM-128f";
static constexpr const char* source_commit = "7a59c5c18b199bae427bd71d3b9fb5ea3f3b6d97";
static constexpr std::size_t expected_signature_bytes = 4980;
#elif Q5_IMPL_ID == 3
using P = faest::lynx::lynx_128_f;
static constexpr const char* algorithm = "Lynxer-128f-opt";
static constexpr const char* source_commit = "3fd635a52bf26d9159a2d53e0e7246b42accf800";
static constexpr std::size_t expected_signature_bytes = 3652;
#elif Q5_IMPL_ID == 4
using P = faest::v2::faest_em_128_s;
static constexpr const char* algorithm = "rFAEST-EM-128s";
static constexpr const char* source_commit = "7a59c5c18b199bae427bd71d3b9fb5ea3f3b6d97";
static constexpr std::size_t expected_signature_bytes = 4014;
#elif Q5_IMPL_ID == 5
using P = faest::v3::faest_em_128_s;
static constexpr const char* algorithm = "FAEST-v3-EM-128s-opt";
static constexpr const char* source_commit = "1d8330979cb467c54edac43ffe695da249fa3417";
static constexpr std::size_t expected_signature_bytes = 3466;
#elif Q5_IMPL_ID == 6
using P = faest::rain_sets::rain3_fast;
static constexpr const char* algorithm = "C030-Rain3-fast";
static constexpr const char* source_commit = Q5_RAIN_SOURCE;
static constexpr std::size_t expected_signature_bytes = 4146;
#elif Q5_IMPL_ID == 7
using P = faest::rain_sets::rain3_bal;
static constexpr const char* algorithm = "C030-Rain3-bal";
static constexpr const char* source_commit = Q5_RAIN_SOURCE;
static constexpr std::size_t expected_signature_bytes = 3706;
#elif Q5_IMPL_ID == 8
using P = faest::rain_sets::rain3_short;
static constexpr const char* algorithm = "C030-Rain3-short";
static constexpr const char* source_commit = Q5_RAIN_SOURCE;
static constexpr std::size_t expected_signature_bytes = 3014;
#elif Q5_IMPL_ID == 9
using P = faest::rain_sets::rain4_fast;
static constexpr const char* algorithm = "C030-Rain4-fast";
static constexpr const char* source_commit = Q5_RAIN_SOURCE;
static constexpr std::size_t expected_signature_bytes = 4112;
#elif Q5_IMPL_ID == 10
using P = faest::rain_sets::rain4_bal;
static constexpr const char* algorithm = "C030-Rain4-bal";
static constexpr const char* source_commit = Q5_RAIN_SOURCE;
static constexpr std::size_t expected_signature_bytes = 4080;
#elif Q5_IMPL_ID == 11
using P = faest::rain_sets::rain4_short;
static constexpr const char* algorithm = "C030-Rain4-short";
static constexpr const char* source_commit = Q5_RAIN_SOURCE;
static constexpr std::size_t expected_signature_bytes = 3190;
#else
#error "Q5_IMPL_ID must be 1 through 11"
#endif
static constexpr int impl_id = Q5_IMPL_ID;
using Scheme = faest::faest_scheme<P>;
static_assert(Scheme::CRYPTO_BYTES == expected_signature_bytes, "parameter/format drift");
static constexpr std::size_t message_bytes = 64;

static volatile std::uint64_t rng_calls = 0;
static volatile std::uint64_t rng_bytes = 0;
static const char* current_api = "initialization";
static unsigned current_index = 0;
static bool current_warmup = false;

[[noreturn]] static void fail(const char* reason, int code = 70) {
    std::printf("{\"kind\":\"fatal\",\"algorithm\":\"%s\",\"reason\":\"%s\","
                "\"api\":\"%s\",\"sample_index\":%u,\"warmup\":%s}\n",
                algorithm, reason, current_api, current_index, current_warmup ? "true" : "false");
    std::fflush(stdout);
    std::_Exit(code);
}

// The unchanged upstream OS CSPRNG body has a TU-local symbol rename. Its error
// is checked by this out-of-line source wrapper; the check and counters are timed.
extern "C" int p0_upstream_rand_bytes(std::uint8_t*, std::size_t);
extern "C" __attribute__((noinline)) int rand_bytes(std::uint8_t* dst, std::size_t size) {
    rng_calls = rng_calls + 1;
    rng_bytes = rng_bytes + size;
    const int rc = p0_upstream_rand_bytes(dst, size);
    if (rc != 0) fail("upstream OS random source failed");
    return rc;
}

static std::uint64_t now_ns() {
    timespec t{};
    std::atomic_signal_fence(std::memory_order_seq_cst);
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t) != 0) fail("clock_gettime failed");
    std::atomic_signal_fence(std::memory_order_seq_cst);
    return std::uint64_t(t.tv_sec) * 1000000000ULL + std::uint64_t(t.tv_nsec);
}

struct Options {
    unsigned samples = 501, warmup = 32, batch = 0, round = 0, chunk = 0, offset = 0;
    bool validate_only = false;
};

static unsigned number(const char* text) {
    if (!text[0] || text[0] == '-') fail("invalid unsigned option", 64);
    errno = 0;
    char* end = nullptr;
    const auto value = std::strtoull(text, &end, 10);
    if (errno || *end || value > 1000000) fail("option out of range", 64);
    return static_cast<unsigned>(value);
}

static Options options(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::string key = argv[i];
        if (key == "--validate-only") { o.validate_only = true; continue; }
        if (key == "--help") {
            std::puts("--samples N --warmup N --batch N --round N --chunk N --sample-offset N [--validate-only]");
            std::exit(0);
        }
        if (i + 1 == argc) fail("missing option value", 64);
        const unsigned value = number(argv[++i]);
        if (key == "--samples") o.samples = value;
        else if (key == "--warmup") o.warmup = value;
        else if (key == "--batch") o.batch = value;
        else if (key == "--round") o.round = value;
        else if (key == "--chunk") o.chunk = value;
        else if (key == "--sample-offset") o.offset = value;
        else fail("unknown option", 64);
    }
    if (!o.validate_only && (!o.samples || o.warmup < 32))
        fail("timing requires positive samples and at least 32 warmups", 64);
    return o;
}

static int pinned_cpu() {
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof(set), &set) != 0) fail("sched_getaffinity failed");
    if (CPU_COUNT(&set) != 1) fail("exactly one logical CPU must be selected with taskset", 64);
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) if (CPU_ISSET(cpu, &set)) return cpu;
    fail("empty affinity");
}

using PublicKey = std::array<unsigned char, Scheme::CRYPTO_PUBLICKEYBYTES>;
using SecretKey = std::array<unsigned char, Scheme::CRYPTO_SECRETKEYBYTES>;
using Message = std::array<unsigned char, message_bytes>;
using SignedMessage = std::array<unsigned char, Scheme::CRYPTO_BYTES + message_bytes>;

static Message public_message(unsigned batch, unsigned index) {
    Message m{};
    // Public deterministic messages only; never used as key or signing randomness.
    std::uint64_t x = 0xa65a9128e371f042ULL ^ (std::uint64_t(batch) << 32) ^ index;
    for (auto& byte : m) {
        x += 0x9e3779b97f4a7c15ULL;
        auto z = x;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        byte = static_cast<unsigned char>(z ^ (z >> 31));
    }
    return m;
}

static void validate() {
    current_api = "untimed_validation";
    PublicKey pk{};
    SecretKey sk{};
    const Message message = public_message(0, 0);
    Message recovered{};
    SignedMessage sm{}, sm2{}, bad{};
    unsigned long long length = 0, second_length = 0, recovered_length = 0;
    if (Scheme::crypto_sign_keypair(pk.data(), sk.data()) != 0) fail("validation keypair failed");
    auto before = rng_calls;
    if (Scheme::crypto_sign(sm.data(), &length, message.data(), message.size(), sk.data()) != 0 ||
        length != sm.size() || rng_calls == before) fail("validation randomized sign failed");
    if (Scheme::crypto_sign_open(recovered.data(), &recovered_length, sm.data(), length, pk.data()) != 0 ||
        recovered_length != message.size() || recovered != message) fail("validation roundtrip failed");
    if (Scheme::crypto_sign(sm2.data(), &second_length, message.data(), message.size(), sk.data()) != 0 ||
        second_length != sm2.size() || sm == sm2) fail("randomized signatures did not differ");
    if (Scheme::crypto_sign_open(recovered.data(), &recovered_length, sm2.data(), second_length, pk.data()) != 0 ||
        recovered_length != message.size() || recovered != message) fail("second roundtrip failed");
    const std::array<std::size_t, 4> positions = {0, message_bytes,
        message_bytes + Scheme::CRYPTO_BYTES / 2, sm.size() - 1};
    for (auto position : positions) {
        bad = sm;
        bad[position] ^= 1;
        recovered_length = 0;
        if (Scheme::crypto_sign_open(recovered.data(), &recovered_length, bad.data(), length, pk.data()) == 0)
            fail("tampered message or signature accepted");
    }
    auto bad_pk = pk;
    bad_pk[0] ^= 1;
    if (Scheme::crypto_sign_open(recovered.data(), &recovered_length, sm.data(), length, bad_pk.data()) == 0)
        fail("modified public key accepted");
    std::printf("{\"kind\":\"validation\",\"algorithm\":\"%s\",\"passed\":true,"
                "\"roundtrips\":2,\"distinct_randomized_signatures\":true,\"tamper_rejections\":5,"
                "\"scope\":\"public API smoke checks; not a known-answer test or security proof\"}\n", algorithm);
}

template<class T> static std::string optional_json(const std::optional<T>& x) {
    return x ? std::to_string(*x) : "null";
}
struct Record {
    std::optional<std::uint64_t> kg_ns, sign_ns, verify_ns, signature_bytes;
    std::optional<int> kg_rc, sign_rc, verify_rc;
    std::uint64_t kg_rng_calls = 0, sign_rng_calls = 0, verify_rng_calls = 0;
    bool valid = false;
};
static void print_record(const Options& o, const Record& r) {
    std::printf("{\"kind\":\"sample\",\"algorithm\":\"%s\",\"batch\":%u,\"round\":%u,"
                "\"chunk\":%u,\"sample_index\":%u,\"warmup\":%s,\"kg_ns\":%s,\"sign_ns\":%s,"
                "\"verify_ns\":%s,\"kg_rc\":%s,\"sign_rc\":%s,\"verify_rc\":%s,"
                "\"signature_bytes\":%s,\"kg_rng_calls\":%llu,\"sign_rng_calls\":%llu,"
                "\"verify_rng_calls\":%llu,\"valid\":%s}\n",
                algorithm, o.batch, o.round, o.chunk, current_index, current_warmup ? "true" : "false",
                optional_json(r.kg_ns).c_str(), optional_json(r.sign_ns).c_str(), optional_json(r.verify_ns).c_str(),
                optional_json(r.kg_rc).c_str(), optional_json(r.sign_rc).c_str(), optional_json(r.verify_rc).c_str(),
                optional_json(r.signature_bytes).c_str(),
                static_cast<unsigned long long>(r.kg_rng_calls), static_cast<unsigned long long>(r.sign_rng_calls),
                static_cast<unsigned long long>(r.verify_rng_calls), r.valid ? "true" : "false");
}

static double median(std::vector<std::uint64_t> values) {
    std::sort(values.begin(), values.end());
    const auto n = values.size();
    if (!n) fail("empty sample set");
    return n % 2 ? static_cast<double>(values[n / 2]) :
        0.5 * (static_cast<double>(values[n / 2 - 1]) + static_cast<double>(values[n / 2]));
}

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0); // Flush raw rows outside all timed intervals.
    const Options o = options(argc, argv);
    const int cpu = pinned_cpu();
    errno = 0;
    const int nice_value = getpriority(PRIO_PROCESS, 0);
    if (errno || nice_value != 19) fail("run with nice -n 19", 64);
    timespec resolution{};
    if (clock_getres(CLOCK_MONOTONIC_RAW, &resolution)) fail("clock_getres failed");
    std::vector<std::uint64_t> clock_pairs;
    for (int i = 0; i < 301; ++i) { auto a = now_ns(); auto b = now_ns(); clock_pairs.push_back(b - a); }
    std::printf("{\"kind\":\"metadata\",\"impl_id\":%d,\"algorithm\":\"%s\",\"source_commit\":\"%s\","
                "\"api\":\"crypto_sign_keypair/crypto_sign/crypto_sign_open\","
                "\"signing\":\"randomized signed-message public API including OS randomness and message copies\","
                "\"rng\":\"upstream randomness_os; fail-closed source wrapper with timed counters\","
                "\"clock\":\"CLOCK_MONOTONIC_RAW\",\"clock_pair_median_ns\":%.1f,"
                "\"clock_overhead_subtracted\":false,\"message_bytes\":64,\"public_key_bytes\":%llu,"
                "\"secret_key_bytes\":%llu,\"signature_bytes_expected\":%zu,\"cpu\":%d,\"nice\":%d,"
                "\"batch\":%u,\"round\":%u,\"chunk\":%u,\"samples_requested\":%u,"
                "\"warmups_requested\":%u,\"sample_offset\":%u}\n",
                impl_id, algorithm, source_commit, median(clock_pairs), Scheme::CRYPTO_PUBLICKEYBYTES,
                Scheme::CRYPTO_SECRETKEYBYTES, expected_signature_bytes, cpu, nice_value,
                o.batch, o.round, o.chunk, o.samples, o.warmup, o.offset);
    validate();
    if (o.validate_only) return 0;
    PublicKey pk{};
    SecretKey sk{};
    SignedMessage sm{};
    Message recovered{};
    std::vector<std::uint64_t> kg, sign, verify;
    kg.reserve(o.samples); sign.reserve(o.samples); verify.reserve(o.samples);
    for (unsigned i = 0; i < o.warmup + o.samples; ++i) {
        current_warmup = i < o.warmup;
        current_index = current_warmup ? i : o.offset + i - o.warmup;
        const auto message = public_message(o.batch, current_index);
        unsigned long long length = 0, recovered_length = 0;
        Record r;
        auto count = rng_calls;
        current_api = "keypair";
        auto a = now_ns();
        r.kg_rc = Scheme::crypto_sign_keypair(pk.data(), sk.data());
        auto b = now_ns();
        r.kg_ns = b - a; r.kg_rng_calls = rng_calls - count;
        if (*r.kg_rc != 0 || !r.kg_rng_calls) { print_record(o, r); fail("keypair failed"); }
        count = rng_calls;
        current_api = "sign";
        a = now_ns();
        r.sign_rc = Scheme::crypto_sign(sm.data(), &length, message.data(), message.size(), sk.data());
        b = now_ns();
        r.sign_ns = b - a; r.sign_rng_calls = rng_calls - count;
        if (*r.sign_rc != 0 || length != sm.size() || !r.sign_rng_calls) {
            print_record(o, r); fail("randomized sign return, length or random source mismatch");
        }
        r.signature_bytes = length - message.size();
        count = rng_calls;
        current_api = "verify";
        a = now_ns();
        r.verify_rc = Scheme::crypto_sign_open(recovered.data(), &recovered_length, sm.data(), length, pk.data());
        b = now_ns();
        r.verify_ns = b - a; r.verify_rng_calls = rng_calls - count;
        r.valid = *r.verify_rc == 0 && recovered_length == message.size() && recovered == message && sched_getcpu() == cpu;
        print_record(o, r);
        if (!r.valid) fail("verify, recovered message or affinity mismatch");
        if (!current_warmup) { kg.push_back(*r.kg_ns); sign.push_back(*r.sign_ns); verify.push_back(*r.verify_ns); }
    }
    std::printf("{\"kind\":\"chunk_summary\",\"algorithm\":\"%s\",\"batch\":%u,\"round\":%u,"
                "\"chunk\":%u,\"samples\":%zu,\"failures\":0,\"kg_median_ns\":%.1f,"
                "\"sign_median_ns\":%.1f,\"verify_median_ns\":%.1f,\"signature_bytes\":%zu,"
                "\"aggregation_note\":\"formal batch median must be computed from all raw non-warmup rows, not medians of chunks\"}\n",
                algorithm, o.batch, o.round, o.chunk, kg.size(), median(kg), median(sign), median(verify), expected_signature_bytes);
    return 0;
}
