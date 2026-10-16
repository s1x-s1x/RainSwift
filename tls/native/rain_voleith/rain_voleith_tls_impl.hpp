// Generic part of the C interface (rain_voleith_tls.h). The including file, rain_voleith_tls.cpp,
// first makes faest::faest_scheme<P> available (the source tree's all.inc and api.hpp) and defines
// namespace rain_tls_table with k_set_names, k_set_count and dispatch(set, f).
//
// The signature code is used unchanged. Keygen, sign and verify call faest_scheme<P>::
// crypto_sign_keypair / crypto_sign / crypto_sign_open, which is what the NIST API (api.cpp.in)
// and the KATs run. This file adds the detached-signature conversion, length checks, the
// random source the library expects (rand_bytes), and the failure handling the library leaves
// to its caller: faest_scheme ignores rand_bytes' return value, so a failed draw is recorded here
// and the call's outputs are wiped and reported as RAIN_TLS_ERR_RANDOM.
#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <vector>

extern "C" int rain_tls_os_random(uint8_t* dst, size_t n);

namespace
{

thread_local bool t_random_failed = false;
thread_local uint64_t t_fallback = 0x243f6a8885a308d3ull;

uint64_t splitmix64_step(uint64_t& state)
{
    uint64_t z = (state += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

// Only used after the OS source failed, so that a rejection loop inside crypto_sign_keypair
// still terminates. Everything produced during such a call is wiped before returning.
void fill_after_failure(uint8_t* dst, size_t n)
{
    for (size_t i = 0; i < n; i++)
        dst[i] = (uint8_t) splitmix64_step(t_fallback);
}

void wipe(void* p, size_t n)
{
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n--)
        *v++ = 0;
}

#if defined(RAIN_TLS_TEST_HOOKS)
std::atomic<bool> g_deterministic{false};
std::atomic<bool> g_fail_random{false};
std::atomic<bool> g_scripted{false};
uint64_t g_det_state = 0;
std::vector<uint8_t> g_script;
size_t g_script_pos = 0;
#endif

} // namespace

// The library's random source (randomness.h). Not exported.
extern "C" int rand_bytes(uint8_t* dst, size_t n)
{
#if defined(RAIN_TLS_TEST_HOOKS)
    if (g_deterministic.load())
    {
        // Same stream as rain_q2_test's det mode: one splitmix64 output per byte, low byte kept.
        for (size_t i = 0; i < n; i++)
            dst[i] = (uint8_t) splitmix64_step(g_det_state);
        return 0;
    }
    if (g_scripted.load())
    {
        // Hands out the given bytes in order; running out counts as a failed source.
        if (g_script.size() - g_script_pos < n)
        {
            t_random_failed = true;
            fill_after_failure(dst, n);
            return -1;
        }
        std::memcpy(dst, g_script.data() + g_script_pos, n);
        g_script_pos += n;
        return 0;
    }
    if (g_fail_random.load())
    {
        t_random_failed = true;
        fill_after_failure(dst, n);
        return -1;
    }
#endif
    if (rain_tls_os_random(dst, n) == 0)
        return 0;
    t_random_failed = true;
    fill_after_failure(dst, n);
    return -1;
}

namespace
{

using faest::faest_scheme;

using rain_tls_table::dispatch;
using rain_tls_table::k_set_count;
using rain_tls_table::k_set_names;

template <typename P> int do_keygen(uint8_t* pk, size_t pk_len, uint8_t* sk, size_t sk_len)
{
    using S = faest_scheme<P>;
    if (pk == nullptr || sk == nullptr || pk_len != S::CRYPTO_PUBLICKEYBYTES || sk_len != S::CRYPTO_SECRETKEYBYTES)
        return RAIN_TLS_ERR_LENGTH;
    t_random_failed = false;
    S::crypto_sign_keypair(pk, sk);
    if (t_random_failed)
    {
        wipe(pk, pk_len);
        wipe(sk, sk_len);
        return RAIN_TLS_ERR_RANDOM;
    }
    return RAIN_TLS_OK;
}

template <typename P>
int do_sign(uint8_t* sig, size_t sig_len, const uint8_t* msg, size_t msg_len, const uint8_t* sk, size_t sk_len)
{
    using S = faest_scheme<P>;
    if (sig == nullptr || sk == nullptr || (msg == nullptr && msg_len != 0) || sig_len != S::CRYPTO_BYTES ||
        sk_len != S::CRYPTO_SECRETKEYBYTES || msg_len > std::numeric_limits<size_t>::max() / 2)
        return RAIN_TLS_ERR_LENGTH;
    std::vector<uint8_t> sm(msg_len + S::CRYPTO_BYTES);
    static const uint8_t empty = 0;
    unsigned long long smlen = 0;
    t_random_failed = false;
    S::crypto_sign(sm.data(), &smlen, msg_len ? msg : &empty, msg_len, sk);
    if (t_random_failed || smlen != sm.size())
    {
        wipe(sm.data(), sm.size());
        wipe(sig, sig_len);
        return RAIN_TLS_ERR_RANDOM;
    }
    std::memcpy(sig, sm.data() + msg_len, S::CRYPTO_BYTES);
    return RAIN_TLS_OK;
}

template <typename P>
int do_verify(const uint8_t* sig, size_t sig_len, const uint8_t* msg, size_t msg_len, const uint8_t* pk, size_t pk_len)
{
    using S = faest_scheme<P>;
    // crypto_sign_open does not check that smlen covers a whole signature, so lengths are checked here.
    if (sig == nullptr || pk == nullptr || (msg == nullptr && msg_len != 0) || sig_len != S::CRYPTO_BYTES ||
        pk_len != S::CRYPTO_PUBLICKEYBYTES || msg_len > std::numeric_limits<size_t>::max() / 2)
        return RAIN_TLS_ERR_LENGTH;
    std::vector<uint8_t> sm(msg_len + S::CRYPTO_BYTES), m(msg_len + S::CRYPTO_BYTES);
    if (msg_len)
        std::memcpy(sm.data(), msg, msg_len);
    std::memcpy(sm.data() + msg_len, sig, S::CRYPTO_BYTES);
    unsigned long long mlen = 0;
    if (S::crypto_sign_open(m.data(), &mlen, sm.data(), sm.size(), pk) != 0 || mlen != msg_len)
        return RAIN_TLS_ERR_INVALID;
    return RAIN_TLS_OK;
}

template <typename F> int guarded(F&& f)
{
    try
    {
        return f();
    }
    catch (const std::bad_alloc&)
    {
        return RAIN_TLS_ERR_MEMORY;
    }
    catch (...)
    {
        return RAIN_TLS_ERR_MEMORY;
    }
}

} // namespace

extern "C" {

RAIN_TLS_API int rain_tls_abi_version(void) { return RAIN_TLS_ABI_VERSION; }

RAIN_TLS_API int rain_tls_set_count(void) { return k_set_count; }

RAIN_TLS_API const char* rain_tls_set_name(int set)
{
    return (set >= 0 && set < k_set_count) ? k_set_names[set] : nullptr;
}

RAIN_TLS_API int rain_tls_set_sizes(int set, size_t* public_key_bytes, size_t* secret_key_bytes,
                                    size_t* signature_bytes)
{
    return dispatch(set, [&]<typename P>() {
        using S = faest_scheme<P>;
        if (public_key_bytes)
            *public_key_bytes = S::CRYPTO_PUBLICKEYBYTES;
        if (secret_key_bytes)
            *secret_key_bytes = S::CRYPTO_SECRETKEYBYTES;
        if (signature_bytes)
            *signature_bytes = S::CRYPTO_BYTES;
        return RAIN_TLS_OK;
    });
}

RAIN_TLS_API int rain_tls_keygen(int set, uint8_t* public_key, size_t public_key_len, uint8_t* secret_key,
                                 size_t secret_key_len)
{
    return guarded([&] {
        return dispatch(set, [&]<typename P>() {
            return do_keygen<P>(public_key, public_key_len, secret_key, secret_key_len);
        });
    });
}

RAIN_TLS_API int rain_tls_sign(int set, uint8_t* signature, size_t signature_len, const uint8_t* message,
                               size_t message_len, const uint8_t* secret_key, size_t secret_key_len)
{
    return guarded([&] {
        return dispatch(set, [&]<typename P>() {
            return do_sign<P>(signature, signature_len, message, message_len, secret_key, secret_key_len);
        });
    });
}

RAIN_TLS_API int rain_tls_verify(int set, const uint8_t* signature, size_t signature_len, const uint8_t* message,
                                 size_t message_len, const uint8_t* public_key, size_t public_key_len)
{
    return guarded([&] {
        return dispatch(set, [&]<typename P>() {
            return do_verify<P>(signature, signature_len, message, message_len, public_key, public_key_len);
        });
    });
}

#if defined(RAIN_TLS_TEST_HOOKS)
RAIN_TLS_API void rain_tls_test_deterministic(uint64_t seed)
{
    g_det_state = seed;
    g_deterministic.store(true);
}

RAIN_TLS_API void rain_tls_test_system_random(void)
{
    g_deterministic.store(false);
    g_fail_random.store(false);
    g_scripted.store(false);
}

RAIN_TLS_API void rain_tls_test_script_random(const uint8_t* bytes, size_t n)
{
    g_script.assign(bytes, bytes + n);
    g_script_pos = 0;
    g_scripted.store(true);
}

RAIN_TLS_API size_t rain_tls_test_script_remaining(void) { return g_script.size() - g_script_pos; }

RAIN_TLS_API void rain_tls_test_fail_random(int fail) { g_fail_random.store(fail != 0); }

RAIN_TLS_API int rain_tls_test_public_key(int set, uint8_t* public_key, const uint8_t* secret_key)
{
    return dispatch(set, [&]<typename P>() { return faest::faest_pubkey<P>(public_key, secret_key) ? 1 : 0; });
}
#endif

} // extern "C"
