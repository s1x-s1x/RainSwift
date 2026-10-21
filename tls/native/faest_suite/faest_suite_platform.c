/*
 * Operating-system random bytes and the processor check, kept apart from the signature code:
 * this file is compiled for the x86-64 baseline, so faest_suite_tls_cpu_supported() can run on any
 * x86-64 processor, including one that lacks the instructions the rest of the library uses.
 */
#define FAEST_SUITE_TLS_BUILDING 1
#include "faest_suite_tls.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <errno.h>
#include <sys/random.h>
#endif

/* Internal: fill dst with n bytes from the operating system. Returns 0 on success. */
int faest_suite_tls_os_random(uint8_t* dst, size_t n)
{
#if defined(_WIN32)
    while (n > 0)
    {
        ULONG chunk = n > 0x40000000u ? 0x40000000u : (ULONG) n;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, dst, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
            return -1;
        dst += chunk;
        n -= chunk;
    }
    return 0;
#else
    while (n > 0)
    {
        ssize_t got = getrandom(dst, n, 0);
        if (got < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        dst += got;
        n -= (size_t) got;
    }
    return 0;
#endif
}

#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>

/* XCR0, read with XGETBV (encoded as bytes so no target feature is needed to assemble it). */
static uint64_t read_xcr0(void)
{
    uint32_t eax, edx;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(eax), "=d"(edx) : "c"(0));
    return ((uint64_t) edx << 32) | eax;
}
#endif

/* CPUID directly rather than __builtin_cpu_supports, whose runtime (__cpu_model) is not part of
 * every toolchain's compiler runtime. Checks everything -march=x86_64_v3 may emit, plus AES-NI and
 * PCLMULQDQ, and that the operating system saves the YMM state. */
FAEST_SUITE_TLS_API int faest_suite_tls_cpu_supported(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d))
        return 0;
    const unsigned need1 = (1u << 0) /* SSE3 */ | (1u << 1) /* PCLMULQDQ */ | (1u << 9) /* SSSE3 */ |
                           (1u << 12) /* FMA */ | (1u << 13) /* CX16 */ | (1u << 19) /* SSE4.1 */ |
                           (1u << 20) /* SSE4.2 */ | (1u << 22) /* MOVBE */ | (1u << 23) /* POPCNT */ |
                           (1u << 25) /* AES */ | (1u << 27) /* OSXSAVE */ | (1u << 28) /* AVX */ |
                           (1u << 29) /* F16C */;
    if ((c & need1) != need1)
        return 0;
    if ((read_xcr0() & 0x6) != 0x6) /* XMM and YMM state enabled by the OS */
        return 0;
    if (__get_cpuid_max(0, NULL) < 7)
        return 0;
    __cpuid_count(7, 0, a, b, c, d);
    const unsigned need7 = (1u << 3) /* BMI1 */ | (1u << 5) /* AVX2 */ | (1u << 8) /* BMI2 */;
    if ((b & need7) != need7)
        return 0;
    if (__get_cpuid_max(0x80000000u, NULL) < 0x80000001u)
        return 0;
    __cpuid(0x80000001u, a, b, c, d);
    return (c & ((1u << 0) /* LAHF/SAHF */ | (1u << 5) /* LZCNT */)) == ((1u << 0) | (1u << 5));
#else
    return 0;
#endif
}
