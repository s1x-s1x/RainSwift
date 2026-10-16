/*
 * C interface to the Rain-VOLEitH signature code for the hybrid TLS 1.3 harness.
 *
 * Every operation runs faest_scheme<P>::crypto_sign_keypair / crypto_sign / crypto_sign_open,
 * the functions behind the NIST API that the published KATs exercise. This layer only converts
 * between detached and attached signatures, checks lengths, supplies the operating-system random
 * source, and wipes its outputs when that source fails.
 *
 * Call rain_tls_cpu_supported() before anything else: the signature code is compiled for
 * x86-64-v3 plus AES-NI and PCLMULQDQ, and running it on an older processor would fault.
 */
#ifndef RAIN_VOLEITH_TLS_H
#define RAIN_VOLEITH_TLS_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#if defined(RAIN_TLS_BUILDING)
#define RAIN_TLS_API __declspec(dllexport)
#else
#define RAIN_TLS_API __declspec(dllimport)
#endif
#else
#define RAIN_TLS_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define RAIN_TLS_ABI_VERSION 1

#define RAIN_TLS_OK 0
#define RAIN_TLS_ERR_SET (-1)     /* unknown parameter set */
#define RAIN_TLS_ERR_LENGTH (-2)  /* a buffer has the wrong length */
#define RAIN_TLS_ERR_RANDOM (-3)  /* the random source failed; outputs were wiped */
#define RAIN_TLS_ERR_INVALID (-4) /* the signature does not verify */
#define RAIN_TLS_ERR_MEMORY (-5)  /* allocation failed */

/* Parameter sets of rain_voleith_tls.dll; callers should look them up by name.
 *   0 rain3-fast   1 rain3-bal    2 rain3-short   (Rain, 3 rounds)
 *   3 rain4-fast   4 rain4-bal    5 rain4-short   (Rain, 4 rounds)
 */
RAIN_TLS_API int rain_tls_abi_version(void);
RAIN_TLS_API int rain_tls_cpu_supported(void);
RAIN_TLS_API int rain_tls_set_count(void);
RAIN_TLS_API const char* rain_tls_set_name(int set);
RAIN_TLS_API int rain_tls_set_sizes(int set, size_t* public_key_bytes, size_t* secret_key_bytes,
                                    size_t* signature_bytes);

RAIN_TLS_API int rain_tls_keygen(int set, uint8_t* public_key, size_t public_key_len,
                                 uint8_t* secret_key, size_t secret_key_len);
RAIN_TLS_API int rain_tls_sign(int set, uint8_t* signature, size_t signature_len,
                               const uint8_t* message, size_t message_len,
                               const uint8_t* secret_key, size_t secret_key_len);
RAIN_TLS_API int rain_tls_verify(int set, const uint8_t* signature, size_t signature_len,
                                 const uint8_t* message, size_t message_len,
                                 const uint8_t* public_key, size_t public_key_len);

#if defined(RAIN_TLS_TEST_HOOKS)
/* Test build only; the production library does not contain these. */
RAIN_TLS_API void rain_tls_test_deterministic(uint64_t seed); /* splitmix64 bytes, as Q2 T7 */
RAIN_TLS_API void rain_tls_test_system_random(void);
RAIN_TLS_API void rain_tls_test_fail_random(int fail);        /* make the OS source fail */
RAIN_TLS_API void rain_tls_test_script_random(const uint8_t* bytes, size_t n); /* hand out exactly these bytes */
RAIN_TLS_API size_t rain_tls_test_script_remaining(void);     /* scripted bytes not yet drawn */
RAIN_TLS_API int rain_tls_test_public_key(int set, uint8_t* public_key,
                                          const uint8_t* secret_key); /* 1 accepted, 0 rejected */
#endif

#ifdef __cplusplus
}
#endif

#endif
