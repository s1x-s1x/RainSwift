/*
 * C interface to the FAEST v2/v3 signature suite for the hybrid TLS 1.3 harness.
 *
 * Every operation runs faest_scheme<P>::crypto_sign_keypair / crypto_sign / crypto_sign_open,
 * the functions behind the NIST API that the published KATs exercise. This layer only converts
 * between detached and attached signatures, checks lengths, supplies the operating-system random
 * source, and wipes its outputs when that source fails.
 *
 * Call faest_suite_tls_cpu_supported() before anything else: the signature code is compiled for
 * x86-64-v3 plus AES-NI and PCLMULQDQ, and running it on an older processor would fault.
 */
#ifndef FAEST_SUITE_TLS_H
#define FAEST_SUITE_TLS_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#if defined(FAEST_SUITE_TLS_BUILDING)
#define FAEST_SUITE_TLS_API __declspec(dllexport)
#else
#define FAEST_SUITE_TLS_API __declspec(dllimport)
#endif
#else
#define FAEST_SUITE_TLS_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FAEST_SUITE_TLS_ABI_VERSION 1

#define FAEST_SUITE_TLS_OK 0
#define FAEST_SUITE_TLS_ERR_SET (-1)     /* unknown parameter set */
#define FAEST_SUITE_TLS_ERR_LENGTH (-2)  /* a buffer has the wrong length */
#define FAEST_SUITE_TLS_ERR_RANDOM (-3)  /* the random source failed; outputs were wiped */
#define FAEST_SUITE_TLS_ERR_INVALID (-4) /* the signature does not verify */
#define FAEST_SUITE_TLS_ERR_MEMORY (-5)  /* allocation failed */

/* Parameter sets of faest_suite_tls.dll; callers should look them up by name.
 *   0 faest3-em-128f   1 faest3-em-128s   (FAEST v3, EM-AES OWF)
 *   2 faest3-aes-128f  3 faest3-aes-128s  (FAEST v3, AES-CTR OWF)
 *   4 faest2-aes-128f  5 faest2-aes-128s  (FAEST v2, AES-CTR OWF)
 *   6 faest2-em-128f   7 faest2-em-128s   (FAEST v2, EM-AES OWF)
 */
FAEST_SUITE_TLS_API int faest_suite_tls_abi_version(void);
FAEST_SUITE_TLS_API int faest_suite_tls_cpu_supported(void);
FAEST_SUITE_TLS_API int faest_suite_tls_set_count(void);
FAEST_SUITE_TLS_API const char* faest_suite_tls_set_name(int set);
FAEST_SUITE_TLS_API int faest_suite_tls_set_sizes(int set, size_t* public_key_bytes,
                                                  size_t* secret_key_bytes, size_t* signature_bytes);

FAEST_SUITE_TLS_API int faest_suite_tls_keygen(int set, uint8_t* public_key, size_t public_key_len,
                                               uint8_t* secret_key, size_t secret_key_len);
FAEST_SUITE_TLS_API int faest_suite_tls_sign(int set, uint8_t* signature, size_t signature_len,
                                             const uint8_t* message, size_t message_len,
                                             const uint8_t* secret_key, size_t secret_key_len);
FAEST_SUITE_TLS_API int faest_suite_tls_verify(int set, const uint8_t* signature, size_t signature_len,
                                               const uint8_t* message, size_t message_len,
                                               const uint8_t* public_key, size_t public_key_len);

#if defined(FAEST_SUITE_TLS_TEST_HOOKS)
/* Test build only; the production library does not contain these. */
FAEST_SUITE_TLS_API void faest_suite_tls_test_deterministic(uint64_t seed); /* splitmix64 bytes */
FAEST_SUITE_TLS_API void faest_suite_tls_test_system_random(void);
FAEST_SUITE_TLS_API void faest_suite_tls_test_fail_random(int fail);
FAEST_SUITE_TLS_API void faest_suite_tls_test_script_random(const uint8_t* bytes, size_t n);
FAEST_SUITE_TLS_API size_t faest_suite_tls_test_script_remaining(void);
FAEST_SUITE_TLS_API int faest_suite_tls_test_public_key(int set, uint8_t* public_key,
                                                        const uint8_t* secret_key);
#endif

#ifdef __cplusplus
}
#endif

#endif
