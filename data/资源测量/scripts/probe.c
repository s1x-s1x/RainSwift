/* storage probe — NIST API, fixed 64-byte message
 * 与《04_存储需求测试要求》第 4 节参考写法一致；不做额外内存分配，
 * pk/sk/sm 均在静态区，不占堆与栈（探针自身）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"

static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
static unsigned char m[64], sm[64 + CRYPTO_BYTES], m2[64 + CRYPTO_BYTES];

static void die(const char *s) { fprintf(stderr, "error: %s\n", s); exit(1); }

static size_t rd(const char *p, unsigned char *b, size_t n) {
    FILE *f = fopen(p, "rb");
    if (!f) die(p);
    size_t r = fread(b, 1, n, f);
    fclose(f);
    return r;
}

static void wr(const char *p, const unsigned char *b, size_t n) {
    FILE *f = fopen(p, "wb");
    if (!f || fwrite(b, 1, n, f) != n) die(p);
    fclose(f);
}

int main(int argc, char **argv) {
    unsigned long long smlen = 0, mlen = 0;
    if (argc != 2) die("usage: probe gen|none|keygen|sign|verify");
    for (int i = 0; i < 64; i++) m[i] = (unsigned char)i;

    if (!strcmp(argv[1], "gen")) {
        if (crypto_sign_keypair(pk, sk)) die("keygen");
        if (crypto_sign(sm, &smlen, m, 64, sk)) die("sign");
        wr("pk.bin", pk, sizeof pk);
        wr("sk.bin", sk, sizeof sk);
        wr("sm.bin", sm, smlen);
        return 0;
    }

    rd("pk.bin", pk, sizeof pk);
    rd("sk.bin", sk, sizeof sk);
    smlen = rd("sm.bin", sm, sizeof sm);
    if (!strcmp(argv[1], "none")) return 0;
    if (!strcmp(argv[1], "keygen")) return crypto_sign_keypair(pk, sk) ? 1 : 0;
    if (!strcmp(argv[1], "sign")) return crypto_sign(sm, &smlen, m, 64, sk) ? 1 : 0;
    if (!strcmp(argv[1], "verify")) {
        if (crypto_sign_open(m2, &mlen, sm, smlen, pk) || mlen != 64 || memcmp(m2, m, 64))
            die("verify");
        return 0;
    }
    die("bad mode");
    return 1;
}
