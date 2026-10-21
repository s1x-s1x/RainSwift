/* 栈深度补测探针：栈涂抹法（与 massif 抽样口径交叉验证）
 * 用法：probe_stack_<impl> stack-none|stack-keygen|stack-sign|stack-verify
 * 输出：一行十进制字节数（该模式实际使用到的栈深度，含探针/运行库）
 * 注意：本探针只用于 M3 补测，不参与 M5；原 probe 保持不变。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"

#define PAINT_BYTES ((size_t)1 << 20) /* 1 MiB，须小于 ulimit -s */
#define PATTERN 0xA5

static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
static unsigned char m[64], sm[64 + CRYPTO_BYTES], m2[64 + CRYPTO_BYTES];

__attribute__((noinline)) static void paint_stack(void) {
    volatile unsigned char buf[PAINT_BYTES];
    for (size_t i = 0; i < PAINT_BYTES; i++) buf[i] = PATTERN;
}

__attribute__((noinline)) static size_t stack_used(void) {
    volatile unsigned char buf[PAINT_BYTES];
    size_t i = 0;
    while (i < PAINT_BYTES && buf[i] == PATTERN) i++;
    return PAINT_BYTES - i;
}

static void die(const char *s) { fprintf(stderr, "error: %s\n", s); exit(1); }

static size_t rd(const char *p, unsigned char *b, size_t n) {
    FILE *f = fopen(p, "rb");
    if (!f) die(p);
    size_t r = fread(b, 1, n, f);
    fclose(f);
    return r;
}

int main(int argc, char **argv) {
    unsigned long long smlen = 0, mlen = 0;
    if (argc != 2 || strncmp(argv[1], "stack-", 6)) die("usage: probe_stack stack-MODE");
    const char *mode = argv[1] + 6;
    for (int i = 0; i < 64; i++) m[i] = (unsigned char)i;

    rd("pk.bin", pk, sizeof pk);
    rd("sk.bin", sk, sizeof sk);
    smlen = rd("sm.bin", sm, sizeof sm);

    int rc = 0;
    if (!strcmp(mode, "none")) {
        paint_stack();
        printf("%zu\n", stack_used());
        return 0;
    } else if (!strcmp(mode, "keygen")) {
        paint_stack();
        rc = crypto_sign_keypair(pk, sk);
    } else if (!strcmp(mode, "sign")) {
        paint_stack();
        rc = crypto_sign(sm, &smlen, m, 64, sk);
    } else if (!strcmp(mode, "verify")) {
        paint_stack();
        rc = crypto_sign_open(m2, &mlen, sm, smlen, pk);
        if (!rc && (mlen != 64 || memcmp(m2, m, 64))) rc = -1;
    } else {
        die("bad mode");
    }
    printf("%zu\n", stack_used());
    return rc ? 1 : 0;
}
