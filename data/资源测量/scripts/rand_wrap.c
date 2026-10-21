/* 探针侧随机源桥：与 A 线 q7 harness 的包装等价，不属于签名实现，不计入 M5。
 * 实现库把上游 OS 随机源改名为 p0_upstream_rand_bytes；NIST 包装模板调用 rand_bytes。
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>

extern int p0_upstream_rand_bytes(uint8_t *dst, size_t len) __attribute__((weak));

int rand_bytes(uint8_t *dst, size_t len) {
    if (p0_upstream_rand_bytes) {
        return p0_upstream_rand_bytes(dst, len);
    }
    size_t off = 0;
    while (off < len) {
        ssize_t r = getrandom(dst + off, len - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}
