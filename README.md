# Rain-VOLEitH：基于 Rain 单向函数的 VOLE-in-the-Head 签名

[![verify](../../actions/workflows/verify.yml/badge.svg)](../../actions/workflows/verify.yml)

**English summary.** A post-quantum signature that replaces the EM-AES one-way function of
[rFAEST](https://github.com/samsungsds-research-papers/rFAEST) (commit `7a59c5c`) with the Rain-3 / Rain-4
block cipher, keeping rFAEST's VOLE, commitment, hashing and AVX2 code unchanged. Six 128-bit parameter sets.
Run `docker build -t rain-voleith . && docker run --rm rain-voleith` to rebuild and check all known-answer
tests byte-for-byte. Documentation is in Chinese.

本仓库在 rFAEST 的同一份代码基础上，把单向函数由 EM-AES 换成 Rain-3／Rain-4，其余部分（VOLE、承诺、哈希、AVX2 实现）保持不变。共有六组 128 位参数。任何人都可以按下文一键复现编译、测试和已知答案测试（KAT）比对，也可以直接调用签名接口。

## 1. 结果概览

公钥与打包私钥均为 32 B。下表为作者在一台服务器上的**实测**数据：AMD EPYC 7R32（Zen 2，AVX2），同机同窗口，调用完整 API，取 1,503 个样本的中位数。测量规程见 [Q3 实测报告](docs/Q3_benchmark_report.md)。

| 参数集 | 签名 / B | 签发 / ms | 验签 / ms | 对照 | 签发加速 | 验签加速 |
|---|---:|---:|---:|---|---:|---:|
| Rain-3 快档 `rain3_fast` | 4,146 | 0.131 | 0.131 | rFAEST-EM-128f（4,980 B） | 3.03× | 2.48× |
| Rain-3 均衡档 `rain3_bal` | 3,706 | 0.240 | 0.220 | rFAEST-EM-128f | 1.66× | 1.48× |
| Rain-4 快档 `rain4_fast` | 4,112 | 0.195 | 0.181 | rFAEST-EM-128f | 2.05× | 1.80× |
| Rain-4 均衡档 `rain4_bal` | 4,080 | 0.207 | 0.168 | rFAEST-EM-128f | 1.92× | 1.94× |
| Rain-3 短档 `rain3_short` | 3,014 | 1.879 | 1.364 | rFAEST-EM-128s（4,014 B） | 1.00× | 1.25× |
| Rain-4 短档 `rain4_short` | 3,190 | 1.943 | 1.398 | rFAEST-EM-128s | 0.97× | 1.22× |

建钥约 1.2–1.6 µs，比 EM-AES 对照慢：Rain-3 慢约 5%，Rain-4 慢约 26%。数值依赖机器，在其他机器上应在同一次运行内比较比值（见第 4 节）。

## 2. 安全性口径

- **已给出（有条件）**：在经典随机预言模型下给出 EUF-CMA 条件证明，依赖明示的 Rain 原语计算假设。另有 128 档设计评估。层级与 rFAEST 作者的安全声明相同，见 [完整安全证明](docs/Q4_03_security_proof.md)、[Rain-128 原语依据](docs/Q4_01_Rain128_primitive.md)、[验收报告](docs/Q4_02_acceptance.md)。
- **未声称**：本仓库不声称“已证明 128 位安全”。严格的具体工作因子尚未建立，QROM、192／256 位档也未覆盖。Rain-3 的轮数余量小于 Rain-4，使用前请阅读原语依据中的风险说明。
- **未评估**：常数时间与侧信道。本实现是研究原型，不建议用于生产环境。

## 3. 一键验证

需要 x86-64 CPU，支持 AVX2、AES-NI 和 PCLMULQDQ（近十年的 Intel／AMD 桌面与服务器 CPU 一般都支持；Apple M 系列和 ARM 不支持）。

**方式一：Docker（推荐，Windows／macOS(Intel)／Linux 均可）**

```bash
git clone https://github.com/<你的用户名>/rain-voleith.git && cd rain-voleith
docker build -t rain-voleith .
docker run --rm rain-voleith
```

第一次构建大约需要 5 分钟，构建时会从 GitHub 下载固定版本的 XKCP。看到下面这行就表示验证通过：

```
VERIFY PASS: T1-T8 passed and all six signature KATs match byte-for-byte
```

**方式二：本机 Linux**

需要 GCC ≥ 14 或 Clang ≥ 19，以及 Meson ≥ 1.4、Ninja 和 Python 3。

```bash
bash verify.sh
```

**验证内容。** `rain_q2_test` 依次运行以下测试：

| 编号 | 内容 |
|---|---|
| T1 | 尺寸 |
| T2 | 签名方与验证方的 VOLE 关系逐行核对 |
| T3 | 零输入拒绝 |
| T4 | 建钥重试 |
| T5 | 逐字节篡改全部拒绝 |
| T6 | 每组 1,000 次签名／验签往返 |
| T7 | Rain 原语 KAT 与签名 KAT |
| T8 | 签名随机数派生 |

测完后，`verify.sh` 把 T7 用确定性随机源生成的六组签名与 [KAT/](KAT/) 逐字节比对。作者用 Zig/Clang 18 生成了这些 KAT，本仓库的 Docker 环境用 GCC 14 独立复现，结果一致。GitHub Actions 每次推送都会自动重跑上述验证。

## 4. 使用算法

接口沿用 NIST 签名 API（`sm = m || signature`），用 C++ 模板选择参数集：

```cpp
#include "all.inc"
#include "api.hpp"
using Scheme = faest::faest_scheme<faest::rain_sets::rain3_fast>;   // 六组之一

Scheme::crypto_sign_keypair(pk, sk);                       // pk、sk 各 32 字节
Scheme::crypto_sign(sm, &smlen, msg, msglen, sk);          // sm 缓冲区长度 msglen + Scheme::CRYPTO_BYTES
int rc = Scheme::crypto_sign_open(m, &mlen, sm, smlen, pk); // 0 = 签名有效
```

完整示例见 [src/examples/sign_demo.cpp](src/examples/sign_demo.cpp)：

```bash
docker run --rm rain-voleith ./build/sign_demo "hello"
```

想在自己的项目中使用，可以把 `src/` 作为 Meson 子项目引入并依赖 `faest_dep`，随机源链接 `randomness_os_dep`。

**在自己机器上测速。** 下面的命令在同一进程内依次测量 Rain 六组以及同源码树编译的 rFAEST-EM-128f／128s，并输出比值。这只是便捷工具；正式测量规程见 Q3 报告，原始脚本存档在 [docs/q3_scripts/](docs/q3_scripts/)。

```bash
docker run --rm rain-voleith taskset -c 2 ./build/rain_bench 501
```

## 5. 目录

| 路径 | 内容 |
|---|---|
| `src/` | 源码（rFAEST 7a59c5c ＋ Rain 补丁，改动清单见 `src/RAIN_PATCHES.json`）；参数集在 `src/parameters.hpp` 的 `rain_sets` |
| `src/rain_q2_test.cpp` | T1–T8 测试 |
| `src/examples/`、`src/bench/` | 使用示例、便捷测速 |
| `KAT/` | 六组签名 KAT 与 SHA-256 |
| `docs/` | Q2 验收、Q3 实测报告、Q4 安全证明三份文档（中文）；文中指向作者内部记录的链接已改为文字标注 |
| `verify.sh`、`Dockerfile`、`.github/workflows/` | 一键验证与持续集成 |

## 6. 来源与许可

- 代码基于 [rFAEST](https://github.com/samsungsds-research-papers/rFAEST)（Samsung SDS，提交 `7a59c5c18b199bae427bd71d3b9fb5ea3f3b6d97`），rFAEST 又基于 FAEST 参考实现。按 MIT 许可证发布，版权声明见 [src/LICENSE](src/LICENSE)。
- SHAKE 使用 [XKCP](https://github.com/XKCP/XKCP)，固定在提交 `64404bee`。
- `src/` 相对 Q2 验收源码的唯一改动是在 `src/meson.build` 末尾追加了 `sign_demo` 和 `rain_bench` 两个构建目标，并新增了这两个程序；协议字节由 KAT 比对保证不变。
