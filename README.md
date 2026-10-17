# Rain-VOLEitH：基于 Rain 单向函数的 VOLE-in-the-Head 签名

[![verify](../../actions/workflows/verify.yml/badge.svg)](../../actions/workflows/verify.yml)
[![tls-windows](../../actions/workflows/tls-windows.yml/badge.svg)](../../actions/workflows/tls-windows.yml)

**English summary.** A post-quantum signature that replaces the EM-AES one-way function of
[rFAEST](https://github.com/samsungsds-research-papers/rFAEST) (commit `7a59c5c`) with the Rain-3 / Rain-4
block cipher, keeping rFAEST's VOLE, commitment, hashing and AVX2 code unchanged. Six 128-bit parameter sets.
Key generation uses an optimized but functionally identical Rain evaluation (`src/rain_kg.hpp`), checked bit for bit
against the original implementation. Run `docker build -t rain-voleith . && docker run --rm rain-voleith` to rebuild
and check all known-answer tests byte-for-byte. `tls/` integrates the six sets into a hybrid TLS 1.3
implementation (the team's earlier v9 stack) as the post-quantum CertificateVerify signature; a Windows CI job builds
the DLL, reproduces the KATs through it and runs the TLS test suite. Documentation is in Chinese.

本仓库在 rFAEST 的同一份代码基础上，把单向函数由 EM-AES 换成 Rain-3／Rain-4，其余部分（VOLE、承诺、哈希、AVX2 实现）保持不变。共有六组 128 位参数。任何人都可以按下文一键复现编译、测试和已知答案测试（KAT）比对，也可以直接调用签名接口。

## 1. 结果概览

公钥与打包私钥均为 32 B。下表为作者在一台服务器上的**实测**数据：AMD EPYC 7R32（Zen 2，AVX2），同机同窗口，调用完整 API，取 1,503 个样本的中位数。数据来自建钥优化（Q5）后的重测，见 [Q5 实测报告](docs/Q5_keygen_report.md)；测量规程见 [Q3 实测报告](docs/Q3_benchmark_report.md)。比值以同一窗口内的 rFAEST 为基准：签发、验签为加速倍数，建钥为时间比（小于 1 表示更快）。

| 参数集 | 签名 / B | 签发 / ms | 验签 / ms | 建钥 / µs | 对照 | 签发加速 | 验签加速 | 建钥时间比 |
|---|---:|---:|---:|---:|---|---:|---:|---:|
| Rain-3 快档 `rain3_fast` | 4,146 | 0.131 | 0.131 | 1.02 | rFAEST-EM-128f（4,980 B） | 3.03× | 2.49× | 0.87 |
| Rain-3 均衡档 `rain3_bal` | 3,706 | 0.239 | 0.220 | 0.99 | rFAEST-EM-128f | 1.66× | 1.48× | 0.85 |
| Rain-4 快档 `rain4_fast` | 4,112 | 0.194 | 0.181 | 1.14 | rFAEST-EM-128f | 2.04× | 1.80× | 0.97 |
| Rain-4 均衡档 `rain4_bal` | 4,080 | 0.202 | 0.168 | 1.14 | rFAEST-EM-128f | 1.97× | 1.94× | 0.97 |
| Rain-3 短档 `rain3_short` | 3,014 | 1.852 | 1.355 | 1.09 | rFAEST-EM-128s（4,014 B） | 1.01× | 1.25× | 0.89 |
| Rain-4 短档 `rain4_short` | 3,190 | 1.906 | 1.390 | 1.24 | rFAEST-EM-128s | 0.98× | 1.22× | 1.01 |

同窗对照的建钥：rFAEST-EM-128f 约 1.17 µs，FAEST v3 EM-128f 约 1.18 µs；128s 对照约 1.22–1.23 µs。建钥优化前（Q3 主窗口），Rain 的建钥比 EM-AES 对照慢 5%–27%；优化只替换建钥中 Rain 正向计算的实现，所计算的函数不变，KAT 与签发、验签均不变（见第 3 节差分测试）。数值依赖机器，在其他机器上应在同一次运行内比较比值（见第 4 节）。

**与 55 项同类方案及对照的综合速度数据。** 另有一套更大范围的实测数据，见 [docs/speed_data/](docs/speed_data/README.md)。它覆盖服务器原语 55 项，以及接入混合 TLS 1.3 后的笔记本原语与握手 41 项。这套数据以本项目实测为主，本项目缺失的项和短档签发用队友的实测，每行注明来源与测量环境。

## 2. 安全性口径

- **已给出（有条件）**：在经典随机预言模型下给出 EUF-CMA 条件证明，依赖明示的 Rain 原语计算假设。另有 128 档设计评估。层级与 rFAEST 作者的安全声明相同，见 [完整安全证明](docs/Q4_03_security_proof.md)、[Rain-128 原语依据](docs/Q4_01_Rain128_primitive.md)、[验收报告](docs/Q4_02_acceptance.md)；证明引用的分稿、内部审查与复算记录见 [docs/Q4_records/](docs/Q4_records/README.md)（内部 AI 审查，非外部同行评审）。
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
VERIFY PASS: T1-T8 passed, the key-generation differential test passed and all six signature KATs match byte-for-byte
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

随后 `q5_kg_test` 把建钥所用的优化实现与原实现逐位对照（GF(2^64) 乘法与平方、多次平方表、线性层、求逆以及完整正向计算，每类 2^20 组输入外加构造用例），任何不一致都判失败。最后，`verify.sh` 把 T7 用确定性随机源生成的六组签名与 [KAT/](KAT/) 逐字节比对。作者用 Zig/Clang 18 生成了这些 KAT，本仓库的 Docker 环境用 GCC 14 独立复现，结果一致。GitHub Actions 每次推送都会自动重跑上述验证。

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

**在自己机器上测速。** 下面的命令在同一进程内依次测量 Rain 六组以及同源码树编译的 rFAEST-EM-128f／128s，并输出比值。这只是便捷工具；正式测量规程见 Q3 报告，原始脚本存档在 [docs/q3_scripts/](docs/q3_scripts/) 与 [docs/q5_scripts/](docs/q5_scripts/)。建钥各组件的新旧耗时可以用 `docker run --rm rain-voleith taskset -c 2 ./build/q5_kg_test --bench` 查看。

```bash
docker run --rm rain-voleith taskset -c 2 ./build/rain_bench 501
```

## 5. 目录

| 路径 | 内容 |
|---|---|
| `src/` | 源码（rFAEST 7a59c5c ＋ Rain 补丁，改动清单见 `src/RAIN_PATCHES.json`）；参数集在 `src/parameters.hpp` 的 `rain_sets` |
| `src/rain_q2_test.cpp` | T1–T8 测试 |
| `src/rain_kg.hpp`、`src/q5_kg_test.cpp` | 建钥专用的 Rain 正向计算（与原实现同一函数）及其差分测试、组件微基准 |
| `src/examples/`、`src/bench/` | 使用示例、便捷测速 |
| `KAT/` | 六组签名 KAT 与 SHA-256 |
| `docs/` | Q2 验收、Q3 实测报告、Q4 安全证明、Q5 建钥优化（计划、组件测试、实测报告、汇总表、分析）等文档（中文） |
| `docs/Q4_records/` | Q4 证明引用的分稿、内部审查与复算记录（索引见其 README） |
| `docs/speed_data/` | 55 项综合速度数据：服务器原语与笔记本 TLS 两张 CSV（来源与环境见其 README） |
| `tls/` | 混合 TLS 1.3 应用：团队前期的 v9 实现接入 Rain-VOLEitH（见第 6 节） |
| `verify.sh`、`Dockerfile`、`.github/workflows/` | 一键验证与持续集成（`verify.yml`：Linux 上的算法验证；`tls-windows.yml`：Windows 上的 TLS 接入验证） |

## 6. TLS 1.3 应用（`tls/`）

`tls/` 是团队前期的混合 TLS 1.3 实现 v9，接入了本仓库的 Rain-VOLEitH，作为握手中的后量子签名使用：

- **协议**：密钥协商用 X25519＋ML-KEM-768。认证时，ECDSA P-256 与 Rain-VOLEitH 对同一个 CertificateVerify 输入各签一次，客户端要求两者都通过。X.509 叶证书的私有扩展携带 32 字节的 Rain 公钥。
- **改动范围**：v9 的握手、密钥协商、密钥调度和记录层都没有改。新增的是：
  - 原生库接口 `tls/native/rain_voleith/`，由本仓库 `src/` 编成 Windows DLL；
  - ctypes 后端 `tls/tls/pq/rain_voleith.py`；
  - 测试、已知答案关卡、演示与文档。

  说明见 [tls/docs/RAIN_VOLEITH.md](tls/docs/RAIN_VOLEITH.md)。
- **只含 Rain-VOLEitH**：本仓库只发布我方算法的接入。六组参数的编号为 0xFEB0–0xFEB5。
- **验证**：GitHub Actions（`tls-windows.yml`）在 Windows 上依次完成：
  1. 用 MinGW-w64 GCC 构建生产版与测试版 DLL；
  2. 已知答案关卡 `tls/tools/rain_voleith_kat_gate.py`：经 DLL 逐字节复现六份签名 KAT，并核对建钥 KAT、负例、随机源失败和并发；
  3. 在要求 Rain 可用的设置下，运行 v9 全套测试；
  4. 运行演示。
- **作者本机结果**：关卡 337/337；v9 全套测试 460 项通过；`verify_all.ps1` 29/29（Verifpal 未安装，未运行）。

| PQ 签名 | 握手字节 | CertificateVerify / B | 进程内握手 / ms |
|---|---:|---:|---:|
| rain3-fast | 7,893 | 4,249 | 2.23 |
| rain3-bal | 7,453 | 3,810 | 2.52 |
| rain3-short | 6,760 | 3,117 | 5.54 |
| rain4-fast | 7,859 | 4,216 | 2.29 |
| rain4-bal | 7,827 | 4,184 | 2.32 |
| rain4-short | 6,937 | 3,293 | 5.75 |
| falcon-512（v9 原有，可移植 C） | 5,273 | 759 | 7.12 |
| ml-dsa-44（v9 原有，可移植 C） | 7,453 | 2,523 | 10.13 |

上表在一台 Windows 笔记本（i7-14700HX）上测得：X.509 链，经 Python 调用，每组 30 次取中位数。六组 Rain 在回环 TCP 与三条整形链路上都保持 1-RTT。Falcon、ML-DSA 用的是 v9 依赖中的可移植 C 实现，不是 AVX2 优化版，所以时间对比只是本协议栈内可用实现之间的比较。

**运行（Windows，x86-64-v3 加 AES-NI、PCLMULQDQ）**，在 `tls/` 目录中依次执行：

1. 构建 DLL，见 [tls/native/rain_voleith/README.md](tls/native/rain_voleith/README.md)。需要 MSYS2 UCRT64 GCC，以及 XKCP 的固定提交。
2. 安装锁定的依赖：`python -m pip install --require-hashes --only-binary :all: --target .deps -r requirements.lock.txt`。
3. 设 `PYTHONPATH=.deps`，然后运行：
   - 演示：`python demo/rain_voleith_demo.py`；
   - 测试：`RAIN_VOLEITH_REQUIRED=1 python -m pytest tests -q`。

**发布时的处理：**
- **脱敏**：`tls/README.md` 中两处开发者本机路径改为 `<仓库>\tls`；`tls/validation/environment*.json` 中的本机路径、用户名和会话编号换成占位符。
- **按 v9 自带的 `.gitignore`**：`.bench-out/*.json` 测量输出不纳入版本库。
- 除 [tls/docs/RAIN_VOLEITH.md](tls/docs/RAIN_VOLEITH.md) 第 2 节列出的接入改动与上述脱敏外，其余 v9 文件与团队提供的 v9 包逐字节相同（`tls/` 按原字节入库，不做换行转换）。

## 7. 来源与许可

- 代码基于 [rFAEST](https://github.com/samsungsds-research-papers/rFAEST)（Samsung SDS，提交 `7a59c5c18b199bae427bd71d3b9fb5ea3f3b6d97`），rFAEST 又基于 FAEST 参考实现。按 MIT 许可证发布，版权声明见 [src/LICENSE](src/LICENSE)。
- SHAKE 使用 [XKCP](https://github.com/XKCP/XKCP)，固定在提交 `64404bee`。
- `tls/` 中的混合 TLS 1.3 实现 v9 是团队前期工作，原包未附许可证。
- `src/` 相对 Q2 验收源码的改动：`src/meson.build` 追加了 `sign_demo`、`rain_bench` 与 `q5_kg_test` 三个构建目标并新增这三个程序；Q5 新增 `src/rain_kg.hpp`，`src/faest_keys.inc` 中建钥（`faest_pubkey`）改调它（增 3 行、删 1 行）。协议字节由 KAT 比对保证不变。
