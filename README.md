# RainSwift（雨燕）：基于 Rain 单向函数的 VOLE-in-the-Head 签名

[![verify](../../actions/workflows/verify.yml/badge.svg)](../../actions/workflows/verify.yml)
[![tls-windows](../../actions/workflows/tls-windows.yml/badge.svg)](../../actions/workflows/tls-windows.yml)

**English summary.** RainSwift is a post-quantum signature that replaces the EM-AES one-way function of
[rFAEST](https://github.com/samsungsds-research-papers/rFAEST) (commit `7a59c5c`) with the Rain-3 / Rain-4
block cipher, keeping rFAEST's VOLE, commitment, hashing and AVX2 code unchanged. Six 128-bit parameter sets.
Key generation uses an optimized but functionally identical Rain evaluation (`src/rain_kg.hpp`), checked bit for bit
against the original implementation. Run `docker build -t rainswift . && docker run --rm rainswift` to rebuild
and check all known-answer tests byte-for-byte. `tls/` integrates the six sets into a hybrid TLS 1.3
implementation (the team's earlier v9 stack) as the post-quantum CertificateVerify signature; a Windows CI job builds
the DLL, reproduces the KATs through it and runs the TLS test suite. Documentation is in Chinese.

本仓库在 rFAEST 的同一份代码基础上，把单向函数由 EM-AES 换成 Rain-3／Rain-4，其余部分（VOLE、承诺、哈希、AVX2 实现）保持不变。共有六组 128 位参数。任何人都可以按下文一键复现编译、测试和已知答案测试（KAT）比对，也可以直接调用签名接口。

论文与仓库名称统一为 **RainSwift（雨燕）**。源码沿用的 `rain_voleith` 文件名、接口和环境变量是早期实现标识，对应同一算法；调用示例按现有接口给出。

## 1. 结果概览

**2026-10-22 数据更新。** 以复赛支撑材料中的 `03_测试数据/` 替换此前的测速数据；完整快照现位于 [data/](data/README.md)，原始文件逐字节保留。正式原语集合为 **38 组实现（6 组 RainSwift ＋ 32 组对照）**，使用完整窗口对 **F3/S3**，每组 1,503 个非预热样本，共 **57,114 个样本、342 份 JSONL**。选择完整窗口对，不逐格选择最小值。

公钥与打包私钥均为 32 B。下表来自 [性能统计 JSON](data/原语性能/性能统计.json)，列出建钥、签名和验签的中位数。环境为 AMD EPYC 7773X、Ubuntu 20.04.5 LTS，64 字节消息、CPU 单线程、`CLOCK_MONOTONIC_RAW`；Rain 使用 Zig 0.13 / Clang 18，`-O3 -march=native -mtune=native`，关闭 LTO。各对照实现的编译组选项、四分位数、排除项及理由见 JSON。

| 参数集 | 源码参数 | 签名 / B | 建钥 / µs | 签名 / ms | 验签 / ms | 窗口 |
|---|---|---:|---:|---:|---:|---|
| RainSwift-3f | `rain3_fast` | 4,146 | 1.63 | 0.19383 | 0.19879 | F3 |
| RainSwift-3b | `rain3_bal` | 3,706 | 1.56 | 0.35144 | 0.32403 | F3 |
| RainSwift-3s | `rain3_short` | 3,014 | 1.59 | 2.55532 | 2.01242 | S3 |
| RainSwift-4f | `rain4_fast` | 4,112 | 1.74 | 0.30483 | 0.28281 | F3 |
| RainSwift-4b | `rain4_bal` | 4,080 | 1.74 | 0.31765 | 0.26608 | F3 |
| RainSwift-4s | `rain4_short` | 3,190 | 1.75 | 2.58270 | 2.03576 | S3 |

完整对照见 [38 组性能 CSV](data/原语性能/性能统计.csv)。同窗 rFAEST-EM-128f 的签名／验签为 0.67262／0.53946 ms，rFAEST-EM-128s 为 2.75686／2.58655 ms；建钥分别为 1.80／1.89 µs。绝对时间依赖机器与构建，比较时保留相同窗口和计量口径。

数据入口：

- [原语性能与原始采样](data/原语性能/)：正式 38 组统计、原始 JSONL、构建记录、核验程序。
- [资源测量](data/资源测量/)：14 组实现的独立探针、原始工具输出和结果表。
- [协议时延](data/协议时延/)：经典 CA 配置的逐次测量、同次运行对照和跨运行最佳观察值；这几种统计分别保存。
- [证书链](data/证书链/)：后量子链验收、签发预算、负例与测试凭据。
- [功能测试](data/功能测试/)：协议回归、原语功能、建钥差分和篡改拒绝日志。

在仓库根目录复算正式原语数据，只需 Python 3.10 或更新版本的标准库：

```bash
python -I -X utf8 data/原语性能/核验性能数据.py
```

期望摘要为 `PASS`、38 组实现、57,114 个非预热样本、342 个原始文件。程序核对原始文件 SHA-256、返回码、有效性、尺寸、中位数及四分位数。[数据说明](data/README.md) 列出其他数据的解释方式及源码版本范围。

## 2. 安全性口径

- **已给出（有条件）**：在经典随机预言模型下给出 EUF-CMA 条件证明，依赖明示的 Rain 原语计算假设。另有 128 档设计评估。层级与 rFAEST 作者的安全声明相同，见 [完整安全证明](docs/Q4_03_security_proof.md)、[Rain-128 原语依据](docs/Q4_01_Rain128_primitive.md)、[验收报告](docs/Q4_02_acceptance.md)；证明引用的分稿、内部审查与复算记录见 [docs/Q4_records/](docs/Q4_records/README.md)（内部 AI 审查，非外部同行评审）。
- **未声称**：本仓库不声称“已证明 128 位安全”。严格的具体工作因子尚未建立，QROM、192／256 位档也未覆盖。Rain-3 的轮数余量小于 Rain-4，使用前请阅读原语依据中的风险说明。
- **未评估**：常数时间与侧信道。本实现是研究原型，不建议用于生产环境。

## 3. 一键验证

需要 x86-64 CPU，支持 AVX2、AES-NI 和 PCLMULQDQ（近十年的 Intel／AMD 桌面与服务器 CPU 一般都支持；Apple M 系列和 ARM 不支持）。

**方式一：Docker（推荐，Windows／macOS(Intel)／Linux 均可）**

```bash
git clone https://github.com/s1x-s1x/RainSwift.git && cd RainSwift
docker build -t rainswift .
docker run --rm rainswift
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
docker run --rm rainswift ./build/sign_demo "hello"
```

想在自己的项目中使用，可以把 `src/` 作为 Meson 子项目引入并依赖 `faest_dep`，随机源链接 `randomness_os_dep`。

**在自己机器上测速。** 下面的命令在同一进程内依次测量 Rain 六组以及同源码树编译的 rFAEST-EM-128f／128s，并输出比值。这只是便捷工具；正式数据与构建记录见 [data/README.md](data/README.md)；早期测量工具保存在 [docs/q3_scripts/](docs/q3_scripts/) 与 [docs/q5_scripts/](docs/q5_scripts/)。建钥各组件的新旧耗时可以用 `docker run --rm rainswift taskset -c 2 ./build/q5_kg_test --bench` 查看。

```bash
docker run --rm rainswift taskset -c 2 ./build/rain_bench 501
```

## 5. 目录

| 路径 | 内容 |
|---|---|
| `src/` | 源码（rFAEST 7a59c5c ＋ Rain 补丁，改动清单见 `src/RAIN_PATCHES.json`）；参数集在 `src/parameters.hpp` 的 `rain_sets` |
| `src/rain_q2_test.cpp` | T1–T8 测试 |
| `src/rain_kg.hpp`、`src/q5_kg_test.cpp` | 建钥专用的 Rain 正向计算（与原实现同一函数）及其差分测试、组件微基准 |
| `src/examples/`、`src/bench/` | 使用示例、便捷测速 |
| `KAT/` | 六组签名 KAT 与 SHA-256 |
| `docs/` | Q2 验收、Q4 安全证明、建钥实现说明与数据更新记录（中文） |
| `docs/Q4_records/` | Q4 证明引用的分稿、内部审查与复算记录（索引见其 README） |
| `data/` | 复赛支撑材料的新数据快照：原语性能、资源测量、协议时延、证书链与功能测试 |
| `tls/` | 混合 TLS 1.3 应用：团队前期的 v9 实现接入 RainSwift（见第 6 节） |
| `verify.sh`、`Dockerfile`、`.github/workflows/` | 一键验证与持续集成（`verify.yml`：Linux 上的算法验证；`tls-windows.yml`：Windows 上的 TLS 接入验证） |

## 6. TLS 1.3 应用（`tls/`）

`tls/` 是团队前期的混合 TLS 1.3 实现 v9，接入了本仓库的 RainSwift，作为握手中的后量子签名使用：

- **协议**：密钥协商用 X25519＋ML-KEM-768。认证时，ECDSA P-256 与 RainSwift 对同一个 CertificateVerify 输入各签一次，客户端要求两者都通过。X.509 叶证书的私有扩展携带 32 字节的 Rain 公钥。
- **改动范围**：v9 的握手、密钥协商、密钥调度和记录层都没有改。新增的是：
  - 原生库接口 `tls/native/rain_voleith/`，由本仓库 `src/` 编成 Windows DLL；
  - ctypes 后端 `tls/tls/pq/rain_voleith.py`；
  - 测试、已知答案关卡、演示与文档。

  说明见 [tls/docs/RAIN_VOLEITH.md](tls/docs/RAIN_VOLEITH.md)。
- **只含 RainSwift**：本仓库只发布我方算法的接入。六组参数的编号为 0xFEB0–0xFEB5。
- **验证**：GitHub Actions（`tls-windows.yml`）在 Windows 上依次完成：
  1. 用 MinGW-w64 GCC 构建生产版与测试版 DLL；
  2. 已知答案关卡 `tls/tools/rain_voleith_kat_gate.py`：经 DLL 逐字节复现六份签名 KAT，并核对建钥 KAT、负例、随机源失败和并发；
  3. 在要求 Rain 可用的设置下，运行 v9 全套测试；
  4. 运行演示。

**当前数据。** 新的握手数据、功能日志和证书链验收结果分别见 [协议时延](data/协议时延/)、[功能测试](data/功能测试/) 与 [证书链](data/证书链/)。协议时延保留各批次原始口径：进程内计时、握手记账字节和证书链功能验收分别解释；跨运行最佳观察值与同次运行对照分别读取。

**源码范围。** 本次更新数据及其说明。现有 `tls/` 仍是先前公开的 v9 Rain 接入版本；支撑材料中更新的 `tlsb/` 和离线 CA `a15/` 源码尚待同步。因此，新日志记录的是支撑材料对应版本的结果，完整的新功能复现还需同步相应源码。

**运行（Windows，x86-64-v3 加 AES-NI、PCLMULQDQ）**，在 `tls/` 目录中依次执行：

1. 构建 DLL，见 [tls/native/rain_voleith/README.md](tls/native/rain_voleith/README.md)。需要 MSYS2 UCRT64 GCC，以及 XKCP 的固定提交。
2. 安装锁定的依赖：`python -m pip install --require-hashes --only-binary :all: --target .deps -r requirements.lock.txt`。
3. 设 `PYTHONPATH=.deps`，然后运行：
   - 演示：`python demo/rain_voleith_demo.py`；
   - 测试：`RAIN_VOLEITH_REQUIRED=1 python -m pytest tests -q`。

**数据文件。** 早期 `docs/speed_data/`、TLS 基准输出与旧验收日志已从当前文件树删除。性能和验收结果统一从 [data/](data/README.md) 读取；原先的数据仍可在 Git 历史中查看。源码中的基准程序保留供重新采集使用。

## 7. 来源与许可

- 代码基于 [rFAEST](https://github.com/samsungsds-research-papers/rFAEST)（Samsung SDS，提交 `7a59c5c18b199bae427bd71d3b9fb5ea3f3b6d97`），rFAEST 又基于 FAEST 参考实现。按 MIT 许可证发布，版权声明见 [src/LICENSE](src/LICENSE)。
- SHAKE 使用 [XKCP](https://github.com/XKCP/XKCP)，固定在提交 `64404bee`。
- `tls/` 中的混合 TLS 1.3 实现 v9 是团队前期工作，原包未附许可证。
- `src/` 相对 Q2 验收源码的改动：`src/meson.build` 追加了 `sign_demo`、`rain_bench` 与 `q5_kg_test` 三个构建目标并新增这三个程序；Q5 新增 `src/rain_kg.hpp`，`src/faest_keys.inc` 中建钥（`faest_pubkey`）改调它（增 3 行、删 1 行）。协议字节由 KAT 比对保证不变。
