# RainSwift（雨燕）

基于 Rain 单向函数与 VOLE-in-the-Head 的后量子数字签名研究原型，包含六组参数、混合 TLS 接入和 SLH-DSA-SM3 离线 CA。

[![submission-check](https://github.com/s1x-s1x/RainSwift/actions/workflows/submission-check.yml/badge.svg?branch=main)](https://github.com/s1x-s1x/RainSwift/actions/workflows/submission-check.yml)
[![verify](https://github.com/s1x-s1x/RainSwift/actions/workflows/verify.yml/badge.svg?branch=main)](https://github.com/s1x-s1x/RainSwift/actions/workflows/verify.yml)
[![tls-windows](https://github.com/s1x-s1x/RainSwift/actions/workflows/tls-windows.yml/badge.svg?branch=main)](https://github.com/s1x-s1x/RainSwift/actions/workflows/tls-windows.yml)
[![ca-linux](https://github.com/s1x-s1x/RainSwift/actions/workflows/ca-linux.yml/badge.svg?branch=main)](https://github.com/s1x-s1x/RainSwift/actions/workflows/ca-linux.yml)

**2026 密码竞赛复赛提交版：`v1.0.0-competition` · 作品编号 `CACR2026RO5FCA`**

| 入口 | 内容 |
|---|---|
| [提交与评审指南](SUBMISSION.md) | 阅读顺序、交付内容与验收标准 |
| [固定版本下载](https://github.com/s1x-s1x/RainSwift/releases/tag/v1.0.0-competition) | 源码、数据、校验清单及本版验证记录 |
| [复现指南](docs/REPRODUCE.md) | 数据复算、算法、Windows TLS 和 Linux CA |
| [结果与证据索引](docs/RESULTS.md) | 论文结果对应的代码与原始数据 |
| [文档索引](docs/README.md) | 设计、安全证明、模块说明与开发记录 |

GitHub 发布代码、测试夹具和数据。最终论文 PDF 随本地比赛提交包提供。发布包中的 `RELEASE_MANIFEST.json` 记录完整 Git 提交号，`SHA256SUMS.txt` 覆盖包内文件。首页徽章反映 `main` 最新运行，固定版本以 Release 所附验证记录为准。

## 快速开始

只需 Python 3.10+ 标准库，在仓库根目录核对材料并复算原语统计：

```bash
python -I -X utf8 tools/check_submission.py
```

通过时报告 `PASS`、1,282 个数据文件哈希、568 个导入源码文件、6 组 KAT，以及 38 组实现、57,114 个非预热样本、342 份 JSONL 的统计复算。完整算法与协议运行按[复现指南](docs/REPRODUCE.md)执行。

使用 Docker 编译验证算法（x86-64，需 AVX2、AES-NI、PCLMULQDQ）：

```bash
git clone --branch v1.0.0-competition https://github.com/s1x-s1x/RainSwift.git
cd RainSwift
docker build -t rainswift .
docker run --rm rainswift
docker run --rm rainswift ./build/sign_demo "hello"
```

构建需要网络获取依赖。成功输出 `VERIFY PASS`，表示 T1–T8、建钥差分和六组签名 KAT 通过。

## 算法与参数

RainSwift 基于 [rFAEST](https://github.com/samsungsds-research-papers/rFAEST) 固定提交 `7a59c5c18b199bae427bd71d3b9fb5ea3f3b6d97`，将单向函数替换为 Rain-3 / Rain-4，并优化建钥中的正向计算。VOLE、承诺与哈希沿用该实现。建钥优化通过逐位差分检查，协议输出通过确定性 KAT 核对。

下表来自支撑材料中 **F3/S3 完整窗口对**的中位数：AMD EPYC 7773X、Ubuntu 20.04.5、64 字节消息、CPU 单线程。公钥与打包私钥均为 32 B。编译组选项、四分位数与原始样本见[性能统计 JSON](data/原语性能/性能统计.json)。

| 论文名称 | 源码参数 | 签名 / B | 建钥 / µs | 签名 / ms | 验签 / ms | 窗口 |
|---|---|---:|---:|---:|---:|---|
| RainSwift-3f | `rain3_fast` | 4,146 | 1.63 | 0.19383 | 0.19879 | F3 |
| RainSwift-3b | `rain3_bal` | 3,706 | 1.56 | 0.35144 | 0.32403 | F3 |
| RainSwift-3s | `rain3_short` | 3,014 | 1.59 | 2.55532 | 2.01242 | S3 |
| RainSwift-4f | `rain4_fast` | 4,112 | 1.74 | 0.30483 | 0.28281 | F3 |
| RainSwift-4b | `rain4_bal` | 4,080 | 1.74 | 0.31765 | 0.26608 | F3 |
| RainSwift-4s | `rain4_short` | 3,190 | 1.75 | 2.58270 | 2.03576 | S3 |

正式原语集合为 6 组 RainSwift 与 32 组对照，每组 1,503 个非预热样本。当前数据统一入口为 [data/](data/README.md)。

## 代码结构

| 路径 | 内容 |
|---|---|
| [src/](src/) | 签名实现、参数、建钥优化、示例与测试；差异清单为 `src/RAIN_PATCHES.json` |
| [KAT/](KAT/) | 六组确定性签名已知答案及 SHA-256 |
| [tls/](tls/README.md) | 在线签名、混合握手、严格替代 CA 链验证及回环 TCP |
| [a15/](a15/README.md) | SLH-DSA-SM3 离线 CA、独立 Python 对照、向量与预签发链 |
| [data/](data/README.md) | 原语性能、资源测量、协议时延、证书链和功能测试 |
| [docs/](docs/README.md) | 当前说明、设计与安全论证、来源和开发记录 |
| [tools/](tools/) | 提交材料核对与固定提交打包 |

论文统一使用 **RainSwift（雨燕）**；`rain_voleith`、`faest` 等内部名称、API 和环境变量保留兼容标识。支撑材料 `tlsb/` 对应仓库 `tls/`。`a15/base_tls/` 是 CA 工具的直接依赖。

## 证据范围与许可

安全论证采用经典随机预言模型中的 EUF-CMA 条件证明，依赖明示的 Rain 原语计算假设。128 位档属于设计评估；严格的具体工作因子、QROM、192/256 位档及侧信道评估尚未完成。范围见[安全证明](docs/Q4_03_security_proof.md)与[原语依据](docs/Q4_01_Rain128_primitive.md)。本项目为研究原型。

混合协议使用实验码点、OID 与分帧，见 [TLS 能力说明](tls/docs/CAPABILITIES.md)。CA 功能入口中的 CUDA 项是模拟检查，真实 GPU 测量按材料单独读取。历史测量与本版功能验证分别记录在[结果索引](docs/RESULTS.md)。各组件许可见 [LICENSES.md](LICENSES.md)。

**English summary.** RainSwift is a research signature prototype built from Rain-3/Rain-4 and rFAEST, with six parameter sets, a hybrid TLS harness and an offline SLH-DSA-SM3 CA. This competition release includes source, known-answer tests and supporting data. Start with [SUBMISSION.md](SUBMISSION.md); detailed documentation is in Chinese.
