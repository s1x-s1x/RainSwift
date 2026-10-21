# 结果与证据索引

本文把论文主题对应到公开实现和支撑材料。原始采样来自团队的复赛材料；本版整理与 CI 功能验证单列。

## 论文主题对应表

| 主题 | 实现 | 数据与论证 |
|---|---|---|
| 六组参数与尺寸 | [参数](../src/parameters.hpp)、[API](../src/api.hpp)、[示例](../src/examples/sign_demo.cpp) | [统计 JSON](../data/原语性能/性能统计.json)、[KAT](../KAT/) |
| Rain 与 VOLE 关系 | [Rain 实现](../src/rain_owf.hpp)、[测试](../src/rain_q2_test.cpp) | [原语依据](Q4_01_Rain128_primitive.md)、[安全证明](Q4_03_security_proof.md) |
| 建钥优化与等价性 | [优化实现](../src/rain_kg.hpp)、[差分测试](../src/q5_kg_test.cpp) | [组件说明](Q5_component_tests.md)、[功能测试](../data/功能测试/) |
| 原语对照性能 | [复算程序](../data/原语性能/核验性能数据.py)、[便捷基准](../src/bench/) | [38 组 CSV](../data/原语性能/性能统计.csv)、[原始 JSONL](../data/原语性能/raw/)、[构建记录](../data/原语性能/构建记录/) |
| 资源开销 | [资源测量快照](../data/资源测量/) | 独立探针的堆、栈、RSS、代码与常量记录 |
| 混合握手 | [TLS](../tls/README.md)、[原生接口](../tls/native/rain_voleith/README.md) | [协议时延](../data/协议时延/)、[功能测试](../data/功能测试/) |
| 证书链与签发预算 | [CA](../a15/README.md)、[功能入口](../a15/ops/bootstrap_local_env.py) | [证书链数据](../data/证书链/)、测试凭据及各批次 JSON |

## 数据口径

- 38 组正式实现采用完整 F3/S3 窗口对，每组 1,503 个非预热样本，合计 57,114 个、342 份 JSONL。每行建钥、签名与验签取同一窗口。
- 原语计时为 64 字节消息、CPU 单线程；构建选项按统计 JSON 读取。`rain_bench` 用于再次试跑，论文原始采集命令在数据构建记录中。
- 资源来自独立探针；协议同次运行对照与跨完整运行最佳观察值分别保留，使用各自环境和计量定义。
- 证书链完整配置有 36 项通过；RainSwift 配置有 29 项通过、7 项未覆盖。功能、签发预算和独立端到端耗时分别读取。
- 1,279 个原始数据文件保持字节一致。清单连同说明与来源元数据覆盖 1,282 个文件，见 [数据说明](../data/README.md)。

## 本版验证

| 流程 | 内容 | 证据 |
|---|---|---|
| `submission-check` | 数据 SHA-256、来源映射、KAT 文件、统计复算、入口链接；导出 ZIP 后再次核对全包 | JSON 报告、ZIP SHA-256 |
| `verify` | 构建、T1–T8、建钥差分、六组 KAT 逐字节匹配与示例 | 固定提交的日志 |
| `tls-windows` | 生产/测试 DLL、KAT 门禁、协议测试与演示 | 固定提交的日志 |
| `ca-linux` | CPU 库、Python 对照、15 步功能入口与 P0–P4 | `ca-functional-evidence` 中的 manifest、日志与 JUnit |

Release 的 `validation.json` 固定四项流程的提交号、运行链接与最终状态，本地提交包保留同一记录。主页徽章会随后续 `main` 更新。

整理前的提交 `6ca893713043fdac281deb712a3b1387b418c069` 已完成原语、TLS 和 CA 全部 CI：Windows TLS 542 通过、1 跳过；CA 的 TLS 回归 576 通过、1 跳过。过程见[源码同步记录](source_update_20261022.md)。本版结果以 Release 附件为准。

本版重跑功能、KAT 与数据复算。绝对性能仍是材料原采样；CA 功能入口中的 CUDA 项为模拟检查，真实 GPU 采样按材料解释。条件安全证明与 128 位档设计评估范围见[安全验收](Q4_02_acceptance.md)。内部审查保留原始性质。
