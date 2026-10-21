# 文档索引

当前提交版本为 `v1.0.0-competition`，评审从 [SUBMISSION.md](../SUBMISSION.md) 开始。

## 当前说明

| 文档 | 用途 |
|---|---|
| [复现指南](REPRODUCE.md) | 环境、命令与验收信号 |
| [结果与证据索引](RESULTS.md) | 论文结果对应的实现、数据与范围 |
| [数据入口](../data/README.md) | 新快照、原始采样与统计口径 |
| [TLS 模块](../tls/README.md) | 依赖、测试与应用演示 |
| [CA 模块](../a15/README.md) | 离线签发、原生/Python 对照与功能入口 |
| [组件许可](../LICENSES.md) | 来源、版权及授权范围 |

## 算法设计与验证依据

| 文档 | 内容 |
|---|---|
| [Q2 验收](Q2_acceptance.md) | 六组参数及 T1–T8 |
| [Rain-128 原语依据](Q4_01_Rain128_primitive.md) | 假设、轮数与余量 |
| [安全验收](Q4_02_acceptance.md) | 证明与评估范围 |
| [完整条件安全证明](Q4_03_security_proof.md) | 经典随机预言模型中的 EUF-CMA 条件论证 |
| [建钥优化分析](Q5_analysis.md) / [组件测试](Q5_component_tests.md) | 实现思路、等价性与测量解释 |
| [TLS 能力说明](../tls/docs/CAPABILITIES.md) | 实验协议能力与边界 |

## 来源与开发记录

| 记录 | 内容 |
|---|---|
| [数据更新](data_update_20261022.md) | 快照来源、旧数据清理与复算 |
| [源码同步](source_update_20261022.md) | 路径映射、适配、Windows 测试修复与既有验证 |
| [逐文件来源](source_snapshot_20261022.json) | 568 个导入文件及明确列出的适配哈希 |
| [证明引用材料](Q4_records/README.md) | 分稿、内部审查、复算和采用情况；内部 AI 审查的性质按原记录 |
| [早期测量脚本](q3_scripts/) / [建钥测量脚本](q5_scripts/) | 开发期工具；正式数据入口为 `data/` |
| [建钥优化计划](Q5_plan.md) | 开发期计划与决策 |

Q2/Q4/Q5 为开发阶段标签。原文保留日期、术语和证据状态；当前阅读、复现与数据入口按本文。
