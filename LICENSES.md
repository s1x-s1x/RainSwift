# 来源与许可范围

各组件所附许可证及版权声明为具体授权依据。

| 组件 | 来源与范围 |
|---|---|
| `src/` | [rFAEST](https://github.com/samsungsds-research-papers/rFAEST) 提交 `7a59c5c18b199bae427bd71d3b9fb5ea3f3b6d97`，含 FAEST 来源；MIT 原文见 [src/LICENSE](src/LICENSE)，Rain 改动见 [src/RAIN_PATCHES.json](src/RAIN_PATCHES.json) |
| XKCP | [XKCP](https://github.com/XKCP/XKCP)，构建获取固定提交 `64404beeeb261b08a1076fe2f076e4e28dd9b040`，各文件按上游授权读取 |
| `tls/`、`a15/` 团队代码 | 来自复赛支撑材料，原包没有团队应用代码的独立许可证；`src/LICENSE` 范围按原文读取 |
| CA 第三方代码与向量 | `a15/third_party/` 保留各自 LICENSE、来源及固定版本，见 [CA 说明](a15/README.md) |
| Python 依赖 | 锁文件固定版本与哈希，各包遵循各自许可证 |
| 数据与说明 | 来源及哈希见 [data/SNAPSHOT.json](data/SNAPSHOT.json)，授权范围按原始说明读取 |

测试证书、密钥 JSON 与预签发链为公开回归夹具。源码出处、原始哈希及适配/测试修复范围见 [源码来源清单](docs/source_snapshot_20261022.json)。
