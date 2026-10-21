# SLH-DSA-SM3 离线CA实现

本目录提供SLH-DSA-SM3原生实现、独立Python对照、公开测试向量、预签发测试CA链及验证程序。

| 目录或文件 | 功能 |
|---|---|
| `c/` | REF、AVX2、OpenMP及显式CUDA后端 |
| `reference/` | Python参考实现、差分程序与测试数据 |
| `base_tls/` | 当前CA链工具直接导入的TLS模块与测试 |
| `fixtures/public-alt-chain/` | 公开测试凭据、签发信息及逐文件散列 |
| `vectors/`、`third_party/` | 测试向量、固定依赖及许可证 |
| `tools/` | 原生接口、预算、差分、协议和验收测试 |
| `ops/bootstrap_local_env.py` | 隔离环境、依赖安装、构建及功能复现入口 |

在Linux x86-64、Python3.12、gcc、make及venv环境，从本目录执行：

```sh
python3 -B ops/bootstrap_local_env.py --verify --falcon --jobs 4 --fixtures fixtures/public-alt-chain --output build/functional-check
```

输出目录须不存在。主入口构建CPU库并运行功能测试；其中CUDA续跑检查为模拟检查，不能计为CUDA设备验收。该命令即可运行随仓库发布的完整 CPU 功能入口。依赖的版本与文件哈希由 `base_tls/requirements.lock.txt` 和 `reference/requirements.lock.txt` 固定；Falcon 使用独立锁与安装记录。

`base_tls/`是当前程序的导入和回归测试依赖，应随本目录保存。公开fixture中的密钥仅用于测试；重放采用`verify`，有限预算CA签发使用独立账本。材料中的测试记录见仓库 [data/](../data/README.md)，源码来源见 [同步记录](../docs/source_update_20261022.md)。

## 容器复现

从仓库根目录运行；镜像使用固定摘要的 Ubuntu 24.04。`ca-evidence/functional` 须为新目录：

```sh
docker build -f a15/Dockerfile.repair -t rainswift-ca a15
mkdir -p ca-evidence
docker run --rm -v "$PWD/ca-evidence:/evidence" rainswift-ca
```

原生库、依赖环境、逐步骤日志、源码与夹具哈希写入输出目录。`manifest.json` 的 `passed` 和 `functional_gate_completed` 均为 `true` 才表示该次入口完成；跳过项和模拟检查另列。该入口不重采论文性能数据。
