# RainSwift（雨燕）混合认证应用

本目录对应复赛支撑材料的 `02_程序与测试源码/tlsb/`，已同步实现、测试与依赖。RainSwift 的内部接口、动态库及环境变量继续使用 `rain_voleith` 标识。离线 CA 模块位于相邻的 [a15/](../a15/README.md)。

包含混合密钥协商、经典与后量子双 CertificateVerify 签名、严格替代 CA 链验证、记录保护、应用数据、exporter、回环 TCP、测试与验收工具。协议范围见 [CAPABILITIES](docs/CAPABILITIES.md)。

## 依赖

在本目录中创建隔离环境并安装固定版本：

```sh
python -m venv .venv
# Linux/macOS: .venv/bin/python; Windows: .venv/Scripts/python.exe
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock.txt -r reference/requirements.lock.txt
```

以下 Python 命令均使用该隔离环境。Falcon 是单独的可选提供方，依赖锁为 `requirements-falcon.lock.txt`；主依赖提供 ML-KEM、ML-DSA，RainSwift 需要下述原生库。

## RainSwift 原生库

XKCP 使用仓库 `src/subprojects/xkcp.wrap` 固定的提交。从本目录准备依赖：

```sh
git init ../xkcp
git -C ../xkcp fetch --depth 1 https://github.com/XKCP/XKCP.git 64404beeeb261b08a1076fe2f076e4e28dd9b040
git -C ../xkcp checkout FETCH_HEAD
```

Windows 安装 MSYS2 UCRT64 GCC，从本目录执行：

```powershell
python native/rain_voleith/build.py --gcc-bin C:/msys64/ucrt64/bin --rain-src ../src --xkcp-src ../xkcp --out build/native-rain --jobs 4
$env:RAIN_VOLEITH_LIB = (Resolve-Path build/native-rain/rain_voleith_tls.dll).Path
$env:RAIN_VOLEITH_REQUIRED = '1'
python -B -m pytest -q -rs -p no:cacheprovider tests
python -B demo/rain_voleith_demo.py
```

Linux x86-64（GCC 14+、G++、ar，CPU 支持 AVX2、AES-NI、PCLMULQDQ）：

```sh
bash native/rain_voleith/build_linux.sh "$(realpath ../src)" "$(realpath ../xkcp)" "$(pwd)/build/native-rain"
export RAIN_VOLEITH_LIB="$PWD/build/native-rain/librain_voleith_tls.so"
export RAIN_VOLEITH_REQUIRED=1
python -B -m pytest -q -rs -p no:cacheprovider tests
python -B demo/rain_voleith_demo.py
```

生产版不导出 KAT 测试钩子。Windows CI 另构建测试版，经 `tools/rain_voleith_kat_gate.py` 复现签名 KAT、建钥 KAT、负例、随机源失败与并发。详细参数见 [native/rain_voleith/README.md](native/rain_voleith/README.md)。

## 目录与数据

| 路径 | 功能 |
|---|---|
| `tls/` | 握手、DER、替代链、原生签名适配和记录层 |
| `native/rain_voleith/`、`native/faest_suite/` | RainSwift 与 FAEST 对照签名库接口、构建程序 |
| `reference/`、`third_party/` | Python 对照、固定依赖、第三方许可 |
| `tests/` | 协议、DER、恢复、验收契约和 RainSwift KAT 回归 |
| `tools/ds_acceptance.py` | 严格替代证书链的功能验收驱动；参数见 `--help` |
| `tools/alt_chain_fixtures.py`、`tools/signing_budget.py` | 测试链与签发预算工具 |
| `demo/`、`bench/` | 演示和新采样工具 |

公开测试夹具和完整离线 CA 构建入口见 [a15/](../a15/README.md)。实验数据统一读取 [data/](../data/README.md)；原始测量与本次源码同步的检查记录分别保存，见 [源码同步记录](../docs/source_update_20261022.md)。
