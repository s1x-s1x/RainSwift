# RainSwift 复现指南

版本 `v1.0.0-competition`。除标明 `cd` 的步骤外，命令从 `RainSwift/` 根目录运行。先核对数据，再验证原语、TLS 和 CA。初次构建需要联网；Python 模块各用独立虚拟环境。

## 1. 提交材料与统计

Python 3.10+ 标准库，Windows/Linux 均可：

```bash
python -I -X utf8 tools/check_submission.py --report ../submission-check.json
```

工具核对 1,282 个数据文件、568 个导入源码文件（含清单记录的适配和测试修复）、6 组 KAT、当前入口链接，再复算 38 组正式统计。预期 `status=PASS`、57,114 个非预热样本、342 份 JSONL。发布包还核对 `RELEASE_MANIFEST.json` 与 `SHA256SUMS.txt`；克隆副本使用数据和来源清单。

单独复算原语统计：

```bash
python -I -X utf8 data/原语性能/核验性能数据.py
```

## 2. 原语：Docker 或 Linux

CPU 需 x86-64、AVX2、AES-NI 和 PCLMULQDQ。Docker 使用本机 CPU 指令，ARM 环境请选用支持上述指令的 x86-64 主机。

```bash
docker build -t rainswift .
docker run --rm rainswift
docker run --rm rainswift ./build/sign_demo "hello"
```

Docker 使用 Debian trixie slim，安装 GCC、Meson、Ninja；XKCP 固定在 `src/subprojects/xkcp.wrap` 所列提交。系统包按构建时仓库安装，容器并非逐字节可重现构建。

本机 Linux 需要 GCC ≥14 或 Clang ≥19、Meson ≥1.4、Ninja、Python 3、Git：

```bash
bash verify.sh
```

通过信号：

```text
VERIFY PASS: T1-T8 passed, the key-generation differential test passed and all six signature KATs match byte-for-byte
```

T1–T8 包含尺寸、VOLE 关系、零输入拒绝、建钥重试、逐字节篡改拒绝、六组各 1,000 次往返、KAT 与随机数派生。建钥差分每类使用 2^20 组输入及构造案例，最后六组签名与 `KAT/` 逐字节比较。

C++ API 与缓冲区用法见 [sign_demo.cpp](../src/examples/sign_demo.cpp)。`src/` 可作 Meson 子项目，依赖 `faest_dep`，操作系统随机源链接 `randomness_os_dep`。便捷测速可执行 `docker run --rm rainswift ./build/rain_bench 501`；论文原始采集命令与环境见[构建记录](../data/原语性能/构建记录/)。

## 3. Windows TLS（PowerShell）

环境：Python 3.13、Git、MSYS2 UCRT64 GCC（示例路径 `C:/msys64/ucrt64/bin`），CPU 同原语要求。从仓库根目录开始，`xkcp/` 需为新目录：

```powershell
git init xkcp
git -C xkcp fetch --depth 1 https://github.com/XKCP/XKCP.git 64404beeeb261b08a1076fe2f076e4e28dd9b040
git -C xkcp checkout FETCH_HEAD
cd tls
python -m venv .venv
.venv/Scripts/python.exe -m pip install --require-hashes --only-binary=:all: -r requirements.lock.txt -r reference/requirements.lock.txt
.venv/Scripts/python.exe -I native/rain_voleith/build.py --gcc-bin C:/msys64/ucrt64/bin --rain-src ../src --xkcp-src ../xkcp --out build/native-rain --jobs 4
$env:RAIN_VOLEITH_LIB = (Resolve-Path build/native-rain/rain_voleith_tls.dll).Path
$env:RAIN_VOLEITH_REQUIRED = '1'
.venv/Scripts/python.exe -B -m pytest -q -rs -p no:cacheprovider tests
.venv/Scripts/python.exe -B demo/rain_voleith_demo.py
```

预期 pytest 退出 0、演示完成。`RAIN_VOLEITH_REQUIRED=1` 将缺少 Rain 库视为错误。可选 Falcon 提供方未装时，对应用例会跳过。完整 CI 另构建 `--test-hooks` DLL 并运行 KAT 门禁，精确命令见 [tls-windows.yml](../.github/workflows/tls-windows.yml)。两种 DLL 用途见[原生接口](../tls/native/rain_voleith/README.md)。

## 4. Linux TLS

先按上一步获取固定 XKCP。从 `tls/` 执行，需要 GCC/G++ ≥14、ar、Python 3.13 和 venv：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock.txt -r reference/requirements.lock.txt
bash native/rain_voleith/build_linux.sh "$(realpath ../src)" "$(realpath ../xkcp)" "$PWD/build/native-rain"
export RAIN_VOLEITH_LIB="$PWD/build/native-rain/librain_voleith_tls.so"
export RAIN_VOLEITH_REQUIRED=1
.venv/bin/python -B -m pytest -q -rs -p no:cacheprovider tests
.venv/bin/python -B demo/rain_voleith_demo.py
```

自动 TLS 全入口以 Windows 流程为验收环境，Linux 可按上述步骤自行运行。协议范围见 [CAPABILITIES.md](../tls/docs/CAPABILITIES.md)。

## 5. Linux 离线 CA

环境：Ubuntu 24.04 / Linux x86-64、Python 3.12 及 venv、GCC、make。`a15/base_tls/` 是直接依赖，随模块保留。从根目录执行：

```bash
cd a15
python3 -B ops/bootstrap_local_env.py --verify --falcon --jobs 4 --fixtures fixtures/public-alt-chain --output build/functional-check
```

每次使用尚未存在的输出目录。入口建立环境、按哈希锁安装依赖、构建 CPU 库，运行原生边界、预算、生命周期、解析器、TLS 回归、预签发链的原生/Python 双重验证与 P0–P4。输出 `manifest.json` 必须同时满足：

```json
{"passed": true, "functional_gate_completed": true}
```

也可从根目录使用模块容器（Linux shell）：

```bash
docker build -f a15/Dockerfile.repair -t rainswift-ca a15
mkdir -p ca-evidence
docker run --rm -v "$PWD/ca-evidence:/evidence" rainswift-ca
```

再次执行时使用新的证据目录。CUDA 项是模拟功能检查，真实 GPU 运行与性能采集见 [a15/README.md](../a15/README.md) 和各批次数据。

## 6. 固定版本证据

[四项工作流](https://github.com/s1x-s1x/RainSwift/actions)分别验证提交材料、原语、Windows TLS 和 Linux CA。Release 附件 `validation.json` 保存完整提交号及最终运行链接，本地提交包附同一记录和材料原始截图。截图按原批次解释。
