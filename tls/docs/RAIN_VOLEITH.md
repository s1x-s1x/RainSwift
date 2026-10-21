# RainSwift 接入说明

2026-10-16。

本目录的混合 TLS 1.3 实现（v9）是团队的前期工作。本次在 v9 上新增一个后量子签名后端 RainSwift，把它作为握手 CertificateVerify 中的后量子签名使用。v9 的握手流程、密钥协商、密钥调度和记录层都没有改动。

> 当前源码已同步支撑材料 `tlsb/`；另含严格替代 CA 链、DER、SLH-DSA-SM3 接口与验收工具，详见本目录 README。

## 1. 做了什么

- **签名方式**：服务器每次握手时，用 ECDSA P-256 和 RainSwift 同时签同一个 `M_CV`；客户端要求两个签名都通过才接受。
- **证书**：X.509 模式下，叶证书的私有扩展（OID 1.3.6.1.4.1.99999.1）携带 32 字节的 Rain 公钥。
- **方案编号**：取私有区编号，客户端与服务器选用的参数集不同时，在第一轮就会失败。
- **为什么适合每次握手现签**：RainSwift 是 VOLE-in-the-head 签名，构造是 rFAEST 证明系统加上 Rain 单向函数（GF(2^128) 上 3 轮或 4 轮），没有状态。快档与均衡档签发、验签都在亚毫秒级，所以每次握手都可以现签现验，不必像 XMSS 那样管理叶子。

| 名称 | 编号 | 公钥 B | 签名 B | 说明 |
|---|---|---|---|---|
| `rain3-fast` / `rain3-bal` / `rain3-short` | 0xFEB0 / 0xFEB1 / 0xFEB2 | 32 | 4146 / 3706 / 3014 | Rain 3 轮；附风险说明（轮数少，分析余量较小） |
| `rain4-fast` / `rain4-bal` / `rain4-short` | 0xFEB3 / 0xFEB4 / 0xFEB5 | 32 | 4112 / 4080 / 3190 | Rain 4 轮；稳妥的选择。演示默认用 `rain4-bal` |

XMSS 占用 0xFE00 + 树高（树高 1–32），与以上编号不重叠。

## 2. 新增与改动的文件

| 文件 | 内容 |
|---|---|
| `native/rain_voleith/` | 新增 C 接口：`rain_voleith_tls.h`、实现 `rain_voleith_tls_impl.hpp`、参数集表 `rain_voleith_tls.cpp`；另有平台层（随机源、CPU 检查）、Windows 兼容头、XKCP 配置、构建脚本 `build.py` 和说明 |
| `tls/pq/rain_voleith.py` | 新增 ctypes 后端，实现 `PqSigner`：缺库时失败即关闭；验签前先查长度、不抛异常；私钥绑定参数集 |
| `tls/pq/signature.py` | 登记：`_SCHEME_IDS` 加入 Rain 编号，`get_pq_signer` 和 `available_pq_signers` 认得新名称 |
| `tests/conftest.py` | 新增六个 Rain 配置；缺库时跳过相应用例；`RAIN_VOLEITH_REQUIRED=1` 时缺库判失败 |
| `tests/test_rain_voleith.py`、`tests/vectors/rain_voleith/` | 新增测试，以及 6 份公开签名 KAT（与仓库根目录 `KAT/` 中的文件相同） |
| `tools/rain_voleith_kat_gate.py` | 新增：原生库的已知答案关卡（生产版与测试版，见第 4 节） |
| `tools/audit_live_checks.py` | 在 `INTERFACE_METHODS` 中声明 `RainVoleith.verify/keygen/sign` |
| `.gitignore` | 加 `build/`（原生库的输出目录） |
| `demo/rain_voleith_demo.py` | 新增演示：X.509 握手 → 回环 TCP（数客户端阻塞次数）→ 篡改矩阵 |
| `README.md`、`docs/PROTOCOL.md`、`docs/SECURITY.md`、`docs/CAPABILITIES.md` | 补充后端矩阵、编号表、安全说明、能力矩阵 |

## 3. 构建与使用

1. 构建 DLL，见 `native/rain_voleith/README.md`。签名源码就是本仓库的 `src/`，XKCP 取 `src/subprojects/xkcp.wrap` 固定的提交。把 `rain_voleith_tls.dll` 放进 `build/`，或用环境变量 `RAIN_VOLEITH_LIB` 指向它。
2. 运行：
   - `python demo/rain_voleith_demo.py`：完整演示。
   - `python demo/run_handshake.py --pq rain4-bal`：v9 原有演示。加 `--tamper pq-signature` 可演示篡改被拒。
   - `python bench/measure_handshake.py --signers rain4-bal falcon-512 --x509`：测量。
3. 测试：`RAIN_VOLEITH_REQUIRED=1 python -m pytest tests -q`。

仓库的 GitHub Actions 在 Windows 上完成上述构建（生产版与测试版）、已知答案关卡与全套测试，见仓库根目录 `.github/workflows/tls-windows.yml`。

## 4. 正确性

- **调用路径**：原生库调用的是公开 KAT 所用的同一组函数（`crypto_sign_keypair` / `crypto_sign` / `crypto_sign_open` 的函数体）。
- **Windows 构建与 Linux 构建等价**：`tools/rain_voleith_kat_gate.py` 用测试版 DLL 的确定性随机源逐字节复现 6 份公开签名 KAT（sk、pk、sm），由私钥算出的公钥与建钥 KAT（含被拒绝的密钥）全部一致；另查负例、随机往返、随机源失败时输出清零、非法编号与多线程并发。
- **本目录测试**：每次运行都通过后端验证 6 份公开签名 KAT，并完成两种证书模式下的握手、篡改矩阵与参数集不匹配检查。

## 5. 当前测量数据

2026-10-22：本文件中的旧握手计时表和旧测量结论已删除。当前使用支撑材料数据：

- [原语正式统计](../../data/原语性能/性能统计.csv)
- [协议时延与同次运行对照](../../data/协议时延/)
- [证书链验收](../../data/证书链/)
- [功能测试日志](../../data/功能测试/)

各数据按原批次、构建与计量定义读取。进程内时间、握手记账字节及后量子证书链功能验收分别保存；跨运行最佳观察值与同次运行对照分别解释。材料版 TLS 与离线 CA 源码的同步范围见[数据说明](../../data/README.md#对应源码)。

## 6. 安全口径与限制

- **安全口径**：见 `docs/SECURITY.md` 末节。RainSwift 的 EUF-CMA 是条件证明（ROM 与理想密码，加上关于 Rain 单向函数的明示假设），与 rFAEST 作者的表述同一层级。不声称“已证明 128 位安全”，也没有 QROM 结论。
- **限制**：
  - 未评估常数时间与侧信道；
  - 私钥在 Python `bytes` 中，无法擦除；
  - 提供 Windows DLL 与 Linux 共享库构建脚本，均需匹配的 x86-64 指令集。
