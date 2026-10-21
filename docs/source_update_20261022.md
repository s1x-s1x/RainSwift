# RainSwift（雨燕）复赛源码同步记录

日期：2026-10-22。名称与数据更新提交 `2267574` 之后，补齐支撑材料中的新版源码。

## 来源与目录

来源为团队提供的 `CACR2026RO5FCA-2026密码竞赛复赛相关支撑材料(1).zip`，SHA-256：

```text
43635e3204ed3dc429d5b29a55199743a0415fc80fa73af033adebbbd34ddf05
```

| 支撑材料中的路径 | 仓库路径 | 同步内容 |
|---|---|---|
| `02_程序与测试源码/tlsb/` | `tls/` | 146 个文件；30 个新增、17 个更新、99 个与此前版本相同。含严格替代链、DER、SLH-DSA-SM3 接口、验收工具、新回归测试、Linux 构建脚本及 FAEST 对照接口。 |
| `02_程序与测试源码/a15/` | `a15/` | 421 个文件；含离线 CA 的 REF/AVX2/OpenMP/CUDA 源码、Python 对照、预算与生命周期工具、向量、第三方来源与许可、公开测试链。 |
| `02_程序与测试源码/rain-voleith/src/test/kat_gen.cpp` | `src/test/kat_gen.cpp` | 补齐 KAT 生成程序。已有共有原语源码与支撑材料一致。 |

共核对 568 个材料文件。逐文件原始哈希、目录映射及 5 处 Markdown 适配记录见 [source_snapshot_20261022.json](source_snapshot_20261022.json)。除这些文档适配外，导入文件保持材料中的原始字节。文档适配包括 RainSwift 名称、仓库相对路径、构建入口及历史范围注释；此前已清理的旧计时表保持清理状态。

`a15/base_tls/` 被 CA 工具直接导入并用于回归，随模块保留。第三方向量、许可证、来源说明及固定版本一起发布。XKCP 延用 `src/subprojects/xkcp.wrap` 的固定提交，由构建流程获取。生成的动态库、虚拟环境、依赖安装目录与临时测试输出由忽略规则排除。

公开夹具中的私钥用于随材料发布的测试链，使用说明保留在夹具目录。它们仅用于这些公开回归案例。

## 本地检查

- 以哈希锁安装 TLS 主依赖及独立参考依赖。
- Windows / Python 3.13 的 TLS 测试首次运行：474 通过、61 跳过、1 失败，共 536 项。失败源于本地深层工作目录超过 Windows 传统路径长度限制。
- 对该缓存元数据测试使用 Win32 扩展路径表示重新运行：1 通过；被测源码未作修改。合计 475 个用例通过，61 个跳过。
- 60 个 Rain 原生库相关用例因本地 DLL 缺失而跳过；1 个 Falcon 用例因可选提供方缺失而跳过。这些结果不代表原生接入已在该次本地运行中完成验证。
- 当前机器的 MinGW 编译后端缺少运行依赖，Windows 本地 DLL 构建未完成。容器拉取和软件包安装也遇到网络解析错误；离线 CA 全入口由下述 Linux CI 检查。
- 使用已有 Debian / GCC 14 容器执行 `tls/native/rain_voleith/build_linux.sh`，成功构建 Linux 共享库；SHA-256 为 `6ace0f795ce59880dcafecc64abd6efd64e004c68eb66e5abdc9bd6bd43edeb5`。构建检查与协议运行检查分别记录。
- 原始性能数据沿用材料，不以本次检查重新采样或替换。

## 持续集成

本次推送触发的检查结果以 [GitHub Actions](https://github.com/s1x-s1x/RainSwift/actions) 的对应提交为准：

| 流程 | 验证内容 |
|---|---|
| `verify` | Linux 构建、算法 T1–T8、六组签名 KAT、使用示例。 |
| `tls-windows` | 从公开源码构建生产版与测试版 DLL；KAT 门禁、要求 Rain 可用的协议测试及演示。主依赖和独立参考依赖均使用哈希锁安装。 |
| `ca-linux` | Python 3.12 / Ubuntu 24.04，执行 `a15/ops/bootstrap_local_env.py --verify --falcon --fixtures fixtures/public-alt-chain`；保存逐步骤日志、JUnit 和清单。 |

CA 入口包含原生库构建、边界与调度测试、预算及生命周期工具、解析器模糊输入、TLS 回归、预签发链的原生/Python 双重验证、P0–P4 功能检查。`manifest.json` 的 `passed` 与 `functional_gate_completed` 同为 `true` 才表示该次入口完成。CUDA 检查在该入口中为模拟测试，真实 GPU 运行及论文性能采样另行验收。

## 与数据的关系

[data/](../data/README.md) 中 1,279 个原始文件仍保持支撑材料字节。仅更新数据目录说明、来源元数据与相应 SHA-256 清单，说明当前源码已同步。历史日志按各自运行环境与构建解释；本次源码导入和 CI 结果单独记录。

项目对外名称统一为 **RainSwift（雨燕）**。内部 `rain_voleith` 文件名、动态库名、API 与环境变量保留兼容标识。
