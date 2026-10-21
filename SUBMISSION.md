# RainSwift 复赛提交与评审指南

| 项目 | 固定信息 |
|---|---|
| 作品编号 | `CACR2026RO5FCA` |
| 算法名称 | RainSwift（雨燕） |
| 版本 | `v1.0.0-competition`，整理日期 2026-10-22 |
| 仓库 | [s1x-s1x/RainSwift](https://github.com/s1x-s1x/RainSwift) |
| 元数据 | [submission.json](submission.json) |
| 固定版本 | [Release](https://github.com/s1x-s1x/RainSwift/releases/tag/v1.0.0-competition)；包内 `RELEASE_MANIFEST.json` 给出完整提交号 |

## 交付内容

GitHub 发布包包含 `src/`、`tls/`、`a15/`、`KAT/`、`data/`、文档与复现工具。`data/` 是本次支撑材料的新数据快照。

本地比赛提交包的 `01_作品设计报告/` 放最终论文 PDF，`02_程序与测试数据/RainSwift/` 放完整仓库，补充截图与本次验证记录单列保存。论文不进入 GitHub 发布文件。

解压后保留完整 `RainSwift/` 目录，从该目录运行命令。Windows 建议使用较短路径，例如 `C:\RainSwift`，避免深层缓存触及旧版工具的路径长度限制。首次构建需要联网安装锁定依赖并获取固定版本 XKCP；包中不含编译器、虚拟环境或预编译库。

## 建议评审顺序

1. 阅读最终论文、[首页参数表](README.md#算法与参数)和[结果索引](docs/RESULTS.md)。
2. 执行 `python -I -X utf8 tools/check_submission.py`，核对数据、KAT、源码来源并复算统计。
3. 按[复现指南](docs/REPRODUCE.md)运行原语、Windows TLS 和 Linux CA。
4. 按[文档索引](docs/README.md)核查安全证明、验收记录与引用材料。

## 验收标准

| 项目 | 通过信号 |
|---|---|
| 材料完整性 | `check_submission.py` 返回 0、`status=PASS`；发布 ZIP 同时核对全包清单 |
| 数据复算 | 38 组实现、57,114 个非预热样本、342 份 JSONL |
| 原语 | `verify.sh` 输出 `VERIFY PASS`，T1–T8、建钥差分与六组 KAT 通过 |
| Windows TLS | 生产/测试 DLL 构建、KAT 门禁、要求 Rain 库可用的协议测试与演示通过 |
| Linux CA | `manifest.json` 中 `passed=true` 且 `functional_gate_completed=true` |

固定提交的运行链接与最终状态保存在 Release 附件 `validation.json`。历史红色失败运行保留用于追溯；判断本版时请匹配完整提交号。

原始数据保留其采集环境、窗口与统计口径。本版 CI 验证相应功能；论文中的耗时、资源与 GPU 结果仍来自各批次原始采样。CA 全入口的 CUDA 项是模拟检查。测试链及密钥为公开回归夹具。

`docs/Q2_*`、`docs/Q4_*`、`docs/Q5_*` 是开发阶段编号；证明引用的内部 AI 审查保留其性质说明。当前阅读入口为本文和 `docs/README.md`。

## 维护者重新打包

提交更改、确保工作区干净后运行：

```bash
python -I -X utf8 tools/package_release.py --output ../RainSwift-v1.0.0-competition.zip
```

工具只导出当前已提交的 Git 文件，生成完整提交号及逐文件 SHA-256。核对包、等待同一提交的四项 CI 通过后，再建立固定标签、上传附件。解压副本可直接运行核对工具，无需 `.git/`。
