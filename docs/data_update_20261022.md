# 2026-10-22 复赛数据替换记录

## 名称同步

论文中的算法名称为 **RainSwift（雨燕）**。GitHub 仓库更名为 `s1x-s1x/RainSwift`，首页、当前使用文档和克隆地址同步更新；Docker 镜像名称为 `rainswift`。源码中的 `rain_voleith` 文件名、接口、环境变量及历史记录保留其原始标识。

## 来源与范围

- 仓库：[s1x-s1x/RainSwift](https://github.com/s1x-s1x/RainSwift)。
- 更新基线：`3a4c58290d7821db13d454a0d425c5f1c2f02e17`。
- 来源：团队提供的 `CACR2026RO5FCA-2026密码竞赛复赛相关支撑材料(1).zip`。
- 原始压缩包 SHA-256：`43635e3204ed3dc429d5b29a55199743a0415fc80fa73af033adebbbd34ddf05`。
- 将支撑材料 `03_测试数据/` 映射至仓库 `data/`，完整导入 **1,279 个原始文件、129,757,903 字节**；文件名、目录和字节保持一致。
- 另附原始 `01_配套文档/测试数据说明.md`，并新增入口说明、来源元数据和完整 SHA-256 清单。

| 原始数据类别 | 文件数 | 字节数 |
|---|---:|---:|
| `功能测试` | 11 | 203,164 |
| `协议时延` | 7 | 2,781,487 |
| `原语性能` | 354 | 21,221,213 |
| `实验环境.json` | 1 | 2,161 |
| `证书链` | 113 | 674,075 |
| `资源测量` | 793 | 104,875,803 |

## 已完成的替换

1. 首页性能表改用正式 F3/S3 窗口数据，六组 RainSwift 的建钥、签名、验签中位数及签名尺寸均来自新 `性能统计.json`。
2. 首页与 TLS 文档的数据入口改为原语性能、资源测量、协议时延、证书链和功能测试五类材料。
3. 删除下列 **33 个旧数据、旧性能报告和旧验收输出文件**；源码中的测量工具仍可用于再次采集。
4. 建钥实现说明移除旧的耗时与估算表；历史计划和协议审查文件加注版本说明。
5. `data/**` 保留原始字节，不做 Git 换行转换；Docker 构建上下文排除数据快照。
6. TLS 的临时基准输出与验收日志加入忽略规则，避免后续误将旧路径下的生成结果作为当前数据提交。

删除清单：

- `docs/Q3_benchmark_report.md`
- `docs/Q5_keygen_report.md`
- `docs/Q5_summary_tables.md`
- `docs/speed_data/README.md`
- `docs/speed_data/laptop_tls.csv`
- `docs/speed_data/server_primitives.csv`
- `tls/.bench-lifecycle-quick/xmss_lifecycle.json`
- `tls/.bench-lifecycle-quick/xmss_lifecycle.md`
- `tls/.bench-lifecycle/xmss_lifecycle.json`
- `tls/.bench-lifecycle/xmss_lifecycle.md`
- `tls/.bench-out/README_U03_HISTORY.md`
- `tls/.bench-out/handshake.md`
- `tls/.bench-out/primitives.md`
- `tls/.bench-out/shaped.md`
- `tls/.bench-out/tcp.md`
- `tls/.bench-u03/handshake.json`
- `tls/.bench-u03/handshake.md`
- `tls/.bench-u03/primitives.json`
- `tls/.bench-u03/primitives.md`
- `tls/validation/baseline-pytest.txt`
- `tls/validation/environment-independent.json`
- `tls/validation/environment.json`
- `tls/validation/final-pytest.txt`
- `tls/validation/handshake.txt`
- `tls/validation/live-checks.txt`
- `tls/validation/patch-check.txt`
- `tls/validation/primitives.txt`
- `tls/validation/summary.json`
- `tls/validation/v9-lifecycle.md`
- `tls/validation/v9-locks.txt`
- `tls/validation/v9-pytest-author.txt`
- `tls/validation/v9-pytest-independent.txt`
- `tls/validation/v9-sweep.txt`

## 核验结果

| 检查 | 结果 |
|---|---|
| 导入文件与解压后的原始文件逐字节比较 | 1,279 / 1,279 一致 |
| 对照支撑材料自带 SHA256SUMS.txt | 1,279 / 1,279 一致 |
| 正式原语统计复算 | PASS：38 组实现、57,114 个非预热样本、342 份 JSONL |
| 返回码、有效性、消息和密钥尺寸、实际签名字节 | 核验程序检查通过 |
| 中位数及四分位数 | 核验程序检查通过 |

复算命令（仓库根目录，Python 3.10+，仅标准库）：

```bash
python -I -X utf8 data/原语性能/核验性能数据.py
```

新 `data/SHA256SUMS.txt` 对 `data/` 下除清单自身以外的所有文件计算 SHA-256。在 Linux/macOS 下执行：

```bash
cd data
sha256sum -c SHA256SUMS.txt
```

上述核验复算已有样本。本次未重新采集性能数据，亦未重新运行协议功能或证书链测试；相应日志原样来自团队材料。

## 数据解释与源码版本

- 正式原语主表为 6 组 RainSwift 加 32 组对照；保留整对 F3/S3 窗口，未按单元格选择最小值。
- 资源测量使用独立探针构建，与原语计时分别解释；协议时延、证书链验收及签发预算也分别读取。
- 材料提供方的 `实验环境.json` 与各原始批次中的工具链、历史环境字段均原样保留；原始日志本身不独立证明宿主平台归属。
- 证书链测试凭据中的 PEM、DER 和密钥 JSON 是公开测试夹具，保留以支持复核。
- 本次只替换数据和文档。原语共有源码与支撑材料一致；当前公开 `tls/` 仍为此前的 v9 Rain 接入，支撑材料中的更新版 `tlsb/` 与离线 CA `a15/` 源码尚待同步。新日志对应材料版本，完整复现这些新功能还需相应源码。
- 旧数据已从当前文件树删除，Git 历史保留原版本。
