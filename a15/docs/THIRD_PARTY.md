# 第三方来源与证据说明

第三方代码保留原有版权、许可证及来源记录。

| 内容 | 来源/版本记录 | 许可证与用途 |
|---|---|---|
| SLH-DSA C 参考代码 | `https://github.com/slh-dsa/slhdsa-c`；原始提交 `2b111e076a3bf0b6041651cf8746acf5ade56cc7` | `third_party/slhdsa-c/LICENSE`，代码中的原始声明保留 |
| Python ACVP/FIPS205 参考代码 | `https://github.com/mjosaarinen/py-acvp-pqc`；原始提交 `1c859956c0217b04fa5ae76e338e5570aba622c5`；来源见 `reference/UPSTREAM.json` | `third_party/py-acvp-pqc/LICENSE`；本地受测修改随源码保存 |
| ACVP、xous、gmsm 外部向量 | `third_party/external_vectors/SOURCES.json`、`GMSM_SOURCE.json` 与 `reference/UPSTREAM.json` | 独立正确性输入，保留上游归档及声明 |
| CA链TLS组件 | `base_tls/README.md` 及对应协议文档 | 项目自有组件，保留来源声明 |
| TLS Python/PQ provider | `base_tls/requirements.lock.txt` 与 `requirements-falcon.lock.txt`；Falcon 独立 provider 为 pqcrypto 0.4.0 | 安装的 wheel 保留各自 METADATA/许可证；独立重命名包不替换主 ML-KEM/ML-DSA provider |
| Verifpal 符号验证工具 | 官方 `symbolicsoft/verifpal` v1.4.12；安装来源与原二进制哈希见 `third_party/verifpal-tool/installation-windows-1.4.12.json` | GPL-3.0，原 LICENSE 保存在 `third_party/verifpal-tool/LICENSE`；只用于独立模型验证，GitHub 不分发工具二进制 |

系统编译器、运行库及CUDA运行环境由复现环境提供，不作为项目源码分发。

参考源码和外部向量的具体 URL、提交及下载哈希以原始 JSON 来源记录为准。

## 验签调度的算法思想来源

`c/src/wots_schedule8.h` 的降序计数排序借鉴 SPHINCS+ 官方实现
`sha2-avx2/wots.c`（提交 `7ec789ace6874d875f4bb84cb61b81155398167e`）；
本项目自主编写 SM3 路径，没有粘贴上游函数。固定排序不是原创。
公开来源为 [固定提交的文件](https://github.com/sphincs/sphincsplus/blob/7ec789ace6874d875f4bb84cb61b81155398167e/sha2-avx2/wots.c)。
动态 SIMD 补位的一般思想参见
[Florian Wende 的 2015 年演讲](https://www.ixpug.org/docs/IXPUG_SC15_FlorianWende.pdf)。
本项目自主实现 SM3 路径的公开链长调度与跨树 FORS 组合；一般排序与动态 SIMD 调度思想已有。组合的学术新颖性未穷尽核验，不声称首次发明相关一般算法。实现原理见 `../c/src/WOTS_DESIGN.md`。
