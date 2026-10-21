# 替代 CA 链接口与约束

本文说明包内替代 CA 链的实现接口。当前复现与结果入口见上层 `README.md` 及本包测试证据索引。

## 实现接口

`base_tls/tls/der.py` 提供有长度上限的 DER TLV 遍历器，检查最短长度编码、截断、重复扩展 OID、AlgorithmIdentifier 参数省略及公钥/签名 BIT STRING 的零未用位。`pre_tbs()` 按 TBSCertificate 结构删除 `signature` 字段与扩展 `2.5.29.74`，保留 `2.5.29.73`，逐字节复制其他字段，只重新编码受影响的外层长度。测试覆盖 127/128、255/256、65535/65536 边界。

`base_tls/tls/pq/slhdsa_sm3.py` 提供轻量构造的 `SlhDsaSm3`：C/ctypes 生成密钥和签名，C 库缺失时通过独立 Python 模型验签。`SLHDSA_SM3_LIB` 选择库，签名空 context；公钥/私钥长度为 32/64 B。签名长度依次为 7856、17088、3856 B，方案号依次为 `0xFEA0`、`0xFEA1`、`0xFEA2`。构造函数不生成树或密钥；长度错误在进入 C 之前返回失败。128-24 的 TLS CertificateVerify 配置和显式凭据注入均被拦截，它仅用于离线 CA 签发。

`base_tls/tls/alt_chain.py` 实现经典路径验证完成后的逐边替代签名验证，以及固定序列号/有效期的两遍证书构建：草稿先含 73，计算 preTBS，PQ 签名，添加 74 后重新进行 ECDSA 签名，最后检查两次 preTBS 字节一致。

| 扩展 | OID | 本实现编码与位置 |
|---|---|---|
| subjectAltPublicKeyInfo | 2.5.29.72 | DER SPKI；根与中间 CA |
| altSignatureAlgorithm | 2.5.29.73 | DER AlgorithmIdentifier，无参数；中间 CA 与叶 |
| altSignatureValue | 2.5.29.74 | DER BIT STRING；中间 CA 与叶 |

三个扩展均为非关键扩展。SLH-SM3 算法 OID 使用实验私有标识 `1.3.6.1.4.1.99999.2.1/.2/.3`；ML-DSA44 使用 `2.16.840.1.101.3.4.3.17`。叶自身的握手 PQ 公钥继续使用原有 `99999.1` 扩展；CA 替代签名算法与 CertificateVerify 算法分别配置。

兼容策略允许某条边完全没有 72/73/74；已出现的部分扩展、OID 不匹配、异常长度或失败签名均被拒绝。`require_alt_chain=True` 要求每条边完整验签，且本地信任根具有 72。根 PQ 公钥从调用方独立提供的精确本地根证书读取；同名、同序列号或相同经典公钥的其他证书均不替代该信任根。Peer 可附带字节完全一致的根，该项在替代路径中跳过。

## 离线夹具和预算

`tools/alt_chain_fixtures.py` 提供 `generate`、`verify`、`e1`。生成阶段共用经典根/中间/叶密钥及握手凭据，分别构建真实 SM3-128-24、SM3-128s、ML-DSA44 三套 alt/hybrid/classical 链；保存 DER、preTBS、测试专用握手密钥和经典私钥、逐文件 SHA256，以及来源/库/线程数清单。正常测试和握手从 `base_tls/tls/alt_fixtures.py` 加载夹具，避免反复生成有限签发次数的 CA 签名。

生成器要求 `--budget-db`，每次 CA 签名尝试之前调用 `SigningBudget.reserve(algorithm, public_key, pre_tbs)`；receipt 保留在签发记录内，失败或退出仍消耗额度。`--test-only-no-budget` 是显式测试开关。预算的预约、完成/失败状态与回执对账由 `SigningBudget` 接口处理；数据库副本和备份的抗回滚仍需外部治理。生成器校验源码和 native 库在整次生成期间保持相同哈希。

接口命令模板（重放既有公开夹具应采用 `verify`，新生成需要独立预算）：

```text
python tools/alt_chain_fixtures.py generate --output FIXTURES --library LIB --threads 32 --budget-db BUDGET_DB
python tools/alt_chain_fixtures.py verify --fixtures FIXTURES --output VERIFICATION_JSON
python tools/alt_chain_fixtures.py e1 --fixtures FIXTURES --output E1_JSONL
```

验签/回归时设置 `SLHDSA_SM3_LIB=LIB`、`A15_ALT_FIXTURES=FIXTURES`。Falcon 使用原项目独立 provider；生成器默认握手算法为 Falcon-512，可用 `--handshake-signer ml-dsa-44` 进行独立功能验收。

`base_tls/tls/alt_profiles.py` 提供 P0 经典、P1 原 hybrid、P2 SM3-128-24 alt、P3 SM3-128s alt、P4 ML-DSA44 alt 五个配置。`e1_record()` 执行真实认证握手并返回实际 DER/扩展长度、消息长度与 wire bytes。TCP 分段、初始拥塞窗口与网络时延仍需独立网络实验。

## 当前证据入口

测试源码和公开 fixture 与本包一同保留。原生/Python 验签、独立根、替代 CA 边、严格配置与负例结果见本包 `03_测试数据/`，具体配置及覆盖数量见配套测试文档。

## 标准来源核对进度

preTBS 的实现与固定版本 [Bouncy Castle r1rv82 X509v3CertificateBuilder.java](https://github.com/bcgit/bc-java/blob/r1rv82/pkix/src/main/java/org/bouncycastle/cert/X509v3CertificateBuilder.java#L430) 交叉核对：其 440 行先添加 altSignatureAlgorithm，474 行清空 TBS signature，479 行签署 generatePreTBSCertificate，480 行才加入 altSignatureValue，482 行恢复经典签名算法。两者对 73、74 和 TBS signature 的处理一致。

ITU-T X.509 (10/2019) 原文核对仍待完成。本次尝试官方 PDF 链接得到 Document Not Found HTML，未获得标准正文；因此本说明只记录实现参考交叉核对，不将该步骤标作标准原文验收通过。后续应获取该版完整标准，核准相关条款和非关键扩展 profile，补齐版本与来源证据。
