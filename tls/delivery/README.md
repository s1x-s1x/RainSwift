# 后续完整修复交付索引（2026-10-19）

## 结论

执行单的 8 个缺口已闭合，四份字段级验收全部通过：

| 验收 | 结果 |
|---|---|
| A1-5 `final-gate-1` | 550 tests：549 passed / 1 skipped；source/fixtures unchanged |
| A1-5 `final-acceptance-full` | 36/36 passed；strict P2 与 TCP 字段谓词全通过 |
| A1-5 `final-acceptance-new`（本轮重签） | 36/36 passed |
| TLS-B 服务器全量 | 502 passed / 1 skipped；审计 PASS |
| TLS-B `final-tlsb-acceptance-full-2` | 36/36 passed |
| Rain `final-rain-acceptance`（p2-only） | 36 cases：29 passed / 0 failed / 7 not_covered；JUnit skipped=7 |
| 本机 TLS-B 全量 | 477 passed / 60 skipped（Rain 库缺失） |
| 本机 A1-5 全量 | 570 passed / 5 skipped |

关键哈希：

- SLH 优化库：`b66ecc3bc57db3f2d2337d37e88503763b64d6c4a128632c711f8b8720284f69`
- 新 fixture：128-24 `6e1a6723…`、128s `92822708…`、ML-DSA-44 `685a0154…`
- Rain fixture：`2dabd0cf74fe0c43fdc3c75be1a2fe0d1a851e54109b5907cabf99ddc16cbe8e`

## 目录

```
后续修复交付-20261019/
├── 后续修复验收报告_20261019.md
├── README.md
├── a15-round2.diff / a15-round2-vs-backup.diff
├── a15-status.txt / a15-untracked.txt / a15-source-sha256.txt
├── tlsb-round2-vs-backup.diff / tlsb-changes.txt / tlsb-source-sha256.txt
├── before-hashes.json / after-hashes.json
├── final-baseline/（命令、解释器、before/after 哈希）
├── logs/
│   ├── tlsb-targeted.log / tlsb-full.log / tlsb-audit.log
│   └── a15-targeted.log / a15-full.log / a15-audit.log
└── server/
    ├── final-evidence-20261019.tar.gz
    └── out/
        ├── final-gate-1/
        ├── final-fixture-verify/
        ├── final-acceptance-full/
        ├── final-acceptance-new/
        ├── final-new-fixtures/
        ├── final-new-fixture-verification.json
        ├── final-tlsb-acceptance-full-2/
        ├── final-rain-fixtures/
        ├── final-rain-fixture-verification.json
        ├── final-rain-acceptance/
        ├── final-ca-budget.sqlite*
        ├── final-ca-cache/
        ├── final-rain-budget.sqlite*
        ├── final-rain-ca-cache/
        └── final-environment.txt
```

## 阅读顺序

1. `后续修复验收报告_20261019.md`
2. `final-baseline/before-hashes.json` 与 `after-hashes.json`
3. `server/out/final-gate-1/manifest.json`
4. `server/out/final-acceptance-full/acceptance.json` 与 `junit.xml`
5. `server/out/final-acceptance-new/acceptance.json`
6. `server/out/final-tlsb-acceptance-full-2/acceptance.json`
7. `server/out/final-rain-acceptance/acceptance.json`（重点看 `not_covered` 的 7 项）

## 边界

- Rain 只覆盖 P0–P2；7 个 `not_covered` 不是通过项。
- Windows 上 Rain/Falcon 的部分测试因缺原生依赖跳过；Linux 服务器已实跑。
- 旧 DeepSeek 服务器证据只作历史材料，不参与本轮结论。
