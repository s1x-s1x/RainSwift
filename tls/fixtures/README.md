# 公开测试夹具

`public-alt-chain/` 的 49 个文件来自基线提交 `808d34c938725cf9b1edb7b2452d550afa396455` 已公开的测试链、测试密钥和预签名；SHA-256、字节数、Git blob 身份见 `PUBLIC_TEST_PROVENANCE.json`。本次逐项验证并复制，没有重新签发 128-24 CA 凭据。

用于离线重放 P0–P4、真实 native/Python 链验证与 CI。测试根、密钥和签名已公开，只用于实验环境。历史 `MANIFEST.json` 保存当时生成来源，不能把其旧源码/库哈希当作当前库验收；当前验证结果由新运行 manifest 给出。

从工程根目录运行：

```sh
python3 -B ops/bootstrap_local_env.py --verify --falcon \
  --fixtures fixtures/public-alt-chain --output build/reproduction-new
```
