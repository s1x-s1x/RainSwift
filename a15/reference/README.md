# SLH-DSA独立参考实现与差分测试

本目录提供Python参考实现、SM3实现及原生/参考差分核验。固定依赖见`requirements.lock.txt`，第三方来源见`UPSTREAM.json`。

在A1-5根目录并已构建原生库的环境执行：

```sh
python3 -B -m reference.selftest
python3 -B -m reference.differential --threads 48 --output results/sm3-128-24-differential.jsonl complete --input reference/evidence/python-sm3-128-24.jsonl
python3 -B -m reference.differential --workers 32 --output results/toy-differential.jsonl toy --count 1000
python3 -B -m reference.differential --workers 16 --output results/subtree-differential-balanced.jsonl subtree --count 1000
```

若原生库不在默认`build/libslhdsa_sm3.so`，使用`--library`显式指定。输出文件须尚不存在。完整参数、toy与子树测试分别计数，不能叠加成同一参数的完整用例。

`evidence/`保存参考输出和差分记录，`evidence_sources/`保存与对应记录绑定的测试基线。测试时间为正确性核验耗时，不作为正式性能结论。
