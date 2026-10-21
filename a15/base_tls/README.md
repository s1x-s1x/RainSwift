# CA链协议组件

本目录为A1-5的当前代码依赖，提供握手、记录保护、X.509替代链及协议回归测试。`../tools/alt_chain_fixtures.py`、`../tools/ds_acceptance.py`及功能门禁从这里加载`tls`包。

依赖锁和`tests/`与实现一并保存。构建与功能测试使用上层`../ops/bootstrap_local_env.py`入口；协议格式见`docs/PROTOCOL.md`。完整操作见支撑包`01_配套文档/`。
