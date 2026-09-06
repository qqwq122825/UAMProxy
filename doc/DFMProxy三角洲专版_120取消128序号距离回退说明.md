# DFMProxy v1.120：取消128序号距离回退

## 变更

- 未知叶子仍按 `recordCode/messageId/length` 命中录制模板。
- 叶子公共头 `0x00..0x0D`（含实时 `recordSequence`）继续继承 Live。
- 命中模板后，`recordSequence` 距离只写入 `dynamic_guard.sequence_distance`。
- `sequence_limit=null`、`sequence_limit_enabled=false`。
- 序号距离超过128时不再产生 `SEQUENCE_DISTANCE_EXCEEDED`，也不再因此回退整叶 Live。
- 显式动态 recordCode/messageId、跨账号身份保护、时间戳过期等其他保护保持原状。

## 测试8对应结果

旧逻辑在报告177、181的 `0x0207` 上分别出现距离139、154，导致整叶 Live 透传。
v1.120回测中这两条应继续命中模板主体，同时保留实时公共14字节头。

## 建议实测流程

1. 进入对局，3366先保持透传。
2. 等待至少两次 Live `0x0207`，确认约30秒周期已经启动。
3. 阻断3366并确认旧连接关闭、重连继续被阻断。
4. 阻断确认后再启动绘制。
5. 全程保持3366阻断直到对局结束，不在本轮恢复。
6. 检查所有 `0x0207` 的 `sequence_distance`、Live/模板/最终 `+0x28` 与 `+0x30`。

本轮只验证长时重放取消序号距离回退后的结果；中途恢复3366会重新引入第二个变量。
