# DFMProxy v1.128.10 报告确认重连校验报告

日期：2026-08-25
分支：`codex/v128-v1-same-device`

## 1. 旧数据重新定性

42字节加入包字段：

- `+0x0A~+0x0D`：同一轮游戏/ACE运行的多次加入包中保持一致，作为会话候选值。
- `+0x0E~+0x11`：产品ID，当前样本为`0x00000A92`。
- `+0x26~+0x29`：完整u32 Unix时间戳，只作日志与延迟诊断。

历史样本：

| 时间范围 | `+0x0A`会话值 | 末尾u32 | 结果 |
|---|---|---|---|
| 18:28→18:56 | `E22BF85B` | `6A8C1CD0→6A8C2363` | 会话值不变，Unix时间推进1683秒 |
| 01:29→01:33 | `EF7F17BE` | `6A8B2DD7→6A8B2EE8` | 会话值不变，首包生成后约9秒才入日志 |
| 21:36→22:12→23:13 | `9ABF276F` | `6A8C48F4→6A8C5158→6A8C5FB3` | 会话值不变，Unix时间与墙钟一致 |

因此末尾时间不再用于判断游戏进程是否结束。

## 2. v1.128.10判定流程

1. 42B、代理账号和游戏ID匹配时，仅建立`RECONNECT_CANDIDATE`。
2. 候选连接暂存旧Type9语义状态，同时重建新连接的report/frame/group传输偏移。
3. 首个完整Live Type9报告到达后，读取原生叶`recordSequence`。
4. 与代理内存中旧连接的`last_native_live_leaf_sequence`比较：
   - 相同：应用层重传，确认续接；
   - 向前`1~65535`：确认同一内存报告状态继续；
   - 重置、倒退或大跨度：建立新游戏会话并在处理首包前清空旧语义状态。
5. 确认续接后保留`emitted/satisfied/player_consumed/device_context`以及累计`leaf_offset`；report/frame/group按新传输重新建立。

## 3. 结构化日志

`reconnect_events.jsonl`升级为`dfm-ai-01-reconnect-v130-v1`：

- `JOIN_42_OBSERVED`：完整42B、会话值、完整Unix时间。
- `BIND_DECISION`：`FIRST_JOIN/NEW_GAME_SESSION/RECONNECT_CANDIDATE`。
- `LIVE_REPORT_DECISION`：旧叶末值、新叶首值、forward delta和最终分类。
- `DISCONNECT_OBSERVED`：最终逻辑时间、会话值和Unix时间。

## 4. 历史回溯

工具：`tools/backtest_v130_reconnect.py`

输入：

`数据/128/128.8/检测前重放长时间/AI日志/run_20260824_213633_063843`

结果：`PASS`

- 42B会话值：`9ABF276F → 9ABF276F`。
- 完整Unix时间差：`3675秒`，与墙钟差`0秒`。
- Live叶：`2196 → 2197`，forward delta=`1`。
- 最终判定：`RESUME_TOKEN_AND_LIVE_REPORT`。
- 外层report：`571 → 1`，确认传输层重建。
- 可抑制重复中央补发：4报告、27叶。
- 新连接输出组机械校验全部通过。

## 5. 自动化测试

```text
Ran 236 tests
OK (skipped=21)
```

新增覆盖：

- 42B会话值和完整Unix时间解析。
- 首个Live叶连续、重传、重置与大跨度判定。
- 相同会话值只进入候选，不立即继承。
- 会话值变化直接建立新会话。
- 确认续接时保留累计leaf offset，重建report/frame/group。
- 报告重置时在首包处理前清空旧时隙、设备和模板消费状态。
- 新旧socket重叠、旧连接过期与stale回调保护。

## 6. 测试流程

1. 纯网络重连：游戏进程保持运行，断网30秒后恢复。
2. 进程重开：同设备同账号，完全结束游戏后重新进入。
3. 跨设备：同账号换设备进入。
4. 每轮保留完整`AI日志/run_*`，重点查看`LIVE_REPORT_DECISION`。

预期：纯网络重连为`NETWORK_RECONNECT`；进程重开和跨设备为`GAME_REOPEN_OR_NEW_SESSION`。
