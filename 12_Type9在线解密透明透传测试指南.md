# Type9 在线解密透明透传测试指南

## 测试目标

本阶段先验证连接稳定性，不把历史完整密文写入实时消息：

```text
final_frames == live_frames
final_sha256 == live_sha256
```

录制池继续保留，当前只作为解密后的语义对照样本。

## 在线流程

```text
完整01帧组重组
→ 非09类型：PASS_NON_TARGET
→ 09类型：提取 selector/keyIndex/plainCRC/ciphertext
→ selector 0/1/2 在线解密
→ 校验 IEEE CRC32
→ 递归解析 0x010A001B 批量容器
→ 提取 recordCode/messageId/recordSequence/childCount
→ 解密当前历史模板并比较
→ 写 PASS_LIVE reason
→ 原样发送实时物理帧
```

## 决策原因

| reason | 含义 | 网络输出 |
|---|---|---|
| `OBSERVE_ONLY_MATCH` | 当前比较项全部相同 | live 原包 |
| `BATCH_SHAPE_MISMATCH` | 批次数量或长度比例明显不同 | live 原包 |
| `SIGNATURE_MISMATCH` | recordCode/messageId 类别不同 | live 原包 |
| `SEQUENCE_MISMATCH` | 内部 recordSequence 不同 | live 原包 |
| `LARGE_BATCH_PROTECT` | 多叶子任务批次保护 | live 原包 |
| `PROTECTED_MESSAGE_ID` | 包含 FFxx/100x/010x 消息 | live 原包 |
| `LIVE_PARSE_OR_CRC` | 实时明文解析或 CRC 异常 | live 原包 |
| `TEMPLATE_PARSE_OR_CRC` | 历史模板解析或 CRC 异常 | live 原包 |
| `GAME_ID_MISMATCH_PASS_LIVE` | 游戏 ID 对照异常 | live 原包 |
| `NO_VALID_TEMPLATE_PASS_LIVE` | 没有可用历史模板 | live 原包 |

## 日志位置

```text
C:\PyProxyApp\01ReplayAnalysis\run_<时间>\01_replace_events.jsonl
C:\PyProxyApp\01ReplayAnalysis\run_<时间>\01_replace_summary.csv
C:\PyProxyApp\01ReplayAnalysis\run_<时间>\01_downlink_events.jsonl
C:\PyProxyApp\01RecordPackets\test_01_downlink_<时间>.jsonl
```

每个 `PASS_LIVE` 事件的 `online_decode` 包含：

```text
live/template selector、算法和keyIndex
stored/calculated plaintext CRC32
topRecordCode、childCount
所有叶子的 recordCode/messageId/recordSequence
语义签名、长度比例、保护消息ID
时间值和可打印字符串
```

## 本地回归结果

交接材料的两轮数据已通过：

```text
01：84/84 目标事件 final == live
02：88/88 目标事件 final == live

01 report 84/85：BATCH_SHAPE_MISMATCH
02 report 85/86/87/88：BATCH_SHAPE_MISMATCH
02 report 89：SIGNATURE_MISMATCH
```

## 在线测试方式

1. 使用本版本重新录制一轮，再启动重放。
2. 保持与前两轮相同操作，重点观察能否超过 report 89、120。
3. 出现提示或连接结束后，保留整个对应时间的录制与重放目录。
4. 提供 `01RecordPackets`、`01ReplayAnalysis` 两个目录；下行日志用于定位最后服务端响应。
