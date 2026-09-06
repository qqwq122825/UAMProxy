# Type9 专项差分旁路与动态保护测试指南（第六版）

## 1. 测试目标

第六版在数据07/08稳定基线上增加专项差分旁路。未映射但结构命中的
普通叶子继续引入录制主体，动态未知叶子保持实时值并生成旁路候选。

```text
已知规则叶子
  -> KNOWN_CLEAN

未映射但 recordCode/messageId/length 命中的叶子
  -> AGGRESSIVE_UNKNOWN

动态消息、序号距离过大或时间戳过旧
  -> AGGRESSIVE_BLOCK_DYNAMIC

无同结构录制叶子
  -> 保留实时值
```

## 2. 叶子重建

每个命中叶子使用距离实时 `recordSequence` 最近的录制样本。

```text
leaf+0x00..0x0D  实时公共头（包含recordSequence）
leaf+0x0E..end   录制主体
```

已有语义规则中的 `inherit` 字段仍覆盖回实时值；`clean` 字段使用
录制值。普通未映射叶子除公共头外使用录制主体。

以下条件命中任意一项时，未知叶子的完整主体保留实时值：

```text
recordCode = 0x01122388
messageId = 0xFFF2 / 0xFFF3
recordSequence 距离 > 128
双方存在十位时间戳且最大最近差值 > 30秒
```

## 3. 发送门槛

```text
游戏ID一致
+ 至少命中一个录制叶子
+ 候选字节与实时字节不同
+ Type9明文CRC通过
+ 重加密后可原样解密
+ 批次结构/叶子顺序/序号与实时一致
+ 01外层CRC通过
-> REPLACE
```

候选无变化、无同结构样本或机械回验失败时发送实时包。

## 4. 数据05离线预测

```text
目标09包：189
第三版 KNOWN_CLEAN 替换：46
第四版新增 AGGRESSIVE_UNKNOWN：55
预计真实替换：101
无同结构候选：2
候选与实时相同：86
```

## 5. `0x8024`

数据05中 `0x8024` 长度44字节，录制与实时主体相同，因此本次不产生
字节变化。以后实时主体不同时，按 `AGGRESSIVE_UNKNOWN` 引入录制主体，
只保留实时公共14字节头。

## 6. 专属日志

`01_replace_events.jsonl` 使用 `dfm-01-replay-v5`，规则集为
`data08-suspect-shadow-v3`。

新增 `01_suspect_diffs.jsonl`，专项记录：

```text
0x8024 / 0x8030 / 0x80CC / 0x80CD
0xFFF2 / 0xFFF3
recordCode 0x01122388
NEW_IDENTITY / NEW_LENGTH
```

每条记录包含原始01帧、完整实时Type9明文、叶子实时/模板HEX、
`shadow_only_candidate_hex`、差异偏移及连续区间。专项候选保持旁路，
网络输出继续使用受保护的实时叶子。

每个发生变化的叶子记录：

```text
replacement_level
record_code / message_id / length
live_sequence / template_sequence
block_reason / dynamic_guard
suspect_flags / available_template_lengths
shadow_only_candidate_hex / shadow_only_diff_ranges
template_pool_idx / template_path
unknown_diff_offsets / clean_diff_offsets
live_hex / template_hex / candidate_hex
```

快速汇总：

```bash
python tools/analyze_01_replay_log.py "C:\PyProxyApp\01ReplayAnalysis\run_<时间>"
```

## 7. 结果定位

测试后保留完整录制和重放目录，同时记录游戏首次异常提示的本地时间。
分析时按以下顺序缩小范围：

1. 找到异常前最后一个 `AGGRESSIVE_UNKNOWN` 事件。
2. 检查 `AGGRESSIVE_BLOCK_DYNAMIC` 是否覆盖动态状态包。
3. 按 `messageId` 分为 `0x800x/0xFFFx` 和无 messageId 的 `0x011223xx` 两类。
4. 对比 `live/template/candidate` 和 `unknown_diff_offsets`。
5. 将表现为计数、时间、会话或阶段值的偏移加入 `inherit`。
6. 重复测试，直到定位必须继承的字段。
