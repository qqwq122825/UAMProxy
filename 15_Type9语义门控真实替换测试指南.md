# Type9 语义门控真实替换测试指南（第三版）

## 1. 本版行为

第三版开始发送经过语义门控的干净候选包，不再把所有目标09包统一透传。

```text
SEMANTIC_READY_FULL/PARTIAL
+ clean_changed_leaves > 0
+ 物理帧/双CRC/重解密/签名/序列全部通过
→ REPLACE：发送 shadow_candidate

其余状态
→ PASS_LIVE：发送 live_input
```

`SEMANTIC_READY_PARTIAL` 中没有录制样本的叶子继续保留实时值；只有已命中且字段
规则完整的叶子引入录制干净字段。

## 2. 真实发送链

```text
实时01帧组
  → Type9解密和明文CRC校验
  → 按 recordCode/messageId/length 建立叶子结构
  → subtype/cycle 精确过滤
  → 最近 recordSequence 选择
  → 实时会话/计数/时间字段覆盖
  → 录制干净字段写入
  → 重算明文CRC、密文和01外层CRC
  → 重解密验证结构、签名与叶子序列
  → 语义门控
      ├─ REPLACE：候选帧进入网络
      └─ PASS_LIVE：实时帧进入网络
```

## 3. 数据04规则修正

规则集版本：`data04-v1`。

### `0x8004`

数据04确认 `group_id` 按 `30、330、630、930` 递增，每组固定包含
`sub_index=0..7,16`。因此：

```text
group_id  @ leaf+0x1C，长度2：继承实时值
sub_index @ leaf+0x20，长度4：匹配录制样本
```

### `0xFFFE`

```text
clean_vector @ leaf+0x26，长度11
```

干净范围覆盖到49字节叶子的最后一个字节。

## 4. 数据04离线发送回归

使用164个录制目标包，对219个实时目标包重新执行第三版逻辑：

```text
REPLACE：59
PASS_LIVE：160
输出物理帧/CRC/游戏ID校验失败：0

SEMANTIC_READY_FULL：157
SEMANTIC_READY_PARTIAL：5
SEMANTIC_UNMAPPED：53
NO_LENGTH_AWARE_LEAF_MATCH：4

结构命中叶子：758/779
语义就绪叶子：678/779 = 87.0%
```

五个 `SEMANTIC_READY_PARTIAL` 在数据04中没有实际干净字段变化，因此仍归入
`PASS_LIVE`。59个 `REPLACE` 均为候选字节确实不同并且完整回验通过。

## 5. 日志判定

目录：

```text
C:\PyProxyApp\01ReplayAnalysis\run_<时间>\
```

`01_replace_events.jsonl` 使用 `dfm-01-replay-v4`：

```text
decision=REPLACE
checks.final_equals_live=false
checks.final_equals_shadow=true
checks.replacement_changed=true
checks.output_crc_ok=true
checks.output_validation_ok=true
shadow_rebuild.semantic_ready=true
shadow_rebuild.sent=true
```

门控透传则应满足：

```text
decision=PASS_LIVE
checks.final_equals_live=true
shadow_rebuild.sent=false
```

快速汇总：

```bash
python tools/analyze_01_replay_log.py "C:\PyProxyApp\01ReplayAnalysis\run_<时间>"
```

汇总工具还会报告录制池回卷，并单独统计：

```text
0x8024 / 0x8030 / 0x80CC / 0x80CD
```

## 6. 测试数据保留

完成一场重放后保留：

```text
01RecordPackets\
01ReplayAnalysis\run_<本次时间>\
```

重点结合 `REPLACE` 前后的下行事件，记录首次异常提示、连接关闭前最后一个
目标09序号、最后一个真实替换事件及其 `leaf_results`。
