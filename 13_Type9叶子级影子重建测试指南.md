# Type9 叶子级影子重建测试指南

## 本版目标

当前版本在保持 `PASS_LIVE` 稳定基线的同时，生成一份可完整校验的
“叶子级影子候选包”。候选包只写日志，网络最终发送的仍是实时原包。

```text
final_output == live_input
shadow_candidate != final_output（有命中且主体变化时）
```

## 叶子级是什么

Type9 解密后的一个批次可包含多个子记录：

```text
实时批次
├─ 叶子1: recordCode / messageId / recordSequence / body
├─ 叶子2: recordCode / messageId / recordSequence / body
└─ 叶子3: recordCode / messageId / recordSequence / body
```

录制池按下列键索引叶子：

```text
recordCode + messageId + actualLength
```

命中后：

1. 保留实时批次容器、叶子数量、顺序和所有尾部。
2. 录制叶子作为主体。
3. 叶子前14字节公共头继承实时值，其中包含 `recordSequence`。
4. 长度或语义键未命中的叶子保持实时值。
5. 候选明文使用实时 `selector/key_index` 重新加密。
6. 重算明文 CRC32 与 01 外层 CRC32。
7. 候选密文立即再解密，验证签名、序列和 CRC。

## 网络流程

```text
完整实时01帧组
  ├─→ 原样写入 final_output → 发给服务器
  └─→ Type9解密
       → 全录制池叶子索引
       → 等长叶子匹配
       → 候选明文/密文/物理帧
       → 双CRC+解密回验
       → shadow_candidate 日志
```

## 影子状态

| status | 含义 |
|---|---|
| `READY_FULL` | 所有实时叶子都有同语义、同长度录制样本，候选回验通过 |
| `READY_PARTIAL` | 部分叶子引入录制主体，其余保持实时值，候选回验通过 |
| `NO_LENGTH_AWARE_LEAF_MATCH` | 录制池未找到同语义且同长度叶子 |
| `LIVE_MATERIAL_INVALID` | 实时 Type9 明文或 CRC 解析异常 |
| `CANDIDATE_VALIDATION_FAILED` | 生成了候选，但物理帧、CRC、签名或序列回验未通过 |

## 日志检查

```text
C:\PyProxyApp\01ReplayAnalysis\run_<时间>\01_replace_events.jsonl
C:\PyProxyApp\01ReplayAnalysis\run_<时间>\01_replace_summary.csv
C:\PyProxyApp\01ReplayAnalysis\run_<时间>\01_downlink_events.jsonl
```

`01_replace_events.jsonl` 的重点字段：

```text
live_input             实时输入完整帧
shadow_candidate       旁路生成的候选完整帧
final_output           真正发送的实时帧
shadow_rebuild         叶子命中、来源、覆盖率和回验结果
ordinals.game_target_09        跨服务器连接的目标09序号
ordinals.leaf_sequence_start   当前明文首序列
ordinals.leaf_sequence_end     当前明文末序列
```

快速汇总：

```bash
python tools/analyze_01_replay_log.py "C:\PyProxyApp\01ReplayAnalysis\run_<时间>"
```

## 数据02离线回归

```text
录制池目标09: 144
实时目标09: 144
实时明文叶子: 463
同语义同长度命中: 447 / 463 = 96.5%
READY_FULL: 132
READY_PARTIAL: 10
NO_LENGTH_AWARE_LEAF_MATCH: 2
影子候选回验失败: 0
最终网络输出等于实时输入: 144 / 144
```

## 测试步骤

1. 录制一场完整会话。
2. 使用重放端口进行一场完整测试。
3. 关注详情中的 `影子=READY_FULL/READY_PARTIAL`，实际网络仍是实时原包。
4. 结束后保留完整 `01RecordPackets` 和 `01ReplayAnalysis` 目录。
5. 候选包连续通过后，下一阶段只对 `READY_FULL` 开启严格门控的真实替换。
