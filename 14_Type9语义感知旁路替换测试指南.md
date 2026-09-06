# Type9 语义感知旁路替换测试指南（第二版）

## 1. 本版结论

第二版仍采用透明透传：网络发送的始终是实时 01 原包，同时在旁路生成一份
“语义感知影子候选包”用于校验和日志分析。

```text
final_output == live_input
shadow_candidate 只记录，不进入网络
```

因此本轮测试重点不是观察服务器是否接受替换，而是确认候选包已经同时满足：

1. 实时批次结构、叶子顺序、叶子 `recordSequence` 不变；
2. 会话、计数、时间、周期等动态字段继承实时明文；
3. 干净值仅从已标注的录制字段范围引入；
4. 子类型或周期字段命中正确的录制叶子；
5. 明文 CRC、密文、外层 CRC 和重新解密回验全部通过；
6. 未识别的变化字节会阻止 `SEMANTIC_READY`，不会被误判为可替换。

## 2. 候选包构造流程

```text
实时完整01物理帧
  ├─→ 原样作为 final_output 发送
  └─→ 重组逻辑 payload
       → 解密 Type9 并校验明文 CRC
       → 递归解析叶子
       → 按 recordCode/messageId/length 找录制候选
       → 按 subtype/cycle 精确过滤
       → 按 recordSequence 距离选择最近录制叶子
       → 录制主体 + 实时公共头/动态字段覆盖
       → 重算明文 CRC + 加密 + 外层 CRC
       → 立即重新解密并校验结构/签名/序列
       → 仅写 shadow_candidate 日志
```

旧版用 `recordSequence % 候选数` 选择样本，可能拿到另一阶段的计数器、时间或
内部子类型。第二版改为“语义字段过滤 + 最近序列”，避免循环游标把不同阶段叶子混用。

## 3. 当前字段规则集

日志中的规则版本为 `data03-v1`。偏移均相对于解密后的单个叶子，区间采用
左闭右开表示。

| messageId | 继承实时字段 | 录制干净字段 | 选择约束 |
|---|---|---|---|
| `1001` | `20..24` 会话开始时间 | — | 同结构 |
| `1002` | — | `20..24` 干净报告值 | 同结构 |
| `1003` | `26..28` 会话字段 | — | 同结构 |
| `1005` | `28..2C` 会话运行值 | — | 同结构 |
| `100A` | `20..24`、`28..34` 计数器；`40..44` 事件时间 | — | 同结构 |
| `100E` | `20..28` 周期与单调计数 | `2C..30` 测量值 | `20..24` 周期相同 |
| `1105` | `20..24` 计数器 | — | 同结构 |
| `2001` | `20..24` 固定步进计数 | — | 同结构 |
| `8004` | — | — | `1C..1E` 分组、`20..24` 子序号相同 |
| `FFF9` | — | `25..29` 类型值 | `23` 子类型相同 |
| `FFFB` | `28..2C` 计数器 | — | 同结构 |
| `FFFE` | — | `26..30` 向量 | 同结构 |
| `0100` | — | `24..98` 数据块 | `20..24` 阶段相同 |
| `0101` | `20..24` 步进计数 | `24..98` 数据块 | 同结构 |
| `0102/0103` | `20..24` 步进计数 | `24..A0` 数据块 | 同结构 |

所有叶子的公共头 `00..0E` 都继承实时数据，其中 `0A..0E` 是
`recordSequence`。规则外的差异保存在 `unknown_diff_offsets`，状态记为
`SEMANTIC_UNMAPPED`。

## 4. 状态说明

| status | 含义 |
|---|---|
| `SEMANTIC_READY_FULL` | 全部实时叶子命中，字段规则与机械回验均通过 |
| `SEMANTIC_READY_PARTIAL` | 部分叶子命中且命中部分语义通过；未命中叶子保持实时值 |
| `SEMANTIC_UNMAPPED` | 候选可加解密，但至少一个命中叶子存在规则外差异 |
| `NO_SEMANTIC_SUBTYPE_MATCH` | 结构匹配，但内部子类型/周期无相同录制样本 |
| `NO_LENGTH_AWARE_LEAF_MATCH` | 无同 `recordCode/messageId/length` 录制叶子 |
| `CANDIDATE_VALIDATION_FAILED` | 候选的物理帧、CRC、签名或序列回验失败 |

`mechanical_ready=true` 仅表示候选包在格式与 CRC 上成立；只有
`semantic_ready=true` 才表示已知动态字段和干净字段也符合规则。

## 5. 专属日志

```text
C:\PyProxyApp\01RecordPackets\test_01_sliced_<时间>.log
C:\PyProxyApp\01RecordPackets\test_01_downlink_<时间>.jsonl
C:\PyProxyApp\01ReplayAnalysis\run_<时间>\01_replace_events.jsonl
C:\PyProxyApp\01ReplayAnalysis\run_<时间>\01_replace_summary.csv
C:\PyProxyApp\01ReplayAnalysis\run_<时间>\01_downlink_events.jsonl
```

每个 `leaf_results` 重点字段：

| 字段 | 用途 |
|---|---|
| `semantic_rule` | 命中的语义规则名 |
| `live_sequence/template_sequence/sequence_distance` | 最近序列选择依据 |
| `match_fields` | 子类型/周期匹配值 |
| `inherited_fields` | 从录制值覆盖成实时值的动态字段 |
| `clean_field_values` | 实时值与录制干净值对照 |
| `clean_diff_offsets` | 实际引入干净数据的位置 |
| `unknown_diff_offsets` | 尚未归类的变化位置 |
| `semantic_ready` | 当前叶子是否通过语义门控 |

快速分析：

```bash
python tools/analyze_01_replay_log.py "C:\PyProxyApp\01ReplayAnalysis\run_<时间>"
```

## 6. 数据03离线回归结果

```text
录制目标09包: 206
重放目标09包: 215
重放明文叶子: 744
结构/长度命中: 722 / 744 = 97.0%
语义就绪叶子: 657 / 744 = 88.3%
机械回验通过: 213 / 215
语义就绪包: 158 / 215
SEMANTIC_READY_FULL: 156
SEMANTIC_READY_PARTIAL: 2
SEMANTIC_UNMAPPED: 55
NO_LENGTH_AWARE_LEAF_MATCH: 2
候选生成后的机械回验失败: 0
最终输出逐字节等于实时输入: 215 / 215
```

重放第 `207..215` 个目标包超过录制包数量后仍可由叶子池完成结构命中，说明
录制池不需要无限增加完整 01 包；后续重点是根据 `unknown_diff_offsets` 继续确认
少量未映射消息类型，而不是单纯增加录制数量。

## 7. 本轮测试步骤

1. 使用第二版程序导入已有完整录制池。
2. 从重放端口完成一场正常会话。
3. 确认界面始终显示“最终=实时原包”。
4. 结束后保留完整 `01RecordPackets` 与本次 `01ReplayAnalysis/run_*`。
5. 运行汇总工具，优先提交 `SEMANTIC_UNMAPPED` 事件及对应录制目录用于补规则。
