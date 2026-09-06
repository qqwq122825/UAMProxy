# DFMProxy v1.124 `tfp_called` 专项处理说明

## 处理顺序

v1.124 对所有已解密 Type9 叶子扫描 `tfp_called`，不再只依赖固定消息号。

1. 优先查找无标记干净模板：已确认的 `0x01122329/0x0112233B` 沿用正常槽规则，其他消息号优先使用同 `recordCode` 的干净叶子。
2. 没有干净模板且字段前缀为 `0000000001000000000B` 时，删除完整 20 字节编码字段，并重建叶子、容器、Type9 密文和 CRC。
3. 字段布局未知时，等长清零全部 `tfp_called` 文本，保持包长度不变。
4. 叶子处理结束后再次检查候选；若仍含标记，执行最终等长清零。

## 规则 ID

| 场景 | 规则 ID | 动作 |
|---|---|---|
| 已确认 `0x01122358` 命中干净模板 | `1122358-tfp-called-clean-slot` | `CLEAN_TEMPLATE_REPLACE` |
| 新消息号命中干净模板 | `v124-tfp-called-any-record-clean-slot` | `CLEAN_TEMPLATE_REPLACE` |
| 无模板、已确认字段结构 | `v124-tfp-called-no-template-structured-remove` | `STRUCTURED_FIELD_REMOVE` |
| 未知字段布局 | `v124-tfp-called-unknown-layout-zero-marker` | `ZERO_MARKER` / `FINAL_GUARD_ZERO_MARKER` |

`0x01122329`、`0x0112233B`、`0x01122358` 分别显示各自的确认规则 ID；
后续首次出现的其他消息号继续由 `any-record` 通配规则覆盖。

## 统计字段

每个 `shadow_rebuild` 记录：

```text
tfp_called_detected_leaves
tfp_called_template_replaced_leaves
tfp_called_structured_removed_leaves
tfp_called_zeroed_leaves
tfp_called_residual_leaves
tfp_called_rule_ids
```

每个命中叶子记录：

```text
tfp_called_detected
tfp_called_rule_id
tfp_called_action
tfp_called_replacement
```

其中 `tfp_called_replacement` 包含命中偏移、替换前后长度、SHA-256、最终候选是否仍含标记等信息。

## 专项日志

每个 `01ReplayAnalysis/run_*` 目录新增：

```text
01_tfp_called_events.jsonl
01_tfp_called_stats.json
```

- `01_tfp_called_events.jsonl`：逐条记录命中消息号、长度、序号、规则 ID、动作、模板和替换摘要。
- `01_tfp_called_stats.json`：累计统计命中、模板替换、结构删除、清零、残留以及各规则/消息号次数。

## 拦截管理界面

“拦截管理 → 01 上行拦截（Type9 规则）”会在普通热规则后显示 6 条
`tfp_called` 内置规则。只有候选通过机械校验并实际成为最终输出后，才增加
对应规则的“成功改写”次数。界面每秒刷新，“清空统计”会同时清零热规则和
`tfp_called` 内置规则统计。

## `0x01122358:225` 实样回验

使用本次数据目录保存的原始叶子样本回验：

```text
输入消息号       = 0x01122358
输入长度         = 225
输入包含标记     = true
候选长度         = 205
命中规则         = v124-tfp-called-no-template-structured-remove
处理动作         = STRUCTURED_FIELD_REMOVE
候选包含标记     = false
Type9往返回验    = true
01最终决策       = REPLACE
01外层校验       = true
残留统计         = 0
```
