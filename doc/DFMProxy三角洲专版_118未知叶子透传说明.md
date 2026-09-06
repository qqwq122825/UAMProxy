# DFMProxy v1.118 未知叶子透传

## 网络处理顺序

```text
实时 Type9 叶子
→ 精确匹配玩家模板
→ 玩家池未命中时匹配已发布官方模板
→ 两级模板均未命中时完整保留实时叶子
→ 仅已命中叶子执行主体替换与动态字段继承
→ 重算 Type9 明文CRC、密文和01外层CRC
→ 解密及帧结构回验通过后输出
```

未知叶子保持原始 `recordCode`、`messageId`、长度、字节、子项顺序和
`recordSequence`。混合报告中，已知叶子可以替换，未知兄弟叶子逐字节来自实时包。

## 专项规则入口

专项处理入口位于：

```text
core/type9_special_rules.py
```

`SPECIAL_UNKNOWN_LEAF_HANDLERS` 初始为空。后续规则按下列精确键单独登记：

```text
(recordCode, messageId, actualLength)
```

处理器接收完整实时叶子，只能返回同长度完整叶子。异常、空结果或长度变化均回到
`PASS_LIVE`，从而让一条专项规则与其他未知结构隔离。

## 裁剪实现

递归裁剪和长度重建代码继续保留在 `core/type9_shadow.py`，正式默认关闭。专项实验需同时满足：

```text
v118_unknown_leaf_policy = prune
v118_leaf_prune_experiment_enabled = true
```

旧配置中的 v1.117 裁剪字段不参与 v1.118 网络决策。裁剪字节实例继续见
《DFMProxy三角洲01协议对抗教程》第17节。

## 日志

普通模式保存：

```text
01_unknown_leaf_samples.jsonl       每种结构最多三份原始叶子
01_unknown_context_samples.jsonl    对应完整01帧和Type9明文
01_unknown_leaf_stats.json          未知结构累计次数
template_usage_events.jsonl         玩家、官方、实时及专项规则计数
```

关键字段：

```text
replacement_level=UNMATCHED_LEAF_PASS_LIVE
unmatched_pass_live_leaves=N
special_handled_leaves=N
special_changed_leaves=N
pruned_leaves=0
```

## 持久化兼容

玩家录制和官方模板继续读取已有 `v117_recording_pools.json` 与
`dfm_official_templates_v117.json`，避免升级后丢失既有模板。文件名只表示存储格式版本，
网络策略由 v1.118 规则集决定。
