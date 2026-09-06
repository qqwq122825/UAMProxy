# DFMProxy v1.120 Type9根叶子与容器叶子替换支持报告

## 1. 结论

当前重放的**同长度模板叶子替换**已经支持两种形态：

1. `0x010A001B`容器内叶子，例如 `path=[3]` 的 `0x0207`。
2. 解密明文本身就是叶子的根叶子，例如 `path=[]` 的 `0x0207`。

两种形态进入同一套叶子匹配、模板选择、公共14字节继承、候选回填、Type9重加密和01外层CRC回验流程。匹配键不包含路径或父容器信息：

```text
(recordCode, messageId, actualLength)
```

因此 `(0x0102000A, 0x0207, 116)` 模板可匹配容器内或根形态的同结构叶子。

## 2. 解析支持

实现位置：`core/type9_shadow.py`

- `_parse_node()` 在根记录不是 `0x010A001B` 时，直接把根记录加入叶子集合，路径为 `[]`。
- 根记录是 `0x010A001B` 时，递归读取每个4字节长度前缀和子记录，子叶子路径为 `[0]`、`[1]` 等。
- `template_leaf_rows()` 对两类叶子统一建立索引。

关键代码区间：

```text
core/type9_shadow.py:247-310   根记录、容器和递归叶子解析
core/type9_shadow.py:361-380   统一叶子键和模板索引
```

## 3. 同长度模板替换支持

`build_shadow_logical()`以实时解密明文作为骨架，为每条叶子保留绝对 `start/end`：

```text
根叶子：start=0，end=明文长度，path=[]
容器叶子：start/end位于父容器内部，path=[index]
```

命中模板后统一执行：

```python
clean_raw = bytearray(selected["raw"])
clean_raw[0:14] = live_leaf["raw"][0:14]
candidate_plain[start:end] = clean_raw
```

所以：

- 根叶子会替换整个明文的对应116字节范围。
- 容器叶子只替换父容器内部自己的116字节范围。
- 两者都保留实时公共14字节头和 `recordSequence`。
- 输出长度保持不变，容器 `childCount`、子项长度前缀和各层声明长度无需变化。

关键代码区间：

```text
core/type9_shadow.py:509-593   统一匹配和模板选择
core/type9_shadow.py:594-680   公共头继承及原位置回填
core/type9_shadow.py:902-933   Type9 CRC、重加密和解密回环
core/crypto.py:686-740        01物理帧回填、外层CRC和结构回验
```

## 4. 测试8实际回测

使用测试8录制池和全部重放Live帧，以v1.120当前代码重新执行叶子重建。

重放Live共发现26条 `0x0207`：

| 形态 | 数量 | AGGRESSIVE_UNKNOWN替换 | Type9回环 | 路径保持 | 01外层回验 |
|---|---:|---:|---:|---:|---:|
| 容器内叶子 | 25 | 25 | 25 | 25 | 25 |
| 根叶子 | 1 | 1 | 1 | 1 | 1 |

根叶子实例：

```text
event=164
report=162
path=[]
messageId=0x0207
liveSequence=558
sequenceDistance=86
replacementLevel=AGGRESSIVE_UNKNOWN
候选长度=Live长度
Type9加解密回环=true
01外层CRC/结构回验=true
```

容器内实例包括：

```text
report=41  path=[4]
report=47  path=[9]
report=52  path=[0]
report=59  path=[0]
```

均完成同长度替换并通过回验。

## 5. 录制模板跨形态匹配

当前叶子模板键不包含 `path`，也不包含“根/容器”标志，因此：

```text
容器内录制的0x0207模板 → 可用于根0x0207 Live
根0x0207录制模板       → 可用于容器内0x0207 Live
```

这在叶子内部结构相同、长度同为116时成立。父容器结构始终来自Live，只回填叶子自身字节。

## 6. 专项等长处理器现状

`core/type9_special_rules.py`支持按精确键注册同长度处理器：

```text
(recordCode, messageId, length)
```

处理器接收完整叶子，不依赖 `path`，因此其字节处理能力也覆盖根叶子和容器叶子。输出长度必须等于输入长度。

当前存在一个优先级细节：

```text
同结构模板已命中 → 先走普通模板替换
模板未命中       → 再执行SPECIAL_UNKNOWN_RULE
```

对应代码顺序：

```text
core/type9_shadow.py:579       if candidates
core/type9_shadow.py:701       elif SPECIAL_UNKNOWN_RULE
```

因此以后把 `0x0207` 设置成强制专项规则时，应把黑名单/专项处理优先级放到普通模板匹配之前，或把它登记为正式 `SEMANTIC_RULES` 字段级规则。仅向当前专项表登记时，已有同结构模板的 `0x0207`仍会优先走普通模板路径。

## 7. 裁剪与替换的边界

### 同长度替换

两种形态均已支持：

```text
容器内0x0207：原位置替换116字节
根0x0207：整个116字节根明文替换
```

### 删除式裁剪

当前递归裁剪要求叶子存在父路径：

```python
live_leaf.get("path")
```

所以：

- 容器内叶子可删除“4字节长度前缀+完整叶子”，再重建父容器。
- 根叶子触发 `ROOT_PRUNE_BLOCKED` 保护；根形态适合等长替换或整报告处置。

此外，现有删除式裁剪是“模板未命中实验”，不是按消息ID黑名单；如果后续增加 `0x0207`删除规则，还需要补齐 `0x010A0009`、`0x010A0023`的外层声明长度同步。

## 8. 推荐实现方向

对 `0x0207`优先采用统一的同长度专项处理：

```text
key=(0x0102000A, 0x0207, 116)
优先级：显式专项规则 > 强动态保留 > 普通模板规则 > 未命中策略
输入：解析后的完整Live叶子
输出：同长度116字节候选叶子
```

这样一套规则可同时覆盖根和容器两种形态，并保持Live外层结构、报告节奏、容器数量及所有长度字段不变。

