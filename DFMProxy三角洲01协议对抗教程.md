# DFMProxy 三角洲 01 协议叶子替换教程

> 用途：长期记录三角洲 `01 0A 00 09` 的实际替换方法。<br>
> 当前实测版本：v1.114，规则集 `data06-dynamic-guard-v2`。<br>
> 当前数据：01～09 均为 v1.114；v1.115 尚未安装和在线验证。<br>
> 最近更新：2026-08-01。

---

## 1. 当前替换目标

01 对抗不是循环发送历史完整 01 包，而是：

```text
保留实时 Type9 容器和实时任务顺序
→ 把 Type9 明文拆成独立叶子
→ 为每个实时叶子寻找同类型、同长度的录制叶子
→ 继承实时序号、计数、时间、会话和阶段字段
→ 只引入录制叶子的干净结果字段或主体
→ 重新计算明文 CRC、密文和 01 外层 CRC
```

当前 v1.114 数据已经证明：完整历史包虽然可以通过长度和 CRC 校验，但内部任务数量、顺序、
计数器和时间会错位。真正需要解决的是“叶子中的哪些字段来自实时，哪些字段来自录制”。

---

## 2. Type9 数据结构

目标记录：

```text
01 0A 00 09
+ 10字节固定前导
+ selector:u8
+ keyIndex:u8
+ plaintextCRC32:u32be
+ ciphertextLength:u16be
+ ciphertext
```

selector：

```text
0 = tersafe custom S-Box/XOR
1 = MARS
2 = RC6
```

解密后记录的公共头：

| 相对偏移 | 类型 | 含义 |
|---:|---|---|
| `+0x00` | `u32be` | version |
| `+0x04` | `u16be` | declaredLength |
| `+0x06` | `u32be` | recordCode |
| `+0x0A` | `u32be` | recordSequence |

批量容器：

```text
recordCode = 0x010A001B
+0x14 childCount:u8
+0x15 重复：childLength:u32be + childRecord
```

二进制叶子通常为：

```text
recordCode = 0x0102000A
messageId  = leaf+0x16 的 u16be
```

实时 Type9 必须先完整解密并递归拆叶子，不能把整个密文或整个批次直接换成录制数据。

---

## 3. 为什么要按叶子替换

同一个外层 report 在两次运行中可能出现：

```text
录制包：1条叶子
实时包：10条叶子
```

也可能出现：

```text
录制和实时的 recordSequence 相近
但 recordCode / messageId 不同
```

这说明下面几项不能作为完整包替换依据：

```text
第 N 个 01 包
外层 report 相同
帧长相近
CRC 正确
```

早期完整模板测试出现过：

```text
report 84：实时10条叶子，历史模板只有1条
report 85：实时6条叶子，历史模板只有1条
内部时间落后约312～327秒
```

这些包的外层 CRC 和物理长度都正确，但内部任务结构、序列与时间已经回退，随后出现异常断开。
所以当前策略必须保持实时批次，只在批次内部逐叶子替换。

---

## 4. 叶子匹配

### 4.1 基础匹配键

录制池中的所有 Type9 包先解密，每个叶子建立索引：

```text
recordCode + messageId + actualLength
```

其中没有 messageId 的叶子使用：

```text
recordCode + None + actualLength
```

长度必须相同，当前候选构造保持实时明文总长度和每个叶子的边界不变。

### 4.2 子类型与周期匹配

仅同身份、同长度仍可能选择到另一种内部阶段，所以部分 messageId 还需要匹配：

```text
subtype
cycle_index
phase_state
sub_index
```

例如：

| messageId | 额外匹配字段 |
|---|---|
| `0x100E` | `leaf+0x20..0x23` cycle_index |
| `0x8004` | `leaf+0x20..0x23` sub_index |
| `0xFFF9` | `leaf+0x23` subtype |
| `0x0100` | `leaf+0x20..0x23` phase_state |

匹配字段不同就不选该录制叶子。

### 4.3 最近序列选择

同一匹配键通常有多个录制叶子，选择与实时 `recordSequence` 距离最近的一份：

```python
selected = min(
    candidates,
    key=lambda row: abs(row.record_sequence - live.record_sequence),
)
```

这样比完整包游标、数组取模或固定取第一份更容易对齐同一对局阶段。

---

## 5. 叶子怎么合成

候选明文最开始是完整实时明文：

```python
candidate_plaintext = bytearray(live_plaintext)
```

每个命中的叶子再单独生成候选。

### 5.1 公共头始终来自实时叶子

先复制录制叶子作为候选主体，然后覆盖实时前 14 字节：

```python
candidate_leaf = bytearray(recorded_leaf)
candidate_leaf[0:14] = live_leaf[0:14]
```

这 14 字节包含：

```text
version
declaredLength
recordCode
recordSequence
```

`recordSequence` 必须使用实时值，禁止使用录制序列，也不建议根据录制值自行 `+1`。
服务器任务调度可能批量增加，直接继承当前实时值最稳。

### 5.2 已知动态字段继续覆盖实时值

公共头之外的计数器、时间和会话字段，需要按 messageId 规则从实时叶子覆盖回候选：

```python
for field in inherit_fields:
    candidate_leaf[field] = live_leaf[field]
```

### 5.3 已知干净字段使用录制值

已经确认属于检测结果或干净测量值的范围保留录制值：

```text
实时叶子：提供容器、序号、计数、时间、会话、阶段
录制叶子：提供已确认的干净结果字段
```

### 5.4 普通未知叶子

v1.114 对结构命中、但尚未完成字段语义标注的普通叶子采用：

```text
leaf[0x00..0x0D] = 实时公共头
leaf[0x0E..end]  = 录制主体
```

日志记为：

```text
replacement_level = AGGRESSIVE_UNKNOWN
```

这能覆盖未知主体中的实时状态，但也可能把其中的计数器、时间、设备字段或阶段值换成旧数据。
因此发现异常时，优先从 `unknown_diff_offsets` 中继续识别必须继承的动态字段。

### 5.5 强动态叶子

v1.114 命中以下条件时保留完整实时主体：

```text
recordCode == 0x01122388
messageId == 0xFFF2 或 0xFFF3
recordSequence 距离 > 128
实时与录制中的十位时间戳差值 > 30秒
```

日志记为：

```text
block_reason = AGGRESSIVE_BLOCK_DYNAMIC
```

此时该叶子不引入录制主体：

```python
candidate_leaf = live_leaf
```

---

## 6. 必须继承的计数器和时序字段

这是稳定性的核心。录制叶子里的计数器属于过去那场会话，直接复制会让服务器看到回退、重复、
跨阶段或时间过旧的数据。即使 CRC 完全正确，仍会造成协议状态不一致，可能直接触发异常提示、
断开或踢下线。

### 6.1 需要分层继承

| 层级 | 字段 | 规则 |
|---|---|---|
| 01 外层 | 帧序号、包组、传输标签、外层 report | 使用实时输入 |
| Type9 容器 | selector、keyIndex、批次数量和叶子顺序 | 使用实时输入 |
| 叶子公共头 | `recordSequence` | 使用实时输入 |
| 叶子主体 | report counter、step counter、cycle、tick | 按规则使用实时输入 |
| 时间字段 | Unix 时间、运行时长、事件时间 | 使用实时输入 |
| 会话字段 | `inc_id`、`obf_id`、session word | 使用实时输入 |
| 阶段字段 | group_id、phase_state、sub_index | 继承或作为模板匹配条件 |

### 6.2 当前已标注的 inherit 字段

偏移相对于单个解密叶子，区间左闭右开：

| messageId | 必须继承实时的字段 |
|---|---|
| `0x1001` | `0x20..0x23` session_start_unix |
| `0x1003` | `0x26..0x27` session_word |
| `0x1005` | `0x28..0x2B` session_runtime_value |
| `0x100A` | `0x20..0x23`、`0x28..0x33` 多份计数器，`0x40..0x43` event_unix_time |
| `0x100E` | `0x20..0x23` cycle_index，`0x24..0x27` monotonic_tick |
| `0x1105` | `0x20..0x23` report_counter |
| `0x2001` | `0x20..0x23` fixed_step_counter |
| `0x8004` | `0x1C..0x1D` group_id |
| `0xFFFB` | `0x28..0x2B` report_counter |
| `0x0101` | `0x20..0x23` step_counter |
| `0x0102` | `0x20..0x23` step_counter |
| `0x0103` | `0x20..0x23` step_counter |

### 6.3 `0x01122388`

这一类可直接出现：

```text
内部时间
inc_id / obf_id
state
r:...
p:...
设备型号和系统版本
```

例如数据 09 中出现：

```text
inc_id:92
obf_id:92
state:00b00017,r:5/11/3041/3057/2879/71/71,p:521/521
```

这些值描述当前运行进度和状态，v1.114 会保留整个实时叶子。把录制值写回来会同时造成时间、
内部计数和设备状态回退。

### 6.4 不要只继承一个总计数器

同一条叶子可能有：

```text
当前计数
前一计数
计数副本1
计数副本2
周期号
阶段号
事件时间
```

它们之间存在内部关系。只继承其中一个、其余继续使用录制值，仍会形成矛盾。新增规则时要对连续
多包做差分，确认整个计数组，而不是看到一个递增 BE32 就结束。

---

## 7. 当前已确认的干净字段

| messageId | 录制值范围 | 说明 |
|---|---|---|
| `0x1002` | `0x20..0x23` | periodic_clean_value |
| `0x100E` | `0x2C..0x2F` | clean_measurement |
| `0xFFF9` | `0x25..0x28` | typed_clean_value |
| `0xFFFE` | `0x26..0x30` | clean_vector |
| `0x0100` | `0x24..0x97` | phase_clean_block |
| `0x0101` | `0x24..0x97` | step_clean_block |
| `0x0102` | `0x24..0x9F` | step_clean_block |
| `0x0103` | `0x24..0x9F` | step_clean_block |

注意：数据 09 表明 `0x0100` 的当前干净区内仍存在规律变化的内部计数和轮转值。这个范围后续还要
继续拆分，新的计数子字段应改为实时继承，不能长期把整个 `0x24..0x97` 当静态干净块。

---

## 8. v1.114 已发现的未知主体问题

### 8.1 `0x8023`

数据 09 的一次激进替换：

```text
recordCode: 0x0102000A
messageId: 0x8023
length: 56
实时五组状态：01 00
录制/最终五组状态：00 03
```

这是 v1.114 真正修改过的未知二进制状态数组，当前仍是优先对比对象。

### 8.2 `0x8024`

v1.114 曾把三个实时时间值换成旧录制时间：

```text
实时：2026-08-01 15:25～15:32
录制/最终：2026-04-20、2026-08-01 04:44
```

这证明 `0x8024` 主体至少包含必须继承的时间/会话数据。v1.115 已准备将其纳入完整实时保护，
但 v1.115 尚未安装测试，所以这个改动仍标记为待验证。

### 8.3 `0x011223xx` 同长度语义碰撞

只按 `recordCode + length` 匹配无 messageId 的字符串叶子，可能出现：

```text
iDevSysVer        → iAppName
iDevRes           → iDevSysName
iTotalMem         → HistoryOpenID
Language          → iDevSysVer
iPad13,4          → iPhone15,3
```

它们长度相同但语义不同。后续应为字符串类叶子增加字段名/前缀签名，或者在未识别时保留实时主体。

---

## 9. 重建与 CRC

所有叶子处理完成后，把候选叶子写回实时批次原位置，保持：

```text
顶层容器
childCount
叶子顺序
每个叶子长度
实时 recordSequence
```

随后：

```text
1. 对候选 Type9 明文重算 IEEE CRC32
2. 使用实时 selector 和实时 keyIndex 重新加密
3. 将新密文写回实时逻辑 payload
4. 对完整 01 逻辑 payload 重算外层 CRC32
5. 按实时物理分片结构重建输出帧
6. 立即重新解密候选，检查明文、签名、叶子顺序和 sequence
```

CRC：

```python
crc = zlib.crc32(data) & 0xFFFFFFFF
```

候选必须同时通过：

```text
明文 CRC
加密→解密回验
外层 CRC
物理长度与分片校验
游戏 ID 校验
批次签名校验
叶子 sequence 校验
```

---

## 10. 最终发送决策

### `REPLACE`

满足：

```text
找到同结构录制叶子
候选与实时包确实不同
候选生成和全部机械回验通过
游戏 ID 与录制池一致
```

已知干净字段变化时记为：

```text
replacement_level = KNOWN_CLEAN
```

包含普通未知主体变化时记为：

```text
replacement_level = AGGRESSIVE_UNKNOWN
```

### `PASS_LIVE`

以下情况发送实时原包：

```text
没有同 recordCode/messageId/length 的录制叶子
subtype/cycle/phase 不匹配
所有命中叶子最终没有字节变化
动态保护使候选保持实时值
解析、CRC、重新加密或机械回验失败
游戏 ID 不一致
```

判断网络真正发出的内容要看：

```text
decision
final_output
checks.final_equals_live
checks.final_equals_shadow
checks.replacement_changed
```

`shadow_candidate` 只是候选，不能单独代表服务器收到的内容。

---

## 11. v1.114 当前实验结果

当前 09 完整重放日志：

```text
总事件：1041
PASS_LIVE：652
PASS_NON_TARGET：3
REPLACE：386
发生字节变化的替换：386/386
叶子结构命中：3044/3374 = 90.2%
分析器异常：0
```

当前在线测试期间没有出现封禁。这个结果说明“实时批次 + 实时计数/时间保护 + 叶子级替换”比
完整历史包循环稳定，但仍需继续检查 `0x0100`、`0x8023`、`0x8024` 和字符串类同长度碰撞。

应将结论写成：

```text
当前 v1.114 数据未观察到封禁
```

不要写成：

```text
所有叶子规则已经永久稳定
```

因为不同客户端版本、对局阶段和新 messageId 仍可能引入新的动态计数器。

---

## 12. 三角洲历史踩坑与校验信号

三角洲对 01 内部状态的一致性反馈较快。字段组合错误时，常见表现是对局中立即提示异常、连接
断开或踢下线。这个特性可以帮助定位具体校验规则，但要把“立即反馈”和“字段正确”分开理解：

```text
立即踢下线
→ 当前改动很可能破坏了强校验项、单调状态或跨包闭环

当前会话表面正常
→ 只表示当前观察窗口内没有被实时拒绝
→ 服务端仍可能记录异常值、矛盾状态或重复特征
→ 后续会话可能出现延迟处置
```

因此三角洲踩过的坑都要保留。将同一算法迁移到反馈较慢的游戏时，这些错误可能不会马上表现为
断线，却可能持续形成服务端记录。

### 12.1 历史错误方案总表

| 坑 | 错误表现 | 根本原因 | 正确处理 |
|---|---|---|---|
| 完整历史物理帧直接发送 | 很快断开；当前连接状态不一致 | 帧序号、包组、传输标签和会话字段来自旧连接 | 实时物理结构为基础，只重建目标 Type9 |
| 完整历史 Type9 密文循环 | CRC 正确仍会异常 | 内部时间、计数、任务批次和设备状态整体回退 | 解密后逐叶子合成 |
| 全部 Type9 共用第 N 包游标 | report 84/85 附近批次严重错位 | 两次运行的任务调度和批量聚合顺序不同 | 按叶子身份、长度、子类型和最近 sequence 匹配 |
| 模板游标回卷到第一条 | 内部计数突然回退到会话开头 | 完整历史密文带回旧 `inc_id/obf_id`、时间和阶段 | 叶子索引复用；动态字段始终取实时值 |
| 不同游戏 ID 共用模板 | 身份字段和检测主体不属于同一账号/游戏 | 模板选择主键缺少 game_id | 选择和最终输出均校验 game_id |
| 新录制会话继续追加旧 01 | 新旧会话模板同时进入候选集合 | 加入阶段没有替换旧池 | 新会话使用独立模板代次 |
| 把 `01 0A 00 1D/52` 当 09 替换 | 控制流程错位、目标计数混乱 | 只搜索局部字节，没有确认完整 record marker | 非 09 类型保持实时并记 `PASS_NON_TARGET` |
| 只搜索 `0A 00 09` | 高熵区可能偶然命中 | 缺少容器边界和完整 `01 0A 00 09` 校验 | 按结构、长度和边界解析 |
| 修改 report 后沿用模板外层 CRC | 服务端直接拒绝帧 | report 位于外层 CRC 覆盖范围 | 对修改后的完整逻辑 payload 重算 CRC |
| 只复制密文 | 解密失败或明文 CRC 错误 | selector、keyIndex、明文 CRC、密文不是同一组 | 重新加密时整组保持自洽 |
| 用录制 selector/keyIndex 加密实时容器 | 当前算法状态与密钥选择发生跳变 | 使用了旧 Type9 加密上下文 | 使用实时 selector 和实时 keyIndex |
| 修改明文后遗漏明文 CRC | 外层 CRC 正确，Type9 内部仍校验失败 | Type9 有独立 plaintext CRC | 先重算明文 CRC，再加密和重算外层 CRC |
| 未收齐物理分片就开始替换 | payload 不完整、CRC 输入错误 | 把单个物理片当成完整逻辑包 | 收齐、排序、重组后处理 |
| 把后续分片 `0x2F` 当传输标签 | 分片长度字段被破坏 | 首片和后片在 `0x2F` 的定义不同 | 首片继承标签；后片保留/重算 BE32 数据长度 |
| 自己根据模板序号 `+1` | 批量任务出现跨越、重复或回退 | 实际 sequence 由当前客户端任务调度产生 | 直接继承实时 `recordSequence` |
| 只继承一个计数器 | 同一叶子内计数副本互相矛盾 | 忽略 current/previous/copy/cycle 的关系 | 对齐连续包，继承完整计数组 |
| 继承外层 report，却遗漏内部计数 | 外层顺序正常，明文内部回退 | 把外层与叶子层误认为同一个计数系统 | 分层维护外层、容器、叶子和消息内部计数 |
| 使用录制 Unix 时间 | 时间突然回到数分钟前或更早 | 录制值属于历史会话 | Unix 时间、运行时长和事件时间取实时值 |
| 使用录制 `inc_id/obf_id` | 状态字符串中的任务进度回退 | 复制了旧运行代次 | `0x01122388` 等强动态记录保留实时主体 |
| 同 recordCode+长度就替换字符串叶子 | 设备、字段名和账号内容交叉 | 同长度不代表同语义 | 增加字段名前缀/语义签名，未识别时保留实时 |
| `0x8024` 当普通未知主体 | 实时时间被换成旧录制时间 | 未识别该叶子的时间语义 | 将时间范围标为 inherit，或完整实时保护 |
| `0x0100` 整块当干净数据 | 隐藏计数和轮转值被固定成录制值 | clean 范围过大 | 继续拆分内部计数、阶段和真正干净范围 |
| 只检查 CRC 和长度 | 包机械合法，但业务状态已经冲突 | 传输校验不验证任务语义 | 同时检查批次签名、叶子顺序、sequence、时间和计数 |
| 候选回验通过就认为已发送 | 分析结论与实际网络输出不一致 | shadow 候选和 final_output 混淆 | 以 `decision` 和 `final_output` 为准 |
| 一次同时修改多个未知叶子 | 出现异常后定位不到具体字段 | 变量过多，缺少单一变更对照 | 分批启用规则，记录首次变化和异常时间 |

### 12.2 已经出现过的强证据

#### 完整模板批次错位

```text
第一轮 report 84：live 10叶子 / template 1叶子
第一轮 report 85：live 6叶子  / template 1叶子

第二轮 report 85：template 11叶子 / live 1叶子
第二轮 report 87：template 1叶子  / live 11叶子
第二轮 report 89：sequence 接近，但 messageId 不同
```

这些实验中三路 CRC 可以全部正确，说明三角洲除了校验封包机械结构，还会消费内部任务状态。

#### 历史时间回退

早期完整模板实验中，录制明文时间相对实时落后约 312～327 秒。数据 09 的 `0x8024` 又出现
实时 2026-08-01 时间被替换成 2026-04-20 和当天凌晨时间。时间值回退是当前最明确的高风险坑。

#### 同长度语义碰撞

数据 09 已实际出现：

```text
iDevSysVer       → iAppName
iDevRes          → iDevSysName
iTotalMem        → HistoryOpenID
Language         → iDevSysVer
iPad13,4         → iPhone15,3
```

这类包可以通过 CRC、长度和重新解密，却会让同一次上报中出现互相冲突的设备与字段语义。

#### 计数器与状态组

`0x01122388` 中同时存在：

```text
Unix 时间
inc_id / obf_id
state
r:多项计数
p:多项计数
```

`0x100A` 中同时存在当前计数、计数副本、上一计数和事件时间。只继承其中一个会留下跨字段矛盾，
所以动态字段要按组识别。

### 12.3 三种服务端反馈模型

将替换逻辑迁移到其他游戏时，至少按以下三种模型记录结果：

| 模型 | 客户端表现 | 分析含义 |
|---|---|---|
| 强实时校验 | 当场提示、断开或踢下线 | 有利于快速定位状态闭环、CRC、序号和时间错误 |
| 延迟校验 | 当前会话继续，稍后出现异常 | 可能按周期、累计分数或跨包一致性处理 |
| 记录后处理 | 当前会话表面正常 | 异常字段可能已进入服务端日志，后续会话存在追溯处置可能 |

所以每次测试要分开记录：

```text
传输层：包是否被服务器接受
会话层：当前对局是否持续稳定
账号层：后续重新登录和后续会话是否正常
```

“没有马上踢下线”只覆盖前两层的当前观察窗口，不等于所有计数器和检测字段已经正确。

### 12.4 如何利用三角洲的立即反馈定位规则

1. 每个版本只调整一组 messageId 或一个字段范围；
2. 记录首次 `REPLACE` 的 event/report/time；
3. 记录首次提示、断开或踢下线的精确时间；
4. 取异常前最后 10～20 个事件；
5. 优先检查新启用的 `AGGRESSIVE_UNKNOWN`；
6. 对比 `live/template/candidate/final` 四份叶子；
7. 查找回退计数、旧时间、设备语义碰撞和 sequence 距离；
8. 将确认的动态范围加入 inherit 或完整实时保护；
9. 使用相同录制池和相同场景再次验证；
10. 即使当前会话稳定，也继续记录后续登录和会话结果。

不要在一次构建中同时修改大量未知叶子。三角洲立即踢下线的价值就在于提供清晰的错误时间点，
如果一次改动过多，这个反馈会失去定位作用。

### 12.5 每次实验建议记录

```text
DFMProxy 版本和 Git commit
规则集版本
录制数据版本
本次启用的 messageId/字段范围
首次 REPLACE 时间
最后一个正常 report
首次异常时间
异常前最后一个 REPLACE
计数器是否单调
时间是否来自实时
final_output 是否等于预期候选
当前会话结果
后续登录/会话观察结果
```

这份记录既用于三角洲的即时定位，也用于反馈较慢游戏的后续追溯分析。

---

## 13. v1.114.1 跨账号模板实验

### 13.1 实验问题

验证以下假设：

```text
账号 A 录制的干净 Type9 叶子
+ 账号 B 的实时容器、账号、序号、计数、时间和会话字段
→ 能否组成账号 B 可持续发送的 01 包
```

该实验使用独立分支：

```text
experiment/v1.114.1-cross-account
```

版本显示：

```text
v1.114.1-cross-account
```

### 13.2 donor 选择

```text
先查账号 B 的同账号录制池
→ 命中时继续使用同账号池
→ 未命中且开启“跨账号01模板(114.1)”时
→ 选择最近一份其他 game_id 的非空 01 池
```

跨账号模式只返回 donor 的 `pool_01`：

```text
pool_01 = donor 的 01 模板
pool_33 = 空
```

这样本轮只验证 01，另一账号的 33 握手、序列和密文不会进入实时连接。

### 13.3 字段来源

| 内容 | 来源 |
|---|---|
| 01 外层物理帧和账号 B 的 `0A 00 23` | 实时包 |
| Type9 selector/keyIndex | 实时包 |
| 批次结构、childCount、叶子顺序 | 实时包 |
| recordSequence | 实时叶子 |
| 计数器、时间、cycle、phase、session | 实时叶子 |
| 已确认 clean 字段 | donor 录制叶子 |
| 普通未知主体 | donor 录制叶子，仍受动态门控 |
| 强动态叶子 | 实时叶子 |
| 明文 CRC、密文、外层 CRC | 根据最终候选重新计算 |

候选始终以账号 B 的完整实时逻辑包为底稿，所以外层当前账号不会被 donor 外层账号覆盖。

### 13.4 叶子内账号改写

如果 donor 叶子主体中精确出现账号 A 的 ASCII game_id：

```text
账号 A ID 与账号 B ID 等长
+ 实时同结构叶子的相同偏移确实是账号 B ID
→ 将候选中的账号 A ID 等长写成账号 B ID
```

以下情况完整保留该实时叶子：

```text
两个 ID 长度不同
实时同结构叶子中没有账号 B ID
```

第二项用于阻止同长度语义碰撞。例如 donor 叶子虽然含账号 A，但实时同长度叶子实际上是设备
信息或另一种字符串字段，此时写入账号 B 仍然会造成字段语义错误。

`HistoryOpenID` 等字段可能描述历史账号，而不是当前 game_id；当前实验只改写与 donor game_id
逐字节完全相同的值，不批量替换所有数字字符串。

### 13.5 最终身份校验

发送前继续验证：

```text
final_output 解析出的 game_id == live_game_id
Type9 叶子 sequence == 实时 sequence
候选明文 CRC 正确
重新加密后可解密回原候选明文
01 外层 CRC 与物理分片正确
```

身份语义碰撞叶子记录：

```text
block_reason = CROSS_ACCOUNT_IDENTITY_BLOCK
identity_rewrite.status = ID_LENGTH_MISMATCH
或 LIVE_ID_CONTEXT_MISMATCH
```

### 13.6 专属日志

`01_replace_events.jsonl` 与 `01_replace_summary.csv` 新增：

```text
cross_account
live_game_id
donor_game_id
identity_rewrite_count
identity_blocked_leaves
identity_rewrite_ranges
final_identity_check
```

每次测试首先确认：

```text
cross_account.enabled = true
live_game_id = 当前测试账号
donor_game_id = 干净录制账号
final_identity_check = true
```

### 13.7 测试观察点

1. 账号 B 是否完成上线、进局和完整对局；
2. 首次跨账号 `REPLACE` 的时间、event 和 report；
3. 是否出现 `CROSS_ACCOUNT_IDENTITY_BLOCK`；
4. donor 主体中是否还残留账号 A 的精确 ID；
5. 内部计数、时间、`inc_id/obf_id` 是否持续来自账号 B；
6. 异常前最后 20 个替换叶子；
7. 当前会话结束后的重新登录和后续会话表现。

v1.114.1 当前属于待在线测试版本。测试结果应进入新的数据目录，与 v1.114 的 01～09 数据分开。

---

## 14. 新叶子规则怎么补

发现新 `recordCode/messageId/length` 或异常前新变化时：

1. 收集同一叶子连续至少 10 次实时值；
2. 对齐录制、实时、候选和最终四份 HEX；
3. 标出所有差异区间；
4. 将单调增加、周期轮转、Unix 时间、运行时长、会话 ID 标为 `inherit`；
5. 将 subtype、cycle、phase、sub_index 标为 `match`；
6. 只有在多轮干净数据中稳定、且需要引入录制结果的范围才标为 `clean`；
7. 无法确定语义但明显包含时间/计数时，先加入动态保护；
8. 重算并验证明文 CRC、外层 CRC、序号和完整物理帧；
9. 将新规则、证据事件和版本记录到本文。

建议日志字段：

```text
record_code / message_id / length
live_sequence / template_sequence / sequence_distance
match_fields
inherited_fields
clean_fields
clean_diff_offsets
unknown_diff_offsets
dynamic_guard / block_reason
live_hex / template_hex / candidate_hex
decision / final_output
```

---

## 15. 当前源码位置

```text
core/type9_shadow.py
  - Type9 明文解析
  - 叶子索引
  - SEMANTIC_RULES
  - inherit / match / clean
  - 动态保护
  - 候选明文生成

core/crypto.py
  - 候选重新加密
  - 外层物理帧重建
  - REPLACE / PASS_LIVE 门控

core/traffic_session_log.py
  - 01_replace_events.jsonl
  - 01_replace_summary.csv
  - 01_replace_errors.jsonl
```

快速分析：

```bash
python tools/analyze_01_replay_log.py "C:\PyProxyApp\01ReplayAnalysis\run_<时间>"
```

---

## 16. 后续更新区

### 2026-08-01 / v1.114 基线

- 确立实时 Type9 容器内的叶子级替换；
- 叶子使用 `recordCode + messageId + length` 匹配；
- 公共 14 字节头和已知计数/时间字段继承实时值；
- 普通未知主体允许使用录制值；
- `0x01122388`、`0xFFF2/0xFFF3`、序号距离和旧时间进入动态保护；
- 当前 09 在线数据未观察到封禁；
- `0x8024` 和字符串类同长度碰撞仍需进一步修正。

### 2026-08-01 / 历史坑汇总

- 记录完整帧、完整密文、全局游标、计数回退、旧时间和同长度语义碰撞；
- 区分三角洲即时踢下线、延迟异常和服务端记录后处理；
- 将当前会话正常与后续账号观察拆成不同结论；
- 固化单变量测试和异常时间点回溯方法。

### 2026-08-01 / v1.114.1 跨账号实验版

- 同账号池缺失时选择最近一份其他账号 01 donor 池；
- 33 池保持为空，单独验证 01；
- 外层账号、叶子 sequence、计数、时间和会话状态继续继承实时；
- donor 叶子中的精确账号 ID 仅在等长且实时语义对应时改写；
- 身份上下文冲突时完整保留实时叶子；
- 增加 live/donor 身份、改写区间和最终身份校验日志；
- 该版本等待首次在线测试。

### v1.115 待验证

- v1.115 尚未安装；
- 预计增加 `0x8024` 等专项实时保护和差分日志；
- 实测数据必须放入新的版本目录，不与 v1.114 的 01～09 数据混算；
- 完成在线测试后再把验证结果写入本教程。

---

## 17. v1.117 未命中叶子裁剪完整实例

> v1.118 正式默认策略为 `UNMATCHED_LEAF_PASS_LIVE`：玩家池和官方池都未命中的叶子保留完整实时字节。本节 v1.117 裁剪算法仅作为显式专项实验与历史对照保留；v1.118 实验启用时必须同时设置 `v118_unknown_leaf_policy=prune` 和 `v118_leaf_prune_experiment_enabled=true`。

本节给出可以直接交给其他 AI 或移植到其他游戏适配器的字节级实例。所有偏移都相对于
**解密后的当前 Record 起点**，不是相对于外层 01 物理帧，也不是相对于 Type9 密文。

### 17.0 当前默认：未知叶子实时透传

```text
实时叶子
→ 玩家模板精确匹配
→ 玩家未命中时查询已发布官方模板
→ 两级池均未命中：保留该叶子的完整实时 raw
→ 原始 childCount、子项顺序、子项长度均不变化
→ 普通日志限量保存未知叶子及对应的完整 Type9 明文、完整01物理帧
→ 后续按 recordCode + messageId + length 做专项规则
```

如果同一报告内其他已知叶子发生替换，未知叶子仍逐字节来自实时包；整份报告没有实际变化时，
输出原始实时帧并记录 `reason=UNMATCHED_LEAF_PASS_LIVE`。

### 17.1 专项实验的裁剪触发条件

对每个实时叶子依次查询：

```text
玩家池 recordCode + messageId + actualLength + 语义匹配字段
→ 玩家池命中：使用玩家模板
→ 玩家池未命中：查询已发布官方池
→ 官方池命中：使用官方模板
→ 两级池均无 recordCode + messageId + actualLength 基础候选
→ 当前 Record 是批次子叶子，path 非空
→ 标记 UNMATCHED_LEAF_PRUNE
```

同结构候选存在、但 `subtype/cycle` 等语义字段未命中时，不按“未知结构”裁剪；该叶子保留
实时主体并继续记录差异。独立根 Record 的 `path=[]`，同样不执行子叶子裁剪。

### 17.2 裁剪前：一个父批次包含两个叶子

下面使用最小化的合成样本，只展示公共头、长度、序号和 `messageId`：

```text
父批次 recordCode = 0x010A001B
父批次 declaredLength = 0x004D = 77
父批次 recordSequence = 0
父批次 childCount = 2

子叶子1：length=0x18，recordCode=0x0102000A，sequence=0x35，messageId=0x8024
子叶子2：length=0x18，recordCode=0x0102000A，sequence=0x36，messageId=0x8029
```

长度计算：

```text
父固定区                = 0x15 = 21字节
子叶子1长度前缀+叶子    = 4 + 0x18 = 28字节
子叶子2长度前缀+叶子    = 4 + 0x18 = 28字节
父总长度                = 21 + 28 + 28 = 77 = 0x004D
```

裁剪前完整 HEX：

```text
0000  00 00 00 01 00 4D 01 0A 00 1B 00 00 00 00 00 00
0010  00 00 00 00 02 00 00 00 18 00 00 00 01 00 18 01
0020  02 00 0A 00 00 00 35 00 00 00 00 00 00 00 00 80
0030  24 00 00 00 18 00 00 00 01 00 18 01 02 00 0A 00
0040  00 00 36 00 00 00 00 00 00 00 00 80 29
```

关键边界：

| 父相对偏移 | 长度 | 内容 |
|---:|---:|---|
| `0x00` | 4 | 父 `version` |
| `0x04` | 2 | 父 `declaredLength=0x004D` |
| `0x06` | 4 | 父 `recordCode=0x010A001B` |
| `0x0A` | 4 | 父 `recordSequence=0` |
| `0x14` | 1 | `childCount=2` |
| `0x15` | 4 | 子叶子1长度前缀 `0x18` |
| `0x19` | 24 | 子叶子1完整 Record |
| `0x31` | 4 | 子叶子2长度前缀 `0x18` |
| `0x35` | 24 | 子叶子2完整 Record |

注意：`0x14` 是 `childCount`；每条 Record 自己的 `recordSequence` 都位于该 Record
相对偏移 `0x0A..0x0D`。

### 17.3 删除 `0x8024` 叶子

假设玩家池和官方池都没有子叶子1的精确结构，而子叶子2已命中。裁剪范围必须包含：

```text
子叶子1的 u32be 长度前缀 + 子叶子1完整 Record
= 父相对偏移 [0x15, 0x31)
= 4 + 0x18
= 28字节
```

裁剪后：

```text
childCount：      0x02 → 0x01
declaredLength：  0x004D → 0x0031
保留叶子 sequence：仍为 0x36，不重排、不减一
保留叶子 messageId：仍为 0x8029
```

新长度计算：

```text
父固定区                = 21字节
剩余叶子长度前缀+叶子    = 4 + 24 = 28字节
父总长度                = 21 + 28 = 49 = 0x0031
```

裁剪后完整 HEX：

```text
0000  00 00 00 01 00 31 01 0A 00 1B 00 00 00 00 00 00
0010  00 00 00 00 01 00 00 00 18 00 00 00 01 00 18 01
0020  02 00 0A 00 00 00 36 00 00 00 00 00 00 00 00 80
0030  29
```

### 17.4 递归重建伪代码

实际数据允许批次嵌套批次，因此要从叶子向根递归重建，而不是只改最外层两个长度字节：

```python
def rebuild(node, prune_paths, replacement_by_path):
    path = tuple(node.path)

    if not node.children:
        if path in prune_paths:
            return None
        return replacement_by_path.get(path, node.raw)

    # 原始子项结束位置之后的内容属于父节点 trailer，必须保留。
    trailer = node.raw[node.original_children_end:]
    rebuilt_children = []

    for child in node.children:
        rebuilt_child = rebuild(child, prune_paths, replacement_by_path)
        if rebuilt_child is not None:
            rebuilt_children.append(rebuilt_child)

    header = bytearray(node.raw[:0x15])
    header[0x14] = len(rebuilt_children)        # childCount

    result = header
    for child in rebuilt_children:
        result += u32be(len(child))             # 新的子项长度前缀
        result += child
    result += trailer

    result[0x04:0x06] = u16be(len(result))      # 当前父节点长度
    return bytes(result)
```

嵌套批次中，内层长度变化会使外层长度继续变化；递归返回时每一级都要更新自己的
`declaredLength`、`childCount` 和子项 `u32be length`。

### 17.5 空批次保护

裁剪候选只有在至少一个实时叶子成功命中玩家或官方模板时才进入发送门控：

```text
matched_leaves > 0
+ shadow机械回验通过
+ changed_leaves > 0
→ 允许发送候选
```

如果整份报告的所有叶子都未命中，`matched_leaves=0`，最终发送实时报告。这样可避免把一个
原本包含任务状态的批次变成 `childCount=0` 的空报告。

### 17.6 从明文到最终01物理帧的更新顺序

```text
1. 解密实时 Type9，得到完整明文树
2. 标记需要替换和裁剪的叶子 path
3. 从叶子向根递归重建明文
4. 更新每级 childCount、u32be childLength、u16be declaredLength
5. 计算最终 Type9 plaintext CRC32
6. 使用实时 selector 和 keyIndex 重新加密
7. 更新 Type9 ciphertextLength
8. 把新 Type9 Record 写回实时逻辑 payload
9. 按新逻辑长度重建01物理分片
10. 继承实时会话字段、报告次数和传输标签
11. 重新计算外层01 CRC32
12. 再次解密候选并检查结构、明文CRC、身份和帧CRC
```

仅修改 `childCount` 和父长度后直接发送是不完整的：Type9 明文 CRC、密文、密文长度、
01 逻辑长度、物理帧长度和外层 CRC 都依赖最终明文。

### 17.7 日志判定

显式启用专项实验并发生真实裁剪时：

```text
decision = REPLACE
reason = V117_TIERED_MISS_LEAF_PRUNE
replacement_level = UNMATCHED_LEAF_PRUNE
pruned_leaves > 0
checks.output_crc_ok = true
checks.output_validation_ok = true
checks.shadow_decode_ok = true
```

普通日志还会生成：

```text
01_unknown_leaf_samples.jsonl
01_unknown_context_samples.jsonl
01_unknown_leaf_stats.json
```

第一个文件为每种未命中结构保存最多三份原始叶子；第二个文件按同一 `event_id` 保存完整01帧和
完整 Type9 明文；第三个文件累计出现次数。分析游戏更新时应先按
`recordCode + messageId + actualLength + subtype变体` 聚类，再判断未知叶子中是否存在时间、
计数器、会话或阶段字段。
