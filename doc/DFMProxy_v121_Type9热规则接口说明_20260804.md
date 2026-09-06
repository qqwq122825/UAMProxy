# DFMProxy v1.121 Type9 叶子热规则

## 目标

把“某个精确消息使用实时改写、模板替换还是完整透传”从打包代码中拆出。
首次安装v1.121后，后续只更新JSON并调用接口，不重启代理、不重新上传EXE。

运行文件：

```text
C:\PyProxyApp\type9_hot_rules.json
```

程序启动时加载一次，运行中每秒最多检查一次文件时间；也可通过管理接口立即上传或重载。
解析失败时保留上一代可用内存快照，避免半写文件影响正在运行的连接。

## 匹配方式

普通规则使用三元组精确匹配：

```text
(record_code, message_id, leaf length)
```

同一三元组只允许一条启用规则。根级消息和批量容器中的叶子在解密后使用同一套匹配逻辑。

`replace_template_nearest` 还支持把 `length` 写成 `"*"`，表示按
`(record_code, message_id)` 匹配所有长度。若同一消息ID同时配置了精确长度规则和
通配长度规则，精确规则优先。

## 四种动作

### `patch_live`

以实时叶子为基础，只修改声明的字节。适合已确认偏移、又要保留实时计数的消息。

```json
{
  "id": "0207-zero-anomaly-counters",
  "enabled": true,
  "match": {
    "record_code": "0x0102000A",
    "message_id": "0x0207",
    "length": 116
  },
  "action": "patch_live",
  "patches": [
    {"offset": "0x48", "hex": "00000000", "note": "body+0x28"},
    {"offset": "0x50", "hex": "00000000", "note": "body+0x30"}
  ]
}
```

### `replace_template`

使用当前同结构、同子类型、最近序号模板作为基础，默认继承实时前14字节公共头；可继续追加定点补丁。

```json
{
  "id": "MESSAGE-template-body",
  "enabled": true,
  "match": {
    "record_code": "0x0102000A",
    "message_id": "0xMESSAGE",
    "length": 116
  },
  "action": "replace_template",
  "inherit_live_header": 14
}
```

没有同结构模板时该条规则保留实时叶子，并在 `special_rule_error` 写入 `HOT_RULE_TEMPLATE_REQUIRED`。

### `replace_template_nearest`

按消息ID从干净录制池选择长度最接近的叶子，完整使用干净模板正文，同时继承实时
结构版本、recordCode和叶子序号。该动作支持模板与Live长度不同；重建时会同步更新：

- 叶子声明长度；
- `0x010A001B` 批量容器子项长度与容器总长度；
- Type9 明文CRC、密文长度与密文；
- 01物理分片长度、分片数量与外层CRC。

`inherit_live_header` 默认是14。对于正文前还包含动态消息头或内部计数器的消息，可以
扩大继承范围；变长替换会保留模板长度字段，并继承除此长度字段以外的指定Live前缀。
例如 `0x1105` 使用36字节前缀，保留Live二进制消息头和内部枚举序号，只从干净模板
取得 `0x24` 之后的 `NULL` 结果区：

```json
{
  "id": "1105-clean-module-enumeration",
  "enabled": true,
  "match": {
    "record_code": "0x0102000A",
    "message_id": "0x1105",
    "length": "*"
  },
  "action": "replace_template_nearest",
  "inherit_live_header": 36
}
```

进程扫描规则示例：

```json
{
  "id": "8027-clean-process-profile",
  "enabled": true,
  "match": {
    "record_code": "0x0102000A",
    "message_id": "0x8027",
    "length": "*"
  },
  "action": "replace_template_nearest"
}
```

同样的规则已用于 `0x1105`、`0x2000`、`0x8029` 和 `0x9000`。其中 `0x1105`
模块枚举和 `0x2000` 模块结果始终使用干净录制池中长度最近的正文。每个Live扫描叶子的正文都取自干净录制池；
Live叶子数量和叶子序号保持实时值，从而保持当次报告的序号结构。若Live同批出现的
扫描叶子多于干净录制，额外叶子也会被干净模板覆盖，日志中可能看到模板被重复选中。

### `pass_live`

完整保留实时叶子，用于临时关闭某条替换：

```json
{
  "id": "MESSAGE-pass",
  "enabled": true,
  "match": {
    "record_code": "0x0102000A",
    "message_id": "0xMESSAGE",
    "length": 116
  },
  "action": "pass_live"
}
```

## 可选原值保护

补丁可加入 `expect_hex`。当前字节与预期不一致时整条规则保留实时值并记录错误，适合客户端结构升级检测：

```json
{
  "offset": "0x48",
  "expect_hex": "01000000",
  "hex": "00000000"
}
```

## 管理接口

所有接口使用现有 `admin_token` 鉴权：

```text
GET  /api/type9/rules
POST /api/type9/rules
POST /api/type9/rules/reload
```

请求头：

```text
X-Admin-Token: TOKEN
```

上传会先完整校验，再使用临时文件和 `os.replace` 原子切换；成功后立即替换内存快照。

### 命令行客户端

```powershell
python tools\type9_rule_client.py --url http://HOST:8787 --token TOKEN status

python tools\type9_rule_client.py --url http://HOST:8787 --token TOKEN `
  apply tools\type9_hot_rules_process_scan.json

python tools\type9_rule_client.py --url http://HOST:8787 --token TOKEN reload
```

也可以直接修改服务器上的JSON。程序会自动检测文件变化；`reload`用于立即读取并返回校验结果。

### 桌面端加载

进入：

```text
拦截管理 → 01 Type9热规则
```

该区域提供：

- **加载规则文件**：选择JSON，完整校验后原子保存并立即切换；
- **重载当前文件**：重新读取运行目录中的 `type9_hot_rules.json`；
- **导出**：保存当前内存中的规范化规则文档；
- 规则表：显示启用状态、规则ID、recordCode、messageId、长度、动作和成功改写次数。

`成功改写`仅在候选字节与Live字节实际不同并完成规则改写时加1。字段原本已经是目标
值、模板缺失、模板与Live相同或 `pass_live` 都保持原计数。界面每秒刷新；成功加载
或重载一份规则文件后进入新generation，并从0重新统计。

界面不为每个消息ID创建单独开关；新增、删除和组合规则都由JSON文档表达。
旧版拦截状态、命令名黑名单、33字符串替换和01阈值拦截面板已从DFM专版界面移除；
历史配置对象暂留为隐藏兼容层，避免旧配置文件影响启动。

## 日志字段

每条命中叶子的 `leaf_results` 会记录：

```text
special_rule_id
special_rule_action
special_hot_action
special_rule_error
replacement_level
live_hex
candidate_hex
candidate_length
template_length
```

`replacement_level`对应：

```text
SPECIAL_PATCH_LIVE
SPECIAL_REPLACE_TEMPLATE
SPECIAL_REPLACE_TEMPLATE_NEAREST
SPECIAL_PASS_LIVE
```

汇总中的 `variable_length_replaced_leaves` 记录本包跨长度替换数量。进程扫描规则成功
改写时，顶层 `replacement_level` 为 `SPECIAL_REPLACE_TEMPLATE_NEAREST`，原因字段为
`PROCESS_SCAN_CLEAN_TEMPLATE_REPLACE`。

最终输出仍经过现有 Type9 明文CRC、加密、01外层CRC和解密回验。

## 默认规则

v1.121首次启动若文件不存在，会生成以下默认规则：

```text
0x0207/116
完整叶子+0x48（body+0x28）清零
完整叶子+0x50（body+0x30）清零
其余全部使用实时字节
```

因此普通累计字段、浮点值和实时叶子序号不再随模板末尾冻结。

```text
0x1105/* -> replace_template_nearest（继承Live前36字节）
0x2000/* -> replace_template_nearest
0x8027/* -> replace_template_nearest
0x8029/* -> replace_template_nearest
0x9000/* -> replace_template_nearest
```

升级机器若已存在旧版 `type9_hot_rules.json`，使用仓库中的
`tools/type9_hot_rules_full.json` 通过 `apply` 上传即可立即切换，代理进程和现有
连接保持运行。
