# DFMProxy v1.128.9 改动校验报告

日期：2026-08-25
项目：`/Users/xxx/Documents/aceProxy/DFMProxy`
分支：`codex/v128-v1-same-device`
状态：已完成第二轮代码审查、缺陷修正、全量测试与历史回溯，达到提交/tag条件

> **v1.128.10勘误（2026-08-25）：** 后续逐字节回看全部42B旧样本，确认末尾4字节是Unix时间戳，而不是进程运行秒钟。v1.128.9仅凭末尾u16续接的结论已由v1.128.10取代。新规则使用`+0x0A`四字节会话候选，并由首个Live Type9报告的`recordSequence`与代理内存旧报告进行最终确认。

## 1. 本轮目标

1. 01 网络断开重连时延续游戏/ACE逻辑时间轴，避免80xx从头重复补发。
2. 同一设备首次干净录制后，支持不同游戏账号复用同设备录制数据。
3. 增加128.9结构化重连日志和历史日志回溯工具。

## 2. 已实现改动

### 2.1 42B连续秒钟与逻辑游戏会话

新增 `core/replay_session_v129.py`：

- 解析42字节加入帧最后2字节大端u16值。
- 使用 `(前值 + 实际时间差) mod 65536` 计算连续性。
- 当前容差为4秒。
- 支持u16从65535回绕到0。
- 逻辑会话暂按 `(proxy_username, game_id)` 建立索引。
- 连续时保留Type9语义状态、已满足时隙、玩家模板消费状态及设备上下文。
- 新TCP/01连接重新建立 `report/frame/group/leaf` 传输偏移。
- 输出分类：`FIRST_JOIN`、`NETWORK_RECONNECT`、`GAME_REOPEN_OR_NEW_SESSION`。

### 2.2 Server接入

修改 `core/server.py`：

- 42B上行帧到达时记录加入秒钟。
- UID绑定录制池时调用128.9逻辑会话注册表。
- 网络重连判定成功时恢复原游戏时间轴起点。
- 保留Type9/80xx语义消费状态，传输游标重新建立。
- 连接结束时保存逻辑会话快照。
- 空录制池路径也接入逻辑会话管理。
- 01池选择入口替换为 `find_v129_01_pool()`。

### 2.3 同设备跨账号候选池

修改 `core/pool.py`：

- 新增 `find_same_device_candidate_01_pool()`。
- 新增 `find_v129_01_pool()`。
- 玩家录制不再只按游戏账号暴露；不同账号录制被标记为设备候选。
- 3366项目排除在跨账号设备候选之外。
- 官方模板仍作为独立回退层。
- 跨账号设备候选仅在 `full_rebuild_01_mode=true` 时建立；关闭时保持原账号池。
- 3366握手与延迟匹配继续使用账号级池，避免01候选池造成33池为空。

### 2.4 严格设备门控

修改 `core/crypto.py` 和 `core/type9_v128_replenish.py`：

- 同设备判定使用 `model + system_version + device_idfv`。
- 跨账号玩家模板先作为候选，Live采集到完整设备上下文后才固定一个录制会话。
- 同时存在“当前账号但设备不一致”和“其他账号但设备一致”的录制时，设备一致会话优先。
- 玩家补充80xx跨账号时记录 donor游戏账号。
- 录制叶正文存在等长ASCII账号字段时改写成Live账号。
- AI日志增加设备池选择、donor和设备门控结果。

### 2.5 128.9重连日志

新增机器日志：`AI日志/run_*/reconnect_events.jsonl`

事件类型：

- `JOIN_42_OBSERVED`：42B完整Hex、u16十进制及十六进制值。
- `DISCONNECT_OBSERVED`：断开连接、加入秒钟、逻辑运行时间及过期连接忽略状态。
- `BIND_DECISION`：前后连接、时间差、预期值、误差、分类、语义状态继承数量、设备上下文和归零后的传输偏移。

涉及文件：

- `core/ai_log_v128.py`
- `core/traffic_session_log.py`
- `core/server.py`

### 2.6 版本标记

- UI版本：`v1.128.9`
- 模型修订：`v128.9-reconnect-device-pool-r1`
- README和消息目录修订同步到128.9。

## 3. 回溯模拟结果

输入日志：

`/Users/xxx/Documents/aceProxy/DFMProxy/数据/128/128.8/检测前重放长时间/AI日志/run_20260824_213633_063843`

报告：

`/Users/xxx/Documents/aceProxy/DFMProxy/数据/128/128.8/检测前重放长时间/v129_回溯模拟报告.json`

结果：`PASS`

- 旧连接：`223.104.137.14:23622`
- 新连接：`223.104.137.14:18781`
- 42B值：`20824 -> 24499`
- 实际间隔：`3675秒`
- 预期值：`24499`
- 误差：`0秒`
- Live叶序号：`2196 -> 2197`
- report：`571 -> 1`
- frame：`60528 -> 39516`
- packet group：`573 -> 2`
- 模拟连续游戏时间：`3675208ms`
- 可抑制重复中央补发：slot `30/158/270/330`，共4报告、27叶。
- 新连接输出组机械校验全部通过。

回溯工具：`tools/backtest_v129_reconnect.py`

第二轮校验同时修复了工具直接执行时仓库根目录不在 `sys.path` 的问题，并将每个注入组的叶数按该组 `message_ids` 计算，避免把事件级总数重复计入每个组。

## 4. 自动化测试

执行：

```bash
/Users/xxx/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 \
  -m unittest discover -s tests -p 'test_*.py'
```

结果：

```text
Ran 233 tests
OK (skipped=21)
```

新增/扩展覆盖：

- 42B解析、时间连续、u16回绕。
- 游戏秒钟重置建立新会话。
- 重连保留语义消费状态、归零传输偏移。
- 同设备跨账号玩家池。
- 全额重建关闭时保持账号级池及3366池。
- 设备不一致时拦截跨账号玩家数据。
- 同账号错误设备与跨账号正确设备并存时选择正确设备。
- 新旧连接短暂重叠时，旧连接回调不会覆盖或断开新会话。
- 断开逻辑会话6小时过期、42B待绑定记录5分钟过期。
- 128.9重连结构化日志。

额外静态校验：`compileall` 与 `git diff --check` 均通过。

## 5. 第二轮审查结果

### 5.1 42B字段来源仍需真实“结束进程重开”样本确认

现有数据证明该u16值在网络重连期间按秒连续增加，但字段可能来自：

- 游戏/ACE进程秒钟；或
- 设备单调秒钟的低16位。

如果属于设备单调秒钟，游戏结束后重新打开仍可能连续。因此实现与README统一称为“42B连续秒钟”，不再把字段来源写死成进程时间。当前续接同时要求代理账号、游戏ID和42B时钟闭合；断开快照最多保留6小时。现有长重连样本还具有Live叶序号 `2196 -> 2197` 的独立连续证据。后续收到“结束游戏进程重开”样本时，再把首个Live叶 `record_sequence` 或Type9初始化结构加入分类器。

### 5.2 设备档案展示边界

当前设备信息由录制模板Type9叶动态提取，严格门控与导出/导入后的重新提取均不依赖UI列。本版本未增加：

- 录制会话显式 `device_id/device_idfv/device_profile_key` 字段；
- 录制管理表“设备ID”列；
- 按设备聚合展示不同账号；
- 独立的设备档案索引缓存。

这些是后续可视化/索引优化项，不影响128.9运行时从Type9原始录制提取 `model + system_version + device_idfv`。

### 5.3 “全额重建”开关边界：已修正

第二轮发现候选池建立早于 `full_rebuild_01_mode` 门控，会使一般Type9影子路径提前看到跨账号录制。现已改成双层门控：

- 池选择层：仅在全额重建开启时调用跨账号设备候选；
- Type9运行层：即使连接期间关闭开关，也不再启用设备跨账号路径；
- 关闭全额重建时保留原账号玩家池和官方模板回退；
- 3366握手/延迟路径固定使用账号级池。

新增回归测试覆盖关闭开关时的账号池与3366池完整性。

### 5.4 账号字段重写

当前样本游戏账号为固定长度ASCII，补充叶仅在找到等长donor账号时重写；长度不一致时整叶不进入跨账号输出。未识别编码保持原有机械门控/透传路径，日志记录donor便于后续样本定位。

### 5.5 生命周期与并发：已修正

- 注册表增加 `RLock`，会话快照和待绑定42B记录均有过期清理。
- 新连接覆盖同键旧连接后，旧连接迟到的 `attach_context/disconnect` 被识别为stale，不会污染新状态。
- 42B待绑定值在UID绑定时单次消费，避免后续UID重复绑定误用旧值。
- 3366 detach只清理其自身连接键；3366匹配不进入跨账号设备池。
- 同一代理账号/游戏ID的真正并行双设备仍共享逻辑键；严格设备门控会阻止跨设备玩家模板输出，重连分类由42B时钟闭合决定，并在 `reconnect_events.jsonl` 中记录 `active_connection_overlap` 供诊断。

## 6. 工作区文件清单

已修改：

- `README.md`
- `core/ai_log_v128.py`
- `core/crypto.py`
- `core/dfm_message_catalog.py`
- `core/pool.py`
- `core/server.py`
- `core/traffic_session_log.py`
- `core/type9_v128_replenish.py`
- `tests/test_01_replay.py`
- `tests/test_ai_log_v128.py`
- `tests/test_ui_startup.py`
- `tests/test_v128_replenish.py`
- `ui/views.py`

新增：

- `core/replay_session_v129.py`
- `tests/test_replay_session_v129.py`
- `tools/backtest_v129_reconnect.py`
- `doc/DFMProxy_v128.9_改动校验报告_20260825.md`

工作区原有大量未跟踪数据目录和 `.DS_Store`，本轮未清理、未纳入实现范围。

## 7. 第二轮结论

代码审查发现并修正4项实际问题：

1. 跨账号设备候选未绑定全额重建开关；
2. 3366路径误用仅含01素材的设备候选池；
3. 新旧socket重叠时旧回调可能污染新逻辑会话；
4. 回溯工具直接运行导入失败，且组叶数统计口径需要收紧。

修正后233项测试、编译检查、diff格式检查与指定历史长重连回溯全部通过。v1.128.9可提交、创建tag并触发Windows打包。
