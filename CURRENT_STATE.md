# DFMProxy 当前项目状态（AI 接手必读）

**权威日期**：2026-09-08
**发布基线**：`v1.131.2`
**当前分支/HEAD**：`main` / `v1.131.2`
**模型 revision**：`v131-builtin-800d-offline-fallback-r1`

> 这份文件是项目主目录下的当前状态基线。`doc/`、`数据/` 中较早的 v120～v129 资料主要用于历史回溯，其中可能包含已经被后续版本替代的方案。开始修改前先读本文、当前代码、测试和最新 v130 AI 日志。

## 1. 当前项目目标

DFMProxy 当前核心是 **01/Type9 语义重放和缺失数据补齐**：

```text
接收当前 Live 01 报告
  → 解密并拆分 report/leaf
  → 识别游戏ID、设备和42B会话
  → 玩家设备池/游戏ID池/中央模型选择
  → 中央固定层和强检层补齐
  → 同设备动态层补齐
  → 二级热规则处理已知叶
  → 未知结构 PASS_LIVE
  → 保持 slot、recordSequence、容器和身份连续
  → 输出新的 01 报告
```

稳定核心：

```text
Live 优先；缺失才补；周期保序；未知可回溯
```

## 2. 已验证成功的基线

最新完整证据目录：

```text
数据/130/AI日志短线重连接并且杀人后强检/
```

该样本确认：

```text
FIRST_JOIN → NETWORK_RECONNECT
42B 会话值保持：0x0813ECF4
Live 叶连续：749 → 750，delta=1

8C03：28 条，slot 150 → ... → 3390，周期 +120
mrpcs_i_vv.data：input/output 均出现
9100：1 条，slot=3000

validation_errors：0
all_output_groups_valid：全部通过
```

因此目前成功基线包括：同设备长时重放、游戏进程未退出时续连、8C03 周期补齐、9100 条件补齐、未知 body 原样保留。

v1.130.4 追加：玩家事件族按 semantic identity 去重，修复 8029 近重复双发；9000 默认动作固定为保序 `empty_2000`。
v1.130.5 追加：130.3 对照确认 `8024 +0x20` 是设备开机 epoch（只重启游戏不换，只有关机重启才换），`+0x24` 是刷机后首次落地时间、重启也不改。全额重建保持录制 `8024` 两处 epoch；`802C +0x20` 继续按 `recorded_at` 绝对时间差推进，避免事件时间冻在录制时刻。不按 01 连接重定位 `8024`，否则只重启游戏/重连会被伪造成新开机。
v1.130.7 追加：录制「周期就绪」改为 7 项。8027/8029 计入扫描波就绪（完整第一波 + 第二波开扫），详情表显示等待完整第一波 / 等待第二波开扫 / 扫描波间隔。
v1.130.8 追加：8027 长波完整改为相邻 `+0x20` 严格递减 + 第二波开扫；短波尾巴 59 仍充分。800A 不再无条件 900：稀疏末两档差 900 才外推，30-slot 密发至少三簇且间隔一致才外推。本场原生回溯 6/7，800A 两簇继续暗。
v1.130.9 追加：录制详情 22 个已知 80xx「周期状态」全部写出重建口径，禁止 `—`。8004=`子型 x/9 · 默认 300-slot`，802A/B 跟随配置档。不改 7/7，不改重建算法。
v1.130.10 追加：全额重建下 8027/8029 可单独开关。`rebuild_scan_waves=off` 不发这对；`repeat_first` 仍循环第一完整波。默认重建。不改扫描波判定与 7/7。

## 3. 模板和设备策略

当前顺序：

```text
同设备玩家池
  ↓ 设备未命中
按游戏ID降级匹配
  ↓ 仍未命中
中央模型 + Live + 二级规则
```

v1.130.2 已移除旧官方模板入口，当前样本为：

```text
personal_01_count = 172
official_01_count = 0
```

设备上下文可包括：`model`、`hardware_model`、`system_version`、`device_idfv`、`device_resolution`、`system_name`、`app_version`、`app_mach_uuid`。

同设备的一份长录制可供同设备其他账号复用；跨设备时，中央固定层继续使用，设备强相关动态层按匹配结果降级。
v1.130.18：玩家层以 IDFV 为同机主键。`ver:16.30` 与 `iDevSysVer:16.3.1` 视为同一台设备上的两种编码，不得把同 IDFV 打成跨设备；Live 尚未采到 IDFV 时保持 `PENDING`。已采到的三段 `iDevSysVer` 不会被后续公共头 `ver` 覆盖。
v1.130.19：`mrpcs_i_v_ic.data` 只记账、不武装 8C03/9100。连接表重放列冷启动即标「首次重放」，只有 42B 候选被首个 Live 叶序号确认后才改成「续连重放」。
v1.131.0：800D 单项开启后按 Live → 录制供体（同设备优先）→ 内置种子回退；无玩家录制或无设备上下文时仍可按固定600-slot轨迹离线补齐。中央9类继续只使用内置权威模板。

## 4. 当前补数据分层

### 中央固定 9 类

```text
8000 / 8002 / 8003 / 8004 / 800B
8020 / 8021 / 8025 / 8028
```

`8004` 有 9 个 subtype，使用 `message_id@slot#subtype` 精确判断：Live 有几片就保留几片，只补缺失片。

### 同设备玩家 12 类

```text
设备画像：8007 / 800F / 8023
会话动态：8024 / 800D / 802C（8024 保持录制开机/首次落地 epoch；802C 的 `+0x20` 按绝对时间差推进，`+0x24/+0x28` 使用四步链计数）
环境事件：800A / 800C / 8027 / 8029 / 802A / 802B（802A/802B 由配置 `rebuild_match_events`：off 不补，random 约 10～20 分钟补一对；不按 FFFB/8027 当进局门。8027/8029 由 `rebuild_scan_waves`：默认 `repeat_first` 循环第一波；`off` 不发）
```

已知玩家周期：录制供体的`8007/800D/802C = 600 slot`、`800F = 900 slot`，至少两个连续周期（末两档相差正好一个周期）才外推。v1.131 的 800D 内置种子自带 slot 60/660 两个权威锚点，单独开启 800D 且录制供体缺失时直接建立600-slot轨迹，`+0x20=1+cycle×20`。`800A` 按当前模板：无相邻 30 时仍用末两档 900；出现连续 30 则按簇划，两个簇只复放不外推，至少三个簇起点且末两个簇间隔近似一致才外推最后一簇。单档不外推。8027/8029 是 elapsed 扫描波，slot 13398 不取模；短波完整看尾巴 `+0x20=59`，长波看相邻 `+0x20` 严格递减，再加第二波开扫首帧才外推，T 取两波开扫 elapsed 差，循环源固定第一波。8029 同波不同 elapsed 多片保留，同 elapsed 近重复仍合并。

### 强检条件层

```text
0x8C03：mrpcs_i_f.data + mrpcs_i_j.data，首个 slot=150，周期=120
0x9100：mrpcs_i_v_tl.data + mrpcs_i_vv.data，首个 slot=600，周期=600
未映射：mrpcs_i_v_ic.data（只记账，不补发）
```

文件状态先武装对应 profile，消息在满足 slot、周期和上下文后生成；文件名出现不等于消息立即生成。

`mrpcs_i_v_ic.data` 于 2026-08-31 重放 `run_20260831_214106_923767` 首次确认。2026-09-02 录制 `run_20260902_185724_141809` 也见到：`0x0112232E` 点名，随后 `0x01122386` 报 `dl:stat:0`，没有 `0x01122366`。该局约 80 秒、slot 只到 30/60，`0x8C03`/`0x9100` 也未出现，因此还不能映射后续 message_id。代码记入 `UNMAPPED_STRONG_PROFILE_FILES`，出现时写入 `unmapped_seen_files`，**禁止**用它武装 8C03/9100。需要更长的未 hook 对照后再建映射。

## 5. 当前重放优先级

```text
1. 解析当前 Live 报告
2. 建立 message_id@slot#subtype 集合
3. 中央层补固定消息
4. 强检层补 8C03/9100
5. 同设备层补动态时间线
6. 热规则处理已知叶
7. 未知结构 PASS_LIVE
8. 重建序号、slot、父容器并校验
```

约束：

- Live 当前 slot 优先，模板只补缺失键。
- 每个周期重新判断，支持 Hook 间歇变化。
- 内置叶和迟到 Live 叶以 `message_id@slot#subtype` 去重。
- 输出序号使用当前会话游标，模板历史序号只作为内容来源。

## 6. 首次重放和续连重放

首次：

```text
42B 加入 → 游戏ID绑定 → 新语义会话 → 首个Live确认 → 首次重放
```

续连：

```text
断开 → 保存语义快照 → 相同42B会话值 → RECONNECT_CANDIDATE
     → 首个Live叶序列连续 → NETWORK_RECONNECT/continued=true
     → 续连重放
```

传输池索引可以在新 TCP 连接上从 0 重新取样，但设备上下文、已发状态、logical elapsed、slot 周期和 Live 序列继续沿用。连接表重放列只有「首次重放」和「续连重放」：游戏ID绑定后先标首次；只有 42B 候选被首个 Live 叶序号确认后才改成续连。冷启动不再停在占位「重放」。

## 7. 热规则和未知结构

动作类型：

```text
patch_live                 保留 Live 叶，只修改明确字段
replace_template_nearest   使用同设备/同长度附近模板
empty_2000                 保留合法叶和序号的空结果
pass_live                  原样保留未知结构
drop_leaf                  旧兼容路径，需配套容器和序号压紧
```

计数类优先 `patch_live`；需要抑制内容时优先 `empty_2000`；未知 `message_id=null` 的 `0x011223xx/0x010Axxxx` body 记录 `recordCode`、长度、Hex hash 和上下文后 `PASS_LIVE`。

当前 manifest 若仍显示 `9000-clean-installed-target-profile=drop_leaf`，后续发布前先核对规则文件和序号压紧测试，再决定是否切换。

## 8. AI 日志读取顺序

```text
manifest.json                    版本、规则 revision、开关、schema
reconnect_events.jsonl           首次/续连判定
template_selection_events.jsonl  模板来源和设备匹配
replay_events.jsonl              决策、注入数量、校验
replay_groups.jsonl              central9/strong/player 分组
replay_leaves.jsonl              input/template/shadow/output 叶对比
anomaly_full.jsonl               未知结构及其前后文
```

发布级目标：

```text
all_output_groups_valid = true
final_identity_check = true
validation_errors = []
recordSequence 单调、slot 不回退、同 slot/subtype 无重复
```

## 9. 已替代的旧认识

1. 官方模板优先：已替换为玩家设备池优先。
2. 每个账号都要单独录制：同设备池支持后续账号复用。
3. 某族出现一次后永久停补：已替换为 `message_id@slot#subtype` 每周期判断。
4. 42B 相同就立即续连：已替换为候选 + 首个 Live 序列确认。
5. 8C03/9100 无条件内置：已替换为文件对条件武装。
6. 0/3 始终等待：已替换为「满两档才外推」；单样本不 estimated。零样本仍缺席。
7. 未知结构直接建立规则：先透传、积累、回溯，再决定是否建规则。

## 10. 其他游戏适配

其他游戏只替换消息规格和字段解码器，复用模板池、续连、日志和校验框架：

```json
{
  "message_id": "GAME_MSG_ID",
  "record_code": "GAME_RECORD_CODE",
  "length": 0,
  "family": "central|player|strong|event",
  "first_slot": 0,
  "period": 0,
  "subtype_rule": "message_id@slot#subtype",
  "dynamic_fields": [],
  "trigger_files": [],
  "fallback": "pass_live"
}
```

先采集正常长样本，至少两个连续周期确认外推；强检通过文件状态和时间线关联；未知 body 保持透传。

## 11. 接手修改固定步骤

```bash
git status --short
git diff
python3 -m unittest tests.test_v128_replenish tests.test_replay_session_v130 -v
python3 -m py_compile core/events.py core/server.py core/type9_v128_replenish.py ui/views.py
git diff --check
```

当前 `tests.test_v128_replenish` 共70项，覆盖`mrpcs_i_v_ic`只记账、800D无录制离线生成、600-slot轨迹、Live优先、关闭开关和完整重放注入。修改算法、周期、触发文件、回退动作或 UI 阶段时，同步更新本文。

## 12. 当前工作区待提交内容

v1.130.10 已发版。全额重建下 8027/8029 可单独不发或循环第一波；扫描波判定仍为 v1.130.8。
v1.130.11：配置页增加“仅补中央9类”和“强检后补8C03/9100”开关；802A/B、8027/8029继续独立控制，运行时按配置门控补发层。
v1.130.13：玩家 80xx 逐项开关与跨账号硬门。
v1.130.14：重放1084可选随机改写 `iDevIDFV`；连接内钉死，出站改写并打日志（历史记录）。
v1.130.15：随机 IDFV 改为 Type9 解密明文改写后重加密并重算 CRC；配置页重建内容区分组+滚动（历史记录）。
v1.130.16：移除重放随机 `iDevIDFV` 改写；`iDevIDFV` 仅用于设备匹配与上下文显示。
v1.130.17：800D 保持在“基础补发”分组，跨设备/跨账号说明放在该项提示中。
v1.130.18：玩家层同设备门控改为以 IDFV 为主；公共头 `ver:16.30` 不得覆盖 `iDevSysVer:16.3.1`，缺 IDFV 保持 PENDING。
v1.130.19：`mrpcs_i_v_ic.data` 只记账不武装；连接表冷启动即标首次重放，Live 确认后续连才升格。录制短局已见该文件，仍无对应新 message_id。
v1.131.0：800D 单项使用 Live → 同设备/录制供体 → 内置种子的回退链。内置64字节种子来自历史328条800D的零偏差结构验证，锚点60/660、周期600、计数步长20；旧全额重建兼容路径保持原语义。

详细算法说明见：

```text
doc/DFMProxy_v130.6_80xx双方沟通.md
doc/DFMProxy_当前重放算法与稳定性说明_20260825.md
doc/DFMProxy_v131_800D内置离线种子_20260902.md
```
