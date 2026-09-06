# DFMProxy 三角洲专版与 v1.116-A

## 版本边界

- 当前分支：`experiment/v1.116-a-learning`
- 回滚标签：`backup/pre-v116-a-dfm-specialized`
- 运行时仅激活三角洲 `0a92` 路径。
- 暗区、王者和旧本地 HTTP 重放实现保留在源代码中，但 UI 隐藏、运行时关闭。
- 后续多游戏整合放入 `AceProxyRefactor` 的 `GameProfile + Adapter + ReplayStrategy`，本分支不混入整合框架。

## 116-A 的行为

116-A 是旁路学习版本，网络发送规则保持已完成整局验证的 114.1：

1. 同账号录制池优先，缺失时可使用最近的跨账号 donor 01 叶子池。
2. 外层账号、会话、报告序号、计数和时间字段继续继承实时包。
3. `0xFFF2/0xFFF3` 与已确认强动态结构保留实时主体。
4. `0x8024/0x8030/0x80CC/0x80CD` 继续执行 114.1 发送规则，同时在旁路生成完整差异与字段画像。
5. Type9 明文 CRC、密文和 01 外层 CRC 仍由最终候选重新计算并回验。

学习器按 `recordCode:messageId:length` 建立结构键，跨运行累计实时/模板字节变化情况。它只输出观察结果，不自动激活新替换规则。

## 日志目录

每次启动重放分析后生成：

```text
C:\PyProxyApp\01ReplayAnalysis\run_YYYYMMDD_HHMMSS_ffffff\
├─ manifest.json
├─ 01_replace_events.jsonl
├─ 01_schema_registry.json
├─ 01_field_profiles.json
├─ 01_learning_decisions.jsonl       # 有新结构/冲突时出现
├─ 01_unknown_identity.jsonl         # 有新 ID/长度时出现
└─ NeedsAIAnalysis\                   # 仅需要分析时出现
   ├─ manifest.json
   ├─ events.jsonl
   ├─ 01_schema_registry.json
   └─ 01_field_profiles.json
```

全局结构注册表位于：

```text
C:\PyProxyApp\01Learning\01_schema_registry.json
```

`NeedsAIAnalysis` 未生成时，说明本轮没有新结构或新冲突。存在该目录时可执行：

```powershell
python tools\package_01_learning_bundle.py
```

脚本自动选择最新运行并输出 `DFMProxy_116A_AI_*.zip`。

## 116-A 测试顺序

1. 保留已验证的录制 JSON，先重放一整局。
2. 换网络、重连、结算等场景各覆盖一次。
3. 查看 `01_replace_errors.jsonl`、下行事件与断开前最后 10 个 01 事件。
4. 若出现 `NeedsAIAnalysis`，打包该目录；否则继续积累多账号样本。
5. 116-B 再根据多轮稳定画像把规则从 `OBSERVE` 晋级，116-A 本身不热更新网络行为。
