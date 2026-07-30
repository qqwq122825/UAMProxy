# UAMProxy · 暗区突围专项版

基于 Python、PySide6 与 asyncio 的 SOCKS5 双端口代理，专门用于暗区突围
ACE `01` / `3366` 数据的录制、顺序重放和拦截管理。

开发协作约定见 [AI_DEV_GUIDELINES.md](AI_DEV_GUIDELINES.md)，type-9 重放格式见
[09_01抓包重放与字段重建指南.md](09_01抓包重放与字段重建指南.md)。

## 专项功能

- 录制端口默认 `1081`，采集暗区 `01 0A 00 09` 与 3366 `09/21` 模板。
- 重放端口默认 `1080`，按游戏账户匹配录制池并按采集顺序取样。
- 新录制生命周期上线时自动清理上一轮同源录制，避免新旧模板被合并追加。
- 样本池按录制顺序循环重放，到达末尾后从第一条模板继续。
- type-9 成套替换 `算法选择器 + Key索引 + 明文CRC + 密文长度 + 密文`。
- 保留实时账户、报告序号、帧序号、包组号和传输标签。
- 由内向外更新长度，对完整逻辑 payload 重算 CRC32，并按 4096 字节重新分片。
- 连接状态明确分为 `录制`、`重放`、`实时重放`、`待匹配`。
- 暗区专项拦截：01 大包、33 字符串、上行脏数据、上行截断与下行块填充。
- `test` 账号在录制端口上线时，将 TCP 分包组装后的完整 01 上行帧保存为
  `PyProxyTrafficLogs_*/01_uplink_frames_test.json`，格式为二维字节数组。
- 用户管理支持复选框、全选、取消全选和批量删除。

## 目录

```text
main.py
core/
  config.py                 暗区专项配置
  crypto.py                 type-9 解析、字段重建、CRC32 和分片
  pool.py                   录制会话与顺序模板池
  protocol_3366.py          暗区 3366 解密和重放
  dl_intercept.py           暗区上下行拦截
  server.py                 SOCKS5 双端口代理
ui/
  views.py                  连接、录制、拦截管理界面
```

## 运行

```bash
pip install PySide6 pycryptodome
python main.py
```

无界面运行：

```bash
python main.py --headless
```

## 关键配置

数据默认保存到 `C:\PyProxyApp\`。

| 字段 | 默认值 | 说明 |
|---|---:|---|
| `port_record` | 1081 | 录制端口 |
| `port_replay` | 1080 | 重放端口 |
| `record_idle_timeout` | 180 | 录制空闲断开秒数 |
| `auto_disconnect_01_threshold` | 100 | 录制模板阈值 |
| `replay_strict_match` | true | 账户无匹配池时严格处理 |
| `special_dual_capture_mode_enabled` | false | 01/3366 双协议专项采集；开启后不生成常规详单或录制池 |
| `special_capture_user` | test | 专项采集的录制端口代理账号 |
| `az_dl_intercept_enabled` | false | 暗区 33 下行字符串拦截 |
| `dl_01_block_enabled` | false | 暗区 01 下行大包拦截 |
| `ace_chunk_block_enabled` | false | 暗区下行块填充 |
| `ul_dirty_clean_enabled` | false | 暗区上行脏数据清除 |

开启“01 / 3366 双协议采集”后，录制端口会为目标账号创建
`capture-clean-<时间>/` 会话目录，同时保存：

- 每次代理读取的双向原始 TCP chunk、SHA256 与真实交错顺序；
- 每条连接的 `c2s.raw.bin`、`s2c.raw.bin` 连续字节流；
- TCP 拼接后切出的完整 01、3366 上行与下行帧；
- 3366 首条完整下行 `1002`（供同连接后续 `4013` 解密）；
- 01 应用层分片重组后的逻辑消息；
- 3366 的会话密钥上下文、4013 密文及成功解密的明文；
- `session.json`、`timeline.jsonl`、完整性报告及 `checksums.sha256`。

`session.json.captureDirections` 固定为 `["c2s","s2c"]`。个别连接只有单向
数据时，已有字节仍会保留，并在 `anomalies.jsonl` 写入
`ONE_DIRECTION_MISSING`。

采集链路保持原样转发，常规流量详单、录制池数据和网络流监控数据均不生成。
SOCKS5 应用层代理不具备 TCP 序号、UDP 和设备全量包视角，因此会在
`session.json` 与完整性报告中明确标记 `pcapngAvailable=false`，不会生成占位
pcapng。

专项写盘使用“不可变字节副本 → 临时文件完整写入 → flush/fsync → 读回
SHA256 → 原子替换”。方向连续流在每次追加后读回刚写入范围；停止采集时再次
核对 chunk 拼接结果、方向 raw 流、frame 引用及文本 NUL，并写入
`sessionStatus=valid|invalid`。自检完成后还会生成同名 `.zip` 和
`.zip.sha256`，跨电脑时优先传输这个 ZIP，避免远程桌面逐个复制大量小文件。

3366 产品注册表只保留暗区突围国服：

```json
{
  "3366_products": {
    "0000094E": {
      "name": "暗区突围国服",
      "decrypt": "aes_cbc_4013",
      "needs_downlink_key": true
    }
  }
}
```

## 重放校验

每次 type-9 替换日志会记录原始与新 CRC32、逻辑 payload 长度、分片数量、
算法选择器、Key 索引、密文长度和新 payload SHA256，便于逐包核对。
