# UAMProxy · 暗区突围专项版

基于 Python、PySide6 与 asyncio 的 SOCKS5 双端口代理，专门用于暗区突围
ACE `01` / `3366` 数据的录制、顺序重放和拦截管理。

开发协作约定见 [AI_DEV_GUIDELINES.md](AI_DEV_GUIDELINES.md)，type-9 重放格式见
[09_01抓包重放与字段重建指南.md](09_01抓包重放与字段重建指南.md)。

## 专项功能

- 录制端口默认 `1081`，采集暗区 `01 0A 00 09` 与 3366 `09/21` 模板。
- 重放端口默认 `1080`，按游戏账户匹配录制池并按采集顺序取样。
- 新录制生命周期上线时自动清理上一轮同源录制，避免新旧模板被合并追加。
- 样本池耗尽后停止替换并等待新模板追加，不回绕历史样本。
- type-9 成套替换 `算法选择器 + Key索引 + 明文CRC + 密文长度 + 密文`。
- 保留实时账户、报告序号、帧序号、包组号和传输标签。
- 由内向外更新长度，对完整逻辑 payload 重算 CRC32，并按 4096 字节重新分片。
- 连接状态明确分为 `录制`、`重放`、`实时重放`、`待匹配`。
- 暗区专项拦截：01 大包、33 字符串、上行脏数据、上行截断与下行块填充。

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
| `az_dl_intercept_enabled` | false | 暗区 33 下行字符串拦截 |
| `dl_01_block_enabled` | false | 暗区 01 下行大包拦截 |
| `ace_chunk_block_enabled` | false | 暗区下行块填充 |
| `ul_dirty_clean_enabled` | false | 暗区上行脏数据清除 |

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
