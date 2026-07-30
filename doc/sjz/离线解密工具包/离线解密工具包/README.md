# 离线解密工具包

这个目录给后续其他 AI / 脚本直接使用。

## 本地客户端密钥

客户端密钥就是当前样本对应的 DH 私钥 `DH_priv`，仅存放在本地
`client_dh_priv.txt`：

```text
DH_PRIVATE_HEX
```

## 当前约定

- 客户端密钥 = `DH_priv`
- `1002` 里包含服务端公钥 `server_pub`
- 会话 AES key = `MD5(DH_compute_key(server_pub, DH_priv))`
- 不需要 `1001`
- 不需要 `logjam/` 预计算

## 文件

- `client_dh_priv.txt`（本地文件；可由 `client_dh_priv.example.txt` 复制创建）
  固定客户端密钥，纯 hex
- `derive_key_from_1002.py`
  只用 `1002` 和固定客户端密钥推导 AES key

## 用法

```bash
python3 derive_key_from_1002.py \
  --frame-1002-hex "3366..."
```

或者直接传服务端公钥：

```bash
python3 derive_key_from_1002.py \
  --server-pub-hex "2c31241c..."
```

## 输出

脚本会输出：

- `client_key`
- `server_pub`
- `shared_secret`
- `aes_key`

## 备注

如果后续更新后客户端密钥变化，只需要替换 `client_dh_priv.txt` 里的内容即可，脚本逻辑不用改。
