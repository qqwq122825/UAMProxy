# 离线解密工具包

这个目录给后续其他 AI / 脚本直接使用。

## 已知固定客户端密钥

当前确认的**客户端密钥**，就是客户端 DH 私钥 `DH_priv`：

```text
726186722687FE8301A7071D26CB480D871F4EB3325FB407489D16EB3B453B6B
C1959D9F17BD90100804B45DC32CD7F088534E04B982BBB3C183A01E2D58DB6A
```

合并后为：

```text
726186722687FE8301A7071D26CB480D871F4EB3325FB407489D16EB3B453B6BC1959D9F17BD90100804B45DC32CD7F088534E04B982BBB3C183A01E2D58DB6A
```

## 当前约定

- 客户端密钥 = `DH_priv`
- `1002` 里包含服务端公钥 `server_pub`
- 会话 AES key = `MD5(DH_compute_key(server_pub, DH_priv))`
- 不需要 `1001`
- 不需要 `logjam/` 预计算

## 文件

- `client_dh_priv.txt`
  固定客户端密钥，纯 hex
- `derive_key_from_1002.py`
  只用 `1002` 和固定客户端密钥推导 AES key

## 用法

```bash
python3 /Users/xxx/Documents/code/fucknetwork/doc/sjzdoc/离线解密工具包/derive_key_from_1002.py \
  --frame-1002-hex "3366..."
```

或者直接传服务端公钥：

```bash
python3 /Users/xxx/Documents/code/fucknetwork/doc/sjzdoc/离线解密工具包/derive_key_from_1002.py \
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
