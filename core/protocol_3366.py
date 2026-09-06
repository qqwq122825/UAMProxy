# ─────────────────────────────────────────
# 33 66 帧协议（ACE 通道）— 切分 / 游戏识别 / 首下行密钥 / 40 13 解密骨架
# 文档见仓库内 3366分析报告.md
# ─────────────────────────────────────────
from __future__ import annotations

import struct
from typing import Callable

MAGIC = b"\x33\x66"

# ─────────────────────────────────────────
# 三角洲（插件类游戏）1002 → AES key 推导
# 规则来源：doc/sjz/离线解密工具包/离线解密工具包/derive_key_from_1002.py
# ─────────────────────────────────────────
_DZ_DH_P_HEX = (
    "97981E0AADE0DE72E29CD2789193562547BAD2591FB7E59C"
    "523923DDDECEBCCAE49BDCD4B8EC39022B0BD95D4AF8FD3C"
    "D600919393255C1084C2FD5ABB2FEDE3"
)
# 固定客户端 DH 私钥（DH_priv），默认值与离线解密工具包一致；如后续变更可在此替换。
_DZ_CLIENT_DH_PRIV_HEX = (
    "726186722687FE8301A7071D26CB480D871F4EB3325FB407489D16EB3B453B6B"
    "C1959D9F17BD90100804B45DC32CD7F088534E04B982BBB3C183A01E2D58DB6A"
)
_DZ_1002_DH_PUB_OFF = 0x18
_DZ_1002_DH_PUB_LEN = 64


def try_derive_aes_key_from_1002(
    frame: bytes,
    *,
    client_dh_priv_hex: str | None = None,
    dh_pub_offset: int = _DZ_1002_DH_PUB_OFF,
) -> bytes | None:
    """
    仅用 1002 帧 + 固定客户端 DH 私钥推导 AES key（MD5(DH(shared_secret))）。
    返回 16B key；失败返回 None。
    """
    if not frame or len(frame) < 16 or frame[:2] != MAGIC:
        return None
    # 1002
    if frame[6:8] != b"\x10\x02":
        return None
    end = dh_pub_offset + _DZ_1002_DH_PUB_LEN
    if len(frame) < end:
        return None
    server_pub = frame[dh_pub_offset:end]
    try:
        import hashlib

        p = int(_DZ_DH_P_HEX, 16)
        client_priv = int((client_dh_priv_hex or _DZ_CLIENT_DH_PRIV_HEX).strip(), 16)
        server_pub_int = int.from_bytes(server_pub, "big")
        shared = pow(server_pub_int, client_priv, p)
        shared_bytes = shared.to_bytes((p.bit_length() + 7) // 8, "big")
        return hashlib.md5(shared_bytes).digest()
    except Exception:
        return None

# 大端 4 字节产品 / 渠道标识（暗区突围国服、王者荣耀）
PRODUCT_AB_BREAKOUT_CN = b"\x00\x00\x09\x4E"
PRODUCT_HOK_CN = b"\x00\x00\x0A\x11"

KNOWN_PRODUCT_NAMES: dict[bytes, str] = {
    PRODUCT_AB_BREAKOUT_CN: "暗区突围国服",
    PRODUCT_HOK_CN: "王者荣耀",
}

ACE_SHORT_PRODUCT_TO_3366_PRODUCT: dict[str, str] = {
    "094e": "0000094E",
    "0a11": "00000A11",
}

# 内置默认注册表（与 config 3366_products 合并）
_DEFAULT_PRODUCT_REGISTRY: dict[str, dict] = {
    "0000094E": {
        "name": "暗区突围国服",
        "decrypt": "aes_cbc_4013",
        "needs_downlink_key": True,
    },
    "00000A11": {
        "name": "王者荣耀",
        "decrypt": "aes_cbc_4013",
        "needs_downlink_key": True,
    },
}


def normalize_product_id_key(k: str) -> str | None:
    """将配置键规范为 8 位 hex，如 0000094E。"""
    if not k or not isinstance(k, str):
        return None
    s = k.strip().upper().replace("0X", "").replace(" ", "")
    if len(s) != 8 or any(c not in "0123456789ABCDEF" for c in s):
        return None
    return s


def merge_3366_product_registry(extra: object) -> dict[str, dict]:
    """
    合并内置产品与 config['3366_products']。
    用户在 config 中按游戏追加条目；decrypt 为 null 或省略表示仅识别、不解密。
    """
    base = {k: dict(v) for k, v in _DEFAULT_PRODUCT_REGISTRY.items()}
    if not isinstance(extra, dict):
        return base
    for k, v in extra.items():
        nk = normalize_product_id_key(k)
        if not nk or not isinstance(v, dict):
            continue
        prev = dict(base.get(nk, {}))
        prev.update(v)
        base[nk] = prev
    return base


def product_uses_downlink_session_key(meta: dict | None, strat: str | None) -> bool:
    """
    是否从「首条下行 33 66」payload 抽取会话 Key/IV（暗区 aes_cbc_4013 为 True）。
    其它游戏可在 config 中显式写 needs_downlink_key: false，则不做首包 Key 解析、不打 Key 日志。
    """
    if not strat or strat in ("none", "null", ""):
        return False
    if not meta:
        return strat == "aes_cbc_4013"
    if "needs_downlink_key" in meta:
        return bool(meta["needs_downlink_key"])
    return strat == "aes_cbc_4013"


def registry_needs_downlink_key_extraction(registry: dict[str, dict]) -> bool:
    """注册表中是否存在任一产品需要从首下行取 Key（任意一条为 True 则整连接启用抽取逻辑）。"""
    for meta in registry.values():
        if not isinstance(meta, dict):
            continue
        strat = meta.get("decrypt")
        if product_uses_downlink_session_key(meta, strat):
            return True
    return False


def find_registered_product_in_blob(
    blob: bytes, registry: dict[str, dict]
) -> tuple[str, str] | None:
    """在二进制中查找已注册的产品 ID（4 字节 raw = 8 hex 键），返回 (pid_hex, 显示名)。"""
    if not blob or not registry:
        return None
    for pid_hex in sorted(registry.keys(), key=len, reverse=True):
        try:
            raw = bytes.fromhex(pid_hex)
        except ValueError:
            continue
        if raw in blob:
            meta = registry.get(pid_hex) or {}
            name = meta.get("name") or pid_hex
            return pid_hex, str(name)
    return None


def decrypt_plain_for_strategy(
    strategy: str | None,
    frame: bytes,
    key: bytes | None,
    iv: bytes | None,
) -> bytes | None:
    """
    按策略解密 40 13 帧体。未知策略返回 None（勿与暗区算法混用）。
    aes_cbc_4013 必须提供 key/iv；其它策略可自行使用包内密钥或明文逻辑（key/iv 可为 None）。
    """
    if not strategy or strategy in ("none", "null", ""):
        return None
    if strategy == "aes_cbc_4013":
        if not key or not iv:
            return None
        return try_decrypt_4013_frame(frame, key, iv)
    return None

# 消息类型（帧头偏移 6..8）
MSG_HANDSHAKE = b"\x10\x01"
MSG_AUTH = b"\x20\x01"
MSG_SERVER_KEY = b"\x10\x02"  # 服务端首下行，含 Key/IV（暗区 64 字节）
MSG_DATA = b"\x40\x13"


def is_breakout_cn_1002_embedded_aes_key(frame: bytes) -> bool:
    """
    暗区国服：10 02 且 payload[4:7]==10 02 10 时，Key/IV 直接内嵌在 payload（见 try_extract_key_iv_from_first_downlink）。
    此类帧不可按三角洲 DH 规则推导，否则会覆盖错误 key。
    """
    if len(frame) < 39 or frame[:2] != MAGIC or frame[6:8] != MSG_SERVER_KEY:
        return False
    pl = frame[16:]
    return len(pl) >= 23 and pl[4:7] == b"\x10\x02\x10"

# TAES 固定 IV（3366-decryption-spec.md §4.1）
TAES_FIXED_IV = bytes(range(16))


_MAX_JUNK = 262144  # 单连接缓冲上限，防止非 3366 二进制撑爆内存


def consume_3366_frames(stream_buf: bytearray) -> list[bytes]:
    """
    从流缓冲中取出所有**完整**的 33 66 帧。
    帧边界：下一帧魔数 33 66；首包或粘包均适用。
    注意：若明文载荷中偶然出现 33 66 会误切分，需结合长度字段的增强版后续再做。
    """
    out: list[bytes] = []
    while True:
        fp = _find_valid_magic(stream_buf, 0)
        if fp < 0:
            if len(stream_buf) > _MAX_JUNK:
                stream_buf.clear()
            break
        if fp > 0:
            del stream_buf[:fp]
        if len(stream_buf) < 16:
            break
        nxt = _find_valid_magic(stream_buf, 2)
        if nxt < 0:
            break
        out.append(bytes(stream_buf[:nxt]))
        del stream_buf[:nxt]
    return out


def feed_3366_stream(state: Conn3366State, chunk: bytes) -> list[bytes]:
    """
    将 TCP 片段喂入状态机，仅当（缓冲里已有半截帧）或（本片段含 33 66）时才吸收数据，
    避免把纯 01/HTTP 流量整块塞进缓冲。
    """
    if not chunk:
        return []
    if not state.buf and _find_valid_magic(chunk, 0) < 0:
        return []
    if not state.buf:
        i = _find_valid_magic(chunk, 0)
        if i < 0:
            return []
        state.buf.extend(chunk[i:])
    else:
        state.buf.extend(chunk)
    if len(state.buf) > _MAX_JUNK:
        state.buf.clear()
        return []
    return consume_3366_frames(state.buf)


def extract_handshake_user_id(frame: bytes) -> str | None:
    """
    从上行 **10 01（握手/注册）** 帧 payload 中解析用户 ID。
    TLV 标记：`XX 03 00 00`（XX 为小整数，已知 01/02），后接大端 16 位长度 + ASCII UID。
    不同账户/游戏 XX 字节可能不同，只匹配后 3 字节 `03 00 00` 以兼容所有变体。
    """
    info = parse_3366_header(frame)
    if not info or info["msg"] != MSG_HANDSHAKE:
        return None
    pl = info["payload"]

    def _try_decode(raw: bytes) -> str | None:
        chunk = raw.split(b"\x00", 1)[0]
        try:
            s = chunk.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError:
            return None
        if s and 4 <= len(s) <= 48 and all(32 <= ord(c) < 127 for c in s):
            return s
        return None

    i = 0
    while i + 6 <= len(pl):
        # 匹配 XX 03 00 00：后 3 字节固定，首字节为小整数（< 0x10）
        if not (pl[i + 1] == 0x03 and pl[i + 2] == 0x00 and pl[i + 3] == 0x00
                and pl[i] < 0x10):
            i += 1
            continue
        off = i + 4
        # 优先 16 位大端长度（与现网抓包一致）
        if off + 2 <= len(pl):
            ln16 = struct.unpack_from(">H", pl, off)[0]
            if 4 <= ln16 <= 64 and off + 2 + ln16 <= len(pl):
                got = _try_decode(pl[off + 2 : off + 2 + ln16])
                if got:
                    return got
        # 兜底 32 位大端长度
        if off + 4 <= len(pl):
            ln32 = struct.unpack_from(">I", pl, off)[0]
            if 4 <= ln32 <= 64 and off + 4 + ln32 <= len(pl):
                got = _try_decode(pl[off + 4 : off + 4 + ln32])
                if got:
                    return got
        i += 1
    return None


def parse_3366_header(frame: bytes) -> dict | None:
    """
    解析 16 字节头；失败返回 None。
    帧头布局：offset 8-11 = segment，offset 9-12 = seq（32 位大端 a[9]..a[12]，
    从 00 00 00 01 递增到 FF FF FF FF）。
    """
    if len(frame) < 16 or frame[:2] != MAGIC:
        return None
    ver = struct.unpack_from(">H", frame, 2)[0]
    sub = struct.unpack_from(">H", frame, 4)[0]
    msg = frame[6:8]
    segment = struct.unpack_from("<I", frame, 8)[0]
    seq = struct.unpack_from(">I", frame, 9)[0]
    return {
        "ver": ver,
        "sub": sub,
        "msg": msg,
        "msg_hex": msg.hex().upper(),
        "seq": seq,
        "segment": segment,
        "payload": frame[16:],
    }


def find_embedded_product_id(blob: bytes) -> tuple[bytes, str] | None:
    """在二进制中查找已知产品 ID（如 00 00 09 4E）。"""
    for pid, name in KNOWN_PRODUCT_NAMES.items():
        if pid in blob:
            return pid, name
    return None


def try_extract_key_iv_from_first_downlink(
    frame: bytes,
    key_off: int | None = None,
    iv_off: int | None = None,
) -> tuple[bytes, bytes] | None:
    """
    从**服务端首帧** payload 中取出 AES-128 Key + IV（各 16 字节）。

    只在明确匹配已知模式时才返回 Key，否则返回 None。
    返回 None 不代表错误——表示该游戏的 Key 需要从其他来源获取（如插件注入）。

    已知模式：
      1. 用户在 config 中显式指定 key_offset / iv_offset
      2. 暗区 10 02：payload[4:7] == \\x10\\x02\\x10 → Key = payload[7:23]
    """
    if len(frame) < 16:
        return None
    pl = frame[16:]

    # ① 用户显式指定偏移（最高优先级）
    if key_off is not None and iv_off is not None:
        if len(pl) < max(key_off, iv_off) + 16:
            return None
        return pl[key_off : key_off + 16], pl[iv_off : iv_off + 16]

    msg = frame[6:8]

    # ② 暗区模式：10 02 帧 + 特征码 \x10\x02\x10
    if msg == MSG_SERVER_KEY and len(pl) >= 23 and pl[4:7] == b"\x10\x02\x10":
        return pl[7:23], TAES_FIXED_IV

    # 不匹配任何已知模式 → 返回 None
    # 三角洲等 DH 密钥交换游戏的 10 02 里是公钥，不是 AES Key
    # 它们的 Key 由插件通过 /api/plugin/key 注入
    return None


def _taes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes | None:
    """
    按 3366-decryption-spec §4.4：明文后加 TAES 填充（tsf4g + pad_len），再 AES-128-CBC 加密。
    """
    import os
    if not plaintext or len(key) != 16 or len(iv) != 16:
        return None
    pad_len = 16 - (len(plaintext) % 16)
    if pad_len == 0:
        pad_len = 16
    if pad_len < 6:
        pad_len += 16
    if pad_len > 32:
        pad_len = 16
    tail = os.urandom(pad_len - 6) + b"tsf4g" + bytes([pad_len])
    padded = plaintext + tail
    return _aes128_cbc_encrypt(padded, key, iv)


def _aes128_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes | None:
    try:
        from Crypto.Cipher import AES  # type: ignore
    except ImportError:
        return None
    if len(key) != 16 or len(iv) != 16 or not plaintext or len(plaintext) % 16 != 0:
        return None
    try:
        c = AES.new(key, AES.MODE_CBC, iv)
        return c.encrypt(plaintext)
    except Exception:
        return None


def _aes128_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes | None:
    try:
        from Crypto.Cipher import AES  # type: ignore
    except ImportError:
        return None
    if len(key) != 16 or len(iv) != 16 or not ciphertext:
        return None
    if len(ciphertext) % 16 != 0:
        return None
    try:
        c = AES.new(key, AES.MODE_CBC, iv)
        return c.decrypt(ciphertext)
    except Exception:
        return None


def _extract_4013_cipher_by_spec(frame: bytes) -> tuple[bytes, int] | None:
    """
    按 3366-decryption-spec.md §2：enc_len 在 frame[19:21] 大端，密文在 frame[25:25+enc_len]。
    返回 (cipher, enc_len)，失败返回 None。
    """
    if len(frame) < 25 or frame[:2] != MAGIC or frame[6:8] != MSG_DATA:
        return None
    enc_len = struct.unpack_from(">H", frame, 19)[0]
    if enc_len == 0 or enc_len % 16 != 0:
        return None
    if len(frame) < 25 + enc_len:
        return None
    return frame[25 : 25 + enc_len], enc_len


def try_decrypt_4013_frame_raw(frame: bytes, key: bytes, iv: bytes) -> bytes | None:
    """
    宽松解密：AES-CBC 解密后剥去 AES 填充（TAES tsf4g 或 PKCS7），不验证业务格式。
    适用于插件 Key 游戏（如三角洲行动），明文为 Protobuf RPC，不含暗区格式特征。
    返回已剥填充的明文；失败或密文提取失败返回 None。
    """
    spec_cipher = _extract_4013_cipher_by_spec(frame)
    if not spec_cipher or not key or not iv:
        return None
    ct, _ = spec_cipher
    raw = _aes128_cbc_decrypt(ct, key, iv)
    if not raw:
        return None
    # 1. 优先用 TAES 填充剥离（tsf4g 尾部或 PKCS7）
    stripped = _try_strip_taes_padding(raw)
    if stripped is not None:
        return stripped
    # 2. 严格 PKCS7 兜底：最后一字节为 pad_len，且最后 pad_len 字节都等于 pad_len
    pad_len = raw[-1]
    if 1 <= pad_len <= 16 and all(x == pad_len for x in raw[-pad_len:]):
        return raw[:-pad_len]
    # 3. 无法剥填充：直接返回原始字节（pb_replace 只处理前段数据，末尾随机字节无害）
    return raw


def try_decrypt_4013_frame(frame: bytes, key: bytes, iv: bytes) -> bytes | None:
    """
    解密完整 33 66 帧中的 40 13 载荷。
    顺序：① 按 spec 取 frame[25:25+enc_len] 密文 + 暗区 Key/IV；② 同上 + TAES 固定 IV；
    ③ 旧逻辑：payload 为 IV(16)+密文 或 全密文+会话 IV。
    """
    info = parse_3366_header(frame)
    if not info or info["msg"] != MSG_DATA:
        return None
    pl = info["payload"]

    # ① 按 spec：cipher = frame[25:25+enc_len]，用暗区 Key+IV
    spec_cipher = _extract_4013_cipher_by_spec(frame)
    if spec_cipher and key and iv:
        ct, _ = spec_cipher
        p = _aes128_cbc_decrypt(ct, key, iv)
        if p:
            norm = _normalize_4013_plain(p)
            if norm is not None:
                return norm

    # ② 同上密文，用 TAES 固定 IV（Key 仍来自 10 02）
    if spec_cipher and key:
        ct, _ = spec_cipher
        p = _aes128_cbc_decrypt(ct, key, TAES_FIXED_IV)
        if p:
            norm = _normalize_4013_plain(p)
            if norm is not None:
                return norm

    # ③ 旧逻辑：wire IV 前缀 或 全 payload 密文
    p = try_decrypt_4013_payload(pl, key, iv, iv_prefix=True)
    if p:
        return p
    return try_decrypt_4013_payload(pl, key, iv, iv_prefix=False)


def _try_strip_taes_padding(raw: bytes) -> bytes | None:
    """
    按 3366-decryption-spec.md §4.3 剥 TAES 填充；失败返回 None。
    """
    if len(raw) < 17 or len(raw) % 16 != 0:
        return None
    pad_len = raw[-1]
    if not (1 <= pad_len <= 32):
        return None
    if len(raw) <= pad_len:
        return None
        
    # 根据用户实际数据：
    # 解密出的部分通常结尾不包含 tsf4g 时，说明它可能不是走的标准 TAES。
    # 根据 137 的成功解密结果，我们发现之前使用 tsf4g 匹配可能不通用，有些包的结尾可能并没有这个标志
    # 为了防止因为 tsf4g 校验失败导致整个解密被丢弃，我们放宽要求，直接截断或者返回。
    # 既然这是个普遍问题，我们只依赖 padding 长度是否合理。
    
    # 我们暂且保留严格 tsf4g 的校验作为其中一种判断方式。
    tail_magic_start = len(raw) - 6
    if tail_magic_start >= 0:
        magic_bytes = raw[tail_magic_start:tail_magic_start+5]
        if magic_bytes == b'tsf4g':
            return raw[: len(raw) - pad_len]
            
    # 如果没有 tsf4g 标志，但 pad_len 合法，有可能是 PKCS7 填充
    # 我们检查最后 pad_len 个字节是否都是 pad_len
    # （这是标准的 PKCS7 填充方式）
    if all(x == pad_len for x in raw[-pad_len:]):
        return raw[: len(raw) - pad_len]
            
    # 如果既没有 tsf4g 也不是 PKCS7，但 pad_len 在 1~16 之间，也有可能是特殊情况。
    # 我们退一步，暂时不截断它，返回整体让调用者通过业务特征（如明文前缀）去判断
    return None

def _normalize_4013_plain(raw: bytes) -> bytes | None:
    """
    解密后得到 plain：先尝试剥 TAES 填充。
    只要存在合法的 TAES 填充 (tsf4g)，或者包含 AB AB，均认为解密成功。
    """
    # 1. 尝试剥离各种 padding
    stripped = _try_strip_taes_padding(raw)
    
    # 2. 判断是否解密成功
    # 2.1 成功剥离了 padding，且明文看起来合法（比如长度 > 0）
    if stripped is not None:
        return stripped
        
    # 2.2 如果没有成功剥离 padding，但包含 AB AB 标志，也认为是成功的
    if len(raw) >= 44 and raw[42:44] == b"\xAB\xAB":
        # 对于这种，我们可以假设它结尾有不知名 padding，尝试把最后 1~16 个多余字节当 padding 砍掉？
        # 稳妥起见，如果 padding 剥离函数失败但又有 AB AB，我们直接返回 raw，由业务层（如长度字段）自己去控制边界。
        return raw
        
    return None


def try_decrypt_4013_payload(
    payload: bytes,
    key: bytes,
    iv: bytes,
    iv_prefix: bool = True,
) -> bytes | None:
    """
    尝试解密 40 13 的载荷：默认假设 wire 为 IV(16) + CBC 密文（与首包派生 key 联用）。
    iv_prefix=False 时使用固定会话 IV（整段 payload 为密文）。
    """
    if iv_prefix:
        if len(payload) < 32:
            return None
        wire_iv, ct = payload[:16], payload[16:]
        return _aes128_cbc_decrypt(ct, key, wire_iv)
    return _aes128_cbc_decrypt(payload, key, iv)


class Conn3366State:
    """单连接、单方向的 33 66 流状态（上行 / 下行各一份）。"""

    __slots__ = ("buf", "seen_server_first", "key", "iv", "product_name", "product_hex")

    def __init__(self):
        self.buf = bytearray()
        self.seen_server_first = False
        self.key: bytes | None = None
        self.iv: bytes | None = None
        self.product_name: str | None = None
        self.product_hex: str | None = None


def process_3366_chunk(
    state: Conn3366State,
    chunk: bytes,
    *,
    is_downlink: bool,
    on_frame: Callable[[bytes, dict | None, Conn3366State], None],
    key_off: int | None = None,
    iv_off: int | None = None,
    product_registry: dict[str, dict] | None = None,
    extract_downlink_key: bool = True,
) -> None:
    """
    累积 chunk，切出完整帧后对每帧调用 on_frame(frame, header_info, state)。
    extract_downlink_key：由调用方根据 registry_needs_downlink_key_extraction() 决定；
    为 False 时不对首下行做 Key/IV 抽取（适用于其它游戏无需暗区式会话密钥的场景）。
    product_registry：由 merge_3366_product_registry(config) 得到，用于识别各游戏 4 字节产品 ID。
    """
    reg = (
        product_registry
        if product_registry is not None
        else merge_3366_product_registry(None)
    )
    frames = feed_3366_stream(state, chunk)
    for fr in frames:
        info = parse_3366_header(fr)
        if is_downlink and not state.seen_server_first:
            state.seen_server_first = True
            if extract_downlink_key:
                pair = try_extract_key_iv_from_first_downlink(
                    fr, key_off=key_off, iv_off=iv_off
                )
                if pair:
                    state.key, state.iv = pair
        hit = find_registered_product_in_blob(fr, reg)
        if hit:
            state.product_name = hit[1]
            state.product_hex = hit[0]
        else:
            legacy = find_embedded_product_id(fr)
            if legacy:
                state.product_name = legacy[1]
                state.product_hex = legacy[0].hex().upper()
        on_frame(fr, info, state)


# 原始 payload 中若含 01 0A 00 09 或 01 0A 00 23，视为透传高熵包，不发送（丢包）但会记录
_RAW_HIGH_ENTROPY_MARKERS = (b"\x01\x0A\x00\x09", b"\x01\x0A\x00\x23")
# 重放端口：10 01 握手、10 02 下发 Key 绝不丢包，否则无法获取会话 Key 导致重连后解密失败
# 录制端口：达阈值直接拒绝，无需保护握手帧
_MSG_NEVER_DROP = frozenset({"1001", "1002"})


def _find_valid_magic(data: bytes, pos: int) -> int:
    """查找下一个有效的 33 66 帧起始位置。跳过数据中的随机碰撞。

    加固规则：bytes[2]=0x00 且 bytes[3] in {0x0A..0x0F}（ver 低字节合理范围），
    bytes[4]=0x00 且 bytes[5] in {0x0A..0x0F}（sub 低字节合理范围）。
    现网样本均为 00 0B 00 0C；此范围兼容少量版本差异，同时过滤 TLS 等非 3366 协议数据。
    """
    while True:
        i = data.find(MAGIC, pos)
        if i < 0:
            return -1
        if i + 8 <= len(data):
            # bytes[2..5] = ver_hi, ver_lo, sub_hi, sub_lo
            if (data[i + 2] == 0x00 and 0x08 <= data[i + 3] <= 0x0F and
                    data[i + 4] == 0x00 and 0x08 <= data[i + 5] <= 0x0F):
                return i
        elif i + 6 <= len(data):
            # 剩余至少 6 字节可判断 ver/sub 高字节
            if data[i + 2] == 0x00 and data[i + 4] == 0x00:
                return i
        else:
            # 剩余太短，留给外层处理
            return i
        pos = i + 2


def filter_3366_frames_with_raw_high_entropy(
    data: bytes,
    on_drop: "Callable[[bytes, str], None] | None" = None,
    never_drop_handshake: bool = False,
) -> bytes:
    """
    移除 payload（frame[16:]）中含 01 0A 00 09 或 01 0A 00 23 的 33 66 帧。
    不发送（丢包），但会通过 on_drop 回调记录。
    on_drop(frame, msg_hex): 每丢弃一帧时回调，msg_hex 如 "66D1"。
    never_drop_handshake: bool，True 时 10 01/10 02 永不丢包（仅重放端口需要）；录制端口 False 即可。
    """
    if not data or MAGIC not in data:
        return data
    pos = 0
    out = bytearray()
    while pos < len(data):
        fp = _find_valid_magic(data, pos)
        if fp < 0:
            out += data[pos:]
            break
        out += data[pos:fp]
        pos = fp
        if pos + 16 > len(data):
            out += data[pos:]
            break
        nxt = _find_valid_magic(data, pos + 2)
        if nxt < 0:
            nxt = len(data)
        frame = bytes(data[pos:nxt])
        msg_h = frame[6:8].hex().upper() if len(frame) >= 8 else "??"
        if never_drop_handshake and msg_h in _MSG_NEVER_DROP:
            out += frame
            pos = nxt
            continue
        payload = frame[16:] if len(frame) > 16 else b""
        has_marker = any(m in payload for m in _RAW_HIGH_ENTROPY_MARKERS)
        if has_marker:
            if on_drop:
                on_drop(frame, msg_h)
        else:
            out += frame
        pos = nxt
    return bytes(out)


def iter_3366_frames_in_buffer(data: bytes) -> list[tuple[bytes, str]]:
    """从 data 中提取所有 33 66 帧，返回 [(frame, msg_hex), ...]。"""
    out: list[tuple[bytes, str]] = []
    pos = 0
    while pos < len(data):
        fp = _find_valid_magic(data, pos)
        if fp < 0:
            break
        pos = fp
        if pos + 16 > len(data):
            break
        nxt = _find_valid_magic(data, pos + 2)
        if nxt < 0:
            nxt = len(data)
        frame = bytes(data[pos:nxt])
        msg_hex = frame[6:8].hex().upper() if len(frame) >= 8 else "??"
        out.append((frame, msg_hex))
        pos = nxt
    return out


def replace_3366_40_13_frames_in_buffer(
    data: bytearray,
    kv: tuple[bytes, bytes] | None,
    pool_33: list,
    pool_01: list,
    index_33_09: list,
    index_33_21: list,
    index_01_fb: list,
    *,
    len_tol: int = 300,
    on_replace_33: Callable[[], None] | None = None,
    on_replace_log: Callable[[bytes, bytes, bytes, bytes, bytes, bytes, int | None], None] | None = None,
    on_skip_frame: Callable[[str, bytes, bytes | None], None] | None = None,
    on_replace_33_detail: Callable[[str, str, int, int, int, int, int, int | None], None] | None = None,
    on_frame_hex: Callable[[bytes], None] | None = None,
    drop_raw_high_entropy: bool = False,
    intercept_config23: bool = False,
    on_intercept_config23: Callable[[bytes, bytes], None] | None = None,
    ul_dirty_clean: bool = False,
    ul_dirty_strings: list[bytes] | None = None,
    on_ul_dirty_clean: Callable[[bytes, bytes, list[str]], None] | None = None,
    ul_truncate_abab: bool = False,
    ul_truncate_min_len: int = 500,
    on_ul_truncate: Callable[[bytes, bytes], None] | None = None,
    plugin_game_id: str = "",
    pb_ace_replace_enabled: bool = False,
    pb_cmd_blacklist: list[str] | None = None,
) -> bytes:
    """
    扫描 data 中的 33 66 40 13 帧，解密→替换高熵区→重加密→更新 enc_len，返回新字节。
    仅上行调用；无 kv 或未替换时返回原 data。
    on_skip_frame(reason, frame, plain): 40_13 帧处理结果回调。
    ul_dirty_clean: 启用上行 A 类脏数据清除（等长清零来源标识符）。
    ul_dirty_strings: 黑名单字节串列表，None 时使用内置默认前缀。
    on_ul_dirty_clean(frame, plain, hit_strings): 清除成功时回调，hit_strings 为命中的字符串列表。
    plugin_game_id: 插件 Key 游戏标识（如 "0a92"），非空时启用对应游戏专用替换逻辑。
    pb_ace_replace_enabled: 三角洲 ACE 明文 Protobuf 替换开关。
    pb_cmd_blacklist: Protobuf 命令名黑名单（仅 plugin_game_id 非空时生效）；
        命中则等长清零命令名字节后重加密，优先于 ACE 替换执行。
    """
    from core.crypto import try_replace_3366_4013_plain, clean_uplink_3366_plain

    if not kv or not data:
        return bytes(data)
    key, iv = kv
    pos = 0
    out = bytearray()
    while pos < len(data):
        fp = _find_valid_magic(data, pos)
        if fp < 0:
            out += data[pos:]
            break
        out += data[pos:fp]
        pos = fp
        if pos + 25 > len(data):
            out += data[pos:]
            break
        msg = data[pos + 6 : pos + 8]
        msg_h = msg.hex().upper()
        if msg != MSG_DATA:
            nxt = _find_valid_magic(data, pos + 2)
            fr = bytes(data[pos:nxt]) if nxt >= 0 else bytes(data[pos:])
            if on_frame_hex and len(fr) >= 8:
                on_frame_hex(fr)
            if on_skip_frame and len(fr) >= 8:
                # 若不是 40 13，比如 20 01 或 10 01，直接跳过不尝试解密
                on_skip_frame(f"非40_13帧 ({msg_h})，无需替换", fr, None)
            if nxt >= 0:
                out += data[pos:nxt]
                pos = nxt
            else:
                out += data[pos:]
                break
            continue
        enc_len = struct.unpack_from(">H", data, pos + 19)[0]
        if enc_len == 0 or enc_len % 16 != 0 or pos + 25 + enc_len > len(data):
            out += data[pos : pos + 2]
            pos += 2
            continue
        frame = bytes(data[pos : pos + 25 + enc_len])
        if on_frame_hex:
            on_frame_hex(frame)
        cipher = bytes(data[pos + 25 : pos + 25 + enc_len])
        # 插件 Key 游戏（如三角洲）明文为 Protobuf RPC，不含暗区格式特征；
        # 用宽松解密跳过 tsf4g/ABAB/PKCS7 验证，直接取 AES 解密结果。
        if plugin_game_id:
            plain = try_decrypt_4013_frame_raw(frame, key, iv)
        else:
            plain = try_decrypt_4013_frame(frame, key, iv)
        if plain:
            # 上行 config2/config3 拦截：明文含 config2 或 config3 时置空载荷
            if intercept_config23 and (b"config2" in plain or b"config3" in plain):
                new_frame = bytearray(data[pos : pos + 25])
                new_frame[19:21] = struct.pack(">H", 0)  # enc_len = 0
                if on_intercept_config23:
                    on_intercept_config23(frame, plain)
                if on_skip_frame:
                    on_skip_frame("已拦截config2/config3(载荷置空)", frame, plain)
                out += new_frame
                pos += 25 + enc_len
                continue

            # ── 上行大包截断（ABAB 后清除）────────────────────────────────
            if ul_truncate_abab and len(plain) >= ul_truncate_min_len:
                from core.crypto import truncate_uplink_at_abab
                truncated = truncate_uplink_at_abab(plain)
                if truncated is not None:
                    new_cipher_tr = _taes_encrypt(truncated, key, iv)
                    if new_cipher_tr:
                        new_frame_tr = bytearray(data[pos: pos + 25])
                        new_frame_tr[19:21] = struct.pack(">H", len(new_cipher_tr))
                        new_frame_tr += new_cipher_tr
                        if on_ul_truncate:
                            on_ul_truncate(frame, truncated)
                        if on_skip_frame:
                            on_skip_frame(
                                f"[UL截断] ✅ 大包截断 {len(plain)}B→{len(truncated)}B "
                                f"帧{len(frame)}B→{len(new_frame_tr)}B",
                                frame, truncated)
                        out += new_frame_tr
                        pos += 25 + enc_len
                        continue
                    if on_skip_frame:
                        on_skip_frame(
                            f"[UL截断] ❌ 重加密失败 plain={len(plain)}B",
                            frame, plain)
                else:
                    if on_skip_frame:
                        on_skip_frame(
                            f"[UL截断] ⚠ 未找到ABAB或已在末尾 plain={len(plain)}B",
                            frame, plain)

            # ── A 类上行脏数据清除（等长清零来源标识符）────────────────────
            if ul_dirty_clean:
                from core.crypto import _DEFAULT_DIRTY_PREFIXES as _DEF_PFX
                _active_prefixes = ul_dirty_strings or list(_DEF_PFX)
                _pfx_display = [dp.decode("latin-1") for dp in _active_prefixes]

                cleaned_plain, hit_strings = clean_uplink_3366_plain(plain, ul_dirty_strings)

                _seq_ul = (parse_3366_header(frame) or {}).get("seq", "?")

                if hit_strings:
                    new_cipher_dirty = _taes_encrypt(cleaned_plain, key, iv)
                    if new_cipher_dirty:
                        new_enc_len_dirty = len(new_cipher_dirty)
                        new_frame_dirty = bytearray(data[pos : pos + 25])
                        new_frame_dirty[19:21] = struct.pack(">H", new_enc_len_dirty)
                        new_frame_dirty += new_cipher_dirty
                        if on_ul_dirty_clean:
                            on_ul_dirty_clean(frame, cleaned_plain, hit_strings)
                        if on_skip_frame:
                            on_skip_frame(
                                f"[UL清除] seq={_seq_ul} 帧{len(frame)}B ✅ 命中={hit_strings}",
                                frame, cleaned_plain)
                        out += new_frame_dirty
                        pos += 25 + enc_len
                        continue
                    if on_skip_frame:
                        on_skip_frame(
                            f"[UL清除] seq={_seq_ul} 帧{len(frame)}B ❌ 重加密失败，降级走B类替换",
                            frame, cleaned_plain)
                    plain = cleaned_plain
                else:
                    if on_skip_frame:
                        on_skip_frame(
                            f"[UL清除] seq={_seq_ul} 帧{len(frame)}B ⚠ 无命中",
                            frame, plain)

            # ── 插件游戏（Protobuf 明文）路径：不走暗区二进制替换逻辑 ──────
            if plugin_game_id:
                # ── Protobuf 命令名黑名单（清零命令名后重加密）────────────────
                if pb_cmd_blacklist:
                    from core.pb_replace import pb_zero_cmd_name
                    _bl_handled = False
                    for _bl_cmd in pb_cmd_blacklist:
                        _bl_bytes = (
                            _bl_cmd.encode("ascii")
                            if isinstance(_bl_cmd, str) else _bl_cmd
                        )
                        _new_bl_plain, _bl_hit = pb_zero_cmd_name(plain, _bl_bytes)
                        if _bl_hit:
                            _new_bl_cipher = _taes_encrypt(_new_bl_plain, key, iv)
                            if _new_bl_cipher:
                                _new_bl_enc_len = len(_new_bl_cipher)
                                _new_bl_frame = bytearray(data[pos : pos + 25])
                                _new_bl_frame[19:21] = struct.pack(">H", _new_bl_enc_len)
                                _new_bl_frame += _new_bl_cipher
                                if on_skip_frame:
                                    on_skip_frame(
                                        f"[PB_BL] ✅ 命令清零 {_bl_cmd} "
                                        f"{len(plain)}B→{len(_new_bl_plain)}B",
                                        frame, plain,
                                    )
                                out += _new_bl_frame
                                pos += 25 + enc_len
                                _bl_handled = True
                            else:
                                if on_skip_frame:
                                    on_skip_frame(
                                        f"[PB_BL] ❌ 重加密失败 {_bl_cmd}",
                                        frame, plain,
                                    )
                            break  # 每帧只匹配一条黑名单
                    if _bl_handled:
                        continue
                    # 黑名单已配置且本帧未命中：仍记一条「扫描」便于拦截管理对齐重放侧排查
                    _seq_pb_miss = (parse_3366_header(frame) or {}).get("seq", "?")
                    if on_skip_frame:
                        on_skip_frame(
                            f"[PB_BL] ⚠ seq={_seq_pb_miss} 帧{len(frame)}B 扫描 未命中命令黑名单",
                            frame,
                            plain,
                        )

                if pb_ace_replace_enabled:
                    # 三角洲 ACE 替换
                    from core.pb_replace import replace_pb_ace_payload, describe_ace_replacement
                    new_plain_pb, did_replace_pb = replace_pb_ace_payload(
                        plain, pool_01, index_01_fb, len_tol=len_tol
                    )
                    if did_replace_pb:
                        _desc = describe_ace_replacement(plain, new_plain_pb)
                        new_cipher_pb = _taes_encrypt(new_plain_pb, key, iv)
                        if new_cipher_pb:
                            new_enc_len_pb = len(new_cipher_pb)
                            new_frame_pb = bytearray(data[pos : pos + 25])
                            new_frame_pb[19:21] = struct.pack(">H", new_enc_len_pb)
                            new_frame_pb += new_cipher_pb
                            if on_replace_33:
                                on_replace_33()
                            if on_replace_log:
                                info_pb = parse_3366_header(frame)
                                seq_pb = info_pb.get("seq") if info_pb else None
                                on_replace_log(
                                    frame, bytes(new_frame_pb),
                                    cipher, plain, new_plain_pb, new_cipher_pb, seq_pb,
                                )
                            if on_skip_frame:
                                on_skip_frame(f"[PB_ACE] 已替换 {_desc}", frame, plain)
                            out += new_frame_pb
                            pos += 25 + enc_len
                            continue
                        elif on_skip_frame:
                            on_skip_frame("[PB_ACE] 重加密失败", frame, plain)
                    elif on_skip_frame:
                        on_skip_frame("[PB_ACE] 未找到 CSAceSendAntiDataNtf 或池为空", frame, plain)
                else:
                    # ACE 替换开关未启用：透传，不走暗区路径
                    if on_skip_frame:
                        on_skip_frame(
                            f"[{plugin_game_id}] ACE替换未启用，透传", frame, plain)
                out += data[pos : pos + 25 + enc_len]
                pos += 25 + enc_len
                continue

            def _on_33_replace_log(block: str, src: str, pool_idx: int, count: int, orig_high: int, new_len: int):
                if on_replace_33_detail:
                    info = parse_3366_header(frame)
                    seq_val = info.get("seq") if info else None
                    on_replace_33_detail(block, src, pool_idx, count, len(frame), orig_high, new_len, seq_val)

            new_plain, did_replace = try_replace_3366_4013_plain(
                plain, pool_33, pool_01,
                index_33_09, index_33_21, index_01_fb,
                len_tol=len_tol,
                on_replace_log=_on_33_replace_log,
            )
            if did_replace:
                if on_replace_33:
                    on_replace_33()
                new_cipher = _taes_encrypt(new_plain, key, iv)
                if new_cipher:
                    new_enc_len = len(new_cipher)
                    new_frame = bytearray(data[pos : pos + 25])
                    new_frame[19:21] = struct.pack(">H", new_enc_len)
                    new_frame += new_cipher
                    
                    if on_replace_log:
                        info = parse_3366_header(frame)
                        seq_val = info.get("seq") if info else None
                        on_replace_log(frame, new_frame, cipher, plain, new_plain, new_cipher, seq_val)
                    if on_skip_frame:
                        on_skip_frame("已替换", frame, plain)
                    
                    out += new_frame
                    pos += 25 + enc_len
                    continue
                elif on_skip_frame:
                    on_skip_frame("重加密失败", frame, plain)
            elif on_skip_frame:
                payload = frame[16:] if len(frame) > 16 else b""
                has_marker = any(m in payload for m in _RAW_HIGH_ENTROPY_MARKERS)
                if has_marker and drop_raw_high_entropy and msg_h not in _MSG_NEVER_DROP:
                    on_skip_frame("明文无匹配池 (含01_0A_00_09/23将丢弃)", frame, plain)
                else:
                    on_skip_frame("明文无01_0A_00_09/21可替换或无匹配池", frame, plain)
        elif on_skip_frame:
            fail_reason = "解密失败"
            try:
                # 尝试用当前 Key 和 TAES_FIXED_IV 打印原始解密结果，帮助调试
                if key:
                    from Crypto.Cipher import AES
                    info = parse_3366_header(frame)
                    if info and info["msg"] == MSG_DATA:
                        enc_len2 = struct.unpack_from(">H", frame, 19)[0]
                        if enc_len2 > 0 and 25 + enc_len2 <= len(frame):
                            ct = frame[25:25+enc_len2]
                            c_obj = AES.new(key, AES.MODE_CBC, TAES_FIXED_IV)
                            raw_p = c_obj.decrypt(ct)
                            if raw_p:
                                fail_reason += f" (RAW: {raw_p[:16].hex().upper()}...{raw_p[-16:].hex().upper()})"
            except Exception:
                pass

            payload = frame[16:] if len(frame) > 16 else b""
            has_marker = any(m in payload for m in _RAW_HIGH_ENTROPY_MARKERS)
            if has_marker and drop_raw_high_entropy and msg_h not in _MSG_NEVER_DROP:
                on_skip_frame(f"{fail_reason} (含01_0A_00_09/23将丢弃)", frame, None)
            else:
                on_skip_frame(fail_reason, frame, None)
        out += data[pos : pos + 25 + enc_len]
        pos += 25 + enc_len
    return bytes(out)


def format_3366_log_preview(frame: bytes, max_b: int = 48) -> str:
    h = frame[:max_b].hex().upper()
    if len(frame) > max_b:
        h += "…"
    return h
