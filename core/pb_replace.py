"""
pb_replace.py — 三角洲行动 Protobuf 格式 33 通道上行替换逻辑

三角洲 40_13 明文结构（Protobuf RPC）：
  [4B 序号]
  [field1, tag=0A wire=2] [outer_len varint]
    [18 counter] [3A cmd_name_len] [命令名]
    [42 service_len] [服务名]
    [field2, tag=12 wire=2] [outer2_len varint]
      [field1_inner, tag=0A wire=2] [inner_len varint]
        {hex_text(ASCII)}          ← 替换目标

ACE hex text 解码为二进制结构：
  00 00 00 01       (4B magic)
  XX XX             (2B BE: total binary 长度 = 4 + 2 + len(raw_payload))
                    例：0084 = 132 = 4 + 2 + 126
  01 0A 00 09       (4B ACE 标记)
  00 00 00 00 ...   (10B 元数据/零填充)
  <高熵 payload>

与 01 池中的 raw_packet 对应关系：
  raw_packet = binary[6:]  即从 01 0A 00 09 开始的全部数据
  binary[4:6] (2B BE) = total binary 总长度（不是 raw_packet 长度！）

替换策略：
  1. 在明文中搜索 CSAceSendAntiDataNtf 命令名
  2. 定位 protobuf field2(tag=12)→field1_inner(tag=0A)→hex_text 区域
  3. hex text decode → binary → 解析 ACE 结构取 raw_payload
  4. 从 01 池取 raw_packet（从 01_0A_00_09 起始的数据）
  5. 拼装新 binary：magic + len_field(2B BE, = len(raw_packet)) + raw_packet
  6. hex encode 回 ASCII text（大写）
  7. 更新 protobuf varint 长度（inner_len 和 outer2_len 级联）
  8. 返回 (新明文, True)
"""

from __future__ import annotations

import struct

# ── Protobuf varint 编解码 ──────────────────────────────────────────

def _pb_encode_varint(value: int) -> bytes:
    """将无符号整数编码为 protobuf varint"""
    if value < 0:
        raise ValueError("varint must be non-negative")
    parts = []
    while True:
        bits = value & 0x7F
        value >>= 7
        if value:
            parts.append(bits | 0x80)
        else:
            parts.append(bits)
            break
    return bytes(parts)


def _pb_decode_varint(data: bytes, pos: int) -> tuple[int, int] | None:
    """
    从 data[pos] 开始解码 protobuf varint。
    返回 (value, new_pos)，失败返回 None。
    """
    value = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return value, pos
        if shift >= 64:
            return None
    return None


# ── 命令名检测 ────────────────────────────────────────────────────

CMD_ACE_BYTES = b"CSAceSendAntiDataNtf"


def detect_pb_ace_ntf(plain: bytes) -> int | None:
    """
    在明文中搜索 CSAceSendAntiDataNtf 命令名。
    返回命令名起始偏移，未找到返回 None。
    """
    pos = plain.find(CMD_ACE_BYTES)
    if pos < 0:
        return None
    return pos


# ── hex text 区域定位 ─────────────────────────────────────────────

def _find_field2_after_cmd(plain: bytes, cmd_pos: int):
    """
    从命令名结束位置向后扫描，找到 field2（tag=0x12, wire=2）。
    返回 (found_12_pos, outer2_len, outer2_len_varint_start, outer2_len_varint_end)
    失败返回 None。
    """
    search_start = cmd_pos + len(CMD_ACE_BYTES)
    pos = search_start
    limit = min(pos + 128, len(plain))
    while pos < limit:
        if plain[pos] == 0x12:
            r = _pb_decode_varint(plain, pos + 1)
            if r is not None:
                outer2_len, after_outer2 = r
                if 4 <= outer2_len <= len(plain) - after_outer2:
                    return pos, outer2_len, pos + 1, after_outer2
        pos += 1
    return None


def extract_ace_hex_text(
    plain: bytes, cmd_pos: int
) -> tuple[int, int, bytes, int, int, int, int, int, int] | None:
    """
    定位 CSAceSendAntiDataNtf 命令后的 hex text 区域，并记录所有 varint 位置。

    返回：
      (hex_start, hex_end, hex_bytes,
       found_12_pos,
       outer2_len_varint_start, outer2_len_varint_end,
       inner_tag_pos,
       inner_len_varint_start, inner_len_varint_end)

    失败返回 None。
    """
    r = _find_field2_after_cmd(plain, cmd_pos)
    if r is None:
        return None
    found_12_pos, outer2_len, outer2_vstart, outer2_vend = r

    # outer2 内容以 0x0A (field1_inner, wire=2) 开头
    if outer2_vend >= len(plain) or plain[outer2_vend] != 0x0A:
        return None

    inner_tag_pos = outer2_vend
    r2 = _pb_decode_varint(plain, inner_tag_pos + 1)
    if r2 is None:
        return None
    inner_len, inner_vend = r2

    hex_start = inner_vend
    hex_end = hex_start + inner_len
    if hex_end > len(plain):
        return None

    hex_bytes = plain[hex_start:hex_end]
    return (
        hex_start, hex_end, hex_bytes,
        found_12_pos,
        outer2_vstart, outer2_vend,
        inner_tag_pos,
        inner_tag_pos + 1, inner_vend,
    )


# ── 二进制解析 ───────────────────────────────────────────────────

# 三角洲 ACE binary 结构：
#   00 00 00 01  (4B magic)
#   XX XX        (2B BE：后续数据长度 = len(raw_payload))
#   01 0A 00 09  (4B ACE 标记)
#   ...          (后续数据)
# 注：binary[4:6] 的 2B 值 = len(binary) - 6 = len(payload after header)
_ACE_MAGIC = b"\x00\x00\x00\x01"
_ACE_MARKER = b"\x01\x0A\x00\x09"
_ACE_HEADER_LEN = 6  # magic(4) + 2B len 字段


def decode_ace_binary(hex_text: bytes) -> bytes | None:
    """
    将 ACE hex text（ASCII hex 字符串字节）解码为原始 binary。
    如 b"000000010084010A0009..." → bytes
    """
    try:
        return bytes.fromhex(hex_text.decode("ascii"))
    except Exception:
        return None


def parse_ace_binary_structure(binary: bytes) -> tuple[int, int, bytes] | None:
    """
    解析 ACE binary 结构。
    返回 (len_field_value, marker_pos, raw_payload_from_marker)
    其中：
      len_field_value = binary[4:6] BE uint16 = total binary 长度（含 magic 4B + 2B 本身）
                        例：0084 = 132 = 4 + 2 + 126(raw_packet)
      raw_payload_from_marker = binary[marker_pos:]，从 01 0A 00 09 起始
    失败返回 None。
    """
    if len(binary) < 10:
        return None
    if binary[:4] != _ACE_MAGIC:
        return None
    len_field_value = struct.unpack_from(">H", binary, 4)[0]
    marker_pos = binary.find(_ACE_MARKER, 4)
    if marker_pos < 0:
        return None
    raw_payload = binary[marker_pos:]
    return len_field_value, marker_pos, raw_payload


# ── 核心替换函数 ─────────────────────────────────────────────────

def replace_pb_ace_payload(
    plain: bytes,
    pool_01: list,
    index_01_fb: list,
    *,
    len_tol: int = 300,
) -> tuple[bytes, bool]:
    """
    在三角洲 40_13 明文中替换 CSAceSendAntiDataNtf 的 ACE payload。

    流程：
      1. 搜索命令名 CSAceSendAntiDataNtf
      2. 定位 field2→inner hex text 区域（记录所有 varint 位置）
      3. hex decode → binary → 解析 ACE 结构（magic + len_field + raw_payload）
      4. 从 01 池取 raw_packet（含 01_0A_00_09 + 高熵数据）
      5. 拼装新 binary：magic + pack(">H", len(raw_packet)) + raw_packet
      6. hex encode 回大写 ASCII text
      7. 更新 inner_len varint 和 outer2_len varint（级联）
      8. 返回 (新明文, True)

    pool_01 每项为 dict，其 raw_packet 字段为 bytes，从 01_0A_00_09 起始。
    index_01_fb 是 [idx, count] 可变列表，函数内就地轮转更新。

    若替换失败，返回 (原明文, False)。
    """
    # ── 1. 检测命令名 ──
    cmd_pos = detect_pb_ace_ntf(plain)
    if cmd_pos is None:
        return plain, False

    # ── 2. 定位 hex text 区域 ──
    loc = extract_ace_hex_text(plain, cmd_pos)
    if loc is None:
        return plain, False
    (
        hex_start, hex_end, hex_bytes,
        found_12_pos,
        outer2_vstart, outer2_vend,
        inner_tag_pos,
        inner_vstart, inner_vend,
    ) = loc

    # ── 3. 解码 hex text → binary ──
    binary = decode_ace_binary(hex_bytes)
    if binary is None:
        return plain, False

    parsed = parse_ace_binary_structure(binary)
    if parsed is None:
        return plain, False
    orig_len_field, _, orig_raw_payload = parsed

    # ── 4. 从 01 池取 raw_packet（优先长度接近原始，其次轮转）──
    if not pool_01:
        return plain, False

    # 优选含 01_0A_00_09 标记的条目
    candidates = [
        it for it in pool_01
        if it.get("raw_packet") and (
            it["raw_packet"][:4] == _ACE_MARKER
            or it["raw_packet"][:3] == _ACE_MARKER[1:]  # 0A 00 09
        )
    ]
    if not candidates:
        candidates = [it for it in pool_01 if it.get("raw_packet")]
    if not candidates:
        return plain, False

    # orig_len_field（2B BE 字段值）= total binary 长度（含 4B magic + 2B 字段本身）
    # 真正的 raw_packet 目标长度 = orig_len_field - 6
    orig_target_len = len(orig_raw_payload)  # 原始 raw_packet 实际长度

    # 按与目标长度的差值排序，筛选容差内的子集
    sorted_cands = sorted(
        candidates,
        key=lambda it: abs(len(it["raw_packet"]) - orig_target_len),
    )
    within_tol = [
        it for it in sorted_cands
        if abs(len(it["raw_packet"]) - orig_target_len) <= len_tol
    ]
    # 容差内有候选：在其中轮转；否则回退到全量轮转
    pool_for_pick = within_tol if within_tol else sorted_cands

    idx = index_01_fb[0] % len(pool_for_pick)
    best = pool_for_pick[idx]
    index_01_fb[0] = (idx + 1) % max(len(pool_for_pick), 1)
    index_01_fb[1] = index_01_fb[1] + 1

    raw_packet = best["raw_packet"]

    # ── 5. 拼装新 binary ──
    # 2B 字段值语义 = total binary 长度（magic 4B + 2B 字段本身 + raw_packet）
    # 原始: 0084 = 132 = 4 + 2 + 126(raw_packet)，校验通过
    new_total_len = 4 + 2 + len(raw_packet)
    if new_total_len > 0xFFFF:
        return plain, False
    new_binary = _ACE_MAGIC + struct.pack(">H", new_total_len) + raw_packet

    # ── 6. hex encode 回大写 ASCII text ──
    new_hex_text = new_binary.hex().upper().encode("ascii")

    # ── 7. 更新 protobuf varint 长度 ──
    old_inner_len = len(hex_bytes)
    new_inner_len = len(new_hex_text)
    inner_delta = new_inner_len - old_inner_len

    if inner_delta == 0:
        buf = bytearray(plain)
        buf[hex_start:hex_end] = new_hex_text
        return bytes(buf), True

    # 重新编码 inner_len varint
    new_inner_varint = _pb_encode_varint(new_inner_len)
    old_inner_varint_len = inner_vend - inner_vstart
    inner_varint_delta = len(new_inner_varint) - old_inner_varint_len

    # 重新编码 outer2_len varint（outer2_len 需要加上 inner 的变化量）
    r_outer = _pb_decode_varint(plain, outer2_vstart)
    if r_outer is None:
        return plain, False
    old_outer2_len = r_outer[0]
    new_outer2_len = old_outer2_len + inner_delta + inner_varint_delta
    new_outer2_varint = _pb_encode_varint(new_outer2_len)

    # 拼装新明文
    buf = bytearray()
    buf += plain[:found_12_pos + 1]       # 含 0x12 tag
    buf += new_outer2_varint              # 新 outer2_len varint
    buf += bytes([0x0A])                  # inner tag
    buf += new_inner_varint               # 新 inner_len varint
    buf += new_hex_text                   # 新 hex text
    buf += plain[hex_end:]                # field2 后的其余 protobuf 数据

    return bytes(buf), True


# ── Protobuf 命令名黑名单：等长清零命令名字节 ─────────────────────

def pb_zero_cmd_name(plain: bytes, cmd_name: bytes) -> tuple[bytes, bool]:
    """
    在 Protobuf 明文中定位 cmd_name 字节串，将其等长清零（保留 varint 长度字段不变）。

    适用于三角洲上行命令黑名单处理，如 CSTssLoadReportConfigReq。
    清零后 Protobuf 结构合法（length varint 不变），但服务端无法识别命令名，
    通常返回空响应或忽略该 RPC，客户端不获得对应配置。

    返回 (新明文, True) 若找到并清零；否则返回 (原明文, False)。
    """
    pos = plain.find(cmd_name)
    if pos < 0:
        return plain, False
    buf = bytearray(plain)
    buf[pos : pos + len(cmd_name)] = b"\x00" * len(cmd_name)
    return bytes(buf), True


# ── 辅助：生成替换日志描述 ───────────────────────────────────────

def describe_ace_replacement(
    orig_plain: bytes,
    new_plain: bytes,
) -> str:
    """生成简短的替换日志描述"""
    cmd_pos_new = detect_pb_ace_ntf(new_plain)
    loc_new = extract_ace_hex_text(new_plain, cmd_pos_new) if cmd_pos_new is not None else None
    new_hex_len = (loc_new[1] - loc_new[0]) if loc_new else 0

    cmd_pos_orig = detect_pb_ace_ntf(orig_plain)
    loc_orig = extract_ace_hex_text(orig_plain, cmd_pos_orig) if cmd_pos_orig is not None else None
    orig_hex_len = (loc_orig[1] - loc_orig[0]) if loc_orig else 0

    return (
        f"ACE hex_text {orig_hex_len}B→{new_hex_len}B  "
        f"明文 {len(orig_plain)}B→{len(new_plain)}B"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 心跳包替换（黑名单命中后用下行心跳帧替换整个明文）
# ─────────────────────────────────────────────────────────────────────────────

# CSOnlineHeartbeatRes Protobuf 模板（从真实流量截取，payload 区清零）
# 结构：
#   0A 19             field1, wire=2, len=25
#     18 81 02        field3=varint(257), 消息类型
#     3A 14           field7, wire=2, len=20
#       "CSOnlineHeartbeatRes" (20B ASCII)
#   12 02             field2, wire=2, len=2
#     10 00           field1=0（原为时间戳，清零）
_HEARTBEAT_CMD = b"CSOnlineHeartbeatRes"
_HEARTBEAT_INNER = (
    b"\x18\x81\x02"                    # field3 = 257
    b"\x3a" + bytes([len(_HEARTBEAT_CMD)]) + _HEARTBEAT_CMD  # field7 = cmd name
)
_HEARTBEAT_PAYLOAD = b"\x12\x02\x10\x00"  # field2, len=2, 内容=0（时间戳清零）
_HEARTBEAT_TEMPLATE: bytes = (
    b"\x0a" + bytes([len(_HEARTBEAT_INNER)]) + _HEARTBEAT_INNER
    + _HEARTBEAT_PAYLOAD
)


def make_heartbeat_plain() -> bytes:
    """
    返回 CSOnlineHeartbeatRes 的 Protobuf 明文（约31B）。
    当下行黑名单命中时，用此替换整个 plain，客户端只会处理一个心跳响应，
    不会执行被拦截命令（如踢出、TSS 上报配置）的实际逻辑。
    """
    return _HEARTBEAT_TEMPLATE
