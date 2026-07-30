# ─────────────────────────────────────────
# ACE 0x01 录制/重放辅助（来自 ACE_RecordHelper.cs）
# ─────────────────────────────────────────
import hashlib
import zlib

MARKER_0A0009 = b"\x0A\x00\x09"
# 40 13 解密明文内的反作弊子包（3366 分析报告）
# 01 0A 00 09：01 包与 33 帧均有；01 0A 00 21：仅 33 帧（0x33 开头）有
MARKER_01_0A_00_09 = b"\x01\x0A\x00\x09"
MARKER_01_0A_00_21 = b"\x01\x0A\x00\x21"
# 01 0A 00 XX 之后：8 填充 + 1 序号 + 1 类型 → 高熵区起点相对 XX 后偏移 10，相对「01」起 +14
_NEST_SKIP_AFTER_01_0A = 14
ACE_FRAGMENT_DATA_MAX = 4096
ACE_FIRST_HEADER_LEN = 0x37
ACE_NEXT_HEADER_LEN = 0x33


def _be16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def _be32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "big")


def parse_ace_fragment(frame: bytes) -> dict | None:
    """解析指南所述的 ``01 00 00`` 物理分片。"""
    if len(frame) < ACE_NEXT_HEADER_LEN or frame[:3] != b"\x01\x00\x00":
        return None
    declared = _be16(frame, 3)
    if declared != len(frame):
        return None
    first = frame[0x2C] == 1
    header_len = ACE_FIRST_HEADER_LEN if first else ACE_NEXT_HEADER_LEN
    if len(frame) < header_len:
        return None
    if first:
        fragment_number = _be16(frame, 0x31)
        data_length = _be32(frame, 0x33)
        payload_type = _be16(frame, 0x2D)
        transport_tag = frame[0x2F]
    else:
        fragment_number = _be16(frame, 0x2D)
        data_length = _be32(frame, 0x2F)
        payload_type = None
        transport_tag = None
    if fragment_number <= 0 or data_length != len(frame) - header_len:
        return None
    fragment_count = _be16(frame, 0x26)
    if fragment_count <= 0 or fragment_number > fragment_count:
        return None
    return {
        "frame": bytes(frame),
        "first": first,
        "header_len": header_len,
        "fragment_number": fragment_number,
        "fragment_count": fragment_count,
        "packet_group": _be16(frame, 0x24),
        "crc32": _be32(frame, 0x28),
        "payload_type": payload_type,
        "transport_tag": transport_tag,
        "data": bytes(frame[header_len:]),
    }


def _type9_record_bounds(logical_payload: bytes) -> dict | None:
    """
    定位 type-9 容器中的 ``01 0A 00 09`` 加密记录。

    返回范围只覆盖必须成套替换的
    selector/key-index/plaintext-crc/cipher-len/ciphertext，不吞掉后续记录。
    """
    if len(logical_payload) < 32:
        return None
    identity_len = logical_payload[23]
    inner_length_offset = 24 + identity_len
    inner_start = inner_length_offset + 2
    descriptor_start = inner_start + 6
    if descriptor_start + 18 > len(logical_payload):
        return None
    if logical_payload[descriptor_start:descriptor_start + 4] != MARKER_01_0A_00_09:
        # 兼容尚未完全标定的容器，但仍要求完整 4 字节记录码。
        descriptor_start = logical_payload.find(MARKER_01_0A_00_09)
        if descriptor_start < 0:
            return None
    fixed_prefix_start = descriptor_start + 4
    record_start = fixed_prefix_start + 10
    if record_start + 8 > len(logical_payload):
        return None
    cipher_len = _be16(logical_payload, record_start + 6)
    record_end = record_start + 8 + cipher_len
    if cipher_len <= 0 or record_end > len(logical_payload):
        return None
    return {
        "identity_len": identity_len,
        "inner_length_offset": inner_length_offset,
        "inner_start": inner_start,
        "descriptor_start": descriptor_start,
        "record_start": record_start,
        "record_end": record_end,
        "cipher_len": cipher_len,
        "algorithm_selector": logical_payload[record_start],
        "key_index": logical_payload[record_start + 1],
        "plaintext_crc32": _be32(logical_payload, record_start + 2),
    }


def _extract_clean_encrypted_record(logical_payload: bytes) -> tuple[bytes, dict] | None:
    bounds = _type9_record_bounds(logical_payload)
    if not bounds:
        return None
    record = bytes(logical_payload[bounds["record_start"]:bounds["record_end"]])
    meta = dict(bounds)
    meta["encrypted_record_sha256"] = hashlib.sha256(record).hexdigest()
    return record, meta


def _rebuild_type9_payload(
    logical_payload: bytes, clean_encrypted_record: bytes
) -> tuple[bytes, dict] | None:
    bounds = _type9_record_bounds(logical_payload)
    if not bounds or len(clean_encrypted_record) < 8:
        return None
    clean_cipher_len = _be16(clean_encrypted_record, 6)
    if clean_cipher_len <= 0 or len(clean_encrypted_record) != 8 + clean_cipher_len:
        return None

    old_record_len = bounds["record_end"] - bounds["record_start"]
    rebuilt = bytearray(
        logical_payload[:bounds["record_start"]]
        + clean_encrypted_record
        + logical_payload[bounds["record_end"]:]
    )
    delta = len(clean_encrypted_record) - old_record_len

    # 由内向外重建已确认的长度字段。
    inner_length_offset = bounds["inner_length_offset"]
    inner_start = bounds["inner_start"]
    inner_len = len(rebuilt) - inner_start
    if 0 <= inner_len <= 0xFFFF:
        rebuilt[inner_length_offset:inner_length_offset + 2] = inner_len.to_bytes(2, "big")
        echo_offset = inner_length_offset + 6
        if echo_offset + 2 <= len(rebuilt):
            rebuilt[echo_offset:echo_offset + 2] = inner_len.to_bytes(2, "big")
    if len(rebuilt) <= 0xFFFF and len(rebuilt) >= 6:
        rebuilt[4:6] = len(rebuilt).to_bytes(2, "big")

    return bytes(rebuilt), {
        "old_encrypted_record_len": old_record_len,
        "new_encrypted_record_len": len(clean_encrypted_record),
        "payload_delta": delta,
        "algorithm_selector_clean": clean_encrypted_record[0],
        "key_index_clean": clean_encrypted_record[1],
        "plaintext_crc32_clean": clean_encrypted_record[2:6].hex().upper(),
        "ciphertext_length_clean": clean_cipher_len,
    }


def rebuild_ace_fragments(
    live_fragments: list[bytes], logical_payload: bytes
) -> tuple[list[bytes], dict]:
    """保留实时会话头字段，重算 CRC/长度并按 4096 字节重新分片。"""
    parsed = [parse_ace_fragment(frame) for frame in live_fragments]
    if not parsed or any(info is None for info in parsed):
        return list(live_fragments), {}
    infos = sorted(parsed, key=lambda info: info["fragment_number"])
    first = next((info for info in infos if info["first"]), None)
    if not first:
        return list(live_fragments), {}

    chunks = [
        logical_payload[pos:pos + ACE_FRAGMENT_DATA_MAX]
        for pos in range(0, len(logical_payload), ACE_FRAGMENT_DATA_MAX)
    ] or [b""]
    crc32_value = zlib.crc32(logical_payload) & 0xFFFFFFFF
    by_number = {info["fragment_number"]: info for info in infos}
    out: list[bytes] = []
    base_sequence = _be16(first["frame"], 0x08)

    for idx, chunk in enumerate(chunks, 1):
        template = by_number.get(idx)
        if idx == 1:
            header = bytearray(first["frame"][:ACE_FIRST_HEADER_LEN])
            header[0x2C] = 1
            header[0x31:0x33] = idx.to_bytes(2, "big")
            header[0x33:0x37] = len(chunk).to_bytes(4, "big")
        else:
            source = template["frame"] if template else first["frame"]
            header = bytearray(source[:ACE_NEXT_HEADER_LEN])
            header[0x2C] = 0
            header[0x2D:0x2F] = idx.to_bytes(2, "big")
            header[0x2F:0x33] = len(chunk).to_bytes(4, "big")
            if not template:
                header[0x08:0x0A] = ((base_sequence + idx - 1) & 0xFFFF).to_bytes(2, "big")
        header[0x24:0x26] = first["packet_group"].to_bytes(2, "big")
        header[0x26:0x28] = len(chunks).to_bytes(2, "big")
        header[0x28:0x2C] = crc32_value.to_bytes(4, "big")
        total_len = len(header) + len(chunk)
        header[3:5] = total_len.to_bytes(2, "big")
        out.append(bytes(header) + chunk)

    return out, {
        "old_crc32": f'{first["crc32"]:08X}',
        "new_crc32": f"{crc32_value:08X}",
        "old_fragment_count": first["fragment_count"],
        "new_fragment_count": len(chunks),
        "new_logical_payload_len": len(logical_payload),
        "new_payload_sha256": hashlib.sha256(logical_payload).hexdigest(),
    }


def _ace_split_packets(buffer: bytes) -> list[bytes]:
    """按 0x01 子包拆分，a[3..4] 大端为包长"""
    out = []
    pos = 0
    while pos + 5 <= len(buffer):
        if buffer[pos] != 0x01:
            pos += 1
            continue
        ln = (buffer[pos + 3] << 8) | buffer[pos + 4]
        if ln < 5 or pos + ln > len(buffer):
            ln = len(buffer) - pos
            if ln < 5:
                break
        out.append(bytes(buffer[pos : pos + ln]))
        pos += ln
    return out


def _ace_index_of(data: bytes, pattern: bytes) -> int:
    for i in range(len(data) - len(pattern) + 1):
        if data[i : i + len(pattern)] == pattern:
            return i
    return -1


def _ace_find_replace_anchor(packet: bytes) -> tuple[int, int, str] | None:
    """
    定位应对「高熵加密区」做池替换的起始下标。
    用于 0x01 包：仅含 01 0A 00 09 / 0A 00 09（01 0A 00 21 只在 0x33 帧有）。
    返回 (replace_start, raw_block_start, kind) 或 None。
    """
    if len(packet) < 16:
        return None
    i = packet.find(MARKER_01_0A_00_09)
    if i >= 0:
        rs = i + _NEST_SKIP_AFTER_01_0A
        if rs <= len(packet):
            return rs, i, "01_0a_09"
    p = _ace_index_of(packet, MARKER_0A0009)
    if p < 0:
        return None
    if p >= 1 and packet[p - 1] == 0x01 and p + 2 < len(packet):
        if packet[p - 1 : p + 3] == MARKER_01_0A_00_09[:4]:
            rs = (p - 1) + _NEST_SKIP_AFTER_01_0A
            if rs <= len(packet):
                return rs, p - 1, "01_0a_xx"
    return p + 3, p, "legacy_0a_09"


def _ace_try_extract(packet: bytes) -> dict | None:
    """
    从 0x01 包提取 0A 00 09 段：payload、CRC、routing、account_id。
    01 包仅含 01 0A 00 09 / 0A 00 09，不含 01 0A 00 21。
    """
    if len(packet) < 102:
        return None
    fragment = parse_ace_fragment(packet)
    if fragment and fragment["first"] and fragment["fragment_count"] == 1:
        return extract_ace_clean_item([packet])
    else:
        # 兼容旧导入格式；新采集优先走结构化、带边界的 type-9 记录。
        anchor = _ace_find_replace_anchor(packet)
        if anchor is None:
            return None
        payload_start, raw_start, kind = anchor
        if payload_start >= len(packet):
            return None
        payload = bytes(packet[payload_start:])
        crc = bytes(packet[40:44])
        routing = bytes([packet[47]])
        account_id = _parse_ace_account_id(packet)
        raw_packet = bytes(packet[raw_start:])
    return {
        "payload": payload,
        "crc": crc,
        "routing": routing,
        "account_id": account_id,
        "source": "01",
        "anchor_kind": kind,
        "raw_packet": raw_packet,
        "schema": "tersafe-type9-clean-record-v2" if fragment else "legacy-tail-v1",
    }


def extract_ace_clean_item(frames: list[bytes]) -> dict | None:
    """从完整物理分片组提取一条有明确边界的 type-9 干净记录。"""
    infos = [parse_ace_fragment(frame) for frame in frames]
    if not infos or any(info is None for info in infos):
        return None
    infos = sorted(infos, key=lambda info: info["fragment_number"])
    expected = infos[0]["fragment_count"]
    if len(infos) != expected:
        return None
    if [info["fragment_number"] for info in infos] != list(range(1, expected + 1)):
        return None
    logical_payload = b"".join(info["data"] for info in infos)
    extracted = _extract_clean_encrypted_record(logical_payload)
    if not extracted:
        return None
    record, meta = extracted
    first = infos[0]
    account_id = _parse_ace_account_id(first["frame"])
    return {
        "payload": record,
        "crc": first["crc32"].to_bytes(4, "big"),
        "routing": bytes([first["transport_tag"] or 0]),
        "account_id": account_id,
        "source": "01",
        "anchor_kind": "01_0a_09",
        "raw_packet": bytes(
            logical_payload[meta["descriptor_start"]:meta["record_end"]]
        ),
        "schema": "tersafe-type9-clean-record-v2",
        "fragment_count": expected,
        "logical_payload_sha256": hashlib.sha256(logical_payload).hexdigest(),
        "encrypted_record_sha256": meta["encrypted_record_sha256"],
    }


class AceCaptureAssembler:
    """录制侧物理分片重组器。"""

    def __init__(self):
        self._pending: dict[tuple[int, int, int], dict] = {}

    def feed(self, frame: bytes) -> dict | None:
        info = parse_ace_fragment(frame)
        if not info:
            return _ace_try_extract(frame)
        if info["fragment_count"] == 1:
            return extract_ace_clean_item([frame])
        key = (info["packet_group"], info["fragment_count"], info["crc32"])
        entry = self._pending.setdefault(
            key, {"expected": info["fragment_count"], "frames": {}}
        )
        entry["frames"][info["fragment_number"]] = frame
        if len(entry["frames"]) < entry["expected"]:
            return None
        ordered = [entry["frames"][i] for i in range(1, entry["expected"] + 1)]
        self._pending.pop(key, None)
        return extract_ace_clean_item(ordered)


def _ace_try_replace_length_fallback(
    packet: bytes,
    pool: list[dict],
    pool_index: list,
    *,
    tol: int,
    header_skip: int,
    on_log=None,
) -> tuple[bytes, bool]:
    """
    无 0A 00 09 / 01 0A 00 09/21 锚点时：从 header_skip 起视为「可替换尾区」，
    在池内按 len(payload) 与尾区长度的差绝对值 ≤ tol 择优，取最小差者。
    """
    if not pool or len(packet) <= header_skip:
        return packet, False
    tail_len = len(packet) - header_skip
    best = None
    best_i = -1
    best_d = tol + 1
    for i, it in enumerate(pool):
        pl = it.get("payload") or b""
        d = abs(len(pl) - tail_len)
        if d <= tol and d < best_d:
            best_d = d
            best = it
            best_i = i
    if best is None or best_i < 0:
        return packet, False
    item = best
    idx = best_i
    pool_index[0] += 1
    new_pl = item.get("payload") or b""
    if not new_pl and tail_len > 0:
        return packet, False
    if len(new_pl) >= tail_len:
        new_tail = new_pl[:tail_len]
    else:
        new_tail = new_pl + bytes(tail_len - len(new_pl))
    new_buf = bytearray(packet)
    new_buf[header_skip : header_skip + tail_len] = new_tail
    total = len(new_buf)
    if total >= 5 and packet[0] == 0x01:
        new_buf[3] = (total >> 8) & 0xFF
        new_buf[4] = total & 0xFF
    if len(new_buf) >= 44:
        new_buf[40:44] = item.get("crc", b"\0\0\0\0")[:4].ljust(4, b"\0")
    if len(new_buf) >= 48:
        new_buf[47] = item.get("routing", b"\0")[0] if item.get("routing") else 0
    if len(new_buf) > 55:
        seg_a = len(new_buf) - 55
        new_buf[53] = (seg_a >> 8) & 0xFF
        new_buf[54] = seg_a & 0xFF
        if len(new_buf) >= 61:
            new_buf[59] = new_buf[53]
            new_buf[60] = new_buf[54]
    if len(new_buf) > 78:
        id_len = new_buf[78]
        if 0 < id_len <= 64:
            seg_b_start = 78 + id_len + 3
            if seg_b_start < len(new_buf):
                seg_b_len = len(new_buf) - seg_b_start
                pos1 = 78 + id_len + 1
                pos2 = 78 + id_len + 7
                if pos1 + 1 < len(new_buf):
                    new_buf[pos1] = (seg_b_len >> 8) & 0xFF
                    new_buf[pos1 + 1] = seg_b_len & 0xFF
                if pos2 + 1 < len(new_buf):
                    new_buf[pos2] = (seg_b_len >> 8) & 0xFF
                    new_buf[pos2 + 1] = seg_b_len & 0xFF
    orig_len = tail_len
    detail = {
        "pool_idx": idx,
        "pool_total": len(pool),
        "orig_payload_len": orig_len,
        "new_payload_len": len(new_tail),
        "orig_pkt_len": len(packet),
        "new_pkt_len": len(new_buf),
        "crc_hex": (item.get("crc") or b"").hex().upper(),
        "routing_hex": (item.get("routing") or b"\0")[:1].hex().upper(),
        "account_id": item.get("account_id", ""),
        "payload_preview": new_tail[:64],
        "orig_packet": bytes(packet),
        "new_packet": bytes(new_buf),
        "replace_mode": "length_fallback",
    }
    if on_log:
        on_log(detail)
    return bytes(new_buf), True


def replace_ace_fragment_group(
    frames: list[bytes],
    pool: list[dict],
    pool_index: list,
    on_log=None,
) -> tuple[bytes, bool]:
    """
    重组完整逻辑 payload，替换 type-9 加密记录，再重算 CRC32 并重新分片。

    样本池使用绝对顺序游标；耗尽后保持原包并等待新录制追加，不回绕旧样本。
    """
    infos = [parse_ace_fragment(frame) for frame in frames]
    if not infos or any(info is None for info in infos):
        return b"".join(frames), False
    infos = sorted(infos, key=lambda info: info["fragment_number"])
    expected = infos[0]["fragment_count"]
    if len(infos) != expected or [x["fragment_number"] for x in infos] != list(range(1, expected + 1)):
        return b"".join(frames), False
    logical_payload = b"".join(info["data"] for info in infos)

    idx = int(pool_index[0])
    if idx >= len(pool):
        return b"".join(info["frame"] for info in infos), False
    item = pool[idx]
    clean_record = item.get("payload") or b""
    if item.get("schema") != "tersafe-type9-clean-record-v2":
        # 旧池若本身恰好是完整自洽记录，仍可迁移使用；其余旧尾区停止套用。
        if len(clean_record) < 8 or _be16(clean_record, 6) + 8 != len(clean_record):
            return b"".join(info["frame"] for info in infos), False
    rebuilt = _rebuild_type9_payload(logical_payload, clean_record)
    if not rebuilt:
        return b"".join(info["frame"] for info in infos), False
    new_payload, record_detail = rebuilt
    new_frames, frame_detail = rebuild_ace_fragments(
        [info["frame"] for info in infos], new_payload
    )
    if not frame_detail:
        return b"".join(info["frame"] for info in infos), False

    pool_index[0] += 1
    detail = {
        "pool_idx": idx,
        "pool_total": len(pool),
        "orig_payload_len": len(logical_payload),
        "new_payload_len": len(new_payload),
        "orig_pkt_len": sum(len(info["frame"]) for info in infos),
        "new_pkt_len": sum(len(frame) for frame in new_frames),
        "crc_hex": frame_detail["new_crc32"],
        "old_crc_hex": frame_detail["old_crc32"],
        "routing_hex": f'{infos[0]["transport_tag"] or 0:02X}',
        "account_id": item.get("account_id", ""),
        "payload_preview": clean_record[:64],
        "orig_packet": b"".join(info["frame"] for info in infos),
        "new_packet": b"".join(new_frames),
        "replace_mode": "type9_crc32_rebuild",
        "anchor_kind": "01_0a_09",
        **record_detail,
        **frame_detail,
    }
    if on_log:
        on_log(detail)
    return b"".join(new_frames), True


class AceReplayAssembler:
    """按连接聚合 type-9 分片，收齐后一次性重放并输出重建帧。"""

    def __init__(self):
        self._pending: dict[tuple[int, int, int], dict] = {}

    def clear(self) -> None:
        self._pending.clear()

    def feed(
        self,
        frame: bytes,
        pool: list[dict],
        pool_index: list,
        on_log=None,
    ) -> tuple[bytes, bool]:
        info = parse_ace_fragment(frame)
        if not info:
            return frame, False
        if info["fragment_count"] == 1:
            return replace_ace_fragment_group([frame], pool, pool_index, on_log=on_log)

        key = (info["packet_group"], info["fragment_count"], info["crc32"])
        entry = self._pending.setdefault(
            key, {"expected": info["fragment_count"], "frames": {}}
        )
        entry["frames"][info["fragment_number"]] = frame
        if len(entry["frames"]) < entry["expected"]:
            return b"", False
        ordered = [entry["frames"][i] for i in range(1, entry["expected"] + 1)]
        self._pending.pop(key, None)
        return replace_ace_fragment_group(
            ordered, pool, pool_index, on_log=on_log
        )


def _ace_try_replace(packet: bytes, pool: list[dict], pool_index: list,
                     on_log=None,
                     *,
                     len_tol: int | None = None,
                     len_header_skip: int | None = None,
                     length_pick_tol: int | None = None) -> tuple[bytes, bool]:
    """
    用池中数据替换包内 0A 00 09 段。
    pool_index: [int] 单元素列表，会被原地修改。
    返回 (替换后的包, 是否发生了替换)。
    on_log(msg, detail_dict) 可选，detail_dict 含替换详情供详情对话框显示。
    若无锚点且提供 len_tol，则对包尾做长度优先匹配（见 _ace_try_replace_length_fallback）。
    length_pick_tol: 若设置且存在锚点：在「可替换区长度」与池项 payload 长度差 ≤ 此值
    的条目中取差最小的一条（长度优先）；若无任何命中则回退为按 pool_index 轮转取池。
    """
    if not pool:
        return packet, False
    fragment = parse_ace_fragment(packet)
    if fragment and fragment["fragment_count"] == 1:
        return replace_ace_fragment_group(
            [packet], pool, pool_index, on_log=on_log
        )
    anchor = _ace_find_replace_anchor(packet)
    if anchor is None:
        if (
            len_tol is not None
            and len_header_skip is not None
            and len(packet) > len_header_skip
        ):
            return _ace_try_replace_length_fallback(
                packet, pool, pool_index,
                tol=len_tol,
                header_skip=len_header_skip,
                on_log=on_log,
            )
        return packet, False

    replace_start, _raw_start, _kind = anchor
    if len(packet) < 102:
        if (
            len_tol is not None
            and len_header_skip is not None
            and len(packet) > len_header_skip
        ):
            return _ace_try_replace_length_fallback(
                packet, pool, pool_index,
                tol=len_tol,
                header_skip=len_header_skip,
                on_log=on_log,
            )
        return packet, False

    orig_len = len(packet) - replace_start
    idx: int
    item: dict
    pick_mode = "anchor"
    best_d: int | None = None
    if length_pick_tol is not None and length_pick_tol >= 0:
        candidates: list[tuple[int, int]] = []
        for i, it in enumerate(pool):
            pl = it.get("payload") or b""
            if not pl:
                continue
            d = abs(len(pl) - orig_len)
            if d <= length_pick_tol:
                candidates.append((d, i))
        if candidates:
            candidates.sort(key=lambda x: (x[0], x[1]))
            best_d, idx = candidates[0]
            item = pool[idx]
            pick_mode = "anchor_length"
        else:
            idx = pool_index[0] % len(pool)
            item = pool[idx]
            pool_index[0] += 1
            pick_mode = "anchor_fallback_rr"
    else:
        idx = pool_index[0]
        if idx >= len(pool):
            return packet, False
        item = pool[idx]
        pool_index[0] += 1
    new_payload = item.get("payload") or b""
    if not new_payload:
        return packet, False

    if len(new_payload) > orig_len:
        new_buf = bytearray(len(packet) + (len(new_payload) - orig_len))
    elif len(new_payload) < orig_len:
        new_buf = bytearray(len(packet) - (orig_len - len(new_payload)))
    else:
        new_buf = bytearray(len(packet))

    new_buf[:replace_start] = packet[:replace_start]
    new_buf[replace_start : replace_start + len(new_payload)] = new_payload

    # 更新总长度 a[3..4]
    total = len(new_buf)
    new_buf[3] = (total >> 8) & 0xFF
    new_buf[4] = total & 0xFF
    # legacy 格式只保留实时路由字节；CRC 不再复制历史样本。
    # 结构化 type-9 帧在 replace_ace_fragment_group 中按完整逻辑 payload 重算。

    # 分段长度等（简化版，主项目有 UpdateTotalLengths）
    if len(new_buf) > 55:
        seg_a = len(new_buf) - 55
        new_buf[53] = (seg_a >> 8) & 0xFF
        new_buf[54] = seg_a & 0xFF
        if len(new_buf) >= 61:
            new_buf[59] = new_buf[53]
            new_buf[60] = new_buf[54]

    # 更新 Segment B（0A 00 09 之后的部分）的相关长度
    if len(new_buf) > 78:
        id_len = new_buf[78]
        if 0 < id_len <= 64:
            seg_b_start = 78 + id_len + 3
            if seg_b_start < len(new_buf):
                seg_b_len = len(new_buf) - seg_b_start
                pos1 = 78 + id_len + 1
                pos2 = 78 + id_len + 7
                if pos1 + 1 < len(new_buf):
                    new_buf[pos1] = (seg_b_len >> 8) & 0xFF
                    new_buf[pos1 + 1] = seg_b_len & 0xFF
                if pos2 + 1 < len(new_buf):
                    new_buf[pos2] = (seg_b_len >> 8) & 0xFF
                    new_buf[pos2 + 1] = seg_b_len & 0xFF

    detail = {
        "pool_idx": idx,
        "pool_total": len(pool),
        "orig_payload_len": orig_len,
        "new_payload_len": len(new_payload),
        "orig_pkt_len": len(packet),
        "new_pkt_len": len(new_buf),
        "crc_hex": (item.get("crc") or b"").hex().upper(),
        "routing_hex": (item.get("routing") or b"\0")[:1].hex().upper(),
        "account_id": item.get("account_id", ""),
        "payload_preview": new_payload[:64],  # 前64字节预览
        "orig_packet": bytes(packet),
        "new_packet": bytes(new_buf),
        "replace_mode": pick_mode,
        "anchor_kind": _kind,
    }
    if length_pick_tol is not None:
        detail["length_pick_tol"] = length_pick_tol
    if pick_mode == "anchor_length":
        detail["length_pick_best_delta"] = best_d
    if on_log:
        on_log(detail)
    return bytes(new_buf), True


# ─────────────────────────────────────────
# 游戏账号 ID 提取（来自 ACE_RecordHelper.cs 算法）
# ─────────────────────────────────────────
def _nested_01_0a_block_end_exclusive(plain: bytes, marker_pos: int) -> int | None:
    """
    若 marker 前紧邻 00000001 + 2B BE 块长（见 3366协议01_0A_00_09长度字段分析.md），
    返回该逻辑块尾端下标（不包含），用于截断高熵区，避免吃到明文尾部填充。
    """
    if marker_pos < 6:
        return None
    if plain[marker_pos - 6 : marker_pos - 2] != b"\x00\x00\x00\x01":
        return None
    blen = int.from_bytes(plain[marker_pos - 2 : marker_pos], "big")
    if blen < 10:
        return None
    start_b = marker_pos - 6
    end_ex = start_b + blen
    if end_ex > len(plain):
        return None
    return end_ex


def try_replace_3366_4013_plain(
    plain: bytes,
    pool_33: list[dict],
    pool_01: list[dict],
    index_33_09: list,
    index_33_21: list,
    index_01_fallback: list,
    *,
    len_tol: int = 300,
    on_replace_log: callable = None,
) -> tuple[bytes, bool]:
    """
    在 40 13 明文中替换 01 0A 00 09/21 高熵区。
    09：先 33 池循环，空则 01 池 ±len_tol 匹配循环。
    21：仅 33 池循环。
    返回 (新明文, 是否发生替换)。会更新子包长度字段。
    """
    if len(plain) < _NEST_SKIP_AFTER_01_0A:
        return plain, False
    pool_33_09 = [it for it in pool_33 if "09" in str(it.get("source", ""))]
    pool_33_21 = [it for it in pool_33 if "21" in str(it.get("source", ""))]
    buf = bytearray(plain)
    replaced = False
    for marker, is_09 in ((MARKER_01_0A_00_09, True), (MARKER_01_0A_00_21, False)):
        pos = 0
        while True:
            i = buf.find(marker, pos)
            if i < 0:
                break
            rs = i + _NEST_SKIP_AFTER_01_0A
            if rs > len(buf):
                pos = i + 1
                continue
            j = len(buf)
            for m2 in (MARKER_01_0A_00_09, MARKER_01_0A_00_21):
                n2 = buf.find(m2, i + 4)
                if n2 >= 0 and n2 < j:
                    j = n2
            bend = _nested_01_0a_block_end_exclusive(bytes(buf), i)
            if bend is not None and bend >= rs:
                j = min(j, bend)
            orig_len = j - rs
            if orig_len <= 0:
                pos = i + 4
                continue

            item = None
            idx_ref = None
            used_idx = 0
            used_src = ""
            if is_09:
                # 09：33 池优先；若 33 池当前项与原始高熵长度差距过大（>len_tol），则从 01 池取更匹配的
                use_01 = False
                if pool_33_09 and index_33_09[0] < len(pool_33_09):
                    idx = index_33_09[0]
                    item_33 = pool_33_09[idx]
                    gap_33 = abs(len(item_33.get("payload") or b"") - orig_len)
                    matches_01 = [
                        (it, abs(len(it.get("payload") or b"") - orig_len))
                        for it in pool_01
                        if abs(len(it.get("payload") or b"") - orig_len) <= len_tol
                    ]
                    if gap_33 > len_tol and matches_01:
                        matches_01.sort(key=lambda x: x[1])
                        use_01 = True
                if use_01:
                    used_src = "01池回退"
                    idx_ref = index_01_fallback
                    idx = idx_ref[0]
                    if idx < len(matches_01):
                        used_idx = idx
                        item = matches_01[idx][0]
                        idx_ref[0] = idx + 1
                elif pool_33_09 and index_33_09[0] < len(pool_33_09):
                    used_src = "33池"
                    idx_ref = index_33_09
                    idx = idx_ref[0]
                    used_idx = idx
                    item = pool_33_09[idx]
                    idx_ref[0] = idx + 1
                else:
                    matches_01 = [
                        (it, abs(len(it.get("payload") or b"") - orig_len))
                        for it in pool_01
                        if abs(len(it.get("payload") or b"") - orig_len) <= len_tol
                    ]
                    if matches_01:
                        used_src = "01池回退"
                        matches_01.sort(key=lambda x: x[1])
                        idx_ref = index_01_fallback
                        idx = idx_ref[0]
                        if idx < len(matches_01):
                            used_idx = idx
                            item = matches_01[idx][0]
                            idx_ref[0] = idx + 1
            else:
                if pool_33_21 and index_33_21[0] < len(pool_33_21):
                    idx_ref = index_33_21
                    idx = idx_ref[0]
                    used_idx = idx
                    item = pool_33_21[idx]
                    idx_ref[0] = idx + 1

            if item is not None and idx_ref is not None:
                new_payload = item.get("payload") or b""
                new_len = len(new_payload)
                count_after = idx_ref[1] + 1
                if on_replace_log:
                    src = used_src if is_09 else "33池"
                    on_replace_log("09" if is_09 else "21", src, used_idx + 1, count_after, orig_len, new_len)
                idx_ref[1] = count_after
                buf[rs:j] = new_payload
                delta = len(new_payload) - orig_len
                # 仅更新 01 0A 00 09 前的块内 LEN
                if i >= 6 and buf[i - 6 : i - 2] == b"\x00\x00\x00\x01":
                    blen_pos = i - 2
                    old_blen = int.from_bytes(buf[blen_pos : blen_pos + 2], "big")
                    new_blen = old_blen + delta
                    if new_blen > 0 and new_blen < 65536:
                        buf[blen_pos : blen_pos + 2] = new_blen.to_bytes(2, "big")
                        
                    # 同步更新头部的 PROTO_LEN (若与旧块长度一致)
                    if len(buf) >= 8:
                        proto_len = int.from_bytes(buf[4:8], "big")
                        if proto_len == old_blen:
                            new_proto_len = proto_len + delta
                            if 0 < new_proto_len < 4294967296:
                                buf[4:8] = new_proto_len.to_bytes(4, "big")
                                
                replaced = True
            pos = i + 4
    return bytes(buf), replaced


def extract_pool_items_from_3366_plaintext(plain: bytes) -> list[dict]:
    """
    在 40 13 AES 解密后的明文中，提取所有 01 0A 00 09 / 01 0A 00 21 嵌套块的高熵区，
    生成与 01 池兼容的 dict（payload / crc / routing / account_id / source）。
    """
    if len(plain) < _NEST_SKIP_AFTER_01_0A:
        return []
    crc = bytes(plain[40:44]) if len(plain) >= 44 else b"\0" * 4
    routing = bytes([plain[47]]) if len(plain) >= 48 else b"\0"
    aid = _parse_ace_account_id(plain)
    out: list[dict] = []
    for marker, tag in (
        (MARKER_01_0A_00_09, "3366_09"),
        (MARKER_01_0A_00_21, "3366_21"),
    ):
        pos = 0
        while True:
            i = plain.find(marker, pos)
            if i < 0:
                break
            rs = i + _NEST_SKIP_AFTER_01_0A
            if rs > len(plain):
                pos = i + 1
                continue
            j = len(plain)
            for m2 in (MARKER_01_0A_00_09, MARKER_01_0A_00_21):
                n2 = plain.find(m2, i + 4)
                if n2 >= 0 and n2 < j:
                    j = n2
            bend = _nested_01_0a_block_end_exclusive(plain, i)
            if bend is not None and bend >= rs:
                j = min(j, bend)
            payload = plain[rs:j]
            if payload:
                # 原始 01 0a 00 xx 块：从 01 字节到块尾
                raw_start = i - 1 if i >= 1 and plain[i - 1] == 0x01 else i
                raw_packet = bytes(plain[raw_start:j])
                out.append(
                    {
                        "payload": payload,
                        "crc": crc,
                        "routing": routing,
                        "account_id": aid,
                        "source": tag,
                        "anchor_kind": (
                            "01_0a_09" if marker == MARKER_01_0A_00_09 else "01_0a_21"
                        ),
                        "raw_packet": raw_packet,
                    }
                )
            pos = i + 4
    return out


def _parse_ace_account_id(data: bytes) -> str:
    """
    从 ACE 0x01 包中提取游戏账号 ID。
    算法来源：ACE_RecordHelper.cs TryParseAccountId()
      - 包内找到 0A 00 23 标记
      - packet[78] = ID 字节长度
      - packet[79 .. 79+len] = ASCII 账号字符串（纯数字，通常 18-20 位）
    返回空字符串表示未找到或解析到非法值。
    """
    MARKER = b"\x0A\x00\x23"
    if len(data) < 80:
        return ""
    if MARKER not in data:
        return ""
    id_len = data[78]
    if id_len <= 0 or id_len > 64:
        return ""
    if 79 + id_len > len(data):
        return ""
    try:
        account_id = data[79:79 + id_len].decode("ascii", errors="replace").rstrip("\x00").strip()
        # 基础合法性检查：必须是可打印 ASCII、不含空白符
        # 暗区账号通常为数字，仍兼容服务端返回的可打印混合 ID。
        if not account_id.isprintable() or " " in account_id or "\t" in account_id:
            return ""
        return account_id
    except Exception:
        return ""


# ─────────────────────────────────────────
# 上行 40 13 明文 A 类脏数据清除
# 等长清零来源标识符（;model: 之前），不改变 PLAIN 总长，无需更新 PROTO_LEN
# ─────────────────────────────────────────

_DEFAULT_DIRTY_PREFIXES: tuple[bytes, ...] = (
    b"/usr/lib/",
    b"TweakInject",
    b"auto_defence",
    b".dylib",
)
_MODEL_TAG = b";model:"


def clean_uplink_3366_plain(
    plain: bytes,
    dirty_strings: list[bytes] | None = None,
) -> tuple[bytes, list[str]]:
    """
    对 40 13 上行明文做 A 类脏数据等长清零。

    dirty_strings: 黑名单字节串列表，None 时使用内置默认前缀。

    算法：
      1. 找到含 `;model:` 的设备字符串，将 `;model:` 之前的来源标识符
         （若匹配黑名单条目）替换为同等长度的 0x00，`;model:xxx;...` 保留不动。
         例：`auto_defence_start;model:iPad13,4;...` → `\x00×18;model:iPad13,4;...`
      2. 找到独立 TLV 脏字段（无 `;model:`，紧跟在长度前缀字节后），
         将 [len_byte] 后的 len_byte 个字节全部清零。
         例：`[0C] config2.dat\x00` → `[0C] \x00×12`

    返回 (new_plain, hit_strings)：
      - new_plain: 清零后的明文（长度与原始相同）
      - hit_strings: 本次命中的黑名单字符串列表（str，可能重复）
    """
    prefixes: tuple[bytes, ...] = tuple(dirty_strings) if dirty_strings else _DEFAULT_DIRTY_PREFIXES
    buf = bytearray(plain)
    hit: list[str] = []

    # ── 第一处：含 ;model: 的字符串，只清来源标识符 ──────────────────────
    pos = 0
    while pos < len(buf):
        mi = buf.find(_MODEL_TAG, pos)
        if mi < 0:
            break
        scan_start = max(0, mi - 96)
        chunk = bytes(buf[scan_start:mi])
        for dp in prefixes:
            di = chunk.find(dp)
            if di >= 0:
                abs_start = scan_start + di
                zero_len = mi - abs_start
                if zero_len > 0:
                    buf[abs_start:mi] = b"\x00" * zero_len
                    hit.append(dp.decode("latin-1"))
                break
        pos = mi + len(_MODEL_TAG)

    # ── 第二处：独立 TLV 脏字段（无 ;model: 跟随）────────────────────────
    for dp in prefixes:
        pos = 0
        while pos < len(buf):
            di = buf.find(dp, pos)
            if di < 0:
                break
            if _MODEL_TAG in buf[di: di + 120]:
                pos = di + 1
                continue
            if di > 0:
                str_len = buf[di - 1]
                if 4 <= str_len <= 64 and di + str_len <= len(buf):
                    buf[di: di + str_len] = b"\x00" * str_len
                    hit.append(dp.decode("latin-1"))
                    pos = di + str_len
                    continue
            pos = di + 1

    return bytes(buf), hit


# ─────────────────────────────────────────
# 上行大包截断：在 ABAB 标记处截断，丢弃后续大块数据
# ─────────────────────────────────────────

_ABAB_MARK        = b"\xab\xab"
_NEST_BLK_PREFIX  = b"\x00\x00\x00\x01"   # 反作弊子包块前缀（ABAB 后 +0:+4）
_NEST_MARKER_PRE  = b"\x01\x0a\x00"       # 01 0A 00 XX 标记前3字节（ABAB 后 +6:+9）


def truncate_uplink_at_abab(plain: bytes) -> bytes | None:
    """
    截断上行明文：找到 ABAB 标记，保留 ABAB 及之前的内容，丢弃之后的压缩/Protobuf 数据块。

    同时将 bytes[4:8] 清零（大包中该字段 = 额外数据字节数；干净帧中该字段恒为 0）。

    高熵反作弊子包（enc_len=192/304/928 等，ABAB 后以 00000001+LEN+01 0A 00 XX 开头）
    不属于大数据块，跳过截断直接返回 None。

    返回：
      - 截断后的新明文（bytes），总长 = abab_pos + 2
      - None：未找到 ABAB / ABAB 已在末尾 / 高熵反作弊帧（不截断）
    """
    mi = plain.find(_ABAB_MARK)
    if mi < 0:
        return None
    end = mi + 2
    if end >= len(plain):
        return None   # ABAB 已是末尾，无需截断

    # 高熵反作弊子包排除：ABAB后 [+0:+4]=00000001 且 [+6:+9]=01 0A 00
    payload = plain[end:]
    if (len(payload) >= 9
            and payload[:4] == _NEST_BLK_PREFIX
            and payload[6:9] == _NEST_MARKER_PRE):
        return None   # 高熵反作弊帧，不截断

    buf = bytearray(plain[:end])
    if len(buf) > 8:
        buf[4:8] = b"\x00\x00\x00\x00"   # 清零额外数据长度字段
    return bytes(buf)
