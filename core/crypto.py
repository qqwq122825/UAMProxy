from __future__ import annotations

import time
import zlib

from core.config import app_config


# ─────────────────────────────────────────
# ACE 0x01 录制/重放辅助（来自 ACE_RecordHelper.cs）
# ─────────────────────────────────────────
MARKER_0A0009 = b"\x0A\x00\x09"
# 40 13 解密明文内的反作弊子包（3366 分析报告）
# 01 0A 00 09：01 包与 33 帧均有；01 0A 00 21：仅 33 帧（0x33 开头）有
MARKER_01_0A_00_09 = b"\x01\x0A\x00\x09"
MARKER_01_0A_00_21 = b"\x01\x0A\x00\x21"
# 01 0A 00 XX 之后：8 填充 + 1 序号 + 1 类型 → 高熵区起点相对 XX 后偏移 10，相对「01」起 +14
_NEST_SKIP_AFTER_01_0A = 14


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


def _ace_01_frame_meta(frame: bytes) -> dict | None:
    """解析指南定义的 01 物理分片头；字段或长度不合法时返回 None。"""
    if len(frame) < 51 or frame[:3] != b"\x01\x00\x00":
        return None
    declared_total = int.from_bytes(frame[3:5], "big")
    if declared_total != len(frame):
        return None
    is_first = frame[44] == 1
    data_start = 55 if is_first else 51
    if len(frame) < data_start:
        return None
    fragment_count = int.from_bytes(frame[38:40], "big")
    fragment_number = int.from_bytes(
        frame[49:51] if is_first else frame[45:47], "big"
    )
    data_length = int.from_bytes(
        frame[51:55] if is_first else frame[47:51], "big"
    )
    if (
        fragment_count <= 0
        or fragment_number <= 0
        or fragment_number > fragment_count
        or data_length != len(frame) - data_start
    ):
        return None
    return {
        "is_first": is_first,
        "data_start": data_start,
        "data": bytes(frame[data_start:]),
        "group": int.from_bytes(frame[36:38], "big"),
        "fragment_count": fragment_count,
        "fragment_number": fragment_number,
        "crc": bytes(frame[40:44]),
    }


def ace_corrupt_01_downlink_zip_frames(
    frames: list[bytes],
) -> tuple[list[bytes], dict]:
    """解密01/0x08记录并破坏其中ZIP本地文件头，再完整重建校验。

    0x08高熵记录与Type9使用相同的 selector/key/crc/length/ciphertext
    结构和自定义变换。这里把首个 ``PK\x03\x04`` 改成 ``PZ\x03\x04``，
    然后重算明文CRC、重新加密并重算01逻辑载荷CRC；传输结构保持有效，
    文件格式校验失败。
    """
    source = [bytes(frame) for frame in frames]
    assembled = _ace_01_reassemble_frames(source)
    base = {
        "changed": False,
        "error": "",
        "zip_offset": None,
        "filename": "",
    }
    if not assembled:
        return source, {**base, "error": "INVALID_01_FRAGMENTS"}
    ordered, logical = assembled
    marker = b"\x01\x0A\x00\x08"
    marker_start = logical.find(marker)
    if marker_start < 0:
        return ordered, {**base, "error": "TYPE8_MARKER_NOT_FOUND"}
    record_start = marker_start + 14
    if record_start + 8 > len(logical):
        return ordered, {**base, "error": "TYPE8_RECORD_HEADER_TRUNCATED"}

    selector = logical[record_start]
    key_index = logical[record_start + 1]
    stored_crc = int.from_bytes(logical[record_start + 2:record_start + 6], "big")
    cipher_len = int.from_bytes(logical[record_start + 6:record_start + 8], "big")
    cipher_start = record_start + 8
    cipher_end = cipher_start + cipher_len
    if cipher_len <= 0 or cipher_end > len(logical):
        return ordered, {**base, "error": "TYPE8_CIPHERTEXT_TRUNCATED"}

    from core.type9_crypto import KEYS, type9_transform

    if key_index >= len(KEYS):
        return ordered, {**base, "error": "TYPE8_KEY_INDEX_INVALID"}
    plaintext = type9_transform(
        logical[cipher_start:cipher_end],
        selector,
        KEYS[key_index],
        direction=0,
    )
    calculated_crc = zlib.crc32(plaintext) & 0xFFFFFFFF
    if calculated_crc != stored_crc:
        return ordered, {
            **base,
            "error": "TYPE8_PLAINTEXT_CRC_MISMATCH",
            "stored_crc32": f"{stored_crc:08X}",
            "calculated_crc32": f"{calculated_crc:08X}",
        }

    zip_offset = plaintext.find(b"PK\x03\x04")
    if zip_offset < 0:
        return ordered, {
            **base,
            "error": "ZIP_LOCAL_HEADER_NOT_FOUND",
            "selector": selector,
            "key_index": key_index,
        }

    filename = ""
    if zip_offset + 30 <= len(plaintext):
        name_len = int.from_bytes(plaintext[zip_offset + 26:zip_offset + 28], "little")
        name_start = zip_offset + 30
        name_end = name_start + name_len
        if name_len > 0 and name_end <= len(plaintext):
            filename = plaintext[name_start:name_end].decode(
                "utf-8", errors="replace"
            )

    candidate_plain = bytearray(plaintext)
    before = candidate_plain[zip_offset + 1]
    candidate_plain[zip_offset + 1] = ord("Z")
    new_crc = zlib.crc32(candidate_plain) & 0xFFFFFFFF
    candidate_cipher = type9_transform(
        bytes(candidate_plain),
        selector,
        KEYS[key_index],
        direction=1,
    )
    if len(candidate_cipher) != cipher_len:
        return ordered, {**base, "error": "TYPE8_REENCRYPT_LENGTH_MISMATCH"}

    candidate_logical = bytearray(logical)
    candidate_logical[record_start + 2:record_start + 6] = new_crc.to_bytes(4, "big")
    candidate_logical[cipher_start:cipher_end] = candidate_cipher
    output = _ace_01_shadow_frames(ordered, bytes(candidate_logical))
    if not output:
        return ordered, {**base, "error": "TYPE8_OUTER_REBUILD_FAILED"}
    return output, {
        "changed": output != ordered,
        "error": "",
        "selector": selector,
        "key_index": key_index,
        "ciphertext_length": cipher_len,
        "stored_crc32": f"{stored_crc:08X}",
        "rewritten_crc32": f"{new_crc:08X}",
        "zip_offset": zip_offset,
        "filename": filename,
        "before": before,
        "after": ord("Z"),
        "plaintext_length": len(plaintext),
    }


def ace_mutate_01_downlink_mrpcs_frames(
    frames: list[bytes],
) -> tuple[list[bytes], dict]:
    """混淆01下行 0x08/0x09 加密明文中的 ``mrpcs*.data`` 文件名。

    仅把命中文件名中 ``.data`` 的点号等长改成 ``1``，例如
    ``mrpcs_i_c.data`` → ``mrpcs_i_c1data``。随后重算内层明文 CRC、
    重新加密并重建01外层 CRC；物理分片数量和每片长度保持不变。
    """
    import re

    source = [bytes(frame) for frame in frames]
    assembled = _ace_01_reassemble_frames(source)
    base = {
        "changed": False,
        "error": "",
        "match_count": 0,
        "matches": [],
        "record_count": 0,
    }
    if not assembled:
        return source, {**base, "error": "INVALID_01_FRAGMENTS"}
    ordered, logical = assembled

    from core.type9_crypto import KEYS, type9_transform

    def _find_downlink_records(data: bytes) -> list[dict]:
        """同时识别01/0x08文件记录和01/0x09 Type9记录。"""
        found: list[dict] = []
        for marker_type in (0x08, 0x09):
            marker = b"\x01\x0A\x00" + bytes([marker_type])
            cursor = 0
            while True:
                marker_offset = data.find(marker, cursor)
                if marker_offset < 0:
                    break
                header = marker_offset + 14
                if header + 8 <= len(data):
                    selector = data[header]
                    key_index = data[header + 1]
                    stored_crc = int.from_bytes(
                        data[header + 2:header + 6], "big"
                    )
                    ciphertext_length = int.from_bytes(
                        data[header + 6:header + 8], "big"
                    )
                    ciphertext_offset = header + 8
                    ciphertext_end = ciphertext_offset + ciphertext_length
                    if (
                        selector <= 2
                        and key_index < len(KEYS)
                        and ciphertext_length > 0
                        and ciphertext_end <= len(data)
                    ):
                        found.append(
                            {
                                "marker_type": f"{marker_type:02X}",
                                "marker_offset": marker_offset,
                                "selector": selector,
                                "key_index": key_index,
                                "stored_crc32": stored_crc,
                                "ciphertext_offset": ciphertext_offset,
                                "ciphertext_length": ciphertext_length,
                                "ciphertext": data[
                                    ciphertext_offset:ciphertext_end
                                ],
                            }
                        )
                cursor = marker_offset + 1
        return sorted(found, key=lambda item: item["marker_offset"])

    records = _find_downlink_records(logical)
    if not records:
        return ordered, {**base, "error": "TYPE9_RECORD_NOT_FOUND"}

    candidate_logical = bytearray(logical)
    match_rows: list[dict] = []
    changed_records = 0
    # 文件名主体按观测样本限定为 ASCII 字母、数字和下划线，避免跨字段误匹配。
    filename_pattern = re.compile(rb"mrpcs[0-9a-z_]*\.data", re.IGNORECASE)

    for record_index, record in enumerate(records):
        selector = int(record["selector"])
        key_index = int(record["key_index"])
        plaintext = type9_transform(
            record["ciphertext"], selector, KEYS[key_index], direction=0
        )
        calculated_crc = zlib.crc32(plaintext) & 0xFFFFFFFF
        if calculated_crc != int(record["stored_crc32"]):
            continue

        candidate_plain = bytearray(plaintext)
        record_matches = list(filename_pattern.finditer(plaintext))
        if not record_matches:
            continue
        for match in record_matches:
            dot_offset = match.end() - len(b".data")
            before = bytes(candidate_plain[match.start():match.end()])
            candidate_plain[dot_offset] = ord("1")
            after = bytes(candidate_plain[match.start():match.end()])
            match_rows.append(
                {
                    "record_index": record_index,
                    "marker_type": record["marker_type"],
                    "plaintext_offset": match.start(),
                    "before": before.decode("ascii", errors="replace"),
                    "after": after.decode("ascii", errors="replace"),
                }
            )

        candidate_cipher = type9_transform(
            bytes(candidate_plain), selector, KEYS[key_index], direction=1
        )
        if len(candidate_cipher) != int(record["ciphertext_length"]):
            return ordered, {
                **base,
                "error": "TYPE9_REENCRYPT_LENGTH_MISMATCH",
                "matches": match_rows,
                "match_count": len(match_rows),
            }
        marker_offset = int(record["marker_offset"])
        ciphertext_offset = int(record["ciphertext_offset"])
        ciphertext_end = ciphertext_offset + int(record["ciphertext_length"])
        new_crc = zlib.crc32(candidate_plain) & 0xFFFFFFFF
        candidate_logical[marker_offset + 16:marker_offset + 20] = (
            new_crc.to_bytes(4, "big")
        )
        candidate_logical[ciphertext_offset:ciphertext_end] = candidate_cipher
        changed_records += 1

    if not match_rows:
        return ordered, {
            **base,
            "error": "MRPCS_DATA_NOT_FOUND",
            "record_count": len(records),
        }

    output = _ace_01_shadow_frames(ordered, bytes(candidate_logical))
    if not output:
        return ordered, {
            **base,
            "error": "TYPE9_OUTER_REBUILD_FAILED",
            "matches": match_rows,
            "match_count": len(match_rows),
            "record_count": len(records),
        }
    output_validation = _ace_01_verify_frames(output)
    if not output_validation.get("ok"):
        return ordered, {
            **base,
            "error": "OUTPUT_01_VALIDATION_FAILED",
            "validation_errors": output_validation.get("errors", []),
            "matches": match_rows,
            "match_count": len(match_rows),
            "record_count": len(records),
        }

    # 发送前再次解密最终密文，复核每条 0x08/0x09 内层明文 CRC。
    output_assembled = _ace_01_reassemble_frames(output)
    output_inner_crc_ok = bool(output_assembled)
    if output_assembled:
        output_records = _find_downlink_records(output_assembled[1])
        output_inner_crc_ok = bool(output_records)
        for output_record in output_records:
            output_plain = type9_transform(
                output_record["ciphertext"],
                output_record["selector"],
                KEYS[output_record["key_index"]],
                direction=0,
            )
            if (
                zlib.crc32(output_plain) & 0xFFFFFFFF
            ) != int(output_record["stored_crc32"]):
                output_inner_crc_ok = False
                break
    if not output_inner_crc_ok:
        return ordered, {
            **base,
            "error": "OUTPUT_TYPE9_CRC_VALIDATION_FAILED",
            "matches": match_rows,
            "match_count": len(match_rows),
            "record_count": len(records),
        }
    return output, {
        "changed": output != ordered,
        "error": "",
        "match_count": len(match_rows),
        "matches": match_rows,
        "record_count": len(records),
        "record_types": sorted({record["marker_type"] for record in records}),
        "changed_record_count": changed_records,
        "validation_ok": True,
        "outer_crc32": output_validation.get("crc_hex", ""),
        "calculated_outer_crc32": output_validation.get(
            "calculated_crc_hex", ""
        ),
        "inner_crc_ok": True,
    }


def _ace_01_fragment_key(frame: bytes) -> tuple[int, int, bytes] | None:
    """返回 (包组号, 分片总数, CRC32)，供录制/重放缓冲聚合同一逻辑包。"""
    meta = _ace_01_frame_meta(frame)
    if not meta:
        return None
    return meta["group"], meta["fragment_count"], meta["crc"]


def _ace_01_reassemble_frames(
    frames: list[bytes],
) -> tuple[list[bytes], bytes] | None:
    """校验、排序并重组一个完整 01 逻辑包。"""
    parsed: list[tuple[int, bytes, dict]] = []
    for frame in frames:
        meta = _ace_01_frame_meta(frame)
        if not meta:
            return None
        parsed.append((meta["fragment_number"], frame, meta))
    if not parsed:
        return None
    first_meta = parsed[0][2]
    group_key = (
        first_meta["group"],
        first_meta["fragment_count"],
        first_meta["crc"],
    )
    for _, _, meta in parsed:
        if (
            meta["group"],
            meta["fragment_count"],
            meta["crc"],
        ) != group_key:
            return None
    parsed.sort(key=lambda x: x[0])
    expected_count = first_meta["fragment_count"]
    if [x[0] for x in parsed] != list(range(1, expected_count + 1)):
        return None
    if not parsed[0][2]["is_first"]:
        return None
    logical = b"".join(x[2]["data"] for x in parsed)
    return [x[1] for x in parsed], logical


def _ace_01_shadow_frames(
    live_frames: list[bytes], candidate_logical: bytes
) -> list[bytes]:
    """把等长影子 payload 回填到实时物理分片，并重算外层 CRC。

    只用于旁路候选验证；物理头、分片数量和每片长度全部继承实时包。
    """
    rebuilt = _ace_01_reassemble_frames(live_frames)
    if not rebuilt:
        return []
    ordered, live_logical = rebuilt
    if len(candidate_logical) != len(live_logical):
        return []
    crc = (zlib.crc32(candidate_logical) & 0xFFFFFFFF).to_bytes(4, "big")
    output: list[bytes] = []
    logical_pos = 0
    for live_frame in ordered:
        meta = _ace_01_frame_meta(live_frame)
        if not meta:
            return []
        data_len = len(meta["data"])
        frame = bytearray(live_frame)
        frame[meta["data_start"]:] = candidate_logical[
            logical_pos:logical_pos + data_len
        ]
        frame[40:44] = crc
        logical_pos += data_len
        output.append(bytes(frame))
    return output if logical_pos == len(candidate_logical) else []


def _ace_01_report_index_offset(logical_payload: bytes) -> int | None:
    """返回 01 0A 00 23 后 BE32 报告序号在逻辑 payload 中的偏移。"""
    pos = logical_payload.find(b"\x01\x0A\x00\x23")
    if pos < 0 or pos + 8 > len(logical_payload):
        return None
    return pos + 4


def _ace_01_report_index(logical_payload: bytes) -> int | None:
    """读取 01 0A 00 23 后的 BE32 实时报告序号（样本中为 4/5/6）。"""
    offset = _ace_01_report_index_offset(logical_payload)
    if offset is None:
        return None
    return int.from_bytes(logical_payload[offset:offset + 4], "big")


def _ace_01_virtual_packet(frames: list[bytes]) -> bytes | None:
    """把一个物理帧组转换成仅供字段解析的首片头 + 完整逻辑 payload。"""
    rebuilt = _ace_01_reassemble_frames(frames)
    if not rebuilt:
        return None
    ordered, logical = rebuilt
    virtual = bytearray(ordered[0][:55])
    virtual += logical
    if len(virtual) <= 0xFFFF:
        virtual[3:5] = len(virtual).to_bytes(2, "big")
    virtual[38:40] = (1).to_bytes(2, "big")
    virtual[44] = 1
    virtual[49:51] = (1).to_bytes(2, "big")
    virtual[51:55] = len(logical).to_bytes(4, "big")
    return bytes(virtual)


def _ace_01_verify_frames(
    frames: list[bytes],
    *,
    expected_game_id: str = "",
) -> dict:
    """
    校验最终准备发送的完整 01 帧组。

    每包都执行；调用方仅需决定前多少包输出详细日志。
    """
    errors: list[str] = []
    metas: list[dict] = []
    for index, frame in enumerate(frames, 1):
        if len(frame) < 5:
            errors.append(f"片{index}:长度小于5")
            continue
        declared = int.from_bytes(frame[3:5], "big")
        if declared != len(frame):
            errors.append(f"片{index}:总长度{declared}!={len(frame)}")
        meta = _ace_01_frame_meta(frame)
        if not meta:
            errors.append(f"片{index}:分片头或数据长度无效")
        else:
            metas.append(meta)

    assembled = _ace_01_reassemble_frames(frames) if len(metas) == len(frames) else None
    logical = b""
    account_id = ""
    report_index = None
    crc_hex = ""
    calculated_crc_hex = ""
    if not assembled:
        errors.append("分片数量/编号/包组/CRC不一致")
    else:
        ordered, logical = assembled
        declared_crc = int.from_bytes(ordered[0][40:44], "big")
        calculated_crc = zlib.crc32(logical) & 0xFFFFFFFF
        crc_hex = f"{declared_crc:08X}"
        calculated_crc_hex = f"{calculated_crc:08X}"
        if declared_crc != calculated_crc:
            errors.append(f"CRC不符:{crc_hex}!={calculated_crc_hex}")
        virtual = _ace_01_virtual_packet(ordered)
        if virtual:
            account_id = _parse_ace_account_id(virtual)
        report_index = _ace_01_report_index(logical)

    expected = str(expected_game_id or "").strip()
    if expected:
        if not account_id:
            errors.append("未解析到游戏ID")
        elif account_id != expected:
            errors.append(f"游戏ID不符:{account_id}!={expected}")

    return {
        "ok": not errors,
        "errors": errors,
        "frame_count": len(frames),
        "logical_payload_len": len(logical),
        "crc_hex": crc_hex,
        "calculated_crc_hex": calculated_crc_hex,
        "account_id": account_id,
        "report_index": report_index,
    }


def _ace_index_of(data: bytes, pattern: bytes) -> int:
    for i in range(len(data) - len(pattern) + 1):
        if data[i : i + len(pattern)] == pattern:
            return i
    return -1


def ace_handshake_product_hex(sub: bytes) -> str | None:
    """
    01 通道 42 字节握手包：a[16..17] 大端为产品/游戏 ID（与 01_PACKET_LAYOUT 中长包一致）。
    例：09 4e → 返回 \"094e\"（小写 4 位 hex，与 暗区产品 ID / get_game 一致）。
    """
    if len(sub) != 42 or sub[0] != 0x01:
        return None
    if len(sub) < 18:
        return None
    return f"{int.from_bytes(sub[16:18], 'big'):04x}"


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


def _ace_find_encrypted_record(
    packet: bytes,
) -> tuple[int, int, int, str] | None:
    """
    按 09_01 指南解析 01 0A 00 09 内的完整加密记录。

    布局：
      01 0A 00 09
      + 10B 固定前导
      + selector(1) + key_index(1) + plain_crc32(4)
      + ciphertext_len(2, BE) + ciphertext

    返回 (record_start, record_end, marker_start, kind)。record_end 不包含在内。
    会遍历所有完整 marker，并以密文长度字段校验边界，避免高熵区中的偶然命中。
    """
    pos = 0
    while True:
        marker_start = packet.find(MARKER_01_0A_00_09, pos)
        if marker_start < 0:
            return None
        record_start = marker_start + _NEST_SKIP_AFTER_01_0A
        cipher_len_offset = record_start + 6
        cipher_start = record_start + 8
        if cipher_start <= len(packet):
            cipher_len = int.from_bytes(
                packet[cipher_len_offset:cipher_start], "big"
            )
            record_end = cipher_start + cipher_len
            if cipher_len > 0 and record_end <= len(packet):
                return record_start, record_end, marker_start, "01_0a_09_record"
        pos = marker_start + 1


def _ace_normalize_pool_record(item: dict) -> bytes:
    """
    返回池项中自洽的 selector..ciphertext 记录。

    新格式直接保存 encrypted_record；旧 v4 文件的 payload 可能从 selector 一直
    保存到物理帧尾，这里依据其内部 ciphertext_len 截断，兼容历史录制。
    """
    record = item.get("encrypted_record") or item.get("payload") or b""
    record = bytes(record)
    if len(record) < 8:
        return b""
    cipher_len = int.from_bytes(record[6:8], "big")
    record_end = 8 + cipher_len
    if cipher_len <= 0 or record_end > len(record):
        return b""
    return record[:record_end]


def _ace_try_extract(packet: bytes) -> dict | None:
    """
    从 0x01 包提取 0A 00 09 段：payload、CRC、routing、account_id。
    01 包仅含 01 0A 00 09 / 0A 00 09，不含 01 0A 00 21。
    """
    if len(packet) < 102:
        return None
    record = _ace_find_encrypted_record(packet)
    if record is None:
        return None
    payload_start, payload_end, raw_start, kind = record
    payload = bytes(packet[payload_start:payload_end])
    crc = bytes(packet[40:44])
    routing = bytes([packet[47]])
    account_id = _parse_ace_account_id(packet)
    raw_packet = bytes(packet[raw_start:payload_end])
    frame_meta = _ace_01_frame_meta(packet)
    logical = packet[55:] if frame_meta and frame_meta["is_first"] else b""
    return {
        "payload": payload,
        "encrypted_record": payload,
        "crc": crc,
        "routing": routing,
        "account_id": account_id,
        "source": "01",
        "anchor_kind": kind,
        "raw_packet": raw_packet,
        "template_frames": [bytes(packet)] if frame_meta and frame_meta["fragment_count"] == 1 else [],
        "report_index": _ace_01_report_index(logical) if logical else None,
    }


def _ace_try_extract_frames(frames: list[bytes]) -> dict | None:
    """从一个已收齐的单片/多片逻辑包提取 01 加密记录。"""
    rebuilt = _ace_01_reassemble_frames(frames)
    if not rebuilt:
        return None
    ordered, logical = rebuilt
    virtual = _ace_01_virtual_packet(ordered)
    if not virtual:
        return None
    item = _ace_try_extract(virtual)
    if item:
        item["template_frames"] = [bytes(frame) for frame in ordered]
        item["report_index"] = _ace_01_report_index(logical)
        item["crc"] = bytes(ordered[0][40:44])
        item["routing"] = bytes([ordered[0][47]])
        # 录制时分散建立叶子缓存，避免重放首包集中解密全池。
        try:
            from core.type9_shadow import template_leaf_rows
            item["_type9_shadow_leaf_cache"] = template_leaf_rows(
                logical, pool_idx=-1
            )
        except (IndexError, KeyError, TypeError, ValueError):
            pass
    return item


def _ace_apply_live_header_to_template(
    live_frames: list[bytes],
    template_frames: list[bytes],
) -> list[bytes]:
    """
    完整模板模式：以干净模板为主体，只继承实时连接的外层会话字段和
    01 0A 00 23 报告序号。报告序号属于 CRC 覆盖的逻辑 payload，覆盖后
    统一重算 CRC 并写入所有模板分片。
    """
    live_result = _ace_01_reassemble_frames(live_frames)
    template_result = _ace_01_reassemble_frames(template_frames)
    if not live_result or not template_result:
        return []
    live_ordered, live_logical = live_result
    clean_ordered, clean_logical_raw = template_result
    live_report_offset = _ace_01_report_index_offset(live_logical)
    clean_report_offset = _ace_01_report_index_offset(clean_logical_raw)
    if live_report_offset is None or clean_report_offset is None:
        return []

    clean_logical = bytearray(clean_logical_raw)
    clean_logical[clean_report_offset:clean_report_offset + 4] = (
        live_logical[live_report_offset:live_report_offset + 4]
    )
    rebuilt_crc = (zlib.crc32(clean_logical) & 0xFFFFFFFF).to_bytes(4, "big")

    live_first = live_ordered[0]
    live_sequence = int.from_bytes(live_first[8:10], "big")
    live_group = bytes(live_first[36:38])
    live_tag = live_first[47]

    output: list[bytes] = []
    logical_pos = 0
    for index, clean_frame in enumerate(clean_ordered):
        frame = bytearray(clean_frame)
        meta = _ace_01_frame_meta(clean_frame)
        if not meta:
            return []
        # 蓝色继承区严格按来源图覆盖：
        #   0x06～0x09：会话/帧序号；
        #   0x12～0x25：会话字段及包组次数。
        # 0x05、0x0A～0x11 等绿色字段继续使用干净模板。
        frame[6:10] = live_first[6:10]
        frame[18:38] = live_first[18:38]
        # 模板若有多个分片，基于实时首片序号连续分配。
        frame[8:10] = ((live_sequence + index) & 0xFFFF).to_bytes(2, "big")
        # 0x24～0x25：当前实时逻辑包的包组/递增次数。
        frame[36:38] = live_group
        # payload 内报告序号已继承实时值，所有分片写入重算后的统一 CRC。
        frame[40:44] = rebuilt_crc
        # 0x2F 在首片中是会话标签；后续片这里属于数据长度，不覆盖。
        if index == 0:
            frame[47] = live_tag
        data_len = len(meta["data"])
        frame[meta["data_start"]:] = clean_logical[
            logical_pos:logical_pos + data_len
        ]
        logical_pos += data_len
        output.append(bytes(frame))
    if logical_pos != len(clean_logical):
        return []
    return output


def _ace_try_replay_template(
    live_frames: list[bytes],
    pool: list[dict],
    pool_index: list,
    *,
    expected_game_id: str,
    allow_cross_account: bool = False,
    donor_game_id: str = "",
    device_mode: str = "",
    special_rule_store=None,
    on_log=None,
    session_elapsed_seconds: float | None = None,
    session_unix_time: float | None = None,
) -> tuple[list[bytes], bool]:
    """
    Type9 叶子级录制主体替换：
      - 1D/52 等非09包保持原样透传；
      - 09包在线解密并使用全录制池构造叶子候选；
      - 已知规则字段按 clean/inherit 处理；
      - 继承模式保留Live设备；替换模式锁定一个录制会话并统一录制设备画像；
      - tfp_called优先使用正常录制叶子，无模板时按确认编码删除完整字段；
      - 机械回验通过且候选字节发生变化时发送，无候选或回验失败时发送实时包。
    """
    from core.type9_online import decode_type9_payload, decide_observe_only
    from core.type9_shadow import (
        DEVICE_MODE_REPLACE_RECORDED,
        build_shadow_logical,
        extract_device_context_from_logical,
        extract_device_context_from_rows,
        merge_device_context,
        normalize_device_mode,
        template_leaf_rows,
    )
    from core.type9_v128_replenish import strict_device_gate

    device_mode = normalize_device_mode(
        device_mode or app_config.get("type9_device_mode", "inherit_live")
    )

    original_frames = [bytes(frame) for frame in live_frames]
    v128_enabled = bool(
        app_config.get("replenish_01_mode")
        and session_elapsed_seconds is not None
    )
    replay_context_state: dict = (
        pool_index[2]
        if len(pool_index) >= 3 and isinstance(pool_index[2], dict)
        else {}
    )
    sequence_safe_state = replay_context_state.get(
        "sequence_safe_drop"
    ) or {"leaf_offset": 0, "last_output_leaf_sequence": 0}
    v128_model_revision = None
    v128_state = None
    if v128_enabled:
        from core.type9_v128_replenish import MODEL_REVISION, ensure_v128_state

        while len(pool_index) < 3:
            pool_index.append({})
        if not isinstance(pool_index[2], dict):
            pool_index[2] = {}
        replay_context_state = pool_index[2]
        v128_model_revision = MODEL_REVISION
        v128_state = ensure_v128_state(
            replay_context_state.setdefault("v128_replenish", {})
        )
        sequence_safe_state = v128_state
    live_result = _ace_01_reassemble_frames(live_frames)
    v130_reconnect_resolution: dict = {}
    if (
        live_result
        and v128_state is not None
        and replay_context_state.get("v130_pending_reconnect")
    ):
        from core.replay_session_v130 import live_leaf_sequence_decision

        pending_reconnect = dict(
            replay_context_state.get("v130_pending_reconnect") or {}
        )
        from core.type9_shadow import decode_material

        pending_material = decode_material(live_result[1])
        pending_sequences = [
            int(leaf.get("record_sequence") or 0)
            for leaf in (pending_material.get("leaves") or [])
        ] if pending_material.get("ok") else []
        reconnect_decision, reconnect_detail = live_leaf_sequence_decision(
            pending_reconnect.get("previous_last_live_leaf_sequence"),
            min(pending_sequences) if pending_sequences else None,
        )
        if reconnect_decision != "PENDING":
            confirmed = reconnect_decision.startswith("CONFIRMED_")
            fresh_started = float(
                pending_reconnect.get("fresh_started_monotonic")
                or time.monotonic()
            )
            if not confirmed:
                # The 42B token was only a candidate.  A reset/backward native
                # report establishes a fresh game process and drops every old
                # semantic/device/template-consumption snapshot before this
                # report is rebuilt.
                replay_context_state.clear()
                replay_context_state["device_mode"] = device_mode
                replay_context_state["v128_replenish"] = ensure_v128_state({})
                v128_state = replay_context_state["v128_replenish"]
                sequence_safe_state = v128_state
                session_elapsed_seconds = max(
                    0.0, time.monotonic() - fresh_started
                )
            replay_context_state.pop("v130_pending_reconnect", None)
            v130_reconnect_resolution = {
                "decision": reconnect_decision,
                "continued": confirmed,
                "classification": (
                    "NETWORK_RECONNECT"
                    if confirmed
                    else "GAME_REOPEN_OR_NEW_SESSION"
                ),
                "started_monotonic": (
                    None if confirmed else fresh_started
                ),
                **reconnect_detail,
            }
            replay_context_state["v130_reconnect_result"] = dict(
                v130_reconnect_resolution
            )

    v128_offsets_before = {
        key: int((v128_state or {}).get(key) or 0)
        for key in ("report_offset", "leaf_offset", "frame_offset", "group_offset")
    }
    v128_sequence_offsets_applied = bool(
        v128_state is not None
        and any(
            int(v128_state.get(key) or 0)
            for key in ("report_offset", "leaf_offset", "frame_offset", "group_offset")
        )
    )

    v128_live_meta: dict = {}
    if live_result and v128_state is not None:
        prepared_frames, v128_live_meta = _v128_prepare_live_frames(
            live_result[0],
            v128_state,
        )
        prepared_result = _ace_01_reassemble_frames(prepared_frames)
        if prepared_result:
            live_frames = prepared_frames
            live_result = prepared_result
    elif live_result and int(sequence_safe_state.get("leaf_offset") or 0):
        prepared_frames, v128_live_meta = _sequence_safe_prepare_live_frames(
            live_result[0],
            sequence_safe_state,
        )
        prepared_result = _ace_01_reassemble_frames(prepared_frames)
        if prepared_result:
            live_frames = prepared_frames
            live_result = prepared_result
    sequence_safe_offset_applied = bool(
        int(sequence_safe_state.get("leaf_offset") or 0)
    )
    cursor_before = int(pool_index[0] or 0)
    # 01 0A 00 1D / 52 等控制、状态包保持原样透传，不消耗09观察游标。
    if live_result and MARKER_01_0A_00_09 not in live_result[1]:
        ordered, logical = live_result
        marker_types = sorted({
            f"{logical[i + 3]:02X}"
            for i in range(len(logical) - 3)
            if logical[i:i + 3] == b"\x01\x0A\x00"
        })
        detail = {
            "decision": "PASS_NON_TARGET",
            "reason": "NO_01_0A_00_09",
            "replace_mode": "passthrough_non_09",
            "validation_ok": True,
            "validation_errors": [],
            "account_id": _parse_ace_account_id(
                _ace_01_virtual_packet(ordered) or b""
            ),
            "report_index": _ace_01_report_index(logical),
            "marker_types": marker_types,
            "pool_total": len(pool),
            "cursor_before": cursor_before,
            "cursor_after": cursor_before,
            "pool_idx": None,
            "live_frames": [bytes(frame) for frame in ordered],
            "input_frames": original_frames,
            "template_frames": [],
            "output_frames": [bytes(frame) for frame in ordered],
            "v128_replenish": {
                "enabled": bool(v128_enabled),
                "model_revision": v128_model_revision,
                "elapsed_ms": (
                    int(float(session_elapsed_seconds or 0.0) * 1000)
                    if v128_enabled else None
                ),
                "offsets_before": v128_offsets_before,
                "offsets_after": {
                    key: int((v128_state or {}).get(key) or 0)
                    for key in v128_offsets_before
                },
                "groups": [],
                "leaf_count": 0,
                "frame_count": 0,
            },
        }
        if on_log:
            on_log(detail)
        return detail["output_frames"], detail["output_frames"] != original_frames

    if not v128_enabled and live_result:
        while len(pool_index) < 3:
            pool_index.append({})
        if not isinstance(pool_index[2], dict):
            pool_index[2] = {}
        replay_context_state = pool_index[2]
        sequence_safe_state = replay_context_state.setdefault(
            "sequence_safe_drop",
            {"leaf_offset": 0, "last_output_leaf_sequence": 0},
        )

    if not live_result:
        detail = {
            "decision": "PASS_LIVE",
            "reason": "LIVE_FRAME_REASSEMBLY_FAILED",
            "replace_mode": "type9_semantic_gate_pass_live",
            "validation_ok": True,
            "validation_errors": ["实时01帧组重组或外层CRC检查失败，保持原始字节透传"],
            "account_id": "",
            "report_index": None,
            "pool_total": len(pool),
            "cursor_before": cursor_before,
            "cursor_after": cursor_before,
            "pool_idx": None,
            "live_frames": original_frames,
            "template_frames": [],
            "output_frames": original_frames,
            "final_equals_live": True,
            "online_decode": {"live": None, "template": None, "facts": {}},
        }
        if on_log:
            on_log(detail)
        return original_frames, False

    live_ordered, live_logical = live_result
    live_virtual = _ace_01_virtual_packet(live_ordered)
    live_game_id = _parse_ace_account_id(live_virtual) if live_virtual else ""
    live_report_index = _ace_01_report_index(live_logical)
    expected = str(expected_game_id or "").strip()
    if not expected:
        expected = live_game_id

    # 目标Type9路径保持旧调用的向后兼容；非09透传不扩展游标。
    if not v128_enabled:
        while len(pool_index) < 3:
            pool_index.append({})
        if not isinstance(pool_index[2], dict):
            pool_index[2] = {}
        replay_context_state = pool_index[2]
    pinned_device_mode = str(replay_context_state.get("device_mode") or "")
    if pinned_device_mode:
        device_mode = normalize_device_mode(pinned_device_mode)
    else:
        replay_context_state["device_mode"] = device_mode
    live_device_context = merge_device_context(
        replay_context_state.get("live_device_context"),
        extract_device_context_from_logical(live_logical),
    )
    replay_context_state["live_device_context"] = live_device_context

    start = cursor_before
    selected = None
    selected_idx = -1
    template_validation = None
    template_frames: list[bytes] = []
    for offset in range(len(pool)):
        idx = (start + offset) % len(pool)
        item = pool[idx]
        candidate_frames = [
            bytes(frame) for frame in (item.get("template_frames") or [])
        ]
        if not candidate_frames:
            continue
        item_game_id = str(item.get("account_id") or "").strip()
        item_scope = str(item.get("template_scope") or "player")
        is_tiered_item = "template_scope" in item
        if is_tiered_item:
            if (
                item_scope != "official"
                and expected
                and item_game_id != expected
                and not (
                    allow_cross_account
                    and bool(item.get("device_cross_account_candidate"))
                )
            ):
                continue
        else:
            if (
                allow_cross_account
                and donor_game_id
                and item_game_id != donor_game_id
            ):
                continue
            if not allow_cross_account and expected and item_game_id != expected:
                continue
        checked = _ace_01_verify_frames(
            candidate_frames,
            expected_game_id=("" if allow_cross_account else expected),
        )
        if not checked["ok"]:
            continue
        selected = item
        selected_idx = idx
        template_frames = candidate_frames
        template_validation = checked
        # 该游标仅用于复现“旧算法第N条会选谁”的分析对照；
        # 真实输出由下方的叶子候选机械回验门控决定。
        pool_index[0] = start + offset + 1
        break

    live_decoded = decode_type9_payload(live_logical)
    template_decoded = None
    if template_frames:
        template_result = _ace_01_reassemble_frames(template_frames)
        if template_result:
            template_decoded = decode_type9_payload(template_result[1])
    reason, decision_facts = decide_observe_only(
        live_decoded,
        template_decoded,
        live_length=sum(map(len, live_ordered)),
        template_length=(sum(map(len, template_frames)) if template_frames else None),
    )

    # 全录制池叶子索引：每个模板只解密一次，后续实时包复用缓存。
    # 索引匹配不依赖 TCP 连接或外层 report_index，因此网络换 IP
    # 不会改变影子候选的模板集合。
    shadow_template_rows: list[dict] = []
    shadow_template_errors = 0
    for shadow_pool_idx, shadow_item in enumerate(pool):
        if not isinstance(shadow_item, dict):
            continue
        item_game_id = str(shadow_item.get("account_id") or "").strip()
        item_scope = str(shadow_item.get("template_scope") or "player")
        is_tiered_item = "template_scope" in shadow_item
        if is_tiered_item:
            if (
                item_scope != "official"
                and expected
                and item_game_id != expected
                and not (
                    allow_cross_account
                    and bool(shadow_item.get("device_cross_account_candidate"))
                )
            ):
                continue
        else:
            if (
                allow_cross_account
                and donor_game_id
                and item_game_id != donor_game_id
            ):
                continue
            if not allow_cross_account and expected and item_game_id != expected:
                continue
        cached = shadow_item.get("_type9_shadow_leaf_cache")
        if not isinstance(cached, dict):
            candidate_frames = [
                bytes(frame)
                for frame in (shadow_item.get("template_frames") or [])
            ]
            candidate_result = _ace_01_reassemble_frames(candidate_frames)
            if candidate_result:
                cached = template_leaf_rows(
                    candidate_result[1], pool_idx=shadow_pool_idx
                )
            else:
                cached = {
                    "ok": False,
                    "errors": ["录制模板物理分片重组失败"],
                    "rows": [],
                }
            shadow_item["_type9_shadow_leaf_cache"] = cached
        if cached.get("ok"):
            for cached_row in cached.get("rows") or []:
                indexed_row = dict(cached_row)
                indexed_row["pool_idx"] = shadow_pool_idx
                indexed_row["donor_game_id"] = item_game_id
                indexed_row["template_scope"] = item_scope
                indexed_row["source_priority"] = int(
                    shadow_item.get("source_priority", 0)
                )
                indexed_row["template_batch_id"] = str(
                    shadow_item.get("template_batch_id") or ""
                )
                indexed_row["template_session_id"] = str(
                    shadow_item.get("template_session_id")
                    or shadow_item.get("template_batch_id")
                    or f"legacy:{item_game_id}:{item_scope}"
                )
                indexed_row["report_index"] = shadow_item.get("report_index")
                indexed_row["recorded_at"] = shadow_item.get("recorded_at")
                indexed_row["recorded_elapsed_seconds"] = shadow_item.get(
                    "recorded_elapsed_seconds"
                )
                indexed_row["device_cross_account_candidate"] = bool(
                    shadow_item.get("device_cross_account_candidate")
                )
                shadow_template_rows.append(indexed_row)
        else:
            shadow_template_errors += 1

    template_rows_by_session: dict[str, list[dict]] = {}
    for row in shadow_template_rows:
        template_rows_by_session.setdefault(
            str(row.get("template_session_id") or "legacy"), []
        ).append(row)
    template_context_by_session = {
        session_id: extract_device_context_from_rows(rows)
        for session_id, rows in template_rows_by_session.items()
    }
    for row in shadow_template_rows:
        row["device_context"] = dict(
            template_context_by_session.get(
                str(row.get("template_session_id") or "legacy"), {}
            )
        )
    replay_context_state["template_device_contexts"] = {
        key: dict(value)
        for key, value in template_context_by_session.items()
    }

    # v1.128.9 cross-account player recordings are candidates until Live has
    # supplied the exact model/system/IDFV tuple.  Pin exactly one matching
    # recording session; official rows remain available as a lower tier.
    device_candidate_session_ids = {
        str(row.get("template_session_id") or "legacy")
        for row in shadow_template_rows
        if row.get("device_cross_account_candidate")
    }
    if device_candidate_session_ids:
        pinned_device_session = str(
            replay_context_state.get("v129_device_template_session_id") or ""
        )
        compatible_device_sessions = [
            session_id
            for session_id in device_candidate_session_ids
            if strict_device_gate(
                live_device_context,
                template_context_by_session.get(session_id),
            )[0] == "MATCH"
        ]
        if pinned_device_session not in compatible_device_sessions:
            pinned_device_session = max(
                compatible_device_sessions,
                key=lambda session_id: len(
                    template_rows_by_session.get(session_id) or []
                ),
                default="",
            )
        replay_context_state["v129_device_template_session_id"] = (
            pinned_device_session
        )
        replay_context_state["v129_device_gate"] = (
            "MATCH" if pinned_device_session else "PENDING_OR_MISMATCH"
        )
        shadow_template_rows = [
            row
            for row in shadow_template_rows
            if str(row.get("template_scope") or "player") == "official"
            or (
                pinned_device_session
                and str(row.get("template_session_id") or "legacy")
                == pinned_device_session
            )
            or (
                not pinned_device_session
                and not row.get("device_cross_account_candidate")
            )
        ]

    recorded_template_session_id = ""
    recorded_device_context: dict[str, str] = {}
    if device_mode == DEVICE_MODE_REPLACE_RECORDED and shadow_template_rows:
        pinned = str(
            replay_context_state.get("recorded_template_session_id") or ""
        )
        if pinned not in template_context_by_session:
            ordered_session_ids = list(dict.fromkeys(
                str(row.get("template_session_id") or "legacy")
                for row in shadow_template_rows
            ))
            pinned = next(
                (
                    session_id
                    for session_id in ordered_session_ids
                    if template_context_by_session.get(session_id, {}).get("model")
                ),
                ordered_session_ids[0] if ordered_session_ids else "",
            )
            replay_context_state["recorded_template_session_id"] = pinned
        recorded_template_session_id = pinned
        recorded_device_context = dict(
            template_context_by_session.get(pinned) or {}
        )
        # 整条连接固定使用一个录制会话，避免同一报告从多个设备/批次拼模板。
        shadow_template_rows = [
            row
            for row in shadow_template_rows
            if str(row.get("template_session_id") or "legacy") == pinned
        ]
        replay_context_state["recorded_device_context"] = dict(
            recorded_device_context
        )

    replenish_01 = bool(app_config.get("replenish_01_mode"))
    insert_state = (
        replay_context_state.setdefault("stable_80xx_insert", {})
        if replenish_01 and not v128_enabled
        else None
    )
    shadow_result = build_shadow_logical(
        live_logical,
        shadow_template_rows,
        cross_account=allow_cross_account,
        live_game_id=expected or live_game_id,
        donor_game_id=donor_game_id,
        prune_unmatched=(
            app_config.get("v118_unknown_leaf_policy", "pass_live") == "prune"
            and bool(
                app_config.get("v118_leaf_prune_experiment_enabled", False)
            )
        ),
        live_device_context=live_device_context,
        device_mode=device_mode,
        recorded_device_context=recorded_device_context,
        recorded_template_session_id=recorded_template_session_id,
        live_report_index=live_report_index,
        insert_state=insert_state,
        refresh_insert_schedule=replenish_01,
        special_rule_store=special_rule_store,
    )
    shadow_frames: list[bytes] = []
    shadow_decoded = None
    shadow_validation = None
    shadow_checks = {
        "generated": False,
        "outer_crc_ok": False,
        "frame_validation_ok": False,
        "decode_ok": False,
        "signature_equal_live": False,
        "sequences_equal_live": False,
        "roundtrip_ok": bool(shadow_result.get("roundtrip_ok")),
    }
    if shadow_result.get("generated"):
        candidate_logical = shadow_result.get("candidate_logical") or b""
        if len(candidate_logical) == len(live_logical):
            shadow_frames = _ace_01_shadow_frames(
                live_ordered, candidate_logical
            )
        else:
            shadow_frames = _ace_refragment_from_first(
                live_ordered,
                candidate_logical,
                crc=(zlib.crc32(candidate_logical) & 0xFFFFFFFF).to_bytes(
                    4, "big"
                ),
                recorded_message_id=live_ordered[0][47],
            )
        if shadow_frames:
            shadow_validation = _ace_01_verify_frames(
                shadow_frames, expected_game_id=(expected if expected else "")
            )
            shadow_assembled = _ace_01_reassemble_frames(shadow_frames)
            if shadow_assembled:
                shadow_decoded = decode_type9_payload(shadow_assembled[1])
        shadow_checks.update(
            {
                "generated": bool(shadow_frames),
                "outer_crc_ok": bool(
                    shadow_validation
                    and shadow_validation.get("crc_hex")
                    == shadow_validation.get("calculated_crc_hex")
                ),
                "frame_validation_ok": bool(
                    shadow_validation and shadow_validation.get("ok")
                ),
                "decode_ok": bool(
                    shadow_decoded
                    and shadow_decoded.get("parse_ok")
                    and shadow_decoded.get("plain_crc_ok")
                ),
                "signature_equal_live": bool(
                    shadow_result.get("pruned_leaves", 0)
                    or shadow_result.get("replace_root_with_clean_2000")
                    or shadow_result.get("special_emptied_leaves", 0)
                    or shadow_result.get("cross_record_replaced_leaves", 0)
                    or shadow_result.get("inserted_leaves", 0)
                    or (
                        shadow_decoded
                        and shadow_decoded.get("signature")
                        == live_decoded.get("signature")
                    )
                ),
                "sequences_equal_live": bool(
                    shadow_result.get("pruned_leaves", 0)
                    or shadow_result.get("replace_root_with_clean_2000")
                    or shadow_result.get("inserted_leaves", 0)
                    or (
                        shadow_decoded
                        and shadow_decoded.get("leaf_sequences")
                        == live_decoded.get("leaf_sequences")
                    )
                ),
            }
        )
    shadow_mechanical_ready = all(shadow_checks.values())
    matched_leaf_count = int(shadow_result.get("matched_leaves") or 0)
    special_handled_leaves = int(
        shadow_result.get("special_handled_leaves") or 0
    )
    special_changed_leaves = int(
        shadow_result.get("special_changed_leaves") or 0
    )
    special_dropped_leaves = int(
        shadow_result.get("special_dropped_leaves") or 0
    )
    special_emptied_leaves = int(
        shadow_result.get("special_emptied_leaves") or 0
    )
    drop_entire_report = bool(shadow_result.get("drop_entire_report"))
    full_live_inherited_leaves = int(
        shadow_result.get("full_live_inherited_leaves") or 0
    )
    shadow_leaf_results = list(shadow_result.get("leaf_results") or [])
    effective_handled_leaves = sum(
        1
        for leaf in shadow_leaf_results
        if leaf.get("matched")
        or leaf.get("special_rule_id")
        or leaf.get("replacement_level")
        in {
            "SPECIAL_UNKNOWN_RULE",
            "SPECIAL_PATCH_LIVE",
            "SPECIAL_REPLACE_TEMPLATE",
            "SPECIAL_REPLACE_TEMPLATE_NEAREST",
            "SPECIAL_DROP_LEAF",
            "SPECIAL_EMPTY_2000",
            "SPECIAL_INSERT_LEAF",
            "SPECIAL_PASS_LIVE",
            "FULL_LIVE_INHERIT",
            "CROSS_RECORD_SLOT_REPLACE",
            "TFP_CALLED_STRUCTURED_REMOVE",
            "TFP_CALLED_ZERO_MARKER",
            "DEVICE_CONTEXT_PASS_LIVE",
            "RECORDED_DEVICE_PROFILE",
        }
    )
    if not shadow_leaf_results:
        effective_handled_leaves = matched_leaf_count + special_handled_leaves
    shadow_semantic_ready = bool(
        shadow_mechanical_ready
        and effective_handled_leaves > 0
        and shadow_result.get("semantic_unmapped_leaves", 0) == 0
        and shadow_result.get("semantic_ready_leaves", 0)
        == effective_handled_leaves
    )
    shadow_send_ready = bool(
        shadow_mechanical_ready
        and effective_handled_leaves > 0
    )
    aggressive_changed_leaves = int(
        shadow_result.get("aggressive_changed_leaves") or 0
    )
    aggressive_blocked_leaves = int(
        shadow_result.get("aggressive_blocked_leaves") or 0
    )
    unmatched_pass_live_leaves = int(
        shadow_result.get("unmatched_pass_live_leaves") or 0
    )
    unmapped_pass_live_leaves = int(
        shadow_result.get("unmapped_pass_live_leaves") or 0
    )
    live_context_pass_live_leaves = int(
        shadow_result.get("live_context_pass_live_leaves") or 0
    )
    device_context_pass_live_leaves = int(
        shadow_result.get("device_context_pass_live_leaves") or 0
    )
    cross_record_replaced_leaves = int(
        shadow_result.get("cross_record_replaced_leaves") or 0
    )
    tfp_called_detected_leaves = int(
        shadow_result.get("tfp_called_detected_leaves") or 0
    )
    tfp_called_template_replaced_leaves = int(
        shadow_result.get("tfp_called_template_replaced_leaves") or 0
    )
    tfp_called_structured_removed_leaves = int(
        shadow_result.get("tfp_called_structured_removed_leaves") or 0
    )
    tfp_called_zeroed_leaves = int(
        shadow_result.get("tfp_called_zeroed_leaves") or 0
    )
    tfp_called_residual_leaves = int(
        shadow_result.get("tfp_called_residual_leaves") or 0
    )
    content_blacklist_dropped_leaves = int(
        shadow_result.get("content_blacklist_dropped_leaves") or 0
    )
    content_blacklist_emptied_leaves = int(
        shadow_result.get("content_blacklist_emptied_leaves") or 0
    )
    recorded_device_profile_rewritten_leaves = int(
        shadow_result.get("recorded_device_profile_rewritten_leaves") or 0
    )
    if shadow_semantic_ready:
        shadow_status = (
            "SEMANTIC_READY_FULL"
            if effective_handled_leaves
            == int(shadow_result.get("total_leaves") or 0)
            else "SEMANTIC_READY_PARTIAL"
        )
    elif shadow_result.get("generated") and not shadow_mechanical_ready:
        shadow_status = "CANDIDATE_VALIDATION_FAILED"
    elif shadow_result.get("generated"):
        shadow_status = "SEMANTIC_UNMAPPED"
    else:
        shadow_status = str(shadow_result.get("reason") or "NO_CANDIDATE")

    shadow_summary = {
        "mode": (
            "recorded_device_profile"
            if device_mode == DEVICE_MODE_REPLACE_RECORDED
            else "inherit_live_device"
        ),
        "device_mode": device_mode,
        "recorded_template_session_id": recorded_template_session_id,
        "recorded_device_context": recorded_device_context,
        "v129_device_gate": replay_context_state.get(
            "v129_device_gate", "NOT_CROSS_ACCOUNT"
        ),
        "v129_device_template_session_id": replay_context_state.get(
            "v129_device_template_session_id", ""
        ),
        "semantic_ruleset": shadow_result.get("semantic_ruleset", ""),
        "status": shadow_status,
        "generated": bool(shadow_result.get("generated")),
        "ready": shadow_send_ready,
        "send_ready": shadow_send_ready,
        "mechanical_ready": shadow_mechanical_ready,
        "semantic_ready": shadow_semantic_ready,
        "reason": shadow_result.get("reason", ""),
        "errors": shadow_result.get("errors", []),
        "template_count": len(pool),
        "template_leaf_rows": len(shadow_template_rows),
        "template_decode_errors": shadow_template_errors,
        "total_leaves": shadow_result.get("total_leaves", 0),
        "structural_matched_leaves": shadow_result.get(
            "structural_matched_leaves", 0
        ),
        "matched_leaves": shadow_result.get("matched_leaves", 0),
        "changed_leaves": shadow_result.get("changed_leaves", 0),
        "pruned_leaves": shadow_result.get("pruned_leaves", 0),
        "unmatched_pass_live_leaves": unmatched_pass_live_leaves,
        "unmapped_pass_live_leaves": unmapped_pass_live_leaves,
        "live_context_pass_live_leaves": live_context_pass_live_leaves,
        "device_context_pass_live_leaves": device_context_pass_live_leaves,
        "cross_record_replaced_leaves": cross_record_replaced_leaves,
        "tfp_called_detected_leaves": tfp_called_detected_leaves,
        "tfp_called_template_replaced_leaves": (
            tfp_called_template_replaced_leaves
        ),
        "tfp_called_structured_removed_leaves": (
            tfp_called_structured_removed_leaves
        ),
        "tfp_called_zeroed_leaves": tfp_called_zeroed_leaves,
        "tfp_called_residual_leaves": tfp_called_residual_leaves,
        "tfp_called_rule_ids": shadow_result.get("tfp_called_rule_ids", []),
        "content_blacklist_dropped_leaves": content_blacklist_dropped_leaves,
        "content_blacklist_emptied_leaves": content_blacklist_emptied_leaves,
        "content_blacklist_tokens": list(
            shadow_result.get("content_blacklist_tokens") or []
        ),
        "recorded_device_profile_rewritten_leaves": (
            recorded_device_profile_rewritten_leaves
        ),
        "live_device_context": shadow_result.get("live_device_context", {}),
        "template_device_contexts": template_context_by_session,
        "full_live_inherited_leaves": full_live_inherited_leaves,
        "special_handled_leaves": special_handled_leaves,
        "special_changed_leaves": special_changed_leaves,
        "special_dropped_leaves": special_dropped_leaves,
        "special_emptied_leaves": special_emptied_leaves,
        "drop_entire_report": drop_entire_report,
        "variable_length_replaced_leaves": shadow_result.get(
            "variable_length_replaced_leaves", 0
        ),
        "clean_changed_leaves": shadow_result.get("clean_changed_leaves", 0),
        "aggressive_changed_leaves": aggressive_changed_leaves,
        "aggressive_blocked_leaves": aggressive_blocked_leaves,
        "semantic_ready_leaves": shadow_result.get("semantic_ready_leaves", 0),
        "semantic_unmapped_leaves": shadow_result.get(
            "semantic_unmapped_leaves", 0
        ),
        "subtype_miss_leaves": shadow_result.get("subtype_miss_leaves", 0),
        "suspect_leaf_count": shadow_result.get("suspect_leaf_count", 0),
        "suspect_live_plaintext_hex": shadow_result.get(
            "suspect_live_plaintext_hex", ""
        ),
        "coverage": shadow_result.get("coverage", 0.0),
        "structural_coverage": shadow_result.get("structural_coverage", 0.0),
        "semantic_coverage": shadow_result.get("semantic_coverage", 0.0),
        "inserted_leaves": int(shadow_result.get("inserted_leaves") or 0),
        "inserted_message_ids": list(
            shadow_result.get("inserted_message_ids") or []
        ),
        "insert_skipped_reason": str(
            shadow_result.get("insert_skipped_reason") or ""
        ),
        "insert_skipped_live_80xx": list(
            shadow_result.get("insert_skipped_live_80xx") or []
        ),
        "candidate_plaintext_sha256": shadow_result.get(
            "candidate_plaintext_sha256", ""
        ),
        "leaf_results": shadow_result.get("leaf_results", []),
        "checks": shadow_checks,
        "decoded": shadow_decoded,
        "cross_account": bool(allow_cross_account),
        "live_game_id": expected or live_game_id,
        "donor_game_id": donor_game_id,
        "identity_rewrite_count": shadow_result.get(
            "identity_rewrite_count", 0
        ),
        "identity_blocked_leaves": shadow_result.get(
            "identity_blocked_leaves", 0
        ),
    }
    validation_errors: list[str] = []
    gate_reason = ""
    if not expected or (live_game_id and live_game_id != expected):
        gate_reason = "GAME_ID_MISMATCH_PASS_LIVE"
        validation_errors.append(
            f"实时游戏ID不匹配:{live_game_id or '空'}!={expected or '空'}"
        )
    elif live_report_index is None:
        gate_reason = "MISSING_REPORT_INDEX_PASS_LIVE"
        validation_errors.append("实时01包缺少0A 00 23报告序号")
    elif selected is None:
        gate_reason = "NO_VALID_TEMPLATE_PASS_LIVE"
        validation_errors.append("录制池无同游戏ID的有效完整01模板")

    changed_leaves = int(shadow_result.get("changed_leaves") or 0)
    nearest_clean_changed = any(
        leaf.get("replacement_level") == "SPECIAL_REPLACE_TEMPLATE_NEAREST"
        and leaf.get("candidate_hex") != leaf.get("live_hex")
        for leaf in shadow_leaf_results
    )
    # 录制池没有可用完整模板时，仍允许删叶/改写（不走叶子替换）。
    rewrite_without_template = gate_reason == "NO_VALID_TEMPLATE_PASS_LIVE"
    replace_allowed = bool(
        (not gate_reason or rewrite_without_template)
        and shadow_send_ready
        and changed_leaves > 0
        and shadow_frames
    )
    drop_report_allowed = bool(
        (not gate_reason or rewrite_without_template)
        and drop_entire_report
        and special_dropped_leaves > 0
        and shadow_mechanical_ready
    )
    output_frames = (
        []
        if drop_report_allowed
        else [bytes(frame) for frame in shadow_frames]
        if replace_allowed
        else [bytes(frame) for frame in live_ordered]
    )
    output_changed = output_frames != [bytes(frame) for frame in live_ordered]
    decision = (
        "DROP"
        if drop_report_allowed
        else "REPLACE"
        if output_changed
        else "PASS_LIVE"
    )
    replacement_level = "NONE"
    if decision == "DROP":
        replacement_level = "SPECIAL_DROP_LEAF"
        reason = "SPECIAL_DROP_ROOT_REPORT"
    elif decision == "REPLACE":
        if cross_record_replaced_leaves > 0:
            replacement_level = "CROSS_RECORD_SLOT_REPLACE"
            reason = "TFP_CALLED_CLEAN_SLOT_REPLACE"
        elif tfp_called_structured_removed_leaves > 0:
            replacement_level = "TFP_CALLED_STRUCTURED_REMOVE"
            reason = "TFP_CALLED_NO_TEMPLATE_STRUCTURED_REMOVE"
        elif tfp_called_zeroed_leaves > 0:
            replacement_level = "TFP_CALLED_ZERO_MARKER"
            reason = "TFP_CALLED_UNKNOWN_LAYOUT_ZERO_MARKER"
        elif int(shadow_result.get("inserted_leaves") or 0) > 0:
            replacement_level = "SPECIAL_INSERT_LEAF"
            reason = "STABLE_80XX_INSERT_LEAF"
        elif special_emptied_leaves > 0:
            replacement_level = "SPECIAL_EMPTY_2000"
            reason = "SEQUENCE_SAFE_EMPTY_2000_REPLACE"
        elif special_dropped_leaves > 0:
            replacement_level = "SPECIAL_DROP_LEAF"
            if any(
                leaf.get("block_reason") == "SPECIAL_DROP_ROOT_TO_CLEAN_2000"
                for leaf in shadow_leaf_results
            ):
                reason = "SPECIAL_DROP_ROOT_TO_CLEAN_2000_REPLACE"
            else:
                reason = "SPECIAL_DROP_LEAF_REPLACE"
        elif shadow_result.get("pruned_leaves", 0) > 0:
            replacement_level = "UNMATCHED_LEAF_PRUNE"
            reason = "V118_EXPERIMENT_UNMATCHED_LEAF_PRUNE"
        elif nearest_clean_changed:
            replacement_level = "SPECIAL_REPLACE_TEMPLATE_NEAREST"
            reason = "PROCESS_SCAN_CLEAN_TEMPLATE_REPLACE"
        elif recorded_device_profile_rewritten_leaves > 0:
            replacement_level = "RECORDED_DEVICE_PROFILE"
            reason = "RECORDED_DEVICE_PROFILE_REPLACE"
        elif special_changed_leaves > 0:
            replacement_level = "SPECIAL_UNKNOWN_RULE"
            reason = "SPECIAL_UNKNOWN_RULE_REPLACE"
        else:
            replacement_level = "KNOWN_CLEAN"
            reason = f"{shadow_status}_CLEAN_REPLACE"
    elif gate_reason:
        reason = gate_reason
    elif live_context_pass_live_leaves > 0 and changed_leaves == 0:
        reason = "LIVE_CONTEXT_MISMATCH_PASS_LIVE"
    elif device_context_pass_live_leaves > 0 and changed_leaves == 0:
        reason = "DEVICE_CONTEXT_MISMATCH_PASS_LIVE"
    elif unmapped_pass_live_leaves > 0 and changed_leaves == 0:
        reason = "UNMAPPED_BODY_PASS_LIVE"
    elif unmatched_pass_live_leaves > 0 and changed_leaves == 0:
        reason = "UNMATCHED_LEAF_PASS_LIVE"
    elif shadow_send_ready and changed_leaves == 0:
        reason = "NO_RECORDED_BODY_CHANGE_PASS_LIVE"
    elif shadow_status == "SEMANTIC_UNMAPPED":
        reason = "SEMANTIC_UNMAPPED_PASS_LIVE"
    elif shadow_status == "CANDIDATE_VALIDATION_FAILED":
        reason = "CANDIDATE_VALIDATION_FAILED_PASS_LIVE"

    drop_leaf_sequence_compaction = {
        "applied": False,
        "input_leaf_count": 0,
        "output_leaf_count": 0,
        "leaf_delta": 0,
        "before_sequences": [],
        "after_sequences": [],
    }
    if (
        decision != "DROP"
        and special_dropped_leaves > 0
        and output_frames
    ):
        output_frames, drop_leaf_sequence_compaction = (
            _sequence_safe_compact_native_leaf_sequences(
                live_logical,
                output_frames,
            )
        )
        if drop_leaf_sequence_compaction.get("applied"):
            output_changed = True
            decision = "REPLACE"
    if (
        v128_state is None
        and sequence_safe_offset_applied
        and decision == "PASS_LIVE"
    ):
        output_changed = True
        decision = "REPLACE"
        reason = "DROP_LEAF_SEQUENCE_OFFSET_SHIFT"
        replacement_level = "DROP_LEAF_SEQUENCE_OFFSET"

    output_validation = (
        {
            "ok": True,
            "errors": [],
            "crc_hex": "",
            "calculated_crc_hex": "",
            "account_id": expected or live_game_id,
        }
        if decision == "DROP"
        else _ace_01_verify_frames(
            output_frames, expected_game_id=(expected if expected else "")
        )
    )
    if (
        decision != "DROP"
        and bool(output_validation.get("ok"))
    ):
        native_leaf_delta = int(
            drop_leaf_sequence_compaction.get("leaf_delta") or 0
        )
        if native_leaf_delta:
            sequence_safe_state["leaf_offset"] = int(
                sequence_safe_state.get("leaf_offset") or 0
            ) + native_leaf_delta
    if decision in {"REPLACE", "DROP"} and bool(output_validation.get("ok")):
        # 内置规则只在最终输出通过机械校验并实际选为网络输出后，
        # 才累计到拦截管理的“成功改写”，避免影子候选失败造成虚高。
        from core.type9_content_blacklist import CONTENT_BLACKLIST_RULE_ID
        from core.type9_special_rules import type9_hot_rule_store

        for leaf in shadow_leaf_results:
            tfp_replacement = leaf.get("tfp_called_replacement") or {}
            rule_id = str(leaf.get("tfp_called_rule_id") or "")
            if (
                decision == "REPLACE"
                and leaf.get("tfp_called_detected")
                and rule_id
                and not bool(tfp_replacement.get("candidate_marker_present"))
                and leaf.get("candidate_hex") != leaf.get("live_hex")
            ):
                type9_hot_rule_store.record_changed(rule_id)
            if (
                leaf.get("content_blacklist_hit")
                and leaf.get("special_rule_action")
                in {"DROP_LEAF", "REPLACE_CLEAN_2000"}
            ):
                type9_hot_rule_store.record_changed(
                    str(leaf.get("special_rule_id") or CONTENT_BLACKLIST_RULE_ID)
                )
    native_output_frames = [bytes(frame) for frame in output_frames]
    v128_injected_frames: list[bytes] = []
    rebuild_controls_v2 = bool(app_config.get("rebuild_controls_v2", False))
    rebuild_controls_v3 = bool(app_config.get("rebuild_controls_v3", False))
    legacy_central9_only = bool(
        app_config.get("rebuild_central9_only", False)
    )
    if rebuild_controls_v3:
        central9_replenish_enabled = bool(
            v128_enabled and app_config.get("rebuild_central9_enabled", False)
        )
        player_base_replenish_enabled = any(
            bool(app_config.get(f"rebuild_player_{message_id:04X}_enabled", False))
            for message_id in (0x8007, 0x800A, 0x800C, 0x800D, 0x800F, 0x8023, 0x8024, 0x802C)
        )
        match_replenish_enabled = bool(
            app_config.get("rebuild_match_events_enabled", False)
        )
        scan_replenish_enabled = bool(
            app_config.get("rebuild_scan_waves_enabled", False)
        )
        strong_profile_replenish_enabled = bool(
            v128_enabled and app_config.get("rebuild_strong_profile", True)
        )
    elif rebuild_controls_v2:
        central9_replenish_enabled = bool(
            v128_enabled and app_config.get("rebuild_central9_enabled", False)
        )
        player_base_replenish_enabled = bool(
            app_config.get("rebuild_player_base_enabled", False)
        )
        match_replenish_enabled = bool(
            app_config.get("rebuild_match_events_enabled", False)
        )
        scan_replenish_enabled = bool(
            app_config.get("rebuild_scan_waves_enabled", False)
        )
        strong_profile_replenish_enabled = bool(
            v128_enabled and app_config.get("rebuild_strong_profile", True)
        )
    else:
        central9_replenish_enabled = False
        legacy_full = bool(
            app_config.get("full_rebuild_01_mode", False)
            and not legacy_central9_only
        )
        player_base_replenish_enabled = legacy_full
        match_replenish_enabled = bool(
            legacy_full
            and str(app_config.get("rebuild_match_events") or "off")
            == "random"
        )
        scan_replenish_enabled = bool(
            legacy_full
            and str(app_config.get("rebuild_scan_waves") or "repeat_first")
            != "off"
        )
        strong_profile_replenish_enabled = bool(
            v128_enabled
            and app_config.get("rebuild_strong_profile", True)
            and not legacy_central9_only
        )
    same_device_replenish_enabled = bool(
        v128_enabled
        and (
            player_base_replenish_enabled
            or match_replenish_enabled
            or scan_replenish_enabled
        )
    )
    v128_replenish_info = {
        "enabled": bool(v128_enabled),
        "model_revision": v128_model_revision,
        "elapsed_ms": (
            int(float(session_elapsed_seconds or 0.0) * 1000)
            if v128_enabled else None
        ),
        "offsets_before": v128_offsets_before,
        "offsets_after": dict(v128_offsets_before),
        "groups": [],
        "leaf_count": 0,
        "frame_count": 0,
        "late_live_duplicates": dict(
            v128_live_meta.get("late_live_duplicates") or {}
        ),
        "builtin_live_policy": dict(
            v128_live_meta.get("builtin_live_policy") or {}
        ),
        "same_device_player": {
            "enabled": same_device_replenish_enabled,
            "gate": "DISABLED" if not same_device_replenish_enabled else "PENDING",
            "clock_metadata_status": "NOT_CHECKED",
            "clock_metadata_missing_message_ids": [],
            "static_ready_message_ids": ["0x800F", "0x8023"],
            "dynamic_ready_message_ids": [
                "0x8007", "0x800A", "0x800C", "0x800D",
                "0x8024", "0x8027", "0x8029", "0x802A", "0x802B", "0x802C",
            ],
            "dynamic_pending_message_ids": [
            ],
            "secondary_fallback_scope": "ALL_PLAYER_SUPPLEMENT_IDS",
            "secondary_fallback_message_ids": [
                "0x8007", "0x800A", "0x800C", "0x800D", "0x800F",
                "0x8023", "0x8024", "0x8027", "0x8029", "0x802A",
                "0x802B", "0x802C",
            ],
            "secondary_fallback_policy": (
                "PLAYER_MISSING_OR_PENDING_AND_LIVE_PRESENT_DEFER_HOT_RULE;"
                "HOT_RULE_MISS_PASS_LIVE;LIVE_ABSENT_NO_OUTPUT_EXCEPT_BUILTIN_800D"
            ),
            "builtin_800d_fallback": False,
            "builtin_800d_seed_revision": "",
            "800d_source": "none",
        },
        "rebuild_options": {
            "controls_v2": rebuild_controls_v2,
            "controls_v3": rebuild_controls_v3,
            "central9": central9_replenish_enabled,
            "strong_profile": strong_profile_replenish_enabled,
            "player_base": player_base_replenish_enabled,
            "match_events": match_replenish_enabled,
            "scan_waves": scan_replenish_enabled,
            "player_message_ids": {
                f"0x{message_id:04X}": bool(
                    app_config.get(f"rebuild_player_{message_id:04X}_enabled", False)
                )
                for message_id in (0x8007, 0x800A, 0x800C, 0x800D, 0x800F, 0x8023, 0x8024, 0x802C)
            },
        },
        "strong_profile": {
            "seen_files": [],
            "unmapped_seen_files": [],
            "armed_message_ids": [],
            "newly_armed_message_ids": [],
            "armed_slots": {},
            "due_message_ids": [],
            "model_policy": (
                "CONDITIONAL_FILE_PAIR;LIVE_SLOT_SUPPRESS;PER_SESSION_LATCH"
            ),
        },
        "state": dict(v128_state or {}),
    }
    native_output_result = _ace_01_reassemble_frames(native_output_frames)
    if v128_state is not None and native_output_result and decision != "DROP":
        from core.type9_shadow import decode_material
        from core.type9_v128_replenish import (
            collect_due_groups,
            collect_due_strong_profile_groups,
            plan_same_device_player_groups,
        )

        # A variable-length native rebuild may itself add/remove physical
        # fragments.  Carry that delta into every later uplink frame.
        native_frame_delta = len(native_output_frames) - len(live_ordered)
        v128_state["frame_offset"] = int(
            v128_state.get("frame_offset") or 0
        ) + native_frame_delta

        native_logical = native_output_result[1]
        native_material = decode_material(native_logical)
        if native_material.get("ok"):
            native_sequences = [
                int(leaf.get("record_sequence") or 0)
                for leaf in native_material.get("leaves") or []
            ]
            if native_sequences:
                v128_state["last_output_leaf_sequence"] = max(native_sequences)
            live_leaves = list(
                {"raw": bytes(leaf.get("raw") or b"")}
                for leaf in native_material.get("leaves") or []
            )
            if central9_replenish_enabled:
                due_groups = collect_due_groups(
                    v128_state,
                    elapsed_seconds=float(session_elapsed_seconds or 0.0),
                    live_leaves=live_leaves,
                )
            else:
                due_groups = []
            central_group_count = len(due_groups)
            if strong_profile_replenish_enabled:
                strong_groups, strong_info = collect_due_strong_profile_groups(
                    v128_state,
                    elapsed_seconds=float(session_elapsed_seconds or 0.0),
                    live_leaves=live_leaves,
                    trigger_leaves=(
                        v128_live_meta.get("live_leaves") or live_leaves
                    ),
                )
            else:
                strong_groups = []
                strong_info = {
                    "enabled": False,
                    "gate": "DISABLED_BY_CONFIG",
                    "due_message_ids": [],
                    "seen_files": [],
                    "unmapped_seen_files": [],
                    "armed_message_ids": [],
                    "newly_armed_message_ids": [],
                    "armed_slots": {},
                    "model_policy": "DISABLED_BY_CONFIG",
                }
            due_groups.extend(strong_groups)
            v128_replenish_info["strong_profile"] = strong_info
            strong_group_count = len(strong_groups)
            if same_device_replenish_enabled:
                player_groups, player_info = plan_same_device_player_groups(
                    v128_state,
                    template_rows=shadow_template_rows,
                    elapsed_seconds=float(session_elapsed_seconds or 0.0),
                    unix_now=(
                        float(session_unix_time)
                        if session_unix_time is not None
                        else time.time()
                    ),
                    live_leaves=v128_live_meta.get("live_leaves") or live_leaves,
                    live_device_context=live_device_context,
                    live_game_id=expected or live_game_id,
                    allow_cross_account_device=bool(allow_cross_account),
                )
                due_groups.extend(player_groups)
                v128_replenish_info["same_device_player"] = player_info
            v128_injected_frames, generated_info = _v128_build_injected_frames(
                native_output_frames,
                native_logical,
                due_groups,
                v128_state,
                expected_game_id=(expected if expected else ""),
            )
            generated_info["central_group_count"] = central_group_count
            generated_info["strong_group_count"] = strong_group_count
            generated_info["player_group_count"] = (
                len(due_groups) - central_group_count - strong_group_count
            )
            v128_replenish_info.update(generated_info)

        if v128_injected_frames:
            output_frames = native_output_frames + v128_injected_frames
            output_changed = True
            decision = "REPLACE"
            if int(v128_replenish_info.get("player_group_count") or 0):
                reason = "V128_7_SAME_DEVICE_REPORT_INJECT"
                replacement_level = "V128_7_SAME_DEVICE_80XX_REPORT"
            elif int(v128_replenish_info.get("strong_group_count") or 0):
                reason = "V130_1_CONDITIONAL_STRONG_PROFILE_INJECT"
                replacement_level = "V130_1_CONDITIONAL_STRONG_PROFILE"
            else:
                reason = "V128_PERIODIC_80XX_REPORT_INJECT"
                replacement_level = "V128_PERIODIC_80XX_REPORT"
        else:
            output_frames = native_output_frames
            if v128_sequence_offsets_applied and decision == "PASS_LIVE":
                output_changed = True
                decision = "REPLACE"
                reason = "V128_SEQUENCE_OFFSET_SHIFT"
                replacement_level = "V128_SEQUENCE_OFFSET"
        v128_replenish_info["state"] = dict(v128_state)
        v128_replenish_info["offsets_after"] = {
            key: int(v128_state.get(key) or 0)
            for key in v128_offsets_before
        }

    output_result = native_output_result
    output_logical = output_result[1] if output_result else live_logical

    shadow_summary["sent"] = output_changed
    shadow_summary["report_dropped"] = decision == "DROP"
    shadow_summary["replacement_level"] = replacement_level
    shadow_summary["v128_replenish"] = v128_replenish_info
    shadow_summary["drop_leaf_sequence_compaction"] = (
        drop_leaf_sequence_compaction
    )
    detail = {
        "decision": decision,
        "reason": reason,
        "replace_mode": (
            "type9_v128_7_same_device_80xx_report"
            if replacement_level == "V128_7_SAME_DEVICE_80XX_REPORT"
            else "type9_v130_1_conditional_strong_profile"
            if replacement_level == "V130_1_CONDITIONAL_STRONG_PROFILE"
            else "type9_v128_periodic_80xx_report"
            if replacement_level == "V128_PERIODIC_80XX_REPORT"
            else "type9_v128_sequence_offset"
            if replacement_level == "V128_SEQUENCE_OFFSET"
            else "type9_drop_leaf_sequence_offset"
            if replacement_level == "DROP_LEAF_SEQUENCE_OFFSET"
            else "type9_v118_experiment_unmatched_leaf_prune"
            if replacement_level == "UNMATCHED_LEAF_PRUNE"
            else "type9_stable_80xx_insert"
            if replacement_level == "SPECIAL_INSERT_LEAF"
            else "type9_v118_special_unknown_rule"
            if replacement_level in {
                "SPECIAL_UNKNOWN_RULE",
                "SPECIAL_REPLACE_TEMPLATE_NEAREST",
                "SPECIAL_DROP_LEAF",
                "SPECIAL_EMPTY_2000",
                "CROSS_RECORD_SLOT_REPLACE",
                "TFP_CALLED_STRUCTURED_REMOVE",
                "TFP_CALLED_ZERO_MARKER",
            }
            else (
                "type9_semantic_allowlist_replace"
                if output_changed else "type9_candidate_gate_pass_live"
            )
        ),
        "replacement_level": replacement_level,
        "pool_idx": selected_idx if selected is not None else None,
        "pool_total": len(pool),
        "account_id": expected or live_game_id,
        "cross_account": bool(allow_cross_account),
        "live_game_id": expected or live_game_id,
        "donor_game_id": donor_game_id,
        "report_index": live_report_index,
        "template_report_index": selected.get("report_index") if selected else None,
        "cursor_before": cursor_before,
        "cursor_after": int(pool_index[0] or 0),
        "live_frames": [bytes(frame) for frame in live_ordered],
        "input_frames": original_frames,
        "template_frames": template_frames,
        "shadow_frames": shadow_frames,
        "output_frames": output_frames,
        "orig_packet": b"".join(live_ordered),
        "new_packet": b"".join(output_frames),
        "orig_pkt_len": sum(map(len, live_ordered)),
        "new_pkt_len": sum(map(len, output_frames)),
        "orig_payload_len": sum(
            len((_ace_01_frame_meta(f) or {}).get("data", b""))
            for f in live_ordered
        ),
        "new_payload_len": len(output_logical),
        "payload_preview": output_logical[:64],
        "crc_hex": output_validation["crc_hex"],
        "routing_hex": f"{live_ordered[0][47]:02X}" if live_ordered else "",
        "fragment_count_before": len(live_ordered),
        "fragment_count_after": len(output_frames),
        "native_fragment_count_after": len(native_output_frames),
        "v128_injected_fragment_count": len(v128_injected_frames),
        "v128_replenish": v128_replenish_info,
        "v130_reconnect_resolution": v130_reconnect_resolution,
        "drop_leaf_sequence_compaction": drop_leaf_sequence_compaction,
        "validation_ok": (
            bool(output_validation.get("ok")) if output_changed else True
        ),
        "validation_errors": validation_errors,
        "template_validation": template_validation,
        "final_equals_live": not output_changed,
        "online_decode": {
            "live": live_decoded,
            "template": template_decoded,
            "facts": decision_facts,
        },
        "shadow_rebuild": shadow_summary,
    }
    detail["final_identity_check"] = bool(
        decision == "DROP"
        or
        not expected
        or output_validation.get("account_id") == expected
    )
    if on_log:
        on_log(detail)
    return detail["output_frames"], detail["output_frames"] != original_frames


MARKER_01_0A_00_08 = b"\x01\x0A\x00\x08"


def ace_is_01_keepalive_template(frame: bytes) -> bool:
    """本连接下行里周期性短 08 心跳：单片、带 Type8 记录，可原样改序号后回放。"""
    if not isinstance(frame, (bytes, bytearray)):
        return False
    raw = bytes(frame)
    if len(raw) < 80 or len(raw) > 220:
        return False
    if raw[:3] != b"\x01\x00\x00":
        return False
    if int.from_bytes(raw[3:5], "big") != len(raw):
        return False
    if raw[44] != 1:
        return False
    if int.from_bytes(raw[38:40], "big") != 1:
        return False
    return MARKER_01_0A_00_08 in raw[55:]


def ace_read_01_outer_ids(frame: bytes) -> tuple[int, int] | None:
    """读外层帧序号 [6:10] 和包组 [36:38]。"""
    if not isinstance(frame, (bytes, bytearray)) or len(frame) < 38:
        return None
    if bytes(frame[:3]) != b"\x01\x00\x00":
        return None
    return (
        int.from_bytes(frame[6:10], "big"),
        int.from_bytes(frame[36:38], "big"),
    )


def ace_next_01_outer_ids(
    seq: int,
    group: int,
    *,
    bump_group: bool = True,
) -> tuple[int, int]:
    seq = (int(seq) + 1) & 0xFFFFFFFF
    if seq == 0:
        seq = 1
    if bump_group:
        group = (int(group) + 1) & 0xFFFF
        if group == 0:
            group = 1
    return seq, int(group) & 0xFFFF


def ace_restamp_01_frame(frame: bytes, *, seq: int, group: int) -> bytes:
    """只改外层序号/包组；首片重算 CRC。密文和分片结构不动。"""
    if not isinstance(frame, (bytes, bytearray)) or len(frame) < 38:
        return b""
    if bytes(frame[:3]) != b"\x01\x00\x00":
        return b""
    packet = bytearray(frame)
    packet[6:10] = int(seq).to_bytes(4, "big")
    packet[36:38] = (int(group) & 0xFFFF).to_bytes(2, "big")
    if len(packet) >= 55 and packet[44] == 1:
        packet[40:44] = (zlib.crc32(bytes(packet[55:])) & 0xFFFFFFFF).to_bytes(
            4, "big"
        )
    return bytes(packet)


def ace_bump_01_keepalive_frame(
    template: bytes,
    *,
    seq: int | None = None,
    group: int | None = None,
) -> bytes:
    """保留本连接最近一条短 08 密文，只推进帧序号和包组并重算外层 CRC。"""
    if not ace_is_01_keepalive_template(template):
        return b""
    current = ace_read_01_outer_ids(template)
    if current is None:
        return b""
    if seq is None or group is None:
        seq, group = ace_next_01_outer_ids(current[0], current[1], bump_group=True)
    return ace_restamp_01_frame(template, seq=int(seq), group=int(group))


def _ace_finalize_single_frame(
    packet: bytearray,
    *,
    recorded_message_id: bytes,
) -> tuple[bytes, bytes, bytes]:
    """
    重建单片 01 物理帧的外层字段。

    - a[3:5]：物理帧总长度
    - a[51:55]：首片数据长度（BE32）
    - a[40:44]：CRC32(完整逻辑 payload)，由修改后的实时 payload 重算
    - a[47]：按当前需求继续使用录制池里的旧消息 ID

    返回 (frame, old_crc, new_crc)。
    """
    old_crc = bytes(packet[40:44]) if len(packet) >= 44 else b""
    total = len(packet)
    if total >= 5:
        packet[3:5] = total.to_bytes(2, "big")

    if len(packet) >= 48 and recorded_message_id:
        packet[47] = recorded_message_id[0]

    # 指南中的首片头长为 0x37。这里只在完整首片上重算；多片需要先重组。
    if len(packet) >= 55 and packet[44] == 1:
        logical_len = len(packet) - 55
        packet[51:55] = logical_len.to_bytes(4, "big")

        # 当前实现中 payload[4:6] 是逻辑长度的 BE16 回显字段。
        if len(packet) >= 61 and logical_len <= 0xFFFF:
            packet[59:61] = logical_len.to_bytes(2, "big")

        # 账号后的两个内层容器长度回显，沿用现有已验证位置。
        if len(packet) > 78:
            id_len = packet[78]
            if 0 < id_len <= 64:
                seg_b_start = 78 + id_len + 3
                seg_b_len = len(packet) - seg_b_start
                if 0 <= seg_b_len <= 0xFFFF:
                    for pos in (78 + id_len + 1, 78 + id_len + 7):
                        if pos + 2 <= len(packet):
                            packet[pos:pos + 2] = seg_b_len.to_bytes(2, "big")

        new_crc = (zlib.crc32(bytes(packet[55:])) & 0xFFFFFFFF).to_bytes(
            4, "big"
        )
        packet[40:44] = new_crc
    else:
        new_crc = old_crc
    return bytes(packet), old_crc, new_crc


def _ace_refragment_from_first(
    original_frames: list[bytes],
    logical_payload: bytes,
    *,
    crc: bytes,
    recorded_message_id: int,
) -> list[bytes]:
    """以当前实时首片为头模板，把修改后的逻辑 payload 按 4096B 重新分片。"""
    ordered_result = _ace_01_reassemble_frames(original_frames)
    if not ordered_result:
        return original_frames
    ordered, _ = ordered_result
    chunks = [
        logical_payload[pos:pos + 4096]
        for pos in range(0, len(logical_payload), 4096)
    ] or [b""]
    fragment_count = len(chunks)
    first = ordered[0]
    base_sequence = int.from_bytes(first[8:10], "big")
    group = first[36:38]
    rebuilt: list[bytes] = []
    for idx, chunk in enumerate(chunks):
        fragment_number = idx + 1
        if idx == 0:
            header = bytearray(first[:55])
            header[44] = 1
            header[47] = recorded_message_id
            header[49:51] = fragment_number.to_bytes(2, "big")
            header[51:55] = len(chunk).to_bytes(4, "big")
        else:
            if idx < len(ordered):
                header = bytearray(ordered[idx][:51])
            else:
                header = bytearray(first[:51])
                header[8:10] = ((base_sequence + idx) & 0xFFFF).to_bytes(
                    2, "big"
                )
            header[44] = 0
            header[45:47] = fragment_number.to_bytes(2, "big")
            header[47:51] = len(chunk).to_bytes(4, "big")
        header[36:38] = group
        header[38:40] = fragment_count.to_bytes(2, "big")
        header[40:44] = crc
        frame = header + chunk
        frame[3:5] = len(frame).to_bytes(2, "big")
        rebuilt.append(bytes(frame))
    return rebuilt


def _v128_replace_type9_plaintext(
    logical_payload: bytes,
    plaintext: bytes,
) -> bytes:
    """Replace the first Type9 plaintext while preserving its live envelope."""
    from core.type9_crypto import KEYS, type9_transform
    from core.type9_shadow import decode_material

    material = decode_material(logical_payload)
    if not material.get("ok"):
        return b""
    record = material["record"]
    selector = int(record["selector"])
    key_index = int(record["key_index"])
    ciphertext = type9_transform(
        plaintext,
        selector,
        KEYS[key_index],
        direction=1,
    )
    cipher_start = int(record["ciphertext_offset"])
    old_cipher_end = cipher_start + int(record["ciphertext_length"])
    logical = bytearray(logical_payload[:cipher_start])
    logical[cipher_start - 6:cipher_start - 2] = (
        zlib.crc32(plaintext) & 0xFFFFFFFF
    ).to_bytes(4, "big")
    logical[cipher_start - 2:cipher_start] = len(ciphertext).to_bytes(2, "big")
    logical.extend(ciphertext)
    logical.extend(logical_payload[old_cipher_end:])
    return bytes(logical)


def _v128_set_report_index(logical_payload: bytes, report_index: int) -> bytes:
    offset = _ace_01_report_index_offset(logical_payload)
    if offset is None:
        return bytes(logical_payload)
    output = bytearray(logical_payload)
    output[offset:offset + 4] = (int(report_index) & 0xFFFFFFFF).to_bytes(
        4, "big"
    )
    return bytes(output)


def _v128_shift_live_logical(
    logical_payload: bytes,
    *,
    report_offset: int,
    leaf_offset: int,
) -> tuple[bytes, dict]:
    """Apply accumulated report/leaf offsets to one native logical packet."""
    from core.type9_shadow import decode_material

    original_report = _ace_01_report_index(logical_payload)
    shifted = bytes(logical_payload)
    if original_report is not None and report_offset:
        shifted = _v128_set_report_index(
            shifted,
            original_report + int(report_offset),
        )
    material = decode_material(shifted)
    meta = {
        "original_report_index": original_report,
        "output_report_index": _ace_01_report_index(shifted),
        "live_message_ids": [],
        "leaf_sequences": [],
    }
    if not material.get("ok"):
        return shifted, meta
    plaintext = bytearray(material["plaintext"])
    message_ids = []
    sequences = []
    for leaf in material.get("leaves") or []:
        sequence = int(leaf.get("record_sequence") or 0)
        output_sequence = (sequence + int(leaf_offset)) & 0xFFFFFFFF
        start = int(leaf["start"])
        plaintext[start + 10:start + 14] = output_sequence.to_bytes(4, "big")
        sequences.append(output_sequence)
        message_ids.append(leaf.get("message_id"))
    if leaf_offset:
        rebuilt = _v128_replace_type9_plaintext(shifted, bytes(plaintext))
        if rebuilt:
            shifted = rebuilt
    meta.update(
        {
            "output_report_index": _ace_01_report_index(shifted),
            "live_message_ids": message_ids,
            "leaf_sequences": sequences,
        }
    )
    return shifted, meta


def _v128_apply_authoritative_builtin_live_policy(
    logical_payload: bytes,
    state: dict,
) -> tuple[bytes, dict]:
    """Use built-in bodies for the fixed nine and neutralize true duplicates.

    A matching native leaf is only a carrier: its version/sequence remain and
    its complete body comes from the built-in model.  Missing subtypes are
    injected later.  A key already emitted, or an unexpected slot/subtype, is
    changed to legal empty 0x2000 with the original recordSequence.
    """
    from core.type9_shadow import clean_2000_root_leaf, decode_material
    from core.type9_stable_80xx_insert import assemble_batch
    from core.type9_v128_replenish import (
        BUILTIN_MESSAGE_IDS,
        PLAYER_SUPPLEMENT_MESSAGE_IDS,
        STRONG_PROFILE_MESSAGE_IDS,
        builtin_template_for_live_leaf,
        live_leaf_key,
        player_event_identity_already_emitted,
        player_leaf_identity,
        strong_profile_live_key,
    )

    info = {
        "changed": False,
        "template_keys": [],
        "late_duplicate_keys": [],
        "unexpected_keys": [],
        "paths": [],
    }
    emitted = {str(value) for value in state.get("emitted") or []}
    player_emitted = {
        str(value)
        for value in (
            state.get("same_device_player", {}).get("emitted_identities") or []
        )
    }
    strong_emitted = {
        str(value)
        for value in (
            state.get("strong_profile", {}).get("emitted") or []
        )
    }
    material = decode_material(logical_payload)
    if not material.get("ok"):
        return bytes(logical_payload), info

    replacements: dict[tuple[int, ...], dict] = {}
    template_keys: set[str] = set()
    late_keys: set[str] = set()
    unexpected_keys: set[str] = set()
    seen_ids = {int(value) for value in state.get("seen_live_ids") or []}
    for leaf in material.get("leaves") or []:
        message_id = leaf.get("message_id")
        if message_id is None:
            continue
        message_id = int(message_id)
        seen_ids.add(message_id)
        raw = bytes(leaf.get("raw") or b"")
        path = tuple(leaf.get("path") or [])
        if message_id in STRONG_PROFILE_MESSAGE_IDS:
            strong_key = strong_profile_live_key(raw)
            if strong_key and strong_key in strong_emitted:
                replacement = clean_2000_root_leaf(
                    int(leaf.get("record_sequence") or 0),
                    version=int(leaf.get("version") or 1),
                )
                replacements[path] = {"raw": replacement, "key": strong_key}
                late_keys.add(strong_key)
            continue
        if message_id in PLAYER_SUPPLEMENT_MESSAGE_IDS:
            identity = player_leaf_identity(raw)
            if player_event_identity_already_emitted(identity, player_emitted):
                replacement = clean_2000_root_leaf(
                    int(leaf.get("record_sequence") or 0),
                    version=int(leaf.get("version") or 1),
                )
                key = f"PLAYER:{identity}"
                replacements[path] = {"raw": replacement, "key": key}
                late_keys.add(key)
            if message_id not in BUILTIN_MESSAGE_IDS:
                continue
        if message_id not in BUILTIN_MESSAGE_IDS:
            continue
        key = live_leaf_key(raw) or f"{message_id:04X}@unexpected"
        if key in emitted:
            replacement = clean_2000_root_leaf(
                int(leaf.get("record_sequence") or 0),
                version=int(leaf.get("version") or 1),
            )
            replacements[path] = {"raw": replacement, "key": key}
            late_keys.add(key)
            continue
        selected = builtin_template_for_live_leaf(raw)
        if selected is not None:
            selected_key, replacement = selected
            replacements[path] = {"raw": replacement, "key": selected_key}
            template_keys.add(selected_key)
            continue
        replacement = clean_2000_root_leaf(
            int(leaf.get("record_sequence") or 0),
            version=int(leaf.get("version") or 1),
        )
        replacements[path] = {"raw": replacement, "key": key}
        unexpected_keys.add(key)
    if not replacements:
        return bytes(logical_payload), info

    def rebuild(node: dict) -> bytes:
        path = tuple(node.get("path") or [])
        raw = bytes(node.get("raw") or b"")
        if not node.get("children"):
            replacement = replacements.get(path)
            return bytes(replacement["raw"]) if replacement else raw
        cursor = 0x15
        for child in node.get("children") or []:
            cursor += 4 + int(child.get("actual_length") or 0)
        trailer = raw[cursor:]
        children = [rebuild(child) for child in node.get("children") or []]
        return assemble_batch(
            children,
            version=int(node.get("version") or 1),
            sequence=int(node.get("record_sequence") or 0),
            trailer=trailer,
        )

    plaintext = rebuild(material["root"])
    rewritten = _v128_replace_type9_plaintext(logical_payload, plaintext)
    if not rewritten:
        return bytes(logical_payload), info
    late = {str(value) for value in state.get("late_live_keys") or []}
    late.update(late_keys)
    state["late_live_keys"] = sorted(late)
    satisfied = {str(value) for value in state.get("satisfied_keys") or []}
    satisfied.update(template_keys)
    state["satisfied_keys"] = sorted(satisfied)
    state["seen_live_ids"] = sorted(seen_ids)
    info.update(
        {
            "changed": rewritten != logical_payload,
            "template_keys": sorted(template_keys),
            "late_duplicate_keys": sorted(late_keys),
            "unexpected_keys": sorted(unexpected_keys),
            "paths": [list(path) for path in sorted(replacements)],
        }
    )
    return rewritten, info


def _v128_restamp_transport(
    frames: list[bytes],
    *,
    frame_offset: int = 0,
    group_offset: int = 0,
    first_sequence: int | None = None,
    group: int | None = None,
) -> list[bytes]:
    """Restamp physical frame sequence and logical packet group counters."""
    output = []
    for index, source in enumerate(frames):
        frame = bytearray(source)
        if len(frame) < 38:
            return []
        if first_sequence is None:
            sequence = int.from_bytes(frame[8:10], "big") + int(frame_offset)
        else:
            sequence = int(first_sequence) + index
        if group is None:
            packet_group = int.from_bytes(frame[36:38], "big") + int(group_offset)
        else:
            packet_group = int(group)
        frame[8:10] = (sequence & 0xFFFF).to_bytes(2, "big")
        frame[36:38] = (packet_group & 0xFFFF).to_bytes(2, "big")
        output.append(bytes(frame))
    return output


def _v128_prepare_live_frames(
    frames: list[bytes],
    state: dict,
) -> tuple[list[bytes], dict]:
    """Apply all prior v128 offsets before the normal semantic rebuild path."""
    assembled = _ace_01_reassemble_frames(frames)
    if not assembled:
        return [bytes(frame) for frame in frames], {}
    ordered, logical = assembled
    from core.type9_shadow import decode_material

    original_material = decode_material(logical)
    original_sequences = [
        int(leaf.get("record_sequence") or 0)
        for leaf in (original_material.get("leaves") or [])
    ] if original_material.get("ok") else []
    if original_sequences:
        # Native input state belongs to the game/ACE process and therefore is
        # kept separately from output sequences shifted by inserted reports.
        state["last_native_live_leaf_sequence"] = max(original_sequences)
    original_live_leaves = [
        {"raw": bytes(leaf.get("raw") or b""), "path": list(leaf.get("path") or [])}
        for leaf in (original_material.get("leaves") or [])
    ] if original_material.get("ok") else []
    logical, builtin_live_meta = _v128_apply_authoritative_builtin_live_policy(
        logical,
        state,
    )
    shifted_logical, meta = _v128_shift_live_logical(
        logical,
        report_offset=int(state.get("report_offset") or 0),
        leaf_offset=int(state.get("leaf_offset") or 0),
    )
    meta["live_leaves"] = original_live_leaves
    meta["live_message_ids"] = [
        int.from_bytes(row["raw"][0x16:0x18], "big")
        for row in original_live_leaves
        if len(row["raw"]) >= 0x18
    ]
    meta["builtin_live_policy"] = builtin_live_meta
    meta["late_live_duplicates"] = {
        "changed": bool(builtin_live_meta.get("late_duplicate_keys")),
        "keys": list(builtin_live_meta.get("late_duplicate_keys") or []),
        "paths": list(builtin_live_meta.get("paths") or []),
    }
    rebuilt = _ace_refragment_from_first(
        ordered,
        shifted_logical,
        crc=(zlib.crc32(shifted_logical) & 0xFFFFFFFF).to_bytes(4, "big"),
        recorded_message_id=ordered[0][47],
    )
    rebuilt = _v128_restamp_transport(
        rebuilt,
        frame_offset=int(state.get("frame_offset") or 0),
        group_offset=int(state.get("group_offset") or 0),
    )
    return rebuilt or [bytes(frame) for frame in frames], meta


def _sequence_safe_prepare_live_frames(
    frames: list[bytes],
    state: dict,
) -> tuple[list[bytes], dict]:
    """Apply the persistent physical DROP_LEAF offset outside v128 mode."""
    assembled = _ace_01_reassemble_frames(frames)
    if not assembled:
        return [bytes(frame) for frame in frames], {}
    ordered, logical = assembled
    shifted_logical, meta = _v128_shift_live_logical(
        logical,
        report_offset=0,
        leaf_offset=int(state.get("leaf_offset") or 0),
    )
    if shifted_logical == logical:
        return [bytes(frame) for frame in ordered], meta
    rebuilt = _ace_refragment_from_first(
        ordered,
        shifted_logical,
        crc=(zlib.crc32(shifted_logical) & 0xFFFFFFFF).to_bytes(4, "big"),
        recorded_message_id=ordered[0][47],
    )
    return rebuilt or [bytes(frame) for frame in frames], meta


def _sequence_safe_compact_native_leaf_sequences(
    live_logical: bytes,
    output_frames: list[bytes],
) -> tuple[list[bytes], dict]:
    """Compact a physical DROP_LEAF and report its persistent leaf delta.

    A child leaf deletion shortens the Type9 plaintext, but the surviving
    recordSequence values still contain the deleted value.  Rewrite the
    surviving leaves as one contiguous run; the caller carries ``leaf_delta``
    into later native reports through the active connection leaf offset.
    """
    from core.type9_shadow import decode_material

    info = {
        "applied": False,
        "input_leaf_count": 0,
        "output_leaf_count": 0,
        "leaf_delta": 0,
        "before_sequences": [],
        "after_sequences": [],
    }
    assembled = _ace_01_reassemble_frames(output_frames)
    live_material = decode_material(live_logical)
    if not assembled or not live_material.get("ok"):
        return [bytes(frame) for frame in output_frames], info
    ordered, output_logical = assembled
    output_material = decode_material(output_logical)
    if not output_material.get("ok"):
        return [bytes(frame) for frame in output_frames], info

    live_leaves = list(live_material.get("leaves") or [])
    output_leaves = list(output_material.get("leaves") or [])
    info["input_leaf_count"] = len(live_leaves)
    info["output_leaf_count"] = len(output_leaves)
    info["leaf_delta"] = len(output_leaves) - len(live_leaves)
    if not output_leaves:
        return [bytes(frame) for frame in output_frames], info

    before = [
        int(leaf.get("record_sequence") or 0) for leaf in output_leaves
    ]
    if live_leaves:
        first_sequence = int(live_leaves[0].get("record_sequence") or 0)
    else:
        first_sequence = before[0]
    after = [
        (first_sequence + index) & 0xFFFFFFFF
        for index in range(len(output_leaves))
    ]
    info["before_sequences"] = before
    info["after_sequences"] = after
    if before == after:
        return [bytes(frame) for frame in output_frames], info

    plaintext = bytearray(output_material["plaintext"])
    for leaf, sequence in zip(output_leaves, after):
        start = int(leaf["start"])
        plaintext[start + 10:start + 14] = sequence.to_bytes(4, "big")
    compacted_logical = _v128_replace_type9_plaintext(
        output_logical,
        bytes(plaintext),
    )
    if not compacted_logical:
        return [bytes(frame) for frame in output_frames], info
    rebuilt = _ace_refragment_from_first(
        ordered,
        compacted_logical,
        crc=(zlib.crc32(compacted_logical) & 0xFFFFFFFF).to_bytes(4, "big"),
        recorded_message_id=ordered[0][47],
    )
    if not rebuilt:
        return [bytes(frame) for frame in output_frames], info
    info["applied"] = True
    return rebuilt, info


def _v128_build_injected_frames(
    base_frames: list[bytes],
    base_logical: bytes,
    groups: list[dict],
    state: dict,
    *,
    expected_game_id: str = "",
) -> tuple[list[bytes], dict]:
    """Build independent Type9 reports immediately after the native report."""
    from core.type9_stable_80xx_insert import assemble_batch, stamp_inserted_leaf
    from core.type9_v128_replenish import (
        PLAYER_CROSS_ACCOUNT_BLOCKED_MESSAGE_IDS,
        PLAYER_INDIVIDUAL_MESSAGE_IDS,
        rebuild_player_message_enabled,
        stamp_player_supplement_leaf,
        stamp_strong_profile_leaf,
    )

    if not groups or not base_frames:
        return [], {"groups": [], "leaf_count": 0, "frame_count": 0}
    base_report = _ace_01_report_index(base_logical)
    if base_report is None:
        return [], {"groups": [], "leaf_count": 0, "frame_count": 0}
    last_frame_sequence = int.from_bytes(base_frames[-1][8:10], "big")
    last_group = int.from_bytes(base_frames[0][36:38], "big")
    next_leaf_sequence = int(state.get("last_output_leaf_sequence") or 0)
    injected_frames: list[bytes] = []
    group_logs = []

    for group_index, planned in enumerate(groups, 1):
        slot = int(planned["slot"])
        layer = str(planned.get("layer") or "central9")
        if layer == "player_same_device":
            # Final injection guard: planner filtering is not the sole authority.
            # This prevents stale groups from an old template/config from being
            # emitted after a checkbox or account context changed.
            filtered_rows = []
            for row in planned.get("rows") or []:
                message_id = int(row.get("message_id") or 0)
                if (
                    message_id in PLAYER_INDIVIDUAL_MESSAGE_IDS
                    and not rebuild_player_message_enabled(message_id)
                ):
                    continue
                if (
                    bool(app_config.get("rebuild_controls_v3", False))
                    and
                    bool(row.get("cross_account_device"))
                    and message_id in PLAYER_CROSS_ACCOUNT_BLOCKED_MESSAGE_IDS
                ):
                    continue
                filtered_rows.append(row)
            if not filtered_rows:
                continue
            planned = dict(planned)
            planned["rows"] = filtered_rows
        children = []
        ids = []
        first_leaf_sequence = next_leaf_sequence + 1
        for row in planned["rows"]:
            next_leaf_sequence += 1
            if layer == "player_same_device":
                stamper = stamp_player_supplement_leaf
            elif layer == "central_strong":
                stamper = stamp_strong_profile_leaf
            else:
                stamper = stamp_inserted_leaf
            leaf = stamper(bytes(row["raw"]), sequence=next_leaf_sequence, version=1)
            if not leaf:
                return [], {"groups": [], "leaf_count": 0, "frame_count": 0}
            leaf_bytes = bytearray(leaf)
            leaf_bytes[0x1C:0x1E] = (slot & 0xFFFF).to_bytes(2, "big")
            children.append(bytes(leaf_bytes))
            ids.append(int(row["message_id"]))
        plaintext = assemble_batch(children, version=1, sequence=0)
        logical = _v128_replace_type9_plaintext(base_logical, plaintext)
        if not logical:
            return [], {"groups": [], "leaf_count": 0, "frame_count": 0}
        logical = _v128_set_report_index(logical, base_report + group_index)
        frames = _ace_refragment_from_first(
            base_frames,
            logical,
            crc=(zlib.crc32(logical) & 0xFFFFFFFF).to_bytes(4, "big"),
            recorded_message_id=base_frames[0][47],
        )
        frames = _v128_restamp_transport(
            frames,
            first_sequence=last_frame_sequence + 1,
            group=last_group + 1,
        )
        checked = _ace_01_verify_frames(
            frames,
            expected_game_id=expected_game_id,
        )
        if not checked.get("ok"):
            return [], {
                "groups": group_logs,
                "leaf_count": 0,
                "frame_count": 0,
                "error": ";".join(checked.get("errors") or []),
            }
        injected_frames.extend(frames)
        last_frame_sequence = int.from_bytes(frames[-1][8:10], "big")
        last_group = int.from_bytes(frames[0][36:38], "big")
        group_logs.append(
            {
                "slot": slot,
                "layer": layer,
                "template_session_id": str(
                    planned.get("template_session_id") or ""
                ),
                "report_index": base_report + group_index,
                "leaf_sequence_start": first_leaf_sequence,
                "leaf_sequence_end": next_leaf_sequence,
                "message_ids": [f"0x{value:04X}" for value in ids],
                "player_identities": [
                    str(row.get("identity") or "")
                    for row in planned["rows"]
                    if row.get("identity")
                ],
                "rebuilt_fields": sorted({
                    f"0x{int(row['message_id']):04X}:{field}"
                    for row in planned["rows"]
                    for field in (row.get("rebuilt_fields") or [])
                }),
                "frame_count": len(frames),
            }
        )

    leaf_count = sum(len(group["rows"]) for group in groups)
    state["last_output_leaf_sequence"] = next_leaf_sequence
    state["report_offset"] = int(state.get("report_offset") or 0) + len(groups)
    state["leaf_offset"] = int(state.get("leaf_offset") or 0) + leaf_count
    state["frame_offset"] = int(state.get("frame_offset") or 0) + len(
        injected_frames
    )
    state["group_offset"] = int(state.get("group_offset") or 0) + len(groups)
    state["injected_report_count"] = int(
        state.get("injected_report_count") or 0
    ) + len(groups)
    state["injected_leaf_count"] = int(state.get("injected_leaf_count") or 0) + leaf_count
    player_leaf_count = sum(
        len(group["rows"])
        for group in groups
        if str(group.get("layer") or "") == "player_same_device"
    )
    if player_leaf_count:
        player_state = state.setdefault("same_device_player", {})
        player_state["injected_leaf_count"] = int(
            player_state.get("injected_leaf_count") or 0
        ) + player_leaf_count
        emitted_identities = {
            str(value)
            for value in player_state.get("emitted_identities") or []
        }
        emitted_identities.update(
            str(row.get("identity") or "")
            for group in groups
            for row in group["rows"]
            if str(group.get("layer") or "") == "player_same_device"
            and row.get("identity")
        )
        player_state["emitted_identities"] = sorted(emitted_identities)
    strong_leaf_count = sum(
        len(group["rows"])
        for group in groups
        if str(group.get("layer") or "") == "central_strong"
    )
    if strong_leaf_count:
        strong_state = state.setdefault("strong_profile", {})
        strong_state["injected_leaf_count"] = int(
            strong_state.get("injected_leaf_count") or 0
        ) + strong_leaf_count
    return injected_frames, {
        "groups": group_logs,
        "leaf_count": leaf_count,
        "frame_count": len(injected_frames),
    }


def _ace_try_replace_frames(
    frames: list[bytes],
    pool: list[dict],
    pool_index: list,
    on_log=None,
    *,
    length_pick_tol: int | None = None,
) -> tuple[list[bytes], bool]:
    """
    收齐物理分片后重组逻辑 payload、替换目标记录、重算 CRC32 并重新分片。
    单片和多片使用同一条字段重建路径。
    """
    assembled = _ace_01_reassemble_frames(frames)
    if not assembled:
        return frames, False
    ordered, logical = assembled
    virtual = bytearray(ordered[0][:55])
    virtual += logical
    virtual[3:5] = len(virtual).to_bytes(2, "big")
    virtual[38:40] = (1).to_bytes(2, "big")
    virtual[44] = 1
    virtual[49:51] = (1).to_bytes(2, "big")
    virtual[51:55] = len(logical).to_bytes(4, "big")

    captured: list[dict] = []
    replaced_virtual, changed = _ace_try_replace(
        bytes(virtual),
        pool,
        pool_index,
        on_log=captured.append,
        length_pick_tol=length_pick_tol,
    )
    if not changed:
        return ordered, False
    new_logical = replaced_virtual[55:]
    new_crc = bytes(replaced_virtual[40:44])
    recorded_message_id = replaced_virtual[47]
    rebuilt = _ace_refragment_from_first(
        ordered,
        new_logical,
        crc=new_crc,
        recorded_message_id=recorded_message_id,
    )
    if captured and on_log:
        detail = captured[0]
        detail.update(
            {
                "orig_packet": b"".join(ordered),
                "new_packet": b"".join(rebuilt),
                "orig_pkt_len": sum(map(len, ordered)),
                "new_pkt_len": sum(map(len, rebuilt)),
                "fragment_count_before": len(ordered),
                "fragment_count_after": len(rebuilt),
            }
        )
        on_log(detail)
    return rebuilt, True


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
    new_packet, old_crc, new_crc = _ace_finalize_single_frame(
        new_buf,
        recorded_message_id=item.get("routing") or b"",
    )
    orig_len = tail_len
    detail = {
        "pool_idx": idx,
        "pool_total": len(pool),
        "orig_payload_len": orig_len,
        "new_payload_len": len(new_tail),
        "orig_pkt_len": len(packet),
        "new_pkt_len": len(new_buf),
        "crc_hex": new_crc.hex().upper(),
        "old_crc_hex": old_crc.hex().upper(),
        "template_crc_hex": (item.get("crc") or b"").hex().upper(),
        "routing_hex": (item.get("routing") or b"\0")[:1].hex().upper(),
        "account_id": item.get("account_id", ""),
        "payload_preview": new_tail[:64],
        "orig_packet": bytes(packet),
        "new_packet": new_packet,
        "replace_mode": "length_fallback",
    }
    if on_log:
        on_log(detail)
    return new_packet, True


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
    record = _ace_find_encrypted_record(packet)
    if record is None:
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

    replace_start, replace_end, _raw_start, _kind = record
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

    orig_len = replace_end - replace_start
    idx: int
    item: dict
    pick_mode = "anchor"
    best_d: int | None = None
    if length_pick_tol is not None and length_pick_tol >= 0:
        candidates: list[tuple[int, int]] = []
        for i, it in enumerate(pool):
            pl = _ace_normalize_pool_record(it)
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
        idx = pool_index[0] % len(pool)
        item = pool[idx]
        pool_index[0] += 1  # 保持绝对递增，当 pool 动态扩展时能自然顺延到新数据
    new_payload = _ace_normalize_pool_record(item)
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
    new_buf[replace_start + len(new_payload):] = packet[replace_end:]

    new_packet, old_crc, new_crc = _ace_finalize_single_frame(
        new_buf,
        recorded_message_id=item.get("routing") or b"",
    )

    detail = {
        "pool_idx": idx,
        "pool_total": len(pool),
        "orig_payload_len": orig_len,
        "new_payload_len": len(new_payload),
        "orig_pkt_len": len(packet),
        "new_pkt_len": len(new_packet),
        "crc_hex": new_crc.hex().upper(),
        "old_crc_hex": old_crc.hex().upper(),
        "template_crc_hex": (item.get("crc") or b"").hex().upper(),
        "routing_hex": (item.get("routing") or b"\0")[:1].hex().upper(),
        "account_id": item.get("account_id", ""),
        "payload_preview": new_payload[:64],  # 前64字节预览
        "orig_packet": bytes(packet),
        "new_packet": new_packet,
        "replace_mode": pick_mode,
        "anchor_kind": _kind,
    }
    if length_pick_tol is not None:
        detail["length_pick_tol"] = length_pick_tol
    if pick_mode == "anchor_length":
        detail["length_pick_best_delta"] = best_d
    if on_log:
        on_log(detail)
    return new_packet, True


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
                if pool_33_09:
                    idx = index_33_09[0] % len(pool_33_09)
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
                    idx = idx_ref[0] % len(matches_01)
                    used_idx = idx
                    item = matches_01[idx][0]
                    idx_ref[0] = (idx + 1) % len(matches_01)
                elif pool_33_09:
                    used_src = "33池"
                    idx_ref = index_33_09
                    idx = idx_ref[0] % len(pool_33_09)
                    used_idx = idx
                    item = pool_33_09[idx]
                    idx_ref[0] = (idx + 1) % len(pool_33_09)
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
                        idx = idx_ref[0] % len(matches_01)
                        used_idx = idx
                        item = matches_01[idx][0]
                        idx_ref[0] = (idx + 1) % len(matches_01)
            else:
                if pool_33_21:
                    idx_ref = index_33_21
                    idx = idx_ref[0] % len(pool_33_21)
                    used_idx = idx
                    item = pool_33_21[idx]
                    idx_ref[0] = (idx + 1) % len(pool_33_21)

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
        # 不要求纯数字，有些游戏（如王者荣耀）使用字母/混合ID
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
