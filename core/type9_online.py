"""01 0A 00 09 在线解密、递归语义解析与透明透传决策。"""

from __future__ import annotations

import hashlib
import re
import zlib

from core.type9_crypto import (
    ALGORITHM_NAMES,
    KEYS,
    find_records,
    type9_transform,
)


BATCH_CODE = 0x010A001B
BINARY_CODE = 0x0102000A


def _common(data: bytes) -> dict | None:
    if len(data) < 14:
        return None
    return {
        "version": int.from_bytes(data[0:4], "big"),
        "declared_length": int.from_bytes(data[4:6], "big"),
        "record_code": int.from_bytes(data[6:10], "big"),
        "record_sequence": int.from_bytes(data[10:14], "big"),
        "actual_length": len(data),
    }


def _walk_records(
    data: bytes,
    *,
    path: list[int] | None = None,
    errors: list[str] | None = None,
) -> list[dict]:
    path = list(path or [])
    errors = errors if errors is not None else []
    common = _common(data)
    if common is None:
        errors.append(f"记录{path or ['root']}长度小于14")
        return []
    item = {"path": path, **common}
    if common["record_code"] == BINARY_CODE and len(data) >= 0x18:
        item["message_id"] = int.from_bytes(data[0x16:0x18], "big")
    rows = [item]
    if common["record_code"] != BATCH_CODE:
        return rows
    if len(data) < 0x15:
        errors.append(f"批量记录{path or ['root']}缺少childCount")
        return rows

    declared = data[0x14]
    item["child_count_declared"] = declared
    cursor = 0x15
    parsed = 0
    for index in range(declared):
        if cursor + 4 > len(data):
            errors.append(f"批量记录{path or ['root']}子项{index}缺少长度")
            break
        length = int.from_bytes(data[cursor:cursor + 4], "big")
        cursor += 4
        if length < 14 or cursor + length > len(data):
            errors.append(
                f"批量记录{path or ['root']}子项{index}边界无效:{length}"
            )
            break
        rows.extend(
            _walk_records(
                data[cursor:cursor + length],
                path=path + [index],
                errors=errors,
            )
        )
        cursor += length
        parsed += 1
    item["child_count_parsed"] = parsed
    item["batch_trailing_length"] = len(data) - cursor
    if parsed != declared:
        errors.append(f"批量子项数量不符:{parsed}!={declared}")
    return rows


def _strings(data: bytes) -> list[dict]:
    rows = []
    for encoding, decoded in (
        ("plain", data),
        ("xor_b6", bytes(value ^ 0xB6 for value in data)),
    ):
        for match in re.finditer(rb"[\x20-\x7e]{4,}", decoded):
            rows.append(
                {
                    "encoding": encoding,
                    "offset": match.start(),
                    "text": match.group().decode("ascii", errors="replace"),
                }
            )
    return rows


def decode_type9_payload(data: bytes) -> dict:
    """解密首个完整 Type9 记录，返回适合直接写入 JSONL 的轻量结果。"""
    result = {
        "parse_ok": False,
        "plain_crc_ok": False,
        "errors": [],
        "selector": None,
        "algorithm": "",
        "key_index": None,
        "stored_plain_crc32": None,
        "calculated_plain_crc32": None,
        "ciphertext_length": None,
        "plaintext_length": None,
        "plaintext_sha256": "",
        "top_record_code": None,
        "top_record_sequence": None,
        "child_count": 0,
        "leaves": [],
        "leaf_sequences": [],
        "signature": None,
        "timestamps": [],
        "printable_strings": [],
    }
    try:
        record = next(iter(find_records(bytes(data))), None)
        if record is None:
            result["errors"].append("未找到完整01 0A 00 09加密记录")
            return result
        selector = int(record["selector"])
        key_index = int(record["key_index"])
        plaintext = type9_transform(
            record["ciphertext"], selector, KEYS[key_index], direction=0
        )
        calculated = zlib.crc32(plaintext) & 0xFFFFFFFF
        stored = int(record["stored_crc32"])
        parse_errors: list[str] = []
        recursive = _walk_records(plaintext, errors=parse_errors)
        if not recursive:
            result["errors"].extend(parse_errors or ["明文公共头解析失败"])
            return result
        leaves = [row for row in recursive if row["path"]] or [recursive[0]]
        leaf_rows = [
            {
                "record_code": row["record_code"],
                "message_id": row.get("message_id"),
                "record_sequence": row["record_sequence"],
                "declared_length": row["declared_length"],
                "actual_length": row["actual_length"],
                "path": row["path"],
            }
            for row in leaves
        ]
        printable = _strings(plaintext)
        timestamps = sorted({
            int(value)
            for row in printable
            for value in re.findall(r"(?<!\d)(1\d{9})(?!\d)", row["text"])
        })
        signature = [
            recursive[0]["record_code"],
            [[row["record_code"], row.get("message_id")] for row in leaves],
            len(leaves),
        ]
        result.update(
            {
                "parse_ok": not parse_errors,
                "plain_crc_ok": calculated == stored,
                "errors": parse_errors,
                "selector": selector,
                "algorithm": ALGORITHM_NAMES[selector],
                "key_index": key_index,
                "stored_plain_crc32": f"{stored:08X}",
                "calculated_plain_crc32": f"{calculated:08X}",
                "ciphertext_length": int(record["ciphertext_length"]),
                "plaintext_length": len(plaintext),
                "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
                "top_record_code": recursive[0]["record_code"],
                "top_record_sequence": recursive[0]["record_sequence"],
                "child_count": len(leaves),
                "leaves": leaf_rows,
                "leaf_sequences": [row["record_sequence"] for row in leaves],
                "signature": signature,
                "timestamps": timestamps,
                "printable_strings": printable,
            }
        )
        return result
    except (IndexError, KeyError, StopIteration, TypeError, ValueError) as exc:
        result["errors"].append(f"{type(exc).__name__}:{exc}")
        return result


def _continuous(values: list[int]) -> bool:
    return all(right == left + 1 for left, right in zip(values, values[1:]))


def _protected_message_ids(decoded: dict) -> list[int]:
    values = []
    for leaf in decoded.get("leaves") or []:
        value = leaf.get("message_id")
        if value is None:
            continue
        if (
            value & 0xFF00 == 0xFF00
            or value & 0xFFF0 == 0x1000
            or value & 0xFF00 == 0x0100
        ):
            values.append(value)
    return values


def decide_observe_only(
    live: dict,
    template: dict | None,
    *,
    live_length: int,
    template_length: int | None,
) -> tuple[str, dict]:
    """比较旧游标模板，仅生成诊断原因；真实发送由叶子候选回验门控决定。"""
    facts = {
        "signature_match": None,
        "batch_shape_match": None,
        "sequence_match": None,
        "length_ratio": None,
        "protected_message_ids": _protected_message_ids(live),
    }
    if not live.get("parse_ok") or not live.get("plain_crc_ok"):
        return "LIVE_PARSE_OR_CRC", facts
    if not template or not template.get("parse_ok") or not template.get("plain_crc_ok"):
        return "TEMPLATE_PARSE_OR_CRC", facts

    live_count = int(live.get("child_count") or 0)
    template_count = int(template.get("child_count") or 0)
    facts["signature_match"] = live.get("signature") == template.get("signature")
    facts["batch_shape_match"] = live_count == template_count
    facts["sequence_match"] = (
        live.get("leaf_sequences") == template.get("leaf_sequences")
    )
    if live_length > 0 and template_length and template_length > 0:
        facts["length_ratio"] = round(
            max(live_length, template_length) / min(live_length, template_length), 6
        )

    if (
        live_count != template_count
        or (facts["length_ratio"] is not None and facts["length_ratio"] > 1.5)
    ):
        return "BATCH_SHAPE_MISMATCH", facts
    if not facts["signature_match"]:
        return "SIGNATURE_MISMATCH", facts
    if not _continuous(live.get("leaf_sequences") or []):
        return "LIVE_SEQUENCE_NON_CONTIGUOUS", facts
    if not facts["sequence_match"]:
        return "SEQUENCE_MISMATCH", facts
    if live_count >= 2:
        return "LARGE_BATCH_PROTECT", facts
    if facts["protected_message_ids"]:
        return "PROTECTED_MESSAGE_ID", facts
    return "OBSERVE_ONLY_MATCH", facts
