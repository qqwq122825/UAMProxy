"""只收录已经坐实、对比时必然变化且不是检测信号的字段。

不要把“看起来像时钟”的东西加进来。宽度或偏移对不上就不命中。
"""

from __future__ import annotations

from tools.compare_01_message_ids import parse_int

# message_id 为 None 表示任意消息；leaf_offset 为 None 表示该消息整叶。
FIELD_WHITELIST = (
    {
        "message_id": 0x2001,
        "leaf_offset": 0x20,
        "width": 4,
        "reason": "已坐实60Hz时钟，约30秒+1800，不是写视角/行为计数",
    },
    {
        "message_id": 0x2001,
        "leaf_offset": 0x20,
        "width": 2,
        "reason": "同上，扫描器有时按2字节切开时钟高位",
    },
    {
        "message_id": 0x8024,
        "leaf_offset": None,
        "width": None,
        "reason": "已坐实时间戳叶，不同会话必然不同，必须跟Live",
    },
)


def whitelist_reason(row: dict) -> str | None:
    message_id = parse_int(row.get("message_id"))
    offset = row.get("leaf_offset")
    if offset is None:
        text = str(row.get("leaf_offset_hex") or "")
        if text.lower().startswith("0x"):
            offset = int(text, 16)
    width = row.get("width")
    for rule in FIELD_WHITELIST:
        if rule["message_id"] is not None and rule["message_id"] != message_id:
            continue
        if rule["leaf_offset"] is None:
            return str(rule["reason"])
        if offset != rule["leaf_offset"]:
            continue
        if rule["width"] is not None and width != rule["width"]:
            continue
        return str(rule["reason"])
    return None


def split_anomalies(anomalies: list[dict]) -> tuple[list[dict], list[dict]]:
    kept = []
    ignored = []
    for row in anomalies:
        reason = whitelist_reason(row)
        if reason:
            ignored.append({**row, "whitelist_reason": reason})
        else:
            kept.append(row)
    return kept, ignored


def group_by_message(anomalies: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in anomalies:
        key = str(row.get("message_id") or row.get("shape") or "unknown")
        grouped.setdefault(key, []).append(row)
    return grouped
