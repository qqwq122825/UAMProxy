"""跨设备已坐实的 80xx 插叶。

只处理正文跨设备相同的 11 个 ID。模板必须来自当前连接的录制池；
录制没有的档位不编造。时间表用录制 ``report_index``，由 Live 报告序号触发，
不另开定时器、不按账号建表。
"""

from __future__ import annotations

from typing import Any, Iterable


BINARY_CODE = 0x0102000A
BATCH_CODE = 0x010A001B

# 125.1 跨 iOS26 / iOS16 正文逐字节相同；绿玩与 Hook 都不改这些常量。
STABLE_INSERT_MESSAGE_IDS = frozenset(
    {
        0x8000,
        0x8002,
        0x8003,
        0x8004,
        0x800B,
        0x8020,
        0x8021,
        0x8025,
        0x8028,
        0x802A,
        0x802B,
    }
)
# 同一报告里的 9 片哈希必须一起插或一起让 Live 覆盖。
CLUSTER_INSERT_MESSAGE_IDS = frozenset({0x8004})


def is_stable_insert_message(message_id: int | None) -> bool:
    return message_id is not None and int(message_id) in STABLE_INSERT_MESSAGE_IDS


def sanitize_insert_leaf(raw: bytes) -> bytes:
    """录制正文原样使用，只强制干净的 8028/8002 计数字段。"""
    if len(raw) < 0x18:
        return b""
    if int.from_bytes(raw[6:10], "big") != BINARY_CODE:
        return b""
    message_id = int.from_bytes(raw[0x16:0x18], "big")
    if message_id not in STABLE_INSERT_MESSAGE_IDS:
        return b""
    out = bytearray(raw)
    out[4:6] = len(out).to_bytes(2, "big")
    if message_id == 0x8028 and len(out) >= 0x28:
        out[0x20:0x24] = (7).to_bytes(4, "big")
        out[0x24:0x28] = (0).to_bytes(4, "big")
    elif message_id == 0x8002 and len(out) >= 0x30:
        out[0x2C:0x30] = (0).to_bytes(4, "big")
    return bytes(out)


def stamp_inserted_leaf(raw: bytes, *, sequence: int, version: int) -> bytes:
    cleaned = sanitize_insert_leaf(raw)
    if not cleaned:
        return b""
    out = bytearray(cleaned)
    out[0:4] = int(version).to_bytes(4, "big")
    out[4:6] = len(out).to_bytes(2, "big")
    out[10:14] = int(sequence).to_bytes(4, "big")
    return bytes(out)


def slot_id(row: dict) -> str:
    return (
        f"{row.get('template_session_id') or 'legacy'}:"
        f"{int(row['report_index'])}:"
        f"{int(row['message_id']):04X}:"
        f"{int(row['record_sequence'])}"
    )


def build_insert_schedule(template_rows: Iterable[dict]) -> list[dict]:
    """从录制叶子建时间表。没有 report_index 或洗不干净的叶子直接丢掉。"""
    by_session: dict[str, list[dict]] = {}
    for row in template_rows:
        raw = row.get("raw")
        if not isinstance(raw, (bytes, bytearray)) or len(raw) < 0x18:
            continue
        if int.from_bytes(raw[6:10], "big") != BINARY_CODE:
            continue
        message_id = int.from_bytes(raw[0x16:0x18], "big")
        if message_id not in STABLE_INSERT_MESSAGE_IDS:
            continue
        report_index = row.get("report_index")
        if report_index is None:
            continue
        cleaned = sanitize_insert_leaf(bytes(raw))
        if not cleaned:
            continue
        session_id = str(row.get("template_session_id") or "legacy")
        slot = {
            "id": slot_id(
                {
                    "template_session_id": session_id,
                    "report_index": int(report_index),
                    "message_id": message_id,
                    "record_sequence": int(row.get("record_sequence") or 0),
                }
            ),
            "template_session_id": session_id,
            "report_index": int(report_index),
            "message_id": message_id,
            "record_sequence": int(row.get("record_sequence") or 0),
            "raw": cleaned,
        }
        by_session.setdefault(session_id, []).append(slot)
    if not by_session:
        return []
    session_id = max(
        by_session,
        key=lambda key: (
            len({item["message_id"] for item in by_session[key]}),
            len(by_session[key]),
        ),
    )
    return sorted(
        by_session[session_id],
        key=lambda item: (item["report_index"], item["message_id"], item["record_sequence"]),
    )


def live_stable_message_ids(live_message_ids: Iterable[int | None]) -> set[int]:
    return {
        int(message_id)
        for message_id in live_message_ids
        if is_stable_insert_message(message_id)
    }


def note_live_80xx(state: dict, live_message_ids: Iterable[int | None]) -> set[int]:
    """Live 一旦出现稳定 80xx，整条连接关闭插叶。"""
    seen = {int(value) for value in (state.get("live_seen_80xx") or [])}
    seen.update(live_stable_message_ids(live_message_ids))
    if seen:
        state["live_seen_80xx"] = sorted(seen)
        state["disabled"] = True
    return seen


def plan_inserts(
    schedule: list[dict],
    *,
    live_report_index: int | None,
    live_message_ids: Iterable[int | None],
    consumed: Iterable[str] | None = None,
    connection_disabled: bool = False,
) -> list[dict]:
    """只插当前报告序号这一档。

    Live 这条连接只要出现过任一稳定 80xx，整条连接都不再插。
    录制没有对应档位不编造。
    """
    if (
        connection_disabled
        or live_report_index is None
        or not schedule
        or live_stable_message_ids(live_message_ids)
    ):
        return []
    used = set(consumed or ())
    planned: list[dict] = []
    for slot in schedule:
        if slot["id"] in used:
            continue
        if int(slot["report_index"]) != int(live_report_index):
            continue
        planned.append(dict(slot))
    return planned


def ensure_insert_state(
    state: dict | None,
    template_rows: Iterable[dict],
    *,
    refresh: bool = False,
) -> dict:
    current = dict(state or {})
    if current.get("schedule") is None or refresh:
        current["schedule"] = build_insert_schedule(template_rows)
        current.setdefault("consumed", [])
    current.setdefault("consumed", [])
    current.setdefault("live_seen_80xx", [])
    current.setdefault("disabled", False)
    return current


def mark_consumed(state: dict, slots: Iterable[dict]) -> None:
    consumed = set(state.get("consumed") or [])
    for slot in slots:
        slot_key = str(slot.get("id") or "")
        if slot_key:
            consumed.add(slot_key)
    state["consumed"] = sorted(consumed)


def wrap_root_as_batch(root_raw: bytes, children: list[bytes]) -> bytes:
    """根叶升成容器再追加插叶，避免新开一条 01。"""
    if int.from_bytes(root_raw[6:10], "big") == BATCH_CODE:
        raise ValueError("root is already a batch")
    version = int.from_bytes(root_raw[0:4], "big")
    sequence = int.from_bytes(root_raw[10:14], "big")
    all_children = [root_raw, *children]
    return assemble_batch(all_children, version=version, sequence=sequence)


def assemble_batch(
    children: list[bytes],
    *,
    version: int,
    sequence: int,
    trailer: bytes = b"",
) -> bytes:
    header = bytearray(21)
    header[0:4] = int(version).to_bytes(4, "big")
    header[6:10] = BATCH_CODE.to_bytes(4, "big")
    header[10:14] = int(sequence).to_bytes(4, "big")
    header[0x14] = len(children)
    rebuilt = header + b"".join(
        len(child).to_bytes(4, "big") + child for child in children
    ) + trailer
    rebuilt[4:6] = len(rebuilt).to_bytes(2, "big")
    return bytes(rebuilt)


def append_batch_children(batch_raw: bytes, extra: list[bytes]) -> bytes:
    if len(batch_raw) < 0x15 or int.from_bytes(batch_raw[6:10], "big") != BATCH_CODE:
        raise ValueError("not a batch")
    cursor = 0x15
    children: list[bytes] = []
    for _ in range(batch_raw[0x14]):
        child_length = int.from_bytes(batch_raw[cursor:cursor + 4], "big")
        cursor += 4
        children.append(batch_raw[cursor:cursor + child_length])
        cursor += child_length
    trailer = batch_raw[cursor:]
    return assemble_batch(
        children + extra,
        version=int.from_bytes(batch_raw[0:4], "big"),
        sequence=int.from_bytes(batch_raw[10:14], "big"),
        trailer=trailer,
    )
