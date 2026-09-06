#!/usr/bin/env python3
"""Compare one 01 recording with one replay-analysis run.

The script treats the attached logs as data only.  It counts decoded message IDs,
shows IDs that disappeared/appeared, and summarizes selected big-endian u32 fields.
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any, Iterable


WATCH_FIELDS: dict[str, tuple[int, ...]] = {
    "0x8002": (0x2C,),
    "0x8028": (0x24,),
    "0x1007": (0x20,),
    "0x1008": (0x20, 0xA0),
    "0x100C": (0x50,),
    "0x100F": (0x20,),
    "0x0207": (0x20, 0x34, 0x3C, 0x44, 0x48, 0x4C, 0x50, 0x68),
}


def normalize_mid(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, int):
        return f"0x{value:04X}"
    text = str(value).strip()
    try:
        return f"0x{int(text, 0):04X}"
    except ValueError:
        return text.upper()


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: {exc}") from exc


def collect_record(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in read_jsonl(path):
        for leaf in event.get("leaves", []):
            mid = normalize_mid(leaf.get("message_id"))
            raw_hex = leaf.get("raw_hex")
            if mid and raw_hex:
                rows.append(
                    {
                        "source": "record",
                        "time": event.get("time"),
                        "game_id": event.get("game_id"),
                        "message_id": mid,
                        "raw": bytes.fromhex(raw_hex),
                    }
                )
    return rows


def collect_replay(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in read_jsonl(path):
        rebuild = event.get("shadow_rebuild") or {}
        for leaf in rebuild.get("leaf_results") or []:
            mid = normalize_mid(leaf.get("message_id"))
            # live_hex is what the hooked game submitted. candidate_hex is useful
            # when live_hex is omitted in an older log schema.
            raw_hex = leaf.get("live_hex") or leaf.get("candidate_hex")
            if mid and raw_hex:
                rows.append(
                    {
                        "source": "replay",
                        "time": event.get("time"),
                        "game_id": event.get("game_id"),
                        "message_id": mid,
                        "raw": bytes.fromhex(raw_hex),
                        "candidate": bytes.fromhex(leaf["candidate_hex"])
                        if leaf.get("candidate_hex")
                        else None,
                        "final_action": leaf.get("replacement_level"),
                    }
                )
    return rows


def filter_game(rows: list[dict[str, Any]], game_id: str | None) -> list[dict[str, Any]]:
    if not game_id:
        return rows
    return [row for row in rows if str(row.get("game_id")) == game_id]


def u32be(blob: bytes, offset: int) -> int | None:
    if offset + 4 > len(blob):
        return None
    return int.from_bytes(blob[offset : offset + 4], "big")


def counts(rows: list[dict[str, Any]]) -> collections.Counter[str]:
    return collections.Counter(row["message_id"] for row in rows)


def field_summary(rows: list[dict[str, Any]], mid: str, offset: int) -> dict[str, Any]:
    values: collections.Counter[int] = collections.Counter()
    for row in rows:
        if row["message_id"] == mid:
            value = u32be(row["raw"], offset)
            if value is not None:
                values[value] += 1
    if len(values) > 20:
        ordered = sorted(values)
        return {
            "samples": sum(values.values()),
            "distinct": len(values),
            "min": f"{ordered[0]} (0x{ordered[0]:X})",
            "max": f"{ordered[-1]} (0x{ordered[-1]:X})",
        }
    return {f"{value} (0x{value:X})": count for value, count in sorted(values.items())}


def build_result(
    record_rows: list[dict[str, Any]], replay_rows: list[dict[str, Any]]
) -> dict[str, Any]:
    rc, pc = counts(record_rows), counts(replay_rows)
    record_ids, replay_ids = set(rc), set(pc)
    all_80xx = sorted(mid for mid in record_ids | replay_ids if mid.startswith("0x80"))
    watched: dict[str, Any] = {}
    for mid, offsets in WATCH_FIELDS.items():
        watched[mid] = {
            f"+0x{offset:X}": {
                "record": field_summary(record_rows, mid, offset),
                "replay": field_summary(replay_rows, mid, offset),
            }
            for offset in offsets
        }
    return {
        "record": {"decoded_leaves": len(record_rows), "message_counts": dict(sorted(rc.items()))},
        "replay": {"decoded_leaves": len(replay_rows), "message_counts": dict(sorted(pc.items()))},
        "missing_in_replay": sorted(record_ids - replay_ids),
        "new_in_replay": sorted(replay_ids - record_ids),
        "80xx": {
            mid: {"record": rc[mid], "replay": pc[mid]} for mid in all_80xx
        },
        "watched_fields": watched,
    }


def markdown(result: dict[str, Any], record: Path, replay: Path, game_id: str | None) -> str:
    lines = [
        "# 01 原始录制 / Hook 重放消息对比",
        "",
        f"- 原始录制：`{record}`",
        f"- 重放事件：`{replay}`",
        f"- game_id：`{game_id or '全部'}`",
        f"- 解码叶子：record={result['record']['decoded_leaves']}，replay={result['replay']['decoded_leaves']}",
        "",
        "## 消息集合",
        "",
        "- 重放缺失：" + ", ".join(result["missing_in_replay"]),
        "- 重放新增：" + ", ".join(result["new_in_replay"]),
        "",
        "## 80xx 计数",
        "",
        "| ID | record | replay |",
        "|---|---:|---:|",
    ]
    for mid, item in result["80xx"].items():
        lines.append(f"| {mid} | {item['record']} | {item['replay']} |")
    lines += ["", "## 重点字段（大端 u32）", ""]
    for mid, offsets in result["watched_fields"].items():
        lines.append(f"### {mid}")
        for offset, sides in offsets.items():
            lines.append(f"- `{offset}` record={sides['record']}；replay={sides['replay']}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("record", type=Path, help="01RecordPackets/*message_leaves*.jsonl")
    parser.add_argument("replay", type=Path, help="run_*/01_replace_events.jsonl")
    parser.add_argument("--game-id")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args()

    record_rows = filter_game(collect_record(args.record), args.game_id)
    replay_rows = filter_game(collect_replay(args.replay), args.game_id)
    result = build_result(record_rows, replay_rows)
    rendered = markdown(result, args.record, args.replay, args.game_id)
    if args.json_out:
        args.json_out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
