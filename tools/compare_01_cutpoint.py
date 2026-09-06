#!/usr/bin/env python3
"""Compare decoded DFM 01 leaves before and after a game_target_09 cutpoint.

The input is a run directory containing ``01_replace_events.jsonl``.  The tool
uses the already decoded ``shadow_rebuild.leaf_results`` records, so it is fast
and does not need to decrypt the original frames again.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path
from typing import Any, Iterable


WATCH_FIELDS = {
    0x8028: (0x24, "activity_counter"),
    0x8002: (0x2C, "status_word"),
    0x100C: (0x50, "tail_status"),
    0x2001: (0x20, "periodic_step"),
}


def _read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_number}: {exc}") from exc
            if isinstance(value, dict):
                yield value


def _locate_run(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if path.is_file():
        return path.parent
    candidate = path / "01_replace_events.jsonl"
    if candidate.is_file():
        return path
    runs = sorted(path.glob("01ReplayAnalysis/run_*"))
    if len(runs) == 1 and (runs[0] / "01_replace_events.jsonl").is_file():
        return runs[0]
    raise SystemExit(f"未找到唯一运行目录: {path}")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _fmt_delta(seconds: float) -> str:
    sign = "+" if seconds >= 0 else "-"
    seconds = abs(seconds)
    minutes, remain = divmod(seconds, 60)
    if minutes:
        return f"{sign}{int(minutes)}m{remain:05.2f}s"
    return f"{sign}{remain:.3f}s"


def _hex_id(value: Any, width: int) -> str:
    return f"0x{int(value):0{width}X}" if isinstance(value, int) else "None"


def load_records(run: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    source = run / "01_replace_events.jsonl"
    for event in _read_jsonl(source):
        ordinals = event.get("ordinals") or {}
        game_target = int(ordinals.get("game_target_09") or 0)
        if game_target <= 0:
            continue
        event_row = {
            "game_target": game_target,
            "event_id": int(event.get("event_id") or 0),
            "time": str(event.get("time") or ""),
            "decision": str(event.get("decision") or ""),
            "final_equals_live": bool((event.get("checks") or {}).get("final_equals_live")),
            "final_equals_shadow": bool((event.get("checks") or {}).get("final_equals_shadow")),
        }
        events.append(event_row)
        for leaf in (event.get("shadow_rebuild") or {}).get("leaf_results") or []:
            try:
                live = bytes.fromhex(str(leaf.get("live_hex") or ""))
                candidate = bytes.fromhex(str(leaf.get("candidate_hex") or ""))
            except ValueError:
                continue
            records.append(
                {
                    **event_row,
                    "record_code": leaf.get("record_code"),
                    "message_id": leaf.get("message_id"),
                    "length": len(live),
                    "live": live,
                    "candidate": candidate,
                    "replacement_level": str(leaf.get("replacement_level") or ""),
                    "special_rule_id": str(leaf.get("special_rule_id") or ""),
                    "block_reason": str(leaf.get("block_reason") or ""),
                }
            )
    return events, records


def field_value(raw: bytes, offset: int, size: int = 4) -> int | None:
    if offset < 0 or offset + size > len(raw):
        return None
    return int.from_bytes(raw[offset : offset + size], "big")


def message_counts(records: list[dict[str, Any]], lo: int, hi: int) -> Counter:
    return Counter(
        (row["record_code"], row["message_id"])
        for row in records
        if lo <= row["game_target"] <= hi
    )


def stable_transitions(
    records: list[dict[str, Any]], cut: int
) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, Any, int], list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        grouped[(row["record_code"], row["message_id"], row["length"])].append(row)
    findings: list[dict[str, Any]] = []
    for key, rows in grouped.items():
        before = [row for row in rows if row["game_target"] < cut]
        after = [row for row in rows if row["game_target"] >= cut]
        if len(before) < 2 or not after:
            continue
        for offset in range(0x10, key[2] - 3, 4):
            before_values = [field_value(row["live"], offset) for row in before]
            after_values = [field_value(row["live"], offset) for row in after]
            before_set = set(before_values)
            after_set = set(after_values)
            kind = ""
            if before_set == {0} and after_set != {0}:
                kind = "ZERO_TO_NONZERO"
            elif len(before_set) == 1 and not after_set <= before_set and len(after_set) <= 8:
                kind = "STABLE_TO_CHANGE"
            if not kind:
                continue
            first = next(row for row in after if field_value(row["live"], offset) not in before_set)
            findings.append(
                {
                    "kind": kind,
                    "record_code": key[0],
                    "message_id": key[1],
                    "length": key[2],
                    "offset": offset,
                    "before_count": len(before),
                    "after_count": len(after),
                    "before_values": sorted(before_set),
                    "after_values": sorted(after_set),
                    "first_game_target": first["game_target"],
                    "first_time": first["time"],
                    "first_live_value": field_value(first["live"], offset),
                    "first_candidate_value": field_value(first["candidate"], offset),
                    "replacement_level": first["replacement_level"],
                    "special_rule_id": first["special_rule_id"],
                    "final_equals_live": first["final_equals_live"],
                    "final_equals_shadow": first["final_equals_shadow"],
                }
            )
    return sorted(findings, key=lambda row: (row["first_game_target"], row["offset"]))


def watch_timelines(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for message_id, (offset, name) in WATCH_FIELDS.items():
        timeline = []
        for row in records:
            if row["message_id"] != message_id:
                continue
            timeline.append(
                {
                    "game_target": row["game_target"],
                    "time": row["time"],
                    "live": field_value(row["live"], offset),
                    "candidate": field_value(row["candidate"], offset),
                    "replacement_level": row["replacement_level"],
                    "special_rule_id": row["special_rule_id"],
                    "final_equals_live": row["final_equals_live"],
                    "final_equals_shadow": row["final_equals_shadow"],
                }
            )
        result[f"0x{message_id:04X}+0x{offset:X}:{name}"] = timeline
    return result


def downlink_shapes(run: Path, cut_time: datetime) -> dict[str, Any]:
    path = run / "01_downlink_events.jsonl"
    result: dict[str, Any] = {"before": Counter(), "after": Counter(), "nearby": []}
    if not path.is_file():
        return result
    for event in _read_jsonl(path):
        packet = event.get("packet") or {}
        frames_hex = packet.get("frames_hex") or []
        if not frames_hex:
            continue
        try:
            raw = bytes.fromhex(str(frames_hex[0]))
            event_time = _parse_time(str(event.get("time") or ""))
        except (ValueError, TypeError):
            continue
        marker = raw.find(b"\x01\x0A\x00")
        subtype = raw[marker + 3] if marker >= 0 and marker + 3 < len(raw) else None
        key = (len(raw), subtype)
        side = "before" if event_time < cut_time else "after"
        result[side][key] += 1
        delta = (event_time - cut_time).total_seconds()
        if abs(delta) <= 180:
            result["nearby"].append(
                {
                    "time": event_time.isoformat(timespec="milliseconds"),
                    "delta_seconds": delta,
                    "length": len(raw),
                    "subtype": subtype,
                }
            )
    return result


def control_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    values: dict[str, list[int]] = {}
    for message_id, (offset, name) in WATCH_FIELDS.items():
        found = {
            field_value(row["live"], offset)
            for row in records
            if row["message_id"] == message_id and field_value(row["live"], offset) is not None
        }
        values[f"0x{message_id:04X}+0x{offset:X}:{name}"] = sorted(found)
    return values


def counter_to_json(counter: Counter) -> list[dict[str, Any]]:
    return [
        {"length": length, "subtype": subtype, "count": count}
        for (length, subtype), count in sorted(counter.items(), key=lambda item: str(item[0]))
    ]


def render_markdown(result: dict[str, Any]) -> str:
    cut = result["cutpoint"]
    lines = [
        "# 01 切点前后快速对比报告",
        "",
        f"- 运行目录：`{result['run']}`",
        f"- 切点：`game_target_09={cut['game_target']}`",
        f"- 切点事件：`event_id={cut['event_id']}`",
        f"- 切点时间：`{cut['time']}`",
        f"- 总报告数：{result['report_count']}；总叶子数：{result['leaf_count']}",
        "",
        "## 1. messageId 集合",
        "",
        f"- 切点前二进制 messageId：{result['message_ids']['before_binary_count']} 种",
        f"- 切点后二进制 messageId：{result['message_ids']['after_binary_count']} 种",
        f"- 切点后首次出现且切点前从未出现：{', '.join(result['message_ids']['new_after']) or '无'}",
        "",
        "## 2. 稳定字段突变",
        "",
        "筛选条件：同一 `record_code/messageId/length` 切点前至少出现两次；扫描对齐的 4 字节大端字段；报告“全零转非零”或“此前恒定、之后改变”。",
        "",
        "| 首次出现 | 相对切点 | 消息 | 长度 | 偏移 | 类型 | 切点前 | 切点后 | 首次 Live→Candidate | 最终路径 |",
        "|---|---:|---|---:|---:|---|---|---|---|---|",
    ]
    for row in result["stable_transitions"]:
        lines.append(
            "| {time} | {delta} | {mid} | {length} | `+0x{offset:X}` | {kind} | `{before}` | `{after}` | `{live}→{candidate}` | {level} |".format(
                time=row["first_time"],
                delta=row["delta"],
                mid=_hex_id(row["message_id"], 4),
                length=row["length"],
                offset=row["offset"],
                kind=row["kind"],
                before=row["before_values"],
                after=row["after_values"],
                live=row["first_live_value"],
                candidate=row["first_candidate_value"],
                level=row["replacement_level"] or "NONE",
            )
        )
    if not result["stable_transitions"]:
        lines.append("| — | — | — | — | — | — | — | — | — | — |")

    lines += ["", "## 3. 重点字段时间线", ""]
    for key, timeline in result["watch_timelines"].items():
        lines += [f"### `{key}`", "", "| gt09 | 时间 | Live | Candidate | 路径/规则 |", "|---:|---|---:|---:|---|"]
        for row in timeline:
            lines.append(
                f"| {row['game_target']} | {row['time']} | {row['live']} | {row['candidate']} | "
                f"{row['replacement_level'] or 'NONE'} {row['special_rule_id']} |"
            )
        lines.append("")

    lines += ["## 4. 下行形态", "", "### 切点前", ""]
    for row in result["downlink"]["before"]:
        subtype = "None" if row["subtype"] is None else f"0x{row['subtype']:02X}"
        lines.append(f"- 长度 {row['length']} / subtype {subtype}: {row['count']}")
    lines += ["", "### 切点后", ""]
    for row in result["downlink"]["after"]:
        subtype = "None" if row["subtype"] is None else f"0x{row['subtype']:02X}"
        lines.append(f"- 长度 {row['length']} / subtype {subtype}: {row['count']}")

    if result.get("control"):
        lines += ["", "## 5. 对照场重点字段全集", ""]
        for key, values in result["control"]["values"].items():
            lines.append(f"- `{key}`: `{values}`")

    lines += ["", "## 6. 切点附近上行", "", "| gt09 | event | 时间 | messageId |", "|---:|---:|---|---|"]
    for row in result["nearby_uplink"]:
        lines.append(
            f"| {row['game_target']} | {row['event_id']} | {row['time']} | "
            + ", ".join(row["message_ids"])
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="运行目录、上级样本目录或 01_replace_events.jsonl")
    parser.add_argument("--cut", type=int, required=True, help="game_target_09 切点")
    parser.add_argument("--window", type=int, default=80, help="频率比较窗口，默认80")
    parser.add_argument("--control", help="可选对照场运行目录")
    parser.add_argument("--output", help="Markdown 输出路径")
    parser.add_argument("--json", dest="json_output", help="JSON 输出路径")
    args = parser.parse_args()

    run = _locate_run(args.run)
    events, records = load_records(run)
    cut_event = next((event for event in events if event["game_target"] == args.cut), None)
    if cut_event is None:
        raise SystemExit(f"运行中没有 game_target_09={args.cut}")
    cut_time = _parse_time(cut_event["time"])
    transitions = stable_transitions(records, args.cut)
    for row in transitions:
        row["delta_seconds"] = (_parse_time(row["first_time"]) - cut_time).total_seconds()
        row["delta"] = _fmt_delta(row["delta_seconds"])

    before_ids = {
        (row["record_code"], row["message_id"])
        for row in records
        if row["game_target"] < args.cut and isinstance(row["message_id"], int)
    }
    after_ids = {
        (row["record_code"], row["message_id"])
        for row in records
        if row["game_target"] >= args.cut and isinstance(row["message_id"], int)
    }
    nearby = []
    grouped_events: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        grouped_events[row["game_target"]].append(row)
    for event in events:
        if args.cut - 5 <= event["game_target"] <= args.cut + 15:
            ids = [
                _hex_id(row["message_id"], 4)
                if isinstance(row["message_id"], int)
                else f"code={_hex_id(row['record_code'], 8)}"
                for row in grouped_events[event["game_target"]]
            ]
            nearby.append({**event, "message_ids": ids})

    downlink = downlink_shapes(run, cut_time)
    result: dict[str, Any] = {
        "schema": "dfm-01-cutpoint-compare-v1",
        "run": str(run),
        "report_count": len(events),
        "leaf_count": len(records),
        "cutpoint": cut_event,
        "window": args.window,
        "message_ids": {
            "before_binary_count": len(before_ids),
            "after_binary_count": len(after_ids),
            "new_after": [
                _hex_id(message_id, 4)
                for _record_code, message_id in sorted(after_ids - before_ids)
            ],
        },
        "window_counts": {
            "before": [
                {
                    "record_code": key[0],
                    "message_id": key[1],
                    "count": count,
                }
                for key, count in message_counts(
                    records, max(1, args.cut - args.window), args.cut - 1
                ).most_common()
            ],
            "after": [
                {
                    "record_code": key[0],
                    "message_id": key[1],
                    "count": count,
                }
                for key, count in message_counts(
                    records, args.cut, args.cut + args.window - 1
                ).most_common()
            ],
        },
        "stable_transitions": transitions,
        "watch_timelines": watch_timelines(records),
        "downlink": {
            "before": counter_to_json(downlink["before"]),
            "after": counter_to_json(downlink["after"]),
            "nearby": downlink["nearby"],
        },
        "nearby_uplink": nearby,
    }
    if args.control:
        control_run = _locate_run(args.control)
        control_events, control_records = load_records(control_run)
        result["control"] = {
            "run": str(control_run),
            "report_count": len(control_events),
            "leaf_count": len(control_records),
            "values": control_summary(control_records),
        }

    markdown_path = Path(args.output).expanduser().resolve() if args.output else run / f"cutpoint_compare_{args.cut}.md"
    json_path = Path(args.json_output).expanduser().resolve() if args.json_output else run / f"cutpoint_compare_{args.cut}.json"
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(markdown_path)
    print(json_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
