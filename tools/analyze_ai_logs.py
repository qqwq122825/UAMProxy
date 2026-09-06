#!/usr/bin/env python3
"""Fast validator and summary generator for DFMProxy AI日志 runs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.crypto import _ace_01_verify_frames


def read_json(path: Path, errors: list[str]) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{path}: {exc}")
        return {}


def read_jsonl(path: Path, errors: list[str]) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{path}:{line_number}: {exc}")
                continue
            if not isinstance(value, dict):
                errors.append(f"{path}:{line_number}: object required")
                continue
            rows.append(value)
    return rows


def follows(previous: int | None, current: int, mask: int) -> bool:
    return previous is None or current == ((previous + 1) & mask)


def latest_run(root: Path) -> Path:
    candidates = sorted(path for path in root.glob("run_*") if path.is_dir())
    if not candidates:
        raise FileNotFoundError(root)
    return candidates[-1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", nargs="?", type=Path)
    parser.add_argument("--root", type=Path, default=Path(r"C:\PyProxyApp") / "AI日志")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--user", help="只分析指定代理用户")
    parser.add_argument("--game-id", help="只分析指定游戏ID")
    args = parser.parse_args()
    run_dir = args.run or latest_run(args.root)
    errors: list[str] = []
    manifest = read_json(run_dir / "manifest.json", errors)
    files = manifest.get("files") or {}
    events = read_jsonl(run_dir / files.get("replay_events", "replay_events.jsonl"), errors)
    groups = read_jsonl(run_dir / files.get("replay_groups", "replay_groups.jsonl"), errors)
    leaves = read_jsonl(run_dir / files.get("replay_leaves", "replay_leaves.jsonl"), errors)
    anomalies = read_jsonl(
        run_dir / files.get("anomaly_full", "anomaly_full.jsonl"), errors
    )
    controls = read_jsonl(
        run_dir / files.get("control_events", "control_events.jsonl"), errors
    )

    if args.user:
        events = [
            row for row in events
            if str((row.get("connection") or {}).get("proxy_username") or "") == args.user
        ]
        event_ids = {row.get("event_id") for row in events}
        groups = [row for row in groups if row.get("event_id") in event_ids]
        leaves = [row for row in leaves if row.get("event_id") in event_ids]
        anomalies = [
            row for row in anomalies
            if str(row.get("proxy_username") or "") == args.user
        ]
    if args.game_id:
        events = [
            row for row in events
            if str((row.get("connection") or {}).get("game_id") or "") == args.game_id
        ]
        event_ids = {row.get("event_id") for row in events}
        groups = [row for row in groups if row.get("event_id") in event_ids]
        leaves = [row for row in leaves if row.get("event_id") in event_ids]
        anomalies = [
            row for row in anomalies
            if str(row.get("game_id") or "") == args.game_id
        ]

    counts = Counter()
    message_ids = Counter()
    previous = defaultdict(lambda: {"report": None, "frame": None, "group": None, "leaf": None})
    output_group_ids = set()
    output_group_connections: dict[int, str] = {}
    for row in groups:
        counts[f"group_phase_{row.get('phase')}"] += 1
        if row.get("phase") != "output":
            continue
        output_group_ids.add(row.get("group_id"))
        packet = row.get("packet") or {}
        conn_id = str(row.get("connection_id") or "")
        output_group_connections[row.get("group_id")] = conn_id
        state = previous[conn_id]
        if not packet.get("frame_validation_ok"):
            errors.append(f"group {row.get('group_id')}: frame validation")
        report = packet.get("report_index")
        if isinstance(report, int):
            if not follows(state["report"], report, 0xFFFFFFFF):
                errors.append(f"group {row.get('group_id')}: report {state['report']}->{report}")
            state["report"] = report
        group = packet.get("packet_group")
        if isinstance(group, int):
            if not follows(state["group"], group, 0xFFFF):
                errors.append(f"group {row.get('group_id')}: packet_group {state['group']}->{group}")
            state["group"] = group
        frame_hexes = packet.get("frames_hex") or []
        if frame_hexes:
            for frame_hex in frame_hexes:
                try:
                    frame = bytes.fromhex(frame_hex)
                    sequence = int.from_bytes(frame[8:10], "big")
                except (ValueError, IndexError):
                    errors.append(f"group {row.get('group_id')}: frame hex")
                    continue
                if not follows(state["frame"], sequence, 0xFFFF):
                    errors.append(f"group {row.get('group_id')}: frame {state['frame']}->{sequence}")
                state["frame"] = sequence
            try:
                raw_frames = [bytes.fromhex(value) for value in frame_hexes]
                verified = _ace_01_verify_frames(raw_frames)
                if not verified.get("ok"):
                    errors.append(
                        f"group {row.get('group_id')}: "
                        + ";".join(verified.get("errors") or [])
                    )
            except ValueError:
                errors.append(f"group {row.get('group_id')}: raw frame decode")
        else:
            sequence = packet.get("frame_sequence_start")
            if isinstance(sequence, int):
                if not follows(state["frame"], sequence, 0xFFFF):
                    errors.append(
                        f"group {row.get('group_id')}: frame {state['frame']}->{sequence}"
                    )
                state["frame"] = packet.get("frame_sequence_end", sequence)
        counts[f"output_source_{row.get('source')}"] += 1
        counts[f"output_capture_{packet.get('capture') or 'unknown'}"] += 1

    for row in leaves:
        if row.get("phase") != "output" or row.get("group_id") not in output_group_ids:
            continue
        conn_id = output_group_connections.get(row.get("group_id"), "")
        state = previous[conn_id]
        sequence = row.get("record_sequence")
        if isinstance(sequence, int):
            if not follows(state["leaf"], sequence, 0xFFFFFFFF):
                errors.append(f"leaf {row.get('leaf_id')}: {state['leaf']}->{sequence}")
            state["leaf"] = sequence
        try:
            raw_leaf = bytes.fromhex(row.get("raw_hex") or "")
        except ValueError:
            raw_leaf = b""
            errors.append(f"leaf {row.get('leaf_id')}: raw hex")
        if raw_leaf:
            if len(raw_leaf) != row.get("length"):
                errors.append(f"leaf {row.get('leaf_id')}: length")
            if hashlib.sha256(raw_leaf).hexdigest() != row.get("raw_sha256"):
                errors.append(f"leaf {row.get('leaf_id')}: sha256")
            if len(raw_leaf) >= 14 and int.from_bytes(raw_leaf[10:14], "big") != sequence:
                errors.append(f"leaf {row.get('leaf_id')}: encoded sequence")
            if len(raw_leaf) >= 10 and int.from_bytes(raw_leaf[6:10], "big") != row.get("record_code"):
                errors.append(f"leaf {row.get('leaf_id')}: encoded record_code")
            if (
                len(raw_leaf) >= 0x18
                and isinstance(row.get("message_id"), int)
                and int.from_bytes(raw_leaf[0x16:0x18], "big") != row.get("message_id")
            ):
                errors.append(f"leaf {row.get('leaf_id')}: encoded message_id")
        message_id = row.get("message_id")
        if isinstance(message_id, int):
            message_ids[f"0x{message_id:04X}"] += 1

    for event in events:
        if not (event.get("checks") or {}).get("all_output_groups_valid", False):
            errors.append(f"event {event.get('event_id')}: output checks")

    control_actions = Counter(str(row.get("action") or "") for row in controls)
    control_sources = Counter(str(row.get("source") or "") for row in controls)
    rule_counter_increments = Counter(
        str((row.get("details") or {}).get("rule_id") or "")
        for row in controls
        if row.get("action") == "hot_rule_success_counter_increment"
    )
    rule_counter_increments.pop("", None)
    control_timeline = [
        {
            "event_id": row.get("event_id"),
            "time": row.get("time"),
            "source": row.get("source"),
            "actor": row.get("actor"),
            "action": row.get("action"),
            "phase": row.get("phase"),
            "details": row.get("details") or {},
        }
        for row in controls[-500:]
    ]

    result = {
        "schema": "dfm-ai-log-analysis-v1",
        "run_dir": str(run_dir),
        "manifest_schema": manifest.get("schema"),
        "app_version": manifest.get("app_version"),
        "model_revision": manifest.get("v128_model_revision"),
        "filter": {"user": args.user, "game_id": args.game_id},
        "counts": {
            "replay_events": len(events),
            "replay_groups": len(groups),
            "replay_leaves": len(leaves),
            "anomaly_full": len(anomalies),
            "control_events": len(controls),
            **dict(sorted(counts.items())),
        },
        "output_message_ids": dict(sorted(message_ids.items())),
        "anomaly_reasons": dict(sorted(Counter(
            reason
            for row in anomalies
            for reason in (row.get("reasons") or [])
        ).items())),
        "control_audit": {
            "revision": manifest.get("control_audit_revision"),
            "actions": dict(sorted(control_actions.items())),
            "sources": dict(sorted(control_sources.items())),
            "rule_counter_increments": dict(
                sorted(rule_counter_increments.items())
            ),
            "final_state": (controls[-1].get("state") or {}) if controls else {},
            "timeline": control_timeline,
        },
        "error_count": len(errors),
        "errors": errors[:500],
        "pass": not errors,
    }
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    sys.stdout.write(output)
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
