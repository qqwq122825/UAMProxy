#!/usr/bin/env python3
"""Backtest v1.128.10 token + native Type9 report reconnect decisions."""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.replay_session_v130 import (
    join_frame_fields,
    live_leaf_sequence_decision,
)


def read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def find_run(path: Path) -> Path:
    if (path / "replay_events.jsonl").is_file():
        return path
    runs = sorted(
        (row for row in path.glob("run_*") if row.is_dir()),
        key=lambda row: row.name,
    )
    if not runs:
        raise FileNotFoundError(f"AI log run not found under {path}")
    return runs[-1]


def stream_join_rows(rows: list[dict]) -> list[dict]:
    joins = []
    for row in rows:
        frames = (row.get("packet") or {}).get("frames_hex") or []
        if (
            row.get("direction") == "↑UP"
            and len(frames) == 1
            and len(frames[0]) == 84
            and frames[0].startswith("010000002A")
        ):
            fields = join_frame_fields(bytes.fromhex(frames[0]))
            if fields:
                joins.append(
                    {
                        "time": row.get("time"),
                        "time_unix_ms": int(row.get("time_unix_ms") or 0),
                        **fields,
                    }
                )
    return joins


def nearest_join(joins: list[dict], event_ms: int) -> dict | None:
    candidates = [
        row for row in joins if 0 <= event_ms - row["time_unix_ms"] <= 3000
    ]
    return max(candidates, key=lambda row: row["time_unix_ms"], default=None)


def input_type9_groups(groups: list[dict], connection_id: str) -> list[dict]:
    return [
        row
        for row in groups
        if row.get("connection_id") == connection_id
        and row.get("phase") == "input"
        and row.get("source") == "live"
        and int((row.get("packet") or {}).get("leaf_count") or 0) > 0
    ]


def injection_keys(events: list[dict]) -> dict[tuple, dict]:
    output = {}
    for event in events:
        for group in (event.get("v128") or {}).get("groups") or []:
            key = (
                str(group.get("layer") or ""),
                int(group.get("slot") or 0),
                tuple(group.get("message_ids") or []),
            )
            output[key] = {
                "time": event.get("time"),
                "elapsed_ms": (event.get("v128") or {}).get("elapsed_ms"),
                "layer": key[0],
                "slot": key[1],
                "message_ids": list(key[2]),
                # One event can contain several injected reports.  The event-
                # level total belongs to all groups together, so each group's
                # leaf count is its own message list length.
                "leaf_count": len(key[2]),
            }
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log_dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    run = find_run(args.log_dir.expanduser().resolve())
    events = read_jsonl(run / "replay_events.jsonl")
    groups = read_jsonl(run / "replay_groups.jsonl")
    joins = stream_join_rows(read_jsonl(run / "stream_frames.jsonl"))

    by_connection: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        conn = str((event.get("connection") or {}).get("connection_id") or "")
        if conn:
            by_connection[conn].append(event)
    connections = sorted(
        by_connection,
        key=lambda conn: by_connection[conn][0].get("time_unix_ms") or 0,
    )
    transitions = []
    for old_conn, new_conn in zip(connections, connections[1:]):
        old_events = by_connection[old_conn]
        new_events = by_connection[new_conn]
        old_identity = old_events[-1].get("connection") or {}
        new_identity = new_events[0].get("connection") or {}
        if (
            old_identity.get("proxy_username")
            != new_identity.get("proxy_username")
            or old_identity.get("game_id") != new_identity.get("game_id")
        ):
            continue
        old_join = nearest_join(joins, int(old_events[0]["time_unix_ms"]))
        new_join = nearest_join(joins, int(new_events[0]["time_unix_ms"]))
        if not old_join or not new_join:
            continue
        old_live = input_type9_groups(groups, old_conn)
        new_live = input_type9_groups(groups, new_conn)
        old_last_packet = (old_live[-1].get("packet") or {}) if old_live else {}
        new_first_packet = (new_live[0].get("packet") or {}) if new_live else {}
        old_injections = injection_keys(old_events)
        new_injections = injection_keys(new_events)
        duplicate_keys = sorted(set(old_injections) & set(new_injections))
        duplicate_groups = [new_injections[key] for key in duplicate_keys]
        old_gate = next(
            (
                ((row.get("v128") or {}).get("same_device_player") or {}).get("gate")
                for row in reversed(old_events)
                if ((row.get("v128") or {}).get("same_device_player") or {}).get("gate")
            ),
            None,
        )
        new_gate = next(
            (
                ((row.get("v128") or {}).get("same_device_player") or {}).get("gate")
                for row in new_events
                if ((row.get("v128") or {}).get("same_device_player") or {}).get("gate")
            ),
            None,
        )
        new_elapsed = int((new_events[0].get("v128") or {}).get("elapsed_ms") or 0)
        simulated_elapsed = new_elapsed + (
            (
                new_join["unix_time_u32"]
                - old_join["unix_time_u32"]
            )
            & 0xFFFFFFFF
        ) * 1000
        old_leaf_end = old_last_packet.get("leaf_sequence_end")
        new_leaf_start = new_first_packet.get("leaf_sequence_start")
        report_decision, report_detail = live_leaf_sequence_decision(
            old_leaf_end,
            new_leaf_start,
        )
        token_matches = (
            old_join["session_token_u32"] == new_join["session_token_u32"]
        )
        continued = bool(
            token_matches and report_decision.startswith("CONFIRMED_")
        )
        wall_gap = round(
            (new_join["time_unix_ms"] - old_join["time_unix_ms"]) / 1000
        )
        unix_gap = (
            new_join["unix_time_u32"] - old_join["unix_time_u32"]
        ) & 0xFFFFFFFF
        transitions.append(
            {
                "old_connection": old_conn,
                "new_connection": new_conn,
                "proxy_username": old_identity.get("proxy_username"),
                "game_id": old_identity.get("game_id"),
                "decision": (
                    "RESUME_TOKEN_AND_LIVE_REPORT"
                    if continued
                    else "NEW_GAME_SESSION"
                ),
                "join_42": {
                    "old": old_join,
                    "new": new_join,
                    "session_token_matches": token_matches,
                    "wall_gap_seconds": wall_gap,
                    "unix_gap_seconds": unix_gap,
                    "unix_vs_wall_error_seconds": unix_gap - wall_gap,
                },
                "live_leaf_continuity": {
                    "old_last": old_leaf_end,
                    "new_first": new_leaf_start,
                    "continuous": report_decision.startswith("CONFIRMED_"),
                    "decision": report_decision,
                    **report_detail,
                },
                "transport_reset_observed": {
                    "report_index": [
                        old_last_packet.get("report_index"),
                        new_first_packet.get("report_index"),
                    ],
                    "frame_sequence": [
                        old_last_packet.get("frame_sequence_end"),
                        new_first_packet.get("frame_sequence_start"),
                    ],
                    "packet_group": [
                        old_last_packet.get("packet_group"),
                        new_first_packet.get("packet_group"),
                    ],
                },
                "current_new_elapsed_ms": new_elapsed,
                "v130_simulated_elapsed_ms": simulated_elapsed,
                "same_device_gate": {
                    "before_disconnect": old_gate,
                    "current_after_reconnect": new_gate,
                    "v130_simulated_after_reconnect": old_gate if continued else new_gate,
                },
                "duplicate_injections_suppressed_by_v130": duplicate_groups,
                "duplicate_report_count": len(duplicate_groups),
                "duplicate_leaf_count": sum(row["leaf_count"] for row in duplicate_groups),
                "all_new_output_groups_valid": all(
                    bool((row.get("checks") or {}).get("all_output_groups_valid"))
                    for row in new_events
                ),
            }
        )

    result = {
        "schema": "dfm-v130-reconnect-backtest-v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "run_dir": str(run),
        "connection_count": len(connections),
        "join_frame_count": len(joins),
        "transitions": transitions,
        "pass": bool(transitions)
        and all(
            row["decision"] == "RESUME_TOKEN_AND_LIVE_REPORT"
            and row["live_leaf_continuity"]["continuous"]
            and row["all_new_output_groups_valid"]
            for row in transitions
        ),
    }
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
