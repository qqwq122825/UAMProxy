#!/usr/bin/env python3
"""Pure-script v1.128 backtest over historical replay event JSONL.

The default fixture has thousands of Type9 reports and zero stable 80xx leaves.
Every stored live frame is passed through the production replay function with an
empty recording pool, so all inserted 80xx data comes from the built-in model.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, OrderedDict
from datetime import datetime
from pathlib import Path

from core.config import app_config
from core.crypto import (
    _ace_01_fragment_key,
    _ace_01_reassemble_frames,
    _ace_01_report_index,
    _ace_01_verify_frames,
    _ace_try_replay_template,
)
from core.type9_shadow import decode_material
from core.type9_v128_replenish import BUILTIN_MESSAGE_IDS, MODEL_REVISION


DEFAULT_SOURCE = Path(
    "数据/126.2/2/01ReplayAnalysis/"
    "run_20260817_055023_014498/01_replace_events.jsonl"
)
DEFAULT_OUTPUT = Path(
    "数据/127/1000个01_重放补数据可行性回溯/"
    "产物/v128_历史无80xx重放原始帧回溯.json"
)


def split_logical_groups(frames: list[bytes]) -> list[list[bytes]]:
    groups: OrderedDict[tuple, list[bytes]] = OrderedDict()
    for frame in frames:
        key = _ace_01_fragment_key(frame)
        if key is None:
            groups[("raw", len(groups))] = [frame]
        else:
            groups.setdefault(key, []).append(frame)
    return list(groups.values())


def follows_u16(previous: int | None, current: int) -> bool:
    return previous is None or current == ((previous + 1) & 0xFFFF)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", nargs="?", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    cursors: dict[str, list] = {}
    anchors: dict[str, datetime] = {}
    previous_report: dict[str, int] = {}
    previous_leaf: dict[str, int] = {}
    previous_frame: dict[str, int] = {}
    previous_group: dict[str, int] = {}
    source_stable_ids = Counter()
    output_stable_ids = Counter()
    errors = []
    stats = Counter()

    previous_mode = app_config.get("replenish_01_mode")
    app_config.set("replenish_01_mode", True)
    try:
        with args.source.open(encoding="utf-8", errors="ignore") as handle:
            for line_number, line in enumerate(handle, 1):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(f"line {line_number}: JSON {exc}")
                    continue
                frames_hex = (event.get("live_input") or {}).get("frames_hex") or []
                if not frames_hex:
                    stats["events_without_raw_frames"] += 1
                    continue
                try:
                    frames = [bytes.fromhex(value) for value in frames_hex]
                except ValueError as exc:
                    errors.append(f"line {line_number}: hex {exc}")
                    continue
                connection = event.get("connection") or {}
                conn_id = str(connection.get("conn_id") or "default")
                event_time = datetime.fromisoformat(event["time"])
                cursor = cursors.setdefault(conn_id, [0, 0, {}])
                anchor = anchors.setdefault(conn_id, event_time)
                elapsed = max(0.0, (event_time - anchor).total_seconds())
                game_id = str(event.get("game_id") or "")

                live_assembled = _ace_01_reassemble_frames(frames)
                if not live_assembled:
                    errors.append(f"line {line_number}: source reassemble")
                    continue
                live_report = _ace_01_report_index(live_assembled[1])
                live_material = decode_material(live_assembled[1])
                if live_report is not None:
                    stats["source_reports"] += 1
                if live_material.get("ok"):
                    stats["source_type9_reports"] += 1
                    for leaf in live_material.get("leaves") or []:
                        stats["source_type9_leaves"] += 1
                        message_id = leaf.get("message_id")
                        if message_id in BUILTIN_MESSAGE_IDS:
                            source_stable_ids[int(message_id)] += 1

                output, _ = _ace_try_replay_template(
                    frames,
                    [],
                    cursor,
                    expected_game_id=game_id,
                    session_elapsed_seconds=elapsed,
                )
                stats["input_events"] += 1
                stats["input_frames"] += len(frames)
                stats["output_frames"] += len(output)

                logical_groups = split_logical_groups(output)
                stats["output_logical_groups"] += len(logical_groups)
                if len(logical_groups) > 1:
                    stats["events_with_injection"] += 1
                    stats["injected_logical_groups"] += len(logical_groups) - 1

                for group_index, group_frames in enumerate(logical_groups):
                    checked = _ace_01_verify_frames(
                        group_frames,
                        expected_game_id=game_id,
                    )
                    if not checked.get("ok"):
                        errors.append(
                            f"line {line_number} group {group_index}: "
                            + ";".join(checked.get("errors") or [])
                        )
                        continue
                    assembled = _ace_01_reassemble_frames(group_frames)
                    if not assembled:
                        errors.append(f"line {line_number} group {group_index}: reassemble")
                        continue
                    ordered, logical = assembled
                    report_index = _ace_01_report_index(logical)
                    material = decode_material(logical)
                    if report_index is not None:
                        prev_report = previous_report.get(conn_id)
                        if prev_report is not None and report_index != prev_report + 1:
                            errors.append(
                                f"line {line_number}: report discontinuity "
                                f"{prev_report}->{report_index}"
                            )
                        previous_report[conn_id] = report_index
                        stats["output_reports"] += 1
                    if material.get("ok"):
                        stats["output_type9_reports"] += 1
                        for leaf in material.get("leaves") or []:
                            stats["output_type9_leaves"] += 1
                            sequence = int(leaf.get("record_sequence") or 0)
                            prev_leaf = previous_leaf.get(conn_id)
                            if prev_leaf is not None and sequence != prev_leaf + 1:
                                errors.append(
                                    f"line {line_number}: leaf discontinuity "
                                    f"{prev_leaf}->{sequence}"
                                )
                            previous_leaf[conn_id] = sequence
                            message_id = leaf.get("message_id")
                            if message_id in BUILTIN_MESSAGE_IDS:
                                output_stable_ids[int(message_id)] += 1
                                stats["output_stable_80xx_leaves"] += 1
                    for frame in ordered:
                        sequence = int.from_bytes(frame[8:10], "big")
                        if not follows_u16(previous_frame.get(conn_id), sequence):
                            errors.append(
                                f"line {line_number}: frame discontinuity "
                                f"{previous_frame.get(conn_id)}->{sequence}"
                            )
                        previous_frame[conn_id] = sequence
                    packet_group = int.from_bytes(ordered[0][36:38], "big")
                    prev_group = previous_group.get(conn_id)
                    if prev_group is not None and packet_group != ((prev_group + 1) & 0xFFFF):
                        errors.append(
                            f"line {line_number}: group discontinuity "
                            f"{prev_group}->{packet_group}"
                        )
                    previous_group[conn_id] = packet_group
    finally:
        app_config.set("replenish_01_mode", previous_mode)

    states = {
        conn_id: dict(cursor[2].get("v128_replenish") or {})
        for conn_id, cursor in cursors.items()
    }
    result = {
        "schema": "dfm-v128-historical-zero-80xx-frame-backtest-v1",
        "model_revision": MODEL_REVISION,
        "source": str(args.source),
        "source_stable_80xx": {
            f"0x{key:04X}": value for key, value in sorted(source_stable_ids.items())
        },
        "output_stable_80xx": {
            f"0x{key:04X}": value for key, value in sorted(output_stable_ids.items())
        },
        "stats": dict(stats),
        "connections": sorted(cursors),
        "states": states,
        "error_count": len(errors),
        "errors": errors[:500],
        "pass": not errors and not source_stable_ids and bool(output_stable_ids),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
