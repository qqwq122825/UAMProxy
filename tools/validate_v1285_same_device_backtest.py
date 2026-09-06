#!/usr/bin/env python3
"""Backtest the v128.5 same-device supplement against a historical run.

The input directory must contain a recording-pool JSON file and a replay
``01_replace_events.jsonl``.  The tool keeps the historical capture read-only,
runs the current reconstruction code on one carrier report, then compares the
generated player leaves with the leaves that the clean same-device client sent
in the historical replay.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import core.type9_special_rules as special_rules
from core.config import app_config
from core.crypto import (
    _ace_01_reassemble_frames,
    _ace_01_report_index,
    _ace_01_verify_frames,
    _ace_try_replay_template,
)
from core.type9_shadow import (
    decode_material,
    extract_device_context_from_logical,
    extract_device_context_from_rows,
    merge_device_context,
    template_leaf_rows,
)
from core.type9_special_rules import HOT_RULE_SCHEMA, Type9HotRuleStore
from core.type9_v128_replenish import (
    INITIAL_LOGICAL_SLOT,
    WALL_SECONDS_PER_LOGICAL_SLOT,
    ensure_v128_state,
    plan_same_device_player_groups,
    player_leaf_identity,
)


TRACKED_IDS = (
    0x8007,
    0x800A,
    0x800C,
    0x800D,
    0x800F,
    0x8023,
    0x8024,
    0x8027,
    0x8029,
    0x802A,
    0x802B,
    0x802C,
)
STATIC_READY_IDS = (0x800F, 0x8023)
CONTEXT_FIELDS = (
    "model",
    "system_version",
    "device_idfv",
    "app_version",
    "hardware_model",
    "device_resolution",
    "system_name",
    "app_mach_uuid",
)


def _find_one(root: Path, name: str) -> Path:
    rows = sorted(root.rglob(name))
    if not rows:
        raise FileNotFoundError(f"missing {name} under {root}")
    return rows[0]


def _normalize_version(value: object) -> str:
    text = str(value or "").strip()
    parts = text.split(".")
    if len(parts) == 2 and all(part.isdigit() for part in parts):
        minor = parts[1].rstrip("0") or "0"
        return f"{int(parts[0])}.{int(minor)}"
    return text


def _normalized_leaf(raw: bytes) -> bytes:
    value = bytearray(raw)
    if len(value) >= 14:
        value[10:14] = b"\x00" * 4
    if len(value) >= 0x1E:
        value[0x1C:0x1E] = b"\x00" * 2
    return bytes(value)


def _load_pool(path: Path) -> tuple[list[dict], str, str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    candidates: list[tuple[int, dict]] = []
    for sessions in (document.get("sessions") or {}).values():
        for session in sessions or []:
            count = len(session.get("pool_items") or [])
            if count:
                candidates.append((count, session))
    if not candidates:
        raise ValueError("recording pool has no 01 items")
    _, session = max(candidates, key=lambda row: row[0])
    game_id = str(session.get("game_id") or "").strip()
    session_id = str(session.get("sid") or "legacy")
    pool: list[dict] = []
    for source in session.get("pool_items") or []:
        pool.append(
            {
                "payload": bytes.fromhex(source["payload"]),
                "crc": bytes.fromhex(source.get("crc", "")),
                "routing": bytes.fromhex(source.get("routing", "00")),
                "account_id": source.get("account_id", ""),
                "source": source.get("source") or "01",
                "raw_packet": bytes.fromhex(source.get("raw_packet", "")),
                "report_index": source.get("report_index"),
                "recorded_at": source.get("recorded_at"),
                "recorded_elapsed_seconds": source.get(
                    "recorded_elapsed_seconds"
                ),
                "template_frames": [
                    bytes.fromhex(value)
                    for value in (source.get("template_frames") or [])
                ],
                "template_scope": "player",
                "source_priority": 0,
                "donor_game_id": game_id,
                "template_session_id": session_id,
            }
        )
    return pool, game_id, session_id


def _decode_pool(pool: Iterable[dict]) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    for pool_index, item in enumerate(pool):
        assembled = _ace_01_reassemble_frames(item["template_frames"])
        if not assembled:
            continue
        decoded = template_leaf_rows(assembled[1], pool_idx=pool_index)
        if not decoded.get("ok"):
            continue
        for source in decoded.get("rows") or []:
            row = dict(source)
            row["report_index"] = item.get("report_index")
            row["recorded_at"] = item.get("recorded_at")
            row["recorded_elapsed_seconds"] = item.get(
                "recorded_elapsed_seconds"
            )
            raw = bytes(row.get("raw") or b"")
            if (
                len(raw) >= 0x18
                and int.from_bytes(raw[6:10], "big") == 0x0102000A
            ):
                row["message_id"] = int.from_bytes(raw[0x16:0x18], "big")
            rows.append(row)
    return rows, extract_device_context_from_rows(rows)


def _enrich_legacy_pool_timing(dataset: Path, pool: list[dict]) -> dict:
    candidates = sorted(dataset.rglob("*_01_message_leaves_*.jsonl"))
    if not candidates:
        return {"source": "legacy_report_index_fallback", "reports": 0}
    path = candidates[0]
    timeline: dict[int, tuple[float, float]] = {}
    first_epoch = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        report_index = event.get("report_index")
        text_time = str(event.get("time") or "")
        if report_index is None or not text_time:
            continue
        epoch = datetime.fromisoformat(text_time).timestamp()
        if first_epoch is None:
            first_epoch = epoch
        timeline[int(report_index)] = (epoch, epoch - first_epoch)
    updated = 0
    for item in pool:
        report_index = item.get("report_index")
        timing = timeline.get(int(report_index)) if report_index is not None else None
        if not timing:
            continue
        if item.get("recorded_at") is None:
            item["recorded_at"] = timing[0]
        if item.get("recorded_elapsed_seconds") is None:
            item["recorded_elapsed_seconds"] = timing[1]
        updated += 1
    return {
        "source": str(path.resolve()),
        "reports": len(timeline),
        "pool_items_enriched": updated,
    }


def _read_replay(path: Path, game_id: str) -> dict:
    context: dict = {}
    events: list[dict] = []
    leaves: dict[int, list[dict]] = defaultdict(list)
    valid_groups = 0
    physical_groups = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        frame_hex = (event.get("live_input") or {}).get("frames_hex") or []
        frames = [bytes.fromhex(value) for value in frame_hex]
        if not frames:
            continue
        physical_groups += 1
        # Some replay logs also contain a valid 01 control frame with no game
        # identity.  Physical/CRC validation therefore stays independent of
        # the Type9 account check here; the counterfactual output below checks
        # the expected account explicitly.
        checked = _ace_01_verify_frames(frames)
        if checked.get("ok"):
            valid_groups += 1
        assembled = _ace_01_reassemble_frames(frames)
        if not assembled:
            continue
        logical = assembled[1]
        context = merge_device_context(
            context, extract_device_context_from_logical(logical)
        )
        material = decode_material(logical)
        if not material.get("ok"):
            continue
        decoded_rows = list(material.get("leaves") or [])
        report_index = _ace_01_report_index(logical)
        for row in decoded_rows:
            message_id = row.get("message_id")
            if message_id in TRACKED_IDS:
                leaves[int(message_id)].append(
                    {
                        "raw": bytes(row["raw"]),
                        "report_index": report_index,
                        "event_id": event.get("event_id"),
                        "time": event.get("time"),
                    }
                )
        events.append(
            {
                "event": event,
                "frames": frames,
                "report_index": report_index,
                "leaf_ids": [row.get("message_id") for row in decoded_rows],
            }
        )
    return {
        "context": context,
        "events": events,
        "leaves": leaves,
        "physical_groups": physical_groups,
        "valid_groups": valid_groups,
    }


def _context_comparison(recorded: dict, replay: dict) -> dict:
    fields = {}
    for key in CONTEXT_FIELDS:
        left = recorded.get(key, "")
        right = replay.get(key, "")
        if key == "system_version":
            equal = _normalize_version(left) == _normalize_version(right)
        else:
            equal = bool(left) and str(left).strip() == str(right).strip()
        fields[key] = {"recorded": left, "replay": right, "equal": equal}
    return {
        "all_equal": all(row["equal"] for row in fields.values()),
        "fields": fields,
    }


def _content_matrix(recorded_rows: list[dict], replay_leaves: dict) -> dict:
    matrix = {}
    for message_id in TRACKED_IDS:
        recorded = [
            _normalized_leaf(bytes(row["raw"]))
            for row in recorded_rows
            if row.get("message_id") == message_id
        ]
        replay = [
            _normalized_leaf(bytes(row["raw"]))
            for row in replay_leaves.get(message_id, [])
        ]
        left = set(recorded)
        right = set(replay)
        matrix[f"0x{message_id:04X}"] = {
            "recorded_count": len(recorded),
            "replay_count": len(replay),
            "recorded_variants": len(left),
            "replay_variants": len(right),
            "shared_variants": len(left & right),
            "all_replay_variants_seen_in_recording": bool(right)
            and right.issubset(left),
        }
    return matrix


def _choose_carrier(events: list[dict]) -> list[bytes]:
    for row in events:
        if row["report_index"] is None:
            continue
        if not any(message_id in STATIC_READY_IDS for message_id in row["leaf_ids"]):
            return row["frames"]
    raise ValueError("replay has no Type9 carrier without 800F/8023")


def _split_output_groups(output: list[bytes], groups: list[dict]) -> list[list[bytes]]:
    generated_count = sum(int(row.get("frame_count") or 0) for row in groups)
    native_count = len(output) - generated_count
    result = [output[:native_count]]
    cursor = native_count
    for row in groups:
        count = int(row.get("frame_count") or 0)
        result.append(output[cursor:cursor + count])
        cursor += count
    return [row for row in result if row]


def _semantic_normalized_leaf(raw: bytes) -> bytes:
    value = bytearray(_normalized_leaf(raw))
    if len(value) >= 0x24:
        message_id = int.from_bytes(value[0x16:0x18], "big")
        if message_id in {0x8027, 0x8029}:
            value[0x20:0x24] = b"\x00" * 4
    return bytes(value)


def _simulate_player_timeline(
    *,
    recorded_rows: list[dict],
    recorded_context: dict,
    replay: dict,
    game_id: str,
    session_id: str,
) -> dict:
    rows = []
    for source in recorded_rows:
        row = dict(source)
        row.update(
            {
                "template_scope": "player",
                "donor_game_id": game_id,
                "template_session_id": session_id,
                "device_context": dict(recorded_context),
            }
        )
        rows.append(row)
    timed_events = [
        row for row in replay["events"]
        if str((row.get("event") or {}).get("time") or "")
    ]
    if not timed_events:
        return {"ok": False, "error": "replay timeline is empty"}
    first_epoch = datetime.fromisoformat(
        timed_events[0]["event"]["time"]
    ).timestamp()
    state = ensure_v128_state({})
    generated: dict[int, list[bytes]] = defaultdict(list)
    group_count = 0
    rebuilt_fields: set[str] = set()
    for event_row in timed_events:
        unix_now = datetime.fromisoformat(
            event_row["event"]["time"]
        ).timestamp()
        groups, info = plan_same_device_player_groups(
            state,
            template_rows=rows,
            elapsed_seconds=max(0.0, unix_now - first_epoch),
            unix_now=unix_now,
            live_leaves=[],
            live_device_context=replay["context"],
            live_game_id=game_id,
        )
        rebuilt_fields.update(info.get("rebuilt_fields") or [])
        group_count += len(groups)
        for group in groups:
            for row in group.get("rows") or []:
                generated[int(row["message_id"])].append(bytes(row["raw"]))

    comparisons = {}
    count_equal = True
    content_models_valid = True
    for message_id in TRACKED_IDS:
        produced = generated.get(message_id, [])
        expected = [
            bytes(row["raw"])
            for row in replay["leaves"].get(message_id, [])
        ]
        produced_exact = {_normalized_leaf(value) for value in produced}
        expected_exact = {_normalized_leaf(value) for value in expected}
        produced_semantic = {_semantic_normalized_leaf(value) for value in produced}
        expected_semantic = {_semantic_normalized_leaf(value) for value in expected}
        row = {
            "generated_count": len(produced),
            "historical_replay_count": len(expected),
            "count_equal": len(produced) == len(expected),
            "generated_variants": len(produced_exact),
            "historical_replay_variants": len(expected_exact),
            "exact_shared_variants": len(produced_exact & expected_exact),
            "semantic_shared_variants": len(
                produced_semantic & expected_semantic
            ),
            "all_generated_semantics_seen_in_replay": bool(produced_semantic)
            and produced_semantic.issubset(expected_semantic),
        }
        if produced and expected and message_id == 0x8007:
            left = bytearray(_normalized_leaf(produced[0]))
            right = bytearray(_normalized_leaf(expected[0]))
            for start, end in ((0x26, 0x29), (0x2A, 0x2D), (0x32, 0x35)):
                left[start:end] = b"\x00" * (end - start)
                right[start:end] = b"\x00" * (end - start)
            row["snapshot_stable_fields_equal"] = left == right
            row["content_model_valid"] = row["snapshot_stable_fields_equal"]
        elif produced and expected and message_id == 0x800D:
            left = bytearray(_normalized_leaf(produced[0]))
            right = bytearray(_normalized_leaf(expected[0]))
            row["round_counter_equal"] = (
                left[0x20:0x24] == right[0x20:0x24]
            )
            left[0x2C:0x34] = b"\x00" * 8
            right[0x2C:0x34] = b"\x00" * 8
            row["stable_fields_equal"] = left == right
            row["content_model_valid"] = bool(
                row["round_counter_equal"] and row["stable_fields_equal"]
            )
        elif produced and expected and message_id == 0x802C:
            generated_elapsed = int.from_bytes(produced[0][0x20:0x24], "big")
            historical_elapsed = int.from_bytes(expected[0][0x20:0x24], "big")
            row["elapsed_delta_seconds"] = (
                generated_elapsed - historical_elapsed
            )
            row["content_model_valid"] = abs(
                row["elapsed_delta_seconds"]
            ) <= 5
        elif message_id == 0x800C:
            row["content_model_valid"] = bool(
                row["count_equal"] and row["semantic_shared_variants"] >= 2
            )
        else:
            row["content_model_valid"] = bool(
                row["count_equal"]
                and row["all_generated_semantics_seen_in_replay"]
            )
        comparisons[f"0x{message_id:04X}"] = row
        count_equal = count_equal and row["count_equal"]
        content_models_valid = content_models_valid and bool(
            row["content_model_valid"]
        )
    return {
        "ok": True,
        "group_count": group_count,
        "dynamic_pending_message_ids": [],
        "rebuilt_fields": sorted(rebuilt_fields),
        "message_checks": comparisons,
        "all_message_counts_equal": count_equal,
        "all_content_models_validated": content_models_valid,
    }


def run_backtest(dataset: Path) -> dict:
    pool_path = _find_one(dataset, "v117_recording_pools.json")
    replay_path = _find_one(dataset, "01_replace_events.jsonl")
    pool, game_id, session_id = _load_pool(pool_path)
    timing_info = _enrich_legacy_pool_timing(dataset, pool)
    recorded_rows, recorded_context = _decode_pool(pool)
    replay = _read_replay(replay_path, game_id)
    carrier = _choose_carrier(replay["events"])
    ground = {
        message_id: replay["leaves"][message_id][0]["raw"]
        for message_id in STATIC_READY_IDS
        if replay["leaves"].get(message_id)
    }
    replay_epochs = [
        datetime.fromisoformat(row["event"]["time"]).timestamp()
        for row in replay["events"]
        if str(row["event"].get("time") or "")
    ]
    counterfactual_elapsed = (
        30 - INITIAL_LOGICAL_SLOT
    ) * WALL_SECONDS_PER_LOGICAL_SLOT
    counterfactual_unix = min(replay_epochs) + counterfactual_elapsed

    previous_replenish = app_config.get("replenish_01_mode")
    previous_full_rebuild = app_config.get("full_rebuild_01_mode")
    previous_store = special_rules.type9_hot_rule_store
    with tempfile.TemporaryDirectory(prefix="v1285-backtest-") as temp_dir:
        store = Type9HotRuleStore(
            os.path.join(temp_dir, "type9_hot_rules.json"),
            auto_reload_interval=0,
        )
        store.replace_document(
            {"schema": HOT_RULE_SCHEMA, "revision": "backtest-empty", "rules": []}
        )
        app_config.set("replenish_01_mode", True)
        app_config.set("full_rebuild_01_mode", True)
        special_rules.type9_hot_rule_store = store
        logs: list[dict] = []
        try:
            cursor = [0, 0, {"live_device_context": dict(replay["context"])}]
            output, changed = _ace_try_replay_template(
                carrier,
                pool,
                cursor,
                expected_game_id=game_id,
                special_rule_store=store,
                on_log=logs.append,
                session_elapsed_seconds=counterfactual_elapsed,
                session_unix_time=counterfactual_unix,
            )
        finally:
            app_config.set("replenish_01_mode", previous_replenish)
            app_config.set("full_rebuild_01_mode", previous_full_rebuild)
            special_rules.type9_hot_rule_store = previous_store

    detail = logs[-1]
    replenish = detail.get("v128_replenish") or {}
    generated_groups = list(replenish.get("groups") or [])
    output_groups = _split_output_groups(output, generated_groups)
    group_checks = []
    generated_static: dict[int, bytes] = {}
    report_indices = []
    leaf_sequences = []
    for frames in output_groups:
        checked = _ace_01_verify_frames(frames, expected_game_id=game_id)
        assembled = _ace_01_reassemble_frames(frames)
        material = decode_material(assembled[1]) if assembled else {"ok": False}
        ids = []
        sequences = []
        if material.get("ok"):
            for row in material.get("leaves") or []:
                message_id = row.get("message_id")
                ids.append(message_id)
                sequences.append(int(row.get("record_sequence") or 0))
                if message_id in STATIC_READY_IDS:
                    generated_static[int(message_id)] = bytes(row["raw"])
        report_indices.append(checked.get("report_index"))
        leaf_sequences.extend(sequences)
        group_checks.append(
            {
                "ok": bool(checked.get("ok")),
                "errors": checked.get("errors") or [],
                "frame_count": len(frames),
                "report_index": checked.get("report_index"),
                "message_ids": [
                    f"0x{value:04X}" for value in ids if value is not None
                ],
            }
        )

    static_checks = {}
    for message_id in STATIC_READY_IDS:
        generated = generated_static.get(message_id)
        expected = ground.get(message_id)
        static_checks[f"0x{message_id:04X}"] = {
            "generated": generated is not None,
            "historical_replay_ground_truth": expected is not None,
            "normalized_body_equal": bool(generated and expected)
            and _normalized_leaf(generated) == _normalized_leaf(expected),
            "generated_length": len(generated or b""),
            "ground_truth_length": len(expected or b""),
            "recording_report_indices": sorted(
                {
                    int(row["report_index"])
                    for row in recorded_rows
                    if row.get("message_id") == message_id
                    and row.get("report_index") is not None
                }
            ),
            "replay_report_indices": sorted(
                {
                    int(row["report_index"])
                    for row in replay["leaves"].get(message_id, [])
                    if row.get("report_index") is not None
                }
            ),
        }

    non_null_reports = [value for value in report_indices if value is not None]
    report_chain_ok = all(
        right == left + 1
        for left, right in zip(non_null_reports, non_null_reports[1:])
    )
    leaf_chain_ok = all(
        right == left + 1 for left, right in zip(leaf_sequences, leaf_sequences[1:])
    )
    same_device = _context_comparison(recorded_context, replay["context"])
    same_player = replenish.get("same_device_player") or {}
    timeline_backtest = _simulate_player_timeline(
        recorded_rows=recorded_rows,
        recorded_context=recorded_context,
        replay=replay,
        game_id=game_id,
        session_id=session_id,
    )
    result = {
        "schema": "dfm-v1285-same-device-backtest-v1",
        "dataset": str(dataset.resolve()),
        "inputs": {
            "pool": str(pool_path.resolve()),
            "replay": str(replay_path.resolve()),
            "game_id": game_id,
            "template_session_id": session_id,
            "recording_pool_items": len(pool),
            "replay_frame_groups": replay["physical_groups"],
            "replay_frame_groups_mechanically_valid": replay["valid_groups"],
            "recording_timing": timing_info,
        },
        "same_device": same_device,
        "historical_content_matrix": _content_matrix(
            recorded_rows, replay["leaves"]
        ),
        "counterfactual_rebuild": {
            "changed": bool(changed),
            "reason": detail.get("reason"),
            "gate": same_player.get("gate"),
            "gate_fields": same_player.get("gate_fields") or [],
            "due_message_ids": same_player.get("due_message_ids") or [],
            "group_checks": group_checks,
            "all_groups_mechanically_valid": all(
                row["ok"] for row in group_checks
            ),
            "report_indices": report_indices,
            "report_chain_continuous": report_chain_ok,
            "leaf_sequence_start": leaf_sequences[0] if leaf_sequences else None,
            "leaf_sequence_end": leaf_sequences[-1] if leaf_sequences else None,
            "leaf_sequence_continuous": leaf_chain_ok,
            "static_checks": static_checks,
            "all_static_bodies_equal_ground_truth": all(
                row["normalized_body_equal"] for row in static_checks.values()
            ),
            "dynamic_pending_message_ids": same_player.get(
                "dynamic_pending_message_ids"
            ) or [],
        },
        "full_player_timeline_backtest": timeline_backtest,
    }
    result["passed"] = bool(
        same_device["all_equal"]
        and result["counterfactual_rebuild"]["all_groups_mechanically_valid"]
        and report_chain_ok
        and leaf_chain_ok
        and result["counterfactual_rebuild"][
            "all_static_bodies_equal_ground_truth"
        ]
        and timeline_backtest.get("ok")
        and timeline_backtest.get("all_message_counts_equal")
        and timeline_backtest.get("all_content_models_validated")
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_backtest(args.dataset)
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
