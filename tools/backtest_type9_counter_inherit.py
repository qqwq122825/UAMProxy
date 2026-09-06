#!/usr/bin/env python3
"""对历史01重放日志回测 0x1105 计数继承与 0x01122388 整叶继承。"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.crypto import _ace_01_reassemble_frames
from core.type9_shadow import (
    build_shadow_logical,
    decode_material,
    template_leaf_rows,
)


DEFAULT_LOGS = (
    "数据/09:干净录制:作弊数据/01ReplayAnalysis/*/01_replace_events.jsonl",
    "数据/10:干净录制:作弊数据/01ReplayAnalysis/*/01_replace_events.jsonl",
    "数据/12:干净录制:作弊数据:封号/01ReplayAnalysis/*/01_replace_events.jsonl",
)
DATA13_LOG = Path(
    "数据/13/01ReplayAnalysis/run_20260802_220509_607074/01_replace_events.jsonl"
)
DATA13_CONTEXT = Path(
    "数据/13/01ReplayAnalysis/run_20260802_220509_607074/"
    "01_unknown_context_samples.jsonl"
)


def _logical(snapshot: dict | None) -> bytes | None:
    frames_hex = (snapshot or {}).get("frames_hex") or []
    if not frames_hex:
        return None
    reassembled = _ace_01_reassemble_frames(
        [bytes.fromhex(value) for value in frames_hex]
    )
    return reassembled[1] if reassembled else None


def _backtest_log(path: Path) -> dict:
    events = [json.loads(line) for line in path.open(encoding="utf-8")]
    rows = []
    seen_templates: set[bytes] = set()
    for event in events:
        logical = _logical(event.get("recorded_template"))
        if logical is None:
            continue
        digest = hashlib.sha256(logical).digest()
        if digest in seen_templates:
            continue
        seen_templates.add(digest)
        rows.extend(
            template_leaf_rows(logical, pool_idx=len(seen_templates) - 1)["rows"]
        )

    stats = {
        "events": len(events),
        "template_packets": len(seen_templates),
        "template_leaves": len(rows),
        "target_events": 0,
        "roundtrip_ok": 0,
        "errors": 0,
        "1105": {
            "total": 0,
            "exact_key_matched": 0,
            "known_clean": 0,
            "live_prefix_0x00_0x23": 0,
            "live_report_counter": 0,
            "sequence_distance_gt_128": 0,
            "gt_128_template_body_applied": 0,
        },
        "01122388": {
            "total": 0,
            "message_id_none": 0,
            "template_matched": 0,
            "full_live_rule": 0,
            "output_equals_live": 0,
        },
    }

    for event in events:
        logical = _logical(event.get("live_input"))
        if logical is None:
            continue
        live = decode_material(logical)
        targets = [
            leaf
            for leaf in live.get("leaves", [])
            if leaf.get("message_id") == 0x1105
            or leaf.get("record_code") == 0x01122388
        ]
        if not targets:
            continue
        stats["target_events"] += 1
        shadow = build_shadow_logical(logical, rows)
        if not shadow.get("generated"):
            stats["errors"] += 1
            continue
        stats["roundtrip_ok"] += bool(shadow.get("roundtrip_ok"))
        candidate = decode_material(shadow["candidate_logical"])
        candidate_by_path = {
            tuple(leaf["path"]): leaf for leaf in candidate["leaves"]
        }
        result_by_path = {
            tuple(leaf["path"]): leaf for leaf in shadow["leaf_results"]
        }
        for leaf in targets:
            output = candidate_by_path[tuple(leaf["path"])]
            result = result_by_path[tuple(leaf["path"])]
            if leaf.get("message_id") == 0x1105:
                row = stats["1105"]
                row["total"] += 1
                row["exact_key_matched"] += bool(result.get("matched"))
                row["known_clean"] += result.get("replacement_level") == "KNOWN_CLEAN"
                row["live_prefix_0x00_0x23"] += (
                    output["raw"][:0x24] == leaf["raw"][:0x24]
                )
                row["live_report_counter"] += (
                    output["raw"][0x20:0x24] == leaf["raw"][0x20:0x24]
                )
                if int(result.get("sequence_distance") or 0) > 128:
                    row["sequence_distance_gt_128"] += 1
                    row["gt_128_template_body_applied"] += (
                        output["raw"] != leaf["raw"]
                    )
            else:
                row = stats["01122388"]
                row["total"] += 1
                row["message_id_none"] += leaf.get("message_id") is None
                row["template_matched"] += bool(result.get("matched"))
                row["full_live_rule"] += (
                    result.get("replacement_level") == "FULL_LIVE_INHERIT"
                )
                row["output_equals_live"] += output["raw"] == leaf["raw"]
    return stats


def _data13_metadata() -> dict:
    stats = {
        "1105_total": 0,
        "exact_record_code_message_id_length_match": 0,
        "old_distance_gate_blocked": 0,
        "old_replaced": 0,
        "lengths": {},
        "max_sequence_distance": 0,
    }
    if not DATA13_LOG.exists():
        return stats
    for line in DATA13_LOG.open(encoding="utf-8"):
        event = json.loads(line)
        for leaf in (event.get("shadow_rebuild") or {}).get("leaf_results") or []:
            if leaf.get("message_id") != 0x1105:
                continue
            stats["1105_total"] += 1
            stats["exact_record_code_message_id_length_match"] += bool(
                leaf.get("matched")
            )
            stats["old_distance_gate_blocked"] += (
                leaf.get("block_reason") == "AGGRESSIVE_BLOCK_DYNAMIC"
            )
            stats["old_replaced"] += leaf.get("replacement_level") in {
                "KNOWN_CLEAN",
                "AGGRESSIVE_UNKNOWN",
            }
            length = str(leaf.get("length"))
            stats["lengths"][length] = stats["lengths"].get(length, 0) + 1
            stats["max_sequence_distance"] = max(
                stats["max_sequence_distance"],
                int(leaf.get("sequence_distance") or 0),
            )
    return stats


def _data13_raw_1105_pair() -> dict:
    rows = []
    if not DATA13_CONTEXT.exists():
        return {"samples": 0}
    for line in DATA13_CONTEXT.open(encoding="utf-8"):
        event = json.loads(line)
        plaintext = bytes.fromhex(event.get("raw_type9_plaintext_hex") or "")
        if len(plaintext) < 0x15 or plaintext[6:10] != bytes.fromhex("010A001B"):
            continue
        cursor = 0x15
        for _ in range(plaintext[0x14]):
            length = int.from_bytes(plaintext[cursor:cursor + 4], "big")
            cursor += 4
            raw = plaintext[cursor:cursor + length]
            cursor += length
            if (
                len(raw) >= 0x24
                and raw[6:10] == bytes.fromhex("0102000A")
                and int.from_bytes(raw[0x16:0x18], "big") == 0x1105
            ):
                rows.append(
                    {
                        "event_id": event["event_id"],
                        "length": length,
                        "sequence": int.from_bytes(raw[10:14], "big"),
                        "counter": int.from_bytes(raw[0x20:0x24], "big"),
                        "raw": raw,
                    }
                )
    varying_offsets = []
    if len(rows) >= 2 and len({row["length"] for row in rows}) == 1:
        varying_offsets = [
            offset
            for offset in range(rows[0]["length"])
            if len({row["raw"][offset] for row in rows}) > 1
        ]
    return {
        "samples": len(rows),
        "rows": [
            {key: value for key, value in row.items() if key != "raw"}
            for row in rows
        ],
        "varying_offsets": [f"0x{offset:02X}" for offset in varying_offsets],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path.cwd()
    logs = []
    for pattern in DEFAULT_LOGS:
        logs.extend(sorted(root.glob(pattern)))
    result = {
        "ruleset": "v1.120-no-sequence-distance-limit",
        "logs": {str(path): _backtest_log(path) for path in logs},
        "data13_metadata": _data13_metadata(),
        "data13_raw_1105_pair": _data13_raw_1105_pair(),
    }
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
