"""Machine-first v1.128 log writer.

Every record is a single compact UTF-8 JSON object.  Replay frames are split
into logical groups before decoding, so one native report followed by several
v1.128 injected reports remains mechanically analyzable.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import time
from collections import OrderedDict, deque
from datetime import datetime
from typing import Iterable


AI_LOG_DIR_NAME = "AI日志"
MANIFEST_SCHEMA = "dfm-ai-log-manifest-v1"
EVENT_SCHEMA = "dfm-ai-01-replay-event-v1"
GROUP_SCHEMA = "dfm-ai-01-group-v1"
LEAF_SCHEMA = "dfm-ai-01-leaf-v1"
CONTROL_EVENT_SCHEMA = "dfm-ai-control-event-v129-v1"
CONTROL_AUDIT_REVISION = "v129-operation-state-audit-r1"
APP_RELEASE_VERSION = "v1.131.2"


def _now() -> tuple[str, int]:
    return (
        datetime.now().isoformat(timespec="milliseconds"),
        time.time_ns() // 1_000_000,
    )


def _json_line(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


def _hex(value: int | None, width: int) -> str | None:
    return f"0x{int(value):0{width}X}" if isinstance(value, int) else None


def _u16_follows(previous: int | None, current: int) -> bool:
    return previous is None or current == ((previous + 1) & 0xFFFF)


def _u32_follows(previous: int | None, current: int) -> bool:
    return previous is None or current == ((previous + 1) & 0xFFFFFFFF)


class V128AiLog:
    FILES = {
        "record_frames": "record_frames.jsonl",
        # 详细01诊断专用：分别保留socket原始TCP请求块，以及TCP重组并按
        # 01长度字段切出的完整物理帧，避免AI从嵌套packet字段二次提取。
        "raw_tcp_requests": "raw_tcp_requests.jsonl",
        "record_3366_frames": "record_3366_frames.jsonl",
        "record_01_slices": "record_01_slices.jsonl",
        "record_reports": "record_reports.jsonl",
        "record_leaves": "record_leaves.jsonl",
        "record_sessions": "record_sessions.jsonl",
        "stream_frames": "stream_frames.jsonl",
        "downlink_events": "downlink_events.jsonl",
        "replay_events": "replay_events.jsonl",
        "replay_groups": "replay_groups.jsonl",
        "replay_leaves": "replay_leaves.jsonl",
        "markers": "markers.jsonl",
        "reconnect_events": "reconnect_events.jsonl",
        "control_events": "control_events.jsonl",
        "template_selection": "template_selection_events.jsonl",
        "anomaly_full": "anomaly_full.jsonl",
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.run_dir: str | None = None
        self.run_id = ""
        self.started_monotonic_ns = 0
        self.counters: dict[str, int] = {}
        self.continuity: dict[str, dict[str, int | None]] = {}
        self.seen_schemas: set[tuple[str, str, int, int | None, int]] = set()
        self.profile_counters: dict[tuple[str, str], int] = {}
        self.replay_context: dict[str, deque] = {}
        self.replay_followups: dict[str, int] = {}

    def reset(self) -> None:
        with self._lock:
            self.run_dir = None
            self.run_id = ""
            self.started_monotonic_ns = 0
            self.counters = {}
            self.continuity = {}
            self.seen_schemas = set()
            self.profile_counters = {}
            self.replay_context = {}
            self.replay_followups = {}

    def path(self, key: str) -> str | None:
        if not self.run_dir:
            return None
        return os.path.join(self.run_dir, self.FILES[key])

    @staticmethod
    def _directory_size(path: str) -> int:
        total = 0
        for root, _, files in os.walk(path):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                except OSError:
                    pass
        return total

    def cleanup_runs(self, data_dir: str, config) -> dict:
        """按保留天数和容量上限整理旧AI日志run目录。"""
        root = os.path.join(data_dir, AI_LOG_DIR_NAME)
        os.makedirs(root, exist_ok=True)
        retention_days = max(
            0, int(config.get("ai_log_retention_days", 7) or 0)
        )
        max_gb = max(0.0, float(config.get("ai_log_max_gb", 10.0) or 0.0))
        protected = os.path.abspath(self.run_dir) if self.run_dir else ""
        rows = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if not name.startswith("run_") or not os.path.isdir(path):
                continue
            try:
                modified = os.path.getmtime(path)
            except OSError:
                continue
            rows.append({"path": path, "modified": modified})

        removed: list[str] = []
        reclaimed = 0

        def remove(row: dict) -> None:
            nonlocal reclaimed
            path = str(row["path"])
            if protected and os.path.abspath(path) == protected:
                return
            size = self._directory_size(path)
            try:
                shutil.rmtree(path)
            except OSError:
                return
            removed.append(os.path.basename(path))
            reclaimed += size

        if retention_days > 0:
            cutoff = time.time() - retention_days * 86400
            for row in list(rows):
                if float(row["modified"]) < cutoff:
                    remove(row)
            rows = [row for row in rows if os.path.isdir(str(row["path"]))]

        max_bytes = int(max_gb * 1024 * 1024 * 1024)
        if max_bytes > 0:
            sized = [
                {**row, "size": self._directory_size(str(row["path"]))}
                for row in rows
            ]
            total = sum(int(row["size"]) for row in sized)
            for row in sorted(sized, key=lambda value: float(value["modified"])):
                if total <= max_bytes:
                    break
                if protected and os.path.abspath(str(row["path"])) == protected:
                    continue
                remove(row)
                total -= int(row["size"])

        return {
            "retention_days": retention_days,
            "max_gb": max_gb,
            "removed_runs": removed,
            "reclaimed_bytes": reclaimed,
        }

    def clear_all_logs(
        self,
        data_dir: str,
        config,
        *,
        start_fresh_run: bool,
    ) -> dict:
        """Delete every entry under AI日志 and optionally start a fresh run.

        The logger lock covers reset, deletion and rotation, so runtime writers
        either finish in the old run or continue in the newly created run.
        Recording/template pools are independent and remain untouched.
        """
        with self._lock:
            root = os.path.join(data_dir, AI_LOG_DIR_NAME)
            os.makedirs(root, exist_ok=True)
            old_run_id = self.run_id
            removed_entries: list[str] = []
            reclaimed_bytes = 0
            errors: list[str] = []
            for name in list(os.listdir(root)):
                path = os.path.join(root, name)
                try:
                    if os.path.isdir(path) and not os.path.islink(path):
                        reclaimed_bytes += self._directory_size(path)
                        shutil.rmtree(path)
                    else:
                        try:
                            reclaimed_bytes += os.path.getsize(path)
                        except OSError:
                            pass
                        os.remove(path)
                    removed_entries.append(name)
                except OSError as exc:
                    errors.append(f"{name}:{exc}")

            self.reset()
            new_run_dir = ""
            if start_fresh_run:
                new_run_dir = self.start_run(
                    data_dir,
                    config,
                    force_new=True,
                )
            return {
                "root": root,
                "old_run_id": old_run_id,
                "new_run_id": self.run_id,
                "new_run_dir": new_run_dir,
                "removed_entries": sorted(removed_entries),
                "removed_count": len(removed_entries),
                "reclaimed_bytes": reclaimed_bytes,
                "errors": errors,
                "fresh_run_started": bool(new_run_dir),
            }

    def start_run(self, data_dir: str, config, *, force_new: bool) -> str:
        with self._lock:
            if self.run_dir and not force_new:
                return self.run_dir
            cleanup = self.cleanup_runs(data_dir, config)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            self.run_id = f"run_{stamp}"
            self.run_dir = os.path.join(data_dir, AI_LOG_DIR_NAME, self.run_id)
            os.makedirs(self.run_dir, exist_ok=True)
            self.started_monotonic_ns = time.monotonic_ns()
            self.counters = {}
            self.continuity = {}
            self.seen_schemas = set()
            self.profile_counters = {}
            self.replay_context = {}
            self.replay_followups = {}

            from core.type9_shadow import SEMANTIC_RULESET_VERSION
            from core.type9_special_rules import type9_hot_rule_store
            from core.type9_v128_replenish import (
                BUILTIN_800D_ANCHOR_SLOTS,
                BUILTIN_800D_SEED_REVISION,
                MODEL_REVISION,
                PLAYER_800A_CLUSTER_INTERVAL_TOLERANCE,
                PLAYER_800A_INNER_STEP,
                PLAYER_800A_MIN_CLUSTERS_TO_EXTEND,
                PLAYER_800A_SPARSE_PERIOD,
                PLAYER_PERIODIC_EXTENSION_PERIODS,
                PLAYER_PERIODIC_MIN_SAMPLES,
                model_summary,
            )

            hot_rule_snapshot = type9_hot_rule_store.snapshot()
            hot_rule_document = hot_rule_snapshot.get("document") or {}
            hot_rule_json = json.dumps(
                hot_rule_document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")

            created_at, created_unix_ms = _now()
            manifest = {
                "schema": MANIFEST_SCHEMA,
                "app_version": APP_RELEASE_VERSION,
                "run_id": self.run_id,
                "created_at": created_at,
                "created_unix_ms": created_unix_ms,
                "encoding": "utf-8",
                "record_format": "jsonl-one-object-per-line",
                "line_ending": "LF",
                "semantic_ruleset": SEMANTIC_RULESET_VERSION,
                "hot_rule_revision": hot_rule_document.get("revision", ""),
                "hot_rule_sha256": hashlib.sha256(hot_rule_json).hexdigest(),
                "hot_rule_actions": {
                    str(rule.get("id") or ""): str(rule.get("action") or "")
                    for rule in hot_rule_document.get("rules") or []
                    if rule.get("id")
                },
                "v128_model_revision": MODEL_REVISION,
                "control_audit_revision": CONTROL_AUDIT_REVISION,
                "v128_model": model_summary(),
                "v128_player_periodic_extension": {
                    "minimum_samples": PLAYER_PERIODIC_MIN_SAMPLES,
                    "periods": {
                        f"0x{message_id:04X}": period
                        for message_id, period in sorted(
                            PLAYER_PERIODIC_EXTENSION_PERIODS.items()
                        )
                    },
                    "800A": {
                        "sparse_period": PLAYER_800A_SPARSE_PERIOD,
                        "inner_step": PLAYER_800A_INNER_STEP,
                        "min_clusters_to_extend": (
                            PLAYER_800A_MIN_CLUSTERS_TO_EXTEND
                        ),
                        "cluster_interval_tolerance": (
                            PLAYER_800A_CLUSTER_INTERVAL_TOLERANCE
                        ),
                    },
                    "event_timeline_policy": "single_pass",
                },
                "v131_builtin_800d": {
                    "message_id": "0x800D",
                    "seed_revision": BUILTIN_800D_SEED_REVISION,
                    "anchor_slots": list(BUILTIN_800D_ANCHOR_SLOTS),
                    "period": PLAYER_PERIODIC_EXTENSION_PERIODS[0x800D],
                    "policy": "LIVE_THEN_RECORDED_DONOR_THEN_BUILTIN",
                },
                "log_cleanup": cleanup,
                "files": dict(self.FILES),
                "record_schemas": {
                    "replay_events": EVENT_SCHEMA,
                    "replay_groups": GROUP_SCHEMA,
                    "replay_leaves": LEAF_SCHEMA,
                    "record_frames": "dfm-ai-01-record-frame-v1",
                    "raw_tcp_requests": "dfm-ai-raw-tcp-request-v1",
                    "record_3366_frames": "dfm-ai-3366-frame-v1",
                    "record_01_slices": "dfm-ai-01-physical-slice-v1",
                    "record_reports": "dfm-ai-01-record-report-v1",
                    "record_leaves": "dfm-ai-01-record-leaf-v1",
                    "record_sessions": "dfm-ai-01-record-session-v1",
                    "stream_frames": "dfm-ai-01-stream-frame-v1",
                    "downlink_events": "dfm-ai-01-downlink-v1",
                    "markers": "dfm-ai-marker-v1",
                    "reconnect_events": "dfm-ai-01-reconnect-v130-v1",
                    "control_events": CONTROL_EVENT_SCHEMA,
                    "template_selection": "dfm-ai-01-template-selection-v1",
                    "anomaly_full": "dfm-ai-01-anomaly-full-v1",
                },
                "field_rules": {
                    "numeric_ids": "integer fields are canonical",
                    "hex_ids": "*_hex fields are display mirrors",
                    "missing_values": "null",
                    "raw_bytes": "uppercase contiguous hexadecimal",
                    "time": "time_unix_ms plus ISO-8601 time",
                    "group_phases": ["input", "template", "shadow", "output"],
                    "output_sources": [
                        "native",
                        "v128_central9",
                        "v130_central_strong",
                        "v128_player_same_device",
                    ],
                },
                "config": {
                    "replenish_01_mode": bool(config.get("replenish_01_mode")),
                    "full_rebuild_01_mode": bool(
                        config.get("full_rebuild_01_mode", False)
                    ),
                    "same_device_replenish_mode": bool(
                        config.get("full_rebuild_01_mode", False)
                    ),
                    "type9_device_mode": config.get("type9_device_mode"),
                    "type9_learning_mode": config.get("type9_learning_mode"),
                    "hold_01_after_threshold": bool(
                        config.get("hold_01_after_threshold")
                    ),
                    "detail_01_log": bool(config.get("detail_01_log", True)),
                    "detail_01_log_users": str(
                        config.get("detail_01_log_users", "test") or "test"
                    ),
                    "ai_log_periodic_full_every": int(
                        config.get("ai_log_periodic_full_every", 100) or 0
                    ),
                    "ai_log_anomaly_context_before": int(
                        config.get("ai_log_anomaly_context_before", 10) or 0
                    ),
                    "ai_log_anomaly_context_after": int(
                        config.get("ai_log_anomaly_context_after", 5) or 0
                    ),
                    "ai_log_retention_days": int(
                        config.get("ai_log_retention_days", 7) or 0
                    ),
                    "ai_log_max_gb": float(
                        config.get("ai_log_max_gb", 10.0) or 0.0
                    ),
                },
            }
            with open(
                os.path.join(self.run_dir, "manifest.json"),
                "w",
                encoding="utf-8",
                newline="\n",
            ) as stream:
                stream.write(json.dumps(manifest, ensure_ascii=False, separators=(",", ":")))
                stream.write("\n")
            return self.run_dir

    def ensure_run(self, data_dir: str, config) -> str:
        return self.start_run(data_dir, config, force_new=False)

    def write_control_event(
        self,
        *,
        source: str,
        action: str,
        phase: str = "after",
        actor: str = "system",
        details: dict | None = None,
        state: dict | None = None,
        ensure_data_dir: str | None = None,
        config=None,
    ) -> str | None:
        """Write one v1.129 operation/state audit row.

        Runtime callers normally append only while a run is active.  Startup
        code may pass ``ensure_data_dir`` and ``config`` after allocating the
        run so the initial state becomes the first auditable row.
        """
        with self._lock:
            if not self.run_dir:
                if not ensure_data_dir or config is None:
                    return None
                self.ensure_run(ensure_data_dir, config)
            time_iso, time_unix_ms = _now()
            elapsed_ms = (
                max(0, (time.monotonic_ns() - self.started_monotonic_ns) // 1_000_000)
                if self.started_monotonic_ns
                else 0
            )
            return self.append(
                "control_events",
                {
                    "schema": CONTROL_EVENT_SCHEMA,
                    "run_id": self.run_id,
                    "event_id": self.next_id("control_event"),
                    "time": time_iso,
                    "time_unix_ms": time_unix_ms,
                    "run_elapsed_ms": elapsed_ms,
                    "source": str(source or "system"),
                    "actor": str(actor or "system"),
                    "action": str(action or "unknown"),
                    "phase": str(phase or "after"),
                    "details": dict(details or {}),
                    "state": dict(state or {}),
                },
            )

    def next_id(self, key: str) -> int:
        self.counters[key] = int(self.counters.get(key) or 0) + 1
        return self.counters[key]

    def append(self, key: str, value: dict) -> str:
        path = self.path(key)
        if not path:
            raise OSError("AI log run is not initialized")
        with open(path, "a", encoding="utf-8", newline="\n") as stream:
            stream.write(_json_line(value))
        return path

    @staticmethod
    def _detail_users(config) -> set[str]:
        raw = str(config.get("detail_01_log_users", "test") or "test")
        return {value.strip() for value in raw.split(",") if value.strip()}

    @classmethod
    def _profile(cls, config, username: str) -> str:
        if (
            bool(config.get("detail_01_log", True))
            and str(username or "") in cls._detail_users(config)
        ):
            return "full"
        return "compact"

    def _periodic_due(self, config, username: str, channel: str) -> bool:
        every = max(0, int(config.get("ai_log_periodic_full_every", 100) or 0))
        key = (str(username or ""), str(channel or ""))
        count = int(self.profile_counters.get(key) or 0) + 1
        self.profile_counters[key] = count
        return bool(every and count % every == 0)

    def _new_schema_reasons(
        self,
        username: str,
        channel: str,
        leaves: list[dict],
    ) -> list[str]:
        reasons: list[str] = []
        for leaf in leaves:
            message_id = leaf.get("message_id")
            key = (
                str(username or ""),
                str(channel or ""),
                int(leaf.get("record_code") or 0),
                int(message_id) if isinstance(message_id, int) else None,
                int(leaf.get("actual_length") or len(leaf.get("raw") or b"")),
            )
            if key in self.seen_schemas:
                continue
            self.seen_schemas.add(key)
            reasons.append(
                f"new_schema:{key[2]:08X}:{key[3] if key[3] is not None else -1:04X}:{key[4]}"
            )
        return reasons

    @staticmethod
    def _hot_leaf_reasons(leaves: list[dict]) -> list[str]:
        hot_ids = {0x0207, 0x2000, 0x2001, 0x8002, 0x8027, 0x8028, 0x8029, 0x9000}
        found = {
            int(leaf.get("message_id"))
            for leaf in leaves
            if isinstance(leaf.get("message_id"), int)
            and int(leaf.get("message_id")) in hot_ids
        }
        return [f"hot_message:0x{value:04X}" for value in sorted(found)]

    @staticmethod
    def _compact_snapshot(snapshot: dict, *, full: bool) -> dict:
        output = dict(snapshot)
        output["capture"] = "full" if full else "compact"
        if not full:
            output["frames_hex"] = None
            output["logical_hex"] = None
        return output

    @staticmethod
    def _frame_capture(detail: dict) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for key, aliases in {
            "input": ("input_frames", "live_frames"),
            "template": ("template_frames",),
            "shadow": ("shadow_frames",),
            "output": ("output_frames",),
        }.items():
            frames = []
            for alias in aliases:
                frames = list(detail.get(alias) or [])
                if frames:
                    break
            result[key] = [bytes(frame).hex().upper() for frame in frames]
        return result

    def _append_anomaly(
        self,
        *,
        source_kind: str,
        event_id: int,
        username: str,
        client_ip: str,
        conn_id: str,
        game_id: str | None,
        reasons: list[str],
        capture: dict,
        context_before: list[dict] | None = None,
    ) -> str:
        time_iso, time_unix_ms = _now()
        return self.append(
            "anomaly_full",
            {
                "schema": "dfm-ai-01-anomaly-full-v1",
                "run_id": self.run_id,
                "anomaly_id": self.next_id("anomaly_full"),
                "event_id": event_id,
                "time": time_iso,
                "time_unix_ms": time_unix_ms,
                "source_kind": source_kind,
                "proxy_username": username or None,
                "client_ip": client_ip or None,
                "connection_id": conn_id or None,
                "game_id": game_id or None,
                "reasons": list(dict.fromkeys(reasons)),
                "context_before": list(context_before or []),
                "capture": capture,
            },
        )

    @staticmethod
    def _split_groups(frames: Iterable[bytes]) -> list[list[bytes]]:
        from core.crypto import _ace_01_fragment_key

        groups: OrderedDict[tuple, list[bytes]] = OrderedDict()
        raw_index = 0
        for source in frames:
            frame = bytes(source)
            key = _ace_01_fragment_key(frame)
            if key is None:
                key = ("raw", raw_index)
                raw_index += 1
            groups.setdefault(key, []).append(frame)
        return list(groups.values())

    @staticmethod
    def _snapshot(frames: list[bytes]) -> tuple[dict, list[dict]]:
        from core.crypto import (
            _ace_01_reassemble_frames,
            _ace_01_report_index,
            _ace_01_verify_frames,
        )
        from core.type9_shadow import decode_material

        checked = _ace_01_verify_frames(frames)
        assembled = _ace_01_reassemble_frames(frames)
        ordered = assembled[0] if assembled else list(frames)
        logical = assembled[1] if assembled else b""
        first = ordered[0] if ordered else b""
        material = decode_material(logical) if logical else {"ok": False}
        leaves = list(material.get("leaves") or []) if material.get("ok") else []
        report_index = _ace_01_report_index(logical) if logical else None
        message_ids = [
            int(leaf["message_id"])
            for leaf in leaves
            if isinstance(leaf.get("message_id"), int)
        ]
        snapshot = {
            "frame_count": len(ordered),
            "frame_lengths": [len(frame) for frame in ordered],
            "frames_hex": [frame.hex().upper() for frame in ordered],
            "frames_sha256": hashlib.sha256(b"".join(ordered)).hexdigest(),
            "logical_length": len(logical),
            "logical_hex": logical.hex().upper() if logical else None,
            "logical_sha256": hashlib.sha256(logical).hexdigest() if logical else None,
            "report_index": report_index,
            "frame_sequence_start": (
                int.from_bytes(first[8:10], "big") if len(first) >= 10 else None
            ),
            "frame_sequence_end": (
                int.from_bytes(ordered[-1][8:10], "big")
                if ordered and len(ordered[-1]) >= 10
                else None
            ),
            "packet_group": (
                int.from_bytes(first[36:38], "big") if len(first) >= 38 else None
            ),
            "game_id": checked.get("account_id") or None,
            "outer_crc32_hex": checked.get("crc_hex") or None,
            "calculated_crc32_hex": checked.get("calculated_crc_hex") or None,
            "outer_crc_ok": bool(
                checked.get("crc_hex")
                and checked.get("crc_hex") == checked.get("calculated_crc_hex")
            ),
            "frame_validation_ok": bool(checked.get("ok")),
            "frame_validation_errors": list(checked.get("errors") or []),
            "type9_decode_ok": bool(material.get("ok")),
            "type9_plain_crc_ok": True if material.get("ok") else None,
            "leaf_count": len(leaves),
            "leaf_sequence_start": (
                int(leaves[0].get("record_sequence") or 0) if leaves else None
            ),
            "leaf_sequence_end": (
                int(leaves[-1].get("record_sequence") or 0) if leaves else None
            ),
            "message_ids": message_ids,
            "message_ids_hex": [_hex(value, 4) for value in message_ids],
        }
        return snapshot, leaves

    def _output_continuity(
        self,
        conn_id: str,
        snapshot: dict,
        frames: list[bytes],
        leaves: list[dict],
    ) -> dict:
        state = self.continuity.setdefault(
            conn_id,
            {"report": None, "leaf": None, "frame": None, "group": None},
        )
        report = snapshot.get("report_index")
        report_ok = None
        if isinstance(report, int):
            report_ok = _u32_follows(state.get("report"), report)
            state["report"] = report

        group = snapshot.get("packet_group")
        group_ok = None
        if isinstance(group, int):
            group_ok = _u16_follows(state.get("group"), group)
            state["group"] = group

        frame_ok = True
        for frame in frames:
            if len(frame) < 10:
                frame_ok = False
                continue
            value = int.from_bytes(frame[8:10], "big")
            frame_ok = frame_ok and _u16_follows(state.get("frame"), value)
            state["frame"] = value

        leaf_ok = True
        for leaf in leaves:
            value = int(leaf.get("record_sequence") or 0)
            leaf_ok = leaf_ok and _u32_follows(state.get("leaf"), value)
            state["leaf"] = value

        return {
            "report_plus_one": report_ok,
            "leaf_plus_one": leaf_ok if leaves else None,
            "frame_plus_one_u16": frame_ok if frames else None,
            "packet_group_plus_one_u16": group_ok,
        }

    @staticmethod
    def _offsets(value: dict | None) -> dict:
        source = value or {}
        return {
            key: int(source.get(key) or 0)
            for key in ("report_offset", "leaf_offset", "frame_offset", "group_offset")
        }

    def write_replay_event(
        self,
        *,
        data_dir: str,
        config,
        detail: dict,
        username: str,
        client_ip: str,
        conn_id: str,
    ) -> str:
        with self._lock:
            self.ensure_run(data_dir, config)
            event_id = self.next_id("replay_event")
            time_iso, time_unix_ms = _now()
            v128 = dict(detail.get("v128_replenish") or {})
            injected_meta = list(v128.get("groups") or [])
            state_after = dict(v128.get("state") or {})
            offsets_before = self._offsets(v128.get("offsets_before"))
            offsets_after = self._offsets(
                v128.get("offsets_after") or state_after
            )
            elapsed_ms = v128.get("elapsed_ms")
            profile = self._profile(config, username)
            periodic_full = (
                profile == "compact"
                and self._periodic_due(config, username, "replay_event")
            )
            shadow = detail.get("shadow_rebuild") or {}
            event_capture_reasons: list[str] = []
            if detail.get("validation_errors"):
                event_capture_reasons.append("validation_errors")
            if str(detail.get("decision") or "").upper().startswith("DROP"):
                event_capture_reasons.append("drop_decision")
            for key in (
                "special_dropped_leaves",
                "special_emptied_leaves",
                "special_changed_leaves",
            ):
                if int(shadow.get(key) or 0) > 0:
                    event_capture_reasons.append(key)

            phase_inputs = [
                ("input", "live", detail.get("input_frames") or detail.get("live_frames") or []),
                ("template", "recording_template", detail.get("template_frames") or []),
                ("shadow", "semantic_candidate", detail.get("shadow_frames") or []),
            ]
            group_ids: dict[str, list[int]] = {
                "input": [], "template": [], "shadow": [], "output": []
            }
            output_checks: list[bool] = []
            leaf_result_by_path = {
                tuple(row.get("path") or []): row
                for row in ((detail.get("shadow_rebuild") or {}).get("leaf_results") or [])
            }

            def write_group(
                phase: str,
                source: str,
                ordinal: int,
                frames: list[bytes],
                injection: dict | None = None,
            ) -> None:
                snapshot, leaves = self._snapshot(frames)
                group_id = self.next_id("replay_group")
                group_ids[phase].append(group_id)
                continuity = (
                    self._output_continuity(conn_id, snapshot, frames, leaves)
                    if phase == "output"
                    else None
                )
                if phase == "output":
                    output_checks.append(bool(snapshot["frame_validation_ok"]))
                    output_checks.extend(
                        value is not False
                        for value in (continuity or {}).values()
                    )
                group_reasons: list[str] = []
                if not snapshot.get("frame_validation_ok"):
                    group_reasons.append(f"{phase}:frame_validation")
                if continuity and any(value is False for value in continuity.values()):
                    group_reasons.append(f"{phase}:sequence_discontinuity")
                group_reasons.extend(
                    self._new_schema_reasons(
                        username, f"replay_{phase}", leaves
                    )
                )
                group_reasons.extend(self._hot_leaf_reasons(leaves))
                if phase == "input":
                    for leaf in leaves:
                        semantic = leaf_result_by_path.get(
                            tuple(leaf.get("path") or []), {}
                        )
                        action = str(semantic.get("special_rule_action") or "")
                        if action:
                            group_reasons.append(f"special_action:{action}")
                event_capture_reasons.extend(group_reasons)
                full_capture = bool(
                    profile == "full"
                    or periodic_full
                    or group_reasons
                    or event_capture_reasons
                )
                group_row = {
                    "schema": GROUP_SCHEMA,
                    "run_id": self.run_id,
                    "event_id": event_id,
                    "group_id": group_id,
                    "time": time_iso,
                    "time_unix_ms": time_unix_ms,
                    "connection_id": conn_id,
                    "client_ip": client_ip,
                    "proxy_username": username,
                    "phase": phase,
                    "source": source,
                    "group_ordinal": ordinal,
                    "injection": injection,
                    "continuity": continuity,
                    "log_profile": profile,
                    "full_capture_reasons": list(dict.fromkeys(group_reasons)),
                    "packet": self._compact_snapshot(snapshot, full=full_capture),
                }
                self.append("replay_groups", group_row)

                for leaf_ordinal, leaf in enumerate(leaves):
                    message_id = leaf.get("message_id")
                    record_code = int(leaf.get("record_code") or 0)
                    raw = bytes(leaf.get("raw") or b"")
                    path = list(leaf.get("path") or [])
                    semantic = leaf_result_by_path.get(tuple(path), {}) if phase == "input" else {}
                    leaf_row = {
                        "schema": LEAF_SCHEMA,
                        "run_id": self.run_id,
                        "event_id": event_id,
                        "group_id": group_id,
                        "leaf_id": self.next_id("replay_leaf"),
                        "phase": phase,
                        "source": source,
                        "group_ordinal": ordinal,
                        "leaf_ordinal": leaf_ordinal,
                        "path": path,
                        "report_index": snapshot.get("report_index"),
                        "record_code": record_code,
                        "record_code_hex": _hex(record_code, 8),
                        "message_id": int(message_id) if isinstance(message_id, int) else None,
                        "message_id_hex": _hex(message_id, 4),
                        "record_sequence": int(leaf.get("record_sequence") or 0),
                        "length": int(leaf.get("actual_length") or len(raw)),
                        "logical_slot_u16": (
                            int.from_bytes(raw[0x1C:0x1E], "big") if len(raw) >= 0x1E else None
                        ),
                        "raw_hex": raw.hex().upper() if full_capture else None,
                        "raw_sha256": hashlib.sha256(raw).hexdigest(),
                        "log_profile": profile,
                        "full_capture": full_capture,
                        "semantic": {
                            key: semantic.get(key)
                            for key in (
                                "replacement_level", "special_rule_id",
                                "special_rule_action", "block_reason",
                                "matched", "semantic_ready",
                            )
                            if key in semantic
                        },
                    }
                    self.append("replay_leaves", leaf_row)

            for phase, source, frames in phase_inputs:
                for ordinal, group in enumerate(self._split_groups(frames)):
                    write_group(phase, source, ordinal, group)

            output_frames = detail.get("output_frames") or []
            for ordinal, group in enumerate(self._split_groups(output_frames)):
                injection = injected_meta[ordinal - 1] if ordinal > 0 and ordinal - 1 < len(injected_meta) else None
                if ordinal == 0:
                    source = "native"
                elif str((injection or {}).get("layer") or "") == "player_same_device":
                    source = "v128_player_same_device"
                elif str((injection or {}).get("layer") or "") == "central_strong":
                    source = "v130_central_strong"
                else:
                    source = "v128_central9"
                write_group("output", source, ordinal, group, injection)

            event = {
                "schema": EVENT_SCHEMA,
                "run_id": self.run_id,
                "event_id": event_id,
                "time": time_iso,
                "time_unix_ms": time_unix_ms,
                "connection": {
                    "connection_id": conn_id,
                    "client_ip": client_ip,
                    "proxy_username": username,
                    "game_id": detail.get("account_id") or None,
                },
                "decision": detail.get("decision") or None,
                "reason": detail.get("reason") or None,
                "replacement_level": detail.get("replacement_level") or None,
                "group_ids": group_ids,
                "group_counts": {key: len(value) for key, value in group_ids.items()},
                "cursor": {
                    "before": detail.get("cursor_before"),
                    "selected_pool_index": detail.get("pool_idx"),
                    "after": detail.get("cursor_after"),
                    "pool_total": int(detail.get("pool_total") or 0),
                },
                "v128": {
                    "enabled": bool(v128.get("enabled")),
                    "model_revision": v128.get("model_revision"),
                    "elapsed_ms": elapsed_ms,
                    "offsets_before": offsets_before,
                    "offsets_after": offsets_after,
                    "injected_report_count": len(injected_meta),
                    "injected_leaf_count": int(v128.get("leaf_count") or 0),
                    "injected_frame_count": int(v128.get("frame_count") or 0),
                    "central_group_count": int(
                        v128.get("central_group_count") or 0
                    ),
                    "player_group_count": int(
                        v128.get("player_group_count") or 0
                    ),
                    "same_device_player": dict(
                        v128.get("same_device_player") or {}
                    ),
                    "groups": injected_meta,
                },
                "semantic": {
                    key: shadow.get(key)
                    for key in (
                        "status", "total_leaves", "matched_leaves", "changed_leaves",
                        "special_handled_leaves", "special_changed_leaves",
                        "special_dropped_leaves", "special_emptied_leaves",
                        "unmatched_pass_live_leaves", "unmapped_pass_live_leaves",
                    )
                    if key in shadow
                },
                "checks": {
                    "all_output_groups_valid": all(output_checks),
                    "output_group_check_count": len(output_checks),
                    "final_identity_check": detail.get("final_identity_check"),
                },
                "validation_errors": list(detail.get("validation_errors") or []),
                "log_profile": profile,
                "periodic_full_sample": periodic_full,
                "full_capture_reasons": list(dict.fromkeys(event_capture_reasons)),
            }
            path = self.append("replay_events", event)

            context_limit = max(
                0, int(config.get("ai_log_anomaly_context_before", 10) or 0)
            )
            context = self.replay_context.get(conn_id)
            if context is None or context.maxlen != context_limit:
                context = deque(list(context or [])[-context_limit:], maxlen=context_limit)
                self.replay_context[conn_id] = context
            current_capture = self._frame_capture(detail)
            unique_reasons = list(dict.fromkeys(event_capture_reasons))
            if unique_reasons:
                self._append_anomaly(
                    source_kind="replay",
                    event_id=event_id,
                    username=username,
                    client_ip=client_ip,
                    conn_id=conn_id,
                    game_id=str(detail.get("account_id") or ""),
                    reasons=unique_reasons,
                    capture=current_capture,
                    context_before=list(context),
                )
                self.replay_followups[conn_id] = max(
                    0, int(config.get("ai_log_anomaly_context_after", 5) or 0)
                )
            elif int(self.replay_followups.get(conn_id) or 0) > 0:
                self._append_anomaly(
                    source_kind="replay_post_context",
                    event_id=event_id,
                    username=username,
                    client_ip=client_ip,
                    conn_id=conn_id,
                    game_id=str(detail.get("account_id") or ""),
                    reasons=["post_anomaly_context"],
                    capture=current_capture,
                )
                self.replay_followups[conn_id] -= 1
            if context_limit:
                context.append(
                    {
                        "event_id": event_id,
                        "time": time_iso,
                        "output": current_capture.get("output") or [],
                    }
                )
            return path

    def write_raw_tcp_request(
        self,
        *,
        data_dir: str,
        config,
        conn_id: str,
        direction: str,
        dst: str,
        mode: str,
        label: str,
        data: bytes,
        username: str,
    ) -> str | None:
        """详细01日志：记录协议识别/缓存/长度切帧之前的socket原始请求块。"""
        with self._lock:
            if not data or self._profile(config, username) != "full":
                return None
            self.ensure_run(data_dir, config)
            time_iso, time_unix_ms = _now()
            raw = bytes(data)
            return self.append(
                "raw_tcp_requests",
                {
                    "schema": "dfm-ai-raw-tcp-request-v1",
                    "run_id": self.run_id,
                    "event_id": self.next_id("raw_tcp_request"),
                    "time": time_iso,
                    "time_unix_ms": time_unix_ms,
                    "capture_stage": "socket_read_pre_protocol_split",
                    "connection_id": conn_id or None,
                    "direction": direction or None,
                    "destination": dst or None,
                    "proxy_mode": mode or None,
                    "server_label": label or None,
                    "proxy_username": username or None,
                    "raw_length": len(raw),
                    "raw_tcp_hex": raw.hex().upper(),
                    "raw_tcp_sha256": hashlib.sha256(raw).hexdigest(),
                    "starts_with_01": bool(raw.startswith(b"\x01\x00")),
                    "contains_3366_magic": bool(b"\x33\x66" in raw),
                    "log_profile": "full",
                },
            )

    def write_3366_frame(
        self,
        *,
        data_dir: str,
        config,
        conn_id: str,
        direction: str,
        client_ip: str,
        uid: str,
        mode: str,
        frame: bytes,
        plaintext: bytes | None,
        username: str,
        message_type_hex: str | None = None,
        sequence: int | None = None,
    ) -> str | None:
        """记录一条完整3366帧：原始整帧、4013密文、解密后明文。"""
        with self._lock:
            raw = bytes(frame or b"")
            if not raw:
                return None
            self.ensure_run(data_dir, config)
            time_iso, time_unix_ms = _now()
            profile = self._profile(config, username)
            msg_hex = (
                str(message_type_hex or "").upper()
                or (raw[6:8].hex().upper() if len(raw) >= 8 else None)
            )
            ciphertext = None
            decrypt_status = "not_encrypted"
            if msg_hex == "4013":
                decrypt_status = "key_unavailable"
                if len(raw) >= 25:
                    enc_len = int.from_bytes(raw[19:21], "big")
                    if enc_len <= 0 or enc_len % 16 or 25 + enc_len > len(raw):
                        decrypt_status = "ciphertext_layout_invalid"
                    else:
                        ciphertext = raw[25:25 + enc_len]
                if plaintext:
                    decrypt_status = "success"

            plain = bytes(plaintext) if plaintext else None
            reasons: list[str] = []
            if decrypt_status in (
                "failed",
                "ciphertext_layout_invalid",
            ):
                reasons.append(f"3366:{decrypt_status}")
            if plain and (
                b"\x01\x0A\x00\x09" in plain or b"\x01\x0A\x00\x23" in plain
            ):
                reasons.append("3366:plaintext_contains_01_marker")
            periodic = (
                profile == "compact"
                and self._periodic_due(config, username, "3366_frame")
            )
            full_capture = bool(profile == "full" or periodic or reasons)
            event_id = self.next_id("record_3366_frame")
            path = self.append(
                "record_3366_frames",
                {
                    "schema": "dfm-ai-3366-frame-v1",
                    "run_id": self.run_id,
                    "event_id": event_id,
                    "time": time_iso,
                    "time_unix_ms": time_unix_ms,
                    "capture_stage": "post_3366_magic_split",
                    "direction": direction or None,
                    "client_ip": client_ip or None,
                    "connection_id": conn_id or None,
                    "game_id": uid or None,
                    "proxy_mode": mode or None,
                    "proxy_username": username or None,
                    "message_type_hex": msg_hex,
                    "sequence": sequence,
                    "frame_length": len(raw),
                    "raw_frame_hex": raw.hex().upper() if full_capture else None,
                    "raw_frame_sha256": hashlib.sha256(raw).hexdigest(),
                    "ciphertext_length": len(ciphertext) if ciphertext else None,
                    "ciphertext_hex": (
                        ciphertext.hex().upper()
                        if ciphertext is not None and full_capture
                        else None
                    ),
                    "ciphertext_sha256": (
                        hashlib.sha256(ciphertext).hexdigest()
                        if ciphertext is not None
                        else None
                    ),
                    "decrypt_status": decrypt_status,
                    "plaintext_length": len(plain) if plain else None,
                    "plaintext_hex": (
                        plain.hex().upper() if plain is not None and full_capture else None
                    ),
                    "plaintext_sha256": (
                        hashlib.sha256(plain).hexdigest() if plain is not None else None
                    ),
                    "contains_01_0a_00_09": bool(
                        plain and b"\x01\x0A\x00\x09" in plain
                    ),
                    "log_profile": profile,
                    "periodic_full_sample": periodic,
                    "full_capture": full_capture,
                    "full_capture_reasons": list(dict.fromkeys(reasons)),
                },
            )
            if reasons:
                self._append_anomaly(
                    source_kind="3366_frame",
                    event_id=event_id,
                    username=username,
                    client_ip=client_ip,
                    conn_id=conn_id,
                    game_id=uid,
                    reasons=reasons,
                    capture={
                        "message_type_hex": msg_hex,
                        "decrypt_status": decrypt_status,
                        "raw_frame_hex": raw.hex().upper() if full_capture else None,
                    },
                )
            return path

    def write_record_frame(
        self,
        *,
        data_dir: str,
        config,
        direction: str,
        client_ip: str,
        conn_id: str,
        uid: str,
        data: bytes,
        username: str,
    ) -> str:
        with self._lock:
            self.ensure_run(data_dir, config)
            time_iso, time_unix_ms = _now()
            snapshot, leaves = self._snapshot([bytes(data)])
            profile = self._profile(config, username)
            reasons: list[str] = []
            if not snapshot.get("frame_validation_ok"):
                reasons.append("record:frame_validation")
            reasons.extend(self._new_schema_reasons(username, "record_frame", leaves))
            reasons.extend(self._hot_leaf_reasons(leaves))
            periodic = (
                profile == "compact"
                and self._periodic_due(config, username, "record_frame")
            )
            full_capture = bool(profile == "full" or periodic or reasons)
            event_id = self.next_id("record_frame")
            path = self.append(
                "record_frames",
                {
                    "schema": "dfm-ai-01-record-frame-v1",
                    "run_id": self.run_id,
                    "event_id": event_id,
                    "time": time_iso,
                    "time_unix_ms": time_unix_ms,
                    "direction": direction or None,
                    "client_ip": client_ip or None,
                    "connection_id": conn_id or None,
                    "game_id": uid or None,
                    "proxy_username": username or None,
                    "log_profile": profile,
                    "periodic_full_sample": periodic,
                    "full_capture_reasons": list(dict.fromkeys(reasons)),
                    "packet": self._compact_snapshot(snapshot, full=full_capture),
                },
            )
            # 详细诊断索引：将TCP重组和01长度切割后的完整物理帧单独平铺。
            # full_capture 同时覆盖detail用户、周期样本及异常/新结构样本。
            if full_capture:
                self.append(
                    "record_01_slices",
                    {
                        "schema": "dfm-ai-01-physical-slice-v1",
                        "run_id": self.run_id,
                        "event_id": self.next_id("record_01_slice"),
                        "source_event_id": event_id,
                        "time": time_iso,
                        "time_unix_ms": time_unix_ms,
                        "capture_stage": "post_tcp_reassembly_and_01_length_split",
                        "slice_kind": "01_physical_frame",
                        "direction": direction or None,
                        "client_ip": client_ip or None,
                        "connection_id": conn_id or None,
                        "game_id": uid or None,
                        "proxy_username": username or None,
                        "slice_length": len(data),
                        "raw_01_hex": bytes(data).hex().upper(),
                        "raw_01_sha256": hashlib.sha256(bytes(data)).hexdigest(),
                        "frame_validation_ok": bool(snapshot.get("frame_validation_ok")),
                        "frame_validation_errors": list(
                            snapshot.get("frame_validation_errors") or []
                        ),
                        "report_index": snapshot.get("report_index"),
                        "packet_group": snapshot.get("packet_group"),
                        "frame_sequence_start": snapshot.get("frame_sequence_start"),
                        "frame_sequence_end": snapshot.get("frame_sequence_end"),
                        "leaf_count": snapshot.get("leaf_count"),
                        "message_ids_hex": list(snapshot.get("message_ids_hex") or []),
                        "log_profile": profile,
                        "full_capture_reasons": list(dict.fromkeys(reasons)),
                    },
                )
            if reasons:
                self._append_anomaly(
                    source_kind="record_frame",
                    event_id=event_id,
                    username=username,
                    client_ip=client_ip,
                    conn_id=conn_id,
                    game_id=uid,
                    reasons=reasons,
                    capture={"frames": [bytes(data).hex().upper()]},
                )
            return path

    def write_stream_frame(
        self,
        *,
        data_dir: str,
        config,
        kind: str,
        direction: str,
        uid: str,
        data: bytes,
        username: str,
    ) -> str:
        with self._lock:
            self.ensure_run(data_dir, config)
            time_iso, time_unix_ms = _now()
            snapshot, _ = self._snapshot([bytes(data)])
            profile = self._profile(config, username)
            reasons = [] if snapshot.get("frame_validation_ok") else ["stream:frame_validation"]
            periodic = (
                profile == "compact"
                and self._periodic_due(config, username, "stream_frame")
            )
            full_capture = bool(profile == "full" or periodic or reasons)
            return self.append(
                "stream_frames",
                {
                    "schema": "dfm-ai-01-stream-frame-v1",
                    "run_id": self.run_id,
                    "event_id": self.next_id("stream_frame"),
                    "time": time_iso,
                    "time_unix_ms": time_unix_ms,
                    "kind": kind or None,
                    "direction": direction or None,
                    "game_id": uid or None,
                    "proxy_username": username or None,
                    "log_profile": profile,
                    "periodic_full_sample": periodic,
                    "full_capture_reasons": reasons,
                    "packet": self._compact_snapshot(snapshot, full=full_capture),
                },
            )

    def write_record_report(
        self,
        *,
        data_dir: str,
        config,
        client_ip: str,
        session: dict,
        item: dict,
    ) -> str | None:
        from core.type9_shadow import decode_material

        with self._lock:
            self.ensure_run(data_dir, config)
            raw_packet = bytes(item.get("raw_packet") or b"")
            decoded = decode_material(raw_packet) if raw_packet else {"ok": False}
            if not decoded.get("ok") or not decoded.get("leaves"):
                return None
            time_iso, time_unix_ms = _now()
            report_event_id = self.next_id("record_report")
            leaves = list(decoded.get("leaves") or [])
            username = str(session.get("owner_username") or "")
            profile = self._profile(config, username)
            reasons = self._new_schema_reasons(
                username, "record_report", leaves
            )
            reasons.extend(self._hot_leaf_reasons(leaves))
            periodic = (
                profile == "compact"
                and self._periodic_due(config, username, "record_report")
            )
            full_capture = bool(profile == "full" or periodic or reasons)
            report = {
                "schema": "dfm-ai-01-record-report-v1",
                "run_id": self.run_id,
                "event_id": report_event_id,
                "time": time_iso,
                "time_unix_ms": time_unix_ms,
                "client_ip": client_ip or None,
                "session_id": session.get("sid") or None,
                "game_id": session.get("game_id") or item.get("account_id") or None,
                "proxy_username": username or None,
                "report_index": item.get("report_index"),
                "top_record_code": int((decoded.get("root") or {}).get("record_code") or 0),
                "leaf_count": len(leaves),
                "type9_plaintext_hex": (
                    bytes(decoded.get("plaintext") or b"").hex().upper()
                    if full_capture else None
                ),
                "type9_plaintext_sha256": hashlib.sha256(
                    bytes(decoded.get("plaintext") or b"")
                ).hexdigest(),
                "log_profile": profile,
                "periodic_full_sample": periodic,
                "full_capture_reasons": list(dict.fromkeys(reasons)),
            }
            path = self.append("record_reports", report)
            for ordinal, leaf in enumerate(leaves):
                raw = bytes(leaf.get("raw") or b"")
                message_id = leaf.get("message_id")
                record_code = int(leaf.get("record_code") or 0)
                self.append(
                    "record_leaves",
                    {
                        "schema": "dfm-ai-01-record-leaf-v1",
                        "run_id": self.run_id,
                        "event_id": report_event_id,
                        "leaf_id": self.next_id("record_leaf"),
                        "leaf_ordinal": ordinal,
                        "time": time_iso,
                        "time_unix_ms": time_unix_ms,
                        "session_id": session.get("sid") or None,
                        "game_id": report["game_id"],
                        "report_index": item.get("report_index"),
                        "path": list(leaf.get("path") or []),
                        "record_code": record_code,
                        "record_code_hex": _hex(record_code, 8),
                        "message_id": int(message_id) if isinstance(message_id, int) else None,
                        "message_id_hex": _hex(message_id, 4),
                        "record_sequence": int(leaf.get("record_sequence") or 0),
                        "length": int(leaf.get("actual_length") or len(raw)),
                        "logical_slot_u16": (
                            int.from_bytes(raw[0x1C:0x1E], "big") if len(raw) >= 0x1E else None
                        ),
                        "raw_hex": raw.hex().upper() if full_capture else None,
                        "raw_sha256": hashlib.sha256(raw).hexdigest(),
                        "log_profile": profile,
                        "full_capture": full_capture,
                    },
                )
            if reasons:
                self._append_anomaly(
                    source_kind="record_report",
                    event_id=report_event_id,
                    username=username,
                    client_ip=client_ip,
                    conn_id=str(session.get("sid") or ""),
                    game_id=str(report.get("game_id") or ""),
                    reasons=reasons,
                    capture={
                        "type9_plaintext_hex": bytes(
                            decoded.get("plaintext") or b""
                        ).hex().upper(),
                        "leaves_hex": [
                            bytes(leaf.get("raw") or b"").hex().upper()
                            for leaf in leaves
                        ],
                    },
                )
            return path

    def write_record_session(
        self,
        *,
        data_dir: str,
        config,
        action: str,
        session: dict,
        client_ip: str,
        reason: str,
    ) -> str:
        with self._lock:
            self.ensure_run(data_dir, config)
            time_iso, time_unix_ms = _now()
            pool = list(session.get("pool_items") or [])
            return self.append(
                "record_sessions",
                {
                    "schema": "dfm-ai-01-record-session-v1",
                    "run_id": self.run_id,
                    "event_id": self.next_id("record_session"),
                    "time": time_iso,
                    "time_unix_ms": time_unix_ms,
                    "action": str(action or "UPDATE").upper(),
                    "reason": reason or None,
                    "session_id": session.get("sid") or None,
                    "client_ip": client_ip or None,
                    "proxy_username": session.get("owner_username") or None,
                    "game_id": session.get("game_id") or None,
                    "pool_scope": session.get("pool_scope") or "player",
                    "batch_id": session.get("batch_id") or None,
                    "active": bool(session.get("active")),
                    "counts": {
                        "01": sum(1 for row in pool if not str(row.get("source") or "").startswith("3366")),
                        "33": sum(1 for row in pool if str(row.get("source") or "").startswith("3366")),
                        "total": len(pool),
                    },
                },
            )

    def write_downlink(
        self,
        *,
        data_dir: str,
        config,
        mode: str,
        client_ip: str,
        conn_id: str,
        uid: str,
        data: bytes,
        username: str,
        disposition: str,
        reason: str,
    ) -> str:
        with self._lock:
            self.ensure_run(data_dir, config)
            time_iso, time_unix_ms = _now()
            snapshot, leaves = self._snapshot([bytes(data)])
            profile = self._profile(config, username)
            reasons: list[str] = []
            if not snapshot.get("frame_validation_ok"):
                reasons.append("downlink:frame_validation")
            disposition_key = str(disposition or "FORWARD").upper()
            routine_dispositions = {"FORWARD", "INTERCEPT_SCAN"}
            routine_reasons = {
                "RECORD_SERVER_DOWNLINK",
                "RECORD_SERVER_DOWNLINK_RESTAMP",
                "REPLAY_SERVER_DOWNLINK",
                "TYPE8_ZIP_AND_TYPE9_MRPCS_SCAN",
            }
            if disposition_key not in routine_dispositions:
                reasons.append(f"downlink:{disposition_key}")
            if reason and str(reason) not in routine_reasons:
                reasons.append(f"downlink_reason:{reason}")
            reasons.extend(self._new_schema_reasons(username, "downlink", leaves))
            reasons.extend(self._hot_leaf_reasons(leaves))
            periodic = (
                profile == "compact"
                and self._periodic_due(config, username, "downlink")
            )
            full_capture = bool(profile == "full" or periodic or reasons)
            event_id = self.next_id("downlink")
            path = self.append(
                "downlink_events",
                {
                    "schema": "dfm-ai-01-downlink-v1",
                    "run_id": self.run_id,
                    "event_id": event_id,
                    "time": time_iso,
                    "time_unix_ms": time_unix_ms,
                    "mode": str(mode or "").upper() or None,
                    "direction": "DOWN",
                    "disposition": disposition or "FORWARD",
                    "reason": reason or None,
                    "client_ip": client_ip or None,
                    "connection_id": conn_id or None,
                    "game_id": uid or snapshot.get("game_id"),
                    "proxy_username": username or None,
                    "log_profile": profile,
                    "periodic_full_sample": periodic,
                    "full_capture_reasons": list(dict.fromkeys(reasons)),
                    "packet": self._compact_snapshot(snapshot, full=full_capture),
                },
            )
            if reasons:
                self._append_anomaly(
                    source_kind="downlink",
                    event_id=event_id,
                    username=username,
                    client_ip=client_ip,
                    conn_id=conn_id,
                    game_id=uid or snapshot.get("game_id"),
                    reasons=reasons,
                    capture={"frames": [bytes(data).hex().upper()]},
                )
            return path

    def write_marker(
        self,
        *,
        data_dir: str,
        config,
        marker: str,
        enabled: bool,
        details: dict | None,
    ) -> str:
        with self._lock:
            self.ensure_run(data_dir, config)
            time_iso, time_unix_ms = _now()
            return self.append(
                "markers",
                {
                    "schema": "dfm-ai-marker-v1",
                    "run_id": self.run_id,
                    "event_id": self.next_id("marker"),
                    "time": time_iso,
                    "time_unix_ms": time_unix_ms,
                    "marker": marker,
                    "enabled": bool(enabled),
                    "details": dict(details or {}),
                },
            )

    def write_reconnect_event(
        self,
        *,
        data_dir: str,
        config,
        phase: str,
        username: str,
        client_ip: str,
        conn_id: str,
        game_id: str = "",
        details: dict | None = None,
    ) -> str:
        """Write one v1.128.10 42B token/native-report decision event."""
        with self._lock:
            self.ensure_run(data_dir, config)
            time_iso, time_unix_ms = _now()
            return self.append(
                "reconnect_events",
                {
                    "schema": "dfm-ai-01-reconnect-v130-v1",
                    "run_id": self.run_id,
                    "event_id": self.next_id("reconnect_event"),
                    "time": time_iso,
                    "time_unix_ms": time_unix_ms,
                    "phase": str(phase or "").upper(),
                    "connection_id": conn_id or None,
                    "client_ip": client_ip or None,
                    "proxy_username": username or None,
                    "game_id": game_id or None,
                    "details": dict(details or {}),
                },
            )

    def write_template_selection(
        self,
        *,
        data_dir: str,
        config,
        username: str,
        client_ip: str,
        conn_id: str,
        live_game_id: str,
        selected: dict,
    ) -> str:
        with self._lock:
            self.ensure_run(data_dir, config)
            time_iso, time_unix_ms = _now()
            personal = int(selected.get("personal_01_count") or 0)
            official = int(selected.get("official_01_count") or 0)
            same_device_cross_account = bool(
                selected.get("device_cross_account")
            )
            if same_device_cross_account:
                mode = "player_same_device_cross_account"
            elif personal and official:
                mode = "player_primary_with_official_fallback"
            elif personal:
                mode = "player_only"
            elif official:
                mode = "official_fallback"
            else:
                mode = "no_01_template"
            return self.append(
                "template_selection",
                {
                    "schema": "dfm-ai-01-template-selection-v1",
                    "run_id": self.run_id,
                    "event_id": self.next_id("template_selection"),
                    "time": time_iso,
                    "time_unix_ms": time_unix_ms,
                    "connection_id": conn_id or None,
                    "client_ip": client_ip or None,
                    "proxy_username": username or None,
                    "live_game_id": live_game_id or None,
                    "template_mode": mode,
                    "client_version": selected.get("client_version") or "auto",
                    "personal_01_count": personal,
                    "official_01_count": official,
                    "official_sources": list(selected.get("official_sources") or []),
                    "same_device_cross_account": same_device_cross_account,
                    "device_donor_game_ids": list(
                        selected.get("device_donor_game_ids") or []
                    ),
                },
            )

    def reset_connection(self, conn_id: str) -> None:
        with self._lock:
            self.continuity.pop(conn_id, None)
            self.replay_context.pop(conn_id, None)
            self.replay_followups.pop(conn_id, None)


ai_log_v128 = V128AiLog()
