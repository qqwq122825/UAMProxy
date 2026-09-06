"""v1.116-A Type9 旁路学习注册表。

该模块只观察已生成的 01 重放事件，不参与网络输出决策。它把
recordCode/messageId/length 归档，统计多账号、多连接的字节稳定度，
并仅在出现新结构或冲突时生成 NeedsAIAnalysis 材料。
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from typing import Any


LEARNING_SCHEMA = "dfm-type9-learning-v1"
MAX_TRACKED_VALUES = 8
MAX_TRACKED_ACCOUNTS = 32
MAX_TRACKED_CONNECTIONS = 64


def _now() -> str:
    return datetime.now().isoformat(timespec="milliseconds")


def _atomic_json(path: str, value: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp = f"{path}.tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
    os.replace(temp, path)


def _append_jsonl(path: str, value: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")


def _safe_bytes(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        return b""
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def _range_rows(offsets: list[int], kind: str) -> list[dict]:
    if not offsets:
        return []
    values = sorted(set(int(value) for value in offsets))
    rows = []
    start = previous = values[0]
    for value in values[1:]:
        if value != previous + 1:
            rows.append(
                {"start": start, "end": previous, "length": previous - start + 1, "kind": kind}
            )
            start = value
        previous = value
    rows.append(
        {"start": start, "end": previous, "length": previous - start + 1, "kind": kind}
    )
    return rows


def _update_byte_profile(profile: dict, raw: bytes) -> None:
    if not raw:
        return
    profile["observations"] = int(profile.get("observations") or 0) + 1
    profile["length"] = len(raw)
    rows = profile.setdefault("bytes", [])
    if not rows:
        rows.extend(
            {
                "first": value,
                "changes": 0,
                "unique_values": 1,
                "seen_mask": f"{1 << value:X}",
                "values": [value],
            }
            for value in raw
        )
        return
    if len(rows) != len(raw):
        profile["length_conflicts"] = int(profile.get("length_conflicts") or 0) + 1
        return
    for offset, value in enumerate(raw):
        row = rows[offset]
        values = row.setdefault("values", [])
        try:
            seen_mask = (
                int(str(row["seen_mask"]), 16)
                if row.get("seen_mask") else sum(1 << int(item) for item in values)
            )
        except (TypeError, ValueError):
            seen_mask = sum(1 << int(item) for item in values)
        value_bit = 1 << value
        if not seen_mask & value_bit:
            row["changes"] = int(row.get("changes") or 0) + 1
            row["unique_values"] = int(row.get("unique_values") or len(values)) + 1
            row["seen_mask"] = f"{seen_mask | value_bit:X}"
            if len(values) < MAX_TRACKED_VALUES:
                values.append(value)


def _profile_summary(profile: dict) -> dict:
    rows = profile.get("bytes") or []
    observations = int(profile.get("observations") or 0)
    stable = [index for index, row in enumerate(rows) if int(row.get("changes") or 0) == 0]
    variable = [index for index, row in enumerate(rows) if int(row.get("changes") or 0) > 0]
    high_variation = [
        index
        for index, row in enumerate(rows)
        if int(row.get("unique_values") or len(row.get("values") or []))
        >= min(MAX_TRACKED_VALUES, max(3, observations // 2))
    ]
    return {
        "observations": observations,
        "length": profile.get("length"),
        "length_conflicts": int(profile.get("length_conflicts") or 0),
        "stable_ranges": _range_rows(stable, "stable"),
        "variable_ranges": _range_rows(variable, "variable"),
        "high_variation_ranges": _range_rows(high_variation, "high_variation"),
    }


class Type9LearningRegistry:
    """116-A 学习状态：全局持久化，每次运行另存快照。"""

    def __init__(self, *, data_dir: str, run_dir: str, detailed: bool = False):
        self.data_dir = os.path.join(data_dir, "01Learning")
        self.run_dir = run_dir
        self.detailed = bool(detailed)
        self.registry_path = os.path.join(self.data_dir, "01_schema_registry.json")
        self.registry = {
            "schema": LEARNING_SCHEMA,
            "version": 1,
            "updated_at": _now(),
            "schemas": {},
        }
        try:
            with open(self.registry_path, "r", encoding="utf-8-sig") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict) and isinstance(loaded.get("schemas"), dict):
                self.registry = loaded
        except (OSError, ValueError, TypeError):
            pass
        self._run_alert_keys: set[str] = set()

    @staticmethod
    def _compact_leaf(leaf: dict) -> dict:
        """普通日志只保留结构和决策；完整 HEX 由未知叶子采样文件承载。"""
        keep = {
            "path", "record_code", "message_id", "length", "live_sequence",
            "structural_match", "matched", "semantic_ready", "semantic_rule",
            "replacement_level", "block_reason", "suspect_watch", "suspect_flags",
            "available_template_lengths", "sequence_distance", "template_sequence",
            "template_scope", "template_batch_id",
        }
        result = {key: leaf[key] for key in keep if key in leaf}
        result["clean_diff_count"] = len(leaf.get("clean_diff_offsets") or [])
        result["unknown_diff_count"] = len(leaf.get("unknown_diff_offsets") or [])
        result["shadow_only_diff_count"] = len(
            leaf.get("shadow_only_diff_offsets") or []
        )
        return result

    def _run_registry_snapshot(self) -> dict:
        """详细模式复制完整画像；普通模式仅复制可分析的结构摘要。"""
        if self.detailed:
            return self.registry
        schemas = {}
        for key, row in sorted((self.registry.get("schemas") or {}).items()):
            compact = {
                name: value
                for name, value in row.items()
                if name not in {"live_profile", "template_profile"}
            }
            compact["live_profile"] = _profile_summary(row.get("live_profile") or {})
            compact["template_profile"] = _profile_summary(
                row.get("template_profile") or {}
            )
            schemas[key] = compact
        return {
            "schema": self.registry.get("schema", LEARNING_SCHEMA),
            "version": self.registry.get("version", 1),
            "updated_at": self.registry.get("updated_at"),
            "log_mode": "normal",
            "schemas": schemas,
        }

    @staticmethod
    def schema_key(leaf: dict) -> str:
        record_code = int(leaf.get("record_code") or 0)
        message_id = leaf.get("message_id")
        message = f"{int(message_id):04X}" if isinstance(message_id, int) else "NONE"
        return f"{record_code:08X}:{message}:{int(leaf.get('length') or 0)}"

    @staticmethod
    def _limited_add(values: list, value: object, limit: int) -> None:
        if value in (None, "") or value in values:
            return
        if len(values) < limit:
            values.append(value)

    def observe(self, event: dict) -> dict:
        shadow = event.get("shadow_rebuild") or {}
        leaves = shadow.get("leaf_results") or []
        if not leaves:
            return {"observed": 0, "alerts": 0}

        alerts = []
        now = event.get("time") or _now()
        account = event.get("game_id") or ""
        conn_id = (event.get("connection") or {}).get("conn_id") or ""
        cross = event.get("cross_account") or {}
        validation_failed = any(
            (event.get("checks") or {}).get(name) is False
            for name in ("output_crc_ok", "output_validation_ok", "shadow_decode_ok")
        )

        for leaf in leaves:
            key = self.schema_key(leaf)
            schemas = self.registry.setdefault("schemas", {})
            is_new = key not in schemas
            if is_new:
                fingerprint = hashlib.sha256(key.encode("ascii")).hexdigest()[:16]
                schemas[key] = {
                    "schema_key": key,
                    "structure_hash": fingerprint,
                    "record_code": f"0x{int(leaf.get('record_code') or 0):08X}",
                    "message_id": (
                        f"0x{int(leaf['message_id']):04X}"
                        if isinstance(leaf.get("message_id"), int) else None
                    ),
                    "length": int(leaf.get("length") or 0),
                    "state": "OBSERVE",
                    "activation": "shadow_only",
                    "first_seen": now,
                    "last_seen": now,
                    "events": 0,
                    "accounts": [],
                    "donor_accounts": [],
                    "connections": [],
                    "decisions": {},
                    "flags": {},
                    "live_profile": {"observations": 0, "bytes": []},
                    "template_profile": {"observations": 0, "bytes": []},
                }
            row = schemas[key]
            row["last_seen"] = now
            row["events"] = int(row.get("events") or 0) + 1
            self._limited_add(row.setdefault("accounts", []), account, MAX_TRACKED_ACCOUNTS)
            self._limited_add(
                row.setdefault("donor_accounts", []),
                cross.get("donor_game_id"),
                MAX_TRACKED_ACCOUNTS,
            )
            self._limited_add(
                row.setdefault("connections", []), conn_id, MAX_TRACKED_CONNECTIONS
            )
            decision = str(event.get("decision") or "UNKNOWN")
            row.setdefault("decisions", {})[decision] = (
                int(row.get("decisions", {}).get(decision) or 0) + 1
            )
            flags = list(dict.fromkeys(str(flag) for flag in (leaf.get("suspect_flags") or [])))
            for flag in flags:
                row.setdefault("flags", {})[flag] = int(row.get("flags", {}).get(flag) or 0) + 1

            live_raw = _safe_bytes(leaf.get("live_hex"))
            template_raw = _safe_bytes(leaf.get("template_hex"))
            _update_byte_profile(row.setdefault("live_profile", {}), live_raw)
            _update_byte_profile(row.setdefault("template_profile", {}), template_raw)

            triggers = []
            if is_new:
                triggers.append("NEW_SCHEMA")
            if "NEW_IDENTITY" in flags:
                triggers.append("NEW_MESSAGE_ID")
            if "NEW_LENGTH" in flags:
                triggers.append("NEW_LENGTH")
            if "DYNAMIC_GUARD" in flags:
                triggers.append("FIELD_CONFLICT")
            identity = leaf.get("identity_rewrite") or {}
            if identity.get("blocked"):
                triggers.append("IDENTITY_BLOCK")
            if validation_failed:
                triggers.append("VALIDATION_FAILED")

            diff_signature = ",".join(
                f"{item.get('start')}-{item.get('end')}"
                for item in (leaf.get("shadow_only_diff_ranges") or [])
            )
            if diff_signature and (leaf.get("suspect_watch") or flags):
                seen = row.setdefault("diff_signatures", [])
                if diff_signature not in seen:
                    if len(seen) < 32:
                        seen.append(diff_signature)
                    triggers.append("NEW_FIELD_PATTERN")

            for trigger in dict.fromkeys(triggers):
                alert_key = f"{trigger}:{key}:{diff_signature}"
                if alert_key in self._run_alert_keys:
                    continue
                self._run_alert_keys.add(alert_key)
                alerts.append(
                    {
                        "schema": "dfm-type9-learning-decision-v1",
                        "time": now,
                        "trigger": trigger,
                        "schema_key": key,
                        "structure_hash": row["structure_hash"],
                        "game_id": account,
                        "donor_game_id": cross.get("donor_game_id", ""),
                        "connection": event.get("connection"),
                        "event_id": event.get("event_id"),
                        "decision": decision,
                        "reason": event.get("reason", ""),
                        "leaf": (
                            leaf if self.detailed else self._compact_leaf(leaf)
                        ),
                    }
                )

        self.registry["updated_at"] = now
        self._persist(alerts)
        return {"observed": len(leaves), "alerts": len(alerts)}

    def _persist(self, alerts: list[dict]) -> None:
        _atomic_json(self.registry_path, self.registry)
        run_registry = self._run_registry_snapshot()
        _atomic_json(
            os.path.join(self.run_dir, "01_schema_registry.json"), run_registry
        )
        profiles = {
            "schema": "dfm-type9-field-profiles-v1",
            "generated_at": _now(),
            "mode": "shadow_only",
            "network_behavior_changed": False,
            "profiles": {
                key: {
                    "schema_key": key,
                    "structure_hash": row.get("structure_hash"),
                    "state": row.get("state", "OBSERVE"),
                    "accounts": row.get("accounts", []),
                    "donor_accounts": row.get("donor_accounts", []),
                    "events": row.get("events", 0),
                    "live": _profile_summary(row.get("live_profile") or {}),
                    "template": _profile_summary(row.get("template_profile") or {}),
                    "candidate_inherit_ranges": [
                        {"start": 0, "end": min(13, max(0, int(row.get("length") or 1) - 1)), "length": min(14, int(row.get("length") or 0)), "kind": "common_header"}
                    ],
                }
                for key, row in sorted((self.registry.get("schemas") or {}).items())
            },
        }
        _atomic_json(os.path.join(self.run_dir, "01_field_profiles.json"), profiles)
        if not alerts:
            return
        decisions_path = os.path.join(self.run_dir, "01_learning_decisions.jsonl")
        for alert in alerts:
            _append_jsonl(decisions_path, alert)
            if alert["trigger"] in {"NEW_MESSAGE_ID", "NEW_LENGTH", "NEW_SCHEMA"}:
                _append_jsonl(os.path.join(self.run_dir, "01_unknown_identity.jsonl"), alert)

        needs_dir = os.path.join(self.run_dir, "NeedsAIAnalysis")
        for alert in alerts:
            _append_jsonl(os.path.join(needs_dir, "events.jsonl"), alert)
        _atomic_json(
            os.path.join(needs_dir, "01_schema_registry.json"), run_registry
        )
        _atomic_json(os.path.join(needs_dir, "01_field_profiles.json"), profiles)
        _atomic_json(
            os.path.join(needs_dir, "manifest.json"),
            {
                "schema": "dfm-ai-analysis-bundle-v1",
                "generated_at": _now(),
                "mode": "116-A-shadow-learning",
                "network_behavior_changed": False,
                "rule_activation": "disabled",
                "event_file": "events.jsonl",
                "registry_file": "01_schema_registry.json",
                "profiles_file": "01_field_profiles.json",
            },
        )
