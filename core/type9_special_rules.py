"""UAMProxy 暗区突围 Type9 叶子热规则与热加载入口。

规则只允许声明式字节操作，不执行上传内容中的 Python 代码。运行时支持：

``patch_live``
    以实时叶子为基础，仅改写指定字节。
``replace_template``
    以当前匹配模板为基础，继承实时公共头后再应用可选补丁。
``replace_template_nearest``
    按 recordCode/messageId 从录制池选择长度最近的干净模板；允许变长，
    由 Type9 重建层同步更新容器长度、密文、物理分片和 CRC。
``pass_live``
    明确保留完整实时叶子。
``drop_leaf``
    删除命中叶子，由Type9重建层同步更新容器子项数、长度和CRC。
``empty_2000``
    用客户端真实存在的44字节空结果0x2000替换命中叶子，保留Live版本与序号。
``no_template``
    仅模板类动作可用。缺录制/官方模板时 ``pass_live``（默认）保留实时叶，
    ``drop_leaf`` 改为删叶，``empty_2000`` 改为合法空结果叶。

配置默认位于 ``C:\\PyProxyApp\\type9_hot_rules.json``。文件变化会自动加载；
管理接口也可以原子写入并立即激活新规则。
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from datetime import datetime
import json
import os
import re
import threading
import time
from typing import Any, Optional, Tuple

from core.config import DATA_DIR


LeafKey = Tuple[int, Optional[int], int]
RuleKey = Tuple[int, Optional[int], Optional[int]]
LeafHandler = Callable[[bytes, Mapping[str, Any]], Optional[bytes]]

HOT_RULES_FILE = os.path.join(DATA_DIR, "type9_hot_rules.json")
MAX_RULE_FILE_BYTES = 512 * 1024
_EMPTY_2000_TEMPLATE = bytes.fromhex(
    "00000001002c0102000a0000000000000000000000162000200f00023456"
    "0001000000000000000000000000"
)

_LIVE_CONTEXT_RE = re.compile(
    rb"(?P<key>model|ver|inc_id|obf_id):(?P<value>[^;\x00]{1,64})"
)


def _sequence_safe_empty_2000(raw: bytes) -> bytes:
    """生成真实44字节空结果叶，并继承Live版本与recordSequence。"""
    data = bytearray(_EMPTY_2000_TEMPLATE)
    if len(raw) >= 4:
        data[0:4] = raw[0:4]
    if len(raw) >= 14:
        data[10:14] = raw[10:14]
    return bytes(data)


def live_context_fields(raw: bytes | bytearray) -> dict[bytes, tuple[bytes, ...]]:
    """提取不应从录制模板跨设备/跨阶段带入的Live上下文。"""
    values: dict[bytes, list[bytes]] = {}
    for matched in _LIVE_CONTEXT_RE.finditer(bytes(raw)):
        values.setdefault(matched.group("key"), []).append(matched.group("value"))
    return {key: tuple(items) for key, items in values.items()}


def live_context_mismatch(
    live_raw: bytes | bytearray,
    candidate_raw: bytes | bytearray,
) -> bool:
    """候选若改变设备/版本/inc_id/obf_id上下文，整叶回退Live。"""
    live_fields = live_context_fields(live_raw)
    candidate_fields = live_context_fields(candidate_raw)
    return bool(
        (live_fields or candidate_fields)
        and live_fields != candidate_fields
    )


def live_runtime_context_mismatch(
    live_raw: bytes | bytearray,
    candidate_raw: bytes | bytearray,
) -> bool:
    """录制设备模式仍必须继承Live的inc_id/obf_id运行槽。"""
    runtime_keys = {b"inc_id", b"obf_id"}
    live_fields = {
        key: value
        for key, value in live_context_fields(live_raw).items()
        if key in runtime_keys
    }
    candidate_fields = {
        key: value
        for key, value in live_context_fields(candidate_raw).items()
        if key in runtime_keys
    }
    return bool(
        (live_fields or candidate_fields)
        and live_fields != candidate_fields
    )


HOT_RULE_SCHEMA = "uam-type9-hot-rules-v1"
SUPPORTED_HOT_RULE_SCHEMAS = frozenset({HOT_RULE_SCHEMA, "dfm-type9-hot-rules-v1"})

RULE_DESCRIPTIONS: dict[str, str] = {
    "8023-zero-offset24-status": (
        "UAM 0x8023 160B：+0x24 非零则清零；已为零不改写；"
        "实际清零计入 rule_changed_counts"
    ),
}

# 暗区突围（UAM）专版：删除三角洲内置热规则，仅保留 0x8023 +0x24 监控清零。
UAM_8023_ZERO_OFFSET24_RULE: dict[str, Any] = {
    "id": "8023-zero-offset24-status",
    "description": (
        "UAM 0x8023 160B 周期叶：+0x24 非零则 patch 为 0；"
        "已为零则不改写（计入 rule_changed_counts 仅在实际清零时）"
    ),
    "enabled": True,
    "match": {
        "record_code": "0x0102000A",
        "message_id": "0x8023",
        "length": 160,
    },
    "action": "patch_live",
    "patches": [
        {
            "offset": "0x24",
            "hex": "00000000",
            "skip_if_zero": True,
            "note": "UAM v1.131.2 +0x24 状态候选字段",
        }
    ],
}
UAM_DEFAULT_HOT_RULE_DOCUMENT: dict[str, Any] = {
    "schema": HOT_RULE_SCHEMA,
    "revision": "uam-v1.131.2-8023-zero-offset24-1",
    "rules": [deepcopy(UAM_8023_ZERO_OFFSET24_RULE)],
}


DEFAULT_HOT_RULE_DOCUMENT = UAM_DEFAULT_HOT_RULE_DOCUMENT

SPECIAL_UNKNOWN_LEAF_HANDLERS: dict[LeafKey, tuple[str, LeafHandler]] = {}


class HotRuleValidationError(ValueError):
    pass


def _parse_int(value: Any, *, field: str, allow_none: bool = False) -> int | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool):
        raise HotRuleValidationError(f"{field}: boolean is not an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        text = value.strip().lower()
        try:
            result = int(text, 16 if text.startswith("0x") else 10)
        except ValueError as exc:
            raise HotRuleValidationError(f"{field}: invalid integer {value!r}") from exc
    else:
        raise HotRuleValidationError(f"{field}: invalid integer {value!r}")
    if result < 0:
        raise HotRuleValidationError(f"{field}: must be >= 0")
    return result


def _parse_hex(value: Any, *, field: str, allow_empty: bool = False) -> bytes:
    text = str(value or "").replace(" ", "").replace("_", "").strip()
    if not text and allow_empty:
        return b""
    if not text or len(text) % 2:
        raise HotRuleValidationError(f"{field}: hex length must be positive and even")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise HotRuleValidationError(f"{field}: invalid hex") from exc


def validate_hot_rule_document(document: Mapping[str, Any]) -> tuple[dict, list[dict]]:
    """校验并编译规则；返回可持久化文档和运行时规则。"""
    if not isinstance(document, Mapping):
        raise HotRuleValidationError("document must be an object")
    schema = str(document.get("schema") or HOT_RULE_SCHEMA)
    if schema not in SUPPORTED_HOT_RULE_SCHEMAS:
        raise HotRuleValidationError(f"unsupported schema: {schema}")
    raw_rules = document.get("rules")
    if not isinstance(raw_rules, list):
        raise HotRuleValidationError("rules must be an array")
    if len(raw_rules) > 256:
        raise HotRuleValidationError("too many rules (max 256)")

    normalized_rules: list[dict] = []
    compiled_rules: list[dict] = []
    seen_ids: set[str] = set()
    seen_keys: set[LeafKey] = set()
    for index, raw_rule in enumerate(raw_rules):
        prefix = f"rules[{index}]"
        if not isinstance(raw_rule, Mapping):
            raise HotRuleValidationError(f"{prefix}: must be an object")
        rule_id = str(raw_rule.get("id") or "").strip()
        if not rule_id:
            raise HotRuleValidationError(f"{prefix}.id: required")
        if rule_id in seen_ids:
            raise HotRuleValidationError(f"{prefix}.id: duplicate {rule_id}")
        seen_ids.add(rule_id)
        description = str(
            raw_rule.get("description")
            or RULE_DESCRIPTIONS.get(rule_id, "")
        ).strip()
        if len(description) > 256:
            raise HotRuleValidationError(
                f"{prefix}.description: exceeds 256 characters"
            )
        enabled = bool(raw_rule.get("enabled", True))
        match = raw_rule.get("match")
        if not isinstance(match, Mapping):
            raise HotRuleValidationError(f"{prefix}.match: required object")
        record_code = _parse_int(match.get("record_code"), field=f"{prefix}.match.record_code")
        message_id = _parse_int(
            match.get("message_id"),
            field=f"{prefix}.match.message_id",
            allow_none=True,
        )
        action = str(raw_rule.get("action") or "").strip().lower()
        if action not in {
            "patch_live", "replace_template", "replace_template_nearest",
            "pass_live", "drop_leaf", "empty_2000",
        }:
            raise HotRuleValidationError(
                f"{prefix}.action: use patch_live, replace_template, "
                "replace_template_nearest, pass_live, drop_leaf or empty_2000"
            )
        raw_length = match.get("length")
        wildcard_length = (
            isinstance(raw_length, str)
            and raw_length.strip().lower() in {"*", "any"}
        )
        if wildcard_length:
            if action not in {
                "replace_template_nearest", "pass_live", "drop_leaf", "empty_2000"
            }:
                raise HotRuleValidationError(
                    f"{prefix}.match.length: wildcard requires "
                    "replace_template_nearest, pass_live, drop_leaf or empty_2000"
                )
            length = None
        else:
            length = _parse_int(raw_length, field=f"{prefix}.match.length")
            if not length:
                raise HotRuleValidationError(f"{prefix}.match.length: must be > 0")
        key: RuleKey = (
            int(record_code), message_id, int(length) if length is not None else None
        )
        if enabled and key in seen_keys:
            raise HotRuleValidationError(f"{prefix}.match: duplicate enabled key {key}")
        if enabled:
            seen_keys.add(key)

        inherit_live_header = _parse_int(
            raw_rule.get("inherit_live_header", 14),
            field=f"{prefix}.inherit_live_header",
        )
        if int(inherit_live_header) > 0xFFFF:
            raise HotRuleValidationError(
                f"{prefix}.inherit_live_header: exceeds maximum leaf length"
            )
        if length is not None and int(inherit_live_header) > int(length):
            raise HotRuleValidationError(
                f"{prefix}.inherit_live_header: exceeds leaf length"
            )
        require_same_device = bool(
            raw_rule.get("require_same_device", False)
        )
        allow_cross_device = bool(
            raw_rule.get("allow_cross_device", False)
        )
        if require_same_device and action not in {
            "replace_template", "replace_template_nearest"
        }:
            raise HotRuleValidationError(
                f"{prefix}.require_same_device: requires template action"
            )
        if allow_cross_device and action not in {
            "replace_template", "replace_template_nearest"
        }:
            raise HotRuleValidationError(
                f"{prefix}.allow_cross_device: requires template action"
            )
        if require_same_device and allow_cross_device:
            raise HotRuleValidationError(
                f"{prefix}: require_same_device cannot combine with allow_cross_device"
            )
        no_template = str(raw_rule.get("no_template") or "pass_live").strip().lower()
        if no_template not in {"pass_live", "drop_leaf", "empty_2000"}:
            raise HotRuleValidationError(
                f"{prefix}.no_template: use pass_live, drop_leaf or empty_2000"
            )
        if no_template != "pass_live" and action not in {
            "replace_template", "replace_template_nearest"
        }:
            raise HotRuleValidationError(
                f"{prefix}.no_template: requires template action"
            )

        raw_patches = raw_rule.get("patches") or []
        if action in {"pass_live", "drop_leaf", "empty_2000"} and raw_patches:
            raise HotRuleValidationError(
                f"{prefix}: {action} cannot contain patches"
            )
        if not isinstance(raw_patches, list):
            raise HotRuleValidationError(f"{prefix}.patches: must be an array")
        patches: list[dict] = []
        occupied: set[int] = set()
        normalized_patches: list[dict] = []
        for patch_index, raw_patch in enumerate(raw_patches):
            pp = f"{prefix}.patches[{patch_index}]"
            if not isinstance(raw_patch, Mapping):
                raise HotRuleValidationError(f"{pp}: must be an object")
            offset = int(_parse_int(raw_patch.get("offset"), field=f"{pp}.offset"))
            value = _parse_hex(raw_patch.get("hex"), field=f"{pp}.hex")
            if length is None:
                raise HotRuleValidationError(
                    f"{prefix}.patches: wildcard nearest rule does not use patches"
                )
            if offset + len(value) > int(length):
                raise HotRuleValidationError(f"{pp}: patch exceeds leaf length")
            byte_range = set(range(offset, offset + len(value)))
            if occupied & byte_range:
                raise HotRuleValidationError(f"{pp}: overlaps another patch")
            occupied |= byte_range
            expect = None
            if raw_patch.get("expect_hex") not in (None, ""):
                expect = _parse_hex(raw_patch.get("expect_hex"), field=f"{pp}.expect_hex")
                if len(expect) != len(value):
                    raise HotRuleValidationError(f"{pp}.expect_hex: length mismatch")
            skip_if_zero = bool(raw_patch.get("skip_if_zero", False))
            note = str(raw_patch.get("note") or "")
            patches.append(
                {
                    "offset": offset,
                    "value": value,
                    "expect": expect,
                    "skip_if_zero": skip_if_zero,
                    "note": note,
                }
            )
            item = {"offset": offset, "hex": value.hex().upper()}
            if expect is not None:
                item["expect_hex"] = expect.hex().upper()
            if skip_if_zero:
                item["skip_if_zero"] = True
            if note:
                item["note"] = note
            normalized_patches.append(item)

        normalized = {
            "id": rule_id,
            "description": description,
            "enabled": enabled,
            "match": {
                "record_code": f"0x{int(record_code):08X}",
                "message_id": (
                    f"0x{int(message_id):04X}" if message_id is not None else None
                ),
                "length": int(length) if length is not None else "*",
            },
            "action": action,
        }
        if action in {"replace_template", "replace_template_nearest"}:
            normalized["inherit_live_header"] = int(inherit_live_header)
            if require_same_device:
                normalized["require_same_device"] = True
            if allow_cross_device:
                normalized["allow_cross_device"] = True
            if no_template != "pass_live":
                normalized["no_template"] = no_template
        if normalized_patches:
            normalized["patches"] = normalized_patches
        normalized_rules.append(normalized)
        compiled_rules.append(
            {
                "id": rule_id,
                "description": description,
                "enabled": enabled,
                "key": key,
                "action": action,
                "inherit_live_header": int(inherit_live_header),
                "require_same_device": require_same_device,
                "allow_cross_device": allow_cross_device,
                "no_template": no_template,
                "patches": patches,
            }
        )

    normalized_document = {
        "schema": HOT_RULE_SCHEMA,
        "revision": str(document.get("revision") or "").strip(),
        "rules": normalized_rules,
    }
    return normalized_document, compiled_rules


class Type9HotRuleStore:
    """线程安全规则快照；坏更新保留上一份可用规则。"""

    def __init__(
        self,
        path: str = HOT_RULES_FILE,
        *,
        default_document: Mapping[str, Any] | None = None,
        managed_previous_defaults: tuple[Mapping[str, Any], ...] = (),
        auto_reload_interval: float = 1.0,
    ):
        self.path = path
        self.default_document = deepcopy(default_document) if default_document else None
        self.managed_previous_defaults = tuple(
            deepcopy(document) for document in managed_previous_defaults
        )
        self.auto_reload_interval = max(0.0, float(auto_reload_interval))
        self._lock = threading.RLock()
        self._document = {"schema": HOT_RULE_SCHEMA, "revision": "", "rules": []}
        self._rules_by_key: dict[RuleKey, dict] = {}
        self._loaded = False
        self._mtime_ns: int | None = None
        self._size: int | None = None
        self._last_check = 0.0
        self._last_error = ""
        self._loaded_at = ""
        self._generation = 0
        self._changed_counts: dict[str, int] = {}

    def _apply_runtime_policy(self, document: Mapping[str, Any]) -> dict:
        return deepcopy(document)
        changed = False
        rules = output.get("rules") or []
        desired = next(
            item
            for item in DEFAULT_HOT_RULE_DOCUMENT["rules"]
            if item.get("id") == "0207-zero-anomaly-counters"
        )
        matched = False
        for rule in rules:
            match = rule.get("match") or {}
            try:
                is_0207_key = (
                    _parse_int(match.get("record_code"), field="record_code")
                    == 0x0102000A
                    and _parse_int(match.get("message_id"), field="message_id")
                    == 0x0207
                )
            except HotRuleValidationError:
                is_0207_key = False
            if (
                rule.get("id") != "0207-zero-anomaly-counters"
                and not is_0207_key
            ):
                continue
            matched = True
            if rule != desired:
                rule.clear()
                rule.update(deepcopy(desired))
                changed = True
        if not matched:
            rules.append(deepcopy(desired))
            output["rules"] = rules
            changed = True
        if changed:
            output["revision"] = DEFAULT_HOT_RULE_DOCUMENT["revision"]
        return output

    def _signature(self) -> tuple[int, int] | None:
        try:
            st = os.stat(self.path)
            return int(st.st_mtime_ns), int(st.st_size)
        except FileNotFoundError:
            return None

    def _audit_state(self) -> dict:
        return {
            "generation": int(self._generation),
            "loaded": bool(self._loaded),
            "loaded_at": self._loaded_at or None,
            "revision": str(self._document.get("revision") or ""),
            "active_rule_count": len(self._rules_by_key),
            "rule_changed_counts": dict(self._changed_counts),
            "file_mtime_ns": self._mtime_ns,
            "file_size": self._size,
            "last_error": self._last_error or None,
        }

    @staticmethod
    def _write_audit(
        action: str,
        *,
        phase: str = "after",
        details: Mapping[str, Any] | None = None,
        state: Mapping[str, Any] | None = None,
    ) -> None:
        """Append a rule-operation audit row when an AI run is active."""
        try:
            from core.ai_log_v128 import ai_log_v128

            ai_log_v128.write_control_event(
                source="hot_rule_store",
                actor="runtime",
                action=action,
                phase=phase,
                details=dict(details or {}),
                state={"hot_rules": dict(state or {})},
            )
        except (OSError, TypeError, ValueError, RuntimeError):
            pass

    def _install(
        self,
        document: Mapping[str, Any],
        *,
        signature=None,
        audit_reason: str = "install",
    ) -> None:
        previous_state = self._audit_state()
        document = self._apply_runtime_policy(document)
        normalized, compiled = validate_hot_rule_document(document)
        self._document = normalized
        self._rules_by_key = {
            rule["key"]: rule for rule in compiled if rule.get("enabled")
        }
        if signature is not None:
            self._mtime_ns, self._size = signature
        else:
            self._mtime_ns = self._size = None
        self._loaded = True
        self._last_error = ""
        self._loaded_at = datetime.now().isoformat(timespec="milliseconds")
        self._generation += 1
        self._changed_counts = {
            str(rule.get("id") or ""): 0
            for rule in normalized.get("rules") or []
            if rule.get("enabled", True) and str(rule.get("id") or "")
        }
        self._write_audit(
            "hot_rule_generation_installed",
            details={
                "reason": str(audit_reason or "install"),
                "counters_reset": any(
                    int(value or 0)
                    for value in (
                        previous_state.get("rule_changed_counts") or {}
                    ).values()
                ),
                "previous": previous_state,
            },
            state=self._audit_state(),
        )

    def bootstrap(self) -> dict:
        with self._lock:
            if self.default_document is not None:
                if not os.path.exists(self.path):
                    self._write_atomic(self.default_document)
                elif self.managed_previous_defaults:
                    # 只升级与历史内置文档逐字段等价的文件；
                    # 同revision但用户改过规则的文件不会被覆盖。
                    try:
                        with open(self.path, "r", encoding="utf-8-sig") as handle:
                            current, _ = validate_hot_rule_document(json.load(handle))
                        forced = self._apply_runtime_policy(current)
                        if forced != current:
                            self._write_atomic(forced)
                            current = validate_hot_rule_document(forced)[0]
                        previous = [
                            validate_hot_rule_document(document)[0]
                            for document in self.managed_previous_defaults
                        ]
                        if current in previous:
                            self._write_atomic(self.default_document)
                    except Exception:
                        # 损坏文件仍交给reload统一报错，不在升级阶段覆盖。
                        pass
            return self.reload(force=True, audit_reason="bootstrap")

    def reload(
        self,
        *,
        force: bool = False,
        audit_reason: str | None = None,
    ) -> dict:
        with self._lock:
            signature = self._signature()
            if signature is None:
                if self.default_document is not None and not self._loaded:
                    try:
                        self._write_atomic(self.default_document)
                        signature = self._signature()
                    except Exception as exc:
                        self._last_error = f"{type(exc).__name__}: {exc}"
                if signature is None:
                    if not self._loaded:
                        self._install(
                            {"schema": HOT_RULE_SCHEMA, "revision": "", "rules": []},
                            audit_reason=audit_reason or "missing_file_empty",
                        )
                    return self.snapshot(check_reload=False)
            if not force and self._loaded and signature == (self._mtime_ns, self._size):
                return self.snapshot(check_reload=False)
            try:
                if signature[1] > MAX_RULE_FILE_BYTES:
                    raise HotRuleValidationError("rule file exceeds 512 KiB")
                with open(self.path, "r", encoding="utf-8-sig") as handle:
                    document = json.load(handle)
                self._install(
                    document,
                    signature=signature,
                    audit_reason=(
                        audit_reason
                        or ("forced_reload" if force else "file_signature_change")
                    ),
                )
            except Exception as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                if not self._loaded:
                    self._install(
                        {"schema": HOT_RULE_SCHEMA, "revision": "", "rules": []},
                        audit_reason=audit_reason or "reload_error_empty",
                    )
                    self._last_error = f"{type(exc).__name__}: {exc}"
                self._write_audit(
                    "hot_rule_reload_failed",
                    phase="failed",
                    details={
                        "reason": str(audit_reason or "reload"),
                        "error": self._last_error,
                    },
                    state=self._audit_state(),
                )
            return self.snapshot(check_reload=False)

    def _write_atomic(self, document: Mapping[str, Any]) -> None:
        document = self._apply_runtime_policy(document)
        normalized, _compiled = validate_hot_rule_document(document)
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, exist_ok=True)
        temp_path = f"{self.path}.tmp-{os.getpid()}-{threading.get_ident()}"
        try:
            with open(temp_path, "w", encoding="utf-8") as handle:
                json.dump(normalized, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.path)
        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except OSError:
                pass

    def replace_document(self, document: Mapping[str, Any]) -> dict:
        """先完整校验，再原子写入并切换内存快照。"""
        with self._lock:
            document = self._apply_runtime_policy(document)
            normalized, _compiled = validate_hot_rule_document(document)
            self._write_atomic(normalized)
            self._install(
                normalized,
                signature=self._signature(),
                audit_reason="replace_document",
            )
            return self.snapshot(check_reload=False)

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if self.auto_reload_interval and now - self._last_check < self.auto_reload_interval:
            return
        self._last_check = now
        self.reload(force=False)

    def get_rule(self, key: LeafKey) -> dict | None:
        self._maybe_reload()
        with self._lock:
            rule = self._rules_by_key.get(key)
            if rule is None:
                rule = self._rules_by_key.get((key[0], key[1], None))
            return dict(rule) if rule is not None else None

    def record_changed(self, rule_id: str) -> int:
        """记录一次实际字节改写，返回该规则当前代累计次数。"""
        key = str(rule_id or "")
        if not key:
            return 0
        with self._lock:
            before = int(self._changed_counts.get(key, 0))
            self._changed_counts[key] = before + 1
            after = self._changed_counts[key]
            self._write_audit(
                "hot_rule_success_counter_increment",
                details={"rule_id": key, "before": before, "after": after},
                state={
                    "generation": int(self._generation),
                    "revision": str(self._document.get("revision") or ""),
                    "rule_id": key,
                    "rule_changed_count": after,
                },
            )
            return after

    def clear_changed_counts(self) -> dict:
        """清零所有热规则的实际改写次数，并返回最新规则快照。"""
        with self._lock:
            before = dict(self._changed_counts)
            for key in tuple(self._changed_counts):
                self._changed_counts[key] = 0
            self._write_audit(
                "hot_rule_success_counters_cleared",
                details={"before": before, "after": dict(self._changed_counts)},
                state=self._audit_state(),
            )
            return self.snapshot(check_reload=False)

    def snapshot(self, *, check_reload: bool = True) -> dict:
        if check_reload:
            self._maybe_reload()
        with self._lock:
            return {
                "ok": not bool(self._last_error),
                "path": self.path,
                "generation": self._generation,
                "loaded_at": self._loaded_at,
                "last_error": self._last_error,
                "active_rule_count": len(self._rules_by_key),
                "rule_changed_counts": dict(self._changed_counts),
                "document": deepcopy(self._document),
            }



type9_hot_rule_store = Type9HotRuleStore(
    HOT_RULES_FILE,
    default_document=DEFAULT_HOT_RULE_DOCUMENT,
    managed_previous_defaults=(),
)



def _apply_compiled_rule(
    rule: Mapping[str, Any],
    raw: bytes,
    *,
    template_raw: bytes | None,
    allow_recorded_device_context: bool = False,
) -> dict:
    action = str(rule.get("action") or "")
    if action == "drop_leaf":
        return {
            "action": "DROP_LEAF",
            "raw": b"",
            "changed": True,
            "error": "",
        }
    if action == "empty_2000":
        output = _sequence_safe_empty_2000(raw)
        return {
            "action": "REPLACE_CLEAN_2000",
            "raw": output,
            "changed": output != raw,
            "error": "",
        }
    if action == "pass_live":
        return {
            "action": "PASS_LIVE",
            "raw": raw,
            "changed": False,
            "error": "",
        }
    if action in {"replace_template", "replace_template_nearest"}:
        if template_raw is None or (
            action == "replace_template" and len(template_raw) != len(raw)
        ):
            no_template = str(rule.get("no_template") or "pass_live")
            if no_template == "drop_leaf":
                return {
                    "action": "DROP_LEAF",
                    "raw": b"",
                    "changed": True,
                    "error": "HOT_RULE_TEMPLATE_REQUIRED_DROP_LEAF",
                }
            if no_template == "empty_2000":
                output = _sequence_safe_empty_2000(raw)
                return {
                    "action": "REPLACE_CLEAN_2000",
                    "raw": output,
                    "changed": output != raw,
                    "error": "HOT_RULE_TEMPLATE_REQUIRED_EMPTY_2000",
                }
            return {
                "action": "PASS_LIVE",
                "raw": raw,
                "changed": False,
                "error": "HOT_RULE_TEMPLATE_REQUIRED",
            }
        candidate = bytearray(template_raw)
        header_len = int(rule.get("inherit_live_header") or 0)
        if header_len > min(len(candidate), len(raw)):
            return {
                "action": "PASS_LIVE",
                "raw": raw,
                "changed": False,
                "error": "HOT_RULE_INHERIT_HEADER_EXCEEDS_TEMPLATE",
            }
        if len(candidate) == len(raw):
            candidate[:header_len] = raw[:header_len]
        else:
            # 变长模板保留模板声明长度；跳过长度字段后继承声明的Live前缀。
            # 0x1105使用36字节前缀，以保留二进制消息头和内部枚举序号。
            prefix = min(4, header_len, len(candidate), len(raw))
            candidate[:prefix] = raw[:prefix]
            if header_len > 6:
                candidate[6:header_len] = raw[6:header_len]
            if len(candidate) >= 6:
                candidate[4:6] = len(candidate).to_bytes(2, "big")
    else:
        candidate = bytearray(raw)

    for patch in rule.get("patches") or []:
        offset = int(patch["offset"])
        value = bytes(patch["value"])
        current = bytes(candidate[offset:offset + len(value)])
        if patch.get("skip_if_zero") and current == b"\x00" * len(value):
            continue
        expect = patch.get("expect")
        if expect is not None and current != bytes(expect):
            return {
                "action": "PASS_LIVE",
                "raw": raw,
                "changed": False,
                "error": f"HOT_RULE_EXPECT_MISMATCH@0x{offset:X}",
            }
        candidate[offset:offset + len(value)] = value
    output = bytes(candidate)
    if (
        output != raw
        and not rule.get("allow_cross_device")
        and (
            live_runtime_context_mismatch(raw, output)
            if allow_recorded_device_context
            else live_context_mismatch(raw, output)
        )
    ):
        return {
            "action": "PASS_LIVE",
            "raw": raw,
            "changed": False,
            "error": (
                "LIVE_RUNTIME_CONTEXT_MISMATCH_PASS_LIVE"
                if allow_recorded_device_context
                else "LIVE_CONTEXT_MISMATCH_PASS_LIVE"
            ),
        }
    return {
        "action": (
            "REPLACE_VARIABLE_LENGTH"
            if len(output) != len(raw) else "REPLACE_SAME_LENGTH"
        ),
        "raw": output,
        "changed": output != raw,
        "error": "",
    }


def get_hot_rule_for_leaf(
    leaf: Mapping[str, Any],
    *,
    rule_store: Type9HotRuleStore | None = None,
) -> dict | None:
    raw = bytes(leaf.get("raw") or b"")
    key: LeafKey = (
        int(leaf.get("record_code") or 0),
        leaf.get("message_id"),
        int(leaf.get("actual_length") or len(raw)),
    )
    store = type9_hot_rule_store if rule_store is None else rule_store
    return store.get_rule(key) if store is not None else None


def apply_special_unknown_leaf(
    leaf: Mapping[str, Any],
    *,
    handlers: Mapping[LeafKey, tuple[str, LeafHandler]] | None = None,
    template_raw: bytes | None = None,
    rule_store: Type9HotRuleStore | None = None,
    hot_rule_override: Mapping[str, Any] | None = None,
    allow_recorded_device_context: bool = False,
) -> dict:
    """执行代码处理器或声明式热规则；无命中时返回普通 PASS_LIVE。"""
    raw = bytes(leaf.get("raw") or b"")
    key: LeafKey = (
        int(leaf.get("record_code") or 0),
        leaf.get("message_id"),
        int(leaf.get("actual_length") or len(raw)),
    )
    registry = SPECIAL_UNKNOWN_LEAF_HANDLERS if handlers is None else handlers
    selected = registry.get(key)
    if selected is not None:
        rule_id, handler = selected
        try:
            candidate = handler(raw, leaf)
        except Exception as exc:
            return {
                "action": "PASS_LIVE",
                "rule_id": str(rule_id),
                "key": key,
                "raw": raw,
                "changed": False,
                "matched_rule": True,
                "error": f"{type(exc).__name__}: {exc}",
            }
        if candidate is None:
            return {
                "action": "PASS_LIVE",
                "rule_id": str(rule_id),
                "key": key,
                "raw": raw,
                "changed": False,
                "matched_rule": True,
            }
        candidate = bytes(candidate)
        if len(candidate) != len(raw):
            return {
                "action": "PASS_LIVE",
                "rule_id": str(rule_id),
                "key": key,
                "raw": raw,
                "changed": False,
                "matched_rule": True,
                "error": "SPECIAL_RULE_LENGTH_MISMATCH",
            }
        return {
            "action": "REPLACE_SAME_LENGTH",
            "rule_id": str(rule_id),
            "key": key,
            "raw": candidate,
            "changed": candidate != raw,
            "matched_rule": True,
        }

    hot_rule = (
        dict(hot_rule_override)
        if hot_rule_override is not None
        else get_hot_rule_for_leaf(leaf, rule_store=rule_store)
    )
    if hot_rule is not None:
        store = type9_hot_rule_store if rule_store is None else rule_store
        decision = _apply_compiled_rule(
            hot_rule,
            raw,
            template_raw=template_raw,
            allow_recorded_device_context=allow_recorded_device_context,
        )
        if (
            store is not None
            and decision.get("changed")
            and callable(getattr(store, "record_changed", None))
        ):
            store.record_changed(str(hot_rule.get("id") or ""))
        return {
            **decision,
            "rule_id": str(hot_rule.get("id") or ""),
            "key": key,
            "matched_rule": True,
            "hot_action": str(hot_rule.get("action") or ""),
        }
    return {
        "action": "PASS_LIVE",
        "rule_id": "",
        "key": key,
        "raw": raw,
        "changed": False,
        "matched_rule": False,
    }
