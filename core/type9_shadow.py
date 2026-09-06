"""Type9 叶子级安全重建。

该模块只生成候选逻辑payload，不决定网络输出。继承模式以Live明文为骨架，
只有显式热规则或语义``clean``白名单字段可以引入录制值；替换模式把连接锁定到
一个录制会话，统一使用该会话的设备画像和设备专项报告。两种模式的recordSequence、
容器顺序、运行槽与连接字段始终来自Live，重建后重算Type9明文CRC及01外层CRC。
"""

from __future__ import annotations

import hashlib
import re
import zlib

from core.type9_content_blacklist import (
    CONTENT_BLACKLIST_RULE_ID,
    scan_type9_content_blacklist,
)
from core.type9_crypto import KEYS, find_records, type9_transform
from core.type9_special_rules import (
    apply_special_unknown_leaf,
    get_hot_rule_for_leaf,
    live_context_mismatch,
    live_runtime_context_mismatch,
)
from core.type9_stable_80xx_insert import (
    append_batch_children,
    ensure_insert_state,
    live_stable_message_ids,
    mark_consumed,
    note_live_80xx,
    plan_inserts,
    stamp_inserted_leaf,
    wrap_root_as_batch,
)


BATCH_CODE = 0x010A001B
BINARY_CODE = 0x0102000A
CLEAN_2000_LENGTH = 44
# 全库 291 条根叶 0x2000 去掉 recordSequence 后正文完全相同：空模块检测结果。
CLEAN_2000_TEMPLATE = bytes.fromhex(
    "00000001002c0102000a0000000000000000000000162000200f00023456"
    "0001000000000000000000000000"
)


def clean_2000_root_leaf(sequence: int, *, version: int = 1) -> bytes:
    """根叶命中时改成空结果 0x2000，保住 0x0102000A 形态和报告序号。"""
    data = bytearray(CLEAN_2000_TEMPLATE)
    data[0:4] = int(version).to_bytes(4, "big")
    data[10:14] = int(sequence).to_bytes(4, "big")
    data[4:6] = CLEAN_2000_LENGTH.to_bytes(2, "big")
    return bytes(data)


def _normalize_pruned_batch(
    rebuilt: bytes,
    *,
    live_root: dict,
    live_leaves: list[dict],
    prune_paths: set[tuple[int, ...]],
) -> bytes:
    """删叶后若容器只剩 0/1 片，改成真实客户端会发的根叶形态。"""
    if len(rebuilt) < 0x15:
        return rebuilt
    if int.from_bytes(rebuilt[6:10], "big") != BATCH_CODE:
        return rebuilt
    child_count = rebuilt[0x14]
    if child_count >= 2:
        return rebuilt
    if child_count == 1:
        child_length = int.from_bytes(rebuilt[0x15:0x19], "big")
        child = rebuilt[0x19:0x19 + child_length]
        if (
            len(child) == child_length
            and len(child) >= 14
            and int.from_bytes(child[6:10], "big") != BATCH_CODE
        ):
            return child
        return rebuilt
    sequence = int(live_root.get("record_sequence") or 0)
    version = int(live_root.get("version") or 1)
    for leaf in live_leaves:
        if tuple(leaf.get("path") or []) in prune_paths:
            sequence = int(leaf["record_sequence"])
            raw = leaf.get("raw") or b""
            if len(raw) >= 4:
                version = int.from_bytes(raw[0:4], "big")
            break
    return clean_2000_root_leaf(sequence, version=version)


SEMANTIC_RULESET_VERSION = "v1.130.6-player-clock-metadata-r1"
DEVICE_MODE_INHERIT_LIVE = "inherit_live"
DEVICE_MODE_REPLACE_RECORDED = "replace_recorded"
DEVICE_MODES = {
    DEVICE_MODE_INHERIT_LIVE,
    DEVICE_MODE_REPLACE_RECORDED,
}
WATCHED_RECORD_CODES = {0x01122388}
WATCHED_MESSAGE_IDS = {
    0x8024,
    0x8030,
    0x80CC,
    0x80CD,
    0xFFF2,
    0xFFF3,
}
DYNAMIC_LIVE_RECORD_CODES = {0x01122388}
# 116-A 仅新增旁路学习，网络替换行为保持已完整对局验证的 114.1。
# WATCHED_MESSAGE_IDS 会完整记录差异，但只有已确认的强动态 ID 强制保留实时主体。
DYNAMIC_LIVE_MESSAGE_IDS = {0xFFF2, 0xFFF3}
DYNAMIC_MAX_TIMESTAMP_DELTA = 30
_ASCII_TIMESTAMP_RE = re.compile(rb"(?<!\d)(1\d{9})(?!\d)")
_DEVICE_CONTEXT_PATTERNS = {
    "model": re.compile(rb"model:([^;\x00]{2,32})"),
    "hardware_model": re.compile(rb"iDevHwModel:([^;\x00]{2,32})"),
    # 叶子公共身份段使用ver；若会话内另有iDevSysVer，提取器会优先采用后者。
    "system_version": re.compile(rb"ver:([^;\x00]{1,24})"),
    "system_name": re.compile(rb"iDevSysName:([^;\x00]{1,24})"),
    "device_idfv": re.compile(rb"iDevIDFV:([^;\x00]{8,80})"),
    "device_resolution": re.compile(rb"iDevRes:([^;\x00]{3,32})"),
    "app_version": re.compile(rb"iAppVersion:([^;\x00]{1,48})"),
    "app_mach_uuid": re.compile(rb"iAppMachUUID:([^;\x00]{8,80})"),
}
_EXACT_SYSTEM_VERSION_RE = re.compile(rb"iDevSysVer:([^;\x00]{1,24})")
_TELEMETRY_SLOT_RE = re.compile(rb"inc_id:(\d+);obf_id:(\d+)")
_RUNTIME_CONTEXT_PATTERNS = {
    "inc_id": re.compile(rb"inc_id:([^;\x00]{1,20})"),
    "obf_id": re.compile(rb"obf_id:([^;\x00]{1,20})"),
}
_TFP_CALLED_MARKER = b"tfp_called"
# 123.2实机叶子中该可选项的完整编码前缀。连同10字节文本共20字节；
# 只有完整签名吻合时才启用无模板结构删除兜底。
_TFP_CALLED_ENCODED_PREFIX = bytes.fromhex("0000000001000000000B")
TFP_CALLED_GENERIC_TEMPLATE_RULE_ID = "v124-tfp-called-any-record-clean-slot"
TFP_CALLED_STRUCTURED_REMOVE_RULE_ID = (
    "v124-tfp-called-no-template-structured-remove"
)
TFP_CALLED_ZERO_MARKER_RULE_ID = "v124-tfp-called-unknown-layout-zero-marker"
TFP_CALLED_INTERCEPT_RULE_ROWS = (
    {
        "id": "1122329-tfp-called-clean-slot",
        "description": "0x01122329命中tfp_called后使用干净语义槽",
        "record_code": "0x01122329",
        "action": "clean_template",
    },
    {
        "id": "112233B-tfp-called-clean-slot",
        "description": "0x0112233B命中tfp_called后使用干净0x01122329语义槽",
        "record_code": "0x0112233B",
        "action": "clean_template",
    },
    {
        "id": "1122358-tfp-called-clean-slot",
        "description": "0x01122358命中tfp_called后使用同消息号干净语义槽",
        "record_code": "0x01122358",
        "action": "clean_template",
    },
    {
        "id": TFP_CALLED_GENERIC_TEMPLATE_RULE_ID,
        "description": "任意新消息号命中tfp_called后使用同消息号干净模板",
        "record_code": "*",
        "action": "clean_template",
    },
    {
        "id": TFP_CALLED_STRUCTURED_REMOVE_RULE_ID,
        "description": "无干净模板时删除已确认的tfp_called完整编码字段",
        "record_code": "*",
        "action": "remove_field",
    },
    {
        "id": TFP_CALLED_ZERO_MARKER_RULE_ID,
        "description": "未知字段布局或最终残留时等长清零tfp_called",
        "record_code": "*",
        "action": "zero_marker",
    },
)

# 这些消息正文包含代码地址、系统函数序言或与OS二进制相关的指纹。
# 同账号不代表同设备；只有录制设备上下文与Live一致时才允许整模板替换。
DEVICE_SENSITIVE_TEMPLATE_MESSAGE_IDS = {
    # UIKit层级、探针状态、进程/调用位置都会随设备和系统环境变化。
    # 代码指纹四项由设备模式基座处理，并继续保留在门控集合中，防止用户
    # 加载旧版replace_template_nearest热规则后再次跨设备混用。
    # 0x100B / 0x8027 / 0x8029 默认规则带 allow_cross_device，
    # 分别覆盖注入绘制层和干净进程/位置模板；无该标记时仍门控。
    0x1007,
    0x1008,
    0x1009,
    0x100B,
    0x100C,
    0x100F,
    0x8027,
    0x8029,
}

# 123.1 数据中 tfp_called 曾出现在 0x0112233B；123.2 实机数据又确认它也会
# 直接出现在 0x01122329。两种命中都统一取无标记的 0x01122329 正常叶子。
CONFIRMED_CROSS_RECORD_SLOT_RULES = {
    0x01122329: {
        "id": "1122329-tfp-called-clean-slot",
        "marker": _TFP_CALLED_MARKER,
        "donor_record_codes": {0x01122329},
    },
    0x0112233B: {
        "id": "112233B-tfp-called-clean-slot",
        "marker": _TFP_CALLED_MARKER,
        "donor_record_codes": {0x01122329},
    },
    0x01122358: {
        "id": "1122358-tfp-called-clean-slot",
        "marker": _TFP_CALLED_MARKER,
        "donor_record_codes": {0x01122358},
    },
}


def normalize_device_mode(value: str | None) -> str:
    aliases = {
        "inherit": DEVICE_MODE_INHERIT_LIVE,
        "live": DEVICE_MODE_INHERIT_LIVE,
        "inherit_live": DEVICE_MODE_INHERIT_LIVE,
        "replace": DEVICE_MODE_REPLACE_RECORDED,
        "recorded": DEVICE_MODE_REPLACE_RECORDED,
        "replace_recorded": DEVICE_MODE_REPLACE_RECORDED,
    }
    return aliases.get(
        str(value or "").strip().lower(),
        DEVICE_MODE_INHERIT_LIVE,
    )


def _system_version_is_exact(value: str) -> bool:
    """iDevSysVer 使用 x.y.z；公共头 ver 只有两段（16.30 / 26.3）。"""
    parts = str(value or "").strip().split(".")
    return len(parts) >= 3 and all(part.isdigit() for part in parts)


def merge_device_context(*contexts: dict | None) -> dict:
    """合并同一会话逐批出现的设备字段，后出现的非空值优先。

    ``system_version`` 一旦采到三段 ``iDevSysVer``（如 16.3.1），后续只有
    公共头 ``ver:16.30`` 的包不得把它覆盖回去。
    """
    merged: dict[str, str] = {}
    for context in contexts:
        for key, value in dict(context or {}).items():
            value = str(value or "").strip()
            if not value:
                continue
            if (
                str(key) == "system_version"
                and _system_version_is_exact(merged.get("system_version") or "")
                and not _system_version_is_exact(value)
            ):
                continue
            merged[str(key)] = value
    return merged



def extract_device_context_from_raws(raws) -> dict:
    """从根遥测叶子的ASCII字段提取设备/系统/应用上下文。"""
    result: dict[str, str] = {}
    exact_system_version = ""
    for source in raws:
        raw = bytes(source or b"")
        exact_match = _EXACT_SYSTEM_VERSION_RE.search(raw)
        if exact_match:
            exact_system_version = exact_match.group(1).decode(
                "ascii", errors="ignore"
            ).strip()
        for key, pattern in _DEVICE_CONTEXT_PATTERNS.items():
            matched = pattern.search(raw)
            if matched:
                result[key] = matched.group(1).decode(
                    "ascii", errors="ignore"
                ).strip()
    if exact_system_version:
        result["system_version"] = exact_system_version
    if not result.get("model") and result.get("hardware_model"):
        result["model"] = result["hardware_model"]
    if not result.get("hardware_model") and result.get("model"):
        result["hardware_model"] = result["model"]
    return result


def extract_device_context_from_rows(rows: list[dict]) -> dict:
    return extract_device_context_from_raws(
        row.get("raw") for row in rows if isinstance(row, dict)
    )


def extract_device_context_from_logical(data: bytes) -> dict:
    material = decode_material(data)
    if not material.get("ok"):
        return {}
    return extract_device_context_from_raws(
        leaf.get("raw") for leaf in material.get("leaves") or []
    )


def _version_major(value: str) -> str:
    matched = re.search(r"\d+", str(value or ""))
    return matched.group(0) if matched else ""


def device_context_compatible(live: dict | None, template: dict | None) -> bool | None:
    """比较设备上下文。

    返回 ``None`` 表示任一侧还没有采集到足够设备信息，此时保留旧兼容行为；
    两侧都有model时严格比较model、系统主版本及已知应用标识。
    """
    live = dict(live or {})
    template = dict(template or {})
    if not live.get("model") or not template.get("model"):
        return None
    if live["model"] != template["model"]:
        return False
    if (
        live.get("hardware_model")
        and template.get("hardware_model")
        and live["hardware_model"] != template["hardware_model"]
    ):
        return False
    live_system = _version_major(live.get("system_version", ""))
    template_system = _version_major(template.get("system_version", ""))
    if live_system and template_system and live_system != template_system:
        return False
    for key in ("app_version", "app_mach_uuid"):
        if live.get(key) and template.get(key) and live[key] != template[key]:
            return False
    return True


def _overlay_recorded_device_fields(
    raw: bytes | bytearray,
    recorded_context: dict | None,
) -> tuple[bytes, list[dict]]:
    """把Live叶子中的设备身份字段统一改成连接锁定的录制设备画像。"""
    candidate = bytes(raw)
    context = dict(recorded_context or {})
    rewrites: list[dict] = []
    targets = [
        ("model", _DEVICE_CONTEXT_PATTERNS["model"]),
        ("hardware_model", _DEVICE_CONTEXT_PATTERNS["hardware_model"]),
        ("system_version", _EXACT_SYSTEM_VERSION_RE),
        ("system_version", _DEVICE_CONTEXT_PATTERNS["system_version"]),
        ("system_name", _DEVICE_CONTEXT_PATTERNS["system_name"]),
        ("device_idfv", _DEVICE_CONTEXT_PATTERNS["device_idfv"]),
        ("device_resolution", _DEVICE_CONTEXT_PATTERNS["device_resolution"]),
        ("app_version", _DEVICE_CONTEXT_PATTERNS["app_version"]),
        ("app_mach_uuid", _DEVICE_CONTEXT_PATTERNS["app_mach_uuid"]),
    ]
    for field, pattern in targets:
        value = str(context.get(field) or "").encode("ascii", errors="ignore")
        if not value:
            continue
        search_from = 0
        while True:
            matched = pattern.search(candidate, search_from)
            if not matched:
                break
            old = matched.group(1)
            start, end = matched.span(1)
            candidate = candidate[:start] + value + candidate[end:]
            if old != value:
                rewrites.append(
                    {
                        "field": field,
                        "live": old.decode("ascii", errors="ignore"),
                        "recorded": value.decode("ascii", errors="ignore"),
                    }
                )
            search_from = start + len(value)
    if rewrites and len(candidate) >= 6:
        candidate = (
            candidate[:4]
            + len(candidate).to_bytes(2, "big")
            + candidate[6:]
        )
    return candidate, rewrites


def _telemetry_slot(raw: bytes | bytearray) -> tuple[int, int] | None:
    matched = _TELEMETRY_SLOT_RE.search(bytes(raw))
    if not matched:
        return None
    return int(matched.group(1)), int(matched.group(2))


def _overlay_live_device_fields(
    candidate_raw: bytes | bytearray,
    live_raw: bytes | bytearray,
) -> tuple[bytes, list[dict]]:
    """把模板中的设备/系统/应用画像字段统一写回Live值。"""
    candidate = bytes(candidate_raw)
    live = bytes(live_raw)
    rewrites: list[dict] = []
    targets = [
        ("model", _DEVICE_CONTEXT_PATTERNS["model"]),
        ("hardware_model", _DEVICE_CONTEXT_PATTERNS["hardware_model"]),
        ("system_version", _EXACT_SYSTEM_VERSION_RE),
        ("system_version", _DEVICE_CONTEXT_PATTERNS["system_version"]),
        ("system_name", _DEVICE_CONTEXT_PATTERNS["system_name"]),
        ("device_idfv", _DEVICE_CONTEXT_PATTERNS["device_idfv"]),
        ("device_resolution", _DEVICE_CONTEXT_PATTERNS["device_resolution"]),
        ("app_version", _DEVICE_CONTEXT_PATTERNS["app_version"]),
        ("app_mach_uuid", _DEVICE_CONTEXT_PATTERNS["app_mach_uuid"]),
    ]
    for key, pattern in targets:
        live_match = pattern.search(live)
        if not live_match:
            continue
        live_value = live_match.group(1)
        search_from = 0
        while True:
            candidate_match = pattern.search(candidate, search_from)
            if not candidate_match:
                break
            old_value = candidate_match.group(1)
            start, end = candidate_match.span(1)
            candidate = candidate[:start] + live_value + candidate[end:]
            if old_value != live_value:
                rewrites.append(
                    {
                        "field": key,
                        "template": old_value.decode("ascii", errors="ignore"),
                        "live": live_value.decode("ascii", errors="ignore"),
                    }
                )
            search_from = start + len(live_value)
    if rewrites and len(candidate) >= 6:
        candidate = (
            candidate[:4]
            + len(candidate).to_bytes(2, "big")
            + candidate[6:]
        )
    return candidate, rewrites


def _overlay_live_runtime_fields(
    candidate_raw: bytes | bytearray,
    live_raw: bytes | bytearray,
) -> tuple[bytes, list[dict]]:
    """把正常模板中的inc_id/obf_id专项写回当前Live运行槽。"""
    candidate = bytes(candidate_raw)
    live = bytes(live_raw)
    rewrites: list[dict] = []
    for field, pattern in _RUNTIME_CONTEXT_PATTERNS.items():
        live_match = pattern.search(live)
        candidate_match = pattern.search(candidate)
        if not live_match or not candidate_match:
            continue
        live_value = live_match.group(1)
        old_value = candidate_match.group(1)
        start, end = candidate_match.span(1)
        candidate = candidate[:start] + live_value + candidate[end:]
        if old_value != live_value:
            rewrites.append(
                {
                    "field": field,
                    "template": old_value.decode("ascii", errors="ignore"),
                    "live": live_value.decode("ascii", errors="ignore"),
                }
            )
    return candidate, rewrites


def _remove_tfp_called_encoded_field(
    raw: bytes | bytearray,
) -> tuple[bytes | None, dict]:
    """无干净模板时删除已确认编码的tfp_called可选项。"""
    source = bytes(raw)
    marker_offset = source.find(_TFP_CALLED_MARKER)
    if marker_offset < len(_TFP_CALLED_ENCODED_PREFIX):
        return None, {"status": "MARKER_OR_PREFIX_MISSING"}
    field_start = marker_offset - len(_TFP_CALLED_ENCODED_PREFIX)
    if source[field_start:marker_offset] != _TFP_CALLED_ENCODED_PREFIX:
        return None, {
            "status": "ENCODED_PREFIX_MISMATCH",
            "marker_offset": marker_offset,
        }
    field_end = marker_offset + len(_TFP_CALLED_MARKER)
    candidate = source[:field_start] + source[field_end:]
    if len(candidate) < 14:
        return None, {"status": "CANDIDATE_TOO_SHORT"}
    candidate = (
        candidate[:4]
        + len(candidate).to_bytes(2, "big")
        + candidate[6:]
    )
    return candidate, {
        "status": "REMOVED",
        "start": field_start,
        "end": field_end - 1,
        "removed_length": field_end - field_start,
        "marker_offset": marker_offset,
    }


def _zero_tfp_called_markers(
    raw: bytes | bytearray,
) -> tuple[bytes, dict]:
    """未知字段布局的最终保底：等长清零所有tfp_called文本。"""
    source = bytes(raw)
    candidate = bytearray(source)
    offsets: list[int] = []
    cursor = 0
    while True:
        offset = source.find(_TFP_CALLED_MARKER, cursor)
        if offset < 0:
            break
        offsets.append(offset)
        candidate[offset:offset + len(_TFP_CALLED_MARKER)] = (
            b"\x00" * len(_TFP_CALLED_MARKER)
        )
        cursor = offset + len(_TFP_CALLED_MARKER)
    return bytes(candidate), {
        "status": "ZEROED" if offsets else "MARKER_MISSING",
        "offsets": offsets,
        "zeroed_marker_count": len(offsets),
        "zeroed_bytes": len(offsets) * len(_TFP_CALLED_MARKER),
    }


def _field(offset: int, length: int, name: str) -> dict:
    return {"offset": offset, "length": length, "name": name}


# 数据03已确认的明文语义规则。偏移相对于单个解密叶子。
# inherit: 从实时叶子覆盖回候选叶子的动态字段。
# match:   选择录制叶子时必须与实时值相同的内部子类型/周期。
# clean:   允许由录制样本引入的干净主体范围。
SEMANTIC_RULES: dict[tuple[int, int], dict] = {
    (BINARY_CODE, 0x1001): {
        "name": "session_start_time",
        "inherit": [_field(32, 4, "session_start_unix")],
    },
    (BINARY_CODE, 0x1002): {
        "name": "periodic_clean_value",
        "clean": [_field(32, 4, "clean_report_value")],
    },
    (BINARY_CODE, 0x1003): {
        "name": "session_word",
        "inherit": [_field(38, 2, "session_word")],
    },
    (BINARY_CODE, 0x1004): {"name": "static_periodic"},
    (BINARY_CODE, 0x1005): {
        "name": "session_runtime_value",
        "inherit": [_field(40, 4, "session_runtime_value")],
    },
    (BINARY_CODE, 0x1008): {"name": "static_periodic"},
    (BINARY_CODE, 0x100A): {
        "name": "report_counter_and_time",
        "inherit": [
            _field(32, 4, "report_counter"),
            _field(40, 4, "report_counter_copy_1"),
            _field(44, 4, "report_counter_copy_2"),
            _field(48, 4, "previous_report_counter"),
            _field(64, 4, "event_unix_time"),
        ],
    },
    (BINARY_CODE, 0x100E): {
        "name": "cycle_tick_and_clean_measurement",
        "match": [_field(32, 4, "cycle_index")],
        "inherit": [
            _field(32, 4, "cycle_index"),
            _field(36, 4, "monotonic_tick"),
        ],
        "clean": [_field(44, 4, "clean_measurement")],
    },
    (BINARY_CODE, 0x1105): {
        "name": "live_header_counter_clean_tail",
        # 0x1105 的公共头、消息头和 report_counter 全部来自实时叶子。
        # 同 recordCode/messageId/length 模板只提供 0x24 之后的主体，
        # 因此模板 recordSequence 距离不再决定整叶透传。
        "inherit": [
            _field(14, 18, "binary_message_header"),
            _field(32, 4, "report_counter"),
        ],
        "clean_tail_from": 36,
    },
    (BINARY_CODE, 0x2001): {
        "name": "fixed_step_counter",
        "inherit": [_field(32, 4, "fixed_step_counter")],
    },
    (BINARY_CODE, 0x8004): {
        "name": "group_and_subindex",
        "match": [_field(32, 4, "sub_index")],
        "inherit": [_field(28, 2, "group_id")],
    },
    (BINARY_CODE, 0xFFF9): {
        "name": "typed_clean_value",
        "match": [_field(35, 1, "subtype")],
        "clean": [_field(37, 4, "clean_subtype_value")],
    },
    (BINARY_CODE, 0xFFFB): {
        "name": "report_counter",
        "inherit": [_field(40, 4, "report_counter")],
    },
    (BINARY_CODE, 0xFFFE): {
        "name": "clean_vector",
        "clean": [_field(38, 11, "clean_vector")],
    },
    (BINARY_CODE, 0x0100): {
        "name": "phase_clean_block",
        "match": [_field(32, 4, "phase_state")],
        "clean": [_field(36, 116, "clean_block")],
    },
    (BINARY_CODE, 0x0101): {
        "name": "step_clean_block",
        "inherit": [_field(32, 4, "step_counter")],
        "clean": [_field(36, 116, "clean_block")],
    },
    (BINARY_CODE, 0x0102): {
        "name": "step_clean_block",
        "inherit": [_field(32, 4, "step_counter")],
        "clean": [_field(36, 124, "clean_block")],
    },
    (BINARY_CODE, 0x0103): {
        "name": "step_clean_block",
        "inherit": [_field(32, 4, "step_counter")],
        "clean": [_field(36, 124, "clean_block")],
    },
}


def semantic_rule(leaf: dict) -> dict | None:
    message_id = leaf.get("message_id")
    if message_id is None:
        return None
    return SEMANTIC_RULES.get((int(leaf["record_code"]), int(message_id)))


def _field_bytes(raw: bytes | bytearray, field: dict) -> bytes:
    start = int(field["offset"])
    end = start + int(field["length"])
    return bytes(raw[start:end])


def _offsets(fields: list[dict]) -> set[int]:
    return {
        offset
        for field in fields
        for offset in range(
            int(field["offset"]),
            int(field["offset"]) + int(field["length"]),
        )
    }


def _ascii_timestamps(raw: bytes | bytearray) -> list[int]:
    return sorted({int(value) for value in _ASCII_TIMESTAMP_RE.findall(bytes(raw))})


def _timestamp_distance(left: list[int], right: list[int]) -> int | None:
    if not left or not right:
        return None
    distances = [
        min(abs(value - other) for other in right)
        for value in left
    ] + [
        min(abs(value - other) for other in left)
        for value in right
    ]
    return max(distances)


def _offset_ranges(offsets: list[int]) -> list[dict]:
    if not offsets:
        return []
    values = sorted(set(int(value) for value in offsets))
    ranges = []
    start = previous = values[0]
    for value in values[1:]:
        if value != previous + 1:
            ranges.append(
                {"start": start, "end": previous, "length": previous - start + 1}
            )
            start = value
        previous = value
    ranges.append(
        {"start": start, "end": previous, "length": previous - start + 1}
    )
    return ranges


def _unmapped_body_guard(
    live_leaf: dict,
    selected: dict,
    sequence_distance: int,
) -> dict:
    """未知正文统一保留Live；时间戳等信息只用于诊断。"""
    live_timestamps = _ascii_timestamps(live_leaf["raw"])
    template_timestamps = _ascii_timestamps(selected["raw"])
    timestamp_delta = _timestamp_distance(live_timestamps, template_timestamps)
    reasons = ["UNMAPPED_BODY"]
    if int(live_leaf["record_code"]) in DYNAMIC_LIVE_RECORD_CODES:
        reasons.append("DYNAMIC_RECORD_CODE")
    if live_leaf.get("message_id") in DYNAMIC_LIVE_MESSAGE_IDS:
        reasons.append("DYNAMIC_MESSAGE_ID")
    if (
        timestamp_delta is not None
        and timestamp_delta > DYNAMIC_MAX_TIMESTAMP_DELTA
    ):
        reasons.append("TIMESTAMP_DELTA_EXCEEDED")
    return {
        "blocked": bool(reasons),
        "reason": "UNMAPPED_BODY_PASS_LIVE",
        "reasons": reasons,
        # v1.120：序号距离仅保留为诊断信息，不再因为距离超过128回退整叶Live。
        "sequence_limit": None,
        "sequence_distance": sequence_distance,
        "sequence_limit_enabled": False,
        "live_timestamps": live_timestamps,
        "template_timestamps": template_timestamps,
        "timestamp_delta": timestamp_delta,
        "timestamp_delta_limit": DYNAMIC_MAX_TIMESTAMP_DELTA,
    }


def _parse_node(
    plaintext: bytes,
    start: int,
    end: int,
    *,
    path: list[int],
    errors: list[str],
) -> tuple[dict | None, list[dict]]:
    if start < 0 or end > len(plaintext) or end - start < 14:
        errors.append(f"记录{path or ['root']}边界无效:{start}..{end}")
        return None, []
    raw = plaintext[start:end]
    node = {
        "path": list(path),
        "start": start,
        "end": end,
        "actual_length": len(raw),
        "version": int.from_bytes(raw[0:4], "big"),
        "declared_length": int.from_bytes(raw[4:6], "big"),
        "record_code": int.from_bytes(raw[6:10], "big"),
        "record_sequence": int.from_bytes(raw[10:14], "big"),
        "message_id": None,
        "raw": bytes(raw),
        "children": [],
    }
    if node["declared_length"] != len(raw):
        errors.append(
            f"记录{path or ['root']}声明长度"
            f"{node['declared_length']}!={len(raw)}"
        )
    if node["record_code"] == BINARY_CODE and len(raw) >= 0x18:
        node["message_id"] = int.from_bytes(raw[0x16:0x18], "big")
    if node["record_code"] != BATCH_CODE:
        return node, [node]
    if len(raw) < 0x15:
        errors.append(f"批次{path or ['root']}缺少子项数")
        return node, []

    declared_children = raw[0x14]
    node["child_count_declared"] = declared_children
    cursor = start + 0x15
    leaves: list[dict] = []
    for index in range(declared_children):
        if cursor + 4 > end:
            errors.append(f"批次{path or ['root']}子项{index}缺少长度")
            break
        child_length = int.from_bytes(plaintext[cursor:cursor + 4], "big")
        cursor += 4
        child_end = cursor + child_length
        if child_length < 14 or child_end > end:
            errors.append(
                f"批次{path or ['root']}子项{index}边界无效:{child_length}"
            )
            break
        child, child_leaves = _parse_node(
            plaintext,
            cursor,
            child_end,
            path=path + [index],
            errors=errors,
        )
        if child is not None:
            node["children"].append(child)
        leaves.extend(child_leaves)
        cursor = child_end
    node["child_count_parsed"] = len(node["children"])
    node["batch_trailing_length"] = end - cursor
    if len(node["children"]) != declared_children:
        errors.append(
            f"批次{path or ['root']}子项数"
            f"{len(node['children'])}!={declared_children}"
        )
    # 实际批次可带不参与子项计数的尾部（样本中常见8字节）。
    # 影子模式以实时明文为骨架，该尾部原样保留。
    return node, leaves


def decode_material(data: bytes) -> dict:
    """返回影子重建所需的 Type9 原始明文与叶子位置。"""
    result = {
        "ok": False,
        "errors": [],
        "record": None,
        "plaintext": b"",
        "root": None,
        "leaves": [],
    }
    try:
        record = next(iter(find_records(bytes(data))), None)
        if record is None:
            result["errors"].append("未找到完整Type9记录")
            return result
        selector = int(record["selector"])
        key_index = int(record["key_index"])
        plaintext = type9_transform(
            record["ciphertext"], selector, KEYS[key_index], direction=0
        )
        calculated_crc = zlib.crc32(plaintext) & 0xFFFFFFFF
        if calculated_crc != int(record["stored_crc32"]):
            result["errors"].append(
                f"明文CRC不符:{int(record['stored_crc32']):08X}!={calculated_crc:08X}"
            )
            return result
        parse_errors: list[str] = []
        root, leaves = _parse_node(
            plaintext, 0, len(plaintext), path=[], errors=parse_errors
        )
        if root is None or parse_errors:
            result["errors"].extend(parse_errors or ["明文记录解析失败"])
            return result
        result.update(
            {
                "ok": True,
                "record": record,
                "plaintext": plaintext,
                "root": root,
                "leaves": leaves,
            }
        )
        return result
    except (IndexError, KeyError, StopIteration, TypeError, ValueError) as exc:
        result["errors"].append(f"{type(exc).__name__}:{exc}")
        return result


def leaf_key(leaf: dict) -> tuple[int, int | None, int]:
    return (
        int(leaf["record_code"]),
        leaf.get("message_id"),
        int(leaf["actual_length"]),
    )


def template_leaf_rows(data: bytes, *, pool_idx: int) -> dict:
    """解密一个录制模板，返回可缓存的叶子索引行。"""
    material = decode_material(data)
    if not material["ok"]:
        return {"ok": False, "errors": material["errors"], "rows": []}
    rows = []
    for leaf in material["leaves"]:
        rows.append(
            {
                "key": leaf_key(leaf),
                "raw": leaf["raw"],
                "pool_idx": pool_idx,
                "path": list(leaf["path"]),
                "record_sequence": int(leaf["record_sequence"]),
            }
        )
    return {"ok": True, "errors": [], "rows": rows}


def _rewrite_cross_account_identity(
    candidate: bytearray,
    live_raw: bytes,
    donor_game_id: str,
    live_game_id: str,
) -> dict:
    """将叶子中明确出现的 donor UID 等长改成实时 UID。

    只有实时叶子同样包含实时 UID 时才改写，防止同长度字符串叶子把账号
    写进另一种语义字段。无法建立这个对应关系时，调用方保留完整实时叶子。
    """
    info = {
        "status": "NO_DONOR_ID_IN_LEAF",
        "blocked": False,
        "ranges": [],
        "donor_game_id": donor_game_id,
        "live_game_id": live_game_id,
    }
    if not donor_game_id or not live_game_id or donor_game_id == live_game_id:
        info["status"] = "NOT_REQUIRED"
        return info
    donor = donor_game_id.encode("ascii", errors="ignore")
    live = live_game_id.encode("ascii", errors="ignore")
    if not donor or donor not in candidate:
        return info
    if len(donor) != len(live):
        info.update({"status": "ID_LENGTH_MISMATCH", "blocked": True})
        return info
    offsets = []
    start = 0
    while True:
        offset = candidate.find(donor, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + len(donor)
    if any(live_raw[offset:offset + len(live)] != live for offset in offsets):
        info.update({"status": "LIVE_ID_CONTEXT_MISMATCH", "blocked": True})
        return info
    for offset in offsets:
        candidate[offset:offset + len(donor)] = live
        info["ranges"].append(
            {"start": offset, "end": offset + len(live) - 1, "length": len(live)}
        )
    info["status"] = "REWRITTEN"
    return info


def build_shadow_logical(
    live_data: bytes,
    template_rows: list[dict],
    *,
    cross_account: bool = False,
    live_game_id: str = "",
    donor_game_id: str = "",
    prune_unmatched: bool = False,
    special_handlers: dict | None = None,
    special_rule_store=None,
    live_device_context: dict | None = None,
    device_mode: str = DEVICE_MODE_INHERIT_LIVE,
    recorded_device_context: dict | None = None,
    recorded_template_session_id: str = "",
    live_report_index: int | None = None,
    insert_state: dict | None = None,
    refresh_insert_schedule: bool = False,
) -> dict:
    """用分层录制叶子构造候选；未知叶子默认保留实时值。"""
    device_mode = normalize_device_mode(device_mode)
    recorded_device_context = dict(recorded_device_context or {})
    result = {
        "generated": False,
        "reason": "",
        "errors": [],
        "candidate_logical": b"",
        "candidate_plaintext": b"",
        "total_leaves": 0,
        "structural_matched_leaves": 0,
        "matched_leaves": 0,
        "changed_leaves": 0,
        "pruned_leaves": 0,
        "cross_record_replaced_leaves": 0,
        "tfp_called_detected_leaves": 0,
        "tfp_called_template_replaced_leaves": 0,
        "tfp_called_structured_removed_leaves": 0,
        "tfp_called_zeroed_leaves": 0,
        "tfp_called_residual_leaves": 0,
        "tfp_called_rule_ids": [],
        "content_blacklist_dropped_leaves": 0,
        "content_blacklist_emptied_leaves": 0,
        "content_blacklist_tokens": [],
        "device_context_pass_live_leaves": 0,
        "recorded_device_profile_rewritten_leaves": 0,
        "unmatched_pass_live_leaves": 0,
        "unmapped_pass_live_leaves": 0,
        "live_context_pass_live_leaves": 0,
        "special_handled_leaves": 0,
        "special_changed_leaves": 0,
        "special_dropped_leaves": 0,
        "special_emptied_leaves": 0,
        "drop_entire_report": False,
        "replace_root_with_clean_2000": False,
        "variable_length_replaced_leaves": 0,
        "full_live_inherited_leaves": 0,
        "clean_changed_leaves": 0,
        "aggressive_changed_leaves": 0,
        "aggressive_blocked_leaves": 0,
        "semantic_ready_leaves": 0,
        "semantic_unmapped_leaves": 0,
        "subtype_miss_leaves": 0,
        "suspect_leaf_count": 0,
        "suspect_live_plaintext_hex": "",
        "cross_account": bool(cross_account),
        "live_game_id": live_game_id,
        "donor_game_id": donor_game_id,
        "identity_rewrite_count": 0,
        "identity_blocked_leaves": 0,
        "coverage": 0.0,
        "semantic_coverage": 0.0,
        "leaf_results": [],
        "semantic_ruleset": SEMANTIC_RULESET_VERSION,
        "device_mode": device_mode,
        "recorded_device_context": dict(recorded_device_context),
        "recorded_template_session_id": str(recorded_template_session_id or ""),
        "inserted_leaves": 0,
        "inserted_message_ids": [],
        "insert_skipped_reason": "",
        "insert_skipped_live_80xx": [],
    }
    live = decode_material(live_data)
    if not live["ok"]:
        result["reason"] = "LIVE_MATERIAL_INVALID"
        result["errors"] = list(live["errors"])
        return result

    observed_live_device_context = extract_device_context_from_raws(
        leaf.get("raw") for leaf in live.get("leaves") or []
    )
    live_device_context = merge_device_context(
        live_device_context, observed_live_device_context
    )
    result["live_device_context"] = dict(live_device_context)

    index: dict[tuple[int, int | None, int], list[dict]] = {}
    identity_rows: dict[tuple[int, int | None], list[dict]] = {}
    identity_lengths: dict[tuple[int, int | None], set[int]] = {}
    telemetry_slot_rows: dict[tuple[int, int], list[dict]] = {}
    for row in template_rows:
        key = tuple(row.get("key") or ())
        if len(key) == 3 and isinstance(row.get("raw"), (bytes, bytearray)):
            index.setdefault(key, []).append(row)
            identity_lengths.setdefault((int(key[0]), key[1]), set()).add(int(key[2]))
            identity_rows.setdefault((int(key[0]), key[1]), []).append(row)
            slot = _telemetry_slot(row["raw"])
            if key[1] is None and slot is not None:
                telemetry_slot_rows.setdefault(slot, []).append(row)

    candidate_plain = bytearray(live["plaintext"])
    candidate_by_path: dict[tuple[int, ...], bytes] = {}
    prune_paths: set[tuple[int, ...]] = set()
    variable_replacement_paths: set[tuple[int, ...]] = set()
    leaf_results = []
    structural_matched = matched = changed = clean_changed = 0
    unmatched_pass_live = 0
    unmapped_pass_live = 0
    live_context_pass_live = 0
    special_handled = 0
    special_changed = 0
    special_dropped = 0
    special_emptied = 0
    cross_record_replaced = 0
    tfp_called_detected = 0
    tfp_called_template_replaced = 0
    tfp_called_structured_removed = 0
    tfp_called_zeroed = 0
    tfp_called_residual = 0
    tfp_called_rule_ids: set[str] = set()
    content_blacklist_dropped = 0
    content_blacklist_emptied = 0
    content_blacklist_tokens: set[str] = set()
    device_context_pass_live = 0
    recorded_device_profile_rewritten = 0
    drop_entire_report = False
    replace_root_with_clean_2000 = False
    clean_2000_sequence = 0
    clean_2000_version = 1
    variable_length_replaced = 0
    full_live_inherited = 0
    aggressive_changed = 0
    aggressive_blocked = 0
    suspect_leaf_count = 0
    identity_rewrite_count = 0
    identity_blocked_leaves = 0
    semantic_ready_count = semantic_unmapped = subtype_miss = 0
    for live_leaf in live["leaves"]:
        key = leaf_key(live_leaf)
        identity_key = (int(live_leaf["record_code"]), live_leaf.get("message_id"))
        available_template_lengths = sorted(identity_lengths.get(identity_key) or [])
        base_candidates = index.get(key) or []
        if base_candidates:
            structural_matched += 1
        rule = semantic_rule(live_leaf)
        match_fields = list((rule or {}).get("match") or [])
        inherit_fields = list((rule or {}).get("inherit") or [])
        clean_fields = list((rule or {}).get("clean") or [])
        clean_tail_from = (rule or {}).get("clean_tail_from")
        if isinstance(clean_tail_from, int):
            tail_length = int(live_leaf["actual_length"]) - clean_tail_from
            if tail_length > 0:
                clean_fields.append(
                    _field(clean_tail_from, tail_length, "clean_body_tail")
                )
        hot_rule = get_hot_rule_for_leaf(
            live_leaf,
            rule_store=special_rule_store,
        )
        hot_action = str((hot_rule or {}).get("action") or "")
        candidates = list(base_candidates)
        if hot_action == "replace_template_nearest":
            candidates = list(identity_rows.get(identity_key) or [])
        live_record_code = int(live_leaf["record_code"])
        tfp_called_marker_hit = (
            _TFP_CALLED_MARKER in bytes(live_leaf["raw"])
        )
        content_blacklist_hit = scan_type9_content_blacklist(
            bytes(live_leaf["raw"])
        )
        cross_slot_rule = CONFIRMED_CROSS_RECORD_SLOT_RULES.get(
            live_record_code
        )
        if tfp_called_marker_hit and cross_slot_rule is None:
            # v1.124不再依赖固定消息号。未知recordCode先尝试使用同消息号
            # 的无标记干净叶子；没有模板时进入结构删除/等长清零保底。
            cross_slot_rule = {
                "id": TFP_CALLED_GENERIC_TEMPLATE_RULE_ID,
                "marker": _TFP_CALLED_MARKER,
                "donor_record_codes": {live_record_code},
            }
        cross_slot = _telemetry_slot(live_leaf["raw"])
        cross_slot_candidates: list[dict] = []
        cross_slot_match_mode = ""
        if tfp_called_marker_hit and cross_slot_rule:
            donor_codes = set(cross_slot_rule["donor_record_codes"])
            marker = bytes(cross_slot_rule["marker"])
            if cross_slot is not None:
                cross_slot_candidates = [
                    row
                    for row in telemetry_slot_rows.get(cross_slot, [])
                    if int((tuple(row.get("key") or (0,)) + (0,))[0])
                    in donor_codes
                    and marker not in bytes(row["raw"])
                ]
            if cross_slot_candidates:
                cross_slot_match_mode = "exact_runtime_slot"
                candidates = cross_slot_candidates
            else:
                # 实机报告的inc_id/obf_id会持续递增，干净录制未必恰好覆盖
                # 当前槽位。改从正常recordCode中选择长度/序号最近的无标记
                # 叶子，候选生成后再把Live运行槽专项写回。
                cross_slot_candidates = [
                    row
                    for donor_code in donor_codes
                    for row in identity_rows.get((donor_code, None), [])
                    if marker not in bytes(row["raw"])
                ]
                if cross_slot_candidates:
                    cross_slot_match_mode = "nearest_clean_runtime_slot"
                    candidates = cross_slot_candidates

        device_sensitive = bool(
            (
                hot_action in {"replace_template", "replace_template_nearest"}
                or (hot_rule is None and rule is not None)
            )
            and (
                live_leaf.get("message_id")
                in DEVICE_SENSITIVE_TEMPLATE_MESSAGE_IDS
                or (hot_rule or {}).get("require_same_device")
            )
            and not (hot_rule or {}).get("allow_cross_device")
        )
        device_context_mismatch = False
        if (
            candidates
            and device_sensitive
            and device_mode == DEVICE_MODE_INHERIT_LIVE
        ):
            compatible_candidates = []
            for row in candidates:
                compatible = device_context_compatible(
                    live_device_context,
                    row.get("device_context")
                    or extract_device_context_from_raws([row.get("raw")]),
                )
                # 设备敏感模板采用闭合策略：只有明确兼容才可进入候选。
                # 任一侧缺少model时也保留Live，避免旧池/首批报告混用。
                if compatible is True:
                    compatible_candidates.append(row)
            if not compatible_candidates:
                candidates = []
                device_context_mismatch = True
            else:
                candidates = compatible_candidates
        if candidates and match_fields:
            candidates = [
                row
                for row in candidates
                if all(
                    int(field["offset"]) + int(field["length"])
                    <= len(row["raw"])
                    and _field_bytes(row["raw"], field)
                    == _field_bytes(live_leaf["raw"], field)
                    for field in match_fields
                )
            ]
            if not candidates:
                subtype_miss += 1
        selected = None
        sequence_distance = None
        semantic_ready = False
        unknown_diff_offsets: list[int] = []
        clean_diff_offsets: list[int] = []
        inherited_log = []
        replacement_level = "NONE"
        block_reason = ""
        dynamic_guard = None
        selected_raw = b""
        candidate_raw = bytes(live_leaf["raw"])
        shadow_only_candidate_raw = b""
        shadow_only_diff_offsets: list[int] = []
        watched = bool(
            int(live_leaf["record_code"]) in WATCHED_RECORD_CODES
            or live_leaf.get("message_id") in WATCHED_MESSAGE_IDS
        )
        suspect_flags = []
        identity_rewrite = {
            "status": "DISABLED",
            "blocked": False,
            "ranges": [],
            "donor_game_id": donor_game_id,
            "live_game_id": live_game_id,
        }
        device_field_rewrites: list[dict] = []
        runtime_field_rewrites: list[dict] = []
        tfp_called_remove_info: dict = {}
        tfp_called_rule_id = ""
        tfp_called_action = ""
        tfp_called_replacement: dict = {}
        if tfp_called_marker_hit:
            tfp_called_detected += 1
        cross_record_slot_rewrite = False
        force_full_live = bool(
            int(live_leaf["record_code"]) in DYNAMIC_LIVE_RECORD_CODES
            or live_leaf.get("message_id") in DYNAMIC_LIVE_MESSAGE_IDS
        )
        if not available_template_lengths:
            suspect_flags.append("NEW_IDENTITY")
        elif int(live_leaf["actual_length"]) not in available_template_lengths:
            suspect_flags.append("NEW_LENGTH")
        # 模板先完成同结构/子类型/最近序号选择，再交给热规则决定。
        # replace_template_nearest 可跨长度选择同消息ID干净模板。
        if candidates:
            sequence = int(live_leaf["record_sequence"])
            # 内部序列在录制/重放中都从1连续增长，选择最近序列
            # 比“sequence取模”更能对齐同一对局阶段。
            if (
                hot_action == "replace_template_nearest"
                or cross_slot_match_mode == "nearest_clean_runtime_slot"
            ):
                selected = min(
                    candidates,
                    key=lambda row: (
                        abs(len(bytes(row["raw"])) - int(live_leaf["actual_length"])),
                        int(row.get("source_priority", 0)),
                        abs(int(row["record_sequence"]) - sequence),
                        int(row["record_sequence"]),
                        int(row.get("pool_idx", -1)),
                        tuple(row.get("path") or []),
                    ),
                )
            else:
                selected = min(
                    candidates,
                    key=lambda row: (
                        int(row.get("source_priority", 0)),
                        abs(int(row["record_sequence"]) - sequence),
                        int(row["record_sequence"]),
                        int(row.get("pool_idx", -1)),
                        tuple(row.get("path") or []),
                    ),
                )
            sequence_distance = abs(int(selected["record_sequence"]) - sequence)
            selected_raw = bytes(selected["raw"])
        special_decision = (
            {
                "action": "REPLACE_CLEAN_2000",
                "rule_id": CONTENT_BLACKLIST_RULE_ID,
                "raw": bytes(live_leaf["raw"]),
                "changed": True,
                "matched_rule": True,
                "hot_action": "empty_2000",
                "blacklist_token": content_blacklist_hit["token"],
                "blacklist_encoding": content_blacklist_hit["encoding"],
            }
            if content_blacklist_hit
            else {
                "action": "PASS_LIVE",
                "rule_id": "",
                "raw": bytes(live_leaf["raw"]),
                "changed": False,
                "matched_rule": False,
            }
            if tfp_called_marker_hit
            else apply_special_unknown_leaf(
                live_leaf,
                handlers=special_handlers,
                template_raw=(selected_raw if selected is not None else None),
                rule_store=special_rule_store,
                hot_rule_override=hot_rule,
                allow_recorded_device_context=(
                    device_mode == DEVICE_MODE_REPLACE_RECORDED
                ),
            )
        )
        if (
            device_context_mismatch
            and hot_rule is not None
            and not content_blacklist_hit
        ):
            special_decision.update(
                {
                    "action": "PASS_LIVE",
                    "raw": bytes(live_leaf["raw"]),
                    "changed": False,
                    "matched_rule": True,
                    "error": "DEVICE_CONTEXT_MISMATCH_PASS_LIVE",
                }
            )
        # 内容黑名单优先于tfp_called和普通热规则：脏进程/包名改成真实
        # 0x2000空结果叶并保留Live序号，不替换成另一条进程。
        special_matched = bool(
            special_decision.get("matched_rule")
            and (not tfp_called_marker_hit or content_blacklist_hit)
        )
        if tfp_called_marker_hit and not content_blacklist_hit:
            device_context_mismatch = False

        if special_matched:
            special_action = str(special_decision.get("action") or "")
            if special_action == "DROP_LEAF":
                if live_leaf.get("path"):
                    prune_paths.add(tuple(live_leaf["path"]))
                    candidate_raw = b""
                    clean_raw = bytearray()
                    semantic_ready = True
                    replacement_level = "SPECIAL_DROP_LEAF"
                    block_reason = "SPECIAL_DROP_LEAF"
                    special_handled += 1
                    special_changed += 1
                    special_dropped += 1
                    changed += 1
                    semantic_ready_count += 1
                    suspect_flags.append("SPECIAL_DROP_LEAF")
                    if content_blacklist_hit:
                        content_blacklist_dropped += 1
                        content_blacklist_tokens.add(
                            str(content_blacklist_hit.get("token") or "")
                        )
                        suspect_flags.append("CONTENT_BLACKLIST_DROP")
                else:
                    # 根叶不能整包丢（会跳号），也不能改成空容器（全库没出现过）。
                    # 改成真实存在的空结果根叶 0x2000，保留 0x0102000A 和 Live 序号。
                    replace_root_with_clean_2000 = True
                    clean_2000_sequence = int(live_leaf["record_sequence"])
                    if len(live_leaf["raw"]) >= 4:
                        clean_2000_version = int.from_bytes(
                            live_leaf["raw"][0:4], "big"
                        )
                    candidate_raw = b""
                    clean_raw = bytearray()
                    semantic_ready = True
                    replacement_level = "SPECIAL_DROP_LEAF"
                    block_reason = "SPECIAL_DROP_ROOT_TO_CLEAN_2000"
                    special_handled += 1
                    special_changed += 1
                    special_dropped += 1
                    changed += 1
                    semantic_ready_count += 1
                    suspect_flags.append("SPECIAL_DROP_ROOT_TO_CLEAN_2000")
                    if content_blacklist_hit:
                        content_blacklist_dropped += 1
                        content_blacklist_tokens.add(
                            str(content_blacklist_hit.get("token") or "")
                        )
                        suspect_flags.append("CONTENT_BLACKLIST_DROP")
            if special_action == "DROP_LEAF":
                pass
            else:
                if special_action == "REPLACE_CLEAN_2000":
                    version = 1
                    if len(live_leaf["raw"]) >= 4:
                        version = int.from_bytes(live_leaf["raw"][0:4], "big")
                    special_raw = clean_2000_root_leaf(
                        int(live_leaf["record_sequence"]),
                        version=version,
                    )
                else:
                    special_raw = bytes(
                        special_decision.get("raw") or live_leaf["raw"]
                    )
                # inherit_live 允许使用手机录制的干净模板主体，但最终
                # 设备、系统、应用画像以及inc_id/obf_id必须继承当前
                # Live端（例如iPad），不将iPhone录制身份带入上报。
                if device_mode == DEVICE_MODE_INHERIT_LIVE:
                    special_raw, device_field_rewrites = (
                        _overlay_live_device_fields(
                            special_raw,
                            live_leaf["raw"],
                        )
                    )
                    special_raw, runtime_field_rewrites = (
                        _overlay_live_runtime_fields(
                            special_raw,
                            live_leaf["raw"],
                        )
                    )
                    if (
                        (device_field_rewrites or runtime_field_rewrites)
                        and len(special_raw) >= 6
                    ):
                        special_raw = (
                            special_raw[:4]
                            + len(special_raw).to_bytes(2, "big")
                            + special_raw[6:]
                        )
                variable_length = len(special_raw) != len(live_leaf["raw"])
                if (
                    variable_length
                    and special_decision.get("action")
                    not in {"REPLACE_VARIABLE_LENGTH", "REPLACE_CLEAN_2000"}
                ):
                    special_raw = bytes(live_leaf["raw"])
                    special_decision["action"] = "PASS_LIVE"
                    special_decision["error"] = "SPECIAL_RULE_LENGTH_MISMATCH"
                    variable_length = False
                if variable_length:
                    variable_replacement_paths.add(tuple(live_leaf["path"]))
                    variable_length_replaced += 1
                else:
                    start, end = int(live_leaf["start"]), int(live_leaf["end"])
                    candidate_plain[start:end] = special_raw
                candidate_by_path[tuple(live_leaf["path"])] = special_raw
                candidate_raw = special_raw
                clean_raw = bytearray(special_raw)
                semantic_ready = True
                special_handled += 1
                semantic_ready_count += 1
                if selected is not None:
                    matched += 1
                hot_action = str(special_decision.get("hot_action") or "")
                if special_action == "REPLACE_CLEAN_2000":
                    hot_action = "empty_2000"
                if special_decision.get("action") in {
                    "REPLACE_SAME_LENGTH", "REPLACE_VARIABLE_LENGTH",
                    "REPLACE_CLEAN_2000",
                }:
                    replacement_level = {
                        "patch_live": "SPECIAL_PATCH_LIVE",
                        "replace_template": "SPECIAL_REPLACE_TEMPLATE",
                        "replace_template_nearest": "SPECIAL_REPLACE_TEMPLATE_NEAREST",
                        "empty_2000": "SPECIAL_EMPTY_2000",
                    }.get(hot_action, "SPECIAL_UNKNOWN_RULE")
                    if special_raw != live_leaf["raw"]:
                        changed += 1
                        special_changed += 1
                    if special_action == "REPLACE_CLEAN_2000":
                        special_emptied += 1
                        block_reason = "SPECIAL_EMPTY_2000_KEEP_SEQUENCE"
                        suspect_flags.append("SPECIAL_EMPTY_2000")
                        if content_blacklist_hit:
                            content_blacklist_emptied += 1
                            content_blacklist_tokens.add(
                                str(content_blacklist_hit.get("token") or "")
                            )
                            suspect_flags.append("CONTENT_BLACKLIST_EMPTY_2000")
                else:
                    if (
                        special_decision.get("error")
                        == "LIVE_CONTEXT_MISMATCH_PASS_LIVE"
                    ):
                        block_reason = "LIVE_CONTEXT_MISMATCH_PASS_LIVE"
                        replacement_level = "LIVE_CONTEXT_PASS_LIVE"
                        live_context_pass_live += 1
                        suspect_flags.append("LIVE_CONTEXT_PASS_LIVE")
                    elif (
                        special_decision.get("error")
                        == "DEVICE_CONTEXT_MISMATCH_PASS_LIVE"
                    ):
                        block_reason = "DEVICE_CONTEXT_MISMATCH_PASS_LIVE"
                        replacement_level = "DEVICE_CONTEXT_PASS_LIVE"
                        device_context_pass_live += 1
                        suspect_flags.append(
                            "DEVICE_CONTEXT_MISMATCH_PASS_LIVE"
                        )
                    else:
                        replacement_level = "SPECIAL_PASS_LIVE"
        elif device_context_mismatch:
            candidate_raw = bytes(live_leaf["raw"])
            clean_raw = bytearray(candidate_raw)
            semantic_ready = True
            semantic_ready_count += 1
            replacement_level = "DEVICE_CONTEXT_PASS_LIVE"
            block_reason = "DEVICE_CONTEXT_MISMATCH_PASS_LIVE"
            device_context_pass_live += 1
            suspect_flags.append("DEVICE_CONTEXT_MISMATCH_PASS_LIVE")
        elif cross_slot_candidates and selected is not None:
            # 用无tfp_called的正常0x01122329叶子替代命中叶子。
            # recordSequence、inc_id/obf_id来自Live；继承模式下设备字段也来自Live。
            clean_raw = bytearray(selected["raw"])
            clean_raw[0:4] = live_leaf["raw"][0:4]
            clean_raw[10:14] = live_leaf["raw"][10:14]
            if device_mode == DEVICE_MODE_INHERIT_LIVE:
                overlaid, device_field_rewrites = _overlay_live_device_fields(
                    clean_raw, live_leaf["raw"]
                )
                clean_raw = bytearray(overlaid)
            overlaid, runtime_field_rewrites = _overlay_live_runtime_fields(
                clean_raw, live_leaf["raw"]
            )
            clean_raw = bytearray(overlaid)
            if cross_account:
                selected_donor_game_id = str(
                    selected.get("donor_game_id") or donor_game_id or ""
                )
                identity_rewrite = _rewrite_cross_account_identity(
                    clean_raw,
                    bytes(live_leaf["raw"]),
                    selected_donor_game_id,
                    str(live_game_id or ""),
                )
                if identity_rewrite["blocked"]:
                    clean_raw = bytearray(live_leaf["raw"])
                    identity_blocked_leaves += 1
                    suspect_flags.append(identity_rewrite["status"])
                elif identity_rewrite["ranges"]:
                    identity_rewrite_count += len(identity_rewrite["ranges"])
            clean_raw[4:6] = len(clean_raw).to_bytes(2, "big")
            candidate_raw = bytes(clean_raw)
            candidate_by_path[tuple(live_leaf["path"])] = candidate_raw
            semantic_ready = True
            semantic_ready_count += 1
            matched += 1
            if identity_rewrite["blocked"]:
                replacement_level = "LIVE_CONTEXT_PASS_LIVE"
                block_reason = "CROSS_ACCOUNT_IDENTITY_BLOCK"
                live_context_pass_live += 1
            else:
                if len(candidate_raw) != len(live_leaf["raw"]):
                    variable_replacement_paths.add(tuple(live_leaf["path"]))
                    variable_length_replaced += 1
                else:
                    start = int(live_leaf["start"])
                    end = int(live_leaf["end"])
                    candidate_plain[start:end] = candidate_raw
                if candidate_raw != live_leaf["raw"]:
                    changed += 1
                cross_record_replaced += 1
                tfp_called_template_replaced += 1
                cross_record_slot_rewrite = True
                replacement_level = "CROSS_RECORD_SLOT_REPLACE"
                block_reason = str(cross_slot_rule["id"])
                tfp_called_rule_id = block_reason
                tfp_called_action = "CLEAN_TEMPLATE_REPLACE"
                tfp_called_rule_ids.add(tfp_called_rule_id)
                tfp_called_replacement = {
                    "detected": True,
                    "rule_id": tfp_called_rule_id,
                    "action": tfp_called_action,
                    "live_marker_offsets": [
                        offset
                        for offset in range(len(live_leaf["raw"]))
                        if bytes(live_leaf["raw"]).startswith(
                            _TFP_CALLED_MARKER, offset
                        )
                    ],
                    "candidate_marker_present": (
                        _TFP_CALLED_MARKER in candidate_raw
                    ),
                    "live_length": len(live_leaf["raw"]),
                    "candidate_length": len(candidate_raw),
                    "live_sha256": hashlib.sha256(
                        bytes(live_leaf["raw"])
                    ).hexdigest(),
                    "candidate_sha256": hashlib.sha256(
                        candidate_raw
                    ).hexdigest(),
                }
                suspect_flags.append("CROSS_RECORD_SLOT_REPLACE")
        elif tfp_called_marker_hit:
            sanitized_raw, tfp_called_remove_info = (
                _remove_tfp_called_encoded_field(live_leaf["raw"])
            )
            semantic_ready = True
            semantic_ready_count += 1
            if sanitized_raw is not None:
                candidate_raw = sanitized_raw
                candidate_by_path[tuple(live_leaf["path"])] = candidate_raw
                variable_replacement_paths.add(tuple(live_leaf["path"]))
                variable_length_replaced += 1
                changed += 1
                special_handled += 1
                special_changed += 1
                tfp_called_structured_removed += 1
                cross_slot_match_mode = "structured_remove_fallback"
                replacement_level = "TFP_CALLED_STRUCTURED_REMOVE"
                tfp_called_rule_id = TFP_CALLED_STRUCTURED_REMOVE_RULE_ID
                tfp_called_action = "STRUCTURED_FIELD_REMOVE"
                tfp_called_rule_ids.add(tfp_called_rule_id)
                block_reason = tfp_called_rule_id
                suspect_flags.append("TFP_CALLED_STRUCTURED_REMOVE")
            else:
                sanitized_raw, zero_info = _zero_tfp_called_markers(
                    live_leaf["raw"]
                )
                tfp_called_remove_info = {
                    "structured_remove_status": str(
                        tfp_called_remove_info.get("status") or ""
                    ),
                    **zero_info,
                }
                candidate_raw = sanitized_raw
                candidate_by_path[tuple(live_leaf["path"])] = candidate_raw
                start = int(live_leaf["start"])
                end = int(live_leaf["end"])
                candidate_plain[start:end] = candidate_raw
                changed += 1
                special_handled += 1
                special_changed += 1
                tfp_called_zeroed += 1
                cross_slot_match_mode = "zero_marker_fallback"
                replacement_level = "TFP_CALLED_ZERO_MARKER"
                tfp_called_rule_id = TFP_CALLED_ZERO_MARKER_RULE_ID
                tfp_called_action = "ZERO_MARKER"
                tfp_called_rule_ids.add(tfp_called_rule_id)
                block_reason = tfp_called_rule_id
                suspect_flags.append("TFP_CALLED_ZERO_MARKER")
            tfp_called_replacement = {
                "detected": True,
                "rule_id": tfp_called_rule_id,
                "action": tfp_called_action,
                "live_marker_offsets": [
                    offset
                    for offset in range(len(live_leaf["raw"]))
                    if bytes(live_leaf["raw"]).startswith(
                        _TFP_CALLED_MARKER, offset
                    )
                ],
                "candidate_marker_present": (
                    _TFP_CALLED_MARKER in candidate_raw
                ),
                "live_length": len(live_leaf["raw"]),
                "candidate_length": len(candidate_raw),
                "live_sha256": hashlib.sha256(
                    bytes(live_leaf["raw"])
                ).hexdigest(),
                "candidate_sha256": hashlib.sha256(
                    candidate_raw
                ).hexdigest(),
                "remove_info": dict(tfp_called_remove_info),
            }
        elif candidates:
            clean_raw = bytearray(selected["raw"])
            # 公共14字节头（包含recordSequence）始终继承实时叶子。
            clean_raw[0:14] = live_leaf["raw"][0:14]
            for field in inherit_fields:
                field_start = int(field["offset"])
                field_end = field_start + int(field["length"])
                if field_end > len(clean_raw):
                    continue
                before = bytes(clean_raw[field_start:field_end])
                live_value = bytes(live_leaf["raw"][field_start:field_end])
                clean_raw[field_start:field_end] = live_value
                inherited_log.append(
                    {
                        **field,
                        "template_hex": before.hex().upper(),
                        "live_hex": live_value.hex().upper(),
                    }
                )
            if cross_account:
                selected_donor_game_id = str(
                    selected.get("donor_game_id") or donor_game_id or ""
                )
                identity_rewrite = _rewrite_cross_account_identity(
                    clean_raw,
                    bytes(live_leaf["raw"]),
                    selected_donor_game_id,
                    str(live_game_id or ""),
                )
                if identity_rewrite["blocked"]:
                    block_reason = "CROSS_ACCOUNT_IDENTITY_BLOCK"
                    clean_raw = bytearray(live_leaf["raw"])
                    identity_blocked_leaves += 1
                    aggressive_blocked += 1
                    suspect_flags.append(identity_rewrite["status"])
                elif identity_rewrite["ranges"]:
                    identity_rewrite_count += len(identity_rewrite["ranges"])
            diff_offsets = [
                offset
                for offset, (live_byte, clean_byte) in enumerate(
                    zip(live_leaf["raw"], clean_raw)
                )
                if live_byte != clean_byte
            ]
            allowed_clean_offsets = _offsets(clean_fields)
            clean_diff_offsets = [
                offset for offset in diff_offsets if offset in allowed_clean_offsets
            ]
            unknown_diff_offsets = [
                offset for offset in diff_offsets if offset not in allowed_clean_offsets
            ]
            shadow_only_candidate_raw = bytes(clean_raw)
            shadow_only_diff_offsets = list(diff_offsets)
            semantic_ready = not unknown_diff_offsets
            candidate_raw = bytes(clean_raw)
            if force_full_live:
                # 0x01122388、0xFFF2、0xFFF3 是显式完整实时继承规则。
                # 它们仍参与同 recordCode/messageId/length 模板命中统计，
                # 但模板主体不进入候选，避免依赖序号/时间距离门间接保活。
                block_reason = "FULL_LIVE_INHERIT"
                candidate_raw = bytes(live_leaf["raw"])
                clean_raw = bytearray(candidate_raw)
                semantic_ready = True
                replacement_level = "FULL_LIVE_INHERIT"
                full_live_inherited += 1
                suspect_flags.append("FULL_LIVE_INHERIT")
            elif block_reason:
                candidate_raw = bytes(live_leaf["raw"])
                semantic_ready = True
            elif unknown_diff_offsets:
                # 未声明为clean的正文差异没有稳定语义。以前会整段引入录制
                # 主体，导致录制设备型号、版本和inc_id/obf_id混进Live。
                # 现在只保留影子候选供诊断，网络候选完整使用Live叶子。
                dynamic_guard = _unmapped_body_guard(
                    live_leaf, selected, int(sequence_distance or 0)
                )
                block_reason = "UNMAPPED_BODY_PASS_LIVE"
                # 以Live为底，只覆盖语义规则明确声明的clean白名单字段。
                # 这样即使同叶还有设备/版本/内部计数差异，也不会从模板带入。
                safe_raw = bytearray(live_leaf["raw"])
                for field in clean_fields:
                    field_start = int(field["offset"])
                    field_end = field_start + int(field["length"])
                    if field_end <= min(len(safe_raw), len(clean_raw)):
                        safe_raw[field_start:field_end] = clean_raw[field_start:field_end]
                candidate_raw = bytes(safe_raw)
                clean_raw = safe_raw
                semantic_ready = True
                replacement_level = (
                    "KNOWN_CLEAN"
                    if candidate_raw != live_leaf["raw"]
                    else "UNMAPPED_BODY_PASS_LIVE"
                )
                unmapped_pass_live += 1
                suspect_flags.append("UNMAPPED_BODY_PASS_LIVE")
            elif clean_diff_offsets:
                replacement_level = "KNOWN_CLEAN"
            if candidate_raw != live_leaf["raw"] and (
                live_runtime_context_mismatch(live_leaf["raw"], candidate_raw)
                if device_mode == DEVICE_MODE_REPLACE_RECORDED
                else live_context_mismatch(live_leaf["raw"], candidate_raw)
            ):
                # 即使clean范围声明过宽，也不允许模板改写设备、版本和
                # inc_id/obf_id。完整录制候选继续保留在影子字段中。
                block_reason = (
                    "LIVE_RUNTIME_CONTEXT_MISMATCH_PASS_LIVE"
                    if device_mode == DEVICE_MODE_REPLACE_RECORDED
                    else "LIVE_CONTEXT_MISMATCH_PASS_LIVE"
                )
                candidate_raw = bytes(live_leaf["raw"])
                clean_raw = bytearray(candidate_raw)
                semantic_ready = True
                replacement_level = "LIVE_CONTEXT_PASS_LIVE"
                live_context_pass_live += 1
                suspect_flags.append(block_reason)
            start, end = int(live_leaf["start"]), int(live_leaf["end"])
            candidate_plain[start:end] = clean_raw
            candidate_by_path[tuple(live_leaf["path"])] = bytes(clean_raw)
            matched += 1
            if candidate_raw != live_leaf["raw"]:
                changed += 1
            if clean_diff_offsets and candidate_raw != live_leaf["raw"]:
                clean_changed += 1
            # 未映射差异只用于影子诊断，不再计入网络改写。
            if semantic_ready:
                semantic_ready_count += 1
            else:
                semantic_unmapped += 1
        elif force_full_live:
            # 即使模板池没有同长度记录，强动态记录仍明确标记为整叶实时继承。
            # candidate_plain 初始即为实时明文，因此这里无需写入字节。
            block_reason = "FULL_LIVE_INHERIT"
            replacement_level = "FULL_LIVE_INHERIT"
            semantic_ready = True
            full_live_inherited += 1
            semantic_ready_count += 1
            suspect_flags.append("FULL_LIVE_INHERIT")
        elif prune_unmatched and live_leaf.get("path") and not base_candidates:
            # 个人池和官方池均无同结构叶子时，删除完整 length-prefix + leaf。
            # 父批次在下方统一重建，子项数、祖先长度和尾部同步处理。
            prune_paths.add(tuple(live_leaf["path"]))
            changed += 1
            replacement_level = "UNMATCHED_LEAF_PRUNE"
        elif not base_candidates:
            # v1.114 稳定策略：新结构完整保留实时叶子，只记录并等待专项规则。
            unmatched_pass_live += 1
            replacement_level = "UNMATCHED_LEAF_PASS_LIVE"

        # 录制设备模式的最后一道一致性处理：无论该叶子走了模板替换、
        # 专项补丁还是Live回退，只要正文携带设备字段，就统一写成连接
        # 锁定的录制设备画像。inc_id/obf_id及公共序号仍保持Live。
        recorded_device_field_rewrites: list[dict] = []
        if (
            candidate_raw
            and device_mode == DEVICE_MODE_REPLACE_RECORDED
            and recorded_device_context
        ):
            profiled_raw, recorded_device_field_rewrites = (
                _overlay_recorded_device_fields(
                    candidate_raw,
                    recorded_device_context,
                )
            )
            if recorded_device_field_rewrites:
                was_changed = candidate_raw != live_leaf["raw"]
                candidate_raw = profiled_raw
                path_key = tuple(live_leaf["path"])
                candidate_by_path[path_key] = candidate_raw
                if len(candidate_raw) != len(live_leaf["raw"]):
                    if path_key not in variable_replacement_paths:
                        variable_replacement_paths.add(path_key)
                        variable_length_replaced += 1
                else:
                    start, end = int(live_leaf["start"]), int(live_leaf["end"])
                    candidate_plain[start:end] = candidate_raw
                if not was_changed and candidate_raw != live_leaf["raw"]:
                    changed += 1
                if not semantic_ready:
                    semantic_ready = True
                    semantic_ready_count += 1
                recorded_device_profile_rewritten += 1
                if replacement_level in {
                    "NONE",
                    "UNMATCHED_LEAF_PASS_LIVE",
                    "UNMAPPED_BODY_PASS_LIVE",
                    "SPECIAL_PASS_LIVE",
                    "DEVICE_CONTEXT_PASS_LIVE",
                    "LIVE_CONTEXT_PASS_LIVE",
                    "FULL_LIVE_INHERIT",
                }:
                    replacement_level = "RECORDED_DEVICE_PROFILE"
                    block_reason = "RECORDED_DEVICE_PROFILE_REWRITE"
                suspect_flags.append("RECORDED_DEVICE_PROFILE_REWRITE")
        if tfp_called_marker_hit and _TFP_CALLED_MARKER in candidate_raw:
            # 最终叶子级不变量：任何分支结束后仍有文本时，执行等长清零。
            was_changed = candidate_raw != live_leaf["raw"]
            candidate_raw, final_zero_info = _zero_tfp_called_markers(
                candidate_raw
            )
            path_key = tuple(live_leaf["path"])
            candidate_by_path[path_key] = candidate_raw
            if len(candidate_raw) == len(live_leaf["raw"]):
                start, end = int(live_leaf["start"]), int(live_leaf["end"])
                candidate_plain[start:end] = candidate_raw
            else:
                variable_replacement_paths.add(path_key)
            if not was_changed and candidate_raw != live_leaf["raw"]:
                changed += 1
            if tfp_called_action != "ZERO_MARKER":
                tfp_called_zeroed += 1
            tfp_called_rule_id = TFP_CALLED_ZERO_MARKER_RULE_ID
            tfp_called_action = "FINAL_GUARD_ZERO_MARKER"
            tfp_called_rule_ids.add(tfp_called_rule_id)
            replacement_level = "TFP_CALLED_ZERO_MARKER"
            block_reason = tfp_called_rule_id
            tfp_called_remove_info = {
                **tfp_called_remove_info,
                "final_guard": final_zero_info,
            }
            tfp_called_replacement = {
                "detected": True,
                "rule_id": tfp_called_rule_id,
                "action": tfp_called_action,
                "live_marker_offsets": [
                    offset
                    for offset in range(len(live_leaf["raw"]))
                    if bytes(live_leaf["raw"]).startswith(
                        _TFP_CALLED_MARKER, offset
                    )
                ],
                "candidate_marker_present": False,
                "live_length": len(live_leaf["raw"]),
                "candidate_length": len(candidate_raw),
                "live_sha256": hashlib.sha256(
                    bytes(live_leaf["raw"])
                ).hexdigest(),
                "candidate_sha256": hashlib.sha256(candidate_raw).hexdigest(),
                "remove_info": dict(tfp_called_remove_info),
            }
            suspect_flags.append("TFP_CALLED_FINAL_GUARD_ZERO")
        if tfp_called_marker_hit and _TFP_CALLED_MARKER in candidate_raw:
            tfp_called_residual += 1
        if watched and shadow_only_diff_offsets:
            suspect_flags.append("BODY_DIFF")
        suspect_flags = list(dict.fromkeys(suspect_flags))
        suspect_watch = bool(watched or suspect_flags)
        if suspect_watch:
            suspect_leaf_count += 1
        # 116-A 需要对全部叶子建立跨运行字节画像。完整 HEX 只写分析日志，
        # 不参与候选选择或网络输出。
        trace_full_hex = True
        leaf_results.append(
            {
                "path": list(live_leaf["path"]),
                "record_code": int(live_leaf["record_code"]),
                "message_id": live_leaf.get("message_id"),
                "length": int(live_leaf["actual_length"]),
                "candidate_length": len(candidate_raw),
                "live_sequence": int(live_leaf["record_sequence"]),
                "structural_match": bool(base_candidates),
                "matched": selected is not None,
                "semantic_ready": semantic_ready,
                "semantic_rule": (rule or {}).get("name"),
                "replacement_level": replacement_level,
                "special_rule_id": special_decision.get("rule_id", ""),
                "special_rule_action": special_decision.get("action", "PASS_LIVE"),
                "special_hot_action": special_decision.get("hot_action", ""),
                "special_rule_error": special_decision.get("error", ""),
                "block_reason": block_reason,
                "dynamic_guard": dynamic_guard,
                "identity_rewrite": identity_rewrite,
                "identity_rewrite_ranges": identity_rewrite.get("ranges", []),
                "device_sensitive": device_sensitive,
                "device_context_mismatch": device_context_mismatch,
                "live_device_context": dict(live_device_context),
                "template_device_context": (
                    dict(selected.get("device_context") or {})
                    if selected is not None else {}
                ),
                "device_field_rewrites": device_field_rewrites,
                "runtime_field_rewrites": runtime_field_rewrites,
                "tfp_called_remove_info": tfp_called_remove_info,
                "tfp_called_detected": tfp_called_marker_hit,
                "tfp_called_rule_id": tfp_called_rule_id,
                "tfp_called_action": tfp_called_action,
                "tfp_called_replacement": tfp_called_replacement,
                "content_blacklist_hit": bool(content_blacklist_hit),
                "content_blacklist_token": (
                    str(content_blacklist_hit.get("token") or "")
                    if content_blacklist_hit else ""
                ),
                "content_blacklist_encoding": (
                    str(content_blacklist_hit.get("encoding") or "")
                    if content_blacklist_hit else ""
                ),
                "recorded_device_field_rewrites": recorded_device_field_rewrites,
                "cross_record_slot_rewrite": cross_record_slot_rewrite,
                "telemetry_slot": list(cross_slot) if cross_slot else None,
                "cross_slot_match_mode": cross_slot_match_mode,
                "suspect_watch": suspect_watch,
                "suspect_flags": suspect_flags,
                "available_template_lengths": available_template_lengths,
                "selection_method": (
                    "tfp_called_confirmed_structure_remove"
                    if cross_slot_match_mode == "structured_remove_fallback"
                    else "tfp_called_unknown_layout_zero_marker"
                    if cross_slot_match_mode == "zero_marker_fallback"
                    else (
                        "tfp_called_"
                        + cross_slot_match_mode
                        + "_then_nearest_length_sequence"
                    )
                    if cross_slot_match_mode
                    else "semantic_fields_then_nearest_sequence"
                    if selected is not None else None
                ),
                "sequence_distance": sequence_distance,
                "match_fields": [
                    {
                        **field,
                        "live_hex": _field_bytes(
                            live_leaf["raw"], field
                        ).hex().upper(),
                    }
                    for field in match_fields
                ],
                "inherited_fields": inherited_log,
                "clean_fields": clean_fields,
                "clean_field_values": [
                    {
                        **field,
                        "live_hex": _field_bytes(
                            live_leaf["raw"], field
                        ).hex().upper(),
                        "template_hex": (
                            _field_bytes(selected["raw"], field).hex().upper()
                            if selected is not None else ""
                        ),
                    }
                    for field in clean_fields
                ],
                "clean_diff_offsets": clean_diff_offsets,
                "unknown_diff_offsets": unknown_diff_offsets,
                "live_hex": (
                    bytes(live_leaf["raw"]).hex().upper()
                    if trace_full_hex else ""
                ),
                "template_hex": (
                    selected_raw.hex().upper()
                    if trace_full_hex and selected is not None else ""
                ),
                "candidate_hex": (
                    candidate_raw.hex().upper()
                    if trace_full_hex else ""
                ),
                "shadow_only_candidate_hex": (
                    shadow_only_candidate_raw.hex().upper()
                    if suspect_watch and shadow_only_candidate_raw else ""
                ),
                "shadow_only_diff_offsets": shadow_only_diff_offsets,
                "shadow_only_diff_ranges": _offset_ranges(
                    shadow_only_diff_offsets
                ),
                "template_pool_idx": (
                    int(selected["pool_idx"]) if selected is not None else None
                ),
                "template_path": (
                    list(selected["path"]) if selected is not None else None
                ),
                "template_sequence": (
                    int(selected["record_sequence"]) if selected is not None else None
                ),
                "template_length": (
                    len(selected_raw) if selected is not None else None
                ),
                "template_scope": (
                    str(selected.get("template_scope") or "player")
                    if selected is not None else None
                ),
                "template_batch_id": (
                    str(selected.get("template_batch_id") or "")
                    if selected is not None else None
                ),
            }
        )

    insert_plan: list[dict] = []
    inserted_raws: list[bytes] = []
    live_stable_ids = live_stable_message_ids(
        leaf.get("message_id") for leaf in live["leaves"]
    )
    insert_skipped_reason = ""
    if insert_state is not None and not replace_root_with_clean_2000:
        insert_state.update(
            ensure_insert_state(
                insert_state,
                template_rows,
                refresh=bool(refresh_insert_schedule),
            )
        )
        seen_live_80xx = note_live_80xx(
            insert_state,
            (leaf.get("message_id") for leaf in live["leaves"]),
        )
        live_stable_ids = set(seen_live_80xx)
        if insert_state.get("disabled"):
            insert_skipped_reason = "LIVE_HAS_STABLE_80XX"
        insert_plan = plan_inserts(
            list(insert_state.get("schedule") or []),
            live_report_index=live_report_index,
            live_message_ids=(
                leaf.get("message_id") for leaf in live["leaves"]
            ),
            consumed=insert_state.get("consumed") or [],
            connection_disabled=bool(insert_state.get("disabled")),
        )
        if (
            not insert_plan
            and not insert_skipped_reason
            and live_report_index is not None
            and insert_state.get("schedule")
        ):
            insert_skipped_reason = "NO_RECORDING_SLOT"
        next_sequence = 0
        for leaf in live["leaves"]:
            next_sequence = max(next_sequence, int(leaf.get("record_sequence") or 0))
        root_raw = bytes(live["root"]["raw"])
        version = int.from_bytes(root_raw[0:4], "big") if len(root_raw) >= 4 else 1
        for slot in insert_plan:
            next_sequence += 1
            stamped = stamp_inserted_leaf(
                slot["raw"], sequence=next_sequence, version=version
            )
            if stamped:
                inserted_raws.append(stamped)
            else:
                inserted_raws = []
                insert_plan = []
                break

    if replace_root_with_clean_2000:
        candidate_plain = bytearray(
            clean_2000_root_leaf(
                clean_2000_sequence, version=clean_2000_version
            )
        )
        variable_length_replaced += 1
    elif prune_paths or variable_replacement_paths:
        def _rebuild_node(node: dict) -> bytes | None:
            path_key = tuple(node.get("path") or [])
            if not node.get("children"):
                if path_key in prune_paths:
                    return None
                return candidate_by_path.get(path_key, bytes(node["raw"]))
            raw = bytes(node["raw"])
            cursor = 0x15
            for child in node["children"]:
                cursor += 4 + int(child["actual_length"])
            trailer = raw[cursor:]
            children = []
            for child in node["children"]:
                rebuilt_child = _rebuild_node(child)
                if rebuilt_child is not None:
                    children.append(rebuilt_child)
            header = bytearray(raw[:0x15])
            header[0x14] = len(children)
            rebuilt = header + b"".join(
                len(child).to_bytes(4, "big") + child
                for child in children
            ) + trailer
            rebuilt[4:6] = len(rebuilt).to_bytes(2, "big")
            return bytes(rebuilt)

        rebuilt_plain = _rebuild_node(live["root"])
        if rebuilt_plain is None:
            result["reason"] = "ROOT_PRUNE_BLOCKED"
            return result
        if prune_paths:
            rebuilt_plain = _normalize_pruned_batch(
                rebuilt_plain,
                live_root=live["root"],
                live_leaves=live["leaves"],
                prune_paths=prune_paths,
            )
        candidate_plain = bytearray(rebuilt_plain)

    if inserted_raws:
        current = bytes(candidate_plain)
        if int.from_bytes(current[6:10], "big") == BATCH_CODE:
            candidate_plain = bytearray(append_batch_children(current, inserted_raws))
        else:
            candidate_plain = bytearray(wrap_root_as_batch(current, inserted_raws))
        changed += len(inserted_raws)
        special_handled += len(inserted_raws)
        special_changed += len(inserted_raws)
        semantic_ready_count += len(inserted_raws)
        for index, (slot, raw) in enumerate(zip(insert_plan, inserted_raws)):
            leaf_results.append(
                {
                    "path": [len(live["leaves"]) + index],
                    "record_code": BINARY_CODE,
                    "message_id": int(slot["message_id"]),
                    "length": len(raw),
                    "live_sequence": None,
                    "template_sequence": int(slot["record_sequence"]),
                    "matched": True,
                    "changed": True,
                    "replacement_level": "SPECIAL_INSERT_LEAF",
                    "block_reason": "SPECIAL_INSERT_LEAF",
                    "special_rule_id": "",
                    "special_rule_action": "INSERT_LEAF",
                    "live_hex": "",
                    "candidate_hex": raw.hex().upper(),
                    "inserted_from_report_index": int(slot["report_index"]),
                }
            )

    total = len(live["leaves"])
    result.update(
        {
            "total_leaves": total,
            "structural_matched_leaves": structural_matched,
            "matched_leaves": matched,
            "changed_leaves": changed,
            "pruned_leaves": len(prune_paths),
            "cross_record_replaced_leaves": cross_record_replaced,
            "tfp_called_detected_leaves": tfp_called_detected,
            "tfp_called_template_replaced_leaves": (
                tfp_called_template_replaced
            ),
            "tfp_called_structured_removed_leaves": (
                tfp_called_structured_removed
            ),
            "tfp_called_zeroed_leaves": tfp_called_zeroed,
            "tfp_called_residual_leaves": tfp_called_residual,
            "tfp_called_rule_ids": sorted(tfp_called_rule_ids),
            "content_blacklist_dropped_leaves": content_blacklist_dropped,
            "content_blacklist_emptied_leaves": content_blacklist_emptied,
            "content_blacklist_tokens": sorted(
                token for token in content_blacklist_tokens if token
            ),
            "device_context_pass_live_leaves": device_context_pass_live,
            "recorded_device_profile_rewritten_leaves": (
                recorded_device_profile_rewritten
            ),
            "unmatched_pass_live_leaves": unmatched_pass_live,
            "unmapped_pass_live_leaves": unmapped_pass_live,
            "live_context_pass_live_leaves": live_context_pass_live,
            "special_handled_leaves": special_handled,
            "special_changed_leaves": special_changed,
            "special_dropped_leaves": special_dropped,
            "special_emptied_leaves": special_emptied,
            "drop_entire_report": drop_entire_report,
            "replace_root_with_clean_2000": replace_root_with_clean_2000,
            "variable_length_replaced_leaves": variable_length_replaced,
            "full_live_inherited_leaves": full_live_inherited,
            "clean_changed_leaves": clean_changed,
            "aggressive_changed_leaves": aggressive_changed,
            "aggressive_blocked_leaves": aggressive_blocked,
            "semantic_ready_leaves": semantic_ready_count,
            "semantic_unmapped_leaves": semantic_unmapped,
            "subtype_miss_leaves": subtype_miss,
            "suspect_leaf_count": suspect_leaf_count,
            "identity_rewrite_count": identity_rewrite_count,
            "identity_blocked_leaves": identity_blocked_leaves,
            "inserted_leaves": len(inserted_raws),
            "inserted_message_ids": [
                f"0x{int(slot['message_id']):04X}" for slot in insert_plan
            ],
            "insert_skipped_reason": insert_skipped_reason,
            "insert_skipped_live_80xx": [
                f"0x{message_id:04X}" for message_id in sorted(live_stable_ids)
            ],
            "suspect_live_plaintext_hex": (
                bytes(live["plaintext"]).hex().upper()
                if suspect_leaf_count else ""
            ),
            "coverage": round(matched / total, 6) if total else 0.0,
            "structural_coverage": (
                round(structural_matched / total, 6) if total else 0.0
            ),
            "semantic_coverage": (
                round(semantic_ready_count / total, 6) if total else 0.0
            ),
            "leaf_results": leaf_results,
        }
    )
    if not total:
        result["reason"] = "LIVE_HAS_NO_LEAVES"
        return result
    if (
        not matched
        and not prune_paths
        and not special_handled
        and not full_live_inherited
        and not recorded_device_profile_rewritten
        and not inserted_raws
    ):
        result["reason"] = (
            "NO_SEMANTIC_SUBTYPE_MATCH"
            if structural_matched else "NO_LENGTH_AWARE_LEAF_MATCH"
        )
        return result

    record = live["record"]
    plaintext = bytes(candidate_plain)
    selector = int(record["selector"])
    key_index = int(record["key_index"])
    ciphertext = type9_transform(
        plaintext, selector, KEYS[key_index], direction=1
    )
    logical = bytearray(live_data[:int(record["ciphertext_offset"])])
    cipher_start = int(record["ciphertext_offset"])
    old_cipher_end = cipher_start + int(record["ciphertext_length"])
    logical[cipher_start - 6:cipher_start - 2] = (
        zlib.crc32(plaintext) & 0xFFFFFFFF
    ).to_bytes(4, "big")
    logical[cipher_start - 2:cipher_start] = len(ciphertext).to_bytes(2, "big")
    logical.extend(ciphertext)
    logical.extend(live_data[old_cipher_end:])

    # 立即解密回验，避免把“能加密”误当成“候选包正确”。
    roundtrip = decode_material(bytes(logical))
    if not roundtrip["ok"] or roundtrip["plaintext"] != plaintext:
        result["reason"] = "ENCRYPT_DECRYPT_ROUNDTRIP_FAILED"
        result["errors"].extend(roundtrip["errors"])
        return result
    result.update(
        {
            "generated": True,
            "reason": "SHADOW_CANDIDATE_READY",
            "candidate_logical": bytes(logical),
            "candidate_plaintext": plaintext,
            "candidate_plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
            "roundtrip_ok": True,
        }
    )
    if insert_state is not None and inserted_raws:
        mark_consumed(insert_state, insert_plan)
    return result
