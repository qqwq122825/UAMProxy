"""v1.123 Type9 叶子专项规则与热加载入口。

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

HOT_RULE_SCHEMA = "dfm-type9-hot-rules-v1"
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

# v1.122 的旧内置全量文档只用于识别“未经用户修改的旧默认文件”。
# v1.123 启动时会将它原子升级为新默认；用户自定义文件保持不动。
LEGACY_V122_DEFAULT_HOT_RULE_DOCUMENT: dict[str, Any] = {
    "schema": HOT_RULE_SCHEMA,
    "revision": "v122-module-clean-1",
    "rules": [
        {
            "id": "0207-zero-anomaly-counters",
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x0207",
                "length": 116,
            },
            "action": "patch_live",
            "patches": [
                {
                    "offset": "0x48",
                    "hex": "00000000",
                    "note": "body+0x28",
                },
                {
                    "offset": "0x50",
                    "hex": "00000000",
                    "note": "body+0x30",
                },
            ],
        },
        {
            "id": "2000-clean-module-report",
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x2000",
                "length": "*",
            },
            "action": "replace_template_nearest",
        },
        {
            "id": "1105-clean-module-enumeration",
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x1105",
                "length": "*",
            },
            "action": "replace_template_nearest",
            "inherit_live_header": 36,
        },
        {
            "id": "8027-clean-process-profile",
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x8027",
                "length": "*",
            },
            "action": "replace_template_nearest",
        },
        {
            "id": "8029-clean-process-location-profile",
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x8029",
                "length": "*",
            },
            "action": "replace_template_nearest",
        },
        {
            "id": "9000-clean-installed-target-profile",
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x9000",
                "length": "*",
            },
            "action": "replace_template_nearest",
        },
    ],
}

# v1.123 历史内置仅包含 0x0207 / 0x8027 / 0x8029 / 0x9000。
# 后续默认将周期模块、行为向量、UIKit视图树和探针状态一并内置；
# 代码完整性的设备模式策略由基座处理，其余仍保持声明式规则。
BUILTIN_RULE_DESCRIPTIONS = {
    "0207-zero-anomaly-counters": "疑似异常页/缺页状态：保留Live，清零状态字段及两个已确认计数字段",
    "2001-zero-behavior-vector": "固定步进状态：保留前0x24字节及步进计数，清零后部20字节行为向量",
    "1007-clean-code-entry-fingerprint": "一次性代码入口指纹：设备/会话相关，明确保留Live",
    "1008-clean-code-integrity-vector": "代码完整性/系统调用指纹：设备/系统相关，明确保留Live",
    "1009-clean-measurement-vector": "周期代码测量向量：阶段/地址相关，明确保留Live",
    "100C-clean-code-integrity-entry": "代码入口及完整性指纹：机器码/尾部状态相关，明确保留Live",
    "100B-clean-uikit-view-tree": "UIKit视图层级摘要：不再用录制模板替换，保留Live",
    "100F-clean-probe-status": "小型探针状态三元组：不再用录制模板替换，保留Live",
    "2000-clean-module-report": (
        "周期模块检测结果：有玩家录制或官方模板则按最近长度替换并保留Live公共头；"
        "没有对应叶则删叶"
    ),
    "1105-clean-module-enumeration": "周期模块/路径枚举：使用最近长度干净模板并保留Live前36字节",
    "8027-clean-process-profile": "活动进程/应用枚举：黑名单脏进程先删叶，其余保留Live",
    "8028-zero-write-counter": "80xx小型状态：保留+0x20的7，仅清零开追踪后跳变的+0x24累计",
    "8029-clean-process-location-profile": "进程调用位置采样：黑名单脏进程先删叶，其余保留Live",
    "8002-zero-status-word": "80xx状态叶：仅清零开追踪后从0变成3的+0x2C，其余字段保留Live",
    "9000-clean-installed-target-profile": "命中型安装应用/环境目标项：改成真实44字节空结果0x2000并保留Live序号",
}
_V123_BUILTIN_RULE_IDS = {
    "0207-zero-anomaly-counters",
    "8027-clean-process-profile",
    "8029-clean-process-location-profile",
    "9000-clean-installed-target-profile",
}


def _rules_with_descriptions(
    rule_ids: set[str],
    *,
    drop_hit_only_9000: bool = False,
) -> list[dict]:
    rules = []
    for source in LEGACY_V122_DEFAULT_HOT_RULE_DOCUMENT["rules"]:
        rule_id = str(source.get("id") or "")
        if rule_id not in rule_ids:
            continue
        rule = deepcopy(source)
        rule["description"] = BUILTIN_RULE_DESCRIPTIONS.get(rule_id, "")
        if drop_hit_only_9000 and rule_id == "9000-clean-installed-target-profile":
            rule["action"] = "drop_leaf"
        rules.append(rule)
    return rules


V123_SAFE_REPLAY_1_DOCUMENT: dict[str, Any] = {
    "schema": HOT_RULE_SCHEMA,
    "revision": "v123-safe-replay-1",
    "rules": _rules_with_descriptions(
        _V123_BUILTIN_RULE_IDS - {"9000-clean-installed-target-profile"}
    ),
}
V123_SAFE_REPLAY_2_DOCUMENT: dict[str, Any] = {
    "schema": HOT_RULE_SCHEMA,
    "revision": "v123-safe-replay-2",
    "rules": _rules_with_descriptions(_V123_BUILTIN_RULE_IDS),
}
V123_SAFE_REPLAY_3_DOCUMENT: dict[str, Any] = {
    "schema": HOT_RULE_SCHEMA,
    "revision": "v123-safe-replay-3",
    "rules": _rules_with_descriptions(
        _V123_BUILTIN_RULE_IDS,
        drop_hit_only_9000=True,
    ),
}

V1232_DEVICE_AWARE_SLOT_CLEAN_1_DOCUMENT: dict[str, Any] = {
    "schema": HOT_RULE_SCHEMA,
    "revision": "v123.2-device-aware-slot-clean-1",
    "rules": [
        {
            "id": "0207-zero-anomaly-counters",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "0207-zero-anomaly-counters"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x0207",
                "length": 116,
            },
            "action": "patch_live",
            "patches": [
                {
                    "offset": "0x20",
                    "hex": "00000000",
                    "note": "状态字段",
                },
                {
                    "offset": "0x48",
                    "hex": "00000000",
                    "note": "body+0x28",
                },
                {
                    "offset": "0x50",
                    "hex": "00000000",
                    "note": "body+0x30",
                },
            ],
        },
        {
            "id": "2001-zero-behavior-vector",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "2001-zero-behavior-vector"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x2001",
                "length": 56,
            },
            "action": "patch_live",
            "patches": [
                {
                    "offset": "0x24",
                    "hex": "0000000000000000000000000000000000000000",
                    "note": "清零count后方四个浮点/行为向量字段",
                }
            ],
        },
        {
            "id": "1007-clean-code-entry-fingerprint",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "1007-clean-code-entry-fingerprint"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x1007",
                "length": "*",
            },
            "action": "pass_live",
        },
        {
            "id": "1008-clean-code-integrity-vector",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "1008-clean-code-integrity-vector"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x1008",
                "length": "*",
            },
            "action": "pass_live",
        },
        {
            "id": "1009-clean-measurement-vector",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "1009-clean-measurement-vector"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x1009",
                "length": "*",
            },
            "action": "pass_live",
        },
        {
            "id": "100B-clean-uikit-view-tree",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "100B-clean-uikit-view-tree"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x100B",
                "length": "*",
            },
            "action": "replace_template_nearest",
            "inherit_live_header": 14,
            "require_same_device": True,
        },
        {
            "id": "100C-clean-code-integrity-entry",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "100C-clean-code-integrity-entry"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x100C",
                "length": "*",
            },
            "action": "pass_live",
        },
        {
            "id": "100F-clean-probe-status",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "100F-clean-probe-status"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x100F",
                "length": "*",
            },
            "action": "replace_template_nearest",
            "inherit_live_header": 14,
            "require_same_device": True,
        },
        {
            "id": "2000-clean-module-report",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "2000-clean-module-report"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x2000",
                "length": "*",
            },
            "action": "replace_template_nearest",
            "inherit_live_header": 14,
        },
        {
            "id": "1105-clean-module-enumeration",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "1105-clean-module-enumeration"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x1105",
                "length": "*",
            },
            "action": "replace_template_nearest",
            "inherit_live_header": 36,
        },
        {
            "id": "8027-clean-process-profile",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "8027-clean-process-profile"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x8027",
                "length": "*",
            },
            "action": "replace_template_nearest",
            "inherit_live_header": 14,
            "require_same_device": True,
        },
        {
            "id": "8029-clean-process-location-profile",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "8029-clean-process-location-profile"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x8029",
                "length": "*",
            },
            "action": "replace_template_nearest",
            "inherit_live_header": 14,
            "require_same_device": True,
        },
        {
            "id": "9000-clean-installed-target-profile",
            "description": BUILTIN_RULE_DESCRIPTIONS[
                "9000-clean-installed-target-profile"
            ],
            "enabled": True,
            "match": {
                "record_code": "0x0102000A",
                "message_id": "0x9000",
                "length": "*",
            },
            "action": "empty_2000",
        },
    ],
}

# 1007/1008/1009/100C 在“继承重放设备”模式下本来就由基座保留Live，
# 在“替换录制设备”模式下则由连接级设备策略统一选取锁定会话模板。
# 因此它们不再作为无实际改写的显式热规则展示，只保留真正执行专项处理的9条。
V1233_TFP_CALLED_SPECIAL_RULES_DOCUMENT = deepcopy(
    V1232_DEVICE_AWARE_SLOT_CLEAN_1_DOCUMENT
)
V1233_TFP_CALLED_SPECIAL_RULES_DOCUMENT["revision"] = (
    "v123.3-tfp-called-special-rules-1"
)
V1233_TFP_CALLED_SPECIAL_RULES_DOCUMENT["rules"] = [
    rule
    for rule in V1233_TFP_CALLED_SPECIAL_RULES_DOCUMENT["rules"]
    if rule.get("id") not in {
        "1007-clean-code-entry-fingerprint",
        "1008-clean-code-integrity-vector",
        "1009-clean-measurement-vector",
        "100C-clean-code-integrity-entry",
    }
]

# v1.124 的tfp_called全消息号扫描由Type9基座执行；热规则表沿用9条专项，
# 修订号用于让未经用户编辑的v1.123.3默认文件自动升级。
V124_TFP_CALLED_GLOBAL_CLEAN_1_DOCUMENT = deepcopy(
    V1233_TFP_CALLED_SPECIAL_RULES_DOCUMENT
)
V124_TFP_CALLED_GLOBAL_CLEAN_1_DOCUMENT["revision"] = (
    "v124-tfp-called-global-clean-1"
)

# v1.125.5 第一阶段：开追踪后跳变的 0x8028/+0x24、0x8002/+0x2C
# 按 0x0207 方式清零。保留该文档用于自动升级已经生成的旧默认文件。
V1255_8028_8002_ZERO_1_DOCUMENT = deepcopy(
    V124_TFP_CALLED_GLOBAL_CLEAN_1_DOCUMENT
)
V1255_8028_8002_ZERO_1_DOCUMENT["revision"] = "v125.5-8028-8002-zero-1"
V1255_8028_8002_ZERO_1_DOCUMENT["rules"] = list(
    V1255_8028_8002_ZERO_1_DOCUMENT["rules"]
)
_DEFAULT_PATCH_LIVE_RULES = [
    {
        "id": "8028-zero-write-counter",
        "description": BUILTIN_RULE_DESCRIPTIONS["8028-zero-write-counter"],
        "enabled": True,
        "match": {
            "record_code": "0x0102000A",
            "message_id": "0x8028",
            "length": 40,
        },
        "action": "patch_live",
        "patches": [
            {
                "offset": "0x24",
                "hex": "00000000",
                "note": "开追踪后跳变的累计，干净样本为0",
            }
        ],
    },
    {
        "id": "8002-zero-status-word",
        "description": BUILTIN_RULE_DESCRIPTIONS["8002-zero-status-word"],
        "enabled": True,
        "match": {
            "record_code": "0x0102000A",
            "message_id": "0x8002",
            "length": 56,
        },
        "action": "patch_live",
        "patches": [
            {
                "offset": "0x2C",
                "hex": "00000000",
                "note": "开追踪后0→3的状态字",
            }
        ],
    },
]
_insert_at = next(
    (
        index + 1
        for index, rule in enumerate(V1255_8028_8002_ZERO_1_DOCUMENT["rules"])
        if rule.get("id") == "2001-zero-behavior-vector"
    ),
    len(V1255_8028_8002_ZERO_1_DOCUMENT["rules"]),
)
V1255_8028_8002_ZERO_1_DOCUMENT["rules"][
    _insert_at:_insert_at
] = _DEFAULT_PATCH_LIVE_RULES

# v1.123.1 的11条默认，用于识别并自动升级未编辑的旧规则文件。
V1231_COMPLETE_TELEMETRY_CLEAN_DOCUMENT = deepcopy(
    V1232_DEVICE_AWARE_SLOT_CLEAN_1_DOCUMENT
)
V1231_COMPLETE_TELEMETRY_CLEAN_DOCUMENT["revision"] = (
    "v123-complete-telemetry-clean-1"
)
V1231_COMPLETE_TELEMETRY_CLEAN_DOCUMENT["rules"] = [
    rule
    for rule in V1231_COMPLETE_TELEMETRY_CLEAN_DOCUMENT["rules"]
    if rule.get("id") not in {
        "1007-clean-code-entry-fingerprint",
        "100C-clean-code-integrity-entry",
    }
]
for _legacy_rule in V1231_COMPLETE_TELEMETRY_CLEAN_DOCUMENT["rules"]:
    _legacy_rule.pop("require_same_device", None)
    if _legacy_rule.get("id") in {
        "1008-clean-code-integrity-vector",
        "1009-clean-measurement-vector",
    }:
        _legacy_rule["action"] = "replace_template_nearest"
        _legacy_rule["inherit_live_header"] = 14
    _legacy_rule["description"] = {
        "1008-clean-code-integrity-vector": "代码完整性/系统调用指纹：使用最近长度干净模板",
        "1009-clean-measurement-vector": "周期检测数值向量：使用最近长度干净模板",
        "100B-clean-uikit-view-tree": "UIKit视图层级摘要：使用最近长度干净模板",
        "100F-clean-probe-status": "小型探针状态三元组：使用最近长度干净模板",
        "8027-clean-process-profile": "活动进程/应用枚举：使用最近长度干净模板",
        "8029-clean-process-location-profile": "进程调用位置、模块/符号/偏移枚举：使用最近长度干净模板",
    }.get(_legacy_rule.get("id"), _legacy_rule.get("description", ""))

# v123阶段曾由管理页加载的7条完整测试规则。内容保持精确，用于识别未修改
# 的旧测试文件并升级到当前默认专项；用户自行编辑过的规则文档仍保持原样。
_LEGACY_COMPLETE_TEST_DESCRIPTIONS = {
    "0207-zero-anomaly-counters": "疑似异常页/缺页状态：保留Live，清零状态字段及两个已确认计数字段",
    "2001-zero-behavior-vector": "固定步进状态：保留前0x24字节及步进计数，清零后部20字节行为向量",
    "2000-clean-module-report": "周期模块检测结果：按长度选择最近的录制模板，并保留Live公共头",
    "1105-clean-module-enumeration": "周期模块/路径枚举：按长度选择最近的录制模板，并保留Live前36字节",
    "8027-clean-process-profile": "活动进程/应用枚举：按长度选择最近的录制模板",
    "8029-clean-process-location-profile": "进程调用位置、模块/符号/偏移枚举：按长度选择最近的录制模板",
    "9000-clean-installed-target-profile": "命中型安装应用/环境目标项：删除叶子并重建容器、长度及CRC",
}
_LEGACY_COMPLETE_TEST_RULE_IDS = set(_LEGACY_COMPLETE_TEST_DESCRIPTIONS)
LEGACY_V123_COMPLETE_TEST_7_DOCUMENT: dict[str, Any] = {
    "schema": HOT_RULE_SCHEMA,
    "revision": "v123-complete-test-0207-2001-1",
    "rules": [
        deepcopy(rule)
        for rule in V1255_8028_8002_ZERO_1_DOCUMENT["rules"]
        if str(rule.get("id") or "") in _LEGACY_COMPLETE_TEST_RULE_IDS
    ],
}
for _legacy_rule in LEGACY_V123_COMPLETE_TEST_7_DOCUMENT["rules"]:
    _legacy_rule["description"] = _LEGACY_COMPLETE_TEST_DESCRIPTIONS[
        str(_legacy_rule["id"])
    ]
    if _legacy_rule["id"] == "0207-zero-anomaly-counters":
        _legacy_rule["patches"][0][
            "note"
        ] = "本次封禁样本新增非零状态字段"

# v1.125.6：
# - 0x0207 没有可用的正常录制叶，出现时直接删叶并重建父容器；
# - 0x100C 使用同设备录制池中的最近长度模板，保留Live公共头；
# - 0x8028/0x8002 继续只清零已确认的跳变字段。
DEFAULT_HOT_RULE_DOCUMENT = deepcopy(V1255_8028_8002_ZERO_1_DOCUMENT)
DEFAULT_HOT_RULE_DOCUMENT["revision"] = "v125.6-0207-drop-100c-template-1"
for _default_rule in DEFAULT_HOT_RULE_DOCUMENT["rules"]:
    if _default_rule.get("id") == "0207-zero-anomaly-counters":
        _default_rule["description"] = (
            "异常页/缺页状态：删除整条0x0207叶并重建父容器、长度及CRC"
        )
        _default_rule["action"] = "drop_leaf"
        _default_rule.pop("patches", None)

_100C_RECORDED_TEMPLATE_RULE = {
    "id": "100C-recorded-code-integrity-entry",
    "description": "代码入口及完整性指纹：使用同设备录制池最近长度模板",
    "enabled": True,
    "match": {
        "record_code": "0x0102000A",
        "message_id": "0x100C",
        "length": "*",
    },
    "action": "replace_template_nearest",
    "inherit_live_header": 14,
    "require_same_device": True,
}
_100C_insert_at = next(
    (
        index + 1
        for index, rule in enumerate(DEFAULT_HOT_RULE_DOCUMENT["rules"])
        if rule.get("id") == "100F-clean-probe-status"
    ),
    len(DEFAULT_HOT_RULE_DOCUMENT["rules"]),
)
DEFAULT_HOT_RULE_DOCUMENT["rules"].insert(
    _100C_insert_at,
    _100C_RECORDED_TEMPLATE_RULE,
)

# 冻结 v1.125.6，用于识别未编辑的旧默认文件并自动升级。
V1256_0207_DROP_100C_TEMPLATE_1_DOCUMENT = deepcopy(DEFAULT_HOT_RULE_DOCUMENT)

# v1.126.4：默认不再用录制模板替换设备/探针/进程叶。
# 录制池没有对应叶时跳过替换；drop_leaf / patch_live 仍然生效。
# 0x1105 仍用录制模板换模块/路径列表，并保留Live前36字节。
_PASS_LIVE_NO_TEMPLATE_RULE_IDS = {
    "100B-clean-uikit-view-tree",
    "100C-recorded-code-integrity-entry",
    "100F-clean-probe-status",
    "2000-clean-module-report",
    "1105-clean-module-enumeration",
    "8027-clean-process-profile",
    "8029-clean-process-location-profile",
}
_PASS_LIVE_NO_TEMPLATE_DESCRIPTIONS = {
    "100C-recorded-code-integrity-entry": (
        "代码入口及完整性指纹：不再用录制模板替换，保留Live"
    ),
}
DEFAULT_HOT_RULE_DOCUMENT["revision"] = "v126.4-drop-patch-only-1"
for _default_rule in DEFAULT_HOT_RULE_DOCUMENT["rules"]:
    rule_id = str(_default_rule.get("id") or "")
    if rule_id not in _PASS_LIVE_NO_TEMPLATE_RULE_IDS:
        continue
    _default_rule["action"] = "pass_live"
    _default_rule.pop("inherit_live_header", None)
    _default_rule.pop("require_same_device", None)
    _default_rule.pop("patches", None)
    _default_rule["description"] = (
        _PASS_LIVE_NO_TEMPLATE_DESCRIPTIONS.get(rule_id)
        or BUILTIN_RULE_DESCRIPTIONS.get(rule_id)
        or _default_rule.get("description", "")
    )

# 冻结「1105 也被改成 pass_live」的短命默认，便于已写出的文件自动升回模板。
V1264_DROP_PATCH_ONLY_1_DOCUMENT = deepcopy(DEFAULT_HOT_RULE_DOCUMENT)
for _default_rule in DEFAULT_HOT_RULE_DOCUMENT["rules"]:
    if _default_rule.get("id") != "1105-clean-module-enumeration":
        continue
    _default_rule["action"] = "replace_template_nearest"
    _default_rule["inherit_live_header"] = 36
    _default_rule.pop("require_same_device", None)
    _default_rule["description"] = (
        "周期模块/路径枚举：有对应录制叶则用最近长度模板替换0x24后主体，"
        "保留Live前36字节（头+计数）；没有对应叶则原样通过"
    )
DEFAULT_HOT_RULE_DOCUMENT["revision"] = "v126.4-restore-1105-template-1"

# 冻结恢复1105后、100B仍为pass_live的默认，便于已写出的文件自动升级。
V1264_RESTORE_1105_TEMPLATE_1_DOCUMENT = deepcopy(DEFAULT_HOT_RULE_DOCUMENT)
for _default_rule in DEFAULT_HOT_RULE_DOCUMENT["rules"]:
    if _default_rule.get("id") != "100B-clean-uikit-view-tree":
        continue
    _default_rule["action"] = "replace_template_nearest"
    _default_rule["inherit_live_header"] = 14
    _default_rule.pop("require_same_device", None)
    _default_rule["allow_cross_device"] = True
    _default_rule["description"] = (
        "UIKit视图层级摘要：注入dylib会多一层绘制视图。"
        "有对应录制叶则无条件用最近长度模板替换，允许跨设备；"
        "没有对应叶则原样通过"
    )
DEFAULT_HOT_RULE_DOCUMENT["revision"] = "v126.4-100b-cross-device-template-1"

# 冻结 12 条含 pass_live 占位的默认，便于已写出的文件自动升到精简 7 条。
V1264_100B_CROSS_DEVICE_TEMPLATE_1_DOCUMENT = deepcopy(DEFAULT_HOT_RULE_DOCUMENT)
_MINIMAL_DEFAULT_RULE_IDS = {
    "0207-zero-anomaly-counters",
    "2001-zero-behavior-vector",
    "8028-zero-write-counter",
    "8002-zero-status-word",
    "100B-clean-uikit-view-tree",
    "1105-clean-module-enumeration",
    "9000-clean-installed-target-profile",
}
DEFAULT_HOT_RULE_DOCUMENT["rules"] = [
    rule
    for rule in DEFAULT_HOT_RULE_DOCUMENT["rules"]
    if str(rule.get("id") or "") in _MINIMAL_DEFAULT_RULE_IDS
]
DEFAULT_HOT_RULE_DOCUMENT["revision"] = "v126.4-minimal-7-1"

# 冻结精简 7 条，便于已写出的文件自动升回 8027/8029 录制模板。
V1264_MINIMAL_7_1_DOCUMENT = deepcopy(DEFAULT_HOT_RULE_DOCUMENT)
_8027_8029_NEAREST_RULE_IDS = (
    "8027-clean-process-profile",
    "8029-clean-process-location-profile",
)
_8027_8029_NEAREST_DESCRIPTIONS = {
    "8027-clean-process-profile": (
        "活动进程/应用枚举：黑名单脏进程先删叶；"
        "有玩家录制或官方模板则按最近长度替换并保留Live公共头；"
        "没有对应叶则原样通过"
    ),
    "8029-clean-process-location-profile": (
        "进程调用位置采样：黑名单脏进程先删叶；"
        "有玩家录制或官方模板则按最近长度替换并保留Live公共头；"
        "没有对应叶则原样通过"
    ),
}
_8027_8029_insert_at = next(
    (
        index
        for index, rule in enumerate(DEFAULT_HOT_RULE_DOCUMENT["rules"])
        if rule.get("id") == "9000-clean-installed-target-profile"
    ),
    len(DEFAULT_HOT_RULE_DOCUMENT["rules"]),
)
for _source_rule in V1264_100B_CROSS_DEVICE_TEMPLATE_1_DOCUMENT["rules"]:
    rule_id = str(_source_rule.get("id") or "")
    if rule_id not in _8027_8029_NEAREST_RULE_IDS:
        continue
    _restored = deepcopy(_source_rule)
    _restored["action"] = "replace_template_nearest"
    _restored["inherit_live_header"] = 14
    _restored.pop("require_same_device", None)
    _restored["allow_cross_device"] = True
    _restored["description"] = _8027_8029_NEAREST_DESCRIPTIONS[rule_id]
    DEFAULT_HOT_RULE_DOCUMENT["rules"].insert(_8027_8029_insert_at, _restored)
    _8027_8029_insert_at += 1
DEFAULT_HOT_RULE_DOCUMENT["revision"] = "v126.5-8027-8029-nearest-1"

# 冻结 9 条（尚无 2000 模板），便于已写出的文件自动升回 2000 nearest。
V1265_8027_8029_NEAREST_1_DOCUMENT = deepcopy(DEFAULT_HOT_RULE_DOCUMENT)
_2000_insert_at = next(
    (
        index
        for index, rule in enumerate(DEFAULT_HOT_RULE_DOCUMENT["rules"])
        if rule.get("id") == "1105-clean-module-enumeration"
    ),
    len(DEFAULT_HOT_RULE_DOCUMENT["rules"]),
)
_2000_source = next(
    (
        deepcopy(rule)
        for rule in V1264_100B_CROSS_DEVICE_TEMPLATE_1_DOCUMENT["rules"]
        if rule.get("id") == "2000-clean-module-report"
    ),
    {
        "id": "2000-clean-module-report",
        "enabled": True,
        "match": {
            "record_code": "0x0102000A",
            "message_id": "0x2000",
            "length": "*",
        },
    },
)
_2000_source["action"] = "replace_template_nearest"
_2000_source["inherit_live_header"] = 14
_2000_source.pop("require_same_device", None)
_2000_source.pop("allow_cross_device", None)
_2000_source["no_template"] = "drop_leaf"
_2000_source["description"] = (
    "周期模块检测结果：有玩家录制或官方模板则按最近长度替换并保留Live公共头；"
    "没有对应叶则删叶"
)
DEFAULT_HOT_RULE_DOCUMENT["rules"].insert(_2000_insert_at, _2000_source)
DEFAULT_HOT_RULE_DOCUMENT["revision"] = "v126.5-2000-nearest-drop-1"

# 冻结 v1.126.5 最终默认，便于已经落盘的未编辑规则在启动时
# 自动升级。v1.126.7 恢复 0x0207 的等长字段清零：保留整条Live叶、
# recordSequence 和父容器形状，避免 drop_leaf 造成消息缺失与序号空洞。
V1265_2000_NEAREST_DROP_1_DOCUMENT = deepcopy(DEFAULT_HOT_RULE_DOCUMENT)
for _default_rule in DEFAULT_HOT_RULE_DOCUMENT["rules"]:
    if _default_rule.get("id") != "0207-zero-anomaly-counters":
        continue
    _default_rule["description"] = (
        "疑似异常页/缺页状态：保留完整Live叶，仅清零+0x48与+0x50字段"
    )
    _default_rule["action"] = "patch_live"
    _default_rule.pop("inherit_live_header", None)
    _default_rule.pop("require_same_device", None)
    _default_rule.pop("allow_cross_device", None)
    _default_rule.pop("no_template", None)
    _default_rule["patches"] = [
        {
            "offset": "0x48",
            "hex": "00000000",
            "note": "body+0x28",
        },
        {
            "offset": "0x50",
            "hex": "00000000",
            "note": "body+0x30",
        },
    ]
DEFAULT_HOT_RULE_DOCUMENT["revision"] = "v126.7-0207-patch-live-1"

# 冻结 v1.126.7。126.6 封禁样本回溯确认：录制输入叶序号全部连续，
# 唯一整叶删除把 3320..3326 改成缺少 3325；同时样本中存在56条完全一致
# （仅recordSequence不同）的44字节0x2000空结果叶，51条为批次子叶、5条为
# 根叶。因此内置抑制不再制造序号空洞，9000及2000缺模板均写成该空结果叶。
V1267_0207_PATCH_LIVE_1_DOCUMENT = deepcopy(DEFAULT_HOT_RULE_DOCUMENT)
for _default_rule in DEFAULT_HOT_RULE_DOCUMENT["rules"]:
    if _default_rule.get("id") == "9000-clean-installed-target-profile":
        _default_rule["description"] = (
            "命中型安装应用/环境目标项：改成真实44字节空结果0x2000，保留Live序号"
        )
        _default_rule["action"] = "empty_2000"
        _default_rule.pop("patches", None)
    elif _default_rule.get("id") == "2000-clean-module-report":
        _default_rule["description"] = (
            "周期模块检测结果：有模板则最近长度替换；无模板则改成真实44字节空结果0x2000并保留Live序号"
        )
        _default_rule["no_template"] = "empty_2000"
DEFAULT_HOT_RULE_DOCUMENT["revision"] = "v126.8-sequence-safe-empty-2000-1"

# v1.127.0 正式采用126.6封禁样本回溯出的保序策略。冻结126.8候选规则，
# 使已经落盘的候选版在启动时自动迁移到127正式版。
V1268_SEQUENCE_SAFE_EMPTY_2000_1_DOCUMENT = deepcopy(
    DEFAULT_HOT_RULE_DOCUMENT
)
DEFAULT_HOT_RULE_DOCUMENT["revision"] = "v127.0-sequence-safe-empty-2000-1"

# v1.128.2：历史124/125数据回溯确认+0x44/+0x4C是正常递增计数；
# 异常页/缺页字段仍位于叶原始偏移+0x48/+0x50。等长patch_live
# 保留叶、父容器及recordSequence，同时保留v1.128.1的DROP_LEAF保序压紧。
V127_SEQUENCE_SAFE_EMPTY_2000_1_DOCUMENT = deepcopy(DEFAULT_HOT_RULE_DOCUMENT)
for _default_rule in DEFAULT_HOT_RULE_DOCUMENT["rules"]:
    if _default_rule.get("id") != "0207-zero-anomaly-counters":
        continue
    _default_rule["description"] = (
        "疑似异常页/缺页状态：保留完整Live叶，仅清零+0x48与+0x50字段"
    )
    _default_rule["action"] = "patch_live"
    _default_rule["patches"] = [
        {
            "offset": "0x48",
            "hex": "00000000",
            "note": "body+0x28",
        },
        {
            "offset": "0x50",
            "hex": "00000000",
            "note": "body+0x30",
        },
    ]
DEFAULT_HOT_RULE_DOCUMENT["revision"] = "v128.2-0207-4850-compact-ai-log-1"

# 代码内专项处理器继续保留，便于单元测试和极少数需要代码语义的规则。
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
    if schema != HOT_RULE_SCHEMA:
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
            or BUILTIN_RULE_DESCRIPTIONS.get(rule_id, "")
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
            note = str(raw_patch.get("note") or "")
            patches.append({"offset": offset, "value": value, "expect": expect, "note": note})
            item = {"offset": offset, "hex": value.hex().upper()}
            if expect is not None:
                item["expect_hex"] = expect.hex().upper()
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
        force_builtin_0207_patch_live: bool = False,
    ):
        self.path = path
        self.default_document = deepcopy(default_document) if default_document else None
        self.managed_previous_defaults = tuple(
            deepcopy(document) for document in managed_previous_defaults
        )
        self.auto_reload_interval = max(0.0, float(auto_reload_interval))
        self.force_builtin_0207_patch_live = bool(
            force_builtin_0207_patch_live
        )
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
        """Keep the built-in 0x0207 contract stable across persisted hot rules."""
        output = deepcopy(document)
        if not self.force_builtin_0207_patch_live:
            return output
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
    managed_previous_defaults=(
        LEGACY_V122_DEFAULT_HOT_RULE_DOCUMENT,
        V123_SAFE_REPLAY_1_DOCUMENT,
        V123_SAFE_REPLAY_2_DOCUMENT,
        V123_SAFE_REPLAY_3_DOCUMENT,
        LEGACY_V123_COMPLETE_TEST_7_DOCUMENT,
        V1231_COMPLETE_TELEMETRY_CLEAN_DOCUMENT,
        V1232_DEVICE_AWARE_SLOT_CLEAN_1_DOCUMENT,
        V1233_TFP_CALLED_SPECIAL_RULES_DOCUMENT,
        V124_TFP_CALLED_GLOBAL_CLEAN_1_DOCUMENT,
        V1255_8028_8002_ZERO_1_DOCUMENT,
        V1256_0207_DROP_100C_TEMPLATE_1_DOCUMENT,
        V1264_DROP_PATCH_ONLY_1_DOCUMENT,
        V1264_RESTORE_1105_TEMPLATE_1_DOCUMENT,
        V1264_100B_CROSS_DEVICE_TEMPLATE_1_DOCUMENT,
        V1264_MINIMAL_7_1_DOCUMENT,
        V1265_8027_8029_NEAREST_1_DOCUMENT,
        V1265_2000_NEAREST_DROP_1_DOCUMENT,
        V1267_0207_PATCH_LIVE_1_DOCUMENT,
        V1268_SEQUENCE_SAFE_EMPTY_2000_1_DOCUMENT,
        V127_SEQUENCE_SAFE_EMPTY_2000_1_DOCUMENT,
    ),
    force_builtin_0207_patch_live=True,
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
        expect = patch.get("expect")
        if expect is not None and bytes(candidate[offset:offset + len(value)]) != bytes(expect):
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
