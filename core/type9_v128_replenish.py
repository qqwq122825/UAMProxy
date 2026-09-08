"""v1.128 built-in stable 80xx replenish model and per-session scheduler.

The model was extracted from the bundled 2026-08-23 long 01 recording.  Runtime
state is connection-local; templates and periods are process-global constants.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import random
from typing import Iterable

from core.type9_stable_80xx_insert import sanitize_insert_leaf


MODEL_REVISION = "v131-builtin-800d-offline-fallback-r1"
WALL_SECONDS_PER_LOGICAL_SLOT = 1.0164
INITIAL_LOGICAL_SLOT = 13
SLOT_DUE_TOLERANCE = 0.5
STALE_SLOT_GRACE = 90.0
MAX_BATCH_CHILDREN = 16

# v128.5 同设备玩家录制层。三角洲中央九类内置模板已移除；其余十二类按
# 同设备录制时间轴复放。录制缺项或Hook漏出的Live叶沿原生路径进入二级热
# 规则，二级无匹配规则时保持Live。
PLAYER_SUPPLEMENT_MESSAGE_IDS = frozenset(
    {
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
    }
)
# 静态画像直接复用；动态族按录制slot/事件时间轴复放，已确认字段在发送前
# 重建。高动态快照保留同设备录制正文，后续Live漏出仍由二级规则优先。
PLAYER_STATIC_READY_MESSAGE_IDS = frozenset({0x800F, 0x8023})
PLAYER_DYNAMIC_READY_MESSAGE_IDS = frozenset(
    PLAYER_SUPPLEMENT_MESSAGE_IDS - PLAYER_STATIC_READY_MESSAGE_IDS
)
PLAYER_DYNAMIC_PENDING_MESSAGE_IDS = frozenset()
PLAYER_EVENT_TIMELINE_MESSAGE_IDS = frozenset(
    {0x8027, 0x8029, 0x802A, 0x802B}
)
PLAYER_BASE_MESSAGE_IDS = frozenset(
    PLAYER_SUPPLEMENT_MESSAGE_IDS - PLAYER_EVENT_TIMELINE_MESSAGE_IDS
)
PLAYER_INDIVIDUAL_MESSAGE_IDS = frozenset(
    {0x8007, 0x800A, 0x800C, 0x800D, 0x800F, 0x8023, 0x8024, 0x802C}
)
PLAYER_CROSS_ACCOUNT_BLOCKED_MESSAGE_IDS = frozenset(
    {0x8007, 0x800A, 0x800C, 0x800F, 0x8023}
)
# 8027/8029 扫描设备环境，同设备跨账号可发；802A/802B 同理不在此集合。
# 800D 轮次 = 1 + cycle×20，仅依赖逻辑 slot，与机型/账号/IDFV 无关：
# 同设备同账号、同设备跨账号、跨设备均可发（有录制 800D 叶即可）。
PLAYER_CROSS_DEVICE_ALLOWED_MESSAGE_IDS = frozenset({0x800D})
# 802A/802B are emitted after the client enters an active match.  Their
# bodies are static snapshots, so elapsed time alone is not a sufficient
# trigger when a session remains in the lobby.  These IDs are the observed
# in-match evidence that opens the event gate; the gate latches per session.
PLAYER_GAMEPLAY_TRIGGER_MESSAGE_IDS = frozenset(
    {
        0x8027,
        0x8028,
        0x8029,
        0x8C03,
        0x9000,
        0xFFFB,
        0xFFFE,
    }
)
PLAYER_GAMEPLAY_GATED_MESSAGE_IDS = frozenset({0x802A, 0x802B})
MATCH_EVENT_MODES = frozenset({"off", "random"})
SCAN_WAVE_MODES = frozenset({"off", "repeat_first"})
# 长录制已确认 8007/800D/802C 以 600 个逻辑 slot 重复，800F 以 900 重复。
# 800A 按当前模板判定：无 30-slot 密发时仍用末两档 900；出现连续 30 则
# 按簇划，至少三个簇起点、两个近似簇间隔才外推，禁止用 30 当外推周期。
# 8027/8029：rebuild_scan_waves=repeat_first 时，第一完整波为模板，
# 第二波开扫首帧量 T，之后按 T 循环第一波；off 不发这两条。
# 短波尾巴 +0x20=59 仍充分；长波要求相邻 +0x20 逐项递减，
# 再加空档>180s + 下一波开扫闭合。
# 8029 同波不同 elapsed 多片保留，同 elapsed 近重复仍合并。
# 802A/802B 由 rebuild_match_events：off 不补；random 按
# 10～20 分钟随机补一对，不跟进把、不跟 FFFB/8027。
PLAYER_PERIODIC_EXTENSION_PERIODS = {
    0x8007: 600,
    0x800D: 600,
    0x802C: 600,
    0x800F: 900,
}
PLAYER_800A_MESSAGE_ID = 0x800A
PLAYER_800A_SPARSE_PERIOD = 900
PLAYER_800A_INNER_STEP = 30
PLAYER_800A_MIN_CLUSTERS_TO_EXTEND = 3
PLAYER_800A_CLUSTER_INTERVAL_TOLERANCE = 30
PLAYER_PERIODIC_SLOT_FAMILY_IDS = frozenset(
    set(PLAYER_PERIODIC_EXTENSION_PERIODS) | {PLAYER_800A_MESSAGE_ID}
)
PLAYER_SCAN_WAVE_MESSAGE_IDS = frozenset({0x8027, 0x8029})
# 129绿色等长录制里同名8027/8029约12分钟后再扫一轮；600s分桶落在两波
# 之间的静默区，同一波近重复仍合成一条。T 本身取自模板，不写死 600。
PLAYER_SCAN_WAVE_SECONDS = 600.0
PLAYER_SCAN_WAVE_GAP_SECONDS = 180.0
PLAYER_SCAN_WAVE_START_MIN_U20 = 150
PLAYER_SCAN_WAVE_TAIL_U20 = 59
PLAYER_PERIODIC_MIN_SAMPLES = 2

# v1.131: 800D 的 328 条历史录制/重放叶均为 64 字节，slot 固定从 60
# 开始按 600 递增，+0x20 固定按 1 + cycle*20 递增。该种子仅提供协议
# 结构；发送前仍由 rebuild_player_supplement_leaf 重建 slot 与轮次字段。
# 真实 Live / 录制 donor 始终优先，只有录制池完全缺少 800D 时才使用。
BUILTIN_800D_SEED_REVISION = "v131-history-328-zero-deviation-r1"
BUILTIN_800D_SESSION_ID = "builtin-800d-offline"
BUILTIN_800D_ANCHOR_SLOTS = (60, 660)
BUILTIN_800D_SEED = bytes.fromhex(
    "0000000100400102000A0000007B000000000000002A800D200F0000003C"
    "000100000001202505130000000100000D2900000EC60000000000000000"
    "00000000"
)


def cluster_800a_slots(slots: Iterable[int]) -> list[list[int]]:
    ordered = sorted({int(value) for value in slots})
    if not ordered:
        return []
    clusters = [[ordered[0]]]
    for slot in ordered[1:]:
        if slot - clusters[-1][-1] == PLAYER_800A_INNER_STEP:
            clusters[-1].append(slot)
        else:
            clusters.append([slot])
    return clusters


def evaluate_800a_period(slots: Iterable[int]) -> dict:
    """Judge 800A from the current template only.

    Sparse recordings keep the 900-slot last-two-sample rule.  A 30-slot
    burst switches to cluster mode: two clusters replay as recorded, three
    cluster starts with two near-equal intervals unlock extrapolation.
    Any non-adjacent 900 pair is ignored.
    """
    ordered = sorted({int(value) for value in slots})
    intervals = [right - left for left, right in zip(ordered, ordered[1:])]
    clusters = cluster_800a_slots(ordered)
    starts = [cluster[0] for cluster in clusters]
    has_inner_30 = PLAYER_800A_INNER_STEP in intervals
    info = {
        "ready": False,
        "morphology": "none",
        "period": None,
        "cluster_count": len(clusters),
        "cluster_starts": starts,
        "cluster_intervals": [],
        "slots": ordered,
        "intervals": intervals,
        "last_interval": intervals[-1] if intervals else None,
        "next_expected_slot": None,
        "status": "等待第2次 (0/2)",
        "minimum_samples": PLAYER_PERIODIC_MIN_SAMPLES,
    }
    if not ordered:
        return info
    if has_inner_30:
        cluster_intervals = [
            right - left for left, right in zip(starts, starts[1:])
        ]
        info["morphology"] = "cluster_30"
        info["cluster_intervals"] = cluster_intervals
        info["minimum_samples"] = PLAYER_800A_MIN_CLUSTERS_TO_EXTEND
        if len(starts) < PLAYER_800A_MIN_CLUSTERS_TO_EXTEND:
            info["status"] = (
                f"等待第{PLAYER_800A_MIN_CLUSTERS_TO_EXTEND}簇 "
                f"({len(starts)}/{PLAYER_800A_MIN_CLUSTERS_TO_EXTEND})"
            )
            return info
        previous, latest = cluster_intervals[-2], cluster_intervals[-1]
        if abs(latest - previous) > PLAYER_800A_CLUSTER_INTERVAL_TOLERANCE:
            info["status"] = f"簇间隔不一致 {previous}/{latest}"
            return info
        info["ready"] = True
        info["period"] = int(latest)
        info["next_expected_slot"] = int(starts[-1]) + int(latest)
        info["status"] = "ready"
        return info
    info["morphology"] = "sparse_900"
    info["period"] = PLAYER_800A_SPARSE_PERIOD
    if len(ordered) < PLAYER_PERIODIC_MIN_SAMPLES:
        info["status"] = f"等待第2次 ({len(ordered)}/2)"
        return info
    if ordered[-1] - ordered[-2] != PLAYER_800A_SPARSE_PERIOD:
        info["status"] = (
            f"间隔{ordered[-1] - ordered[-2]}/{PLAYER_800A_SPARSE_PERIOD}"
        )
        return info
    info["ready"] = True
    info["next_expected_slot"] = ordered[-1] + PLAYER_800A_SPARSE_PERIOD
    info["status"] = "ready"
    return info


def rebuild_match_event_mode() -> str:
    """802A/802B product mode. Unknown values collapse to off."""
    from core.config import app_config

    if bool(app_config.get("rebuild_controls_v2", False)):
        return (
            "random"
            if bool(app_config.get("rebuild_match_events_enabled", False))
            else "off"
        )
    raw = str(app_config.get("rebuild_match_events") or "off").strip().lower()
    return "random" if raw == "random" else "off"


def rebuild_scan_wave_mode() -> str:
    """8027/8029 product mode. Unknown values collapse to repeat_first."""
    from core.config import app_config

    if bool(app_config.get("rebuild_controls_v2", False)):
        return (
            "repeat_first"
            if bool(app_config.get("rebuild_scan_waves_enabled", False))
            else "off"
        )
    raw = str(app_config.get("rebuild_scan_waves") or "repeat_first").strip().lower()
    return raw if raw in SCAN_WAVE_MODES else "repeat_first"


def rebuild_player_base_mode() -> bool:
    """Whether the eight non-event same-device player families are enabled."""
    from core.config import app_config

    if bool(app_config.get("rebuild_controls_v2", False)):
        return bool(app_config.get("rebuild_player_base_enabled", False))
    return bool(app_config.get("full_rebuild_01_mode", False))


def rebuild_controls_v3_mode() -> bool:
    from core.config import app_config

    return bool(app_config.get("rebuild_controls_v3", False))


def _player_toggle_key(message_id: int) -> str:
    return f"rebuild_player_{int(message_id):04X}_enabled"


def rebuild_player_message_enabled(message_id: int) -> bool:
    """Return the per-ID toggle, with v2/legacy compatibility."""
    if rebuild_controls_v3_mode() and int(message_id) in PLAYER_INDIVIDUAL_MESSAGE_IDS:
        from core.config import app_config

        return bool(app_config.get(_player_toggle_key(message_id), False))
    return rebuild_player_base_mode()


def match_event_schedule_bounds() -> tuple[float, float, float]:
    from core.config import app_config

    quiet = float(app_config.get("match_event_lobby_quiet_seconds") or 360.0)
    low = float(app_config.get("match_event_min_seconds") or 600.0)
    high = float(app_config.get("match_event_max_seconds") or 1200.0)
    quiet = max(0.0, quiet)
    low = max(0.0, low)
    if high < low:
        high = low
    return quiet, low, high


def ensure_match_event_schedule(player_state: dict) -> None:
    if player_state.get("match_event_next_elapsed") is not None:
        return
    quiet, low, high = match_event_schedule_bounds()
    player_state["match_event_next_elapsed"] = max(quiet, random.uniform(low, high))
    player_state.setdefault("match_event_count", 0)

# 强检条件中央层。文件对在Live报告中出现后才开启对应消息，避免把强检
# 心跳带到普通会话。两组触发关系由历史长录制交叉回溯确认：
#   j + f       -> 8C03，首档150，之后每120逻辑slot；
#   vv + v_tl   -> 9100，600逻辑slot周期。
STRONG_PROFILE_MESSAGE_IDS = frozenset({0x8C03, 0x9100})
STRONG_PROFILE_FILE_TRIGGERS = {
    0x8C03: frozenset({"mrpcs_i_j.data", "mrpcs_i_f.data"}),
    0x9100: frozenset({"mrpcs_i_vv.data", "mrpcs_i_v_tl.data"}),
}
STRONG_PROFILE_FILE_NAMES = frozenset(
    value
    for required in STRONG_PROFILE_FILE_TRIGGERS.values()
    for value in required
)
# Live 已见、但录制池没有、因此还没有对应 8C/91/80xx 映射的检测文件。
# 只记账、不武装、不补发。首见：v1.130.18 重放
# run_20260831_214106_923767，上行 0x0112232E 点名，随后
# 0x01122349 / 0x01122386 报 dl:mrpcs_i_v_ic.data,stat:0。
UNMAPPED_STRONG_PROFILE_FILES = frozenset({"mrpcs_i_v_ic.data"})
WATCHED_MRPCS_FILE_NAMES = frozenset(
    (*STRONG_PROFILE_FILE_NAMES, *UNMAPPED_STRONG_PROFILE_FILES)
)

_STRONG_PROFILE_ROWS = {
    0x8C03: {
        "first_slot": 150,
        "period": 120,
        # 2026-08-25强检长录制中的完整真实轨迹。发送时重建
        # recordSequence、logical slot与轮次计数，其他指标取同轮模板。
        "templates": [
            "0000000100700102000A000000DC000000000000005A8C03200F00000096000101352640000000040000000300006909000064DD00000E83000000000000001E000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100700102000A00000131000000000000005A8C03200F0000010E0001013526400000000800000003000062A600005E4800001DD0000000000000003C000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100700102000A00000186000000000000005A8C03200F000001860001013526400000000C000000030000517500004CA900003546000000000000003C0000000B0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100700102000A000001CE000000000000005A8C03200F000001FE0001013526400000001000000003000046720000418D0000521B000000000000003C0000000D0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100700102000A00000233000000000000005A8C03200F0000027600010135264000000014000000030000412100003C4600006F0B000000000000003C0000000F0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100700102000A00000284000000000000005A8C03200F000002EE000101352640000000180000000300003DF20000392600008B44000000000000003C0000000F0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100700102000A000002DF000000000000005A8C03200F000003660001013526400000001C0000000300003BCF000037130000A784000000000000003C0000000F0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100700102000A00000345000000000000005A8C03200F000003DE000101352640000000200000000300003A68000035B30000C4FE000000000000003C0000000F0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100700102000A00000395000000000000005A8C03200F0000045600010135264000000024000000030000397C000034BF0000E148000000000000003C0000000F0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100700102000A000003F1000000000000005A8C03200F000004CE0001013526400000002800000003000038C2000034010000FD95000000000000003C0000000F0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100700102000A00000444000000000000005A8C03200F000005460001013526400000002C00000003000039310000347D000114E10000010B0000001E000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100700102000A0000049A000000000000005A8C03200F000005BE000101352640000000300000000300003B54000036A4000123370000010B0000001E000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ],
    },
    0x9100: {
        "first_slot": 600,
        "period": 600,
        "templates": [
            "0000000100240102000A00000211000000000000000E9100200F00000258000100000002",
        ],
    },
}


# 暗区干净录制未见三角洲中央九类 8000/8002/8003/8004/800B/8020/8021/8025/8028。
# 这些内置权威模板已移除；中央层调度保留，后续按暗区 hook/录制再填。
_MODEL_ROWS: dict[int, dict] = {}


def _decoded_model() -> dict[int, dict]:
    output: dict[int, dict] = {}
    for message_id, row in _MODEL_ROWS.items():
        templates = []
        for value in row["templates"]:
            cleaned = sanitize_insert_leaf(bytes.fromhex(value))
            if not cleaned:
                raise ValueError(f"invalid built-in template 0x{message_id:04X}")
            templates.append(cleaned)
        output[message_id] = {
            "first_slot": int(row["first_slot"]),
            "period": (
                int(row["period"]) if row.get("period") is not None else None
            ),
            "templates": tuple(templates),
        }
    return output


BUILTIN_MODEL = _decoded_model()
BUILTIN_MESSAGE_IDS = frozenset(BUILTIN_MODEL)


def sanitize_strong_profile_leaf(raw: bytes | bytearray) -> bytes:
    """Validate a conditional strong-profile leaf and normalize its length."""
    data = bytes(raw)
    if len(data) < 0x1E:
        return b""
    if int.from_bytes(data[6:10], "big") != 0x0102000A:
        return b""
    message_id = int.from_bytes(data[0x16:0x18], "big")
    expected_length = {0x8C03: 112, 0x9100: 36}.get(message_id)
    if expected_length is None or len(data) != expected_length:
        return b""
    output = bytearray(data)
    output[4:6] = len(output).to_bytes(2, "big")
    return bytes(output)


def _decoded_strong_profile_model() -> dict[int, dict]:
    output: dict[int, dict] = {}
    for message_id, row in _STRONG_PROFILE_ROWS.items():
        templates = []
        for value in row["templates"]:
            cleaned = sanitize_strong_profile_leaf(bytes.fromhex(value))
            if not cleaned:
                raise ValueError(
                    f"invalid strong-profile template 0x{message_id:04X}"
                )
            templates.append(cleaned)
        output[message_id] = {
            "first_slot": int(row["first_slot"]),
            "period": int(row["period"]),
            "templates": tuple(templates),
        }
    return output


STRONG_PROFILE_MODEL = _decoded_strong_profile_model()


def ensure_v128_state(state: dict | None) -> dict:
    current = state if isinstance(state, dict) else {}
    current.setdefault("model_revision", MODEL_REVISION)
    current.setdefault("report_offset", 0)
    current.setdefault("leaf_offset", 0)
    current.setdefault("frame_offset", 0)
    current.setdefault("group_offset", 0)
    current.setdefault("seen_live_ids", [])
    current.setdefault("satisfied_keys", [])
    current.setdefault("late_live_keys", [])
    current.setdefault("emitted", [])
    current.setdefault("skipped_stale", [])
    current.setdefault("last_output_leaf_sequence", 0)
    current.setdefault("injected_report_count", 0)
    current.setdefault("injected_leaf_count", 0)
    current.setdefault(
        "same_device_player",
        {
            "selected_session_id": "",
            "consumed": [],
            "suppressed_by_live": [],
            "emitted_identities": [],
            "injected_leaf_count": 0,
            "gameplay_gate_open": False,
            "gameplay_trigger_ids": [],
            "gameplay_trigger_elapsed_seconds": None,
            "match_event_next_elapsed": None,
            "match_event_count": 0,
            "802c_link_counter": None,
        },
    )
    current.setdefault(
        "strong_profile",
        {
            "seen_files": [],
            "armed_message_ids": [],
            "armed_slots": {},
            "satisfied_keys": [],
            "emitted": [],
            "skipped_stale": [],
            "injected_leaf_count": 0,
        },
    )
    return current


def stamp_strong_profile_leaf(
    raw: bytes | bytearray,
    *,
    sequence: int,
    version: int,
) -> bytes:
    cleaned = sanitize_strong_profile_leaf(raw)
    if not cleaned:
        return b""
    output = bytearray(cleaned)
    output[0:4] = int(version).to_bytes(4, "big")
    output[10:14] = int(sequence).to_bytes(4, "big")
    output[4:6] = len(output).to_bytes(2, "big")
    return bytes(output)


def sanitize_player_supplement_leaf(raw: bytes | bytearray) -> bytes:
    """Validate a recorded-only supplemental leaf without changing its body."""
    data = bytes(raw)
    if len(data) < 0x1E:
        return b""
    if int.from_bytes(data[6:10], "big") != 0x0102000A:
        return b""
    message_id = int.from_bytes(data[0x16:0x18], "big")
    if message_id not in PLAYER_SUPPLEMENT_MESSAGE_IDS:
        return b""
    output = bytearray(data)
    output[4:6] = len(output).to_bytes(2, "big")
    return bytes(output)


def stamp_player_supplement_leaf(
    raw: bytes | bytearray,
    *,
    sequence: int,
    version: int,
) -> bytes:
    cleaned = sanitize_player_supplement_leaf(raw)
    if not cleaned:
        return b""
    output = bytearray(cleaned)
    output[0:4] = int(version).to_bytes(4, "big")
    output[10:14] = int(sequence).to_bytes(4, "big")
    output[4:6] = len(output).to_bytes(2, "big")
    return bytes(output)


def player_leaf_identity(raw: bytes | bytearray) -> str | None:
    """Return the semantic de-duplication key for a player 80xx leaf."""
    data = bytes(raw)
    cleaned = sanitize_player_supplement_leaf(data)
    if not cleaned:
        return None
    message_id = int.from_bytes(cleaned[0x16:0x18], "big")
    if message_id in PLAYER_EVENT_TIMELINE_MESSAGE_IDS:
        body = bytearray(cleaned[0x1E:])
        # 8027/8029的正文首个32位值随扫描时点轻微变化；其余正文标识同一
        # 快照条目。802A/802B整段正文作为事件子型。
        if message_id in {0x8027, 0x8029} and len(body) >= 6:
            body[2:6] = b"\x00" * 4
        subtype = hashlib.sha256(bytes(body)).hexdigest()[:16].upper()
        return f"{message_id:04X}@EVENT#{subtype}"
    slot = int.from_bytes(cleaned[0x1C:0x1E], "big")
    return f"{message_id:04X}@{slot}"


def event_recorded_elapsed_seconds(template_row: dict) -> float:
    """Wall-clock offset of a recorded event leaf, for due-time and wave index."""
    recorded_elapsed = template_row.get("recorded_elapsed_seconds")
    if recorded_elapsed is not None:
        return float(recorded_elapsed)
    source_report = int(template_row.get("report_index") or 0)
    return max(0.0, (source_report - 1) * WALL_SECONDS_PER_LOGICAL_SLOT)


def player_event_emit_key(
    raw: bytes | bytearray,
    *,
    recorded_elapsed_seconds: float | None = None,
) -> str | None:
    """Session emit key: body identity, scan-wave bucket, 8029 elapsed bucket."""
    identity = player_leaf_identity(raw)
    if not identity:
        return None
    data = bytes(raw)
    if len(data) < 0x18:
        return identity
    message_id = int.from_bytes(data[0x16:0x18], "big")
    if message_id not in PLAYER_SCAN_WAVE_MESSAGE_IDS:
        return identity
    elapsed = float(recorded_elapsed_seconds or 0.0)
    wave = int(elapsed // PLAYER_SCAN_WAVE_SECONDS)
    if message_id == 0x8029:
        elapsed_bucket = round(elapsed, 1)
        return f"{identity}@W{wave}@{elapsed_bucket:g}"
    return f"{identity}@W{wave}"


def player_event_identity_already_emitted(
    identity: str | None,
    emitted: Iterable[str],
) -> bool:
    """True if this body identity was injected in any recorded scan wave."""
    if not identity:
        return False
    emitted_set = {str(value) for value in emitted}
    if identity in emitted_set:
        return True
    prefix = f"{identity}@W"
    return any(item.startswith(prefix) for item in emitted_set)


def _replay_recorded_at(
    template_row: dict,
    *,
    unix_now: float,
    elapsed_seconds: float,
) -> float | None:
    """Wall-clock instant of a recorded player leaf, for 802C uptime rebuild.

    Pool rows carry ``recorded_at``.  Tests and older rows may only have
    ``recorded_elapsed_seconds``; recover that as connection-start + elapsed
    so 802C still advances instead of freezing at the recorded counter.
    """
    if template_row.get("recorded_at") is not None:
        return float(template_row["recorded_at"])
    recorded_elapsed = template_row.get("recorded_elapsed_seconds")
    if recorded_elapsed is None:
        return None
    return float(unix_now) - float(elapsed_seconds) + float(recorded_elapsed)


def rebuild_player_supplement_leaf(
    raw: bytes | bytearray,
    *,
    target_slot: int,
    unix_now: float,
    recorded_at: float | None,
    previous_802c_counter: int | None = None,
) -> tuple[bytes, list[str]]:
    """Rebuild confirmed dynamic fields while preserving same-device payload.

    ``8024 +0x20/+0x24`` stay on the recorded boot/install epochs: native
    traces only refresh ``+0x20`` after a device reboot, and ``+0x24``
    survives reboot.  Rebasing them onto the current 01 connection would
    look like a new boot across game restarts.

    ``802C +0x20`` must keep moving with wall clock
    (``recorded_uptime + now - recorded_at``).  Leaving it frozen pins
    ``8024+802C`` to the recording instant.  ``+0x24/+0x28`` stay a
    four-step linked counter for the current connection.
    """
    cleaned = sanitize_player_supplement_leaf(raw)
    if not cleaned:
        return b"", []
    output = bytearray(cleaned)
    message_id = int.from_bytes(output[0x16:0x18], "big")
    rebuilt_fields: list[str] = []
    # 周期外推必须把协议逻辑slot同步到新周期；原始录制行写回相同值。
    output[0x1C:0x1E] = int(target_slot).to_bytes(2, "big")
    if message_id == 0x800D and len(output) >= 0x24:
        cycle = max(0, (int(target_slot) - 60) // 600)
        output[0x20:0x24] = (1 + cycle * 20).to_bytes(4, "big")
        rebuilt_fields.append("round_counter@0x20")
    elif message_id == 0x802C and len(output) >= 0x24:
        if recorded_at is not None:
            recorded_uptime = int.from_bytes(output[0x20:0x24], "big")
            delta = max(0, int(float(unix_now) - float(recorded_at)))
            output[0x20:0x24] = min(
                0xFFFFFFFF, recorded_uptime + delta
            ).to_bytes(4, "big")
            rebuilt_fields.append("elapsed_counter@0x20")
        if previous_802c_counter is not None and len(output) >= 0x2C:
            previous = max(0, int(previous_802c_counter))
            current = min(0xFFFFFFFF, previous + 4)
            output[0x24:0x28] = previous.to_bytes(4, "big")
            output[0x28:0x2C] = current.to_bytes(4, "big")
            rebuilt_fields.extend(
                ["link_previous@0x24", "link_counter@0x28"]
            )
    output[4:6] = len(output).to_bytes(2, "big")
    return bytes(output), rebuilt_fields


def builtin_800d_template_rows() -> list[dict]:
    """Return the two authoritative anchors for offline 800D scheduling.

    Two anchors make the existing verified-period extension path reusable
    without weakening its two-sample requirement for recorded families.
    """
    rows: list[dict] = []
    for index, slot in enumerate(BUILTIN_800D_ANCHOR_SLOTS, 1):
        raw, _ = rebuild_player_supplement_leaf(
            BUILTIN_800D_SEED,
            target_slot=slot,
            unix_now=0.0,
            recorded_at=None,
        )
        rows.append(
            {
                "raw": raw,
                "message_id": 0x800D,
                "report_index": index,
                "recorded_elapsed_seconds": max(0, slot - INITIAL_LOGICAL_SLOT)
                * WALL_SECONDS_PER_LOGICAL_SLOT,
                "recorded_at": None,
                "template_scope": "player",
                "template_session_id": BUILTIN_800D_SESSION_ID,
                "donor_game_id": "",
                "device_context": {},
                "pool_idx": -len(BUILTIN_800D_ANCHOR_SLOTS) + index,
                "builtin_fallback": True,
                "builtin_seed_revision": BUILTIN_800D_SEED_REVISION,
            }
        )
    return rows


def _extend_verified_periodic_player_rows(
    rows: Iterable[dict],
    *,
    logical_now: float,
) -> tuple[list[dict], dict[int, list[int]]]:
    """Append verified 8007/800D/802C (600), 800F (900) and template 800A cycles.

    800A uses evaluate_800a_period: sparse 900 last-two samples, or 30-slot
    clusters with three starts.  Short recordings stay on the recorded timeline.
    """
    output = [dict(row) for row in rows]
    conservative = rebuild_controls_v3_mode()
    by_message: dict[int, list[dict]] = defaultdict(list)
    for row in output:
        message_id = int(row.get("message_id") or 0)
        if (
            message_id not in PLAYER_PERIODIC_EXTENSION_PERIODS
            and message_id != PLAYER_800A_MESSAGE_ID
        ):
            continue
        raw = bytes(row.get("raw") or b"")
        if len(raw) < 0x1E:
            continue
        by_message[message_id].append(row)

    extended_slots: dict[int, list[int]] = {}
    max_slot = min(0xFFFF, int(float(logical_now) + SLOT_DUE_TOLERANCE))

    def _rows_by_slot(candidates: list[dict]) -> dict[int, dict]:
        by_slot: dict[int, dict] = {}
        for row in candidates:
            raw = bytes(row["raw"])
            slot = int.from_bytes(raw[0x1C:0x1E], "big")
            previous = by_slot.get(slot)
            if previous is None or int(row.get("pool_idx") or 0) >= int(
                previous.get("pool_idx") or 0
            ):
                by_slot[slot] = row
        return by_slot

    def _clone_slot_row(
        source_row: dict,
        *,
        target_slot: int,
        cycle_index: int,
        period: int,
    ) -> dict:
        source_raw = bytes(source_row["raw"])
        raw = bytearray(source_raw)
        raw[0x1C:0x1E] = int(target_slot).to_bytes(2, "big")
        clone = dict(source_row)
        clone["raw"] = bytes(raw)
        clone["message_id"] = int(source_row.get("message_id") or 0)
        clone["report_index"] = int(source_row.get("report_index") or 0) + cycle_index
        if source_row.get("recorded_elapsed_seconds") is not None:
            clone["recorded_elapsed_seconds"] = float(
                source_row["recorded_elapsed_seconds"]
            ) + cycle_index * period * WALL_SECONDS_PER_LOGICAL_SLOT
        clone["periodic_extension"] = True
        clone["periodic_source_slot"] = int.from_bytes(source_raw[0x1C:0x1E], "big")
        clone["periodic_target_slot"] = target_slot
        return clone

    for message_id, candidates in by_message.items():
        if conservative and message_id not in {0x800D, 0x802C}:
            continue
        if conservative and message_id == 0x802C and not all(
            row.get("recorded_at") is not None for row in candidates
        ):
            continue
        if message_id == PLAYER_800A_MESSAGE_ID:
            continue
        period = int(PLAYER_PERIODIC_EXTENSION_PERIODS[message_id])
        by_slot = _rows_by_slot(candidates)
        observed_slots = sorted(by_slot)
        if len(observed_slots) < PLAYER_PERIODIC_MIN_SAMPLES:
            continue
        if observed_slots[-1] - observed_slots[-2] != period:
            continue
        source_slot = observed_slots[-1]
        target_slot = source_slot + period
        cycle_index = 1
        while target_slot <= max_slot:
            clone = _clone_slot_row(
                by_slot[source_slot],
                target_slot=target_slot,
                cycle_index=cycle_index,
                period=period,
            )
            output.append(clone)
            extended_slots.setdefault(message_id, []).append(target_slot)
            target_slot += period
            cycle_index += 1

    a_candidates = by_message.get(PLAYER_800A_MESSAGE_ID) or []
    if a_candidates:
        by_slot = _rows_by_slot(a_candidates)
        observed_slots = sorted(by_slot)
        judged = evaluate_800a_period(observed_slots)
        period = judged.get("period")
        if judged.get("ready") and period:
            if judged.get("morphology") == "cluster_30":
                last_cluster = cluster_800a_slots(observed_slots)[-1]
                cycle_index = 1
                while True:
                    added = False
                    for source_slot in last_cluster:
                        target_slot = int(source_slot) + cycle_index * int(period)
                        if target_slot > max_slot:
                            continue
                        output.append(
                            _clone_slot_row(
                                by_slot[source_slot],
                                target_slot=target_slot,
                                cycle_index=cycle_index,
                                period=int(period),
                            )
                        )
                        extended_slots.setdefault(
                            PLAYER_800A_MESSAGE_ID, []
                        ).append(target_slot)
                        added = True
                    if not added:
                        break
                    cycle_index += 1
            else:
                source_slot = observed_slots[-1]
                target_slot = source_slot + int(period)
                cycle_index = 1
                while target_slot <= max_slot:
                    output.append(
                        _clone_slot_row(
                            by_slot[source_slot],
                            target_slot=target_slot,
                            cycle_index=cycle_index,
                            period=int(period),
                        )
                    )
                    extended_slots.setdefault(
                        PLAYER_800A_MESSAGE_ID, []
                    ).append(target_slot)
                    target_slot += int(period)
                    cycle_index += 1
    return output, extended_slots


def _scan_leaf_u20(raw: bytes | bytearray) -> int | None:
    data = bytes(raw or b"")
    if len(data) < 0x24:
        return None
    return int.from_bytes(data[0x20:0x24], "big")


def _cluster_scan_template_waves(rows: list[dict]) -> list[list[dict]]:
    ordered = sorted(rows, key=event_recorded_elapsed_seconds)
    waves: list[list[dict]] = []
    current: list[dict] = []
    for row in ordered:
        elapsed = event_recorded_elapsed_seconds(row)
        if (
            current
            and elapsed - event_recorded_elapsed_seconds(current[-1])
            > PLAYER_SCAN_WAVE_GAP_SECONDS
        ):
            waves.append(current)
            current = [row]
        else:
            current.append(row)
    if current:
        waves.append(current)
    return waves


def _wave_u20_values(wave: list[dict]) -> list[int]:
    values = []
    for row in wave:
        u20 = _scan_leaf_u20(bytes(row.get("raw") or b""))
        if u20 is not None:
            values.append(u20)
    return values


def _is_valid_8027_start_wave(wave: list[dict]) -> bool:
    if not wave:
        return False
    first_u20 = _scan_leaf_u20(bytes(wave[0].get("raw") or b""))
    values = _wave_u20_values(wave)
    return (
        first_u20 is not None
        and values
        and first_u20 >= PLAYER_SCAN_WAVE_START_MIN_U20
        and first_u20 == max(values)
    )


def _is_complete_8027_wave(wave: list[dict]) -> bool:
    """Short-wave completeness: valid open and tail +0x20=59."""
    if not _is_valid_8027_start_wave(wave):
        return False
    last_u20 = _scan_leaf_u20(bytes(wave[-1].get("raw") or b""))
    return last_u20 == PLAYER_SCAN_WAVE_TAIL_U20


def _is_decreasing_8027_wave(wave: list[dict]) -> bool:
    """Long-wave shape: valid open and every adjacent +0x20 strictly decreases."""
    if not _is_valid_8027_start_wave(wave) or len(wave) < 2:
        return False
    values = _wave_u20_values(wave)
    if len(values) != len(wave):
        return False
    return all(later < earlier for earlier, later in zip(values, values[1:]))


def evaluate_scan_wave_template(rows: Iterable[dict]) -> dict:
    """Judge whether recorded 8027/8029 can repeat the first complete wave.

    Short waves stay on F5: tail +0x20=59 is sufficient for W1.  Long waves
    close when every adjacent +0x20 decreases and a later valid open appears
    more than 180s later.  Isolated +0x20=59 cannot start a wave.  Slot values
    are frozen and must not be used as the period.
    """
    by_id: dict[int, list[dict]] = defaultdict(list)
    for row in rows:
        message_id = int(row.get("message_id") or 0)
        if message_id in PLAYER_SCAN_WAVE_MESSAGE_IDS:
            by_id[message_id].append(row)
    info = {
        "ready": False,
        "has_complete_wave1": False,
        "has_wave2_open": False,
        "has_wave1_8029": False,
        "scan_wave_period_seconds": None,
        "scan_wave_origin_elapsed": None,
        "status": "waiting_wave1",
        "wave1_8027": [],
        "wave1_8029": [],
        "wave1_shape": None,
    }
    waves_8027 = _cluster_scan_template_waves(by_id.get(0x8027) or [])
    wave1 = None
    wave2 = None
    wave1_shape = None
    pending_long = None
    for index, wave in enumerate(waves_8027):
        short = _is_complete_8027_wave(wave)
        long_shape = _is_decreasing_8027_wave(wave)
        if not short and not long_shape:
            continue
        nxt = next(
            (
                later
                for later in waves_8027[index + 1 :]
                if _is_valid_8027_start_wave(later)
            ),
            None,
        )
        if short:
            wave1 = wave
            wave2 = nxt
            wave1_shape = "short_tail_59"
            break
        if long_shape and nxt is not None:
            wave1 = wave
            wave2 = nxt
            wave1_shape = "long_gap"
            break
        if long_shape and pending_long is None:
            pending_long = wave
    if wave1 is None:
        if pending_long is not None:
            info["wave1_8027"] = list(pending_long)
            info["wave1_shape"] = "long_gap"
            info["status"] = "waiting_wave2"
        return info
    info["wave1_8027"] = list(wave1)
    info["wave1_shape"] = wave1_shape
    if wave1_shape == "short_tail_59":
        info["has_complete_wave1"] = True
        info["status"] = "waiting_wave2"
        if wave2 is None:
            return info
    else:
        if wave2 is None:
            return info
        info["has_complete_wave1"] = True
        info["status"] = "waiting_wave2"
    info["has_wave2_open"] = True
    origin = event_recorded_elapsed_seconds(wave1[0])
    period = event_recorded_elapsed_seconds(wave2[0]) - origin
    if period <= PLAYER_SCAN_WAVE_GAP_SECONDS:
        info["status"] = "period_too_short"
        return info
    wave1_end = event_recorded_elapsed_seconds(wave1[-1])
    wave1_8029: list[dict] = []
    for wave in _cluster_scan_template_waves(by_id.get(0x8029) or []):
        start = event_recorded_elapsed_seconds(wave[0])
        end = event_recorded_elapsed_seconds(wave[-1])
        if end < origin - 30.0 or start > wave1_end + 80.0:
            continue
        wave1_8029 = wave
        break
    if not wave1_8029:
        info["status"] = "waiting_8029"
        return info
    info["has_wave1_8029"] = True
    info["ready"] = True
    info["status"] = "ready"
    info["scan_wave_period_seconds"] = period
    info["scan_wave_origin_elapsed"] = origin
    info["wave1_8029"] = list(wave1_8029)
    return info


def _expand_scan_wave_rows(
    rows: Iterable[dict],
    *,
    elapsed_seconds: float,
) -> tuple[list[dict], dict]:
    """Replay complete 8027/8029 wave 1 on the template's own period.

    Short wave 1 finishes at +0x20=59.  Long wave 1 requires every adjacent
    +0x20 to decrease, then a later valid 8027 start more than 180s later.  Wave 2 only
    needs its opening 8027 (max +0x20, >=150).  T is that opening elapsed
    minus wave-1 opening.  Recorded remnants after wave 1 are dropped so
    they cannot overlay the synthetic copies.  Mode off skips 8027/8029.
    Incomplete wave 1 or missing wave-2 start keep the recorded timeline.
    """
    output = [dict(row) for row in rows]
    info = {
        "rebuild_scan_waves": rebuild_scan_wave_mode(),
        "scan_wave_period_seconds": None,
        "scan_wave_origin_elapsed": None,
        "scan_wave_copy_count": 0,
    }
    if info["rebuild_scan_waves"] != "repeat_first":
        return output, info

    scan = evaluate_scan_wave_template(output)
    info["scan_wave_period_seconds"] = scan.get("scan_wave_period_seconds")
    info["scan_wave_origin_elapsed"] = scan.get("scan_wave_origin_elapsed")
    if not scan.get("ready"):
        return output, info

    others = [
        row
        for row in output
        if int(row.get("message_id") or 0) not in PLAYER_SCAN_WAVE_MESSAGE_IDS
    ]
    template_rows = list(scan.get("wave1_8027") or []) + list(
        scan.get("wave1_8029") or []
    )
    period = float(scan["scan_wave_period_seconds"])
    scheduled = list(others) + [dict(row) for row in template_rows]
    due_horizon = float(elapsed_seconds) + SLOT_DUE_TOLERANCE
    max_shift = due_horizon - min(
        event_recorded_elapsed_seconds(row) for row in template_rows
    )
    copy_count = max(0, int(max_shift // period))
    for copy_index in range(1, copy_count + 1):
        for source_row in template_rows:
            clone = dict(source_row)
            source_elapsed = event_recorded_elapsed_seconds(source_row)
            clone["recorded_elapsed_seconds"] = source_elapsed + copy_index * period
            clone["report_index"] = int(source_row.get("report_index") or 0) + copy_index
            clone["scan_wave_extension"] = True
            clone["scan_wave_copy"] = copy_index
            clone["pool_idx"] = (
                1_000_000
                + copy_index * 10_000
                + int(source_row.get("pool_idx") or 0)
            )
            scheduled.append(clone)
        info["scan_wave_copy_count"] = copy_index
    return scheduled, info


def _strict_device_gate(
    live_context: dict | None,
    recorded_context: dict | None,
) -> tuple[str, list[str]]:
    """Player-layer device gate. IDFV is the physical-device key.

    ``ver:16.30`` and ``iDevSysVer:16.3.1`` are two encodings of the same OS
    on one phone. Model and version only describe a device class; they must
    not override a matching IDFV, and they must not decide MATCH while IDFV
    is still missing.
    """
    live = dict(live_context or {})
    recorded = dict(recorded_context or {})
    live_idfv = str(live.get("device_idfv") or "").strip()
    recorded_idfv = str(recorded.get("device_idfv") or "").strip()
    if not live_idfv or not recorded_idfv:
        missing = []
        if not live_idfv:
            missing.append("live.device_idfv")
        if not recorded_idfv:
            missing.append("recorded.device_idfv")
        return "PENDING_CONTEXT", missing
    if live_idfv != recorded_idfv:
        return "DEVICE_MISMATCH", ["device_idfv"]
    return "MATCH", []


def strict_device_gate(
    live_context: dict | None,
    recorded_context: dict | None,
) -> tuple[str, list[str]]:
    """Public v1.128.9 wrapper used by cross-account device-pool selection."""
    return _strict_device_gate(live_context, recorded_context)


def plan_same_device_player_groups(
    state: dict,
    *,
    template_rows: Iterable[dict],
    elapsed_seconds: float,
    unix_now: float,
    live_leaves: Iterable[dict | bytes | bytearray],
    live_device_context: dict | None,
    live_game_id: str,
    allow_cross_account_device: bool = False,
) -> tuple[list[dict], dict]:
    """Plan recorded-only 80xx leaves for an exact account/device recording.

    Slot-based rows use their protocol logical slot.  Event/scan rows use the
    recording's session-relative wall-clock time, with report-index timing only
    as a legacy fallback.  802A/802B follow rebuild_match_events: off skips
    them; random emits the recorded pair on a 10-20 minute jitter clock.
    8027/8029 follow rebuild_scan_waves: repeat_first clones complete wave 1
    by the template's own opening-to-opening period; off emits neither.
    Exact Live semantic keys own the current occurrence and suppress only the
    matching player row.
    """
    state = ensure_v128_state(state)
    live_leaves = list(live_leaves)
    player_state = state.setdefault("same_device_player", {})
    player_state.setdefault("selected_session_id", "")
    player_state.setdefault("consumed", [])
    player_state.setdefault("suppressed_by_live", [])
    player_state.setdefault("emitted_identities", [])
    player_state.setdefault("injected_leaf_count", 0)
    player_state.setdefault("gameplay_gate_open", False)
    player_state.setdefault("gameplay_trigger_ids", [])
    player_state.setdefault("gameplay_trigger_elapsed_seconds", None)
    player_state.setdefault("match_event_next_elapsed", None)
    player_state.setdefault("match_event_count", 0)
    player_state.setdefault("802c_link_counter", None)
    info = {
        "enabled": True,
        "gate": "NO_PLAYER_RECORDING",
        "gate_fields": [],
        "selected_session_id": "",
        "recorded_device_context": {},
        "cross_account_device": False,
        "cross_account_blocked_message_ids": [],
        "donor_game_id": "",
        "eligible_message_ids": [],
        "static_ready_message_ids": ["0x800F", "0x8023"],
        "dynamic_ready_message_ids": [
            f"0x{value:04X}"
            for value in sorted(PLAYER_DYNAMIC_READY_MESSAGE_IDS)
        ],
        "dynamic_pending_message_ids": [
            f"0x{value:04X}"
            for value in sorted(PLAYER_DYNAMIC_PENDING_MESSAGE_IDS)
        ],
        "due_message_ids": [],
        "suppressed_by_live": [],
        "recorded_missing_message_ids": [
            f"0x{value:04X}"
            for value in sorted(PLAYER_SUPPLEMENT_MESSAGE_IDS)
        ],
        "recorded_dynamic_pending_message_ids": [],
        "recorded_dynamic_ready_message_ids": [],
        "builtin_800d_fallback": False,
        "builtin_800d_seed_revision": BUILTIN_800D_SEED_REVISION,
        "800d_source": "none",
        "live_secondary_fallback_message_ids": [],
        "rebuilt_fields": [],
        "clock_metadata_status": "OK",
        "clock_metadata_missing_message_ids": [],
        "periodic_extension_periods": {
            f"0x{message_id:04X}": period
            for message_id, period in sorted(
                PLAYER_PERIODIC_EXTENSION_PERIODS.items()
            )
        },
        "periodic_extension_eligible_message_ids": [],
        "periodic_extension_due_message_ids": [],
        "periodic_extension_slots": {},
        "secondary_fallback_scope": "ALL_PLAYER_SUPPLEMENT_IDS",
        "secondary_fallback_message_ids": [
            f"0x{value:04X}"
            for value in sorted(PLAYER_SUPPLEMENT_MESSAGE_IDS)
        ],
        "secondary_fallback_policy": (
            "PLAYER_MISSING_OR_PENDING_AND_LIVE_PRESENT_DEFER_HOT_RULE;"
            "HOT_RULE_MISS_PASS_LIVE;LIVE_ABSENT_NO_OUTPUT"
        ),
        "gameplay_gate": "PENDING",
        "gameplay_trigger_ids": [],
        "gameplay_trigger_elapsed_seconds": None,
        "rebuild_player_base": rebuild_player_base_mode(),
        "rebuild_match_events": rebuild_match_event_mode(),
        "match_event_next_elapsed": None,
        "match_event_count": 0,
        "rebuild_scan_waves": rebuild_scan_wave_mode(),
        "scan_wave_period_seconds": None,
        "scan_wave_origin_elapsed": None,
        "scan_wave_copy_count": 0,
    }
    live_ids: set[int] = set()
    for source in live_leaves:
        raw = source.get("raw") if isinstance(source, dict) else source
        data = bytes(raw or b"")
        if len(data) >= 0x18 and int.from_bytes(data[6:10], "big") == 0x0102000A:
            live_ids.add(int.from_bytes(data[0x16:0x18], "big"))
    info["live_secondary_fallback_message_ids"] = [
        f"0x{value:04X}"
        for value in sorted(live_ids & PLAYER_SUPPLEMENT_MESSAGE_IDS)
    ]
    gameplay_trigger_ids = sorted(
        live_ids & PLAYER_GAMEPLAY_TRIGGER_MESSAGE_IDS
    )
    if live_ids & PLAYER_GAMEPLAY_GATED_MESSAGE_IDS:
        gameplay_trigger_ids.extend(
            sorted(live_ids & PLAYER_GAMEPLAY_GATED_MESSAGE_IDS)
        )
    if gameplay_trigger_ids:
        player_state["gameplay_gate_open"] = True
        existing_triggers = {
            int(value) for value in player_state.get("gameplay_trigger_ids") or []
        }
        existing_triggers.update(gameplay_trigger_ids)
        player_state["gameplay_trigger_ids"] = sorted(existing_triggers)
        if player_state.get("gameplay_trigger_elapsed_seconds") is None:
            player_state["gameplay_trigger_elapsed_seconds"] = float(
                elapsed_seconds
            )
    info["gameplay_gate"] = (
        "OPEN" if player_state.get("gameplay_gate_open") else "PENDING"
    )
    info["gameplay_trigger_ids"] = [
        f"0x{int(value):04X}"
        for value in player_state.get("gameplay_trigger_ids") or []
    ]
    info["gameplay_trigger_elapsed_seconds"] = player_state.get(
        "gameplay_trigger_elapsed_seconds"
    )

    # A live 802C anchors the linked +0x24/+0x28 counter for this runtime.
    # Rebuilt rows then advance that counter by four per emitted observation.
    for source in live_leaves:
        raw = source.get("raw") if isinstance(source, dict) else source
        data = bytes(raw or b"")
        if (
            len(data) >= 0x2C
            and int.from_bytes(data[6:10], "big") == 0x0102000A
            and int.from_bytes(data[0x16:0x18], "big") == 0x802C
        ):
            player_state["802c_link_counter"] = int.from_bytes(
                data[0x28:0x2C], "big"
            )

    account = str(live_game_id or "").strip()
    allow_800d_any_donor = rebuild_player_message_enabled(0x800D)
    by_session: dict[str, list[dict]] = defaultdict(list)
    for source in template_rows:
        row = dict(source or {})
        if str(row.get("template_scope") or "player") != "player":
            continue
        donor = str(row.get("donor_game_id") or "").strip()
        if not account:
            continue
        raw = sanitize_player_supplement_leaf(row.get("raw") or b"")
        if not raw or row.get("report_index") is None:
            continue
        message_id = int.from_bytes(raw[0x16:0x18], "big")
        account_ok = donor == account or (
            allow_cross_account_device
            and bool(row.get("device_cross_account_candidate"))
        )
        # 800D 与账号无关：勾选后任意 donor 的 800D 叶也可进入调度。
        if not account_ok and not (
            allow_800d_any_donor and message_id == 0x800D
        ):
            continue
        row["raw"] = raw
        row["message_id"] = message_id
        session_id = str(row.get("template_session_id") or "legacy")
        by_session[session_id].append(row)

    recorded_800d_present = any(
        int(row.get("message_id") or 0) == 0x800D
        for rows in by_session.values()
        for row in rows
    )
    # v1.131 fallback is tied to the explicit 800D checkbox.  Legacy
    # full-rebuild mode keeps its historical recording-only semantics.
    builtin_800d_enabled = rebuild_controls_v3_mode() and allow_800d_any_donor
    builtin_800d_rows = (
        builtin_800d_template_rows()
        if builtin_800d_enabled and not recorded_800d_present
        else []
    )
    if builtin_800d_rows:
        by_session[BUILTIN_800D_SESSION_ID].extend(builtin_800d_rows)
        info["builtin_800d_fallback"] = True
    if not by_session:
        return [], info

    compatible: list[tuple[tuple[int, int, int], str, list[dict], dict]] = []
    account_fallback: list[tuple[tuple[int, int, int], str, list[dict], dict]] = []
    pending_fields: set[str] = set()
    mismatch_fields: set[str] = set()
    for session_id, rows in by_session.items():
        recorded_context: dict = {}
        for row in rows:
            recorded_context.update(dict(row.get("device_context") or {}))
        score = (
            max(int(row.get("pool_idx") or 0) for row in rows),
            len({int(row["message_id"]) for row in rows}),
            len(rows),
        )
        # 同账号会话先收下，供 800D 等跨设备计数回退；同设备 MATCH 另入主列表。
        account_fallback.append((score, session_id, rows, recorded_context))
        gate, fields = _strict_device_gate(live_device_context, recorded_context)
        if gate == "MATCH":
            compatible.append((score, session_id, rows, recorded_context))
        elif gate == "PENDING_CONTEXT":
            pending_fields.update(fields)
        else:
            mismatch_fields.update(fields)

    pinned = str(player_state.get("selected_session_id") or "")
    selected = next((row for row in compatible if row[1] == pinned), None)
    if selected is None and compatible:
        selected = max(compatible, key=lambda row: row[0])
    cross_device_counter_only = False
    builtin_800d_only = False
    if selected is None:
        live_idfv = str((live_device_context or {}).get("device_idfv") or "").strip()
        allow_cross_device_counter = any(
            rebuild_player_message_enabled(message_id)
            for message_id in PLAYER_CROSS_DEVICE_ALLOWED_MESSAGE_IDS
        )
        counter_fallbacks = [
            candidate
            for candidate in account_fallback
            if any(int(row.get("message_id") or 0) == 0x800D for row in candidate[2])
            and candidate[1] != BUILTIN_800D_SESSION_ID
        ]
        if not rebuild_controls_v3_mode():
            # Preserve the legacy gate label even when the selected recording
            # has no 800D leaf; legacy mode still emits no synthetic fallback.
            counter_fallbacks = list(account_fallback)
        if not live_idfv and not builtin_800d_rows:
            info["gate"] = "PENDING_CONTEXT"
            info["gate_fields"] = sorted(pending_fields or ["live.device_idfv"])
            return [], info
        if allow_cross_device_counter and counter_fallbacks and live_idfv:
            selected = next(
                (row for row in counter_fallbacks if row[1] == pinned),
                None,
            )
            if selected is None:
                selected = max(counter_fallbacks, key=lambda row: row[0])
            cross_device_counter_only = True
        elif builtin_800d_rows:
            selected = next(
                row
                for row in account_fallback
                if row[1] == BUILTIN_800D_SESSION_ID
            )
            cross_device_counter_only = True
            builtin_800d_only = True
        else:
            if pending_fields:
                info["gate"] = "PENDING_CONTEXT"
                info["gate_fields"] = sorted(pending_fields)
            else:
                info["gate"] = "DEVICE_MISMATCH"
                info["gate_fields"] = sorted(mismatch_fields)
            return [], info

    # A compatible player session owns all device-sensitive families.  800D
    # is account/device independent, so source it separately when that
    # selected session lacks the family: another recorded donor first, then
    # the built-in seed as the final offline fallback.
    selected_score, session_id, selected_rows, recorded_context = selected
    selected_rows = list(selected_rows)
    selected_has_800d = any(
        int(row.get("message_id") or 0) == 0x800D for row in selected_rows
    )
    selected_800d_source = "none"
    if selected_has_800d:
        if session_id == BUILTIN_800D_SESSION_ID:
            selected_800d_source = "builtin"
        elif cross_device_counter_only:
            selected_800d_source = "cross_device_donor"
        else:
            selected_800d_source = "selected_recording"
    elif allow_800d_any_donor:
        donor_candidates = [
            candidate
            for candidate in account_fallback
            if candidate[1] != BUILTIN_800D_SESSION_ID
            and any(int(row.get("message_id") or 0) == 0x800D for row in candidate[2])
        ]
        if donor_candidates:
            def _800d_donor_rank(candidate):
                score, _, candidate_rows, candidate_context = candidate
                device_gate, _ = _strict_device_gate(
                    live_device_context, candidate_context
                )
                same_account = any(
                    str(row.get("donor_game_id") or "").strip() == account
                    for row in candidate_rows
                    if int(row.get("message_id") or 0) == 0x800D
                )
                return (device_gate == "MATCH", same_account, score)

            donor = max(donor_candidates, key=_800d_donor_rank)
            selected_rows.extend(
                row
                for row in donor[2]
                if int(row.get("message_id") or 0) == 0x800D
            )
            donor_gate, _ = _strict_device_gate(live_device_context, donor[3])
            selected_800d_source = (
                "same_device_donor"
                if donor_gate == "MATCH"
                else "cross_device_donor"
            )
        elif builtin_800d_rows:
            selected_rows.extend(builtin_800d_rows)
            selected_800d_source = "builtin"
    selected = (selected_score, session_id, selected_rows, recorded_context)

    _, session_id, rows, recorded_context = selected
    selected_donor = str(rows[0].get("donor_game_id") or "") if rows else ""
    player_state["selected_session_id"] = session_id
    info.update(
        {
            "gate": (
                "BUILTIN_800D"
                if builtin_800d_only
                else "CROSS_DEVICE_800D"
                if cross_device_counter_only
                else "MATCH"
            ),
            "selected_session_id": session_id,
            "recorded_device_context": dict(recorded_context),
            "cross_account_device": bool(
                selected_donor and selected_donor != account
            ),
            "cross_device_counter_only": cross_device_counter_only,
            "donor_game_id": selected_donor,
            "eligible_message_ids": [
                f"0x{value:04X}"
                for value in sorted({int(row["message_id"]) for row in rows})
            ],
            "800d_source": selected_800d_source,
        }
    )
    if cross_device_counter_only:
        info["gate_fields"] = sorted(mismatch_fields or pending_fields)
    cross_account_device = bool(selected_donor and selected_donor != account)
    recorded_ids = {
        int(row["message_id"])
        for row in rows
        if not row.get("builtin_fallback")
    }
    info["recorded_missing_message_ids"] = [
        f"0x{value:04X}"
        for value in sorted(PLAYER_SUPPLEMENT_MESSAGE_IDS - recorded_ids)
    ]
    info["recorded_dynamic_pending_message_ids"] = [
        f"0x{value:04X}"
        for value in sorted(recorded_ids & PLAYER_DYNAMIC_PENDING_MESSAGE_IDS)
    ]
    info["recorded_dynamic_ready_message_ids"] = [
        f"0x{value:04X}"
        for value in sorted(recorded_ids & PLAYER_DYNAMIC_READY_MESSAGE_IDS)
    ]

    consumed = {str(value) for value in player_state.get("consumed") or []}
    suppressed = {
        str(value) for value in player_state.get("suppressed_by_live") or []
    }
    # 8027 按扫描波次去重：同一波近重复只发一次，下一波可再发。
    # 8029 同波不同 elapsed 保留多片；同 elapsed 近重复仍合并。
    # 8027/8029 由 rebuild_scan_waves 决定：off 不发。
    # 802A/802B 由 rebuild_match_events 决定。source_key 仍按 pool_idx
    # 消费，避免同一行反复调度。
    emitted_identities = {
        str(value) for value in player_state.get("emitted_identities") or []
    }
    planned_identities: set[str] = set()
    logical_now = logical_slot_from_elapsed(elapsed_seconds)
    live_identities = {
        identity
        for source in live_leaves
        for identity in [player_leaf_identity(
            source.get("raw") if isinstance(source, dict) else source
        )]
        if identity
    }
    due_buckets: dict[tuple[str, int], list[dict]] = defaultdict(list)
    rebuilt_fields: set[str] = set()
    seen_source_keys: set[str] = set()
    random_match_ids_used: set[int] = set()
    planned_match_ids: set[int] = set()
    match_mode = rebuild_match_event_mode()
    player_base_enabled = rebuild_player_base_mode()
    info["rebuild_player_base"] = player_base_enabled
    info["rebuild_match_events"] = match_mode
    if match_mode == "random":
        ensure_match_event_schedule(player_state)
    info["match_event_next_elapsed"] = player_state.get("match_event_next_elapsed")
    info["match_event_count"] = int(player_state.get("match_event_count") or 0)
    scheduled_rows, extension_slots = _extend_verified_periodic_player_rows(
        rows,
        logical_now=logical_now,
    )
    scheduled_rows, scan_info = _expand_scan_wave_rows(
        scheduled_rows,
        elapsed_seconds=elapsed_seconds,
    )
    info["rebuild_scan_waves"] = scan_info.get("rebuild_scan_waves")
    info["scan_wave_period_seconds"] = scan_info.get("scan_wave_period_seconds")
    info["scan_wave_origin_elapsed"] = scan_info.get("scan_wave_origin_elapsed")
    info["scan_wave_copy_count"] = int(scan_info.get("scan_wave_copy_count") or 0)
    info["periodic_extension_eligible_message_ids"] = [
        f"0x{message_id:04X}" for message_id in sorted(extension_slots)
    ]
    ordered_rows = sorted(
        scheduled_rows,
        key=lambda row: (
            float(row.get("recorded_elapsed_seconds") or 0.0),
            int(row.get("report_index") or 0),
            int(row.get("pool_idx") or 0),
            int(row.get("message_id") or 0),
        ),
    )
    for template_row in ordered_rows:
        message_id = int(template_row["message_id"])
        if (
            cross_device_counter_only
            and message_id not in PLAYER_CROSS_DEVICE_ALLOWED_MESSAGE_IDS
        ):
            continue
        if message_id in PLAYER_INDIVIDUAL_MESSAGE_IDS:
            if not rebuild_player_message_enabled(message_id):
                continue
            if (
                rebuild_controls_v3_mode()
                and
                cross_account_device
                and message_id in PLAYER_CROSS_ACCOUNT_BLOCKED_MESSAGE_IDS
            ):
                blocked = info.setdefault("cross_account_blocked_message_ids", [])
                marker = f"0x{message_id:04X}"
                if marker not in blocked:
                    blocked.append(marker)
                continue
        elif message_id in PLAYER_BASE_MESSAGE_IDS and not player_base_enabled:
            continue
        if message_id in PLAYER_DYNAMIC_PENDING_MESSAGE_IDS:
            continue
        source_raw = bytes(template_row["raw"])
        identity = player_leaf_identity(source_raw)
        if not identity:
            continue
        recorded_elapsed = event_recorded_elapsed_seconds(template_row)
        emit_key = player_event_emit_key(
            source_raw,
            recorded_elapsed_seconds=recorded_elapsed,
        ) or identity
        source_key = (
            f"{session_id}:{identity}:"
            f"{int(template_row.get('pool_idx') or 0)}"
        )
        if source_key in seen_source_keys:
            continue
        seen_source_keys.add(source_key)

        if message_id in PLAYER_SCAN_WAVE_MESSAGE_IDS:
            if info["rebuild_scan_waves"] != "repeat_first":
                continue
        if message_id in PLAYER_EVENT_TIMELINE_MESSAGE_IDS:
            source_report = int(template_row.get("report_index") or 0)
            due_value = float(recorded_elapsed)
            is_due = due_value <= float(elapsed_seconds) + SLOT_DUE_TOLERANCE
            is_stale = float(elapsed_seconds) - due_value > STALE_SLOT_GRACE
            bucket = ("event", source_report)
            slot = int.from_bytes(source_raw[0x1C:0x1E], "big")
            if message_id in PLAYER_GAMEPLAY_GATED_MESSAGE_IDS:
                if match_mode != "random":
                    continue
                if message_id in random_match_ids_used:
                    continue
                random_match_ids_used.add(message_id)
                match_index = int(player_state.get("match_event_count") or 0)
                next_due = float(
                    player_state.get("match_event_next_elapsed") or 0.0
                )
                emit_key = f"{identity}@M{match_index}"
                source_key = f"{session_id}:{identity}:M{match_index}"
                is_due = (
                    float(elapsed_seconds) + SLOT_DUE_TOLERANCE >= next_due
                )
                is_stale = False
                bucket = ("event", match_index)
        else:
            slot = int.from_bytes(source_raw[0x1C:0x1E], "big")
            is_due = slot <= logical_now + SLOT_DUE_TOLERANCE
            is_stale = logical_now - slot > STALE_SLOT_GRACE
            bucket = ("slot", slot)
        slot_key = f"{session_id}:{emit_key}"
        if source_key in consumed or not is_due:
            continue
        consumed.add(source_key)
        if is_stale:
            continue
        if identity in live_identities:
            suppressed.add(source_key)
            info["suppressed_by_live"].append(f"0x{message_id:04X}")
            continue
        if emit_key in emitted_identities or emit_key in planned_identities:
            # 同一扫描波次的近重复录制行：指纹相同但pool_idx不同。
            # 8029 另按 elapsed 分桶，elapsed 不同的同进程仍可发出。
            continue
        planned_identities.add(emit_key)
        previous_802c_counter = None
        if message_id == 0x802C and not (
            rebuild_controls_v3_mode()
            and template_row.get("recorded_at") is None
        ):
            previous_802c_counter = player_state.get("802c_link_counter")
        replay_recorded_at = _replay_recorded_at(
            template_row,
            unix_now=unix_now,
            elapsed_seconds=elapsed_seconds,
        )
        if rebuild_controls_v3_mode() and template_row.get("recorded_at") is None:
            replay_recorded_at = None
        if message_id == 0x802C and replay_recorded_at is None:
            info["clock_metadata_status"] = "CLOCK_METADATA_MISSING"
            info["clock_metadata_missing_message_ids"].append(
                f"0x{message_id:04X}"
            )
        rebuilt, changed_fields = rebuild_player_supplement_leaf(
            source_raw,
            target_slot=slot,
            unix_now=unix_now,
            recorded_at=replay_recorded_at,
            previous_802c_counter=(
                int(previous_802c_counter)
                if previous_802c_counter is not None
                else None
            ),
        )
        if not rebuilt:
            continue
        row_donor = str(template_row.get("donor_game_id") or "")
        if (
            allow_cross_account_device
            and row_donor
            and account
            and row_donor != account
        ):
            donor_bytes = row_donor.encode("ascii", errors="ignore")
            live_bytes = account.encode("ascii", errors="ignore")
            if donor_bytes and donor_bytes in rebuilt:
                if len(donor_bytes) != len(live_bytes):
                    continue
                rebuilt = rebuilt.replace(donor_bytes, live_bytes)
                changed_fields = list(changed_fields) + ["account_identity"]
        rebuilt_fields.update(
            f"0x{message_id:04X}:{value}" for value in changed_fields
        )
        if message_id == 0x802C and len(rebuilt) >= 0x2C:
            player_state["802c_link_counter"] = int.from_bytes(
                rebuilt[0x28:0x2C], "big"
            )
        due_buckets[bucket].append(
            {
                "message_id": message_id,
                "slot": slot,
                "raw": rebuilt,
                "key": slot_key,
                "identity": emit_key,
                "source_key": source_key,
                "layer": "player_same_device",
                "cross_account_device": cross_account_device,
                "template_session_id": session_id,
                "source_report_index": int(template_row["report_index"]),
                "recorded_elapsed_seconds": template_row.get(
                    "recorded_elapsed_seconds"
                ),
                "rebuilt_fields": list(changed_fields),
                "periodic_extension": bool(
                    template_row.get("periodic_extension")
                ),
            }
        )
        if message_id in PLAYER_GAMEPLAY_GATED_MESSAGE_IDS:
            planned_match_ids.add(message_id)

    if match_mode == "random" and planned_match_ids:
        _, low, high = match_event_schedule_bounds()
        player_state["match_event_count"] = int(
            player_state.get("match_event_count") or 0
        ) + 1
        player_state["match_event_next_elapsed"] = (
            float(elapsed_seconds) + random.uniform(low, high)
        )
        info["match_event_count"] = int(player_state["match_event_count"])
        info["match_event_next_elapsed"] = player_state[
            "match_event_next_elapsed"
        ]

    player_state["consumed"] = sorted(consumed)
    player_state["suppressed_by_live"] = sorted(suppressed)
    # planned_identities 只负责本轮规划内去重。emitted_identities 必须等
    # _v128_build_injected_frames 验证并实际注入成功后再提交，避免候选
    # 构建失败时把未发出的身份永久标成已发。
    groups: list[dict] = []
    for bucket in sorted(due_buckets, key=lambda row: (row[1], row[0])):
        rows_at_slot = sorted(
            due_buckets[bucket],
            key=lambda row: (
                int(row.get("source_report_index") or 0),
                int(row["message_id"]),
                str(row.get("identity") or ""),
            ),
        )
        slot = int(rows_at_slot[0]["slot"])
        for start in range(0, len(rows_at_slot), MAX_BATCH_CHILDREN):
            groups.append(
                {
                    "slot": slot,
                    "layer": "player_same_device",
                    "template_session_id": session_id,
                    "rows": rows_at_slot[start:start + MAX_BATCH_CHILDREN],
                }
            )
    info["due_message_ids"] = [
        f"0x{row['message_id']:04X}" for group in groups for row in group["rows"]
    ]
    info["planned_identity_count"] = len(planned_identities)
    info["rebuilt_fields"] = sorted(rebuilt_fields)
    periodic_due_rows = [
        row
        for group in groups
        for row in group["rows"]
        if row.get("periodic_extension")
    ]
    info["periodic_extension_due_message_ids"] = [
        f"0x{int(row['message_id']):04X}" for row in periodic_due_rows
    ]
    info["periodic_extension_slots"] = {
        f"0x{message_id:04X}": slots
        for message_id, slots in sorted(extension_slots.items())
    }
    return groups, info


def _leaf_subtype(message_id: int, raw: bytes) -> str:
    if int(message_id) == 0x8004 and len(raw) >= 0x24:
        return f"{int.from_bytes(raw[0x20:0x24], 'big'):08X}"
    return "single"


def _row_key(message_id: int, slot: int, raw: bytes) -> str:
    return f"{int(message_id):04X}@{int(slot)}#{_leaf_subtype(message_id, raw)}"


def live_leaf_key(raw: bytes | bytearray) -> str | None:
    data = bytes(raw)
    if len(data) < 0x24:
        return None
    if int.from_bytes(data[6:10], "big") != 0x0102000A:
        return None
    message_id = int.from_bytes(data[0x16:0x18], "big")
    if message_id not in BUILTIN_MESSAGE_IDS:
        return None
    slot = int.from_bytes(data[0x1C:0x1E], "big")
    return _row_key(message_id, slot, data)


def strong_profile_live_key(raw: bytes | bytearray) -> str | None:
    data = bytes(raw)
    if not sanitize_strong_profile_leaf(data):
        return None
    message_id = int.from_bytes(data[0x16:0x18], "big")
    slot = int.from_bytes(data[0x1A:0x1E], "big")
    return f"STRONG:{message_id:04X}@{slot}"


def _next_strong_profile_slot(
    message_id: int,
    logical_now: float,
) -> int:
    row = STRONG_PROFILE_MODEL[int(message_id)]
    first_slot = int(row["first_slot"])
    period = int(row["period"])
    if logical_now <= first_slot:
        return first_slot
    cycles = int((float(logical_now) - first_slot + period - 1) // period)
    return first_slot + cycles * period


def note_strong_profile_signals(
    state: dict,
    live_leaves: Iterable[dict | bytes | bytearray],
    *,
    elapsed_seconds: float,
) -> dict:
    """Latch module-file pairs and native strong-profile leaves per session."""
    state = ensure_v128_state(state)
    strong = state.setdefault("strong_profile", {})
    seen_files = {str(value) for value in strong.get("seen_files") or []}
    armed = {int(value) for value in strong.get("armed_message_ids") or []}
    armed_slots = {
        str(key): int(value)
        for key, value in dict(strong.get("armed_slots") or {}).items()
    }
    satisfied = {
        str(value) for value in strong.get("satisfied_keys") or []
    }
    logical_now = logical_slot_from_elapsed(elapsed_seconds)

    for source in live_leaves:
        raw = source.get("raw") if isinstance(source, dict) else source
        data = bytes(raw or b"")
        for file_name in WATCHED_MRPCS_FILE_NAMES:
            if file_name.encode("ascii") in data:
                seen_files.add(file_name)
        key = strong_profile_live_key(data)
        if not key:
            continue
        message_id = int.from_bytes(data[0x16:0x18], "big")
        slot = int.from_bytes(data[0x1A:0x1E], "big")
        satisfied.add(key)
        if message_id not in armed:
            armed.add(message_id)
            armed_slots[f"0x{message_id:04X}"] = slot

    newly_armed = []
    for message_id, required_files in STRONG_PROFILE_FILE_TRIGGERS.items():
        if message_id in armed or not required_files <= seen_files:
            continue
        armed.add(message_id)
        armed_slots[f"0x{message_id:04X}"] = _next_strong_profile_slot(
            message_id, logical_now
        )
        newly_armed.append(message_id)

    unmapped_seen = sorted(seen_files & UNMAPPED_STRONG_PROFILE_FILES)
    strong["seen_files"] = sorted(seen_files)
    strong["unmapped_seen_files"] = unmapped_seen
    strong["armed_message_ids"] = sorted(armed)
    strong["armed_slots"] = dict(sorted(armed_slots.items()))
    strong["satisfied_keys"] = sorted(satisfied)
    strong.setdefault("emitted", [])
    strong.setdefault("skipped_stale", [])
    strong.setdefault("injected_leaf_count", 0)
    return {
        "seen_files": sorted(seen_files),
        "unmapped_seen_files": unmapped_seen,
        "armed_message_ids": [f"0x{value:04X}" for value in sorted(armed)],
        "newly_armed_message_ids": [
            f"0x{value:04X}" for value in sorted(newly_armed)
        ],
        "armed_slots": dict(sorted(armed_slots.items())),
    }


def rebuild_strong_profile_leaf(
    message_id: int,
    *,
    slot: int,
    schedule_start: int,
) -> tuple[bytes, list[str]]:
    row = STRONG_PROFILE_MODEL[int(message_id)]
    period = int(row["period"])
    occurrence = max(0, (int(slot) - int(schedule_start)) // period)
    templates = row["templates"]
    source = templates[min(occurrence, len(templates) - 1)]
    output = bytearray(source)
    # 该字段在8C03/9100样本中均为完整u32逻辑slot。
    output[0x1A:0x1E] = int(slot).to_bytes(4, "big")
    rebuilt_fields = ["logical_slot@0x1A"]
    if int(message_id) == 0x8C03:
        # body+0x06：4、8、12...，每次8C03递增4。
        output[0x24:0x28] = (4 * (occurrence + 1)).to_bytes(4, "big")
        rebuilt_fields.append("round_counter@0x24")
    output[4:6] = len(output).to_bytes(2, "big")
    return bytes(output), rebuilt_fields


def collect_due_strong_profile_groups(
    state: dict,
    *,
    elapsed_seconds: float,
    live_leaves: Iterable[dict | bytes | bytearray] = (),
    trigger_leaves: Iterable[dict | bytes | bytearray] = (),
) -> tuple[list[dict], dict]:
    """Plan conditional 8C03/9100 rows after their module pairs are seen."""
    state = ensure_v128_state(state)
    live_rows = list(live_leaves)
    trigger_rows = list(trigger_leaves)
    signal_info = note_strong_profile_signals(
        state,
        [*trigger_rows, *live_rows],
        elapsed_seconds=elapsed_seconds,
    )
    strong = state["strong_profile"]
    armed = {int(value) for value in strong.get("armed_message_ids") or []}
    armed_slots = {
        str(key): int(value)
        for key, value in dict(strong.get("armed_slots") or {}).items()
    }
    satisfied = {
        str(value) for value in strong.get("satisfied_keys") or []
    }
    emitted = {str(value) for value in strong.get("emitted") or []}
    skipped = {str(value) for value in strong.get("skipped_stale") or []}
    logical_now = logical_slot_from_elapsed(elapsed_seconds)
    by_slot: dict[int, list[dict]] = defaultdict(list)

    for message_id in sorted(armed):
        row = STRONG_PROFILE_MODEL.get(message_id)
        if row is None:
            continue
        start = int(
            armed_slots.get(
                f"0x{message_id:04X}", int(row["first_slot"])
            )
        )
        slot = start
        period = int(row["period"])
        while slot <= logical_now + SLOT_DUE_TOLERANCE:
            key = f"STRONG:{message_id:04X}@{slot}"
            if key not in emitted and key not in skipped and key not in satisfied:
                if logical_now - slot > STALE_SLOT_GRACE:
                    skipped.add(key)
                else:
                    raw, rebuilt_fields = rebuild_strong_profile_leaf(
                        message_id,
                        slot=slot,
                        schedule_start=start,
                    )
                    by_slot[slot].append(
                        {
                            "message_id": message_id,
                            "slot": slot,
                            "raw": raw,
                            "key": key,
                            "rebuilt_fields": rebuilt_fields,
                        }
                    )
                    emitted.add(key)
            slot += period

    strong["satisfied_keys"] = sorted(satisfied)
    strong["emitted"] = sorted(emitted)
    strong["skipped_stale"] = sorted(skipped)
    groups = [
        {
            "slot": slot,
            "layer": "central_strong",
            "rows": sorted(by_slot[slot], key=lambda item: item["message_id"]),
        }
        for slot in sorted(by_slot)
    ]
    signal_info["due_message_ids"] = [
        f"0x{row['message_id']:04X}"
        for group in groups
        for row in group["rows"]
    ]
    signal_info["model_policy"] = (
        "CONDITIONAL_FILE_PAIR;LIVE_SLOT_SUPPRESS;PER_SESSION_LATCH"
    )
    return groups, signal_info


def builtin_template_for_live_leaf(
    raw: bytes | bytearray,
) -> tuple[str, bytes] | None:
    """Return the authoritative built-in row for an expected Live key.

    The built-in body wins; only the native version, recordSequence and the
    already validated schedule slot are retained from the Live carrier.
    """
    data = bytes(raw)
    key = live_leaf_key(data)
    if not key:
        return None
    message_id = int.from_bytes(data[0x16:0x18], "big")
    slot = int.from_bytes(data[0x1C:0x1E], "big")
    row = BUILTIN_MODEL[message_id]
    first_slot = int(row["first_slot"])
    period = row["period"]
    if period is None:
        expected_slot = slot == first_slot
    else:
        expected_slot = slot >= first_slot and (
            (slot - first_slot) % int(period) == 0
        )
    if not expected_slot:
        return None
    live_subtype = _leaf_subtype(message_id, data)
    for source in row["templates"]:
        template = bytes(source)
        if _leaf_subtype(message_id, template) != live_subtype:
            continue
        output = bytearray(template)
        output[0:4] = data[0:4]
        output[10:14] = data[10:14]
        output[0x1C:0x1E] = data[0x1C:0x1E]
        output[4:6] = len(output).to_bytes(2, "big")
        return key, bytes(output)
    return None


def note_live_leaves(
    state: dict,
    live_leaves: Iterable[dict | bytes | bytearray],
) -> set[str]:
    satisfied = {str(value) for value in state.get("satisfied_keys") or []}
    seen_ids = {int(value) for value in state.get("seen_live_ids") or []}
    for item in live_leaves:
        raw = item.get("raw") if isinstance(item, dict) else item
        if not isinstance(raw, (bytes, bytearray)):
            continue
        key = live_leaf_key(raw)
        if not key:
            continue
        satisfied.add(key)
        seen_ids.add(int.from_bytes(bytes(raw)[0x16:0x18], "big"))
    state["satisfied_keys"] = sorted(satisfied)
    state["seen_live_ids"] = sorted(seen_ids)
    return satisfied


def logical_slot_from_elapsed(elapsed_seconds: float) -> float:
    return INITIAL_LOGICAL_SLOT + (
        max(0.0, float(elapsed_seconds)) / WALL_SECONDS_PER_LOGICAL_SLOT
    )


def _slot_key(message_id: int, slot: int, raw: bytes) -> str:
    return _row_key(message_id, slot, raw)


def collect_due_groups(
    state: dict,
    *,
    elapsed_seconds: float,
    live_message_ids: Iterable[int | None] = (),
    live_leaves: Iterable[dict | bytes | bytearray] = (),
) -> list[dict]:
    """Return due per-slot template groups and mark their keys consumed.

    Live satisfies only its exact logical slot and subtype.  A later slot is
    evaluated independently, so intermittent Hook output neither duplicates a
    live leaf nor disables all future replenishment for that family.
    """
    state = ensure_v128_state(state)
    satisfied = note_live_leaves(state, live_leaves)
    generic_live_ids = {
        int(value)
        for value in live_message_ids
        if value is not None and int(value) in BUILTIN_MESSAGE_IDS
    }
    if generic_live_ids:
        seen_ids = {int(value) for value in state.get("seen_live_ids") or []}
        seen_ids.update(generic_live_ids)
        state["seen_live_ids"] = sorted(seen_ids)
    emitted = set(state.get("emitted") or [])
    skipped = set(state.get("skipped_stale") or [])
    logical_now = logical_slot_from_elapsed(elapsed_seconds)
    by_slot: dict[int, list[dict]] = defaultdict(list)

    for message_id, row in BUILTIN_MODEL.items():
        slot = int(row["first_slot"])
        period = row["period"]
        while slot <= logical_now + SLOT_DUE_TOLERANCE:
            for template in row["templates"]:
                raw = bytes(template)
                key = _slot_key(message_id, slot, raw)
                # Backward-compatible callers that only supply IDs suppress
                # the currently due slot, never the whole future family.
                generic_live_hit = (
                    message_id in generic_live_ids
                    and logical_now - slot <= STALE_SLOT_GRACE
                )
                if generic_live_hit:
                    satisfied.add(key)
                if key not in emitted and key not in skipped and key not in satisfied:
                    if logical_now - slot > STALE_SLOT_GRACE:
                        skipped.add(key)
                    else:
                        by_slot[slot].append(
                            {
                                "message_id": message_id,
                                "slot": slot,
                                "raw": raw,
                                "key": key,
                            }
                        )
                        emitted.add(key)
            if period is None:
                break
            slot += int(period)

    state["satisfied_keys"] = sorted(satisfied)
    state["emitted"] = sorted(emitted)
    state["skipped_stale"] = sorted(skipped)
    groups = []
    for slot in sorted(by_slot):
        rows = sorted(by_slot[slot], key=lambda item: item["message_id"])
        for start in range(0, len(rows), MAX_BATCH_CHILDREN):
            groups.append(
                {
                    "slot": slot,
                    "layer": "central9",
                    "rows": rows[start:start + MAX_BATCH_CHILDREN],
                }
            )
    return groups


def model_summary() -> list[dict]:
    central = [
        {
            "message_id": f"0x{message_id:04X}",
            "first_slot": row["first_slot"],
            "period": row["period"],
            "leaf_count": len(row["templates"]),
            "layer": "central9",
        }
        for message_id, row in sorted(BUILTIN_MODEL.items())
    ]
    conditional = [
        {
            "message_id": f"0x{message_id:04X}",
            "first_slot": row["first_slot"],
            "period": row["period"],
            "leaf_count": len(row["templates"]),
            "layer": "central_strong",
            "trigger_files": sorted(
                STRONG_PROFILE_FILE_TRIGGERS[message_id]
            ),
        }
        for message_id, row in sorted(STRONG_PROFILE_MODEL.items())
    ]
    return central + conditional
