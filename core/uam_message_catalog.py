"""UAMProxy 暗区突围 Type9 messageId、录制覆盖率与周期就绪统计。"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Iterable

from core.type9_v128_replenish import (
    PLAYER_800A_MESSAGE_ID,
    PLAYER_PERIODIC_EXTENSION_PERIODS,
    PLAYER_PERIODIC_MIN_SAMPLES,
    PLAYER_PERIODIC_SLOT_FAMILY_IDS,
    PLAYER_SCAN_WAVE_MESSAGE_IDS,
    evaluate_800a_period,
    evaluate_scan_wave_template,
)


CATALOG_REVISION = "uam-v131.2-message-catalog-20260927"

# UAM v1.131.2 独立 01 通道实测 48 种 message_id（见数据/131/分析结果文档）。
UAM_KNOWN_MESSAGE_ID_CATALOG: dict[int, str] = {
    0x8007: "144B 固定正文块（稀疏周期样本）",
    0x8023: "160B 周期计数与状态候选字段",
    0x8030: "44B 单样本短记录",
    0x80CC: "152B 双计数组与状态字",
    0x80CD: "152B 配套双计数组与状态字",
    0x80CF: "两分钟序号与动态正文",
    0x8101: "56B 单样本记录",
    0x8102: "80B 固定正文块",
    0x8103: "60B 动态数值记录",
    0x8104: "88B 固定正文块",
    0x8105: "68B 固定正文块",
    0x8106: "60B 固定正文块",
    0x8107: "48B 固定正文块",
    0x8108: "64B 固定正文块",
    0x8109: "180B 固定正文块",
    0x810A: "80B 双正文变体",
    0x810B: "周期计数组与秒级递增字段",
    0x810C: "112B 固定正文块",
    0x810D: "84B 固定正文块",
    0x810E: "模 8 槽位及动态数值",
    0x810F: "112B 全零正文块",
    0x8110: "114B 固定正文块",
    0x8111: "44B 固定正文块",
    0x8113: "56B 固定正文块",
    0x8210: "44B 单样本短记录",
    0x8217: "周期计数与变长正文",
    0x8306: "44B 固定正文短记录",
    0x8307: "184B 突发记录组",
    0x8309: "170B 突发固定正文组",
    0x8400: "48B 周期固定正文块",
    0x8401: "55B 周期固定正文块",
    0x8403: "40B 周期固定正文块",
    0x8404: "44B 四正文变体组",
    0x8405: "60B 周期固定正文块",
    0x8409: "56B 周期固定正文块",
    0x840C: "164B 周期固定正文块",
    0x840D: "44B 周期固定正文块",
    0x840E: "52B 启动阶段动态记录",
    0x840F: "52B 双正文变体",
    0x8410: "52B 周期固定正文块",
    0x8411: "48B 单样本记录",
    0x8417: "64B 周期固定正文块",
    0x8418: "变长成组记录",
    0xFFF2: "89B/161B 两种正文记录",
    0xFFF3: "202B 键值计数汇总（24 项）",
    0xFFF9: "42B 五正文变体组",
    0xFFFB: "80B 周期计数记录",
    0xFFFE: "周期变长记录及 37B 短事件混合",
}

UAM_KNOWN_MESSAGE_IDS = frozenset(UAM_KNOWN_MESSAGE_ID_CATALOG)

# 录制详情「样本目录」覆盖范围 = 上述 48 类（不再使用旧 80xx 核心 21 类集合）。
UAM_REPLAY_80XX_MESSAGE_IDS = UAM_KNOWN_MESSAGE_IDS

UAM_8004_EXPECTED_SUBTYPES = frozenset()

PLAYER_SCAN_WAVE_PERIODIC_IDS = ()

_80XX_RANGE_START = 0x8000
_80XX_RANGE_END = 0x8FFF

# v1.131.2 样本中间隔中位数观察（秒）；无条目则走录制统计或「见备注」。
UAM_SAMPLE_PERIOD_STATUS: dict[int, str] = {
    0x8007: "约 959 s（稀疏，待复核）",
    0x8023: "约 120 秒（UAM 样本）",
    0x8030: "单次观测",
    0x80CC: "约 120 秒（样本）",
    0x80CD: "约 120 秒（样本）",
    0x80CF: "约 120 秒（样本）",
    0x8102: "约 30 秒（样本）",
    0x8103: "约 30 秒（样本）",
    0x8104: "约 30 秒（样本）",
    0x8105: "约 30 秒（样本）",
    0x8106: "约 30 秒（样本）",
    0x8107: "约 150 秒（样本）",
    0x8108: "约 600 秒（样本）",
    0x8109: "约 30 秒（样本）",
    0x810A: "约 90 秒（样本）",
    0x810B: "约 30 秒（样本）",
    0x810C: "约 240 秒（样本）",
    0x810D: "约 180 秒（样本）",
    0x810E: "约 30 秒（样本）",
    0x810F: "约 120 秒（样本）",
    0x8110: "约 60 秒（样本）",
    0x8111: "约 180 秒（样本）",
    0x8113: "约 90 秒（样本）",
    0x8217: "约 30 秒（样本）",
    0x8306: "间隔不固定",
    0x8307: "突发分组",
    0x8309: "突发分组",
    0x8400: "约 605 秒（样本）",
    0x8404: "约 303 秒（成组）",
    0xFFF3: "约 90 秒（样本）",
    0xFFF9: "约 180 秒（成组）",
    0xFFFB: "约 60 秒（样本）",
    0xFFFE: "约 60 秒（混合）",
}


def is_80xx_message_id(message_id: int) -> bool:
    value = int(message_id)
    return _80XX_RANGE_START <= value <= _80XX_RANGE_END


UAM_KNOWN_80XX_MESSAGE_IDS = frozenset(
    message_id
    for message_id in UAM_KNOWN_MESSAGE_IDS
    if is_80xx_message_id(message_id)
)


def format_match_event_period_status(mode: str | None) -> str:
    if str(mode or "off").strip().lower() == "random":
        return "跟随配置 · 随机10～20分钟"
    return "跟随配置 · 不重建"


def format_8004_period_status(coverage: dict | None = None) -> str:
    payload = coverage or {}
    seen = int(payload.get("subtype_8004_seen_count") or 0)
    total = int(
        payload.get("subtype_8004_total") or len(UAM_8004_EXPECTED_SUBTYPES)
    )
    return f"子型 {seen}/{total} · 默认 300-slot"


def _format_periodic_row_status(message_id: int, periodic: dict) -> str:
    if str(periodic.get("kind") or "") == "scan_wave":
        status = str(periodic.get("status") or "waiting_wave1")
        period_s = periodic.get("period_seconds")
        if periodic.get("ready"):
            return (
                f"✓ 扫描波 {float(period_s):.0f}s"
                if period_s
                else "✓ 扫描波"
            )
        if status == "waiting_wave2":
            return "等待第二波开扫"
        if status == "waiting_8029":
            return "等待配套8029"
        if status == "period_too_short":
            return "间隔过短"
        return "等待完整第一波"
    if periodic.get("ready"):
        period = int(periodic.get("period") or 0)
        if (
            int(message_id) == 0x800A
            and str(periodic.get("morphology") or "") == "cluster_30"
        ):
            return f"✓ 簇 {period}-slot"
        return f"✓ {period}-slot"
    if (
        int(message_id) == 0x800A
        and str(periodic.get("status") or "")
        and str(periodic.get("status") or "") != "ready"
    ):
        return str(periodic.get("status"))
    if int(periodic.get("sample_count") or 0) < 2:
        return (
            f"等待第2次 ({int(periodic.get('sample_count') or 0)}/2)"
        )
    return (
        f"间隔{periodic.get('last_interval')}/"
        f"{int(periodic.get('period') or 0)}"
    )


def format_recording_period_status(
    message_id: int,
    *,
    coverage: dict | None = None,
    match_event_mode: str | None = None,
    periodic: dict | None = None,
) -> str:
    """录制详情表「周期状态」文案（UAM 样本口径）。"""
    mid = int(message_id)
    row = periodic
    if row is None:
        for item in (coverage or {}).get("periodic_rows") or []:
            if int(item.get("message_id") or 0) == mid:
                row = item
                break
    if row:
        return _format_periodic_row_status(mid, row)
    label = UAM_SAMPLE_PERIOD_STATUS.get(mid)
    if label:
        return label
    if mid in UAM_KNOWN_MESSAGE_IDS:
        return "见本次录制"
    return "—"


def _scan_wave_eval_rows(observations: Iterable[dict] | None) -> list[dict]:
    rows = []
    for item in observations or []:
        message_id = int(item.get("message_id") or 0)
        elapsed = item.get("recorded_elapsed_seconds")
        u20 = item.get("u20")
        if (
            message_id not in PLAYER_SCAN_WAVE_MESSAGE_IDS
            or elapsed is None
            or u20 is None
        ):
            continue
        raw = bytearray(0x24)
        raw[0x20:0x24] = int(u20).to_bytes(4, "big")
        rows.append({
            "message_id": message_id,
            "recorded_elapsed_seconds": float(elapsed),
            "raw": bytes(raw),
        })
    return rows


def _compact_scan_wave_observations(
    observations: Iterable[dict] | None,
) -> list[dict]:
    compact = []
    for item in observations or []:
        message_id = int(item.get("message_id") or 0)
        elapsed = item.get("recorded_elapsed_seconds")
        u20 = item.get("u20")
        if (
            message_id not in PLAYER_SCAN_WAVE_MESSAGE_IDS
            or elapsed is None
            or u20 is None
        ):
            continue
        compact.append({
            "message_id": message_id,
            "recorded_elapsed_seconds": float(elapsed),
            "u20": int(u20),
        })
    return compact


def _cached_item_rows(item: dict) -> list[dict]:
    cached = item.get("_type9_shadow_leaf_cache")
    if isinstance(cached, dict) and cached.get("ok"):
        return list(cached.get("rows") or [])
    return []


def message_observation_details_from_item(
    item: dict,
) -> tuple[list[dict], bool]:
    """Return message ID, leaf length and logical slot observations."""
    elapsed = item.get("recorded_elapsed_seconds")
    elapsed_value = float(elapsed) if elapsed is not None else None
    rows = _cached_item_rows(item)
    if rows:
        observations = []
        for row in rows:
            key = tuple(row.get("key") or ())
            if len(key) < 3 or not isinstance(key[1], int):
                continue
            raw = bytes(row.get("raw") or b"")
            slot = (
                int.from_bytes(raw[0x1C:0x1E], "big")
                if len(raw) >= 0x1E else None
            )
            observations.append({
                "message_id": int(key[1]),
                "length": int(key[2]),
                "slot": slot,
                "u20": (
                    int.from_bytes(raw[0x20:0x24], "big")
                    if len(raw) >= 0x24 else None
                ),
                "elapsed": elapsed_value,
                "subtype": (
                    int.from_bytes(raw[0x20:0x24], "big")
                    if int(key[1]) == 0x8004 and len(raw) >= 0x24
                    else None
                ),
            })
        return observations, True

    payload = bytes(item.get("encrypted_record") or item.get("payload") or b"")
    if not payload:
        return [], False
    try:
        from core.type9_shadow import decode_material
        from core.type9_crypto import MARKER

        material = decode_material(payload)
        # Pool items store selector..ciphertext without the outer 01 marker.
        # The general decoder scans marker+10-byte-prefix first, so provide a
        # synthetic carrier for this normalized record form.
        if not material.get("ok") and len(payload) >= 8:
            cipher_length = int.from_bytes(payload[6:8], "big")
            record_end = 8 + cipher_length
            if (
                payload[0] <= 2
                and payload[1] <= 9
                and cipher_length > 0
                and record_end <= len(payload)
            ):
                material = decode_material(
                    MARKER + (b"\x00" * 10) + payload[:record_end]
                )
    except Exception:
        # Coverage is side-band diagnostics and never affects the record path.
        return [], False
    if not material.get("ok"):
        return [], False
    observations = []
    for leaf in material.get("leaves") or []:
        if not isinstance(leaf.get("message_id"), int):
            continue
        raw = bytes(leaf.get("raw") or b"")
        observations.append({
            "message_id": int(leaf["message_id"]),
            "length": int(leaf.get("actual_length") or 0),
            "slot": (
                int.from_bytes(raw[0x1C:0x1E], "big")
                if len(raw) >= 0x1E else None
            ),
            "u20": (
                int.from_bytes(raw[0x20:0x24], "big")
                if len(raw) >= 0x24 else None
            ),
            "elapsed": elapsed_value,
            "subtype": (
                int.from_bytes(raw[0x20:0x24], "big")
                if int(leaf["message_id"]) == 0x8004 and len(raw) >= 0x24
                else None
            ),
        })
    return observations, True


def message_observations_from_item(item: dict) -> tuple[list[tuple[int, int]], bool]:
    """返回单个池项的 ``[(message_id, leaf_length)]`` 与解码成功状态。"""
    details, ok = message_observation_details_from_item(item)
    return [
        (int(row["message_id"]), int(row["length"]))
        for row in details
    ], ok


def summarize_message_observations(
    counts: dict[int, int] | Counter,
    lengths: dict[int, Iterable[int]],
    *,
    slots: dict[int, Iterable[int]] | None = None,
    subtypes: dict[int, Iterable[int]] | None = None,
    scan_wave_rows: Iterable[dict] | None = None,
    decoded_reports: int = 0,
    decode_failures: int = 0,
) -> dict:
    normalized_counts = {
        int(message_id): int(count)
        for message_id, count in counts.items()
        if int(count) > 0
    }
    normalized_lengths = {
        int(message_id): sorted({int(value) for value in values})
        for message_id, values in lengths.items()
    }
    seen = set(normalized_counts)
    seen_known = sorted(seen & UAM_KNOWN_MESSAGE_IDS)
    missing = sorted(UAM_KNOWN_MESSAGE_IDS - seen)
    unknown = sorted(seen - UAM_KNOWN_MESSAGE_IDS)
    seen_priority = sorted(seen & UAM_REPLAY_80XX_MESSAGE_IDS)
    missing_priority = sorted(UAM_REPLAY_80XX_MESSAGE_IDS - seen)
    priority_total = len(UAM_REPLAY_80XX_MESSAGE_IDS)
    priority_coverage = (
        len(seen_priority) / priority_total * 100.0
        if priority_total else 100.0
    )
    total = len(UAM_KNOWN_MESSAGE_IDS)
    coverage = (len(seen_known) / total * 100.0) if total else 100.0
    normalized_slots = {
        int(message_id): sorted({int(value) for value in values})
        for message_id, values in (slots or {}).items()
    }
    normalized_subtypes = {
        int(message_id): sorted({int(value) for value in values})
        for message_id, values in (subtypes or {}).items()
    }
    seen_8004_subtypes = sorted(
        set(normalized_subtypes.get(0x8004, [])) & UAM_8004_EXPECTED_SUBTYPES
    )
    missing_8004_subtypes = sorted(
        UAM_8004_EXPECTED_SUBTYPES - set(seen_8004_subtypes)
    )
    subtype_8004_total = len(UAM_8004_EXPECTED_SUBTYPES)
    subtype_8004_count = len(seen_8004_subtypes)
    subtype_8004_coverage = (
        subtype_8004_count / subtype_8004_total * 100.0
        if subtype_8004_total else 100.0
    )
    periodic_rows = []
    periodic_ready_ids = []
    for message_id, period in sorted(PLAYER_PERIODIC_EXTENSION_PERIODS.items()):
        observed_slots = normalized_slots.get(int(message_id), [])
        intervals = [
            right - left
            for left, right in zip(observed_slots, observed_slots[1:])
        ]
        ready = (
            len(observed_slots) >= PLAYER_PERIODIC_MIN_SAMPLES
            and observed_slots[-1] - observed_slots[-2] == int(period)
        )
        if ready:
            periodic_ready_ids.append(int(message_id))
        periodic_rows.append({
            "message_id": int(message_id),
            "kind": "slot",
            "period": int(period),
            "minimum_samples": int(PLAYER_PERIODIC_MIN_SAMPLES),
            "sample_count": len(observed_slots),
            "slots": observed_slots,
            "intervals": intervals,
            "last_interval": intervals[-1] if intervals else None,
            "next_expected_slot": (
                observed_slots[-1] + int(period) if observed_slots else None
            ),
            "ready": ready,
        })
    a_slots = normalized_slots.get(PLAYER_800A_MESSAGE_ID, [])
    judged = evaluate_800a_period(a_slots)
    if judged.get("ready"):
        periodic_ready_ids.append(PLAYER_800A_MESSAGE_ID)
    period = judged.get("period")
    periodic_rows.append({
        "message_id": PLAYER_800A_MESSAGE_ID,
        "kind": "slot",
        "period": int(period) if period else None,
        "minimum_samples": int(
            judged.get("minimum_samples") or PLAYER_PERIODIC_MIN_SAMPLES
        ),
        "sample_count": len(a_slots),
        "slots": a_slots,
        "intervals": list(judged.get("intervals") or []),
        "last_interval": judged.get("last_interval"),
        "next_expected_slot": judged.get("next_expected_slot"),
        "ready": bool(judged.get("ready")),
        "status": str(judged.get("status") or ""),
        "morphology": judged.get("morphology"),
        "cluster_count": judged.get("cluster_count"),
        "cluster_starts": list(judged.get("cluster_starts") or []),
        "cluster_intervals": list(judged.get("cluster_intervals") or []),
    })
    periodic_rows.sort(key=lambda row: int(row["message_id"]))
    scan_observations = _compact_scan_wave_observations(scan_wave_rows)
    scan = evaluate_scan_wave_template(_scan_wave_eval_rows(scan_observations))
    for message_id in PLAYER_SCAN_WAVE_PERIODIC_IDS:
        if scan.get("ready"):
            periodic_ready_ids.append(int(message_id))
        periodic_rows.append({
            "message_id": int(message_id),
            "kind": "scan_wave",
            "period": None,
            "period_seconds": scan.get("scan_wave_period_seconds"),
            "minimum_samples": 2,
            "sample_count": sum(
                1
                for row in scan_observations
                if int(row.get("message_id") or 0) == int(message_id)
            ),
            "slots": [],
            "intervals": [],
            "last_interval": None,
            "next_expected_slot": None,
            "ready": bool(scan.get("ready")),
            "status": str(scan.get("status") or "waiting_wave1"),
            "has_complete_wave1": bool(scan.get("has_complete_wave1")),
            "has_wave2_open": bool(scan.get("has_wave2_open")),
            "has_wave1_8029": bool(scan.get("has_wave1_8029")),
            "wave1_shape": scan.get("wave1_shape"),
        })
    periodic_total = (
        len(PLAYER_PERIODIC_SLOT_FAMILY_IDS) + len(PLAYER_SCAN_WAVE_PERIODIC_IDS)
    )
    periodic_ready_count = len(periodic_ready_ids)
    periodic_coverage = (
        periodic_ready_count / periodic_total * 100.0
        if periodic_total else 100.0
    )
    # 8004's single ID criterion is replaced by its nine subtype criteria.
    completion_total = priority_total - 1 + subtype_8004_total + periodic_total
    completion_count = (
        len(seen_priority)
        - (1 if 0x8004 in seen_priority else 0)
        + subtype_8004_count
        + periodic_ready_count
    )
    recording_completion = (
        completion_count / completion_total * 100.0
        if completion_total else 100.0
    )
    return {
        "catalog_revision": CATALOG_REVISION,
        "known_total": total,
        "seen_known_count": len(seen_known),
        "coverage_percent": coverage,
        "complete": not missing,
        "priority_name": "80xx",
        "priority_total": priority_total,
        "seen_priority_count": len(seen_priority),
        "priority_coverage_percent": priority_coverage,
        "priority_complete": not missing_priority,
        "seen_priority_ids": seen_priority,
        "missing_priority_ids": missing_priority,
        "seen_known_ids": seen_known,
        "missing_ids": missing,
        "unknown_ids": unknown,
        "message_counts": normalized_counts,
        "message_lengths": normalized_lengths,
        "message_slots": normalized_slots,
        "message_subtypes": normalized_subtypes,
        "subtype_8004_total": subtype_8004_total,
        "subtype_8004_seen_count": subtype_8004_count,
        "subtype_8004_seen": seen_8004_subtypes,
        "subtype_8004_missing": missing_8004_subtypes,
        "subtype_8004_coverage_percent": subtype_8004_coverage,
        "subtype_8004_ready": not missing_8004_subtypes,
        "periodic_total": periodic_total,
        "periodic_ready_count": periodic_ready_count,
        "periodic_ready_ids": periodic_ready_ids,
        "periodic_missing_ids": sorted(
            (
                set(PLAYER_PERIODIC_SLOT_FAMILY_IDS)
                | set(PLAYER_SCAN_WAVE_PERIODIC_IDS)
            )
            - set(periodic_ready_ids)
        ),
        "periodic_coverage_percent": periodic_coverage,
        "periodic_rows": periodic_rows,
        "scan_wave_ready": bool(scan.get("ready")),
        "scan_wave_status": str(scan.get("status") or "waiting_wave1"),
        "scan_wave_period_seconds": scan.get("scan_wave_period_seconds"),
        "scan_wave_observations": scan_observations,
        "recording_completion_count": completion_count,
        "recording_completion_total": completion_total,
        "recording_completion_percent": recording_completion,
        "decoded_reports": int(decoded_reports),
        "decode_failures": int(decode_failures),
    }


def summarize_pool_items(
    items: Iterable[dict],
    *,
    source_01_only: bool = True,
) -> dict:
    counts: Counter = Counter()
    lengths: dict[int, set[int]] = defaultdict(set)
    slots: dict[int, set[int]] = defaultdict(set)
    subtypes: dict[int, set[int]] = defaultdict(set)
    scan_wave_rows: list[dict] = []
    decoded_reports = 0
    decode_failures = 0
    for item in items:
        source = str(item.get("source") or "01")
        if source_01_only and source.startswith("3366"):
            continue
        observations, ok = message_observation_details_from_item(item)
        if ok:
            decoded_reports += 1
        else:
            decode_failures += 1
        for row in observations:
            message_id = int(row["message_id"])
            length = int(row["length"])
            counts[message_id] += 1
            lengths[message_id].add(length)
            if row.get("slot") is not None:
                slots[message_id].add(int(row["slot"]))
            if row.get("subtype") is not None:
                subtypes[message_id].add(int(row["subtype"]))
            if (
                message_id in PLAYER_SCAN_WAVE_MESSAGE_IDS
                and row.get("elapsed") is not None
                and row.get("u20") is not None
            ):
                scan_wave_rows.append({
                    "message_id": message_id,
                    "recorded_elapsed_seconds": float(row["elapsed"]),
                    "u20": int(row["u20"]),
                })
    return summarize_message_observations(
        counts,
        lengths,
        slots=slots,
        subtypes=subtypes,
        scan_wave_rows=scan_wave_rows,
        decoded_reports=decoded_reports,
        decode_failures=decode_failures,
    )
