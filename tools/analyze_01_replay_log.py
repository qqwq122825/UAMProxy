#!/usr/bin/env python3
"""汇总 DFMProxy 01ReplayAnalysis 日志，便于快速定位游标、报告序号和 CRC 异常。"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict


def _events_path(value: str) -> str:
    path = os.path.abspath(value)
    if os.path.isdir(path):
        path = os.path.join(path, "01_replace_events.jsonl")
    return path


def _read_jsonl(path: str) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8-sig") as stream:
        for line_no, line in enumerate(stream, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path} 第 {line_no} 行 JSON 损坏: {exc}") from exc
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description="分析 01ReplayAnalysis/run_* 中的 01 重放事件"
    )
    parser.add_argument("path", help="run_* 目录或 01_replace_events.jsonl 文件")
    args = parser.parse_args()
    input_path = os.path.abspath(args.path)
    run_dir = input_path if os.path.isdir(input_path) else os.path.dirname(input_path)
    path = _events_path(input_path)

    events = _read_jsonl(path) if os.path.isfile(path) else []
    selection_path = os.path.join(run_dir, "template_selection_events.jsonl")
    usage_path = os.path.join(run_dir, "template_usage_events.jsonl")
    selections = _read_jsonl(selection_path) if os.path.isfile(selection_path) else []
    usages = _read_jsonl(usage_path) if os.path.isfile(usage_path) else []

    decisions = Counter(event.get("decision", "UNKNOWN") for event in events)
    reasons = Counter(event.get("reason", "") for event in events)
    anomalies = []
    reports_by_conn: dict[str, list[tuple[int, int | None]]] = defaultdict(list)
    wraps = []
    last_selected_by_conn: dict[str, int] = {}
    replacement_changed = 0
    replacement_levels = Counter()
    aggressive_leaf_ids = Counter()
    aggressive_blocked_leaf_ids = Counter()
    watched_message_ids = Counter()
    watched_replaced_ids = Counter()
    shadow_statuses = Counter()
    shadow_ready = 0
    shadow_semantic_known = 0
    shadow_mechanical_ready = 0
    shadow_matched = 0
    shadow_total = 0
    shadow_semantic_leaves = 0
    shadow_unmapped_leaves = 0
    shadow_subtype_miss_leaves = 0
    shadow_semantic_leaf_metrics_known = 0
    shadow_invalid = []
    continuity_breaks = []
    cross_account_events = 0
    cross_account_pairs = Counter()
    identity_rewrites = 0
    identity_blocked = 0
    final_identity_failures = []

    for event in events:
        event_id = event.get("event_id")
        decision = event.get("decision")
        checks = event.get("checks") or {}
        cursor = event.get("cursor") or {}
        ordinals = event.get("ordinals") or {}
        conn_id = (event.get("connection") or {}).get("conn_id", "")
        shadow = event.get("shadow_rebuild") or {}
        cross_account = event.get("cross_account") or {}
        if cross_account.get("enabled"):
            cross_account_events += 1
            pair = (
                str(cross_account.get("live_game_id") or "?"),
                str(cross_account.get("donor_game_id") or "?"),
            )
            cross_account_pairs[pair] += 1
            identity_rewrites += int(
                cross_account.get("identity_rewrite_count") or 0
            )
            identity_blocked += int(
                cross_account.get("identity_blocked_leaves") or 0
            )
            if cross_account.get("final_identity_check") is False:
                final_identity_failures.append(event_id)
        if shadow:
            status = shadow.get("status", "UNKNOWN")
            mechanical_ready = bool(
                shadow.get("mechanical_ready", shadow.get("ready"))
            )
            shadow_statuses[status] += 1
            if "semantic_ready" in shadow:
                shadow_semantic_known += 1
                shadow_ready += int(bool(shadow.get("semantic_ready")))
            shadow_mechanical_ready += int(mechanical_ready)
            shadow_matched += int(shadow.get("matched_leaves") or 0)
            shadow_total += int(shadow.get("total_leaves") or 0)
            if "semantic_ready_leaves" in shadow:
                shadow_semantic_leaf_metrics_known += 1
                shadow_semantic_leaves += int(
                    shadow.get("semantic_ready_leaves") or 0
                )
                shadow_unmapped_leaves += int(
                    shadow.get("semantic_unmapped_leaves") or 0
                )
                shadow_subtype_miss_leaves += int(
                    shadow.get("subtype_miss_leaves") or 0
                )
            if shadow.get("generated") and not mechanical_ready:
                shadow_invalid.append(event_id)
            for leaf in shadow.get("leaf_results") or []:
                message_id = leaf.get("message_id")
                if message_id in {0x8024, 0x8030, 0x80CC, 0x80CD}:
                    watched_message_ids[int(message_id)] += 1
                    if decision == "REPLACE" and leaf.get("replacement_level") != "NONE":
                        watched_replaced_ids[int(message_id)] += 1
                if (
                    decision == "REPLACE"
                    and leaf.get("replacement_level") == "AGGRESSIVE_UNKNOWN"
                ):
                    key = (
                        f"0x{int(message_id):04X}"
                        if isinstance(message_id, int)
                        else f"code=0x{int(leaf.get('record_code') or 0):08X}"
                    )
                    aggressive_leaf_ids[key] += 1
                if leaf.get("block_reason") == "AGGRESSIVE_BLOCK_DYNAMIC":
                    key = (
                        f"0x{int(message_id):04X}"
                        if isinstance(message_id, int)
                        else f"code=0x{int(leaf.get('record_code') or 0):08X}"
                    )
                    aggressive_blocked_leaf_ids[key] += 1
        if checks.get("leaf_sequence_continuous_from_previous") is False:
            continuity_breaks.append(event_id)

        if decision in {"REPLACE", "PASS_LIVE"}:
            selected = cursor.get("selected_pool_idx")
            total = cursor.get("pool_total")
            if isinstance(selected, int):
                previous_selected = last_selected_by_conn.get(conn_id)
                if (
                    isinstance(total, int) and total > 0
                    and previous_selected is not None
                    and selected < previous_selected
                ):
                    wraps.append(event_id)
                last_selected_by_conn[conn_id] = selected
            before = cursor.get("before")
            after = cursor.get("after")
            if (
                isinstance(total, int) and total > 0
                and isinstance(selected, int)
                and isinstance(after, int)
                and selected != (after - 1) % total
            ):
                anomalies.append(
                    f"事件{event_id}: 游标 selected={selected}, after={after}, total={total}"
                )

        if decision == "REPLACE":
            level = str(
                event.get("replacement_level")
                or shadow.get("replacement_level")
                or "KNOWN_CLEAN"
            )
            replacement_levels[level] += 1
            required_names = {
                "report_inherited",
                "blue_06_09_inherited",
                "blue_12_25_inherited",
                "blue_2f_inherited",
                "final_equals_shadow",
                "replacement_changed",
                "output_crc_ok",
                "output_validation_ok",
                "shadow_candidate_ready",
                "shadow_mechanical_ready",
                "shadow_outer_crc_ok",
                "shadow_decode_ok",
                "shadow_signature_equal_live",
                "shadow_sequences_equal_live",
            }
            failed = [
                name for name in sorted(required_names)
                if checks.get(name) is False
            ]
            if failed:
                anomalies.append(f"事件{event_id}: REPLACE 检查失败 {','.join(failed)}")
            send_ready = checks.get(
                "shadow_send_ready", checks.get("shadow_candidate_ready")
            )
            if send_ready is False:
                anomalies.append(f"事件{event_id}: REPLACE 候选未达到发送门槛")
            if checks.get("final_equals_live") is True:
                anomalies.append(f"事件{event_id}: REPLACE最终字节没有变化")
            replacement_changed += int(bool(checks.get("replacement_changed")))
        elif decision == "PASS_NON_TARGET":
            if cursor.get("before") != cursor.get("after"):
                anomalies.append(f"事件{event_id}: 非09包移动了游标")
        elif decision == "PASS_LIVE":
            if not checks.get("final_equals_live"):
                anomalies.append(f"事件{event_id}: PASS_LIVE最终字节不等于实时输入")
            if not checks.get("output_crc_ok"):
                anomalies.append(f"事件{event_id}: PASS_LIVE外层CRC异常")
        elif decision == "DROP":
            anomalies.append(
                f"事件{event_id}: DROP {event.get('reason')} "
                f"{';'.join(event.get('validation_errors') or [])}"
            )

        if decision in {"REPLACE", "PASS_LIVE", "DROP"}:
            reports_by_conn[conn_id].append(
                (int(ordinals.get("target_09") or 0), ordinals.get("report_index"))
            )

    print(f"文件: {path}")
    print(f"事件总数: {len(events)}")
    if selections:
        selection_modes = Counter(
            row.get("template_mode", "UNKNOWN") for row in selections
        )
        print(
            "模板池选择: "
            + ", ".join(
                f"{key}={value}" for key, value in sorted(selection_modes.items())
            )
        )
    if usages:
        usage_modes = Counter(row.get("template_mode", "UNKNOWN") for row in usages)
        print(
            "模板实际使用: "
            + ", ".join(
                f"{key}={value}" for key, value in sorted(usage_modes.items())
            )
        )
        print(
            "叶子来源合计: "
            f"player={sum(int(row.get('player_template_leaves') or 0) for row in usages)}, "
            f"official={sum(int(row.get('official_template_leaves') or 0) for row in usages)}, "
            f"pruned={sum(int(row.get('pruned_leaves') or 0) for row in usages)}"
        )
    print("决策: " + ", ".join(f"{key}={value}" for key, value in sorted(decisions.items())))
    print("原因: " + ", ".join(f"{key}={value}" for key, value in sorted(reasons.items())))
    print(f"游标回卷事件: {wraps or '无'}")
    if decisions.get("REPLACE"):
        print(
            f"真实替换且字节变化: {replacement_changed}/"
            f"{decisions.get('REPLACE', 0)}"
        )
        print(
            "替换级别: "
            + ", ".join(
                f"{key}={value}" for key, value in sorted(replacement_levels.items())
            )
        )
        print(
            "激进未知叶子: "
            + (
                ", ".join(
                    f"{key}={value}"
                    for key, value in aggressive_leaf_ids.most_common()
                )
                if aggressive_leaf_ids else "无"
            )
        )
    if aggressive_blocked_leaf_ids:
        print(
            "动态保护叶子: "
            + ", ".join(
                f"{key}={value}"
                for key, value in aggressive_blocked_leaf_ids.most_common()
            )
        )
    if shadow_statuses:
        print(
            "影子状态: "
            + ", ".join(
                f"{key}={value}" for key, value in sorted(shadow_statuses.items())
            )
        )
        coverage = (shadow_matched / shadow_total) if shadow_total else 0.0
        semantic_packet_text = (
            f"{shadow_ready}/{shadow_semantic_known}"
            if shadow_semantic_known else "未记录（旧日志）"
        )
        print(
            f"影子机械回验: {shadow_mechanical_ready}/{sum(shadow_statuses.values())}; "
            f"语义就绪: {semantic_packet_text}; "
            f"叶子覆盖: {shadow_matched}/{shadow_total} ({coverage:.1%})"
        )
        semantic_coverage = (
            shadow_semantic_leaves / shadow_total if shadow_total else 0.0
        )
        if shadow_semantic_leaf_metrics_known:
            print(
                f"语义叶子: {shadow_semantic_leaves}/{shadow_total} "
                f"({semantic_coverage:.1%}); 未映射={shadow_unmapped_leaves}; "
                f"子类型未命中={shadow_subtype_miss_leaves}"
            )
        else:
            print("语义叶子: 未记录（旧日志）")
        print(f"影子生成后回验失败: {shadow_invalid or '无'}")
        print(f"跨事件明文序列不连续: {continuity_breaks or '无'}")
        print(
            "专项消息ID: "
            + ", ".join(
                f"0x{message_id:04X}={watched_message_ids[message_id]}"
                f"(替换={watched_replaced_ids[message_id]})"
                for message_id in (0x8024, 0x8030, 0x80CC, 0x80CD)
            )
        )
    if cross_account_events:
        print(f"跨账号01事件: {cross_account_events}")
        print(
            "实时/donor组合: "
            + ", ".join(
                f"{live_id}<-{donor_id}={count}"
                for (live_id, donor_id), count in cross_account_pairs.most_common()
            )
        )
        print(
            f"账号等长改写: {identity_rewrites}; "
            f"身份语义保护叶子: {identity_blocked}; "
            f"最终账号校验失败: {final_identity_failures or '无'}"
        )
    for conn_id, pairs in reports_by_conn.items():
        if pairs:
            print(
                f"连接 {conn_id or '?'}: target09={pairs[0][0]}..{pairs[-1][0]}, "
                f"report={pairs[0][1]}..{pairs[-1][1]}"
            )
    if anomalies:
        print("异常/关注项:")
        for item in anomalies:
            print(f"- {item}")
    else:
        print("异常/关注项: 无")

    suspect_path = os.path.join(os.path.dirname(path), "01_suspect_diffs.jsonl")
    if os.path.isfile(suspect_path):
        suspect_events = _read_jsonl(suspect_path)
        suspect_flags = Counter()
        suspect_identities = Counter()
        shadow_only_candidates = 0
        for suspect_event in suspect_events:
            for leaf in suspect_event.get("suspect_leaves") or []:
                suspect_flags.update(leaf.get("suspect_flags") or [])
                message_id = leaf.get("message_id")
                identity = (
                    f"0x{int(message_id):04X}"
                    if isinstance(message_id, int)
                    else f"code=0x{int(leaf.get('record_code') or 0):08X}"
                )
                suspect_identities[identity] += 1
                shadow_only_candidates += int(
                    bool(leaf.get("shadow_only_candidate_hex"))
                )
        print(f"专项差分事件: {len(suspect_events)}")
        print(
            "专项差分标记: "
            + (
                ", ".join(
                    f"{key}={value}" for key, value in suspect_flags.most_common()
                )
                if suspect_flags else "无"
            )
        )
        print(
            "专项差分叶子: "
            + ", ".join(
                f"{key}={value}"
                for key, value in suspect_identities.most_common()
            )
        )
        print(f"仅旁路候选: {shadow_only_candidates}")

    downlink_path = os.path.join(os.path.dirname(path), "01_downlink_events.jsonl")
    if os.path.isfile(downlink_path):
        downlinks = _read_jsonl(downlink_path)
        dispositions = Counter(
            event.get("disposition", "UNKNOWN") for event in downlinks
        )
        lengths = [
            int((event.get("packet") or {}).get("total_length") or 0)
            for event in downlinks
        ]
        print(f"01下行事件: {len(downlinks)}")
        print(
            "01下行处置: "
            + ", ".join(
                f"{key}={value}" for key, value in sorted(dispositions.items())
            )
        )
        if lengths:
            print(f"01下行长度: {min(lengths)}..{max(lengths)}B")
        for event in downlinks[-5:]:
            packet = event.get("packet") or {}
            print(
                "01下行末尾: "
                f"event={event.get('event_id')} time={event.get('time')} "
                f"len={packet.get('total_length')} "
                f"markers={packet.get('marker_types')} "
                f"disposition={event.get('disposition')}"
            )
    else:
        print("01下行事件: 本次日志未生成")
    return 1 if anomalies else 0


if __name__ == "__main__":
    raise SystemExit(main())
