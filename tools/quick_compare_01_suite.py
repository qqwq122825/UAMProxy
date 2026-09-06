#!/usr/bin/env python3
"""One-command batch comparison for future DFMProxy 01 captures.

The first input is the baseline.  Every later input is compared with it.  When
an observed input is a replay run, the script also audits Live versus Final so
that dropped/replaced messages are visible separately from runtime changes.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.compare_01_field_whitelist import (  # noqa: E402
    group_by_message,
    split_anomalies,
)
from tools.compare_01_message_ids import (  # noqa: E402
    compare_datasets,
    load_dataset,
    parse_int,
    resolve_source,
    write_outputs,
)

# 索引里除了按分数排序的前几名，这些消息只要有字段异常就必须单独列出。
# 否则像 0x100C +0x50 这种 STABLE_BASELINE_CHANGED 会被时钟/噪声 ZERO_TO_NONZERO 压到第 40 名以后。
DEFAULT_WATCH_IDS = (
    0x0207,
    0x1007,
    0x1008,
    0x100C,
    0x100F,
    0x8002,
    0x8028,
)


def safe_name(path: Path) -> str:
    text = re.sub(r"[^0-9A-Za-z._-]+", "_", path.name).strip("_")
    return text or "dataset"


def _anomaly_row(row: dict) -> dict:
    return {
        "shape": row["shape"],
        "message_id": row.get("message_id"),
        "category": row["category"],
        "offset": row["leaf_offset_hex"],
        "payload_offset": row["payload_offset_hex"],
        "width": row["width"],
        "ratio": row["outlier_ratio_b"],
        "values_a": row.get("values_a"),
        "values_b": row.get("values_b"),
    }


def value_text(values: object) -> str:
    if not values:
        return "-"
    parts = []
    for item in values[:4]:
        if isinstance(item, dict):
            parts.append(f"{item.get('hex')}x{item.get('count')}")
        else:
            parts.append(str(item))
    return ", ".join(parts)


def watched_anomalies(anomalies: list[dict], watch_ids: set[int]) -> list[dict]:
    watched = []
    for row in anomalies:
        message_id = parse_int(row.get("message_id"))
        if message_id in watch_ids:
            watched.append(_anomaly_row(row))
    return watched


def result_summary(
    result: dict,
    relative_dir: str,
    *,
    watch_ids: set[int],
) -> dict:
    anomalies = result.get("field_anomalies") or []
    return {
        "baseline": result["baseline"],
        "observed": result["observed"],
        "output_dir": relative_dir,
        "new_ids": [row["identity"] for row in result.get("new_ids_b") or []],
        "missing_ids": [row["identity"] for row in result.get("missing_ids_b") or []],
        "frequency_shifts": [
            row["identity"] for row in result.get("frequency_shifts") or []
        ],
        "top_field_anomalies": [_anomaly_row(row) for row in anomalies[:20]],
        "watched_anomalies": watched_anomalies(anomalies, watch_ids),
    }


def write_ai_review(output_root: Path, results: list[dict]) -> None:
    """给 AI 先看的单页文档：消息ID集合 + 同ID字段，白名单已剔除。"""
    lines = [
        "# 01 录制/重放快速对比（AI审阅）",
        "",
        f"生成时间：{datetime.now().isoformat(timespec='seconds')}",
        "",
        "阅读顺序：先看消息ID集合有没有新增/缺失，再看同一消息ID里哪些字段变了。",
        "时间戳和已坐实的60Hz时钟已加白，不进第2节。其余字段全部保留，包括100C尾部。",
        "",
    ]
    for index, result in enumerate(results, 1):
        kept, ignored = split_anomalies(result.get("field_anomalies") or [])
        grouped = group_by_message(kept)
        base = result["baseline"]
        observed = result["observed"]
        new_ids = [row["identity"] for row in result.get("new_ids_b") or []]
        missing_ids = [row["identity"] for row in result.get("missing_ids_b") or []]
        common = [
            row["identity"]
            for row in result.get("message_ids") or []
            if row.get("status") in {"COMMON", "FREQUENCY_SHIFT"}
        ]
        lines += [
            f"## {index}. {base['label']} → {observed['label']}",
            "",
            f"- A：`{base['input']}`，view=`{base['view']}`，{base['packets']}包 / {base['leaves']}叶子",
            f"- B：`{observed['input']}`，view=`{observed['view']}`，{observed['packets']}包 / {observed['leaves']}叶子",
            "",
            "### 1. 消息ID集合",
            "",
            f"- 新增（B有A无）：{', '.join(f'`{item}`' for item in new_ids) or '无'}",
            f"- 缺失（A有B无）：{', '.join(f'`{item}`' for item in missing_ids) or '无'}",
            f"- 两边都有：{len(common)} 种",
            "",
            "### 2. 同一消息ID的字段变化（已去白名单）",
            "",
        ]
        if not grouped:
            lines += ["无。同一消息ID的载荷字段相对基线没有越过阈值的变化。", ""]
        else:
            for message_id in sorted(grouped, key=lambda key: (key.startswith("code="), key)):
                rows = grouped[message_id]
                lines += [f"#### `{message_id}`（{len(rows)}个字段）", ""]
                lines += [
                    "| 形状 | 类型 | 叶子偏移 | 载荷偏移 | 宽度 | A值 | B值 | B异常占比 |",
                    "|---|---|---|---|---:|---|---|---:|",
                ]
                for row in rows:
                    lines.append(
                        f"| `{row['shape']}` | {row['category']} | "
                        f"`{row['leaf_offset_hex']}` | `{row['payload_offset_hex']}` | "
                        f"{row['width']} | `{value_text(row.get('values_a'))}` | "
                        f"`{value_text(row.get('values_b'))}` | "
                        f"{row['outlier_ratio_b']:.1%} |"
                    )
                lines.append("")
        if ignored:
            lines += [
                "### 3. 白名单已忽略",
                "",
                "| 消息 | 偏移 | 原因 |",
                "|---|---|---|",
            ]
            seen = set()
            for row in ignored:
                key = (row.get("shape"), row.get("leaf_offset_hex"), row.get("whitelist_reason"))
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f"| `{row.get('shape')}` | `{row.get('leaf_offset_hex')}` | "
                    f"{row.get('whitelist_reason')} |"
                )
            lines.append("")
        else:
            lines += ["### 3. 白名单已忽略", "", "本场没有命中白名单的字段。", ""]
    (output_root / "AI_REVIEW.md").write_text("\n".join(lines), encoding="utf-8")


def write_index(output_root: Path, rows: list[dict]) -> None:
    (output_root / "comparison_index.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    lines = [
        "# 01 批量快速对比索引",
        "",
        f"生成时间：{datetime.now().isoformat(timespec='seconds')}",
        "",
        "给 AI 先看同目录的 [AI_REVIEW.md](AI_REVIEW.md)：消息ID集合 + 同ID字段（已去时间戳白名单）。",
        "",
    ]
    for index, row in enumerate(rows, 1):
        base = row["baseline"]
        observed = row["observed"]
        lines += [
            f"## {index}. {base['label']} → {observed['label']}",
            "",
            f"- A：`{base['input']}`，view=`{base['view']}`",
            f"- B：`{observed['input']}`，view=`{observed['view']}`",
            f"- 新增ID：{', '.join(row['new_ids']) or '无'}",
            f"- 缺失ID：{', '.join(row['missing_ids']) or '无'}",
            f"- 频率显著变化：{', '.join(row['frequency_shifts']) or '无'}",
            f"- 字段异常候选：{len(row['top_field_anomalies'])}项写入索引，完整结果见子目录",
            f"- 重点消息命中：{len(row.get('watched_anomalies') or [])}项",
            f"- [详细报告]({row['output_dir']}/message_diff.md)",
            "",
        ]
        watched = row.get("watched_anomalies") or []
        if watched:
            lines += [
                "重点消息（0207/1007/1008/100C/100F/8002/8028，不按总分截断）：",
                "",
                "| 消息 | 类型 | 叶子偏移 | 载荷偏移 | 宽度 | B异常占比 | A值 | B值 |",
                "|---|---|---|---|---:|---:|---|---|",
            ]
            for item in watched:
                lines.append(
                    f"| `{item['shape']}` | {item['category']} | "
                    f"`{item['offset']}` | `{item['payload_offset']}` | "
                    f"{item['width']} | {item['ratio']:.1%} | "
                    f"`{value_text(item.get('values_a'))}` | "
                    f"`{value_text(item.get('values_b'))}` |"
                )
            lines.append("")
        if row["top_field_anomalies"]:
            lines += [
                "按分数排序的字段异常（前10，可能把重点消息挤下去）：",
                "",
                "| 消息 | 类型 | 叶子偏移 | 载荷偏移 | 宽度 | B异常占比 |",
                "|---|---|---|---|---:|---:|",
            ]
            for item in row["top_field_anomalies"][:10]:
                lines.append(
                    f"| `{item['shape']}` | {item['category']} | "
                    f"`{item['offset']}` | `{item['payload_offset']}` | "
                    f"{item['width']} | {item['ratio']:.1%} |"
                )
            lines.append("")
    (output_root / "comparison_index.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="以第一份数据为基线，批量比较后续01录制/重放并审计Live→Final"
    )
    parser.add_argument("baseline", type=Path, help="正常基线文件或目录")
    parser.add_argument("observed", nargs="+", type=Path, help="一份或多份待检查数据")
    parser.add_argument("--baseline-label")
    parser.add_argument("--view-a", choices=("live", "candidate", "template", "final"), default="live")
    parser.add_argument("--view-b", choices=("live", "candidate", "template", "final"), default="live")
    parser.add_argument("--direction", choices=("up", "down", "both"), default="up")
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--top", type=int, default=100)
    parser.add_argument("--min-baseline-samples", type=int, default=2)
    parser.add_argument("--message-id", action="append", default=[])
    parser.add_argument(
        "--watch-id",
        action="append",
        default=[],
        help="索引里必须单独列出的重点消息，可重复。默认 0207/1007/1008/100C/100F/8002/8028",
    )
    parser.add_argument(
        "--skip-final-audit",
        action="store_true",
        help="跳过重放数据的Live→Final规则改写审计",
    )
    args = parser.parse_args()

    output_root = args.output_root or Path(
        "01Compare_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    output_root = output_root.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    only_ids = {
        value
        for value in (parse_int(item) for item in args.message_id)
        if value is not None
    } or None
    watch_ids = {
        value
        for value in (parse_int(item) for item in args.watch_id)
        if value is not None
    } or set(DEFAULT_WATCH_IDS)
    baseline_label = args.baseline_label or safe_name(args.baseline)
    baseline = load_dataset(
        args.baseline,
        baseline_label,
        direction=args.direction,
        view=args.view_a,
    )

    summaries: list[dict] = []
    reviews: list[dict] = []
    for ordinal, observed_path in enumerate(args.observed, 1):
        observed_label = safe_name(observed_path)
        observed = load_dataset(
            observed_path,
            observed_label,
            direction=args.direction,
            view=args.view_b,
        )
        result = compare_datasets(
            baseline,
            observed,
            min_baseline_samples=args.min_baseline_samples,
            only_message_ids=only_ids,
        )
        folder = f"{ordinal:02d}_{safe_name(args.baseline)}_vs_{observed_label}_{args.view_b}"
        write_outputs(result, output_root / folder, top=args.top)
        reviews.append(result)
        summaries.append(result_summary(result, folder, watch_ids=watch_ids))

        kind, _paths = resolve_source(observed_path)
        if kind == "replay" and not args.skip_final_audit:
            live = load_dataset(
                observed_path,
                observed_label + "-Live",
                direction=args.direction,
                view="live",
            )
            final = load_dataset(
                observed_path,
                observed_label + "-Final",
                direction=args.direction,
                view="final",
            )
            audit = compare_datasets(
                live,
                final,
                min_baseline_samples=1,
                only_message_ids=only_ids,
            )
            audit_folder = f"{ordinal:02d}_{observed_label}_live_vs_final"
            write_outputs(audit, output_root / audit_folder, top=args.top)
            reviews.append(audit)
            summaries.append(result_summary(audit, audit_folder, watch_ids=watch_ids))

    write_index(output_root, summaries)
    write_ai_review(output_root, reviews)
    print(f"输出目录: {output_root}")
    print(f"AI审阅: {output_root / 'AI_REVIEW.md'}")
    print(f"对比任务: {len(summaries)}")
    for row in summaries:
        print(
            f"- {row['baseline']['label']} -> {row['observed']['label']}: "
            f"新增{len(row['new_ids'])} 缺失{len(row['missing_ids'])} "
            f"字段候选{len(row['top_field_anomalies'])}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
