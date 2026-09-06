#!/usr/bin/env python3
"""对比 01 重放叶子里的计数器。

用法：

    # 一场内部切点：407 前 vs 407 后（绘制段）
    python3 tools/compare_01_counters.py 数据/125.4/4 --cut 407

    # 多段：0-237 / 237-407 / 407-结束
    python3 tools/compare_01_counters.py 数据/125.4/4 --cut 237,407

    # 两场对照
    python3 tools/compare_01_counters.py 数据/125.4/3 数据/125.4/4

输入可以是 ``01_replace_events.jsonl``、``run_*`` 目录，或 ``数据/125.4/4`` 这种会话目录。
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

WATCH = (0x8028, 0x8002, 0x2001, 0x0207, 0x100C, 0x802C, 0x8007, 0x800D)
XOR_B6 = 0xB6
BLACKLIST_KEYS = (
    b"mtxdfm",
    b"com.mtx",
    b"dopamine",
    b"trollstore",
    b"sileo",
    b"zebra",
    b"filza",
    b"roothide",
    b"shadowrocket",
    b"appstoreplus",
)


def hx(value: object) -> bytes:
    try:
        return bytes.fromhex(str(value or "").replace(" ", ""))
    except ValueError:
        return b""


def parse_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def u32s(raw: bytes) -> list[tuple[int, int]]:
    if len(raw) < 0x24:
        return []
    body = raw[0x20:]
    out = []
    for index in range(0, len(body) - 3, 4):
        out.append((0x20 + index, struct.unpack(">I", body[index : index + 4])[0]))
    return out


def u32(raw: bytes, offset: int) -> int | None:
    if len(raw) >= offset + 4:
        return struct.unpack(">I", raw[offset : offset + 4])[0]
    return None


def ascii_runs(raw: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    cur: list[str] = []
    for byte in raw:
        if 32 <= byte < 127:
            cur.append(chr(byte))
            continue
        if len(cur) >= min_len:
            out.append("".join(cur))
        cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def resolve_events(path: Path) -> Path:
    if path.is_file():
        return path
    direct = path / "01_replace_events.jsonl"
    if direct.is_file():
        return direct
    found = [
        item
        for item in path.rglob("01_replace_events.jsonl")
        if "NeedsAIAnalysis" not in item.parts
    ]
    if not found:
        raise SystemExit(f"找不到 01_replace_events.jsonl: {path}")
    return max(found, key=lambda item: item.stat().st_mtime)


def load_leaves(path: Path) -> tuple[list[dict], list[dict]]:
    events_path = resolve_events(path)
    events = []
    leaves = []
    with events_path.open(encoding="utf-8-sig") as stream:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            events.append(event)
            ordinals = event.get("ordinals") or {}
            gt09 = ordinals.get("game_target_09")
            t09 = ordinals.get("target_09")
            for leaf in (event.get("shadow_rebuild") or {}).get("leaf_results") or []:
                live = hx(leaf.get("live_hex"))
                sent = hx(leaf.get("candidate_hex"))
                mid = parse_int(leaf.get("message_id"))
                if mid is None and len(live) >= 0x18:
                    mid = struct.unpack(">H", live[0x16:0x18])[0]
                names = ascii_runs(live) + ascii_runs(bytes(byte ^ XOR_B6 for byte in live))
                hits = [
                    key.decode()
                    for key in BLACKLIST_KEYS
                    if any(key.decode() in name.lower() for name in names)
                ]
                leaves.append(
                    {
                        "time": event.get("time") or "",
                        "t09": t09,
                        "gt09": gt09,
                        "mid": mid,
                        "length": leaf.get("length") or len(live),
                        "live": live,
                        "sent": sent,
                        "live_u32": u32s(live),
                        "sent_u32": u32s(sent),
                        "rule": leaf.get("special_rule_id") or "",
                        "level": leaf.get("replacement_level") or "",
                        "drop": bool(leaf.get("content_blacklist_hit")),
                        "token": leaf.get("content_blacklist_token") or "",
                        "names": names,
                        "hits": hits,
                    }
                )
    return events, leaves


def session_span(events: list[dict], leaves: list[dict]) -> dict:
    times = [event.get("time") for event in events if event.get("time")]
    gt09 = [item["gt09"] for item in leaves if item["gt09"] is not None]
    t09 = [item["t09"] for item in leaves if item["t09"] is not None]
    start = datetime.fromisoformat(times[0]) if times else None
    end = datetime.fromisoformat(times[-1]) if times else None
    game_id = ""
    for event in events:
        game_id = str(event.get("game_id") or "")
        if game_id:
            break
    return {
        "events": len(events),
        "leaves": len(leaves),
        "game_id": game_id,
        "start": times[0] if times else "",
        "end": times[-1] if times else "",
        "seconds": (end - start).total_seconds() if start and end else 0,
        "t09": (min(t09), max(t09)) if t09 else None,
        "gt09": (min(gt09), max(gt09)) if gt09 else None,
        "mids": sorted({item["mid"] for item in leaves if item["mid"] is not None}),
    }


def phase_of(gt09: int | None, cuts: list[int]) -> int:
    if gt09 is None or not cuts:
        return 0
    for index, cut in enumerate(cuts):
        if gt09 < cut:
            return index
    return len(cuts)


def field_sets(leaves: list[dict]) -> dict[tuple[int, int], set[int]]:
    out: dict[tuple[int, int], set[int]] = defaultdict(set)
    for leaf in leaves:
        if leaf["mid"] is None:
            continue
        for offset, value in leaf["live_u32"]:
            out[(leaf["mid"], offset)].add(value)
    return out


def dominant_step(values: set[int]) -> int | None:
    ordered = sorted(v for v in values if v >= 0)
    if len(ordered) < 3:
        return None
    gaps = [ordered[index] - ordered[index - 1] for index in range(1, len(ordered))]
    gaps = [gap for gap in gaps if gap > 0]
    if not gaps:
        return None
    counts = Counter(gaps)
    step, freq = counts.most_common(1)[0]
    if freq < max(2, len(gaps) // 2):
        return None
    return step


def is_clock(before: set[int], after: set[int]) -> bool:
    merged = before | after
    step = dominant_step(merged) or dominant_step(before)
    if not step:
        return False
    if step > 4 and len(before) < 3:
        return False
    before_max = max(before) if before else 0
    after_max = max(after) if after else 0
    if after_max < before_max:
        return False
    return after_max <= before_max + step * (len(after) + 8)


def classify_jump(
    before: set[int],
    after: set[int],
    *,
    mid: int | None = None,
) -> str | None:
    extra = after - before
    if not extra:
        return None
    if mid == 0:
        return None
    if is_clock(before, after):
        return None
    before_max = max(before) if before else 0
    after_max = max(after) if after else 0
    if before_max == 0 and after_max > 0:
        return f"0 -> {after_max}"
    if before_max <= 32 and after_max > 32:
        return f"{before_max} -> {after_max}"
    if extra and max(extra) >= 20 and after_max >= max(before_max * 2, before_max + 20):
        return f"+{max(extra)} (before_max={before_max})"
    return None


def print_span(label: str, span: dict) -> None:
    t09 = span["t09"]
    gt09 = span["gt09"]
    print(f"\n=== {label} ===")
    print(
        f"  {span['start']} -> {span['end']}  "
        f"{span['seconds']:.0f}s  events={span['events']}  leaves={span['leaves']}"
    )
    print(f"  game_id {span['game_id']}")
    if t09:
        print(f"  t09 {t09[0]}-{t09[1]}  gt09 {gt09[0]}-{gt09[1]}  mids={len(span['mids'])}")


def print_watch(leaves: list[dict], watch: tuple[int, ...]) -> None:
    print("\n=== 盯梢时间线 Live / 发出 ===")
    for mid in watch:
        rows = [item for item in leaves if item["mid"] == mid]
        if not rows:
            print(f"\n  {mid:#06x}  0 条")
            continue
        live24 = [u32(item["live"], 0x24) for item in rows]
        nonzero24 = [value for value in live24 if value]
        print(f"\n  {mid:#06x}  n={len(rows)}  +0x24非零={len(nonzero24)}")
        show = rows
        if mid == 0x2001 and not nonzero24 and len(rows) > 6:
            show = [rows[0], *rows[1:-1: max(1, len(rows) // 4)], rows[-1]]
            print("    +0x24 全程 0，只列首尾和间隔样本")
        for item in show:
            live = item["live"]
            sent = item["sent"]
            print(
                f"    {item['time'][11:19]}  t09={item['t09']!s:>4}  "
                f"gt09={item['gt09']!s:>4}  "
                f"L20={u32(live, 0x20)} L24={u32(live, 0x24)} L2C={u32(live, 0x2C)}  "
                f"S20={u32(sent, 0x20)} S24={u32(sent, 0x24)} S2C={u32(sent, 0x2C)}  "
                f"{item['rule']}"
            )


def print_blacklist(leaves: list[dict]) -> None:
    print("\n=== 黑名单 / 外挂进程 ===")
    hits = [
        item
        for item in leaves
        if item["drop"] or item["hits"] or item["token"]
    ]
    if not hits:
        print("  无")
        return
    for item in hits:
        names = [name for name in item["names"] if any(key.decode() in name.lower() for key in BLACKLIST_KEYS)]
        print(
            f"  {item['time'][11:19]}  t09={item['t09']}  gt09={item['gt09']}  "
            f"{item['mid']:#06x}  drop={item['drop']}  token={item['token'] or '-'}  "
            f"{names[:4]}"
        )


def compare_groups(groups: list[tuple[str, list[dict]]]) -> None:
    print("\n=== 切点后新亮的计数（已过滤序号/时钟） ===")
    found = False
    for index in range(1, len(groups)):
        left_name, left = groups[index - 1]
        right_name, right = groups[index]
        left_fields = field_sets(left)
        right_fields = field_sets(right)
        left_mids = {item["mid"] for item in left if item["mid"] is not None}
        right_mids = {item["mid"] for item in right if item["mid"] is not None}
        new_mids = sorted(
            mid
            for mid in right_mids - left_mids
            if mid
            and (
                mid in WATCH
                or 0x8000 <= mid <= 0x90FF
                or 0x1000 <= mid <= 0x1105
                or mid >= 0xFFF0
                or sum(1 for item in right if item["mid"] == mid) >= 2
            )
        )
        print(f"\n  [{left_name}] -> [{right_name}]")
        if new_mids:
            print("    新 messageId:", " ".join(f"{mid:#06x}" for mid in new_mids))
        else:
            print("    无新 messageId")
        keys = sorted(set(left_fields) | set(right_fields))
        local = False
        for mid, offset in keys:
            reason = classify_jump(
                left_fields.get((mid, offset), set()),
                right_fields.get((mid, offset), set()),
                mid=mid,
            )
            if not reason:
                continue
            local = True
            found = True
            before_vals = sorted(left_fields.get((mid, offset), set()))
            after_vals = sorted(right_fields.get((mid, offset), set()))
            print(
                f"    {mid:#06x} +0x{offset:02X}  {reason}  "
                f"前{before_vals[:8]}  后{after_vals[:8]}"
            )
        if not local:
            print("    无新跳变计数")
    if not found:
        print("\n  各切点都没有 0→非零 的新计数器。")


def compare_sessions(left: list[dict], right: list[dict], left_name: str, right_name: str) -> None:
    print(f"\n=== 两场对照 {left_name} vs {right_name} ===")
    left_mids = {item["mid"] for item in left if item["mid"] is not None}
    right_mids = {item["mid"] for item in right if item["mid"] is not None}
    only_right = sorted(right_mids - left_mids)
    only_left = sorted(left_mids - right_mids)
    print("  只在后者:", " ".join(f"{mid:#06x}" for mid in only_right) or "无")
    print("  只在前者:", " ".join(f"{mid:#06x}" for mid in only_left) or "无")
    left_fields = field_sets(left)
    right_fields = field_sets(right)
    print("\n  后者多出来的 0→非零 / 放大字段：")
    hits = 0
    for key in sorted(set(left_fields) | set(right_fields)):
        reason = classify_jump(
            left_fields.get(key, set()),
            right_fields.get(key, set()),
            mid=key[0],
        )
        if not reason:
            continue
        hits += 1
        mid, offset = key
        print(
            f"    {mid:#06x} +0x{offset:02X}  {reason}  "
            f"{left_name}{sorted(left_fields.get(key, set()))[:6]}  "
            f"{right_name}{sorted(right_fields.get(key, set()))[:6]}"
        )
    if not hits:
        print("    无")


def parse_cuts(text: str) -> list[int]:
    cuts = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        cuts.append(int(part, 16) if part.lower().startswith("0x") else int(part))
    return sorted(set(cuts))


def parse_watch(text: str | None) -> tuple[int, ...]:
    if not text:
        return WATCH
    mids = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        mids.append(int(part, 16) if part.lower().startswith("0x") else int(part))
    return tuple(mids)


def main() -> int:
    parser = argparse.ArgumentParser(description="对比 01 重放叶子计数器")
    parser.add_argument("paths", nargs="+", help="会话目录 / run_* / 01_replace_events.jsonl")
    parser.add_argument(
        "--cut",
        default="",
        help="按 game_target_09 切段，逗号分隔，例如 237,407",
    )
    parser.add_argument(
        "--watch",
        default="",
        help="时间线 messageId，默认 8028,8002,2001,0207,100C,802C,8007,800D",
    )
    args = parser.parse_args()
    cuts = parse_cuts(args.cut) if args.cut else []
    watch = parse_watch(args.watch)

    loaded = []
    for raw in args.paths:
        path = Path(raw)
        events, leaves = load_leaves(path)
        loaded.append((str(path), events, leaves))

    for label, events, leaves in loaded:
        print_span(label, session_span(events, leaves))
        print_watch(leaves, watch)
        print_blacklist(leaves)

    if cuts:
        if len(loaded) != 1:
            raise SystemExit("--cut 只用于单场内部对比")
        _, _, leaves = loaded[0]
        edges = [0, *cuts, None]
        groups = []
        for index in range(len(edges) - 1):
            low = edges[index]
            high = edges[index + 1]
            name = f"gt09 {low}-{high if high is not None else 'end'}"
            rows = [
                item
                for item in leaves
                if item["gt09"] is not None
                and item["gt09"] >= low
                and (high is None or item["gt09"] < high)
            ]
            groups.append((name, rows))
            print(f"\n  段 {name}: leaves={len(rows)} mids={len({item['mid'] for item in rows})}")
        compare_groups(groups)
    elif len(loaded) == 2:
        compare_sessions(loaded[0][2], loaded[1][2], loaded[0][0], loaded[1][0])
    elif len(loaded) > 2:
        for index in range(1, len(loaded)):
            compare_sessions(
                loaded[0][2],
                loaded[index][2],
                loaded[0][0],
                loaded[index][0],
            )
    else:
        print("\n提示: 加 --cut 407 做切点对比，或再传一场路径做两场对照。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
