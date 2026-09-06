"""把v1.128 AI日志运行目录打成可直接交给脚本/AI的ZIP。"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import zipfile
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.config import DATA_DIR
from core.ai_log_v128 import AI_LOG_DIR_NAME


def _latest_run(root: str) -> str | None:
    if not os.path.isdir(root):
        return None
    runs = [
        os.path.join(root, name)
        for name in os.listdir(root)
        if name.startswith("run_") and os.path.isdir(os.path.join(root, name))
    ]
    return max(runs, key=os.path.getmtime) if runs else None


def _row_identity(row: dict) -> tuple[str, str]:
    connection = row.get("connection") or {}
    user = str(row.get("proxy_username") or connection.get("proxy_username") or "")
    game_id = str(
        row.get("game_id")
        or row.get("live_game_id")
        or connection.get("game_id")
        or ""
    )
    return user, game_id


def _matches(row: dict, user: str, game_id: str) -> bool:
    row_user, row_game_id = _row_identity(row)
    return (not user or row_user == user) and (not game_id or row_game_id == game_id)


def _selected_event_ids(path: str, user: str, game_id: str) -> set[int]:
    selected: set[int] = set()
    if not os.path.isfile(path):
        return selected
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if _matches(row, user, game_id) and isinstance(row.get("event_id"), int):
                selected.add(int(row["event_id"]))
    return selected


def package(
    run_dir: str,
    output: str | None = None,
    *,
    user: str = "",
    game_id: str = "",
) -> str | None:
    run_dir = os.path.abspath(run_dir)
    files = []
    if os.path.isdir(run_dir):
        for base, _, names in os.walk(run_dir):
            for name in names:
                path = os.path.join(base, name)
                if (
                    os.path.isfile(path)
                    and os.path.getsize(path) > 0
                    and name != os.path.basename(output or "")
                    and (name == "manifest.json" or name.endswith(".jsonl"))
                ):
                    files.append(path)
    if not files:
        return None
    if output is None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scope_values = [
            re.sub(r"[^0-9A-Za-z._-]+", "_", value)[:80]
            for value in (user, game_id)
            if value
        ]
        scope = "_" + "_".join(scope_values) if scope_values else ""
        output = os.path.join(run_dir, f"DFMProxy_v128_AI_LOG{scope}_{stamp}.zip")

    if not user and not game_id:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(files):
                archive.write(path, os.path.relpath(path, run_dir))
        return output

    replay_ids = _selected_event_ids(
        os.path.join(run_dir, "replay_events.jsonl"), user, game_id
    )
    record_report_ids = _selected_event_ids(
        os.path.join(run_dir, "record_reports.jsonl"), user, game_id
    )
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            name = os.path.relpath(path, run_dir)
            if name == "manifest.json":
                archive.write(path, name)
                continue
            with open(path, encoding="utf-8") as source, archive.open(name, "w") as target:
                for line in source:
                    try:
                        row = json.loads(line)
                    except (json.JSONDecodeError, TypeError):
                        continue
                    keep = False
                    if name in {"replay_groups.jsonl", "replay_leaves.jsonl"}:
                        keep = row.get("event_id") in replay_ids
                    elif name == "record_leaves.jsonl":
                        keep = row.get("event_id") in record_report_ids
                    elif name == "markers.jsonl":
                        keep = True
                    else:
                        keep = _matches(row, user, game_id)
                    if keep:
                        target.write(line.encode("utf-8"))
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run_dir",
        nargs="?",
        help="AI日志/run_*；省略时选择最新一次",
    )
    parser.add_argument("-o", "--output", help="输出 ZIP 路径")
    parser.add_argument("--user", default="", help="只打包指定代理用户")
    parser.add_argument("--game-id", default="", help="只打包指定游戏ID")
    args = parser.parse_args()
    run_dir = args.run_dir or _latest_run(os.path.join(DATA_DIR, AI_LOG_DIR_NAME))
    if not run_dir:
        print(f"未找到 {AI_LOG_DIR_NAME}/run_* 目录")
        return 2
    output = package(
        run_dir,
        args.output,
        user=args.user,
        game_id=args.game_id,
    )
    if output is None:
        print(f"{run_dir} 中没有可打包的JSON/JSONL")
        return 0
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
