#!/usr/bin/env python3
"""DFMProxy v1.121 Type9 热规则管理客户端（仅标准库）。"""

from __future__ import annotations

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def request_json(url: str, token: str, *, method: str = "GET", body=None) -> dict:
    data = None
    headers = {"X-Admin-Token": token, "Accept": "application/json"}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=15) as resp:
            raw = resp.read()
    except HTTPError as exc:
        raw = exc.read()
        try:
            detail = json.loads(raw.decode("utf-8"))
        except Exception:
            detail = raw.decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc
    return json.loads(raw.decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="查看、上传或重载Type9热规则")
    parser.add_argument("--url", default="http://127.0.0.1:8787")
    parser.add_argument("--token", required=True, help="config.json中的admin_token")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="查看当前内存规则")
    apply_parser = sub.add_parser("apply", help="校验、原子保存并立即激活JSON")
    apply_parser.add_argument("file")
    sub.add_parser("reload", help="重新读取服务器本地JSON")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    if args.command == "status":
        result = request_json(f"{base}/api/type9/rules", args.token)
    elif args.command == "reload":
        result = request_json(
            f"{base}/api/type9/rules/reload", args.token, method="POST", body={}
        )
    else:
        with open(args.file, "r", encoding="utf-8-sig") as handle:
            document = json.load(handle)
        result = request_json(
            f"{base}/api/type9/rules", args.token, method="POST", body=document
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
