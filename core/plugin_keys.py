"""
插件 Key 存储：外部插件通过 HTTP API 注入 AES 会话密钥。
适用于 DH 密钥交换等无法从报文中直接提取 Key 的游戏（如三角洲）。

流程：
  1. 游戏建立 3366 连接 → 10 01 / 10 02 完成 DH 握手
  2. 插件从客户端内存读取协商出的 Key
  3. 插件 POST /api/plugin/key → 本模块存储
  4. 代理从本模块取 Key → 解密后续 40 13 帧
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime

from core.protocol_3366 import TAES_FIXED_IV

_DUMP_BASE = os.path.join(r"C:\PyProxyApp", "3366_dump")


class PluginKeyStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._keys: dict[str, dict] = {}
        # 01 通道 42B 握手包 a[16..17] 解析出的产品 ID（4 位 hex，如 0a92），无需等插件 POST Key
        self._game_hints: dict[str, str] = {}
        self._callbacks: list = []

    def set_key(
        self,
        client_ip: str,
        key_hex: str,
        game: str = "",
        uid: str = "",
    ) -> bool:
        try:
            key = bytes.fromhex(key_hex.replace(" ", ""))
        except ValueError:
            return False
        if len(key) != 16:
            return False
        with self._lock:
            self._keys[client_ip] = {
                "key": key,
                "iv": TAES_FIXED_IV,
                "game": game,
                "uid": uid,
                "ts": time.time(),
            }
            # 插件显式带上 game 时，与握手 hint 对齐（统一小写 4 位 hex）
            if game:
                self._game_hints[client_ip] = game.strip().lower()
        for cb in self._callbacks:
            try:
                cb(client_ip)
            except Exception:
                pass
        return True

    def get(self, client_ip: str) -> tuple[bytes, bytes] | None:
        with self._lock:
            info = self._keys.get(client_ip)
            return (info["key"], info["iv"]) if info else None

    def get_info(self, client_ip: str) -> dict | None:
        with self._lock:
            return dict(self._keys[client_ip]) if client_ip in self._keys else None

    def set_game_hint(self, client_ip: str, game: str) -> None:
        """由 01 握手等途径写入游戏/产品 ID（4 位 hex）。不与已注入的 Key 冲突。"""
        g = (game or "").strip().lower()
        if not g:
            return
        with self._lock:
            info = self._keys.get(client_ip)
            if info and (info.get("game") or "").strip():
                return
            self._game_hints[client_ip] = g

    def clear_game_hint(self, client_ip: str) -> None:
        """清除 set_game_hint 的提示；不影响已 POST 的插件 Key 及其 game 字段。"""
        with self._lock:
            self._game_hints.pop(client_ip, None)

    def get_game(self, client_ip: str) -> str:
        with self._lock:
            info = self._keys.get(client_ip)
            if info:
                g = (info.get("game") or "").strip()
                if g:
                    return g
            return self._game_hints.get(client_ip, "")

    def get_game_hint(self, client_ip: str) -> str:
        with self._lock:
            return self._game_hints.get(client_ip, "")

    def remove(self, client_ip: str):
        with self._lock:
            self._keys.pop(client_ip, None)
            self._game_hints.pop(client_ip, None)

    def all_keys(self) -> dict[str, dict]:
        with self._lock:
            return {k: dict(v) for k, v in self._keys.items()}

    def on_key_set(self, callback):
        self._callbacks.append(callback)


plugin_key_store = PluginKeyStore()


def dump_3366_frame(
    game: str,
    client_ip: str,
    direction: str,
    frame: bytes,
    info: dict | None,
    plain: bytes | None = None,
):
    """将 3366 原始帧（及可选明文）追加到 dump 日志，用于研究分析。"""
    if not game:
        return
    dump_dir = os.path.join(_DUMP_BASE, game)
    try:
        os.makedirs(dump_dir, exist_ok=True)
    except Exception:
        return
    safe_ip = client_ip.replace(":", "_")
    fname = f"session_{safe_ip}.log"
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    msg_h = info.get("msg_hex", "??") if info else "??"
    seq = info.get("seq", "?") if info else "?"
    d = "UP" if "UP" in direction else "DN"
    header = f"[{ts}] {d} msg={msg_h} seq={seq} len={len(frame)}"

    def _hex_block(raw: bytes, label: str = "") -> str:
        h = raw.hex().upper()
        lines = [h[i : i + 64] for i in range(0, len(h), 64)]
        tag = f"  [{label}]" if label else ""
        return tag + "\n".join(lines)

    entry = header + "\n" + _hex_block(frame, "cipher")
    if plain:
        entry += "\n" + _hex_block(plain, "plain")
    entry += "\n\n"
    try:
        with open(os.path.join(dump_dir, fname), "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass
