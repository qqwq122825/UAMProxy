"""
PyProxyApp Demo
==============
单 App 双端口 SOCKS5 代理：
  - 端口 1081 : 录制模式（无鉴权）
  - 端口 1080 : 重放模式（用户名/密码鉴权，账号从 users.json 加载）
  - 外部上游代理 SOCKS5（可选，含连通检测）
  - 用户管理：添加/删除账号、设置到期时间、持久化到 users.json
"""

import asyncio
import json
import os
import socket
import struct
import threading
import time
from datetime import datetime, date

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QGroupBox,
    QCheckBox, QSpinBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QStatusBar, QDateEdit, QMessageBox,
    QDialog, QFormLayout, QDialogButtonBox, QAbstractItemView, QFileDialog
)
from PySide6.QtCore import Qt, Signal, QObject, QDate, QTimer
from PySide6.QtGui import QColor, QFont, QTextCursor

# ─────────────────────────────────────────
# 路径常量
# 所有持久化数据统一存放在 C:\PyProxyApp\
# 打包为 EXE 后 BASE_DIR 是临时解压目录，必须用固定路径
# ─────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_DIR    = r"C:\PyProxyApp"          # 所有持久化文件的根目录
USERS_FILE  = os.path.join(DATA_DIR, "users.json")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

# ─────────────────────────────────────────
# 应用配置（持久化）
# ─────────────────────────────────────────
class AppConfig:
    """
    持久化界面配置到 C:\\PyProxyApp\\config.json。
    字段：
      port_record   : 录制端口（默认 1081）
      port_replay   : 重放端口（默认 1080）
      ext_enabled   : 是否启用外部代理（默认 False）
      ext_ip        : 外部代理 IP（默认 127.0.0.1）
      ext_port      : 外部代理端口（默认 8889）
    """
    _DEFAULTS = {
        "port_record": 1081,
        "port_replay": 1080,
        "ext_enabled": False,
        "ext_ip":      "127.0.0.1",
        "ext_port":    8889,
        "detail_01_log": False,  # 详细 01 替换日志（原始+替换后完整 Hex）
    }

    def __init__(self, path: str = CONFIG_FILE):
        self.path = path
        self._data: dict = dict(self._DEFAULTS)
        self.load()

    def load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                # 只覆盖已知字段，保留默认值作为兜底
                for k, v in saved.items():
                    if k in self._DEFAULTS:
                        self._data[k] = v
        except Exception:
            pass  # 读取失败静默降级为默认值

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass  # 写入失败不影响运行

    def get(self, key: str):
        return self._data.get(key, self._DEFAULTS.get(key))

    def set(self, key: str, value):
        if key in self._DEFAULTS:
            self._data[key] = value


app_config = AppConfig()

# ─────────────────────────────────────────
# 本地重放管理（域名 → 本地文件映射）
# ─────────────────────────────────────────
class LocalMapManager:
    """
    持久化域名→本地文件映射到 C:\\PyProxyApp\\local_map.json。
    当 SOCKS5 代理收到对应域名的 HTTP:80 请求时，直接用本地文件
    内容作响应，不访问真实服务器（类似 Fiddler 的 Map Local 功能）。
    """
    def __init__(self, path: str = os.path.join(DATA_DIR, "local_map.json")):
        self.path = path
        self._map: dict = {}
        self.load()

    def load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    self._map = json.load(f)
        except Exception:
            self._map = {}

    def save(self):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._map, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    @staticmethod
    def _normalize(domain: str) -> str:
        domain = domain.strip().lower()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        return domain.split("/")[0].split(":")[0]

    def add(self, domain: str, filepath: str):
        key = self._normalize(domain)
        if key:
            self._map[key] = filepath
            self.save()

    def remove(self, domain: str):
        self._map.pop(self._normalize(domain), None)
        self.save()

    def get_file(self, host: str) -> str | None:
        """按域名查找本地文件路径，自动互转 www. 前缀。"""
        host = host.lower().split(":")[0]
        if host in self._map:
            return self._map[host]
        alt = host[4:] if host.startswith("www.") else "www." + host
        return self._map.get(alt)

    def items(self) -> list:
        return list(self._map.items())

    def clear(self):
        self._map.clear()
        self.save()


local_map_manager = LocalMapManager()

# ─────────────────────────────────────────
# 用户管理（持久化）
# ─────────────────────────────────────────
class UserManager:
    """
    users.json 格式：
    [
      {"username": "alice", "password": "123456", "expire": "2099-12-31", "note": "管理员"},
      ...
    ]
    expire = "never" 表示永不过期
    """
    def __init__(self, path: str = USERS_FILE):
        self.path = path
        self._users: list[dict] = []
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self._users = json.load(f)
            except Exception:
                self._users = []
        else:
            # 默认添加一个 test 账号方便初次测试
            self._users = [
                {"username": "test", "password": "123456", "expire": "never", "note": "默认账号"}
            ]
            self.save()

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._users, f, ensure_ascii=False, indent=2)

    def all(self) -> list[dict]:
        return list(self._users)

    def add(self, username: str, password: str, expire: str = "never",
            note: str = "", allow_multi: bool = False) -> bool:
        """返回 False 表示用户名已存在"""
        if any(u["username"] == username for u in self._users):
            return False
        self._users.append({"username": username, "password": password,
                             "expire": expire, "note": note,
                             "allow_multi": allow_multi})
        self.save()
        return True

    def remove(self, username: str):
        self._users = [u for u in self._users if u["username"] != username]
        self.save()

    def update_password(self, username: str, new_pass: str):
        for u in self._users:
            if u["username"] == username:
                u["password"] = new_pass
                break
        self.save()

    def to_dict(self) -> dict[str, str]:
        """返回 {username: password} 用于代理鉴权（过期账号会被过滤）"""
        today = date.today().isoformat()
        result = {}
        for u in self._users:
            exp = u.get("expire", "never")
            if exp == "never" or exp >= today:
                result[u["username"]] = u["password"]
        return result

    def is_expired(self, username: str) -> bool:
        today = date.today().isoformat()
        for u in self._users:
            if u["username"] == username:
                exp = u.get("expire", "never")
                return exp != "never" and exp < today
        return True

    def get_allow_multi(self, username: str) -> bool:
        """是否允许同账户多 IP 同时在线（默认 False）"""
        for u in self._users:
            if u["username"] == username:
                return bool(u.get("allow_multi", False))
        return False

    def set_allow_multi(self, username: str, value: bool):
        for u in self._users:
            if u["username"] == username:
                u["allow_multi"] = value
                break
        self.save()


user_manager = UserManager()


# ─────────────────────────────────────────
# 全局事件总线
# ─────────────────────────────────────────
class LogBus(QObject):
    # 业务事件日志（显示在系统日志 Tab）
    event_log  = Signal(str, str, str)   # (level, tag, message)
    # 连接状态
    conn_added = Signal(str, str, str, str, str)   # (conn_id, src, dst, user, mode)
    conn_closed= Signal(str)                   # conn_id
    # Hex 数据（只显示在 Hex Tab）
    hex_data   = Signal(str, str, str, int)   # (conn_id, direction, hex_str, length)
    # 录制池结构变化（新会话/停止/游戏ID就绪）→ 全量刷新录制管理 Tab
    record_updated = Signal()
    # 录制计数轻量更新（每包）→ 只更新对应行的"加密区数"列，不重建表
    record_count   = Signal(str, int)          # (sid, pool_count)
    # 重放连接详情日志（每条替换记录）→ 详情对话框
    conn_detail    = Signal(str, str)          # (client_ip, log_line)
    # 重放进度更新 → 连接表"重放进度"列
    replay_progress = Signal(str, int, int)    # (client_ip, current_idx, total)
    # 连接模式更新 → 连接表"模式"列（"重放(待验证)" / "重放" / "透传"）
    conn_mode_update = Signal(str, str)        # (client_ip, mode_text)

log_bus = LogBus()


def _event(level: str, tag: str, msg: str):
    """业务事件日志，会显示在系统日志 Tab（不含原始 Hex）"""
    log_bus.event_log.emit(level, tag, msg)


def _fmt_dur(seconds: int) -> str:
    """将秒数格式化为可读时长：刚刚 / Xm / Xh Ym"""
    if seconds < 60:
        return "刚刚"
    m = seconds // 60
    if m < 60:
        return f"{m}分"
    h, rm = divmod(m, 60)
    return f"{h}小时{rm}分" if rm else f"{h}小时"


# ─────────────────────────────────────────
# 录制内存池（1081 写入，1080 读取）
# ─────────────────────────────────────────
class RecordingPool:
    """
    按客户端 IP + 游戏ID 存储录制的 01 00 反作弊数据包。
    同一 IP 可以有多条录制（不同游戏账号），互不覆盖。
    1081 录制端口静默写入；1080 重放端口按游戏ID选择匹配的会话进行重放。

    内部结构：
      _sessions: {ip: [session, ...]}
      session:   {"sid": str, "pkts": [bytes], "active": bool,
                  "game_id": str, "created_at": float}
      sid 格式："{ip}#{idx}"（唯一标识一条录制会话）
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict[str, list[dict]] = {}   # ip → [session, ...]

    # ── 内部工具 ─────────────────────────────
    def _active_session(self, client_ip: str) -> dict | None:
        """返回该 IP 当前活跃的录制会话（最后一条 active=True），否则 None"""
        for s in reversed(self._sessions.get(client_ip, [])):
            if s.get("active"):
                return s
        return None

    def _stop_active(self, client_ip: str) -> tuple[int, str]:
        """停止该 IP 的活跃会话，返回 (包数, 游戏ID)"""
        s = self._active_session(client_ip)
        if s:
            s["active"] = False
            return len(s["pkts"]), s.get("game_id", "")
        return 0, ""

    @staticmethod
    def _build_pool(pkts: list[bytes]) -> list[dict]:
        pool = []
        for raw in pkts:
            for sub in _ace_split_packets(raw):
                item = _ace_try_extract(sub)
                if item:
                    pool.append(item)
        return pool

    @staticmethod
    def _session_pool(s: dict) -> list[dict]:
        """
        从 session 中获取 pool items 的引用（保证录制追加时重放能实时看到）。
        兼容两种存储格式：
        · 录制会话（实时）：动态维护 pool_items
        · 导入会话（v4）：直接返回 pool_items
        """
        if "pool_items" not in s:
            s["pool_items"] = RecordingPool._build_pool(s.get("pkts", []))
            s["_pool_count"] = len(s["pool_items"])
        return s["pool_items"]

    # ── 录制侧 API ───────────────────────────
    def new_session(self, client_ip: str) -> bool:
        """
        1081 新连接时调用。
        · 已有活跃会话 → 共享（引用计数 +1），返回 False。
        · 无活跃会话 → 创建新会话，返回 True。
        注意：此时仅为“幽灵会话”，不触发 UI 刷新，直到 append() 收到真实游戏ID才转正。
        """
        with self._lock:
            active = self._active_session(client_ip)
            if active:
                active["_refs"] = active.get("_refs", 1) + 1
                return False
            sessions = self._sessions.setdefault(client_ip, [])
            sid = f"{client_ip}#{int(time.time())}"
            sessions.append({"sid": sid, "pkts": [], "active": True,
                              "game_id": "", "created_at": time.time(),
                              "pool_items": [], "_pool_count": 0,
                              "_refs": 1, "_ghost": True})
        return True

    def append(self, client_ip: str, data: bytes):
        """录制一个 01 00 开头的包，追加到当前活跃会话。
        · 新增加密区时：发出轻量 record_count(sid, count) 信号（每包实时）
        · 首次识别游戏ID时：
            - 取消“幽灵”状态，使其可被 UI 显示
            - 若同 IP 下已有相同游戏ID的旧会话 → 删除旧会话（替换逻辑）
            - 若不同游戏ID → 保留旧会话（共存逻辑）
            - 发出 record_updated 全量刷新信号
        """
        emit_full   = False
        count_info: tuple | None = None
        replaced_info: tuple | None = None   # (game_id, old_count) 替换时记录
        with self._lock:
            s = self._active_session(client_ip)
            if s:
                s["pkts"].append(bytes(data))
                new_items = []
                for sub in _ace_split_packets(data):
                    item = _ace_try_extract(sub)
                    if item:
                        new_items.append(item)
                if new_items:
                    pool = RecordingPool._session_pool(s)
                    pool.extend(new_items)
                    s["_pool_count"] = len(pool)
                    if not s.get("_ghost"):
                        count_info = (s["sid"], s["_pool_count"])
                if not s["game_id"]:
                    gid = _parse_ace_account_id(data)
                    if gid:
                        s["game_id"] = gid
                        s["_ghost"] = False  # 成功识别出游戏 ID，正式转正
                        emit_full = True
                        # 查找同 IP 下相同游戏ID的旧非活跃会话
                        # 只有当没有任何活跃的重放连接（即不在边录边播状态）时，
                        # 新录制才替换旧录制；如果在边录边播中（重放端口活跃），则追加（共存）
                        has_active_replay = False
                        try:
                            # 访问全局变量 engine 中的重放连接状态
                            if engine.server_1080:
                                # 检查 _user_active_conns 中是否有当前 IP 的活跃重放连接
                                for uname, ip_map in engine.server_1080._user_active_conns.items():
                                    if client_ip in ip_map and ip_map[client_ip]:
                                        has_active_replay = True
                                        break
                        except Exception:
                            pass
                            
                        if not has_active_replay:
                            sessions = self._sessions.get(client_ip, [])
                            dups = [o for o in sessions
                                    if o is not s and not o.get("active")
                                    and o.get("game_id") == gid]
                            if dups:
                                old_cnt = sum(
                                    o.get("_pool_count") or len(self._session_pool(o))
                                    for o in dups)
                                sessions[:] = [o for o in sessions if o not in dups]
                                replaced_info = (gid, old_cnt)
        if replaced_info:
            gid, old_cnt = replaced_info
            _event("RECORD", "录制",
                   f"[{client_ip}] 游戏ID=[{gid}] 已存在旧录制（{old_cnt}个加密区），已替换为新录制")
        if emit_full:
            log_bus.record_updated.emit()
        elif count_info:
            log_bus.record_count.emit(*count_info)

    def stop(self, client_ip: str, force: bool = False) -> tuple[int, str]:
        """
        连接断开时调用，引用计数 -1；只有当引用计数归零或 force=True 时才真正停止。
        返回 (总包数, 游戏ID)；若仍有其他连接在用则返回 (0, "")。
        如果会话断开时仍未识别出游戏ID（即一直是幽灵会话），则直接丢弃。
        """
        discarded_ghost = False
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return 0, ""
            if not force:
                refs = s.get("_refs", 1) - 1
                s["_refs"] = refs
                if refs > 0:
                    return 0, ""   # 还有其他连接在使用本会话
            
            s["active"] = False
            result = len(s["pkts"]), s.get("game_id", "")
            
            # 如果断开时仍然是幽灵会话（没拿到游戏ID），静默删除
            if s.get("_ghost"):
                sessions = self._sessions.get(client_ip, [])
                if s in sessions:
                    sessions.remove(s)
                discarded_ghost = True

        if not discarded_ghost:
            log_bus.record_updated.emit()
        return result if not discarded_ghost else (0, "")

    def count(self, client_ip: str) -> int:
        """当前活跃会话的包数（用于 SESSION 日志）"""
        with self._lock:
            s = self._active_session(client_ip)
            return len(s["pkts"]) if s else 0

    def game_id(self, client_ip: str) -> str:
        """当前活跃会话的游戏ID"""
        with self._lock:
            s = self._active_session(client_ip)
            return s.get("game_id", "") if s else ""

    # ── 重放侧 API ───────────────────────────
    def has_any_data(self, client_ip: str) -> bool:
        """该 IP 是否有任意非空的、有效（非幽灵）的录制会话（含活跃中）"""
        with self._lock:
            return any(s.get("pkts") and not s.get("_ghost") for s in self._sessions.get(client_ip, []))

    def get_all_ip_pools(self, client_ip: str) -> dict[str, list[dict]]:
        """
        返回该 IP 所有会话（包含活跃录制中的）的重放池，按游戏ID索引。
        返回的是 pool_items 列表的引用，录制端 append() 时重放端可实时生效。
        忽略仍处于“幽灵”状态的会话。
        """
        with self._lock:
            result: dict[str, list[dict]] = {}
            for s in self._sessions.get(client_ip, []):
                if s.get("_ghost"):
                    continue
                pool = self._session_pool(s)
                if not pool:
                    continue
                gid = s.get("game_id", "") or s["sid"].replace(":", "_")
                if gid not in result or len(pool) > len(result[gid]):
                    result[gid] = pool
        return result

    # ── 录制管理 Tab API ─────────────────────
    def get_extracted_payloads(self, sid: str) -> list[bytes]:
        """返回指定会话（sid）的 0A 00 09 加密区列表（供 UI 展示）"""
        with self._lock:
            ip = sid.rsplit("#", 1)[0]
            for s in self._sessions.get(ip, []):
                if s["sid"] == sid:
                    pool = self._session_pool(s)
                    return [item.get("payload") or b"" for item in pool]
        return []

    def get_all_sessions(self) -> list[dict]:
        """
        返回所有会话的摘要列表，供录制管理 Tab 全量刷新。
        过滤掉“幽灵”会话（还没识别出游戏ID的无效连接）。
        """
        with self._lock:
            result = []
            for ip, sessions in self._sessions.items():
                for s in sessions:
                    if s.get("_ghost"):
                        continue
                    cached = s.get("_pool_count")
                    if cached is None:
                        pool = self._session_pool(s)
                        cached = len(pool)
                        s["_pool_count"] = cached
                    gid = s.get("game_id", "")
                    result.append({
                        "sid":    s["sid"],
                        "ip":     ip,
                        "game_id": gid,
                        "count":  cached,
                        "active": s.get("active", False),
                    })
            return result

    def cleanup_expired(self, max_age_seconds: float = 86400.0):
        """删除超过 max_age_seconds 的非活跃会话"""
        now = time.time()
        changed = False
        with self._lock:
            for ip, sessions in list(self._sessions.items()):
                kept = [s for s in sessions
                        if s.get("active") or
                           (now - s.get("created_at", now)) <= max_age_seconds]
                if len(kept) < len(sessions):
                    changed = True
                    if kept:
                        self._sessions[ip] = kept
                    else:
                        del self._sessions[ip]
        if changed:
            log_bus.record_updated.emit()

    def export_to_file(self, path: str) -> tuple[bool, str]:
        """
        导出所有会话为 JSON（v4 格式）。
        只存储提取好的 pool items（payload/crc/routing/account_id），
        不保留原始 01 包，文件更小、可读性更高。
        """
        try:
            with self._lock:
                data: dict[str, list] = {}
                for ip, sessions in self._sessions.items():
                    ip_list = []
                    for s in sessions:
                        if s.get("_ghost"):
                            continue
                        pool = self._session_pool(s)
                        pool_export = [
                            {
                                "payload":    item["payload"].hex(),
                                "crc":        (item.get("crc") or b"").hex(),
                                "routing":    (item.get("routing") or b"\x00").hex(),
                                "account_id": item.get("account_id") or "",
                            }
                            for item in pool
                        ]
                        ip_list.append({
                            "sid":        s["sid"],
                            "game_id":    s.get("game_id", ""),
                            "active":     False,
                            "created_at": s.get("created_at", time.time()),
                            "pool_items": pool_export,
                        })
                    if ip_list:
                        data[ip] = ip_list
            payload = {"version": 4, "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "sessions": data}
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            total_s = sum(len(v) for v in data.values())
            total_p = sum(len(s["pool_items"]) for v in data.values() for s in v)
            return True, f"已导出 {len(data)} 个 IP，{total_s} 条会话，共 {total_p} 个加密区 → {path}"
        except Exception as ex:
            return False, f"导出失败: {ex}"

    def import_from_file(self, path: str, overwrite: bool = False) -> tuple[bool, str]:
        """
        从 JSON 文件导入。
        支持所有历史格式：
          v4 ： pool_items（新格式，只含加密区）
          v2/v3：pkts（旧格式，含原始 01 包，自动转换为 pool_items）
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            version  = payload.get("version", 2)
            raw_data = payload.get("sessions", {})
            imported = skipped = 0
            with self._lock:
                for ip, val in raw_data.items():
                    if isinstance(val, dict):
                        val = [val]   # v2 兼容
                    existing     = self._sessions.setdefault(ip, [])
                    existing_sids = {s["sid"] for s in existing}
                    for item in val:
                        sid = item.get("sid") or f"{ip}#{len(existing)}"
                        if sid in existing_sids and not overwrite:
                            skipped += 1
                            continue
                        if overwrite:
                            existing[:] = [s for s in existing if s["sid"] != sid]

                        if "pool_items" in item:
                            # v4：直接恢复 pool items
                            pool_items = [
                                {
                                    "payload":    bytes.fromhex(pi["payload"]),
                                    "crc":        bytes.fromhex(pi.get("crc", "")),
                                    "routing":    bytes.fromhex(pi.get("routing", "00")),
                                    "account_id": pi.get("account_id", ""),
                                }
                                for pi in item["pool_items"]
                            ]
                            new_s = {
                                "sid":        sid,
                                "game_id":    item.get("game_id", ""),
                                "active":     False,
                                "created_at": item.get("created_at", time.time()),
                                "pool_items": pool_items,
                                "_pool_count": len(pool_items),
                            }
                        else:
                            # v2/v3：原始 pkts，导入时转换为 pool_items
                            raw_pkts = [bytes.fromhex(p) for p in item.get("pkts", [])]
                            pool_items = self._build_pool(raw_pkts)
                            new_s = {
                                "sid":        sid,
                                "game_id":    item.get("game_id", ""),
                                "active":     False,
                                "created_at": item.get("created_at", time.time()),
                                "pool_items": pool_items,
                                "_pool_count": len(pool_items),
                            }
                        existing.append(new_s)
                        imported += 1
            log_bus.record_updated.emit()
            msg = f"导入完成：{imported} 条会话"
            if skipped:
                msg += f"，跳过已有 {skipped} 条"
            return True, msg
        except Exception as ex:
            return False, f"导入失败: {ex}"


recording_pool = RecordingPool()


# ─────────────────────────────────────────
# ACE 0x01 录制/重放辅助（来自 ACE_RecordHelper.cs）
# ─────────────────────────────────────────
MARKER_0A0009 = b"\x0A\x00\x09"


def _ace_split_packets(buffer: bytes) -> list[bytes]:
    """按 0x01 子包拆分，a[3..4] 大端为包长"""
    out = []
    pos = 0
    while pos + 5 <= len(buffer):
        if buffer[pos] != 0x01:
            pos += 1
            continue
        ln = (buffer[pos + 3] << 8) | buffer[pos + 4]
        if ln < 5 or pos + ln > len(buffer):
            ln = len(buffer) - pos
            if ln < 5:
                break
        out.append(bytes(buffer[pos : pos + ln]))
        pos += ln
    return out


def _ace_index_of(data: bytes, pattern: bytes) -> int:
    for i in range(len(data) - len(pattern) + 1):
        if data[i : i + len(pattern)] == pattern:
            return i
    return -1


def _ace_try_extract(packet: bytes) -> dict | None:
    """
    从 0x01 包提取 0A 00 09 段：payload、CRC、routing、account_id。
    返回 {"payload", "crc", "routing", "account_id"} 或 None。
    """
    if len(packet) < 102:
        return None
    data_pos = _ace_index_of(packet, MARKER_0A0009)
    if data_pos < 0:
        return None
    payload_start = data_pos + 3
    if payload_start >= len(packet):
        return None
    payload = bytes(packet[payload_start:])
    crc = bytes(packet[40:44])
    routing = bytes([packet[47]])
    account_id = _parse_ace_account_id(packet)
    return {"payload": payload, "crc": crc, "routing": routing, "account_id": account_id}


def _ace_try_replace(packet: bytes, pool: list[dict], pool_index: list,
                     on_log=None) -> tuple[bytes, bool]:
    """
    用池中数据替换包内 0A 00 09 段。
    pool_index: [int] 单元素列表，会被原地修改。
    返回 (替换后的包, 是否发生了替换)。
    on_log(msg, detail_dict) 可选，detail_dict 含替换详情供详情对话框显示。
    """
    if not pool or len(packet) < 102:
        return packet, False
    data_pos = _ace_index_of(packet, MARKER_0A0009)
    if data_pos < 0:
        return packet, False

    idx = pool_index[0] % len(pool)
    item = pool[idx]
    pool_index[0] += 1  # 保持绝对递增，当 pool 动态扩展时能自然顺延到新数据

    replace_start = data_pos + 3
    orig_len = len(packet) - replace_start
    new_payload = item.get("payload") or b""
    if not new_payload:
        return packet, False

    if len(new_payload) > orig_len:
        new_buf = bytearray(len(packet) + (len(new_payload) - orig_len))
    elif len(new_payload) < orig_len:
        new_buf = bytearray(len(packet) - (orig_len - len(new_payload)))
    else:
        new_buf = bytearray(len(packet))

    new_buf[:replace_start] = packet[:replace_start]
    new_buf[replace_start : replace_start + len(new_payload)] = new_payload

    # 更新总长度 a[3..4]
    total = len(new_buf)
    new_buf[3] = (total >> 8) & 0xFF
    new_buf[4] = total & 0xFF
    # 更新 CRC a[40..43] 和 routing a[47]
    if len(new_buf) >= 44:
        new_buf[40:44] = item.get("crc", b"\0\0\0\0")[:4].ljust(4, b"\0")
    if len(new_buf) >= 48:
        new_buf[47] = item.get("routing", b"\0")[0] if item.get("routing") else 0

    # 分段长度等（简化版，主项目有 UpdateTotalLengths）
    if len(new_buf) > 55:
        seg_a = len(new_buf) - 55
        new_buf[53] = (seg_a >> 8) & 0xFF
        new_buf[54] = seg_a & 0xFF
        if len(new_buf) >= 61:
            new_buf[59] = new_buf[53]
            new_buf[60] = new_buf[54]

    # 更新 Segment B（0A 00 09 之后的部分）的相关长度
    if len(new_buf) > 78:
        id_len = new_buf[78]
        if 0 < id_len <= 64:
            seg_b_start = 78 + id_len + 3
            if seg_b_start < len(new_buf):
                seg_b_len = len(new_buf) - seg_b_start
                pos1 = 78 + id_len + 1
                pos2 = 78 + id_len + 7
                if pos1 + 1 < len(new_buf):
                    new_buf[pos1] = (seg_b_len >> 8) & 0xFF
                    new_buf[pos1 + 1] = seg_b_len & 0xFF
                if pos2 + 1 < len(new_buf):
                    new_buf[pos2] = (seg_b_len >> 8) & 0xFF
                    new_buf[pos2 + 1] = seg_b_len & 0xFF

    detail = {
        "pool_idx": idx,
        "pool_total": len(pool),
        "orig_payload_len": orig_len,
        "new_payload_len": len(new_payload),
        "orig_pkt_len": len(packet),
        "new_pkt_len": len(new_buf),
        "crc_hex": (item.get("crc") or b"").hex().upper(),
        "routing_hex": (item.get("routing") or b"\0")[:1].hex().upper(),
        "account_id": item.get("account_id", ""),
        "payload_preview": new_payload[:64],  # 前64字节预览
        "orig_packet": bytes(packet),
        "new_packet": bytes(new_buf),
    }
    if on_log:
        on_log(detail)
    return bytes(new_buf), True


# ─────────────────────────────────────────
# 游戏账号 ID 提取（来自 ACE_RecordHelper.cs 算法）
# ─────────────────────────────────────────
def _parse_ace_account_id(data: bytes) -> str:
    """
    从 ACE 0x01 包中提取游戏账号 ID。
    算法来源：ACE_RecordHelper.cs TryParseAccountId()
      - 包内找到 0A 00 23 标记
      - packet[78] = ID 字节长度
      - packet[79 .. 79+len] = ASCII 账号字符串
    返回空字符串表示未找到。
    """
    MARKER = b"\x0A\x00\x23"
    if len(data) < 80:
        return ""
    if MARKER not in data:
        return ""
    id_len = data[78]
    if id_len <= 0 or id_len > 64:
        return ""
    if 79 + id_len > len(data):
        return ""
    try:
        account_id = data[79:79 + id_len].decode("ascii", errors="replace").rstrip("\x00").strip()
        return account_id
    except Exception:
        return ""


# ─────────────────────────────────────────
# SOCKS5 代理核心
# ─────────────────────────────────────────
class Socks5Server:
    def __init__(self, port: int, auth_required: bool = False,
                 users: dict = None, external_proxy=None, label: str = "",
                 mode: str = "", tool_auth_ok: bool = False, tool_debug: bool = False):
        """
        mode: "record"  → 1081 录制端口，静默录制 01 00 包
              "replay"  → 1080 重放端口，用户上线时检查录制池
              ""        → 普通代理
        """
        self.port = port
        self.auth_required = auth_required
        self.users = users or {}
        self.external_proxy = external_proxy
        self.label = label
        self.mode  = mode
        self.tool_auth_ok = tool_auth_ok
        self.tool_debug = tool_debug
        self._server = None
        # 重放模式：每连接一个池索引 conn_id -> [pool_index, replace_count]
        self._replay_index: dict[str, list] = {}
        # 选定后的重放池（发现游戏ID后按游戏ID选定）conn_id -> [RecordedItem]
        self._replay_pools: dict[str, list] = {}
        # 该 IP 所有录制会话的池快照，发现游戏ID后用于匹配 conn_id -> {game_id: pool}
        self._replay_all_pools: dict[str, dict] = {}
        # 是否已完成游戏 ID 匹配（每连接仅执行一次）
        self._replay_gid_checked: dict[str, bool] = {}
        # 流重组缓冲区：应对 TCP 分包（一个 01 包拆成多次 read）conn_id -> bytearray
        self._stream_bufs: dict[str, bytearray] = {}
        # 多开控制：username → 当前活跃的 conn_id 集合
        self._user_active_conns: dict[str, set[str]] = {}
        # conn_id → client StreamWriter（用于踢人时强制断开）
        self._conn_client_writers: dict[str, "asyncio.StreamWriter"] = {}

        # 统计
        self._total_conns   = 0
        self._active_conns  = 0
        self._total_up_pkts = 0
        self._total_dn_pkts = 0

    async def start(self):
        self._server = await asyncio.start_server(
            self.handle_client, "0.0.0.0", self.port
        )
        _event("INFO", self.label, f"监听 0.0.0.0:{self.port}  鉴权={self.auth_required}")
        async with self._server:
            await self._server.serve_forever()

    def stop(self):
        if self._server:
            self._server.close()
        _event("INFO", self.label, "服务已停止")

    async def handle_client(self, reader, writer):
        addr      = writer.get_extra_info("peername")
        client_ip = addr[0]
        conn_id   = f"{client_ip}:{addr[1]}"
        username  = "Anonymous"
        self._total_conns  += 1
        self._active_conns += 1

        # ── 工具层鉴权控制 ────────────────────────
        actual_mode = self.mode
        if actual_mode in ("record", "replay") and not self.tool_auth_ok:
            if self.tool_debug:
                _event("DEBUG", "Auth", f"[{client_ip}] 未输入正确授权码，[{actual_mode}] 模式降级为透传")
            actual_mode = "pass"

        # ── 录制端口：新连接时加入（或新建）录制会话 ──────────────
        _rec_joined = False   # 标记本连接是否已向 recording_pool 注册（需要配对 stop）
        if actual_mode == "record":
            is_new = recording_pool.new_session(client_ip)
            _rec_joined = True
            if is_new:
                _event("RECORD", self.label, f"[{client_ip}] 开始录制会话")
            # is_new=False 时：共享已有活跃会话，不重复打印日志

        try:
            # ① 握手
            hdr = await reader.readexactly(2)
            if hdr[0] != 5:
                return
            methods = await reader.readexactly(hdr[1])

            if self.auth_required:
                if 0x02 not in methods:
                    writer.write(b"\x05\xff"); await writer.drain()
                    return
                writer.write(b"\x05\x02")
            else:
                writer.write(b"\x05\x00")
            await writer.drain()

            # ② 鉴权
            if self.auth_required:
                av = await reader.readexactly(1)
                if av[0] != 0x01:
                    return
                ulen   = (await reader.readexactly(1))[0]
                uname  = (await reader.readexactly(ulen)).decode("utf-8", errors="replace")
                plen   = (await reader.readexactly(1))[0]
                passwd = (await reader.readexactly(plen)).decode("utf-8", errors="replace")

                username = uname
                if self.users.get(uname) == passwd:
                    writer.write(b"\x01\x00"); await writer.drain()

                    # ── 多开控制 ─────────────────────────────────────
                    # 结构：{username: {ip: {conn_id, ...}}}
                    # 同 IP 的并发连接（游戏服+ACE服）属于同一次登录，允许共存；
                    # 只有来自不同 IP 的连接才视为"多开"。
                    allow_multi = user_manager.get_allow_multi(uname)
                    ip_map = self._user_active_conns.setdefault(uname, {})
                    other_ips = {ip: cids for ip, cids in ip_map.items()
                                 if ip != client_ip}
                    if other_ips and not allow_multi:
                        kicked = 0
                        for old_ip, old_cids in other_ips.items():
                            for old_cid in old_cids:
                                old_w = self._conn_client_writers.pop(old_cid, None)
                                if old_w:
                                    try:
                                        old_w.close()
                                    except Exception:
                                        pass
                                kicked += 1
                            ip_map.pop(old_ip, None)
                        if kicked:
                            _event("WARN", self.label,
                                   f"[{uname}] 不允许多开，踢出其他 IP 的旧连接 {kicked} 个"
                                   f"  新来源={conn_id}")

                    # 是否是该 IP 本次会话的第一条连接（后续并发连接不重复打上线日志）
                    is_first_conn = client_ip not in ip_map

                    # 注册本次连接（同 IP 可并发多条）
                    ip_map.setdefault(client_ip, set()).add(conn_id)
                    self._conn_client_writers[conn_id] = writer

                    if is_first_conn:
                        _event("AUTH_OK", self.label,
                               f"用户 [{uname}] 登录成功  来源={conn_id}")
                    # 后续并发连接只记录 DEBUG 级别（不污染主日志）

                    # ── 重放端口：仅首条连接打上线日志 ────
                    if actual_mode == "replay" and is_first_conn:
                        # 允许边录边播：不强制停止录制，直接获取池引用
                        preview_pools = recording_pool.get_all_ip_pools(client_ip)
                        if preview_pools:
                            known_gids = [g for g in preview_pools.keys() if g]
                            pool_total = sum(len(p) for p in preview_pools.values())
                            gid_str = ("  游戏ID: " + " / ".join(f"[{g}]" for g in known_gids)
                                       if known_gids else "  游戏ID: [待识别]")
                            _event("REPLAY", self.label,
                                   f"代理用户=[{uname}]({client_ip}) 上线 — "
                                   f"发现 {len(preview_pools)} 条录制 共 {pool_total} 个加密区"
                                   f"{gid_str}，待游戏ID匹配后重放")
                            log_bus.conn_detail.emit(
                                client_ip,
                                f"[上线] 代理用户={uname}{gid_str}  加密区={pool_total}"
                                f"  来源={conn_id}  【待游戏ID匹配】")
                        else:
                            _event("REPLAY", self.label,
                                   f"代理用户=[{uname}]({client_ip}) 上线 — 无录制数据，透传模式")
                            log_bus.conn_detail.emit(
                                client_ip,
                                f"[上线] 代理用户={uname}  来源={conn_id}  【无录制数据，透传】")
                    elif actual_mode == "replay" and not is_first_conn:
                        # 非首条并发连接：不强制停止录制，也不打日志
                        pass
                else:
                    writer.write(b"\x01\x01"); await writer.drain()
                    _event("AUTH_FAIL", self.label,
                           f"用户 [{uname}] 鉴权失败  来源={conn_id}")
                    return

            # ③ 请求
            req = await reader.readexactly(4)
            if req[1] != 1:
                writer.write(b"\x05\x07\x00\x01" + b"\x00"*6)
                await writer.drain()
                return

            atype = req[3]
            if atype == 1:
                target_host = socket.inet_ntoa(await reader.readexactly(4))
            elif atype == 3:
                dlen = (await reader.readexactly(1))[0]
                target_host = (await reader.readexactly(dlen)).decode("utf-8", errors="replace")
            elif atype == 4:
                target_host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                return

            target_port = struct.unpack("!H", await reader.readexactly(2))[0]
            dst_str = f"{target_host}:{target_port}"
            _event("CONNECT", self.label,
                   f"[{username}] → {dst_str}")
            log_bus.conn_added.emit(conn_id, conn_id, dst_str, username, actual_mode)

            # ④ 本地重放优先检查：命中则跳过真实连接，直接返回本地文件
            # 必须在 _connect_remote 之前，避免无谓的真实连接超时和强制断开报错
            if target_port == 80:
                local_file = local_map_manager.get_file(target_host)
                if local_file and os.path.isfile(local_file):
                    writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                    await writer.drain()
                    await _local_map_serve(reader, writer, local_file, target_host)
                    _event("SESSION", self.label,
                           f"[{username}] {dst_str}  [本地重放] → {os.path.basename(local_file)}")
                    return

            # ⑤ 连接远端
            rr, rw = await self._connect_remote(atype, target_host, target_port)
            if rr is None:
                _event("WARN", self.label, f"[{username}] 上游连接失败，已拒绝 → {dst_str}")
                writer.write(b"\x05\x05\x00\x01" + b"\x00"*6)
                await writer.drain()
                return

            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            # 重放模式：快照该 IP 所有录制会话，等发现游戏ID后再选具体池
            if actual_mode == "replay":
                all_pools = recording_pool.get_all_ip_pools(client_ip)
                if all_pools:
                    self._replay_all_pools[conn_id]   = all_pools
                    self._replay_gid_checked[conn_id] = False
                    # 进度列先置为"待匹配"，发现游戏ID后更新
                    log_bus.conn_mode_update.emit(client_ip, "待匹配")
                else:
                    # 无任何录制数据
                    log_bus.conn_mode_update.emit(client_ip, "无录制")

            # ⑤ 双向转发
            # half_close=True：上行读完 EOF 后只发 TCP FIN（半关闭写端），
            # 保持连接供下行读取服务器响应，修复 HTTP 明文请求返回空白的问题
            up_count = [0]
            dn_count = [0]
            await asyncio.gather(
                self._forward(reader, rw,     "↑UP",   conn_id, username, up_count,
                              client_ip=client_ip, mode=actual_mode, half_close=True),
                self._forward(rr,     writer, "↓DOWN", conn_id, username, dn_count,
                              client_ip=client_ip, mode=actual_mode),
                return_exceptions=True
            )
            _safe_close(rw)  # 两个方向都结束后统一关闭远端连接

            self._total_up_pkts += up_count[0]
            self._total_dn_pkts += dn_count[0]
            if actual_mode == "record":
                # 引用计数 -1；所有连接都断开时才真正停止（rec_total > 0）
                rec_total, game_id = recording_pool.stop(client_ip)
                _rec_joined = False  # 已正常 stop，finally 不再重复调用
                gid_info = f"  游戏ID=[{game_id}]" if game_id else ""
                rec_info = f"  [录制已停止: {rec_total} 包]{gid_info}" if rec_total > 0 else ""
                if rec_total > 0:
                    _event("RECORD", self.label,
                           f"[{client_ip}] 所有连接断开，录制停止{gid_info}，共 {rec_total} 包，等待重放")
            else:
                rec_info = ""
            _event("SESSION", self.label,
                   f"[{username}] {dst_str}  上行包={up_count[0]} 下行包={dn_count[0]}{rec_info}")

        except asyncio.IncompleteReadError:
            pass
        except Exception as ex:
            _event("ERROR", self.label, f"handle_client: {ex}")
        finally:
            # 兜底：若因握手失败/异常提前退出，确保 recording_pool 引用计数归还
            if _rec_joined:
                recording_pool.stop(client_ip)
            self._active_conns -= 1
            self._replay_index.pop(conn_id, None)
            self._replay_pools.pop(conn_id, None)
            self._replay_all_pools.pop(conn_id, None)
            self._replay_gid_checked.pop(conn_id, None)
            self._stream_bufs.pop(conn_id, None)
            self._stream_bufs.pop(f"{conn_id}_rec_↑UP", None)
            self._stream_bufs.pop(f"{conn_id}_rec_↓DOWN", None)
            # 注销多开跟踪
            self._conn_client_writers.pop(conn_id, None)
            if username:
                ip_map = self._user_active_conns.get(username, {})
                ip_conns = ip_map.get(client_ip, set())
                ip_conns.discard(conn_id)
                if not ip_conns:
                    ip_map.pop(client_ip, None)
                if not ip_map:
                    self._user_active_conns.pop(username, None)
            _safe_close(writer)
            log_bus.conn_closed.emit(conn_id)

    async def _connect_remote(self, atype, target_host, target_port):
        ext = self.external_proxy
        try:
            if ext:
                ext_ip, ext_port, ext_proto = ext[0], ext[1], ext[2] if len(ext) > 2 else "SOCKS5"
                rr, rw = await asyncio.wait_for(
                    asyncio.open_connection(ext_ip, ext_port), timeout=10)

                if ext_proto == "HTTP":
                    # ── HTTP CONNECT 模式（Charles/Fiddler HTTP 代理端口）──
                    req_line = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
                    rw.write(req_line.encode()); await rw.drain()
                    # 读取响应头直到 \r\n\r\n
                    resp = b""
                    while b"\r\n\r\n" not in resp:
                        chunk = await asyncio.wait_for(rr.read(512), timeout=10)
                        if not chunk:
                            raise ConnectionError("上游 HTTP 代理意外关闭连接")
                        resp += chunk
                    first_line = resp.split(b"\r\n")[0].decode("utf-8", errors="replace")
                    if b" 200 " not in resp[:resp.index(b"\r\n")]:
                        _event("ERROR", self.label, f"HTTP CONNECT 被拒绝: {first_line}")
                        _safe_close(rw); return None, None
                    _event("VIA-EXT", self.label,
                           f"{target_host}:{target_port} → 通过 HTTP 代理 {ext_ip}:{ext_port}")
                else:
                    # ── SOCKS5 模式（Clash / Charles SOCKS5 端口）──
                    rw.write(b"\x05\x01\x00"); await rw.drain()
                    hs = await asyncio.wait_for(rr.readexactly(2), timeout=10)
                    if hs[1] != 0x00:
                        _event("ERROR", self.label, f"SOCKS5 上游握手失败 hs={hs.hex()}")
                        _safe_close(rw); return None, None
                    cmd = b"\x05\x01\x00"
                    if atype == 1:
                        cmd += b"\x01" + socket.inet_aton(target_host)
                    elif atype == 3:
                        cmd += b"\x03" + bytes([len(target_host)]) + target_host.encode()
                    elif atype == 4:
                        cmd += b"\x04" + socket.inet_pton(socket.AF_INET6, target_host)
                    cmd += struct.pack("!H", target_port)
                    rw.write(cmd); await rw.drain()
                    rep = await asyncio.wait_for(rr.readexactly(4), timeout=10)
                    if rep[1] != 0x00:
                        _event("ERROR", self.label, f"SOCKS5 上游拒绝 rep={rep[1]}")
                        _safe_close(rw); return None, None
                    if rep[3] == 1:   await rr.readexactly(6)
                    elif rep[3] == 3:
                        dl = (await rr.readexactly(1))[0]; await rr.readexactly(dl + 2)
                    elif rep[3] == 4: await rr.readexactly(18)
                    _event("VIA-EXT", self.label,
                           f"{target_host}:{target_port} → 通过 SOCKS5 代理 {ext_ip}:{ext_port}")
                return rr, rw
            else:
                loop = asyncio.get_running_loop()
                info = await asyncio.wait_for(
                    loop.getaddrinfo(target_host, target_port, type=socket.SOCK_STREAM),
                    timeout=10)
                af, _, _, _, sa = info[0]
                rr, rw = await asyncio.wait_for(
                    asyncio.open_connection(sa[0], sa[1], family=af), timeout=10)
                return rr, rw
        except Exception as ex:
            _event("ERROR", self.label, f"连接 {target_host}:{target_port} 失败: {ex}")
            return None, None

    async def _forward(self, reader, writer, direction, conn_id, username, counter,
                       client_ip: str = "", mode: str = "", half_close: bool = False):

        def _make_on_replace(ri_ref: list, client_ip: str) -> callable:
            """构造替换回调，捕获 ri 引用和 client_ip"""
            def _on_replace(detail: dict):
                ri_ref[1] += 1
                # 发送绝对累计值，_on_replay_progress 负责换算轮次和轮内进度
                log_bus.replay_progress.emit(client_ip, ri_ref[1], detail["pool_total"])
                prev = " ".join(f"{b:02X}" for b in detail["payload_preview"][:64])
                if len(detail["payload_preview"]) > 64:
                    prev += " …"
                line = (
                    f"[替换] 池#{detail['pool_idx']+1}/{detail['pool_total']}  "
                    f"加密区 {detail['orig_payload_len']}B→{detail['new_payload_len']}B  "
                    f"总包长 {detail['orig_pkt_len']}→{detail['new_pkt_len']}  "
                    f"CRC={detail['crc_hex']} 路由={detail['routing_hex']}  "
                    f"账号={detail['account_id']}\n"
                    f"  替换后加密区前64B: {prev}"
                )
                if app_config.get("detail_01_log"):
                    def _hex_lines(b: bytes, per_line: int = 32) -> str:
                        rows = []
                        for i in range(0, len(b), per_line):
                            rows.append(" ".join(f"{x:02X}" for x in b[i:i + per_line]))
                        return "\n  ".join(rows)
                    line += (
                        f"\n  【原始请求】{detail['orig_pkt_len']}B:\n"
                        f"  {_hex_lines(detail.get('orig_packet', b''))}\n"
                        f"  【替换后封包】{detail['new_pkt_len']}B:\n"
                        f"  {_hex_lines(detail.get('new_packet', b''))}"
                    )
                log_bus.conn_detail.emit(client_ip, line)
            return _on_replace

        try:
            while True:
                data = await reader.read(65536)  # 64KB：ACE 单次 send 可达数万字节，减少跨 read 截断
                if not data:
                    break
                counter[0] += 1

                # ── 静默录制：TCP 流重组，提取完整的 01 包 ──────────────────
                if mode == "record":
                    rec_key = f"{conn_id}_rec_{direction}"
                    in_rec_stream = rec_key in self._stream_bufs
                    if in_rec_stream or (len(data) >= 2 and data[0] == 0x01 and data[1] == 0x00):
                        rec_buf = self._stream_bufs.setdefault(rec_key, bytearray())
                        rec_buf += data
                        pos = 0
                        while pos + 5 <= len(rec_buf):
                            if rec_buf[pos] != 0x01:
                                pos += 1
                                continue
                            pkt_len = (rec_buf[pos + 3] << 8) | rec_buf[pos + 4]
                            if pkt_len < 5:
                                pos += 1
                                continue
                            if pos + pkt_len > len(rec_buf):
                                break
                            sub = bytes(rec_buf[pos : pos + pkt_len])
                            recording_pool.append(client_ip, sub)
                            pos += pkt_len
                        del rec_buf[:pos]

                # ── 重放替换：流重组缓冲区 ──────────────────────────────────────
                # TCP 分包问题：一次 read 可能只包含某个 01 子包的一部分，
                # 下次 read 才是续体（不以 01 开头）。
                # 方案：维护 per-connection 流缓冲区，逐步提取完整子包，
                #        不完整尾部留缓冲等下次 read，所有处理后子包拼一起发出。
                if mode == "replay":
                    ri   = self._replay_index.get(conn_id)
                    pool = self._replay_pools.get(conn_id) if ri is not None else None
                    # 有录制数据快照 or 已激活流缓冲时进入处理
                    has_all_pools = conn_id in self._replay_all_pools
                    in_stream     = conn_id in self._stream_bufs

                    if (ri is not None or has_all_pools) and (
                        in_stream or (len(data) >= 2 and data[0] == 0x01 and data[1] == 0x00)
                    ):
                        buf = self._stream_bufs.setdefault(conn_id, bytearray())
                        buf += data

                        on_replace = _make_on_replace(ri, client_ip) if ri is not None else None
                        output = bytearray()
                        pos = 0

                        while pos + 5 <= len(buf):
                            if buf[pos] != 0x01:
                                output.append(buf[pos])
                                pos += 1
                                continue

                            pkt_len = (buf[pos + 3] << 8) | buf[pos + 4]
                            if pkt_len < 5:
                                output.append(buf[pos])
                                pos += 1
                                continue

                            if pos + pkt_len > len(buf):
                                break

                            sub = bytes(buf[pos : pos + pkt_len])

                            # ── 游戏ID匹配：首次遇到 0A 00 23 包时选定重放池 ──
                            if not self._replay_gid_checked.get(conn_id, True):
                                if b"\x0A\x00\x23" in sub:
                                    live_gid  = _parse_ace_account_id(sub)
                                    all_pools = self._replay_all_pools.get(conn_id, {})
                                    matched   = all_pools.get(live_gid) if live_gid else None
                                    if matched:
                                        # 找到匹配的录制会话 → 激活重放
                                        self._replay_pools[conn_id] = matched
                                        self._replay_index[conn_id] = [0, 0]
                                        ri   = self._replay_index[conn_id]
                                        pool = matched
                                        on_replace = _make_on_replace(ri, client_ip)
                                        log_bus.replay_progress.emit(client_ip, 0, len(pool))
                                        log_bus.conn_detail.emit(
                                            client_ip,
                                            f"[重放就绪] 游戏ID=[{live_gid}]  匹配录制 {len(pool)} 个加密区")
                                    else:
                                        # 无匹配录制 → 本连接透传
                                        gid_str = f"[{live_gid}]" if live_gid else "[未知]"
                                        _event("WARN", "",
                                               f"[{username}] 无匹配录制 游戏ID={gid_str}，透传")
                                        log_bus.conn_detail.emit(
                                            client_ip,
                                            f"[透传] 无匹配录制  游戏ID={gid_str}")
                                        log_bus.conn_mode_update.emit(client_ip, "无匹配录制")
                                        self._replay_all_pools.pop(conn_id, None)
                                        self._stream_bufs.pop(conn_id, None)
                                        output += buf[pos:]
                                        pos = len(buf)
                                        break
                                    self._replay_gid_checked[conn_id] = True

                            if ri is None:
                                # 还没选定池（等待 0A 00 23 包），当前包透传
                                output += sub
                                pos += pkt_len
                                continue

                            has_marker = _ace_index_of(sub, MARKER_0A0009) >= 0
                            replaced, _ = _ace_try_replace(
                                sub, pool, ri,
                                on_log=on_replace if has_marker else None
                            )
                            output += replaced
                            pos += pkt_len

                        del buf[:pos]
                        data = bytes(output) if output else b""

                # 33 66 开头的游戏协议包暂不显示到 Hex 视图（后续再处理）
                if data and len(data) >= 2 and data[0] == 0x33 and data[1] == 0x66:
                    pass
                else:
                    show = data[:64]
                    hex_str = " ".join(f"{b:02X}" for b in show)
                    if len(data) > 64:
                        hex_str += "  ..."
                    log_bus.hex_data.emit(conn_id, direction, hex_str, len(data))
                if data:  # 可能 output 为空（所有包都不完整，等待下次 read）
                    writer.write(data)
                    await writer.drain()
        except Exception:
            pass
        finally:
            if half_close:
                # 上行方向：客户端发完请求（half-close），向服务器发送 TCP FIN。
                # 服务器收到 FIN 后无论是 Connection:close 还是 keep-alive，
                # 都会发完当前响应后关闭写端 → 下行 rr.read() 自然收到 EOF 退出，
                # 手机浏览器得到 FIN 才知道响应结束（修复 keep-alive 站点白屏）。
                try:
                    if writer.can_write_eof():
                        writer.write_eof()
                except Exception:
                    pass
            else:
                _safe_close(writer)


def _safe_close(writer):
    try:
        writer.close()
    except Exception:
        pass


async def _local_map_serve(client_reader, client_writer, filepath: str, host: str):
    """
    本地重放：读取本地文件，以 HTTP/1.1 200 OK 回应客户端，
    不访问真实服务器（仅拦截 HTTP:80 请求）。
    """
    try:
        # 耗尽客户端发来的 HTTP 请求头，避免对方阻塞（最多等 5 秒 / 16 KB）
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                chunk = await asyncio.wait_for(client_reader.read(4096), timeout=5)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 16384:
                    break
        except Exception:
            pass

        # 读取本地文件
        try:
            with open(filepath, "rb") as f:
                body = f.read()
        except Exception as e:
            body = f"<html><body>读取文件失败: {e}</body></html>".encode("utf-8")

        # MIME 类型推断
        ext = os.path.splitext(filepath)[1].lower()
        mime = {
            ".html": "text/html; charset=utf-8",
            ".htm":  "text/html; charset=utf-8",
            ".js":   "application/javascript; charset=utf-8",
            ".css":  "text/css; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".txt":  "text/plain; charset=utf-8",
            ".xml":  "text/xml; charset=utf-8",
            ".png":  "image/png",
            ".jpg":  "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif":  "image/gif",
            ".ico":  "image/x-icon",
            ".svg":  "image/svg+xml",
        }.get(ext, "application/octet-stream")

        # 构造 HTTP/1.1 200 OK 响应
        resp_head = (
            b"HTTP/1.1 200 OK\r\n"
            b"Connection: close\r\n"
            + f"Content-Type: {mime}\r\n".encode()
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Cache-Control: no-cache, no-store\r\n"
            + b"\r\n"
        )
        client_writer.write(resp_head + body)
        # 先记录成功（数据已写入发送缓冲区），再 drain 等待确认
        # 若客户端因 HSTS 等原因提前 RST，只静默处理，不计为错误
        _event("MAPLOCAL", "本地重放",
               f"{host} → {os.path.basename(filepath)}  ({len(body)} B)")
        try:
            await client_writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass  # 客户端提前断开（HSTS 强制升级等），数据已入缓冲，忽略传输确认失败
    except Exception as ex:
        _event("ERROR", "本地重放", f"{host}: {ex}")
    finally:
        _safe_close(client_writer)


# ─────────────────────────────────────────
# 外部代理连通检测
# ─────────────────────────────────────────
async def _check_external_proxy(ip: str, port: int, proto: str = "SOCKS5") -> tuple[bool, str]:
    """测试外部代理连通性，支持 SOCKS5 和 HTTP CONNECT 两种协议"""
    try:
        t0 = time.monotonic()
        rr, rw = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=5)

        if proto == "HTTP":
            # 发一个 CONNECT 到公共地址测试连通性
            rw.write(b"CONNECT 1.1.1.1:80 HTTP/1.1\r\nHost: 1.1.1.1:80\r\n\r\n")
            await rw.drain()
            resp = b""
            try:
                while b"\r\n\r\n" not in resp:
                    chunk = await asyncio.wait_for(rr.read(256), timeout=5)
                    if not chunk:
                        break
                    resp += chunk
            except asyncio.TimeoutError:
                pass
            latency = int((time.monotonic() - t0) * 1000)
            _safe_close(rw)
            first_line = resp.split(b"\r\n")[0].decode("utf-8", errors="replace") if resp else ""
            if b"200" in resp[:40]:
                return True, f"连通  延迟 {latency}ms  ({first_line.strip()})"
            elif resp:
                return False, f"响应异常: {first_line.strip()}"
            else:
                return False, "无响应（超时）"
        else:
            # SOCKS5 握手测试
            rw.write(b"\x05\x01\x00")
            await rw.drain()
            resp = await asyncio.wait_for(rr.readexactly(2), timeout=5)
            latency = int((time.monotonic() - t0) * 1000)
            _safe_close(rw)
            if resp[0] == 5 and resp[1] in (0x00, 0x02):
                return True, f"连通  延迟 {latency}ms  (method={resp[1]})"
            else:
                return False, f"握手响应异常: {resp.hex()}"
    except asyncio.TimeoutError:
        return False, "超时（5s）"
    except Exception as ex:
        return False, f"{ex}"


# ─────────────────────────────────────────
# asyncio 运行引擎
# ─────────────────────────────────────────
class ProxyEngine:
    def __init__(self):
        self.loop: asyncio.AbstractEventLoop = None
        self._thread: threading.Thread = None
        self.server_1080: Socks5Server = None
        self.server_1081: Socks5Server = None
        self.running = False

    def start(self, cfg: dict):
        if self.running:
            return
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, args=(cfg,), daemon=True)
        self._thread.start()

    def _run(self, cfg):
        asyncio.set_event_loop(self.loop)
        ext = None
        if cfg.get("ext_enabled") and cfg.get("ext_ip"):
            ext = (cfg["ext_ip"], int(cfg["ext_port"]), cfg.get("ext_proto", "SOCKS5"))

        # 代码级常量配置
        TOOL_AUTH_CODE = "999999" # 软件运行的全局授权码
        TOOL_IS_DEBUG  = False # 是否显示鉴权失败时的降级透传日志 调试模式

        # 注意：此处你可以通过某种方式硬编码校验密码，比如从某个不易察觉的本地文件或环境变量里读。
        # 如果需要彻底隐藏，可以在打包时修改此处变量。
        tool_auth_ok = cfg.get("tool_auth_ok", False)
        tool_debug = TOOL_IS_DEBUG

        self.server_1081 = Socks5Server(
            port=cfg.get("port_1081", 1081),
            auth_required=False,
            external_proxy=ext,
            label="录制",
            mode="record",
            tool_auth_ok=tool_auth_ok,
            tool_debug=tool_debug
        )
        self.server_1080 = Socks5Server(
            port=cfg.get("port_1080", 1080),
            auth_required=True,
            users=cfg.get("users", {}),
            external_proxy=ext,
            label="重放",
            mode="replay",
            tool_auth_ok=tool_auth_ok,
            tool_debug=tool_debug
        )
        try:
            self.running = True
            self.loop.run_until_complete(asyncio.gather(
                self.server_1081.start(),
                self.server_1080.start(),
            ))
        except Exception as ex:
            _event("ERROR", "Engine", f"崩溃: {ex}")
        finally:
            self.running = False

    def stop(self):
        if self.server_1080: self.server_1080.stop()
        if self.server_1081: self.server_1081.stop()
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.running = False

    def reload_users(self):
        """动态重载用户列表（无需重启代理）"""
        users = user_manager.to_dict()
        if self.server_1080:
            self.server_1080.users = users
        _event("INFO", "UserMgr", f"用户列表已重载，共 {len(users)} 个有效账号")

    def update_external_proxy(self, ext_ip: str, ext_port: int, enabled: bool, proto: str = "SOCKS5"):
        ext = (ext_ip, ext_port, proto) if enabled and ext_ip else None
        if self.server_1080: self.server_1080.external_proxy = ext
        if self.server_1081: self.server_1081.external_proxy = ext
        state = f"已启用 [{proto}] {ext_ip}:{ext_port}" if enabled and ext_ip else "已禁用"
        _event("INFO", "外部代理", state)

    def check_ext_proxy(self, ip: str, port: int, proto: str, callback):
        """在 asyncio 线程里执行检测，把结果通过 callback 回调到主线程"""
        if not self.loop or not self.running:
            callback(False, "代理服务未启动")
            return
        async def _run():
            ok, msg = await _check_external_proxy(ip, port, proto)
            callback(ok, msg)
        asyncio.run_coroutine_threadsafe(_run(), self.loop)


engine = ProxyEngine()


# ─────────────────────────────────────────
# 连接重放详情对话框（非模态，可多开）
# ─────────────────────────────────────────
class ConnDetailDialog(QDialog):
    """
    显示单个来源 IP 的重放详细日志：
      · 每条 01 00 包的替换记录（替换前/后加密区长度、池索引、账号等）
      · 当前重放进度 (X / total)
    """
    def __init__(self, client_ip: str, parent=None):
        super().__init__(parent)
        self.client_ip = client_ip
        self.setWindowTitle(f"重放详情 — {client_ip}")
        self.resize(740, 520)
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinimizeButtonHint)

        v = QVBoxLayout(self)
        v.setContentsMargins(8, 8, 8, 6)

        # 进度条文字
        self.lbl_progress = QLabel("重放进度：—")
        self.lbl_progress.setStyleSheet("font-weight:bold;color:#ce93d8;")
        v.addWidget(self.lbl_progress)

        # 日志区
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont("Consolas", 9))
        self.log.setStyleSheet("background:#0d1117;color:#c9d1d9;")
        v.addWidget(self.log)

        # 底部按钮
        bar = QHBoxLayout()
        bar.addStretch()
        btn_clr = QPushButton("清空日志"); btn_clr.setFixedWidth(80)
        btn_clr.clicked.connect(self.log.clear)
        btn_close = QPushButton("关闭"); btn_close.setFixedWidth(60)
        btn_close.clicked.connect(self.close)
        bar.addWidget(btn_clr); bar.addWidget(btn_close)
        v.addLayout(bar)

    def closeEvent(self, event):
        if self.parent() and hasattr(self.parent(), "_detail_dialogs"):
            self.parent()._detail_dialogs.pop(self.client_ip, None)
        event.accept()

    def append(self, line: str):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        escaped = _esc(line).replace("\n", "<br>")
        self.log.append(f'<span style="color:#555">[{ts}]</span> {escaped}')
        self.log.ensureCursorVisible()

    def set_progress(self, current: int, total: int):
        if total > 0:
            round_num = (current - 1) // total + 1
            pos       = (current - 1) % total + 1
            round_str = f"  <span style='color:#888'>第 {round_num} 轮</span>" if round_num > 1 else ""
            self.lbl_progress.setText(
                f"重放进度：<b style='color:#ce93d8'>{pos} / {total}</b>  包{round_str}"
            )
        else:
            self.lbl_progress.setText(
                f"重放进度：<b style='color:#ce93d8'>{current} / {total}</b>  包"
            )


# ─────────────────────────────────────────
# 添加用户对话框
# ─────────────────────────────────────────
class AddUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("添加用户")
        self.setFixedSize(340, 240)

        form = QFormLayout()
        self.edit_uname  = QLineEdit()
        self.edit_passwd = QLineEdit(); self.edit_passwd.setEchoMode(QLineEdit.Password)
        self.edit_note   = QLineEdit()
        self.cb_never    = QCheckBox("永不过期"); self.cb_never.setChecked(True)
        self.date_expire = QDateEdit(QDate.currentDate().addYears(1))
        self.date_expire.setCalendarPopup(True)
        self.date_expire.setEnabled(False)
        self.cb_never.toggled.connect(lambda v: self.date_expire.setEnabled(not v))
        self.cb_multi    = QCheckBox("允许同账户多 IP 同时在线（测试/内部使用）")
        self.cb_multi.setChecked(False)

        form.addRow("用户名:", self.edit_uname)
        form.addRow("密码:",   self.edit_passwd)
        form.addRow("备注:",   self.edit_note)
        expire_row = QHBoxLayout()
        expire_row.addWidget(self.cb_never)
        expire_row.addWidget(self.date_expire)
        form.addRow("到期时间:", expire_row)
        form.addRow("多开控制:", self.cb_multi)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        root = QVBoxLayout(self)
        root.addLayout(form)
        root.addWidget(btns)

    def get_data(self) -> dict:
        expire = "never" if self.cb_never.isChecked() \
                 else self.date_expire.date().toString("yyyy-MM-dd")
        return {
            "username":    self.edit_uname.text().strip(),
            "password":    self.edit_passwd.text(),
            "expire":      expire,
            "note":        self.edit_note.text().strip(),
            "allow_multi": self.cb_multi.isChecked(),
        }


# ─────────────────────────────────────────
# 主界面
# ─────────────────────────────────────────
class MainWindow(QMainWindow):
    # 用于从非 Qt 线程回调到主线程
    _ext_check_done = Signal(bool, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyProxyApp  |  SOCKS5 双端口代理")
        self.resize(1150, 740)
        # 连接表：按 IP 分组，每个 IP 一行
        self._ip_rows:    dict[str, int] = {}    # ip → row index
        self._ip_active:  dict[str, int] = {}    # ip → 当前活跃连接数
        self._ip_rec_active: dict[str, int] = {} # ip → 当前活跃的录制连接数
        self._ip_rep_active: dict[str, int] = {} # ip → 当前活跃的重放连接数
        self._ip_total:   dict[str, int] = {}    # ip → 累计连接次数
        self._conn_info:  dict[str, tuple] = {}  # conn_id → (ip, mode)
        self._ip_last_active:  dict[str, datetime] = {}  # ip → 最后活跃时间（断开/连接）
        self._ip_online_since: dict[str, datetime] = {}  # ip → 本轮上线起始时间
        # 重放进度（连接表 + 详情对话框用）；详情日志仅在对话框打开时实时追加，不存储
        self._ip_replay_progress: dict[str, tuple] = {}        # ip → (current, total)
        self._detail_dialogs:    dict[str, ConnDetailDialog] = {}  # ip → dialog
        self._rec_sid_rows:      dict[str, int] = {}               # sid → 录制管理表行号
        self._build_ui()
        self._load_config_to_ui()
        self._connect_signals()
        self._refresh_user_table()
        # 定时刷新空闲时长 + 清理超过 60 分钟无活动的行（每 60 秒跑一次）
        self._idle_timer = QTimer(self)
        self._idle_timer.timeout.connect(self._on_cleanup_tick)
        self._idle_timer.start(60_000)

    # ─── 构建界面 ───────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 4)
        root.setSpacing(6)

        # ── 顶部控制栏 ──────────────────────
        top = QHBoxLayout(); top.setSpacing(10)

        # 端口
        pg = QGroupBox("端口配置")
        pl = QHBoxLayout(pg)
        pl.addWidget(QLabel("录制端口:"))
        self.spin_1081 = QSpinBox(); self.spin_1081.setRange(1, 65535); self.spin_1081.setValue(1081)
        pl.addWidget(self.spin_1081)
        pl.addSpacing(10)
        pl.addWidget(QLabel("重放端口:"))
        self.spin_1080 = QSpinBox(); self.spin_1080.setRange(1, 65535); self.spin_1080.setValue(1080)
        pl.addWidget(self.spin_1080)
        top.addWidget(pg)

        # 外部代理
        eg = QGroupBox("外部上游代理 (SOCKS5)")
        el = QHBoxLayout(eg)
        self.cb_ext = QCheckBox("启用"); el.addWidget(self.cb_ext)
        el.addWidget(QLabel("IP:"))
        self.edit_ext_ip = QLineEdit("127.0.0.1"); self.edit_ext_ip.setFixedWidth(110)
        el.addWidget(self.edit_ext_ip)
        el.addWidget(QLabel("端口:"))
        self.spin_ext_port = QSpinBox(); self.spin_ext_port.setRange(1, 65535)
        self.spin_ext_port.setValue(8889); self.spin_ext_port.setFixedWidth(68)
        el.addWidget(self.spin_ext_port)
        self.btn_ext_apply = QPushButton("应用"); self.btn_ext_apply.setFixedWidth(48)
        self.btn_ext_test  = QPushButton("测试"); self.btn_ext_test.setFixedWidth(48)
        el.addWidget(self.btn_ext_apply)
        el.addWidget(self.btn_ext_test)

        # 隐藏的授权框
        el.addStretch()
        self.edit_pwd = QLineEdit()
        self.edit_pwd.setEchoMode(QLineEdit.Password)
        self.edit_pwd.setMaxLength(6) 
        self.edit_pwd.setFixedWidth(40)
        self.edit_pwd.setStyleSheet("background: transparent; border: none; color: transparent;")
        el.addWidget(self.edit_pwd)

        top.addWidget(eg)

        # 启停
        ctrl = QVBoxLayout()
        self.btn_start = QPushButton("▶  启动代理")
        self.btn_start.setMinimumHeight(34)
        self.btn_start.setStyleSheet("QPushButton{background:#27ae60;color:white;font-weight:bold;border-radius:4px}"
                                     "QPushButton:disabled{background:#555;}")
        self.btn_stop = QPushButton("■  停止代理")
        self.btn_stop.setMinimumHeight(34)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("QPushButton{background:#c0392b;color:white;font-weight:bold;border-radius:4px}"
                                    "QPushButton:disabled{background:#555;}")
        ctrl.addWidget(self.btn_start)
        ctrl.addWidget(self.btn_stop)
        top.addLayout(ctrl)
        root.addLayout(top)

        # ── 主 Tab ──────────────────────────
        self.tabs = QTabWidget()

        # Tab 0: 事件日志（业务级，无 Hex）
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 9))
        self.log_view.setStyleSheet("background:#1a1a2e;color:#e0e0e0;")
        t0 = QWidget(); v0 = QVBoxLayout(t0); v0.setContentsMargins(0, 0, 0, 0)
        bar0 = QHBoxLayout()
        bar0.addWidget(QLabel("事件日志（用户登录/会话统计/代理状态）"))
        bar0.addStretch()
        b_clr0 = QPushButton("清空"); b_clr0.setFixedWidth(50)
        b_clr0.clicked.connect(self.log_view.clear)
        bar0.addWidget(b_clr0)
        v0.addLayout(bar0); v0.addWidget(self.log_view)
        self.tabs.addTab(t0, "📋 事件日志")

        # Tab 1: 用户管理
        t1 = self._build_user_tab()
        self.tabs.addTab(t1, "👥 用户管理")

        # Tab 2: 连接 & Hex
        t2 = self._build_hex_tab()
        self.tabs.addTab(t2, "🔬 连接 & Hex")

        # Tab 3: 录制管理
        t3 = self._build_record_tab()
        self.tabs.addTab(t3, "📼 录制管理")

        # Tab 4: 本地重放
        t4 = self._build_maplocal_tab()
        self.tabs.addTab(t4, "🗺️ 本地重放")

        root.addWidget(self.tabs)

        # 状态栏
        sb = QStatusBar(); self.setStatusBar(sb)
        self.lbl_status = QLabel("就绪"); sb.addWidget(self.lbl_status)
        self.lbl_stats  = QLabel(""); sb.addPermanentWidget(self.lbl_stats)

    def _build_user_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        # 操作栏
        bar = QHBoxLayout()
        self.btn_add_user  = QPushButton("➕  添加用户")
        self.btn_del_user  = QPushButton("🗑  删除选中")
        self.btn_reload_users = QPushButton("🔄  重载到代理")
        for b in [self.btn_add_user, self.btn_del_user, self.btn_reload_users]:
            b.setFixedHeight(30)
            bar.addWidget(b)
        bar.addStretch()
        bar.addWidget(QLabel("(修改后需点[重载到代理]使账号生效)"))
        v.addLayout(bar)

        # 用户表格
        self.user_table = QTableWidget(0, 6)
        self.user_table.setHorizontalHeaderLabels(["用户名", "密码", "到期时间", "备注", "多开", "状态"])
        self.user_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.user_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.user_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.user_table.verticalHeader().setVisible(False)
        v.addWidget(self.user_table)
        return w

    def _build_hex_tab(self) -> QWidget:
        split = QSplitter(Qt.Vertical)

        # ── 连接表工具栏 ─────────────────────
        conn_wrap = QWidget()
        conn_vlay = QVBoxLayout(conn_wrap); conn_vlay.setContentsMargins(0, 0, 0, 0)
        conn_bar  = QHBoxLayout()
        conn_bar.addWidget(QLabel("连接列表（按来源 IP 聚合）"))
        conn_bar.addStretch()
        self.cb_detail_01 = QCheckBox("详细 01 替换日志")
        self.cb_detail_01.setToolTip("勾选后，重放详情中显示原始请求与替换后封包的完整 Hex")
        conn_bar.addWidget(self.cb_detail_01)
        self.btn_conn_detail = QPushButton("📋 查看重放详情")
        self.btn_conn_detail.setFixedHeight(26)
        self.btn_conn_detail.setToolTip("选中一行后点击，查看该 IP 的逐包重放日志")
        conn_bar.addWidget(self.btn_conn_detail)
        conn_vlay.addLayout(conn_bar)

        self.conn_table = QTableWidget(0, 8)
        self.conn_table.setHorizontalHeaderLabels(
            ["来源 IP", "最近目标", "用户", "模式", "总连接", "活跃", "重放进度", "状态"])
        hh = self.conn_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)   # 来源 IP
        hh.setSectionResizeMode(1, QHeaderView.Stretch)             # 最近目标（拉伸）
        hh.setSectionResizeMode(2, QHeaderView.ResizeToContents)   # 用户
        hh.setSectionResizeMode(3, QHeaderView.ResizeToContents)   # 模式
        hh.setSectionResizeMode(4, QHeaderView.ResizeToContents)   # 总连接
        hh.setSectionResizeMode(5, QHeaderView.ResizeToContents)   # 活跃
        hh.setSectionResizeMode(6, QHeaderView.ResizeToContents)   # 重放进度
        hh.setSectionResizeMode(7, QHeaderView.ResizeToContents)   # 状态
        self.conn_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.conn_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.conn_table.verticalHeader().setVisible(False)
        conn_vlay.addWidget(self.conn_table)
        split.addWidget(conn_wrap)

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Consolas", 9))
        self.hex_view.setStyleSheet("background:#0d1117;color:#58a6ff;")
        hw = QWidget(); hv = QVBoxLayout(hw); hv.setContentsMargins(0, 0, 0, 0)
        hbar = QHBoxLayout()
        hbar.addWidget(QLabel("网络流日志 (仅限最新记录)"))
        
        # 添加实时预览开关
        self.chk_enable_hex = QCheckBox("启用实时抓取")
        self.chk_enable_hex.setChecked(False)  # 默认关闭以节省性能
        hbar.addWidget(self.chk_enable_hex)
        
        self.chk_only_send = QCheckBox("只显示发送")
        self.chk_only_send.setChecked(False)
        hbar.addWidget(self.chk_only_send)
        
        self.chk_auto_scroll = QCheckBox("自动滚动到底部")
        self.chk_auto_scroll.setChecked(True)
        hbar.addWidget(self.chk_auto_scroll)

        hbar.addWidget(QLabel("最大条数限制:"))
        self.spin_hex_max = QSpinBox()
        self.spin_hex_max.setRange(100, 100000)
        self.spin_hex_max.setValue(5000)
        self.spin_hex_max.setFixedWidth(80)
        self.spin_hex_max.setToolTip("限制显示的最多行数，超出后自动删除最老的记录，防止内存爆炸")
        hbar.addWidget(self.spin_hex_max)
        
        hbar.addStretch()
        b_clrh = QPushButton("清空记录"); b_clrh.setFixedWidth(80)
        b_clrh.clicked.connect(self.hex_view.clear)
        hbar.addWidget(b_clrh)
        hv.addLayout(hbar); hv.addWidget(self.hex_view)
        split.addWidget(hw)
        split.setSizes([200, 320])

        w = QWidget(); vv = QVBoxLayout(w); vv.setContentsMargins(0, 0, 0, 0)
        vv.addWidget(split)
        return w

    def _build_record_tab(self) -> QWidget:
        """
        录制管理 Tab 布局：
          上半：会话表（来源IP / 游戏ID / 加密区数 / 状态）— 仅统计 0A 00 09 提取出的加密区
          下半：左=加密区列表（序号/大小/前16字节），右=选中加密区前128字节 Hex
        """
        outer = QSplitter(Qt.Vertical)

        # ── 上：会话列表 ──────────────────────
        top_w = QWidget()
        top_v = QVBoxLayout(top_w); top_v.setContentsMargins(0, 0, 0, 0)
        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("录制会话（仅 0A 00 09 加密区，按来源 IP）"))
        top_bar.addStretch()
        self.btn_rec_refresh = QPushButton("🔄 刷新");   self.btn_rec_refresh.setFixedWidth(70)
        self.btn_rec_export  = QPushButton("📤 导出");   self.btn_rec_export.setFixedWidth(70)
        self.btn_rec_import  = QPushButton("📥 导入");   self.btn_rec_import.setFixedWidth(70)
        self.btn_rec_clear   = QPushButton("🗑 清空全部"); self.btn_rec_clear.setFixedWidth(80)
        top_bar.addWidget(self.btn_rec_refresh)
        top_bar.addWidget(self.btn_rec_export)
        top_bar.addWidget(self.btn_rec_import)
        top_bar.addWidget(self.btn_rec_clear)
        top_v.addLayout(top_bar)

        self.rec_session_table = QTableWidget(0, 4)
        self.rec_session_table.setHorizontalHeaderLabels(["来源 IP", "游戏 ID", "加密区数", "状态"])
        sh = self.rec_session_table.horizontalHeader()
        sh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        sh.setSectionResizeMode(1, QHeaderView.Stretch)
        sh.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        sh.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.rec_session_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rec_session_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rec_session_table.verticalHeader().setVisible(False)
        top_v.addWidget(self.rec_session_table)
        outer.addWidget(top_w)

        # ── 下：包列表 + Hex 详情 ─────────────
        bottom_split = QSplitter(Qt.Horizontal)

        # 左：包列表
        pkt_w = QWidget()
        pkt_v = QVBoxLayout(pkt_w); pkt_v.setContentsMargins(0, 0, 0, 0)
        pkt_v.addWidget(QLabel("0A 00 09 加密区列表（点击查看右侧 Hex）"))
        self.rec_pkt_table = QTableWidget(0, 3)
        self.rec_pkt_table.setHorizontalHeaderLabels(["序号", "大小(B)", "前16字节"])
        ph = self.rec_pkt_table.horizontalHeader()
        ph.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        ph.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        ph.setSectionResizeMode(2, QHeaderView.Stretch)
        self.rec_pkt_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rec_pkt_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rec_pkt_table.verticalHeader().setVisible(False)
        pkt_v.addWidget(self.rec_pkt_table)
        bottom_split.addWidget(pkt_w)

        # 右：Hex 详情（前 128 字节，或完整 Hex 无 ASCII）
        hex_w = QWidget()
        hex_v = QVBoxLayout(hex_w); hex_v.setContentsMargins(0, 0, 0, 0)
        hex_bar = QHBoxLayout()
        hex_bar.addWidget(QLabel("加密区 Hex"))
        hex_bar.addStretch()
        self.btn_rec_full_hex = QPushButton("完整 Hex")
        self.btn_rec_full_hex.setFixedWidth(70)
        self.btn_rec_full_hex.setToolTip("显示选中加密区全部数据，纯 Hex 无 ASCII，便于核对替换")
        hex_bar.addWidget(self.btn_rec_full_hex)
        hex_v.addLayout(hex_bar)
        self.rec_hex_view = QTextEdit()
        self.rec_hex_view.setReadOnly(True)
        self.rec_hex_view.setFont(QFont("Consolas", 9))
        self.rec_hex_view.setStyleSheet("background:#1a1a2e;color:#a8d8a8;")
        hex_v.addWidget(self.rec_hex_view)
        bottom_split.addWidget(hex_w)
        bottom_split.setSizes([280, 460])

        outer.addWidget(bottom_split)
        outer.setSizes([180, 340])

        # 存储当前选中 IP 的包缓存，供包列表点击时快速读取
        self._rec_current_pkts: list[bytes] = []

        w = QWidget(); vv = QVBoxLayout(w); vv.setContentsMargins(0, 0, 0, 0)
        vv.addWidget(outer)
        return w

    def _build_maplocal_tab(self) -> QWidget:
        """
        本地重放 Tab：配置域名 → 本地文件映射。
        命中时代理直接返回本地文件，不访问真实服务器（仅 HTTP:80）。
        """
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(6, 6, 6, 6)
        v.setSpacing(6)

        # 说明标签
        hint = QLabel(
            "拦截指定域名的 HTTP(端口80) 请求，直接返回本地文件内容，"
            "不连接真实服务器。  HTTPS 请求不受影响。"
        )
        hint.setStyleSheet("color:#9ca3af; font-size:11px;")
        hint.setWordWrap(True)
        v.addWidget(hint)

        # 工具栏
        bar = QHBoxLayout()
        self.btn_map_add   = QPushButton("➕ 添加规则")
        self.btn_map_del   = QPushButton("🗑  删除选中")
        self.btn_map_clear = QPushButton("🧹 清空全部")
        for b in (self.btn_map_add, self.btn_map_del, self.btn_map_clear):
            b.setFixedHeight(28)
            bar.addWidget(b)
        bar.addStretch()
        self.lbl_map_count = QLabel("已配置 0 条规则")
        self.lbl_map_count.setStyleSheet("color:#9ca3af; font-size:11px;")
        bar.addWidget(self.lbl_map_count)
        v.addLayout(bar)

        # 规则表格
        self.map_table = QTableWidget(0, 2)
        self.map_table.setHorizontalHeaderLabels(["域名", "本地文件路径"])
        mh = self.map_table.horizontalHeader()
        mh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        mh.setSectionResizeMode(1, QHeaderView.Stretch)
        self.map_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.map_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.map_table.verticalHeader().setVisible(False)
        self.map_table.setAlternatingRowColors(True)
        v.addWidget(self.map_table)

        return w

    def _refresh_map_table(self):
        """从 local_map_manager 重新加载规则到表格。"""
        items = local_map_manager.items()
        self.map_table.setRowCount(len(items))
        for row, (domain, filepath) in enumerate(items):
            self.map_table.setItem(row, 0, QTableWidgetItem(domain))
            self.map_table.setItem(row, 1, QTableWidgetItem(filepath))
        self.lbl_map_count.setText(f"已配置 {len(items)} 条规则")

    # ─── 信号绑定 ───────────────────────────
    def _connect_signals(self):
        self.btn_start.clicked.connect(self._on_start)
        self.btn_stop.clicked.connect(self._on_stop)
        self.btn_ext_apply.clicked.connect(self._on_apply_ext)
        self.btn_ext_test.clicked.connect(self._on_test_ext)
        self.btn_add_user.clicked.connect(self._on_add_user)
        self.btn_del_user.clicked.connect(self._on_del_user)
        self.btn_reload_users.clicked.connect(self._on_reload_users)
        self.user_table.cellDoubleClicked.connect(self._on_user_table_double_click)

        log_bus.event_log.connect(self._on_event_log)
        log_bus.conn_added.connect(self._on_conn_added)
        log_bus.conn_closed.connect(self._on_conn_closed)
        log_bus.hex_data.connect(self._on_hex_data)
        log_bus.record_updated.connect(self._on_record_updated)
        log_bus.record_count.connect(self._on_record_count)
        log_bus.conn_detail.connect(self._on_conn_detail)
        log_bus.replay_progress.connect(self._on_replay_progress)
        log_bus.conn_mode_update.connect(self._on_conn_mode_update)
        self._ext_check_done.connect(self._on_ext_check_result)

        # 连接表详情按钮 + 双击 + 详细日志勾选
        self.btn_conn_detail.clicked.connect(self._on_show_detail)
        self.conn_table.doubleClicked.connect(lambda _: self._on_show_detail())
        self.cb_detail_01.toggled.connect(self._save_config_from_ui)

        # 录制管理 Tab 内的按钮
        self.btn_rec_refresh.clicked.connect(self._on_record_updated)
        self.btn_rec_export.clicked.connect(self._on_rec_export)
        self.btn_rec_import.clicked.connect(self._on_rec_import)
        self.btn_rec_clear.clicked.connect(self._on_rec_clear_all)
        self.btn_rec_full_hex.clicked.connect(self._on_rec_full_hex)
        self.rec_session_table.currentItemChanged.connect(self._on_rec_session_selected)
        self.rec_pkt_table.currentItemChanged.connect(self._on_rec_pkt_selected)

        # 本地重放 Tab 内的按钮
        self.btn_map_add.clicked.connect(self._on_map_add)
        self.btn_map_del.clicked.connect(self._on_map_del)
        self.btn_map_clear.clicked.connect(self._on_map_clear)
        self._refresh_map_table()

    # ─── 配置读写 ────────────────────────────
    def _load_config_to_ui(self):
        """从 AppConfig 恢复界面控件值"""
        self.spin_1081.setValue(app_config.get("port_record"))
        self.spin_1080.setValue(app_config.get("port_replay"))
        self.cb_ext.setChecked(app_config.get("ext_enabled"))
        self.edit_ext_ip.setText(app_config.get("ext_ip"))
        self.spin_ext_port.setValue(app_config.get("ext_port"))
        self.cb_detail_01.setChecked(app_config.get("detail_01_log"))

    def _save_config_from_ui(self):
        """将界面控件值保存到 AppConfig（并写磁盘）"""
        app_config.set("port_record", self.spin_1081.value())
        app_config.set("port_replay", self.spin_1080.value())
        app_config.set("ext_enabled", self.cb_ext.isChecked())
        app_config.set("ext_ip",      self.edit_ext_ip.text().strip())
        app_config.set("ext_port",    self.spin_ext_port.value())
        app_config.set("detail_01_log", self.cb_detail_01.isChecked())
        app_config.save()

    # ─── 槽 ─────────────────────────────────
    def _on_start(self):
        self._save_config_from_ui()   # 启动时顺手保存当前配置
        cfg = {
            "port_1080":   self.spin_1080.value(),
            "port_1081":   self.spin_1081.value(),
            "users":       user_manager.to_dict(),
            "ext_enabled": self.cb_ext.isChecked(),
            "ext_ip":      self.edit_ext_ip.text().strip(),
            "ext_port":    self.spin_ext_port.value(),
            "ext_proto":   "SOCKS5",
            "tool_auth_ok": (self.edit_pwd.text().strip() == "999999"),
        }
        engine.start(cfg)
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        
        # 隐藏式反馈：密码正确时按钮为深紫/深蓝色，错误时为原本的红色
        if cfg["tool_auth_ok"]:
            self.btn_stop.setStyleSheet("QPushButton{background:#673ab7;color:white;font-weight:bold;border-radius:4px}"
                                        "QPushButton:disabled{background:#555;}")
        else:
            self.btn_stop.setStyleSheet("QPushButton{background:#c0392b;color:white;font-weight:bold;border-radius:4px}"
                                        "QPushButton:disabled{background:#555;}")

        self.spin_1080.setEnabled(False)
        self.spin_1081.setEnabled(False)
        self.lbl_status.setText(
            f"运行中 | 录制:{cfg['port_1081']}(无鉴权)  重放:{cfg['port_1080']}(鉴权 {len(cfg['users'])} 账号)")

    def _on_stop(self):
        engine.stop()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        # 恢复默认红色
        self.btn_stop.setStyleSheet("QPushButton{background:#c0392b;color:white;font-weight:bold;border-radius:4px}"
                                    "QPushButton:disabled{background:#555;}")
        self.spin_1080.setEnabled(True)
        self.spin_1081.setEnabled(True)
        self.lbl_status.setText("已停止")

    def _on_apply_ext(self):
        self._save_config_from_ui()   # 应用外部代理时也保存
        engine.update_external_proxy(
            self.edit_ext_ip.text().strip(),
            self.spin_ext_port.value(),
            self.cb_ext.isChecked(),
            "SOCKS5"
        )
        if self.cb_ext.isChecked():
            self.lbl_status.setText(
                f"外部代理已启用 [SOCKS5] "
                f"{self.edit_ext_ip.text().strip()}:{self.spin_ext_port.value()}"
            )
        else:
            self.lbl_status.setText("外部代理已禁用")

    def _on_test_ext(self):
        ip   = self.edit_ext_ip.text().strip()
        port = self.spin_ext_port.value()
        if not ip:
            QMessageBox.warning(self, "提示", "请先填写外部代理 IP")
            return
        self.btn_ext_test.setEnabled(False)
        self.btn_ext_test.setText("检测中…")
        self.lbl_status.setText(f"正在检测 [SOCKS5] {ip}:{port}…")

        def _cb(ok, msg):
            self._ext_check_done.emit(ok, msg)

        if engine.running:
            engine.check_ext_proxy(ip, port, "SOCKS5", _cb)
        else:
            def _run():
                loop = asyncio.new_event_loop()
                ok, msg = loop.run_until_complete(_check_external_proxy(ip, port, "SOCKS5"))
                loop.close()
                _cb(ok, msg)
            threading.Thread(target=_run, daemon=True).start()

    def _on_ext_check_result(self, ok: bool, msg: str):
        self.btn_ext_test.setEnabled(True)
        self.btn_ext_test.setText("测试")
        icon = "✅" if ok else "❌"
        full_msg = f"{icon} [SOCKS5] {msg}"
        color = "#27ae60" if ok else "#c0392b"
        self.lbl_status.setStyleSheet(f"color:{color};")
        self.lbl_status.setText(full_msg)
        _event("EXT_TEST", "外部代理", full_msg)

    def _on_add_user(self):
        dlg = AddUserDialog(self)
        if dlg.exec() == QDialog.Accepted:
            d = dlg.get_data()
            if not d["username"] or not d["password"]:
                QMessageBox.warning(self, "错误", "用户名和密码不能为空")
                return
            if not user_manager.add(d["username"], d["password"], d["expire"],
                                    d["note"], d.get("allow_multi", False)):
                QMessageBox.warning(self, "错误", f"用户名 {d['username']} 已存在")
                return
            self._refresh_user_table()
            _event("INFO", "UserMgr", f"添加用户 [{d['username']}]  到期={d['expire']}")

    def _on_del_user(self):
        rows = self.user_table.selectedItems()
        if not rows:
            return
        row = self.user_table.currentRow()
        uname = self.user_table.item(row, 0).text()
        if QMessageBox.question(self, "确认", f"删除用户 [{uname}]？") == QMessageBox.Yes:
            user_manager.remove(uname)
            self._refresh_user_table()
            _event("INFO", "UserMgr", f"删除用户 [{uname}]")

    def _on_user_table_double_click(self, row: int, col: int):
        """双击"多开"列（col=4）快速切换该用户的多开权限"""
        if col != 4:
            return
        uname_item = self.user_table.item(row, 0)
        if uname_item is None:
            return
        uname = uname_item.text()
        current = user_manager.get_allow_multi(uname)
        new_val = not current
        user_manager.set_allow_multi(uname, new_val)
        self._refresh_user_table()
        verb = "开启" if new_val else "关闭"
        _event("INFO", "UserMgr", f"[{uname}] 多开权限已{verb}")

    def _on_reload_users(self):
        user_manager.load()
        self._refresh_user_table()
        engine.reload_users()

    def _refresh_user_table(self):
        self.user_table.setRowCount(0)
        today = date.today().isoformat()
        for u in user_manager.all():
            row = self.user_table.rowCount()
            self.user_table.insertRow(row)
            exp = u.get("expire", "never")
            expired = exp != "never" and exp < today
            status  = "⚠ 已过期" if expired else "✅ 有效"
            passwd_mask = "●" * min(len(u["password"]), 8)
            allow_multi = u.get("allow_multi", False)
            multi_text  = "✅ 允许" if allow_multi else "🔒 禁止"
            for col, text in enumerate([u["username"], passwd_mask, exp,
                                        u.get("note", ""), multi_text, status]):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignCenter)
                if expired:
                    item.setForeground(QColor("#888"))
                elif col == 4 and allow_multi:
                    item.setForeground(QColor("#4fc3f7"))  # 蓝色提示多开已开
                self.user_table.setItem(row, col, item)

    # ─── 事件日志（业务级）──────────────────
    def _on_event_log(self, level: str, tag: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        colors = {
            "DEBUG":     "#888888",
            "INFO":      "#d4d4d4",
            "WARN":      "#f0a500",
            "ERROR":     "#f44747",
            "AUTH_OK":   "#3fb950",
            "AUTH_FAIL": "#f85149",
            "CONNECT":   "#79c0ff",
            "SESSION":   "#d2a8ff",
            "EXT_TEST":  "#ffa657",
            "VIA-EXT":   "#e6b800",
            "RECORD":    "#4fc3f7",
            "REPLAY":    "#ce93d8",
            "MAPLOCAL":  "#ffd700",
        }
        color = colors.get(level, "#d4d4d4")
        html = (
            f'<span style="color:#555">[{ts}]</span> '
            f'<span style="color:{color};font-weight:bold">[{level}]</span> '
            f'<span style="color:#aaa">&lt;{_esc(tag)}&gt;</span> '
            f'<span style="color:{color}">{_esc(msg)}</span><br>'
        )
        self._append_html(self.log_view, html, max_lines=1000)

    # ─── 连接表（按 IP 分组）────────────────
    def _on_conn_added(self, conn_id: str, src: str, dst: str, user: str, actual_mode: str = ""):
        ip = src.split(":")[0]
        if actual_mode == "record":
            mode = "录制"
        elif actual_mode == "replay":
            mode = "重放"
        else:
            mode = "透传"
        self._conn_info[conn_id] = (ip, mode)
        self._ip_last_active[ip]  = datetime.now()

        if ip not in self._ip_rows:
            row = self.conn_table.rowCount()
            self._ip_rows[ip]   = row
            self._ip_active[ip] = 0
            self._ip_rec_active[ip] = 0
            self._ip_rep_active[ip] = 0
            self._ip_total[ip]  = 0
            self.conn_table.insertRow(row)
            for col in range(8):
                item = QTableWidgetItem("")
                item.setTextAlignment(Qt.AlignCenter)
                self.conn_table.setItem(row, col, item)

        prev_active = self._ip_active.get(ip, 0)
        self._ip_active[ip] = prev_active + 1
        self._ip_total[ip]  = self._ip_total.get(ip, 0) + 1
        
        if mode == "录制":
            self._ip_rec_active[ip] = self._ip_rec_active.get(ip, 0) + 1
        else:
            self._ip_rep_active[ip] = self._ip_rep_active.get(ip, 0) + 1

        # 从空闲变为活跃时记录本轮上线起始时间
        if prev_active == 0:
            self._ip_online_since[ip] = datetime.now()
        row = self._ip_rows[ip]
        self._set_cell(row, 0, ip)
        self._set_cell(row, 1, dst)
        self._set_cell(row, 2, user)
        
        rec_cnt = self._ip_rec_active.get(ip, 0)
        rep_cnt = self._ip_rep_active.get(ip, 0)
        if rec_cnt > 0 and rep_cnt > 0:
            display_mode = "实时重放"
            mode_color = "#4fc3f7"
        elif rec_cnt > 0:
            display_mode = "录制"
            mode_color = ""
        else:
            display_mode = "重放"
            mode_color = ""
            
        self._set_cell(row, 3, display_mode, color=mode_color)
        self._set_cell(row, 4, str(self._ip_total[ip]))
        self._set_cell(row, 5, str(self._ip_active[ip]))
        # 重放进度列：纯录制模式清空缓存并显示 —，重放/实时重放模式保留或恢复缓存
        if display_mode == "录制":
            self._ip_replay_progress.pop(ip, None)
            self._set_cell(row, 6, "—", color="#666666")
        else:
            prog = self._ip_replay_progress.get(ip, (0, 0))
            prog_text = f"{prog[0]}/{prog[1]}" if prog[1] > 0 else "—"
            self._set_cell(row, 6, prog_text, color="#ce93d8")
        self._set_cell(row, 7, "● 活跃 刚刚", color="#3fb950")

    def _on_conn_closed(self, conn_id: str):
        info = self._conn_info.pop(conn_id, None)
        if info is None:
            return
        ip, mode = info
        now = datetime.now()
        self._ip_last_active[ip] = now
        self._ip_active[ip] = max(0, self._ip_active.get(ip, 1) - 1)
        
        if mode == "录制":
            self._ip_rec_active[ip] = max(0, self._ip_rec_active.get(ip, 1) - 1)
        else:
            self._ip_rep_active[ip] = max(0, self._ip_rep_active.get(ip, 1) - 1)
            
        row = self._ip_rows.get(ip)
        if row is None or row >= self.conn_table.rowCount():
            return
            
        rec_cnt = self._ip_rec_active.get(ip, 0)
        rep_cnt = self._ip_rep_active.get(ip, 0)
        if rec_cnt > 0 and rep_cnt > 0:
            display_mode = "实时重放"
            mode_color = "#4fc3f7"
        elif rec_cnt > 0:
            display_mode = "录制"
            mode_color = ""
        elif rep_cnt > 0:
            display_mode = "重放"
            mode_color = ""
        else:
            display_mode = self.conn_table.item(row, 3).text()
            mode_color = "#666666"

        self._set_cell(row, 3, display_mode, color=mode_color)

        # 切回纯录制模式时清空重放进度缓存和进度列
        if display_mode == "录制" and rep_cnt == 0:
            self._ip_replay_progress.pop(ip, None)
            self._set_cell(row, 6, "—", color="#666666")

        active = self._ip_active[ip]
        self._set_cell(row, 5, str(active))
        if active == 0:
            self._set_cell(row, 7, "○ 空闲 刚刚", color="#666666")

    def _set_cell(self, row: int, col: int, text: str, color: str = ""):
        item = self.conn_table.item(row, col)
        if item is None:
            item = QTableWidgetItem(text)
            item.setTextAlignment(Qt.AlignCenter)
            self.conn_table.setItem(row, col, item)
        else:
            item.setText(text)
        if color:
            item.setForeground(QColor(color))

    # ─── Hex 视图 ────────────────────────────
    def _on_hex_data(self, conn_id: str, direction: str, hex_str: str, length: int):
        if not hasattr(self, 'chk_enable_hex') or not self.chk_enable_hex.isChecked():
            return
            
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        dir_color = "#58a6ff" if "UP" in direction else "#3fb950"
        html = (
            f'<span style="color:#555">[{ts}]</span> '
            f'<span style="color:{dir_color}">{_esc(direction)}</span> '
            f'<span style="color:#f0883e">[{_esc(conn_id)}]</span> '
            f'<span style="color:#aaa">{length}B</span> '
            f'<span style="color:#cdd9e5">{_esc(hex_str)}</span><br>'
        )
        max_lines = self.spin_hex_max.value() if hasattr(self, 'spin_hex_max') else 5000
        self._append_html(self.hex_view, html, max_lines=max_lines)
        
        if hasattr(self, 'chk_auto_scroll') and not self.chk_auto_scroll.isChecked():
            pass # 如果不自动滚动就不调 ensureCursorVisible，但 QTextEdit 插入内容默认光标在末尾，所以需要控制滑动条
        else:
            self.hex_view.verticalScrollBar().setValue(self.hex_view.verticalScrollBar().maximum())

    @staticmethod
    def _append_html(edit: QTextEdit, html: str, max_lines: int = 5000):
        doc = edit.document()
        
        # 先获取当前滚动条是否在最底部
        scrollbar = edit.verticalScrollBar()
        is_at_bottom = scrollbar.value() == scrollbar.maximum()
        
        # 超出上限时从头部删除多余行（保持内存可控）
        while doc.blockCount() > max_lines:
            del_cur = QTextCursor(doc.begin())
            del_cur.movePosition(QTextCursor.NextBlock, QTextCursor.KeepAnchor)
            del_cur.removeSelectedText()
            
        cursor = edit.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(html)
        
        # 恢复滚动条状态
        if not is_at_bottom:
            pass # 外部 _on_hex_data 会通过 chk_auto_scroll 来判断是否要强制滚动到底部

    # ─── 录制管理 Tab 槽 ─────────────────────
    def _on_record_updated(self):
        """录制池结构变化时全量刷新会话列表（保留当前选中 sid）"""
        sessions = recording_pool.get_all_sessions()
        cur_row = self.rec_session_table.currentRow()
        cur_sid = ""
        if cur_row >= 0:
            it = self.rec_session_table.item(cur_row, 0)
            if it:
                cur_sid = it.data(Qt.UserRole) or ""

        self.rec_session_table.setRowCount(0)
        self._rec_sid_rows: dict[str, int] = {}   # sid → 行号，供轻量更新用
        restore_row = -1
        for i, s in enumerate(sessions):
            self.rec_session_table.insertRow(i)
            ip_item = QTableWidgetItem(s["ip"])
            ip_item.setTextAlignment(Qt.AlignCenter)
            ip_item.setData(Qt.UserRole, s["sid"])
            gid_item = QTableWidgetItem(s["game_id"] or "—")
            gid_item.setTextAlignment(Qt.AlignCenter)
            cnt_item = QTableWidgetItem(f"{s['count']}个")
            cnt_item.setTextAlignment(Qt.AlignCenter)
            status   = "● 录制中" if s["active"] else "○ 已停止"
            st_item  = QTableWidgetItem(status)
            st_item.setTextAlignment(Qt.AlignCenter)
            if s["active"]:
                for item in (ip_item, gid_item, cnt_item, st_item):
                    item.setForeground(QColor("#ff6b6b"))
            self.rec_session_table.setItem(i, 0, ip_item)
            self.rec_session_table.setItem(i, 1, gid_item)
            self.rec_session_table.setItem(i, 2, cnt_item)
            self.rec_session_table.setItem(i, 3, st_item)
            self._rec_sid_rows[s["sid"]] = i
            if s["sid"] == cur_sid:
                restore_row = i

        if restore_row >= 0:
            self.rec_session_table.selectRow(restore_row)

    def _on_record_count(self, sid: str, count: int):
        """轻量更新：只修改对应行的"加密区数"列，不重建表"""
        row = getattr(self, "_rec_sid_rows", {}).get(sid, -1)
        if row < 0:
            # 行不存在（可能是第一次），触发全量刷新
            self._on_record_updated()
            return
        cnt_item = self.rec_session_table.item(row, 2)
        if cnt_item:
            cnt_item.setText(f"{count}个")

    def _on_rec_session_selected(self, current, _previous):
        """选中一条录制会话后，加载该会话的包列表"""
        if current is None:
            return
        row = current.row()
        ip_item = self.rec_session_table.item(row, 0)
        if ip_item is None:
            return
        sid = ip_item.data(Qt.UserRole) or ""
        if not sid:
            return
        payloads = recording_pool.get_extracted_payloads(sid)
        self._rec_current_pkts = payloads

        self.rec_pkt_table.setRowCount(0)
        self.rec_hex_view.clear()
        for idx, pkt in enumerate(payloads):
            self.rec_pkt_table.insertRow(idx)
            n_item = QTableWidgetItem(str(idx + 1))
            n_item.setTextAlignment(Qt.AlignCenter)
            sz_item = QTableWidgetItem(str(len(pkt)))
            sz_item.setTextAlignment(Qt.AlignCenter)
            preview = " ".join(f"{b:02X}" for b in pkt[:16])
            if len(pkt) > 16:
                preview += " …"
            pr_item = QTableWidgetItem(preview)
            self.rec_pkt_table.setItem(idx, 0, n_item)
            self.rec_pkt_table.setItem(idx, 1, sz_item)
            self.rec_pkt_table.setItem(idx, 2, pr_item)

        if payloads:
            self.rec_pkt_table.selectRow(0)

    def _on_rec_pkt_selected(self, current, _previous):
        """选中一个包后，在右侧显示前 128 字节的格式化 Hex（含 ASCII）"""
        if current is None:
            return
        row = current.row()
        if row < 0 or row >= len(self._rec_current_pkts):
            return
        pkt  = self._rec_current_pkts[row]
        data = pkt[:128]
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            offset = f"{i:04X}"
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            hex_part = f"{hex_part:<47}"       # 对齐到47字符
            asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset}  {hex_part}  {asc_part}")
        total = len(pkt)
        header = f"加密区 #{row + 1}  大小={total}B  显示前 {len(data)}B\n{'─' * 70}\n"
        self.rec_hex_view.setPlainText(header + "\n".join(lines))

    def _on_rec_full_hex(self):
        """显示选中加密区的完整 Hex（无 ASCII），便于核对替换"""
        row = self.rec_pkt_table.currentRow()
        if row < 0 or row >= len(self._rec_current_pkts):
            return
        pkt = self._rec_current_pkts[row]
        lines = []
        per_line = 32
        for i in range(0, len(pkt), per_line):
            chunk = pkt[i:i + per_line]
            lines.append(" ".join(f"{b:02X}" for b in chunk))
        header = f"加密区 #{row + 1}  完整 {len(pkt)}B（纯 Hex 无 ASCII）\n{'─' * 70}\n"
        self.rec_hex_view.setPlainText(header + "\n".join(lines))

    # ─── 重放详情槽 ──────────────────────────
    def _on_conn_detail(self, client_ip: str, line: str):
        """
        收到一条重放详情日志。
        仅当该 IP 的详情对话框已打开时才追加显示；未打开时不存储，避免内存增长。
        """
        dlg = self._detail_dialogs.get(client_ip)
        if dlg and dlg.isVisible():
            dlg.append(line)

    def _on_conn_mode_update(self, client_ip: str, status: str):
        """更新连接表"重放进度"列的特殊状态文字"""
        row = self._ip_rows.get(client_ip)
        if row is None:
            return
        
        # 处理进度溢出的情况（例如 163/145 -> 18/145）
        if "/" in status:
            try:
                parts = status.split("/")
                if len(parts) == 2:
                    current = int(parts[0])
                    total = int(parts[1])
                    if total > 0 and current > total:
                        # 自动取模，如果刚好整除，则显示满进度 (如 145/145) 而不是 0/145
                        mod = current % total
                        current = mod if mod != 0 else total
                        status = f"{current}/{total}"
            except Exception:
                pass

        color_map = {
            "ID不匹配":   "#ffb74d",
            "无匹配录制": "#ffb74d",
            "待匹配":     "#64b5f6",
        }
        # 带有 / 的进度文字也给点颜色
        if "/" in status:
            color = "#ce93d8"
        else:
            color = color_map.get(status, "#888888")
            
        self._set_cell(row, 6, status, color=color)

    def _on_cleanup_tick(self):
        """每 60 秒：刷新在线/空闲时长 + 清理 30 分钟无活动的行 + 清理 1 天以上的录制数据"""
        now = datetime.now()
        to_remove = []

        # ── 活跃 IP：刷新在线时长 ──
        for ip, since in list(self._ip_online_since.items()):
            if self._ip_active.get(ip, 0) == 0:
                continue
            row = self._ip_rows.get(ip)
            if row is None or row >= self.conn_table.rowCount():
                continue
            elapsed = int((now - since).total_seconds())
            self._set_cell(row, 7, f"● {_fmt_dur(elapsed)}", color="#3fb950")

        # ── 空闲 IP：刷新空闲时长 + 标记待清理 ──
        for ip, last_t in list(self._ip_last_active.items()):
            if self._ip_active.get(ip, 0) > 0:
                continue
            row = self._ip_rows.get(ip)
            if row is None or row >= self.conn_table.rowCount():
                continue
            elapsed = int((now - last_t).total_seconds())
            self._set_cell(row, 7, f"○ 空闲 {_fmt_dur(elapsed)}", color="#666666")
            if elapsed >= 1800:   # 30 分钟后清理
                to_remove.append(ip)

        # 按行号倒序删除，避免索引漂移
        to_remove.sort(key=lambda x: self._ip_rows.get(x, 0), reverse=True)
        for ip in to_remove:
            self._remove_ip_row(ip)

        # ── 录制池：清理超过 1 天的非活跃会话 ──
        recording_pool.cleanup_expired(86400)

    def _remove_ip_row(self, ip: str):
        # 同时清理时间跟踪
        self._ip_online_since.pop(ip, None)
        """从连接表中删除指定 IP 的行，并更新所有后续行的索引"""
        row = self._ip_rows.pop(ip, None)
        if row is None or row >= self.conn_table.rowCount():
            return
        self.conn_table.removeRow(row)
        # 被删行之后的所有行索引 -1
        for other_ip in self._ip_rows:
            if self._ip_rows[other_ip] > row:
                self._ip_rows[other_ip] -= 1
        # 清理关联状态
        self._ip_active.pop(ip, None)
        self._ip_rec_active.pop(ip, None)
        self._ip_rep_active.pop(ip, None)
        self._ip_total.pop(ip, None)
        self._ip_last_active.pop(ip, None)
        self._ip_online_since.pop(ip, None)
        self._ip_replay_progress.pop(ip, None)
        # 关闭已打开的详情对话框
        dlg = self._detail_dialogs.pop(ip, None)
        if dlg:
            dlg.close()

    def _on_replay_progress(self, client_ip: str, current: int, total: int):
        """重放进度更新：刷新连接表进度列 + 已打开的详情对话框"""
        self._ip_replay_progress[client_ip] = (current, total)
        row = self._ip_rows.get(client_ip)
        if row is not None:
            if total > 0:
                round_num = (current - 1) // total + 1
                pos       = (current - 1) % total + 1
                text = f"{pos}/{total}" if round_num == 1 else f"{pos}/{total} ×{round_num}"
            else:
                text = f"{current}/{total}"
            self._set_cell(row, 6, text, color="#ce93d8")
        dlg = self._detail_dialogs.get(client_ip)
        if dlg and dlg.isVisible():
            dlg.set_progress(current, total)

    def _on_show_detail(self):
        """打开（或聚焦）选中 IP 的重放详情对话框"""
        row = self.conn_table.currentRow()
        if row < 0:
            return
        ip_item = self.conn_table.item(row, 0)
        if ip_item is None:
            return
        client_ip = ip_item.text()

        dlg = self._detail_dialogs.get(client_ip)
        if dlg and dlg.isVisible():
            dlg.raise_(); dlg.activateWindow()
            return

        dlg = ConnDetailDialog(client_ip, self)
        self._detail_dialogs[client_ip] = dlg
        # 详情仅在打开时实时显示，不存储历史（关闭时不占内存）
        prog = self._ip_replay_progress.get(client_ip)
        if prog:
            dlg.set_progress(*prog)
        dlg.show()

    def _on_rec_export(self):
        """导出录制池到 JSON 文件"""
        default_name = f"recording_{time.strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出录制数据", os.path.join("C:\\PyProxyApp", default_name),
            "JSON 文件 (*.json);;所有文件 (*)"
        )
        if not path:
            return
        ok, msg = recording_pool.export_to_file(path)
        QMessageBox.information(self, "导出结果", msg) if ok else QMessageBox.warning(self, "导出失败", msg)

    def _on_rec_import(self):
        """从 JSON 文件导入录制数据"""
        path, _ = QFileDialog.getOpenFileName(
            self, "导入录制数据", "C:\\PyProxyApp",
            "JSON 文件 (*.json);;所有文件 (*)"
        )
        if not path:
            return
        # 询问是否覆盖已有同 IP 会话
        overwrite = QMessageBox.question(
            self, "导入方式",
            "是否覆盖内存中相同 IP 的录制数据？\n选「否」则跳过已有 IP，保留现有数据。",
            QMessageBox.Yes | QMessageBox.No
        ) == QMessageBox.Yes
        ok, msg = recording_pool.import_from_file(path, overwrite=overwrite)
        QMessageBox.information(self, "导入结果", msg) if ok else QMessageBox.warning(self, "导入失败", msg)

    def _on_rec_clear_all(self):
        """清空整个录制池（谨慎操作）"""
        from PySide6.QtWidgets import QMessageBox as MB
        if MB.question(self, "确认", "确认清空所有录制数据？此操作不可恢复。",
                       MB.Yes | MB.No) == MB.Yes:
            recording_pool._sessions.clear()
            log_bus.record_updated.emit()
            self.rec_pkt_table.setRowCount(0)
            self.rec_hex_view.clear()
            self._rec_current_pkts = []

    # ─── 本地重放操作 ───────────────────────
    def _on_map_add(self):
        """弹出对话框添加域名→本地文件映射规则。"""
        dlg = QDialog(self)
        dlg.setWindowTitle("添加本地重放规则")
        dlg.setMinimumWidth(500)
        form = QFormLayout(dlg)
        form.setSpacing(10)
        form.setContentsMargins(14, 14, 14, 14)

        edit_domain = QLineEdit()
        edit_domain.setPlaceholderText("如: www.ok123.com  或  ok123.com")
        form.addRow("域名:", edit_domain)

        file_row = QHBoxLayout()
        edit_path = QLineEdit()
        edit_path.setPlaceholderText("选择或输入本地文件路径")
        btn_browse = QPushButton("浏览…")
        btn_browse.setFixedWidth(60)
        file_row.addWidget(edit_path)
        file_row.addWidget(btn_browse)
        form.addRow("本地文件:", file_row)

        def _browse():
            path, _ = QFileDialog.getOpenFileName(
                dlg, "选择本地文件", "",
                "网页文件 (*.html *.htm *.js *.css *.json *.txt);;所有文件 (*.*)")
            if path:
                edit_path.setText(path)
        btn_browse.clicked.connect(_browse)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        form.addRow(btns)

        if dlg.exec() == QDialog.Accepted:
            domain = edit_domain.text().strip()
            filepath = edit_path.text().strip()
            if not domain:
                QMessageBox.warning(self, "提示", "域名不能为空")
                return
            if not filepath:
                QMessageBox.warning(self, "提示", "文件路径不能为空")
                return
            if not os.path.isfile(filepath):
                QMessageBox.warning(self, "提示", f"文件不存在:\n{filepath}")
                return
            local_map_manager.add(domain, filepath)
            self._refresh_map_table()
            _event("INFO", "本地重放", f"添加规则: [{domain}] → {filepath}")

    def _on_map_del(self):
        """删除选中的映射规则。"""
        row = self.map_table.currentRow()
        if row < 0:
            return
        domain_item = self.map_table.item(row, 0)
        if not domain_item:
            return
        domain = domain_item.text()
        local_map_manager.remove(domain)
        self._refresh_map_table()
        _event("INFO", "本地重放", f"删除规则: [{domain}]")

    def _on_map_clear(self):
        """清空全部映射规则。"""
        if QMessageBox.question(self, "确认", "确认清空所有本地重放规则？") == QMessageBox.Yes:
            local_map_manager.clear()
            self._refresh_map_table()
            _event("INFO", "本地重放", "清空全部规则")

    def closeEvent(self, event):
        self._save_config_from_ui()   # 关闭前保存配置
        engine.stop()
        event.accept()


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ─────────────────────────────────────────
# 主入口
# ─────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if "--headless" in sys.argv:
        print("[headless] 启动代理 1080(鉴权) + 1081(无鉴权)")
        print(f"[headless] 用户列表: {list(user_manager.to_dict().keys())}")
        print("[headless] Ctrl+C 停止")

        log_bus.event_log.connect(
            lambda lvl, tag, msg: print(f"[{lvl}] <{tag}> {msg}"))

        async def _main():
            s1 = Socks5Server(port=1081, auth_required=False, label="录制")
            s2 = Socks5Server(port=1080, auth_required=True,
                              users=user_manager.to_dict(), label="重放")
            await asyncio.gather(s1.start(), s2.start())

        try:
            asyncio.run(_main())
        except KeyboardInterrupt:
            print("\n[headless] 已停止")
        sys.exit(0)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
