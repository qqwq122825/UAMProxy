import os
import json
import threading
import time

from core.events import log_bus, _event
from core.crypto import (
    AceCaptureAssembler,
    _ace_split_packets,
    _ace_try_extract,
    _parse_ace_account_id,
)
from core.traffic_session_log import traffic_file_logger

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
        self._capture_assemblers: dict[str, AceCaptureAssembler] = {}

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

    def _remove_stale_game_sessions_locked(self, current: dict, game_id: str) -> int:
        """新录制识别账号后，只保留当前会话，避免旧池继续被合并追加。"""
        removed = 0
        for ip, sessions in list(self._sessions.items()):
            stale = [
                session for session in sessions
                if session is not current
                and not session.get("active")
                and str(session.get("game_id") or "") == str(game_id)
            ]
            if stale:
                removed += sum(
                    session.get("_pool_count") or len(self._session_pool(session))
                    for session in stale
                )
                self._sessions[ip] = [session for session in sessions if session not in stale]
                if not self._sessions[ip]:
                    self._sessions.pop(ip, None)
        return removed

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
        cleared_count = 0
        with self._lock:
            active = self._active_session(client_ip)
            if active:
                active["_refs"] = active.get("_refs", 1) + 1
                return False
            # 一个新的录制生命周期必须从空池开始。旧实现保留同 IP 历史会话，
            # 后续 find_pool_by_game_id 会把新旧模板合并，表现为“不明原因追加录制”。
            old_sessions = self._sessions.pop(client_ip, [])
            self._capture_assemblers[client_ip] = AceCaptureAssembler()
            cleared_count = sum(
                session.get("_pool_count") or len(self._session_pool(session))
                for session in old_sessions
            )
            sessions = self._sessions.setdefault(client_ip, [])
            sid = f"{client_ip}#{int(time.time())}"
            sessions.append({"sid": sid, "pkts": [], "active": True,
                              "game_id": "", "created_at": time.time(),
                              "last_record_at": 0.0,
                              "pool_items": [], "_pool_count": 0,
                              "pool_01_items": [], "pool_33_items": [],
                              "_refs": 1, "_ghost": True,
                              "_generation": 1, "_join_conn_id": "",
                              "raw_3366": [], "ace_product": "",
                              "product_hex_3366": "", "product_name_3366": "",
                              "game_id_source": "",
                              "ace_user_01": "",
                              "ace_user_3366": "",
                              "has_3366_key": False})
        if cleared_count:
            _event(
                "RECORD", "录制",
                f"[{client_ip}] 新录制上线，已清空上一轮录制池（{cleared_count} 条模板）",
            )
            log_bus.record_updated.emit()
        return True

    def set_session_3366_key_ready(self, client_ip: str) -> None:
        """
        暗区突围等：首下行 10 02 取到 Key 时调用，会话加入录制管理（不要求已有 01 0A 00 xx）。
        """
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return
            if not s.get("has_3366_key"):
                s["has_3366_key"] = True
                s["_ghost"] = False
                if not s.get("game_id") and s.get("ace_user_3366"):
                    s["game_id"] = s["ace_user_3366"]
                    s["game_id_source"] = "3366_key"
        log_bus.record_updated.emit()

    def note_join_packet(self, client_ip: str, conn_id: str) -> bool:
        """
        记录 42B 加入包。若活跃会话已经有模板，而新的 01 连接再次出现加入包，
        视为新一轮录制并原地清空旧池；保留引用计数，兼容上一轮残留 TCP 稍后断开。
        """
        cleared = 0
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return False
            previous_conn = s.get("_join_conn_id") or ""
            if not previous_conn:
                s["_join_conn_id"] = conn_id
                return False
            if previous_conn == conn_id:
                return False
            pool = self._session_pool(s)
            if not pool:
                s["_join_conn_id"] = conn_id
                return False
            cleared = len(pool)
            refs = max(1, int(s.get("_refs", 1) or 1))
            generation = int(s.get("_generation", 1) or 1) + 1
            s.update({
                "sid": f"{client_ip}#{int(time.time())}-{generation}",
                "pkts": [],
                "game_id": "",
                "created_at": time.time(),
                "last_record_at": 0.0,
                "pool_items": [],
                "_pool_count": 0,
                "pool_01_items": [],
                "pool_33_items": [],
                "_refs": refs,
                "_ghost": True,
                "_generation": generation,
                "_join_conn_id": conn_id,
                "raw_3366": [],
                "ace_product": "",
                "product_hex_3366": "",
                "product_name_3366": "",
                "game_id_source": "",
                "ace_user_01": "",
                "ace_user_3366": "",
                "has_3366_key": False,
            })
            self._capture_assemblers[client_ip] = AceCaptureAssembler()
        _event(
            "RECORD", "录制",
            f"[{client_ip}] 检测到新的 42B 加入包，已清空上一轮录制池（{cleared} 条模板）",
        )
        log_bus.record_updated.emit()
        return True

    def set_session_3366_product(
        self, client_ip: str, product_hex: str, product_name: str = ""
    ) -> None:
        """
        由 server 在 3366 帧中识别到产品 ID 时写入当前活跃会话，并刷新录制管理 UI。
        product_hex：8 位大写 hex，如 0000094E。
        重放连接同样需要发射信号以更新 UI 游戏名，即使没有活跃录制会话也要发。
        """
        product_hex = (product_hex or "").strip().upper()
        product_name = (product_name or "").strip()
        if not product_hex:
            return
        # 无论有无录制会话，先发信号让 UI 更新连接表的游戏名（重放连接也需要）
        try:
            log_bus.conn_3366_product.emit(client_ip, product_hex, product_name or product_hex)
        except Exception:
            pass
        changed = False
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return
            if s.get("product_hex_3366") != product_hex:
                s["product_hex_3366"] = product_hex
                changed = True
            if product_name and s.get("product_name_3366") != product_name:
                s["product_name_3366"] = product_name
                changed = True
        if changed:
            log_bus.record_updated.emit()

    def get_active_session_ace_ids(self, client_ip: str) -> tuple[str, str]:
        """当前活跃录制会话中，01 通道与 3366 通道分别解析到的账号串（可对账）。"""
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return "", ""
            return (
                (s.get("ace_user_01") or "").strip(),
                (s.get("ace_user_3366") or "").strip(),
            )

    def get_active_01_count(self, client_ip: str) -> int:
        """当前活跃录制会话中，来源为 01 的池条目数量（用于自动断线阈值判断）。"""
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return 0
            pool = self._session_pool(s)
            return sum(1 for it in pool if str(it.get("source", "") or "") == "01")

    def get_active_33_count(self, client_ip: str) -> int:
        """当前活跃录制会话中，来源为 3366（09/21）的池条目数量。"""
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return 0
            pool = self._session_pool(s)
            return sum(1 for it in pool if str(it.get("source", "") or "").startswith("3366"))

    def append(self, client_ip: str, data: bytes):
        """录制一个 01 00 开头的包，追加到当前活跃会话。
        · 新增加密区时：发出轻量 record_count(sid, count) 信号（每包实时）
        · 会话级 ACE 标识（game_id）：**以 01 通道解析为准**（覆盖 3366 临时值，并回填池中 3366 条目的 account_id）。
        · 3366 仅可在尚无 game_id 时暂存（见 append_from_3366_plain）。
        · 标识变化时：去重旧会话、conn_game_id_update、全量刷新等。
        """
        emit_full   = False
        count_info: tuple | None = None
        replaced_info: tuple | None = None   # (game_id, old_count) 替换时记录
        with self._lock:
            s = self._active_session(client_ip)
            if s:
                new_items = []
                assembler = self._capture_assemblers.setdefault(
                    client_ip, AceCaptureAssembler()
                )
                for sub in _ace_split_packets(data):
                    item = assembler.feed(sub)
                    if item:
                        new_items.append(item)
                        raw_blk = item.get("raw_packet")
                        if raw_blk:
                            s["pkts"].append(raw_blk)  # 仅 01 0A 00 09/21 块，不存完整封包
                if new_items:
                    pool = RecordingPool._session_pool(s)
                    pool.extend(new_items)
                    s.setdefault("pool_01_items", []).extend(new_items)
                    s["_pool_count"] = len(pool)
                    s["last_record_at"] = time.time()
                    if not s.get("_ghost"):
                        count_info = (s["sid"], s["_pool_count"])
                gid = _parse_ace_account_id(data)
                if gid:
                    prev_a1 = s.get("ace_user_01") or ""
                    s["ace_user_01"] = gid
                    if prev_a1 != gid:
                        try:
                            log_bus.conn_ace_channels_updated.emit(client_ip)
                        except Exception:
                            pass
                    prev = s.get("game_id") or ""
                    s["game_id"] = gid
                    s["game_id_source"] = "01"
                    s["_ghost"] = False
                    pool = RecordingPool._session_pool(s)
                    backfill_changed = False
                    for it in pool:
                        if str(it.get("source", "")).startswith("3366"):
                            if it.get("account_id") != gid:
                                it["account_id"] = gid
                                backfill_changed = True
                    if prev != gid:
                        emit_full = True
                        log_bus.conn_game_id_update.emit(client_ip, str(gid), "录制")
                        old_cnt = self._remove_stale_game_sessions_locked(s, gid)
                        if old_cnt:
                            replaced_info = (gid, old_cnt)
                    elif backfill_changed:
                        log_bus.record_updated.emit()
        if replaced_info:
            gid, old_cnt = replaced_info
            _event("RECORD", "录制",
                   f"[{client_ip}] 游戏ID=[{gid}] 已存在旧录制（{old_cnt}个加密区），已替换为新录制")
        if emit_full:
            log_bus.record_updated.emit()
        elif count_info:
            log_bus.record_count.emit(*count_info)

    def apply_3366_handshake_user_id(self, client_ip: str, uid: str) -> None:
        """
        3366 上行 10 01 首包中的用户 ID（TLV）；后续帧通常不再携带。
        **ace_user_3366** 始终更新，便于与 01 侧 ace_user_01 对账。
        若 game_id 已由 01 锁定，不改编 game_id / game_id_source，录制照常。
        否则按原逻辑用握手 ID 暂存会话 game_id。
        """
        uid = (uid or "").strip()
        if not uid:
            return
        emit_full = False
        replaced_info: tuple | None = None
        need_conn_refresh = False
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return
            prev36 = s.get("ace_user_3366") or ""
            s["ace_user_3366"] = uid
            if prev36 != uid:
                need_conn_refresh = True

            if s.get("game_id_source") == "01":
                pass
            else:
                prev = s.get("game_id") or ""
                s["game_id"] = uid
                s["game_id_source"] = "3366_handshake"
                s["_ghost"] = False
                pool = RecordingPool._session_pool(s)
                for it in pool:
                    if str(it.get("source", "")).startswith("3366"):
                        if it.get("account_id") != uid:
                            it["account_id"] = uid
                if prev != uid:
                    emit_full = True
                    log_bus.conn_game_id_update.emit(client_ip, str(uid), "录制")
                    old_cnt = self._remove_stale_game_sessions_locked(s, uid)
                    if old_cnt:
                        replaced_info = (uid, old_cnt)
        if replaced_info:
            g, old_cnt = replaced_info
            _event(
                "RECORD",
                "录制",
                f"[{client_ip}] 游戏ID=[{g}] 已存在旧录制（{old_cnt}个加密区），已替换为新录制",
            )
        if emit_full:
            log_bus.record_updated.emit()
        if need_conn_refresh:
            try:
                log_bus.conn_ace_channels_updated.emit(client_ip)
            except Exception:
                pass

    def append_from_3366_plain(self, client_ip: str, plain: bytes, items: list[dict],
                                conn_uid: str = ""):
        """
        将 40 13 解密明文中提取的 01 0A 00 09 / 21 高熵块并入**同一**加密区池（与 01 通道录制共用）。
        会话级 ACE 标识：仅当当前会话尚无 game_id 时，才用明文解析结果暂存；**01 包到达后一律以 01 为准覆盖**。
        若会话已有 01 写下的 game_id，本批 3366 条目的 account_id 直接沿用该串，而不用明文内解析值。
        conn_uid: 本条33连接握手中解析出的游戏UID，用于校验与当前会话game_id是否一致。
        """
        if not items:
            return
        pass  # 3366 通道切片由 33_uplink.log 记录，不写入 01_sliced.log
        emit_full = False
        count_info: tuple | None = None
        replaced_info: tuple | None = None
        uid_mismatch_warn: str | None = None
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return
            sess_gid = (s.get("game_id") or "").strip()
            # UID一致性校验：conn_uid 与会话已知 game_id 不匹配时记录警告
            if conn_uid and sess_gid and s.get("game_id_source") == "01":
                if str(conn_uid).strip() != sess_gid:
                    uid_mismatch_warn = (
                        f"[{client_ip}] UID不匹配！33握手uid=[{conn_uid}] vs 会话game_id=[{sess_gid}]"
                        f"（来源:01通道），本批33数据仍入池但account_id保持会话uid"
                    )
            if sess_gid:
                for it in items:
                    it["account_id"] = sess_gid
            pool = RecordingPool._session_pool(s)
            pool.extend(items)
            s.setdefault("pool_33_items", []).extend(items)
            s["_pool_count"] = len(pool)
            s["last_record_at"] = time.time()
            if not s.get("_ghost"):
                count_info = (s["sid"], s["_pool_count"])
            gid = _parse_ace_account_id(plain)
            if gid and not s["game_id"]:
                s["game_id"] = gid
                s["game_id_source"] = "3366_plain"
                if not (s.get("ace_user_3366") or "").strip():
                    s["ace_user_3366"] = gid
                    try:
                        log_bus.conn_ace_channels_updated.emit(client_ip)
                    except Exception:
                        pass
                for it in items:
                    it["account_id"] = gid
                s["_ghost"] = False
                emit_full = True
                log_bus.conn_game_id_update.emit(client_ip, str(gid), "录制")
                old_cnt = self._remove_stale_game_sessions_locked(s, gid)
                if old_cnt:
                    replaced_info = (gid, old_cnt)
        if uid_mismatch_warn:
            _event("WARN", "录制", uid_mismatch_warn)
        if replaced_info:
            gid, old_cnt = replaced_info
            _event("RECORD", "录制",
                   f"[{client_ip}] 游戏ID=[{gid}] 已存在旧录制（{old_cnt}个加密区），已替换为新录制")
        if emit_full:
            log_bus.record_updated.emit()
        elif count_info:
            log_bus.record_count.emit(*count_info)

    def append_3366(
        self,
        client_ip: str,
        direction: str,
        frame: bytes,
        *,
        product_label: str | None = None,
    ):
        """
        录制完整 33 66 帧（上下行均可）。用于后续解密分析与重放骨架。
        任意一帧写入后即可结束「幽灵」会话占位（与仅 01 路径一致可展示）。
        """
        emit_full = False
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return
            s.setdefault("raw_3366", []).append(
                {"dir": direction, "data": bytes(frame), "t": time.time()}
            )
            if product_label:
                s["ace_product"] = product_label
            if s.get("_ghost"):
                s["_ghost"] = False
                emit_full = True
        if emit_full:
            log_bus.record_updated.emit()

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
            
            # 如果断开时仍然是幽灵会话（无用户ID、无Key、无池数据），静默删除
            if s.get("_ghost"):
                pool = self._session_pool(s)
                has_3366 = bool(s.get("raw_3366")) or any(
                    str(x.get("source", "")).startswith("3366") for x in pool
                )
                has_user_or_key = bool(s.get("ace_user_3366") or s.get("ace_user_01") or s.get("has_3366_key"))
                if not has_3366 and not has_user_or_key:
                    sessions = self._sessions.get(client_ip, [])
                    if s in sessions:
                        sessions.remove(s)
                    discarded_ghost = True
                else:
                    s["_ghost"] = False

        if not discarded_ghost:
            log_bus.record_updated.emit()
        return result if not discarded_ghost else (0, "")

    def is_game_id_being_replayed(self, game_id: str) -> bool:
        """
        检查该游戏账号是否有重放端口活跃连接正在使用（_conn_live_gid 中已识别该 uid）。
        录制端口识别到 uid 时调用：若 uid 正在被重放，则阻止追加录制（01 不入池、33 断连）。
        重放端空闲超时断开后，_conn_live_gid 会被清理，此方法自动返回 False。
        """
        if not game_id:
            return False
        try:
            from .server import engine
            if engine.server_1080:
                for gid in engine.server_1080._conn_live_gid.values():
                    if str(gid) == str(game_id):
                        return True
        except Exception:
            pass
        return False

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

    def get_all_ip_pools(self, client_ip: str) -> dict[str, dict[str, list[dict]]]:
        """
        返回该 IP 所有会话的重放池，按 game_id 索引，每个 game_id 下分 pool_01 / pool_33。
        pool_01：仅 01 来源；pool_33：仅 3366 来源（09/21）。同 game_id 多会话时合并两池。
        返回的是 pool_items 列表的引用，录制端 append() 时重放端可实时生效。
        """
        with self._lock:
            result: dict[str, dict[str, list[dict]]] = {}
            for s in self._sessions.get(client_ip, []):
                if s.get("_ghost"):
                    continue
                pool = self._session_pool(s)
                if not pool:
                    continue
                gid = s.get("game_id", "") or s["sid"].replace(":", "_")
                if gid not in result:
                    if "pool_01_items" in s:
                        # 直接引用 session 内的分类列表，录制追加时重放端实时可见
                        result[gid] = {
                            "pool_01": s["pool_01_items"],
                            "pool_33": s["pool_33_items"],
                        }
                    else:
                        # 旧格式（导入数据）：数据已完整，拷贝过滤
                        result[gid] = {"pool_01": [], "pool_33": []}
                        for it in pool:
                            src = str(it.get("source", "") or "")
                            if src.startswith("3366"):
                                result[gid]["pool_33"].append(it)
                            else:
                                result[gid]["pool_01"].append(it)
                else:
                    # 同 gid 多 session（已完成录制合并）：拷贝追加
                    if "pool_01_items" in s:
                        result[gid]["pool_01"] = list(result[gid]["pool_01"]) + s["pool_01_items"]
                        result[gid]["pool_33"] = list(result[gid]["pool_33"]) + s["pool_33_items"]
                    else:
                        for it in pool:
                            src = str(it.get("source", "") or "")
                            if src.startswith("3366"):
                                result[gid]["pool_33"].append(it)
                            else:
                                result[gid]["pool_01"].append(it)
            for gid in list(result.keys()):
                if not result[gid]["pool_01"] and not result[gid]["pool_33"]:
                    del result[gid]
        return result

    def find_pool_by_game_id(self, game_id: str) -> dict[str, list[dict]] | None:
        """
        跨所有录制 IP 查找 game_id 匹配的录制池。
        用于重放用户 IP 与录制用户 IP 不同、但游戏账号相同时的跨 IP 匹配。
        返回合并后的 {pool_01: [...], pool_33: [...]}，未找到则返回 None。
        """
        if not game_id:
            return None
        with self._lock:
            matched_sessions = []
            for sessions in self._sessions.values():
                for s in sessions:
                    if s.get("_ghost"):
                        continue
                    if str(s.get("game_id") or "") != str(game_id):
                        continue
                    pool = self._session_pool(s)
                    if not pool:
                        continue
                    matched_sessions.append(s)
            if not matched_sessions:
                return None
            if len(matched_sessions) == 1:
                s = matched_sessions[0]
                if "pool_01_items" in s:
                    # 单 session：直接返回引用，录制追加时重放端实时可见
                    return {"pool_01": s["pool_01_items"], "pool_33": s["pool_33_items"]}
            # 多 session 或旧格式：合并拷贝
            result: dict[str, list[dict]] = {"pool_01": [], "pool_33": []}
            for s in matched_sessions:
                if "pool_01_items" in s:
                    result["pool_01"].extend(s["pool_01_items"])
                    result["pool_33"].extend(s["pool_33_items"])
                else:
                    for it in self._session_pool(s):
                        src = str(it.get("source", "") or "")
                        if src.startswith("3366"):
                            result["pool_33"].append(it)
                        else:
                            result["pool_01"].append(it)
            return result

    def is_game_id_actively_recording(self, game_id: str) -> bool:
        """判断指定游戏账号是否有活跃录制会话（任意IP）。跨IP实时重放判断使用。"""
        if not game_id:
            return False
        with self._lock:
            for sessions in self._sessions.values():
                for s in sessions:
                    if s.get("_ghost"):
                        continue
                    if str(s.get("game_id") or "") == str(game_id) and s.get("active"):
                        return True
        return False

    def get_all_game_ids(self) -> list[str]:
        """返回当前所有录制会话中已识别的游戏账号列表（去重）。"""
        with self._lock:
            ids = set()
            for sessions in self._sessions.values():
                for s in sessions:
                    if s.get("_ghost"):
                        continue
                    gid = s.get("game_id")
                    if gid:
                        ids.add(str(gid))
            return sorted(ids)

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

    @staticmethod
    def _account_preview_from_pool(pool: list[dict]) -> str:
        """池内去重后的账户 ID 摘要（与重放匹配用的游戏账号一致）。"""
        seen: list[str] = []
        for it in pool:
            a = (it.get("account_id") or "").strip()
            if a and a not in seen:
                seen.append(a)
            if len(seen) >= 4:
                break
        if not seen:
            return ""
        if len(seen) > 3:
            return " / ".join(seen[:3]) + "…"
        return " / ".join(seen)

    def get_pool_item_rows(self, sid: str) -> list[dict]:
        """
        供录制管理 Tab 列表：每条含 payload、来源标签（01 / 3366）。
        """
        with self._lock:
            ip = sid.rsplit("#", 1)[0]
            for s in self._sessions.get(ip, []):
                if s["sid"] == sid:
                    pool = self._session_pool(s)
                    rows = []
                    for item in pool:
                        raw = item.get("source") or "01"
                        if str(raw).startswith("3366"):
                            lbl = "3366"
                        else:
                            lbl = "01"
                        rows.append({
                            "payload": item.get("payload") or b"",
                            "raw_packet": item.get("raw_packet") or b"",
                            "source": lbl,
                            "source_detail": str(raw),
                            "anchor_kind": item.get("anchor_kind") or "",
                        })
                    return rows
        return []

    def get_game_id_for_sid(self, sid: str) -> str:
        """根据 sid 返回对应会话的 game_id（用于轻量更新时定位行）"""
        with self._lock:
            ip = sid.rsplit("#", 1)[0]
            for s in self._sessions.get(ip, []):
                if s["sid"] == sid:
                    gid = (s.get("game_id") or "").strip()
                    if not gid and (s.get("ace_user_3366") or s.get("has_3366_key")):
                        return f"待识别-{ip}"
                    return gid or f"待识别-{ip}"
        return ""

    def get_aggregated_counts_for_game_id(self, game_id: str) -> tuple[int, int]:
        """返回该 game_id 下所有会话聚合的 (count_01, count_3366)"""
        with self._lock:
            n01, n3366 = 0, 0
            for ip, sessions in self._sessions.items():
                for s in sessions:
                    if s.get("_ghost"):
                        continue
                    gid = s.get("game_id", "")
                    if game_id.startswith("待识别-"):
                        if ip != game_id.replace("待识别-", "", 1) or gid:
                            continue
                    elif gid != game_id:
                        continue
                    pool = self._session_pool(s)
                    for x in pool:
                        if str(x.get("source", "")).startswith("3366"):
                            n3366 += 1
                        else:
                            n01 += 1
            return n01, n3366

    def get_last_record_at_for_game_id(self, game_id: str) -> float:
        """返回该 game_id 下所有会话中最新的 last_record_at 时间戳"""
        with self._lock:
            latest = 0.0
            for ip, sessions in self._sessions.items():
                for s in sessions:
                    if s.get("_ghost"):
                        continue
                    gid = s.get("game_id", "")
                    if game_id.startswith("待识别-"):
                        if ip != game_id.replace("待识别-", "", 1) or gid:
                            continue
                    elif gid != game_id:
                        continue
                    t = s.get("last_record_at", 0.0) or 0.0
                    if t > latest:
                        latest = t
            return latest

    def get_pool_item_rows_by_game_id(self, game_id: str) -> list[dict]:
        """
        按游戏用户 ID 聚合：返回该 game_id 下所有会话的池项合并列表。
        game_id 为 "待识别-{ip}" 时，取该 ip 下无 game_id 的会话。
        """
        with self._lock:
            rows: list[dict] = []
            for ip, sessions in self._sessions.items():
                for s in sessions:
                    if s.get("_ghost"):
                        continue
                    gid = s.get("game_id", "")
                    if game_id.startswith("待识别-"):
                        want_ip = game_id.replace("待识别-", "", 1)
                        if ip != want_ip or gid:
                            continue
                    elif gid != game_id:
                        continue
                    pool = self._session_pool(s)
                    for item in pool:
                        raw = item.get("source") or "01"
                        lbl = "3366" if str(raw).startswith("3366") else "01"
                        rows.append({
                            "payload": item.get("payload") or b"",
                            "raw_packet": item.get("raw_packet") or b"",
                            "source": lbl,
                            "source_detail": str(raw),
                            "anchor_kind": item.get("anchor_kind") or "",
                        })
            return rows

    def get_all_sessions(self) -> list[dict]:
        """
        返回按游戏用户 ID 聚合的会话摘要，供录制管理 Tab 全量刷新。
        每行：游戏用户ID | 01数 | 33数 | 来源IP | 状态。
        过滤掉“幽灵”会话。
        """
        with self._lock:
            # 先收集所有非幽灵会话的原始数据
            raw_list: list[dict] = []
            for ip, sessions in self._sessions.items():
                for s in sessions:
                    if s.get("_ghost"):
                        continue
                    pool = self._session_pool(s)
                    cached = len(pool)
                    s["_pool_count"] = cached
                    n3366 = sum(
                        1 for x in pool if str(x.get("source", "")).startswith("3366")
                    )
                    n01 = cached - n3366
                    gid = (s.get("game_id") or "").strip()
                    if not gid and (s.get("ace_user_3366") or s.get("has_3366_key")):
                        gid = f"待识别-{ip}"
                    raw_list.append({
                        "sid": s["sid"],
                        "ip": ip,
                        "game_id": gid or f"待识别-{ip}",
                        "count_01": n01,
                        "count_3366": n3366,
                        "count": cached,
                        "active": s.get("active", False),
                        "ace_product": s.get("ace_product", ""),
                        "product_hex_3366": s.get("product_hex_3366", ""),
                        "product_name_3366": s.get("product_name_3366", ""),
                        "count_3366_raw": len(s.get("raw_3366", [])),
                        "last_record_at": s.get("last_record_at", 0.0),
                    })
            # 按 game_id 聚合
            agg: dict[str, dict] = {}
            for r in raw_list:
                gid = r["game_id"]
                if gid not in agg:
                    agg[gid] = {
                        "game_id": gid,
                        "count_01": 0,
                        "count_3366": 0,
                        "count": 0,
                        "ips": [],
                        "active": False,
                        "sid": r["sid"],
                        "ace_product": r.get("ace_product", ""),
                        "product_hex_3366": r.get("product_hex_3366", ""),
                        "product_name_3366": r.get("product_name_3366", ""),
                        "count_3366_raw": 0,
                        "last_record_at": 0.0,
                    }
                agg[gid]["count_01"] += r["count_01"]
                agg[gid]["count_3366"] += r["count_3366"]
                agg[gid]["count"] += r["count"]
                agg[gid]["count_3366_raw"] += r.get("count_3366_raw", 0)
                if r["ip"] not in agg[gid]["ips"]:
                    agg[gid]["ips"].append(r["ip"])
                if r["active"]:
                    agg[gid]["active"] = True
                # 取多个会话中最新的录制时间
                t = r.get("last_record_at", 0.0) or 0.0
                if t > agg[gid]["last_record_at"]:
                    agg[gid]["last_record_at"] = t
            result = list(agg.values())
            # 排序：活跃优先，再按最近录制时间倒序，最后待识别排末尾
            def _sk(x: dict):
                g = (x.get("game_id") or "").strip()
                is_pending = 1 if g.startswith("待识别-") else 0
                active = 0 if x.get("active") else 1   # 活跃=0排前
                last_t = x.get("last_record_at", 0.0) or 0.0
                return (is_pending, active, -last_t)

            result.sort(key=_sk)
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
        导出所有会话为 JSON（v5 格式，含 type-9 结构化记录元数据）。
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
                                "source":     item.get("source") or "",
                                "raw_packet": (item.get("raw_packet") or b"").hex(),
                                "schema": item.get("schema") or "",
                                "fragment_count": int(item.get("fragment_count", 1) or 1),
                                "logical_payload_sha256": item.get("logical_payload_sha256") or "",
                                "encrypted_record_sha256": item.get("encrypted_record_sha256") or "",
                            }
                            for item in pool
                        ]
                        raw3366 = s.get("raw_3366") or []
                        raw3366_export = [
                            {"dir": e["dir"], "hex": e["data"].hex()}
                            for e in raw3366[:4000]
                        ]
                        ip_list.append({
                            "sid":        s["sid"],
                            "game_id":    s.get("game_id", ""),
                            "game_id_source": s.get("game_id_source", ""),
                            "ace_user_01": s.get("ace_user_01", ""),
                            "ace_user_3366": s.get("ace_user_3366", ""),
                            "ace_product": s.get("ace_product", ""),
                            "product_hex_3366": s.get("product_hex_3366", ""),
                            "product_name_3366": s.get("product_name_3366", ""),
                            "active":     False,
                            "created_at": s.get("created_at", time.time()),
                            "pool_items": pool_export,
                            "raw_3366": raw3366_export,
                        })
                    if ip_list:
                        data[ip] = ip_list
            payload = {"version": 5, "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
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
          v4/v5：pool_items（v5 额外含 type-9 schema/分片/hash）
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
                                    "source":     pi.get("source") or "01",
                                    "raw_packet": bytes.fromhex(pi.get("raw_packet", "")),
                                    "schema": pi.get("schema") or "",
                                    "fragment_count": int(pi.get("fragment_count", 1) or 1),
                                    "logical_payload_sha256": pi.get("logical_payload_sha256") or "",
                                    "encrypted_record_sha256": pi.get("encrypted_record_sha256") or "",
                                }
                                for pi in item["pool_items"]
                            ]
                            raw_hex_list = item.get("raw_3366") or []
                            raw_3366_imp = []
                            for e in raw_hex_list:
                                try:
                                    raw_3366_imp.append({
                                        "dir": e["dir"],
                                        "data": bytes.fromhex(e["hex"]),
                                        "t": item.get("created_at", time.time()),
                                    })
                                except (ValueError, KeyError, TypeError):
                                    continue
                            new_s = {
                                "sid":        sid,
                                "game_id":    item.get("game_id", ""),
                                "game_id_source": item.get("game_id_source", ""),
                                "ace_user_01": item.get("ace_user_01", ""),
                                "ace_user_3366": item.get("ace_user_3366", ""),
                                "ace_product": item.get("ace_product", ""),
                                "product_hex_3366": item.get("product_hex_3366", ""),
                                "product_name_3366": item.get("product_name_3366", ""),
                                "active":     False,
                                "created_at": item.get("created_at", time.time()),
                                "pool_items": pool_items,
                                "_pool_count": len(pool_items),
                                "raw_3366": raw_3366_imp,
                                "pkts": [],
                            }
                        else:
                            # v2/v3：原始 pkts，导入时转换为 pool_items
                            raw_pkts = [bytes.fromhex(p) for p in item.get("pkts", [])]
                            pool_items = self._build_pool(raw_pkts)
                            raw_hex_list = item.get("raw_3366") or []
                            raw_3366_imp = []
                            for e in raw_hex_list:
                                try:
                                    raw_3366_imp.append({
                                        "dir": e["dir"],
                                        "data": bytes.fromhex(e["hex"]),
                                        "t": item.get("created_at", time.time()),
                                    })
                                except (ValueError, KeyError, TypeError):
                                    continue
                            new_s = {
                                "sid":        sid,
                                "game_id":    item.get("game_id", ""),
                                "game_id_source": item.get("game_id_source", ""),
                                "ace_user_01": item.get("ace_user_01", ""),
                                "ace_user_3366": item.get("ace_user_3366", ""),
                                "ace_product": item.get("ace_product", ""),
                                "product_hex_3366": item.get("product_hex_3366", ""),
                                "product_name_3366": item.get("product_name_3366", ""),
                                "active":     False,
                                "created_at": item.get("created_at", time.time()),
                                "pool_items": pool_items,
                                "_pool_count": len(pool_items),
                                "raw_3366": raw_3366_imp,
                                "pkts": raw_pkts,
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
