from __future__ import annotations

import os
import json
import hashlib
import threading
import time
from collections import Counter, defaultdict

from core.config import DATA_DIR, app_config
from core.events import log_bus, _event
from core.crypto import (
    _ace_01_fragment_key,
    _ace_01_frame_meta,
    _ace_split_packets,
    _ace_try_extract,
    _ace_try_extract_frames,
    _parse_ace_account_id,
)
from core.traffic_session_log import traffic_file_logger
from core.dfm_message_catalog import (
    message_observation_details_from_item,
    summarize_message_observations,
)
from core.type9_v128_replenish import PLAYER_SCAN_WAVE_MESSAGE_IDS

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
        # 保留当前进程的录制状态；新会话统一进入玩家设备池。
        self._official_arms: dict[str, dict] = {}
        self._snapshot_path = os.path.join(DATA_DIR, "v117_recording_pools.json")

    def load_snapshot(self) -> tuple[bool, str]:
        """启动时恢复当前版本的统一玩家录制池。"""
        loaded: list[str] = []
        if os.path.isfile(self._snapshot_path):
            ok, msg = self.import_from_file(
                self._snapshot_path,
                overwrite=True,
                persist=False,
            )
            if not ok:
                return ok, msg
            loaded.append("玩家录制池")
        if not loaded:
            return True, "录制池快照尚未创建"
        return True, f"已自动恢复：{'、'.join(loaded)}"

    def save_snapshot(self) -> tuple[bool, str]:
        """持久化玩家录制，供同设备跨账号与游戏ID回退长期复用。"""
        return self.export_to_file(
            self._snapshot_path,
            export_scope="player",
        )

    def save_official_templates(self) -> tuple[bool, str]:
        """当前版本不使用独立官方模板文件。"""
        return True, "统一玩家录制池已保存"

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

    @staticmethod
    def _log_record_session(
        *,
        action: str,
        session: dict,
        client_ip: str,
        reason: str,
    ) -> None:
        """兼容精简运行环境的录制生命周期日志调用。"""
        try:
            logger = getattr(traffic_file_logger, "log_record_session_event", None)
            if logger:
                logger(
                    action=action,
                    session=session,
                    client_ip=client_ip,
                    reason=reason,
                )
        except Exception:
            pass

    @staticmethod
    def _clear_session_01_locked(s: dict) -> int:
        """
        原地清空会话中的 01 录制，保留 3366 池。

        必须原地修改 pool_items / pool_01_items，已有重放连接可能正持有这些
        list 的引用；重新赋值会让旧引用继续读到过期数据。
        """
        pool = RecordingPool._session_pool(s)
        old_count = sum(
            1 for item in pool
            if not str(item.get("source", "") or "").startswith("3366")
        )
        pool[:] = [
            item for item in pool
            if str(item.get("source", "") or "").startswith("3366")
        ]
        pool_01 = s.setdefault("pool_01_items", [])
        pool_01.clear()
        s.setdefault("pkts", []).clear()
        s.setdefault("_01_fragment_groups", {}).clear()
        s["_pool_count"] = len(pool)
        RecordingPool._reset_message_coverage_locked(s)
        RecordingPool._reset_device_context_locked(s)
        return old_count

    @staticmethod
    def _reset_message_coverage_locked(s: dict) -> None:
        """清空会话消息覆盖率缓存；调用方必须已经持有录制池锁。"""
        s["_message_coverage_ready"] = True
        s["_message_id_counts"] = Counter()
        s["_message_id_lengths"] = defaultdict(set)
        s["_message_id_slots"] = defaultdict(set)
        s["_message_id_subtypes"] = defaultdict(set)
        s["_scan_wave_rows"] = []
        s["_message_decoded_reports"] = 0
        s["_message_decode_failures"] = 0

    @staticmethod
    def _reset_device_context_locked(s: dict) -> None:
        """清空录制会话的派生设备画像缓存。"""
        s["_device_context_ready"] = True
        s["_device_context"] = {}

    @staticmethod
    def _append_device_context_locked(s: dict, items: list[dict]) -> None:
        """从新增Type9录制中增量提取型号、系统版本与IDFV。"""
        from core.type9_shadow import (
            extract_device_context_from_logical,
            extract_device_context_from_rows,
            merge_device_context,
        )

        context = dict(s.get("_device_context") or {})
        for item in items:
            if str(item.get("source") or "01").startswith("3366"):
                continue
            cached = item.get("_type9_shadow_leaf_cache") or {}
            rows = list(cached.get("rows") or []) if cached.get("ok") else []
            observed = (
                extract_device_context_from_rows(rows)
                if rows
                else extract_device_context_from_logical(
                    bytes(item.get("raw_packet") or b"")
                )
            )
            context = merge_device_context(context, observed)
        s["_device_context"] = context
        s["_device_context_ready"] = True

    @staticmethod
    def _ensure_device_context_locked(s: dict) -> None:
        """旧快照/导入会话首次显示时延迟提取设备画像。"""
        if s.get("_device_context_ready"):
            return
        RecordingPool._reset_device_context_locked(s)
        RecordingPool._append_device_context_locked(
            s, RecordingPool._session_pool(s)
        )

    @staticmethod
    def _device_fingerprint(context: dict) -> str:
        """生成稳定的同设备显示指纹；完整判定仍使用原始三字段。"""
        required = (
            str(context.get("model") or "").strip(),
            str(context.get("system_version") or "").strip(),
            str(context.get("device_idfv") or "").strip(),
        )
        if not all(required):
            return ""
        return hashlib.sha256("\x1f".join(required).encode("utf-8")).hexdigest()

    @staticmethod
    def _summarize_device_contexts(contexts: list[dict]) -> dict:
        """把同一游戏ID下的一个或多个录制会话整理为UI摘要。"""
        from core.type9_shadow import merge_device_context

        nonempty = [dict(row) for row in contexts if row]
        merged: dict = {}
        for row in nonempty:
            merged = merge_device_context(merged, row)
        fingerprints = sorted({
            value
            for value in (
                RecordingPool._device_fingerprint(row) for row in nonempty
            )
            if value
        })
        identity_fields = (
            "model",
            "hardware_model",
            "system_version",
            "device_idfv",
        )
        distinct_values = {
            key: {
                str(row.get(key) or "").strip()
                for row in nonempty
                if str(row.get(key) or "").strip()
            }
            for key in identity_fields
        }
        conflict = any(len(values) > 1 for values in distinct_values.values())
        complete = bool(RecordingPool._device_fingerprint(merged))
        if len(fingerprints) > 1 or conflict:
            status = "multiple"
        elif complete:
            status = "complete"
        elif merged:
            status = "partial"
        else:
            status = "pending"
        fingerprint = (
            fingerprints[0]
            if len(fingerprints) == 1 and not conflict
            else RecordingPool._device_fingerprint(merged)
            if not fingerprints and complete and not conflict
            else ""
        )
        observed_device_count = max(
            [len(fingerprints)]
            + [len(values) for values in distinct_values.values()]
        )
        return {
            "status": status,
            "complete": bool(status == "complete"),
            "reuse_ready": bool(status == "complete"),
            "device_count": observed_device_count,
            "context_count": len(nonempty),
            "fingerprint_sha256": fingerprint,
            "fingerprint_short": fingerprint[:12].upper() if fingerprint else "",
            "context": merged,
            "contexts": nonempty,
        }

    @staticmethod
    def _append_message_coverage_locked(s: dict, items: list[dict]) -> None:
        """把新增 01 池项增量计入消息 ID 覆盖率。"""
        counts = s.setdefault("_message_id_counts", Counter())
        lengths = s.setdefault("_message_id_lengths", defaultdict(set))
        slots = s.setdefault("_message_id_slots", defaultdict(set))
        subtypes = s.setdefault("_message_id_subtypes", defaultdict(set))
        scan_rows = s.setdefault("_scan_wave_rows", [])
        for item in items:
            if str(item.get("source") or "01").startswith("3366"):
                continue
            observations, ok = message_observation_details_from_item(item)
            if ok:
                s["_message_decoded_reports"] = int(
                    s.get("_message_decoded_reports") or 0
                ) + 1
            else:
                s["_message_decode_failures"] = int(
                    s.get("_message_decode_failures") or 0
                ) + 1
            for row in observations:
                message_id = int(row["message_id"])
                length = int(row["length"])
                counts[int(message_id)] += 1
                lengths[int(message_id)].add(int(length))
                if row.get("slot") is not None:
                    slots[int(message_id)].add(int(row["slot"]))
                if row.get("subtype") is not None:
                    subtypes[int(message_id)].add(int(row["subtype"]))
                if (
                    message_id in PLAYER_SCAN_WAVE_MESSAGE_IDS
                    and row.get("elapsed") is not None
                    and row.get("u20") is not None
                ):
                    scan_rows.append({
                        "message_id": int(message_id),
                        "recorded_elapsed_seconds": float(row["elapsed"]),
                        "u20": int(row["u20"]),
                    })

    @staticmethod
    def _ensure_message_coverage_locked(s: dict) -> None:
        """首次读取旧快照/导入会话时，延迟建立覆盖率缓存。"""
        if s.get("_message_coverage_ready"):
            return
        RecordingPool._reset_message_coverage_locked(s)
        RecordingPool._append_message_coverage_locked(
            s, RecordingPool._session_pool(s)
        )

    @staticmethod
    def _session_message_coverage_locked(s: dict) -> dict:
        RecordingPool._ensure_message_coverage_locked(s)
        return summarize_message_observations(
            s.get("_message_id_counts") or {},
            s.get("_message_id_lengths") or {},
            slots=s.get("_message_id_slots") or {},
            subtypes=s.get("_message_id_subtypes") or {},
            scan_wave_rows=s.get("_scan_wave_rows") or [],
            decoded_reports=int(s.get("_message_decoded_reports") or 0),
            decode_failures=int(s.get("_message_decode_failures") or 0),
        )

    def begin_01_join(self, client_ip: str) -> int:
        """
        收到 42B 01 加入包时开始一轮新的 01 录制。

        当前会话旧 01 池立即清空，后续 0A 00 23/09 数据从空池重新顺序写入；
        同会话已经录到的 3366 数据继续保留。
        """
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return 0
            old_count = self._clear_session_01_locked(s)
            s["ace_user_01"] = ""
            if s.get("game_id_source") == "01":
                fallback_gid = (s.get("ace_user_3366") or "").strip()
                s["game_id"] = fallback_gid
                s["game_id_source"] = "3366_handshake" if fallback_gid else ""
            s["last_record_at"] = time.time()
        if old_count:
            _event(
                "RECORD",
                "录制",
                f"[{client_ip}] 收到42B加入包，已清空旧01录制（{old_count}个加密区），开始新录制",
            )
        log_bus.record_updated.emit()
        return old_count

    def _replace_old_01_for_gid_locked(
        self, current: dict, game_id: str
    ) -> int:
        """清空其他同 UID 会话的旧 01 池；所有列表均原地更新。"""
        old_count = 0
        for sessions in self._sessions.values():
            for other in sessions:
                if other is current:
                    continue
                current_scope = str(current.get("pool_scope") or "player")
                other_scope = str(other.get("pool_scope") or "player")
                # 同账号的新录制替换旧玩家池，避免同一账号重复累积。
                if current_scope != other_scope:
                    continue
                if str(other.get("game_id") or "") != str(game_id):
                    continue
                old_count += self._clear_session_01_locked(other)
        return old_count

    # ── 录制侧 API ───────────────────────────
    def arm_official_batch(
        self,
        proxy_username: str,
        *,
        game_key: str = "dfm",
        client_version: str = "auto",
        batch_name: str = "",
    ) -> dict:
        proxy_username = str(proxy_username or "").strip()
        now = time.time()
        batch = {
            "batch_id": f"official-{int(now)}",
            "batch_name": batch_name.strip() or time.strftime("DFM-%Y%m%d-%H%M%S"),
            "game_key": str(game_key or "dfm").strip().lower(),
            "client_version": str(client_version or "auto").strip(),
            "proxy_username": proxy_username,
            "armed_at": now,
        }
        with self._lock:
            self._official_arms[proxy_username] = batch
        return dict(batch)

    def get_armed_official_batches(self) -> list[dict]:
        with self._lock:
            return [dict(value) for value in self._official_arms.values()]

    def publish_official(self, game_id: str, batch_id: str = "") -> int:
        """发布指定 donor 游戏账号下的官方草稿；返回发布会话数。"""
        changed = 0
        published_sessions: list[tuple[str, dict]] = []
        with self._lock:
            for ip, sessions in self._sessions.items():
                for session in sessions:
                    if (
                        session.get("pool_scope") == "official"
                        and str(session.get("game_id") or "") == str(game_id or "")
                        and (
                            not batch_id
                            or str(session.get("batch_id") or "") == str(batch_id)
                        )
                        and self._session_pool(session)
                    ):
                        session["published"] = True
                        session["published_at"] = time.time()
                        changed += 1
                        published_sessions.append((ip, dict(session)))
        if changed:
            for ip, session in published_sessions:
                self._log_record_session(
                    action="PUBLISH_OFFICIAL",
                    session=session,
                    client_ip=ip,
                    reason="OFFICIAL_TEMPLATE_PUBLISHED",
                )
            log_bus.record_updated.emit()
            self.save_snapshot()
            self.save_official_templates()
        return changed

    def promote_player_recording(
        self,
        game_id: str,
        *,
        client_version: str = "",
        batch_name: str = "",
    ) -> int:
        """把选中的玩家录制直接设为已发布官方模板。"""
        game_id = str(game_id or "").strip()
        if not game_id:
            return 0
        now = time.time()
        batch_id = f"promoted-{int(now * 1000)}"
        final_batch_name = (
            str(batch_name or "").strip()
            or time.strftime("Player-%Y%m%d-%H%M%S")
        )
        changed_sessions: list[tuple[str, dict]] = []
        with self._lock:
            for ip, sessions in self._sessions.items():
                for session in sessions:
                    if session.get("_ghost"):
                        continue
                    if str(session.get("game_id") or "").strip() != game_id:
                        continue
                    if str(session.get("pool_scope") or "player") != "player":
                        continue
                    pool = self._session_pool(session)
                    has_01 = any(
                        not str(item.get("source") or "").startswith("3366")
                        for item in pool
                    )
                    if not has_01:
                        continue
                    session["pool_scope"] = "official"
                    session["published"] = True
                    session["published_at"] = now
                    session["batch_id"] = batch_id
                    session["batch_name"] = final_batch_name
                    session["game_key"] = "dfm"
                    if str(client_version or "").strip():
                        session["client_version"] = str(client_version).strip()
                    else:
                        session["client_version"] = str(
                            session.get("client_version") or
                            app_config.get("dfm_client_version", "auto")
                        )
                    changed_sessions.append((ip, dict(session)))
        if changed_sessions:
            for ip, session in changed_sessions:
                self._log_record_session(
                    action="PROMOTE_OFFICIAL",
                    session=session,
                    client_ip=ip,
                    reason="PLAYER_RECORDING_PROMOTED_TO_OFFICIAL",
                )
            log_bus.record_updated.emit()
            self.save_snapshot()
            self.save_official_templates()
        return len(changed_sessions)

    def new_session(
        self,
        client_ip: str,
        proxy_username: str = "",
        record_role: str = "player",
    ) -> bool:
        """
        1081 新连接时调用。
        · 已有活跃会话 → 共享（引用计数 +1），返回 False。
        · 无活跃会话 → 创建新会话，返回 True。
        注意：此时仅为“幽灵会话”，不触发 UI 刷新，直到 append() 收到真实游戏ID才转正。
        """
        created_session: dict | None = None
        with self._lock:
            active = self._active_session(client_ip)
            if active and str(active.get("owner_username") or "") == str(proxy_username or ""):
                active["_refs"] = active.get("_refs", 1) + 1
                return False
            if active:
                active["active"] = False
            sessions = self._sessions.setdefault(client_ip, [])
            sid = f"{client_ip}#{int(time.time())}"
            role = "player"
            armed = {}
            pool_scope = "player"
            created_session = {"sid": sid, "pkts": [], "active": True,
                              "game_id": "", "created_at": time.time(),
                              "last_record_at": 0.0,
                              "pool_items": [], "_pool_count": 0,
                              "pool_01_items": [], "pool_33_items": [],
                              "_01_fragment_groups": {},
                              "_refs": 1, "_ghost": True,
                              "raw_3366": [], "ace_product": "",
                              "product_hex_3366": "", "product_name_3366": "",
                              "game_id_source": "",
                              "ace_user_01": "",
                              "ace_user_3366": "",
                              "has_3366_key": False,
                              "owner_username": proxy_username,
                              "pool_scope": pool_scope,
                              "batch_id": "",
                              "batch_name": "",
                              "game_key": "dfm",
                              "client_version": app_config.get(
                                  "dfm_client_version", "auto"
                              ),
                              "published": False}
            sessions.append(created_session)
        if created_session is not None:
            self._log_record_session(
                action="START",
                session=created_session,
                client_ip=client_ip,
                reason="PLAYER_RECORDING",
            )
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

    def get_active_message_coverage(self, client_ip: str) -> dict:
        """返回当前活跃录制会话的已知消息 ID 覆盖率。"""
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return summarize_message_observations({}, {})
            return self._session_message_coverage_locked(s)

    def get_active_33_count(self, client_ip: str) -> int:
        """当前活跃录制会话中，来源为 3366（09/21）的池条目数量。"""
        with self._lock:
            s = self._active_session(client_ip)
            if not s:
                return 0
            pool = self._session_pool(s)
            return sum(1 for it in pool if str(it.get("source", "") or "").startswith("3366"))

    def append(self, client_ip: str, data: bytes):
        """录制一个 01 00 开头的包，写入当前活跃会话。
        · 新增加密区时：发出轻量 record_count(sid, count) 信号（每包实时）
        · 会话级 ACE 标识（game_id）：**以 01 通道解析为准**（覆盖 3366 临时值，并回填池中 3366 条目的 account_id）。
        · 3366 仅可在尚无 game_id 时暂存（见 append_from_3366_plain）。
        · 标识变化时：去重旧会话、conn_game_id_update、全量刷新等。
        """
        emit_full   = False
        count_info: tuple | None = None
        replaced_info: tuple | None = None   # (game_id, old_count) 替换时记录
        identified_session: dict | None = None
        message_log_items: list[dict] = []
        message_log_session: dict = {}
        with self._lock:
            s = self._active_session(client_ip)
            if s:
                new_items = []
                for sub in _ace_split_packets(data):
                    meta = _ace_01_frame_meta(sub)
                    item = None
                    if meta and meta["fragment_count"] > 1:
                        key = _ace_01_fragment_key(sub)
                        groups = s.setdefault("_01_fragment_groups", {})
                        slots = groups.setdefault(key, {})
                        slots[meta["fragment_number"]] = sub
                        if len(slots) == meta["fragment_count"]:
                            frames = [slots[i] for i in sorted(slots)]
                            item = _ace_try_extract_frames(frames)
                            groups.pop(key, None)
                    else:
                        item = _ace_try_extract(sub)
                    if item:
                        recorded_at = time.time()
                        item["recorded_at"] = recorded_at
                        item["recorded_elapsed_seconds"] = max(
                            0.0,
                            recorded_at - float(
                                s.get("created_at") or recorded_at
                            ),
                        )
                        new_items.append(item)
                        raw_blk = item.get("raw_packet")
                        if raw_blk:
                            s["pkts"].append(raw_blk)  # 仅 01 0A 00 09/21 块，不存完整封包
                if new_items:
                    pool = RecordingPool._session_pool(s)
                    # 先同步旧池缓存，再把本次新增项计入，避免重复统计。
                    self._ensure_message_coverage_locked(s)
                    pool.extend(new_items)
                    self._append_message_coverage_locked(s, new_items)
                    self._append_device_context_locked(s, new_items)
                    s.setdefault("pool_01_items", []).extend(new_items)
                    s["_pool_count"] = len(pool)
                    s["last_record_at"] = time.time()
                    if not s.get("_ghost"):
                        count_info = (s["sid"], s["_pool_count"])
                    message_log_items = list(new_items)
                    message_log_session = dict(s)
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
                        identified_session = dict(s)
                        log_bus.conn_game_id_update.emit(client_ip, str(gid), "录制")
                        old_cnt = self._replace_old_01_for_gid_locked(s, gid)
                        if old_cnt:
                            replaced_info = (gid, old_cnt)
                    elif backfill_changed:
                        log_bus.record_updated.emit()
        for message_item in message_log_items:
            try:
                traffic_file_logger.log_persistent_01_message_item(
                    client_ip=client_ip,
                    session=message_log_session,
                    item=message_item,
                )
            except Exception:
                pass
        if replaced_info:
            gid, old_cnt = replaced_info
            _event("RECORD", "录制",
                   f"[{client_ip}] 游戏ID=[{gid}] 已存在旧录制（{old_cnt}个加密区），已替换为新录制")
        if identified_session is not None:
            self._log_record_session(
                action="IDENTIFY",
                session=identified_session,
                client_ip=client_ip,
                reason="GAME_ID_FROM_01",
            )
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
                    has_active_replay = False
                    try:
                        from .server import engine
                        if engine.server_1080:
                            for uname, ip_map in engine.server_1080._user_active_conns.items():
                                if client_ip in ip_map and ip_map[client_ip]:
                                    has_active_replay = True
                                    break
                    except Exception:
                        pass
                    if not has_active_replay:
                        sessions = self._sessions.get(client_ip, [])
                        dups = [
                            o for o in sessions
                            if o is not s and not o.get("active") and o.get("game_id") == uid
                        ]
                        if dups:
                            old_cnt = sum(
                                o.get("_pool_count") or len(self._session_pool(o))
                                for o in dups
                            )
                            sessions[:] = [o for o in sessions if o not in dups]
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
                has_active_replay = False
                try:
                    from .server import engine
                    if engine.server_1080:
                        for uname, ip_map in engine.server_1080._user_active_conns.items():
                            if client_ip in ip_map and ip_map[client_ip]:
                                has_active_replay = True
                                break
                except Exception:
                    pass
                if not has_active_replay:
                    sessions = self._sessions.get(client_ip, [])
                    dups = [
                        o for o in sessions
                        if o is not s and not o.get("active") and o.get("game_id") == gid
                    ]
                    if dups:
                        old_cnt = sum(
                            o.get("_pool_count") or len(self._session_pool(o))
                            for o in dups
                        )
                        sessions[:] = [o for o in sessions if o not in dups]
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
        stopped_session: dict | None = None
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
                stopped_session = dict(s)

        if not discarded_ghost:
            self._log_record_session(
                action="STOP",
                session=stopped_session or {},
                client_ip=client_ip,
                reason="ALL_RECORD_CONNECTIONS_CLOSED",
            )
            log_bus.record_updated.emit()
            self.save_snapshot()
            self.save_official_templates()
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

    def find_cross_account_01_pool(self, live_game_id: str) -> dict | None:
        """返回最近一份其他游戏 ID 的非空 01 池。

        v1.114.1 跨账号实验只借用 donor 的 01 Type9 叶子，33 池固定为空，
        避免把另一账号的 33 握手、序列和密文带进实时连接。
        """
        live_game_id = str(live_game_id or "").strip()
        with self._lock:
            candidates: list[tuple[float, str, list[dict]]] = []
            for sessions in self._sessions.values():
                for session in sessions:
                    if session.get("_ghost"):
                        continue
                    donor_game_id = str(session.get("game_id") or "").strip()
                    if not donor_game_id or donor_game_id == live_game_id:
                        continue
                    pool = self._session_pool(session)
                    if "pool_01_items" in session and session["pool_01_items"]:
                        pool_01 = session["pool_01_items"]
                    else:
                        pool_01 = [
                            item for item in pool
                            if not str(item.get("source", "") or "").startswith("3366")
                        ]
                    if not pool_01:
                        continue
                    freshness = float(
                        session.get("last_record_at")
                        or session.get("created_at")
                        or 0.0
                    )
                    candidates.append((freshness, donor_game_id, pool_01))
            if not candidates:
                return None
            _, donor_game_id, pool_01 = max(
                candidates,
                key=lambda row: (row[0], row[1]),
            )
            return {
                "pool_01": pool_01,
                "pool_33": [],
                "game_id": donor_game_id,
                "donor_game_id": donor_game_id,
                "cross_account": True,
            }

    def find_tiered_01_pool(
        self,
        live_game_id: str,
        *,
        client_version: str = "auto",
        include_official: bool = True,
    ) -> dict | None:
        """v1.118：个人池优先，随后补入已发布的官方模板池。

        返回列表为独立浅拷贝，附带 template_scope/source_priority，既不会修改
        原录制数据，也能让 Type9 叶子选择器稳定优先个人样本。
        """
        live_game_id = str(live_game_id or "").strip()
        wanted_version = str(client_version or "auto").strip()
        if not live_game_id:
            return None
        with self._lock:
            personal: list[tuple[float, dict]] = []
            official: list[tuple[float, dict]] = []
            personal_33: list[dict] = []
            donors: list[str] = []
            official_sources: dict[tuple[str, str, str], dict] = {}
            for sessions in self._sessions.values():
                for session in sessions:
                    if session.get("_ghost"):
                        continue
                    scope = str(session.get("pool_scope") or "player")
                    donor = str(session.get("game_id") or "").strip()
                    session_version = str(session.get("client_version") or "auto")
                    version_ok = (
                        wanted_version == "auto"
                        or session_version == "auto"
                        or session_version == wanted_version
                    )
                    if not version_ok:
                        continue
                    if scope == "official":
                        if not include_official:
                            continue
                        if not session.get("published"):
                            continue
                    elif donor != live_game_id:
                        continue
                    pool = self._session_pool(session)
                    freshness = float(
                        session.get("published_at")
                        or session.get("last_record_at")
                        or session.get("created_at")
                        or 0.0
                    )
                    for item in pool:
                        source = str(item.get("source") or "")
                        if source.startswith("3366"):
                            if scope != "official" and donor == live_game_id:
                                personal_33.append(item)
                            continue
                        tagged = dict(item)
                        tagged["template_scope"] = scope
                        tagged["source_priority"] = 0 if scope != "official" else 1
                        tagged["donor_game_id"] = donor
                        tagged["template_batch_id"] = session.get("batch_id", "")
                        tagged["template_batch_name"] = session.get("batch_name", "")
                        tagged["template_session_id"] = str(
                            session.get("sid") or ""
                        )
                        tagged["template_client_version"] = session_version
                        tagged["template_owner_username"] = session.get(
                            "owner_username", ""
                        )
                        if scope == "official":
                            official.append((freshness, tagged))
                            if donor and donor not in donors:
                                donors.append(donor)
                            source_key = (
                                str(session.get("batch_id") or ""),
                                donor,
                                session_version,
                            )
                            official_sources[source_key] = {
                                "batch_id": source_key[0],
                                "batch_name": str(session.get("batch_name") or ""),
                                "client_version": source_key[2],
                                "donor_game_id": donor,
                                "owner_username": str(
                                    session.get("owner_username") or ""
                                ),
                                "published_at": float(
                                    session.get("published_at") or 0.0
                                ),
                            }
                        else:
                            personal.append((freshness, tagged))
            personal.sort(key=lambda row: row[0], reverse=True)
            official.sort(key=lambda row: row[0], reverse=True)
            pool_01 = [row[1] for row in personal] + [row[1] for row in official]
            if not pool_01 and not personal_33:
                return None
            return {
                "pool_01": pool_01,
                "pool_33": list(personal_33),
                "game_id": live_game_id,
                "donor_game_id": "",
                "official_donor_game_ids": donors,
                "cross_account": bool(official),
                "tiered": True,
                "personal_01_count": len(personal),
                "official_01_count": len(official),
                "official_sources": list(official_sources.values()),
                "client_version": wanted_version,
            }

    def find_same_device_candidate_01_pool(
        self,
        live_game_id: str,
        *,
        client_version: str = "auto",
        include_official: bool = True,
    ) -> dict | None:
        """v1.128.9: expose player sessions as strict device candidates.

        Account identity is deliberately *not* used to select the donor here.
        Runtime Type9 decoding must first obtain model/system/IDFV and pins one
        exact recording session.  3366 material never crosses accounts.
        """
        live_game_id = str(live_game_id or "").strip()
        wanted_version = str(client_version or "auto").strip()
        if not live_game_id:
            return None
        with self._lock:
            player: list[tuple[float, dict]] = []
            official: list[tuple[float, dict]] = []
            donors: list[str] = []
            for sessions in self._sessions.values():
                for session in sessions:
                    if session.get("_ghost"):
                        continue
                    scope = str(session.get("pool_scope") or "player")
                    donor = str(session.get("game_id") or "").strip()
                    session_version = str(session.get("client_version") or "auto")
                    version_ok = (
                        wanted_version == "auto"
                        or session_version == "auto"
                        or session_version == wanted_version
                    )
                    if not version_ok:
                        continue
                    if scope == "official":
                        if not include_official or not session.get("published"):
                            continue
                    elif not donor:
                        continue
                    freshness = float(
                        session.get("published_at")
                        or session.get("last_record_at")
                        or session.get("created_at")
                        or 0.0
                    )
                    for item in self._session_pool(session):
                        if str(item.get("source") or "").startswith("3366"):
                            continue
                        tagged = dict(item)
                        tagged["template_scope"] = scope
                        tagged["source_priority"] = 0 if scope != "official" else 1
                        tagged["donor_game_id"] = donor
                        tagged["template_batch_id"] = session.get("batch_id", "")
                        tagged["template_batch_name"] = session.get("batch_name", "")
                        tagged["template_session_id"] = str(session.get("sid") or "")
                        tagged["template_client_version"] = session_version
                        tagged["template_owner_username"] = session.get(
                            "owner_username", ""
                        )
                        if scope == "official":
                            official.append((freshness, tagged))
                        else:
                            tagged["device_cross_account_candidate"] = (
                                donor != live_game_id
                            )
                            player.append((freshness, tagged))
                            if donor != live_game_id and donor not in donors:
                                donors.append(donor)
            player.sort(key=lambda row: row[0], reverse=True)
            official.sort(key=lambda row: row[0], reverse=True)
            if not player:
                return None
            return {
                "pool_01": [row[1] for row in player] + [row[1] for row in official],
                "pool_33": [],
                "game_id": live_game_id,
                "donor_game_id": "",
                "official_donor_game_ids": [],
                "cross_account": bool(donors),
                "device_cross_account": bool(donors),
                "tiered": True,
                "personal_01_count": len(player),
                "official_01_count": len(official),
                "official_sources": [],
                "device_donor_game_ids": donors,
                "client_version": wanted_version,
            }

    def find_v129_01_pool(
        self,
        live_game_id: str,
        *,
        client_version: str = "auto",
        include_official: bool = False,
        enable_device_cross_account: bool = True,
    ) -> dict | None:
        """Build the player-only replay pool.

        Player recordings from every account are exposed as candidates. Runtime
        Type9 decoding pins a strict model/system/IDFV match first; when no
        compatible device recording exists, rows belonging to ``live_game_id``
        remain as the deterministic account-level fallback.

        ``include_official`` remains in the signature for old callers and is
        intentionally ignored by the current player-only policy.
        """
        exact = self.find_tiered_01_pool(
            live_game_id,
            client_version=client_version,
            include_official=False,
        )
        if not enable_device_cross_account:
            return exact
        device = self.find_same_device_candidate_01_pool(
            live_game_id,
            client_version=client_version,
            include_official=False,
        )
        if device and exact:
            # 01可跨账号做严格设备匹配；3366始终保留当前游戏ID自己的池。
            device["pool_33"] = list(exact.get("pool_33") or [])
        return device or exact

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

    def get_message_coverage_for_game_id(self, game_id: str) -> dict:
        """聚合同一游戏用户 ID 下所有录制会话的消息覆盖率。"""
        with self._lock:
            counts: Counter = Counter()
            lengths: dict[int, set[int]] = defaultdict(set)
            slots: dict[int, set[int]] = defaultdict(set)
            subtypes: dict[int, set[int]] = defaultdict(set)
            scan_wave_rows: list[dict] = []
            decoded_reports = 0
            decode_failures = 0
            for ip, sessions in self._sessions.items():
                for s in sessions:
                    if s.get("_ghost"):
                        continue
                    gid = str(s.get("game_id") or "")
                    if game_id.startswith("待识别-"):
                        if ip != game_id.replace("待识别-", "", 1) or gid:
                            continue
                    elif gid != game_id:
                        continue
                    self._ensure_message_coverage_locked(s)
                    counts.update(s.get("_message_id_counts") or {})
                    for message_id, values in (
                        s.get("_message_id_lengths") or {}
                    ).items():
                        lengths[int(message_id)].update(values)
                    for message_id, values in (
                        s.get("_message_id_slots") or {}
                    ).items():
                        slots[int(message_id)].update(values)
                    for message_id, values in (
                        s.get("_message_id_subtypes") or {}
                    ).items():
                        subtypes[int(message_id)].update(values)
                    scan_wave_rows.extend(list(s.get("_scan_wave_rows") or []))
                    decoded_reports += int(
                        s.get("_message_decoded_reports") or 0
                    )
                    decode_failures += int(
                        s.get("_message_decode_failures") or 0
                    )
            return summarize_message_observations(
                counts,
                lengths,
                slots=slots,
                subtypes=subtypes,
                scan_wave_rows=scan_wave_rows,
                decoded_reports=decoded_reports,
                decode_failures=decode_failures,
            )

    def get_device_identity_for_game_id(self, game_id: str) -> dict:
        """聚合同一游戏用户ID录制中的设备画像与稳定显示指纹。"""
        with self._lock:
            contexts: list[dict] = []
            for ip, sessions in self._sessions.items():
                for s in sessions:
                    if s.get("_ghost"):
                        continue
                    gid = str(s.get("game_id") or "")
                    if game_id.startswith("待识别-"):
                        if ip != game_id.replace("待识别-", "", 1) or gid:
                            continue
                    elif gid != game_id:
                        continue
                    self._ensure_device_context_locked(s)
                    context = dict(s.get("_device_context") or {})
                    if context:
                        contexts.append(context)
            return self._summarize_device_contexts(contexts)

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
                    coverage = self._session_message_coverage_locked(s)
                    self._ensure_device_context_locked(s)
                    device_context = dict(s.get("_device_context") or {})
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
                        "owner_username": s.get("owner_username", ""),
                        "pool_scope": s.get("pool_scope", "player"),
                        "client_version": s.get("client_version", "auto"),
                        "batch_id": s.get("batch_id", ""),
                        "batch_name": s.get("batch_name", ""),
                        "published": bool(s.get("published", False)),
                        "message_coverage": coverage,
                        "device_context": device_context,
                    })
            # 按 game_id 聚合
            agg: dict[str, dict] = {}
            for r in raw_list:
                gid = r["game_id"]
                agg_key = (
                    f"{gid}|{r.get('pool_scope')}|{r.get('batch_id')}"
                    if str(r.get("pool_scope") or "").startswith("official")
                    else gid
                )
                if agg_key not in agg:
                    agg[agg_key] = {
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
                        "owner_username": r.get("owner_username", ""),
                        "pool_scope": r.get("pool_scope", "player"),
                        "client_version": r.get("client_version", "auto"),
                        "batch_id": r.get("batch_id", ""),
                        "batch_name": r.get("batch_name", ""),
                        "published": bool(r.get("published", False)),
                        "_device_contexts": [],
                        "_message_id_counts": Counter(),
                        "_message_id_lengths": defaultdict(set),
                        "_message_id_slots": defaultdict(set),
                        "_message_id_subtypes": defaultdict(set),
                        "_scan_wave_rows": [],
                        "_message_decoded_reports": 0,
                        "_message_decode_failures": 0,
                    }
                agg[agg_key]["count_01"] += r["count_01"]
                agg[agg_key]["count_3366"] += r["count_3366"]
                agg[agg_key]["count"] += r["count"]
                agg[agg_key]["count_3366_raw"] += r.get("count_3366_raw", 0)
                rcov = r.get("message_coverage") or {}
                agg[agg_key]["_message_id_counts"].update(
                    rcov.get("message_counts") or {}
                )
                for message_id, values in (
                    rcov.get("message_lengths") or {}
                ).items():
                    agg[agg_key]["_message_id_lengths"][int(message_id)].update(values)
                for message_id, values in (
                    rcov.get("message_slots") or {}
                ).items():
                    agg[agg_key]["_message_id_slots"][int(message_id)].update(values)
                for message_id, values in (
                    rcov.get("message_subtypes") or {}
                ).items():
                    agg[agg_key]["_message_id_subtypes"][int(message_id)].update(values)
                agg[agg_key]["_scan_wave_rows"].extend(
                    list(rcov.get("scan_wave_observations") or [])
                )
                agg[agg_key]["_message_decoded_reports"] += int(
                    rcov.get("decoded_reports") or 0
                )
                agg[agg_key]["_message_decode_failures"] += int(
                    rcov.get("decode_failures") or 0
                )
                if r.get("device_context"):
                    agg[agg_key]["_device_contexts"].append(
                        dict(r.get("device_context") or {})
                    )
                if r["ip"] not in agg[agg_key]["ips"]:
                    agg[agg_key]["ips"].append(r["ip"])
                if r["active"]:
                    agg[agg_key]["active"] = True
                if r.get("pool_scope") == "official":
                    agg[agg_key]["pool_scope"] = "official"
                    agg[agg_key]["published"] = bool(
                        agg[agg_key].get("published") or r.get("published")
                    )
                # 取多个会话中最新的录制时间
                t = r.get("last_record_at", 0.0) or 0.0
                if t > agg[agg_key]["last_record_at"]:
                    agg[agg_key]["last_record_at"] = t
            result = list(agg.values())
            for row in result:
                row["message_coverage"] = summarize_message_observations(
                    row.pop("_message_id_counts"),
                    row.pop("_message_id_lengths"),
                    slots=row.pop("_message_id_slots"),
                    subtypes=row.pop("_message_id_subtypes"),
                    scan_wave_rows=row.pop("_scan_wave_rows"),
                    decoded_reports=row.pop("_message_decoded_reports"),
                    decode_failures=row.pop("_message_decode_failures"),
                )
                row["device_identity"] = self._summarize_device_contexts(
                    row.pop("_device_contexts")
                )
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
                kept = [
                    s for s in sessions
                    if s.get("pool_scope") == "official"
                    or s.get("active")
                    or (now - s.get("created_at", now)) <= max_age_seconds
                ]
                if len(kept) < len(sessions):
                    changed = True
                    if kept:
                        self._sessions[ip] = kept
                    else:
                        del self._sessions[ip]
        if changed:
            log_bus.record_updated.emit()

    @staticmethod
    def _export_scope_matches(session: dict, export_scope: str) -> bool:
        scope = str(session.get("pool_scope") or "player")
        if export_scope == "player":
            return scope == "player"
        if export_scope == "official_published":
            return scope == "official" and bool(session.get("published"))
        return True

    def export_to_file(
        self,
        path: str,
        export_scope: str = "all",
    ) -> tuple[bool, str]:
        """
        导出会话为 JSON（v7 格式，包含导出用途和分层模板元数据）。

        export_scope:
          all                完整恢复备份（玩家、官方草稿、官方已发布）
          player             仅玩家录制
          official_published 仅已发布官方01模板

        01 池同时保存完整物理帧模板，供简单游标循环重放。
        """
        export_scope = str(export_scope or "all").strip().lower()
        if export_scope not in {"all", "player", "official_published"}:
            export_scope = "all"
        try:
            with self._lock:
                data: dict[str, list] = {}
                for ip, sessions in self._sessions.items():
                    ip_list = []
                    for s in sessions:
                        if s.get("_ghost") or not self._export_scope_matches(
                            s, export_scope
                        ):
                            continue
                        pool = self._session_pool(s)
                        if export_scope == "official_published":
                            pool = [
                                item for item in pool
                                if not str(item.get("source") or "").startswith("3366")
                            ]
                            if not pool:
                                continue
                        pool_export = [
                            {
                                "payload":    item["payload"].hex(),
                                "crc":        (item.get("crc") or b"").hex(),
                                "routing":    (item.get("routing") or b"\x00").hex(),
                                "account_id": item.get("account_id") or "",
                                "source":     item.get("source") or "",
                                "raw_packet": (item.get("raw_packet") or b"").hex(),
                                "report_index": item.get("report_index"),
                                "recorded_at": item.get("recorded_at"),
                                "recorded_elapsed_seconds": item.get(
                                    "recorded_elapsed_seconds"
                                ),
                                "template_frames": [
                                    bytes(frame).hex()
                                    for frame in (item.get("template_frames") or [])
                                ],
                            }
                            for item in pool
                        ]
                        raw3366 = (
                            []
                            if export_scope == "official_published"
                            else (s.get("raw_3366") or [])
                        )
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
                            "owner_username": s.get("owner_username", ""),
                            "pool_scope": s.get("pool_scope", "player"),
                            "client_version": s.get("client_version", "auto"),
                            "batch_id": s.get("batch_id", ""),
                            "batch_name": s.get("batch_name", ""),
                            "game_key": s.get("game_key", "dfm"),
                            "published": bool(s.get("published", False)),
                            "published_at": s.get("published_at", 0.0),
                            "pool_items": pool_export,
                            "raw_3366": raw3366_export,
                        })
                    if ip_list:
                        data[ip] = ip_list
            sessions_flat = [session for rows in data.values() for session in rows]
            player_count = sum(
                1 for session in sessions_flat
                if session.get("pool_scope") == "player"
            )
            official_count = sum(
                1 for session in sessions_flat
                if session.get("pool_scope") == "official"
                and session.get("published")
            )
            total_p = sum(len(session["pool_items"]) for session in sessions_flat)
            payload = {
                "version": 7,
                "schema": "dfm-recording-pool-v7",
                "export_scope": export_scope,
                "package_id": f"dfm-{export_scope}-{int(time.time() * 1000)}",
                "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "counts": {
                    "ip": len(data),
                    "sessions": len(sessions_flat),
                    "player_sessions": player_count,
                    "official_published_sessions": official_count,
                    "pool_items": total_p,
                },
                "sessions": data,
            }
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, exist_ok=True)
            temp_path = f"{path}.tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, path)
            scope_names = {
                "all": "完整备份",
                "player": "玩家录制",
                "official_published": "已发布官方模板",
            }
            return True, (
                f"已导出[{scope_names[export_scope]}] {len(data)} 个 IP，"
                f"{len(sessions_flat)} 条会话，共 {total_p} 个加密区 → {path}"
            )
        except Exception as ex:
            return False, f"导出失败: {ex}"

    @staticmethod
    def inspect_import_file(path: str) -> tuple[bool, dict | str]:
        """读取导入包摘要，供 UI 在写入内存池前展示。"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            sessions = [
                session
                for rows in (payload.get("sessions") or {}).values()
                for session in (rows if isinstance(rows, list) else [rows])
            ]
            counts = dict(payload.get("counts") or {})
            counts.setdefault("sessions", len(sessions))
            counts.setdefault(
                "player_sessions",
                sum(1 for s in sessions if s.get("pool_scope", "player") == "player"),
            )
            counts.setdefault(
                "official_published_sessions",
                sum(
                    1 for s in sessions
                    if s.get("pool_scope") == "official" and s.get("published")
                ),
            )
            return True, {
                "version": int(payload.get("version", 2)),
                "export_scope": str(payload.get("export_scope") or "legacy_all"),
                "package_id": str(payload.get("package_id") or ""),
                "counts": counts,
            }
        except Exception as ex:
            return False, str(ex)

    def import_from_file(
        self,
        path: str,
        overwrite: bool = False,
        *,
        persist: bool = True,
    ) -> tuple[bool, str]:
        """
        从 JSON 文件导入。
        支持所有历史格式：
          v7 ： v6 + export_scope/package_id/counts
          v6 ： v5 + pool_scope/client_version/batch/published
          v5 ： pool_items + 完整 01 template_frames
          v4 ： pool_items（旧格式，只含加密区；不可用于完整模板模式）
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
                        item_scope = str(item.get("pool_scope") or "player")
                        item_batch = str(item.get("batch_id") or "")
                        item_identity = (
                            item_scope,
                            item_batch,
                            str(item.get("game_id") or ""),
                            str(item.get("client_version") or "auto"),
                        )
                        duplicate_official_ref = next(
                            (
                                (stored_ip, session)
                                for stored_ip, stored_sessions in self._sessions.items()
                                for session in stored_sessions
                                if item_scope == "official"
                                and item_batch
                                and (
                                    str(session.get("pool_scope") or "player"),
                                    str(session.get("batch_id") or ""),
                                    str(session.get("game_id") or ""),
                                    str(session.get("client_version") or "auto"),
                                ) == item_identity
                            ),
                            None,
                        )
                        duplicate_official = (
                            duplicate_official_ref[1]
                            if duplicate_official_ref else None
                        )
                        if (sid in existing_sids or duplicate_official) and not overwrite:
                            skipped += 1
                            continue
                        if overwrite:
                            if duplicate_official_ref:
                                duplicate_ip, duplicate_session = duplicate_official_ref
                                duplicate_sessions = self._sessions.get(duplicate_ip, [])
                                duplicate_sessions[:] = [
                                    session for session in duplicate_sessions
                                    if session is not duplicate_session
                                ]
                            existing[:] = [
                                session for session in existing
                                if session["sid"] != sid
                            ]

                        if "pool_items" in item:
                            # v4/v5：直接恢复 pool items；v5 额外带完整物理帧模板
                            pool_items = [
                                {
                                    "payload":    bytes.fromhex(pi["payload"]),
                                    "crc":        bytes.fromhex(pi.get("crc", "")),
                                    "routing":    bytes.fromhex(pi.get("routing", "00")),
                                    "account_id": pi.get("account_id", ""),
                                    "source":     pi.get("source") or "01",
                                    "raw_packet": bytes.fromhex(pi.get("raw_packet", "")),
                                    "report_index": pi.get("report_index"),
                                    "recorded_at": pi.get("recorded_at"),
                                    "recorded_elapsed_seconds": pi.get(
                                        "recorded_elapsed_seconds"
                                    ),
                                    "template_frames": [
                                        bytes.fromhex(frame_hex)
                                        for frame_hex in (pi.get("template_frames") or [])
                                    ],
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
                                "owner_username": item.get("owner_username", ""),
                                "pool_scope": "player",
                                "client_version": item.get("client_version", "auto"),
                                "batch_id": "",
                                "batch_name": "",
                                "game_key": item.get("game_key", "dfm"),
                                "published": False,
                                "published_at": 0.0,
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
                                "owner_username": item.get("owner_username", ""),
                                "pool_scope": "player",
                                "client_version": item.get("client_version", "auto"),
                                "batch_id": "",
                                "batch_name": "",
                                "game_key": item.get("game_key", "dfm"),
                                "published": False,
                                "published_at": 0.0,
                            }
                        existing.append(new_s)
                        existing_sids.add(sid)
                        imported += 1
            log_bus.record_updated.emit()
            if persist:
                self.save_snapshot()
                self.save_official_templates()
            msg = f"导入完成：{imported} 条会话"
            if skipped:
                msg += f"，跳过已有 {skipped} 条"
            return True, msg
        except Exception as ex:
            return False, f"导入失败: {ex}"


recording_pool = RecordingPool()
recording_pool.load_snapshot()
