import asyncio
import os
import socket
import struct
import time
import threading

from core.config import app_config
from core.replay_session_v130 import ReplaySessionRegistry, replay_phase_label
from core.edition import (
    DFM_3366_PASSTHROUGH_ONLY,
    LEGACY_GAME_RUNTIME_ENABLED,
    LEGACY_LOCAL_MAP_RUNTIME_ENABLED,
    is_dfm_plugin_game,
)
from core.events import log_bus, _event, _log_exc
from core.managers import user_manager, local_map_manager
from core.crypto import (
    ace_corrupt_01_downlink_zip_frames,
    ace_mutate_01_downlink_mrpcs_frames,
    _ace_01_fragment_key,
    _ace_01_frame_meta,
    _ace_try_replay_template,
    _parse_ace_account_id,
    ace_handshake_product_hex,
    ace_is_01_keepalive_template,
    ace_bump_01_keepalive_frame,
    ace_next_01_outer_ids,
    ace_read_01_outer_ids,
    ace_restamp_01_frame,
    extract_pool_items_from_3366_plaintext,
    try_replace_3366_4013_plain,
)
from core.protocol_3366 import (
    MAGIC as MAGIC_3366,
    MSG_DATA,
    MSG_HANDSHAKE,
    MSG_SERVER_KEY,
    Conn3366State,
    feed_3366_stream,
    process_3366_chunk,
    format_3366_log_preview,
    merge_3366_product_registry,
    decrypt_plain_for_strategy,
    registry_needs_downlink_key_extraction,
    product_uses_downlink_session_key,
    ACE_SHORT_PRODUCT_TO_3366_PRODUCT,
    try_derive_aes_key_from_1002,
    is_breakout_cn_1002_embedded_aes_key,
    try_decrypt_4013_frame,
    try_decrypt_4013_frame_raw,
    replace_3366_40_13_frames_in_buffer,
    iter_3366_frames_in_buffer,
    extract_handshake_user_id,
    filter_3366_frames_with_raw_high_entropy,
    parse_3366_header,
    _find_valid_magic,
)
from core.pool import recording_pool
from core.admin_api import AdminApiServer
from core.plugin_keys import plugin_key_store, dump_3366_frame
from core.traffic_session_log import (
    TrafficSessionLog,
    traffic_file_logger,
    hex_slice_from_01_0a_00_09,
)


def _register_01_42_handshake_hint(client_ip: str, sub: bytes) -> None:
    """42B 01 握手：写入产品 ID 到 plugin_key_store，省略插件上报前即可识别 094e 等。"""
    h = ace_handshake_product_hex(sub)
    if h:
        plugin_key_store.set_game_hint(client_ip, h)


def _plugin_game_id_from_store(
    client_ip: str,
    *,
    ab_cn_33_first_seen: bool = False,
) -> str:
    """
    仅当 game_hint / 插件 Key 的 game 出现在 config['plugin_games'] 中时，才视为「三角洲等插件路径」。
    - 01 握手写入的 094e（暗区）不在 plugin_games 中 → 返回空。
    - 33 往往先于 01：若已在本 IP 观察到暗区国服首条 10 01（总长 HS_LEN_AB_BREAKOUT_CN_1001），
      不依赖 01，直接返回空，避免此前三角洲启发式（HS_LEN_DZ_HEURISTIC_1001）误标 0a92。
    """
    if ab_cn_33_first_seen:
        return ""
    g = (plugin_key_store.get_game(client_ip) or "").strip().lower()
    if not g:
        return ""
    if not LEGACY_GAME_RUNTIME_ENABLED and not is_dfm_plugin_game(g):
        return ""
    pg = app_config.get("plugin_games") or {}
    if isinstance(pg, dict) and g in pg:
        return g
    return ""


# 33 66 上行首条 10 01（握手）整帧长度：01 通道常晚于 33，故用此区分暗区 / 三角洲。
# 暗区突围国服：首帧总长 75B；三角洲行动：现网样本常见 206B（启发式标 0a92，与 75 互斥）。
HS_LEN_AB_BREAKOUT_CN_1001 = 75
HS_LEN_DZ_HEURISTIC_1001 = 206


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
        # 重放模式：每连接池索引 conn_id -> [pool_index, replace_count]
        self._replay_index: dict[str, list] = {}      # 01 池
        self._replay_index_33: dict[str, dict] = {}  # 33 池索引 {"09":[0,0],"21":[0,0],"01_fb":[0,0]}
        # 选定后的重放池（发现游戏ID后按游戏ID选定）conn_id -> {pool_01, pool_33}
        self._replay_pools: dict[str, dict] = {}
        # 该 IP 所有录制会话的池快照，发现游戏ID后用于匹配 conn_id -> {game_id: pool}
        self._replay_all_pools: dict[str, dict] = {}
        # 是否已完成游戏 ID 匹配（每连接仅执行一次）
        self._replay_gid_checked: dict[str, bool] = {}
        # 每条连接解析出的游戏ID（无论是否命中重放池都保存，供下发拦截展示）
        self._conn_live_gid: dict[str, str] = {}
        # 流重组缓冲区：应对 TCP 分包（一个 01 包拆成多次 read）conn_id -> bytearray
        self._stream_bufs: dict[str, bytearray] = {}
        # 多开控制：username → {ip: {conn_id, ...}}；踢人按游戏ID，不按IP
        self._user_active_conns: dict[str, dict[str, set[str]]] = {}
        # conn_id → client StreamWriter（用于踢人时强制断开）
        self._conn_client_writers: dict[str, "asyncio.StreamWriter"] = {}
        # conn_id → SOCKS CONNECT 目标端口；用于运行时只切断 3366，保留 01 通道。
        self._conn_target_ports: dict[str, int] = {}
        # 录制/重放共用实验开关：立即断开已有 3366 连接，并拒绝后续目标端口 3366；默认关闭。
        self._manual_3366_block_enabled = False
        self._manual_3366_drop_logged: set[str] = set()
        # 33 66 流状态（上行 / 下行分离）
        self._st3366_up: dict[str, Conn3366State] = {}
        self._st3366_down: dict[str, Conn3366State] = {}
        self._3366_key_logged: set[str] = set()
        self._3366_prod_logged: set[str] = set()
        # client_ip → (key, iv)，仅当产品配置了可解密策略时写入
        self._3366_aes: dict[str, tuple[bytes, bytes]] = {}
        # client_ip → 产品 ID 8hex（如 0000094E）
        self._3366_prod_hex: dict[str, str] = {}
        # conn_id → 已提示「有产品但未配置解密」
        self._3366_decrypt_skip_logged: set[str] = set()
        self._3366_unknown_strat_logged: set[str] = set()
        # 自动断线：01 包达阈值后，仅该 IP 的新 3366 连接将被拒绝，直到所有连接断开。
        # 该状态必须与全局手动开关分离，否则任一 IP 达阈值都会把录制口永久全局阻断。
        self._auto_disconnect_blocked: set[str] = set()
        # 阈值后 01 只收录：每个 IP 只打一次日志
        self._01_hold_logged: set[str] = set()
        self._01_keepalive_logged: set[str] = set()
        self._01_keepalive_forging: set[str] = set()
        self._01_seq_desynced: set[str] = set()
        self._01_client_gone: set[str] = set()
        self._01_keepalive_template: dict[str, bytes] = {}
        self._01_last_real_down: dict[str, float] = {}
        self._01_last_inject: dict[str, float] = {}
        self._01_client_seq: dict[str, int] = {}
        self._01_client_group: dict[str, int] = {}
        self._01_last_ace_group: dict[str, int] = {}
        # 携带 33（3366）数据的 conn_id 集合，用于 01 满时断开 33 连接
        self._conn_carries_3366: set[str] = set()
        # 录制阻止：uid 正在被重放时，标记该 conn_id 不录制（01 不入池；33 直接断开连接）
        self._record_blocked_conns: set[str] = set()
        # 01 两步握手判断：收到42握手包后暂存，等下一帧uid确认是否在重放，再决定是否入池
        self._pending_01_handshake: dict[str, bytes] = {}
        # 重放 01 多分片：rep_key → {(group,count,crc): {fragment_no: frame}}
        self._replay_01_fragment_groups: dict[str, dict] = {}
        # 重放 01 UID 匹配失败计数（游戏可能随机发送错误UID包，容忍若干次后再严格阻断）
        self._replay_gid_fail: dict[str, int] = {}
        # 重放进行中 ACE 重握手检测：收到42字节加入包后标记，随后的 0A 00 23 包若UID不匹配则丢弃
        self._replay_ace_recheck: set[str] = set()
        # 下发拦截缓冲（只拼装 payload，不包含 3366 头）
        self._dl_intercept_bufs: dict[str, bytearray] = {}
        # 无匹配录制时绑空池：01 只做删叶/改写，不替换录制叶子、不断开连接。
        # conn_id → 3366 10_01 解析出的游戏账户（供下发拦截统计「游戏账户」列显示）
        self._3366_hs_uid: dict[str, str] = {}
        # client_ip → 游戏 UID（跨 conn_id 共享；01 连接和 3366 连接各自写入，互为兜底）
        self._ip_game_uid: dict[str, str] = {}
        # 插件 Key：已完成等待的 client_ip 集合（每个 IP 只等一次）
        self._plugin_key_wait_done: set[str] = set()
        # 插件游戏名：已向 UI 发送过 conn_3366_product 信号的 client_ip（每 IP 只发一次）
        self._plugin_game_notified: set[str] = set()
        # 该 IP 已出现暗区国服特征首帧：上行 10 01 总长 == HS_LEN_AB_BREAKOUT_CN_1001（75B）
        self._3366_ab_cn_first_hs: set[str] = set()
        # 重放就绪日志去重：同 IP 首次匹配成功后记录，后续连接静默匹配
        self._replay_ready_logged: set[str] = set()
        # IP 已有 UID 时，新连接须先收到 42B 加入包才允许 0A 00 23 匹配（防止早到的旧包误匹配）
        self._replay_await_join: set[str] = set()
        # 已经由 42B 加入包解锁的连接：0A 00 23 不在录制池时直接丢弃，不走重试逻辑
        self._replay_join_triggered: set[str] = set()
        # v1.128 per-01-session logical clock.  One monotonic timestamp per
        # connection; due slots are evaluated lazily on complete uplink frames.
        self._replay_01_join_started: dict[str, float] = {}
        # v1.128.10: 42B token only establishes a candidate; the first native
        # Type9 report must confirm in-memory leaf sequence continuity.
        self._replay_game_sessions_v130 = ReplaySessionRegistry()

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

    def is_manual_3366_connection(self, conn_id: str) -> bool:
        """目标端口或流量解析任一确认3366时，视为3366连接。"""
        return (
            self._conn_target_ports.get(conn_id) == 3366
            or conn_id in self._conn_carries_3366
        )

    def detach_3366_from_01_replay(self, conn_id: str) -> None:
        """确认3366连接后移除其01模板匹配状态，独立01连接保持原游标。"""
        self._replay_game_sessions_v130.disconnect(conn_id)
        self._replay_index.pop(conn_id, None)
        self._replay_index_33.pop(conn_id, None)
        self._replay_pools.pop(conn_id, None)
        self._replay_all_pools.pop(conn_id, None)
        self._replay_gid_checked.pop(conn_id, None)
        self._replay_gid_fail.pop(conn_id, None)
        self._replay_ace_recheck.discard(conn_id)
        self._replay_await_join.discard(conn_id)
        self._replay_join_triggered.discard(conn_id)
        self._replay_01_join_started.pop(conn_id, None)
        self._pending_01_handshake.pop(conn_id, None)
        self._replay_01_fragment_groups.pop(f"{conn_id}_rep_↑UP", None)
        self._replay_01_fragment_groups.pop(f"{conn_id}_rep_↓DOWN", None)
        self._conn_live_gid.pop(conn_id, None)

    def should_reject_manual_3366(
        self,
        target_port: int,
        _mode: str,
        client_ip: str = "",
    ) -> bool:
        """判断已知目标端口的 3366 连接是否应被阻断。

        手动按钮是服务器级开关；01 阈值是录制口、客户端 IP 级状态。
        """
        return bool(
            (
                self._manual_3366_block_enabled
                or (
                    self.mode == "record"
                    and bool(client_ip)
                    and client_ip in self._auto_disconnect_blocked
                )
            )
            and self.mode in ("record", "replay")
            and int(target_port) == 3366
        )

    def should_block_detected_3366(self, client_ip: str) -> bool:
        """判断运行中才识别出的 3366 流量是否应被阻断。"""
        return bool(
            self.mode in ("record", "replay")
            and (
                self._manual_3366_block_enabled
                or (
                    self.mode == "record"
                    and client_ip in self._auto_disconnect_blocked
                )
            )
        )

    def _close_client_3366_connections(self, client_ip: str) -> int:
        """只关闭指定客户端 IP 当前已知的 3366 连接。"""
        client_conn_ids: set[str] = set()
        for ip_map in self._user_active_conns.values():
            client_conn_ids.update(ip_map.get(client_ip, set()))
        conn_ids = {
            conn_id
            for conn_id in client_conn_ids
            if self.is_manual_3366_connection(conn_id)
        }
        for conn_id in conn_ids:
            writer = self._conn_client_writers.get(conn_id)
            if writer:
                _safe_close(writer)
        return len(conn_ids)

    def set_manual_3366_block(self, enabled: bool) -> int:
        """切换录制/重放3366阻断；开启时立即关闭当前已识别连接。"""
        previous = self._manual_3366_block_enabled
        self._manual_3366_block_enabled = bool(enabled)
        if not enabled:
            self._manual_3366_drop_logged.clear()
            if previous:
                _event("INFO", self.label, "实验开关：已恢复3366连接；01通道保持原状态")
                TrafficSessionLog.write_experiment_marker(
                    "REPLAY_3366_BLOCK",
                    enabled=False,
                    details={
                        "server": self.label,
                        "mode": self.mode,
                        "closed_connections": 0,
                    },
                )
            return 0
        if self.mode not in ("record", "replay"):
            return 0
        conn_ids = {
            conn_id
            for conn_id in self._conn_client_writers
            if self.is_manual_3366_connection(conn_id)
        }
        for conn_id in conn_ids:
            writer = self._conn_client_writers.get(conn_id)
            if writer:
                _safe_close(writer)
        _event(
            "BLOCK",
            self.label,
            f"实验开关：3366已阻断，立即断开{len(conn_ids)}条连接；"
            "后续目标端口3366将被拒绝，01通道继续转发",
        )
        TrafficSessionLog.write_experiment_marker(
            "REPLAY_3366_BLOCK",
            enabled=True,
            details={
                "server": self.label,
                "mode": self.mode,
                "closed_connections": len(conn_ids),
                "connection_ids": sorted(conn_ids),
                "policy": "target_port_3366_or_protocol_detected",
                "independent_01": "continue",
            },
        )
        return len(conn_ids)

    def maybe_block_3366_after_01_threshold(
        self,
        client_ip: str,
        *,
        n01: int | None = None,
    ) -> bool:
        """兼容旧调用名：按当前配置判断录制完成条件。"""
        return self.maybe_block_3366_after_recording_goal(client_ip, n01=n01)

    def maybe_block_3366_after_recording_goal(
        self,
        client_ip: str,
        *,
        n01: int | None = None,
    ) -> bool:
        """配置的录制完成目标达标后，仅阻断同 IP 的录制口3366连接。"""
        if self.mode != "record":
            return False
        policy = str(
            app_config.get("auto_disconnect_01_policy") or "count"
        ).strip().lower()
        if policy == "off":
            return False
        if policy not in {
            "count", "coverage", "coverage_periodic", "either"
        }:
            policy = "count"
        thresh = int(app_config.get("auto_disconnect_01_threshold") or 0)
        coverage_thresh = int(
            app_config.get("auto_disconnect_message_coverage_threshold") or 0
        )
        if client_ip in self._auto_disconnect_blocked:
            return False
        if n01 is None:
            n01 = recording_pool.get_active_01_count(client_ip)
        coverage = recording_pool.get_active_message_coverage(client_ip)
        id_coverage_percent = float(
            coverage.get("priority_coverage_percent") or 0.0
        )
        coverage_percent = float(
            coverage.get("recording_completion_percent")
            if coverage.get("recording_completion_percent") is not None
            else id_coverage_percent
        )
        count_met = thresh > 0 and int(n01) >= thresh
        coverage_met = coverage_thresh > 0 and coverage_percent >= coverage_thresh
        periodic_ready = int(coverage.get("periodic_ready_count") or 0)
        periodic_total = int(coverage.get("periodic_total") or 0)
        periodic_met = periodic_total > 0 and periodic_ready >= periodic_total
        should_block = {
            "count": count_met,
            "coverage": coverage_met,
            "coverage_periodic": coverage_met and periodic_met,
            "either": count_met or coverage_met,
        }[policy]
        if not should_block:
            return False
        if policy == "coverage_periodic":
            reason = "80xx完整度＋周期就绪"
        elif coverage_met and (policy == "coverage" or not count_met):
            reason = "80xx完整度"
        elif count_met and (policy == "count" or not coverage_met):
            reason = "01数量"
        else:
            reason = "数量/80xx完整度"
        progress = (
            f"01={int(n01)}/{thresh if thresh > 0 else '关闭'}，"
            f"80xx完整度={coverage_percent:.1f}%/{coverage_thresh if coverage_thresh > 0 else '关闭'}%"
            f"（ID={id_coverage_percent:.1f}%,"
            f"8004子型={int(coverage.get('subtype_8004_seen_count') or 0)}/"
            f"{int(coverage.get('subtype_8004_total') or 0)},"
            f"周期={periodic_ready}/{periodic_total}）"
        )
        self._auto_disconnect_blocked.add(client_ip)
        # 阈值状态只属于当前 IP；不要复用全局手动开关。
        self._close_client_3366_connections(client_ip)
        hold_01 = bool(app_config.get("hold_01_after_threshold"))
        hold_note = "，01上行只收录不转发" if hold_01 else "，01继续转发"
        _event(
            "RECORD",
            self.label,
            f"[{client_ip}] 录制目标已达成（{reason}；{progress}），仅阻断同IP录制口3366；"
            f"重放口3366继续{hold_note}",
        )
        log_bus.conn_detail.emit(
            client_ip,
            f"[录制完成] {reason}；{progress}；同IP录制口3366已阻断，重放3366继续"
            + ("，01只收录" if hold_01 else "，01继续"),
        )
        TrafficSessionLog.write_experiment_marker(
            "THRESHOLD_3366_BLOCK",
            enabled=True,
            details={
                "server": self.label,
                "mode": self.mode,
                "client_ip": client_ip,
                "n01": int(n01),
                "threshold": thresh,
                "policy": policy,
                "coverage_percent": coverage_percent,
                "id_coverage_percent": id_coverage_percent,
                "coverage_threshold": coverage_thresh,
                "coverage_scope": "80xx",
                "coverage_seen": int(coverage.get("seen_priority_count") or 0),
                "coverage_total": int(coverage.get("priority_total") or 0),
                "periodic_ready": int(coverage.get("periodic_ready_count") or 0),
                "periodic_total": int(coverage.get("periodic_total") or 0),
                "periodic_met": periodic_met,
                "subtype_8004_seen": int(
                    coverage.get("subtype_8004_seen_count") or 0
                ),
                "subtype_8004_total": int(
                    coverage.get("subtype_8004_total") or 0
                ),
                "trigger_reason": reason,
                "record_3366": "block",
                "replay_3366": "continue",
                "record_01_uplink": "hold" if hold_01 else "forward",
                "independent_01": "continue",
            },
        )
        log_bus.recording_goal_3366_block.emit(client_ip, reason, progress)
        return True

    def should_hold_record_01(self, client_ip: str, direction: str = "↑UP") -> bool:
        """阈值已触发且开启「01只收录」时，录制口 01 上行不转 ACE。"""
        return bool(
            self.mode == "record"
            and direction == "↑UP"
            and app_config.get("hold_01_after_threshold")
            and client_ip in self._auto_disconnect_blocked
        )

    def _log_01_hold_once(self, client_ip: str) -> None:
        if client_ip in self._01_hold_logged:
            return
        self._01_hold_logged.add(client_ip)
        _event(
            "RECORD",
            self.label,
            f"[{client_ip}] 01上行只收录不转发，连接不断；下行有就转（序号接本地心跳），没有就本地补心跳",
        )
        log_bus.conn_detail.emit(
            client_ip,
            "[01只收录] 上行不转ACE；下行真包不丢，本地补过心跳则改外层序号再转；"
            "ACE断了也只维持客户端，除非客户端自己断开",
        )
        TrafficSessionLog.write_experiment_marker(
            "THRESHOLD_01_HOLD",
            enabled=True,
            details={
                "server": self.label,
                "mode": self.mode,
                "client_ip": client_ip,
                "uplink": "record_only",
                "downlink": "forward_restamp_or_local_keepalive",
                "replay_01": "unaffected",
            },
        )

    def is_01_hold_active(self, client_ip: str) -> bool:
        return bool(
            self.mode == "record"
            and app_config.get("hold_01_after_threshold")
            and client_ip in self._auto_disconnect_blocked
        )

    def _cache_01_keepalive_template(self, conn_id: str, frame: bytes) -> None:
        if ace_is_01_keepalive_template(frame):
            self._01_keepalive_template[conn_id] = bytes(frame)

    def _note_01_client_outer(
        self,
        conn_id: str,
        frame: bytes,
        *,
        ace_group: int | None = None,
    ) -> None:
        ids = ace_read_01_outer_ids(frame)
        if not ids:
            return
        self._01_client_seq[conn_id] = ids[0]
        self._01_client_group[conn_id] = ids[1]
        if ace_group is not None:
            self._01_last_ace_group[conn_id] = int(ace_group)

    def _prepare_record_01_downlink(
        self,
        conn_id: str,
        client_ip: str,
        frame: bytes,
    ) -> bytes:
        """真包不丢。本地已伪过心跳则把外层序号接到客户端已见序号后面。"""
        ace_ids = ace_read_01_outer_ids(frame)
        ace_group = ace_ids[1] if ace_ids else None
        outgoing = bytes(frame)
        restamped = False
        old_seq = ace_ids[0] if ace_ids else None
        if conn_id in self._01_seq_desynced:
            last_seq = self._01_client_seq.get(conn_id)
            last_group = self._01_client_group.get(conn_id)
            if last_seq is not None and last_group is not None:
                last_ace = self._01_last_ace_group.get(conn_id)
                bump_group = not (
                    ace_group is not None
                    and last_ace is not None
                    and ace_group == last_ace
                )
                seq, group = ace_next_01_outer_ids(
                    last_seq, last_group, bump_group=bump_group
                )
                stamped = ace_restamp_01_frame(frame, seq=seq, group=group)
                if stamped:
                    outgoing = stamped
                    restamped = True
        self._note_real_01_downlink(
            conn_id,
            client_ip,
            outgoing,
            restamped=restamped,
            ace_seq=old_seq,
        )
        self._note_01_client_outer(conn_id, outgoing, ace_group=ace_group)
        return outgoing

    def _note_real_01_downlink(
        self,
        conn_id: str,
        client_ip: str,
        frame: bytes,
        *,
        restamped: bool = False,
        ace_seq: int | None = None,
    ) -> None:
        """真实 ACE 下行到了：不丢包，转给客户端；伪过心跳则序号已接上。"""
        self._01_last_real_down[conn_id] = time.time()
        self._cache_01_keepalive_template(conn_id, frame)
        if conn_id in self._01_keepalive_forging:
            self._01_keepalive_forging.discard(conn_id)
            new_ids = ace_read_01_outer_ids(frame)
            new_seq = new_ids[0] if new_ids else None
            _event(
                "RECORD",
                self.label,
                f"[{client_ip}] ACE下行恢复，真包不丢，"
                f"序号 {ace_seq}→{new_seq} 接到本地心跳后转发",
            )
            log_bus.conn_detail.emit(
                client_ip,
                "[01下行恢复] 服务器又下发了，不拦截；"
                + (
                    f"外层序号 {ace_seq}→{new_seq} 接到本地心跳后面再转"
                    if restamped
                    else "继续转给客户端"
                ),
            )
            TrafficSessionLog.write_experiment_marker(
                "THRESHOLD_01_DOWNLINK_RESUME",
                enabled=True,
                details={
                    "server": self.label,
                    "client_ip": client_ip,
                    "conn_id": conn_id,
                    "frame_len": len(frame),
                    "policy": "forward_restamp_outer_seq",
                    "restamped": restamped,
                    "ace_seq": ace_seq,
                    "client_seq": new_seq,
                },
            )

    def _log_01_keepalive_once(self, client_ip: str, conn_id: str, frame: bytes) -> None:
        if conn_id in self._01_keepalive_logged:
            log_bus.conn_detail.emit(
                client_ip,
                f"[01本地心跳] {len(frame)}B seq={int.from_bytes(frame[6:10], 'big')}",
            )
            return
        self._01_keepalive_logged.add(conn_id)
        _event(
            "RECORD",
            self.label,
            f"[{client_ip}] ACE下行静默，已用本连接短08心跳本地补给客户端",
        )
        log_bus.conn_detail.emit(
            client_ip,
            "[01本地心跳] ACE太久没下发，本地补短08；01连接不断",
        )
        TrafficSessionLog.write_experiment_marker(
            "THRESHOLD_01_LOCAL_KEEPALIVE",
            enabled=True,
            details={
                "server": self.label,
                "client_ip": client_ip,
                "conn_id": conn_id,
                "frame_len": len(frame),
            },
        )

    async def _maybe_inject_01_keepalive(
        self,
        conn_id: str,
        client_ip: str,
        writer,
        *,
        force: bool = False,
    ) -> bool:
        if not self.is_01_hold_active(client_ip):
            return False
        template = self._01_keepalive_template.get(conn_id)
        if not template:
            return False
        now = time.time()
        try:
            gap = float(app_config.get("hold_01_keepalive_sec") or 8)
        except (TypeError, ValueError):
            gap = 8.0
        gap = max(2.0, gap)
        last_real = float(self._01_last_real_down.get(conn_id) or 0)
        last_inject = float(self._01_last_inject.get(conn_id) or 0)
        if not force and now - max(last_real, last_inject) < gap:
            return False
        last_seq = self._01_client_seq.get(conn_id)
        last_group = self._01_client_group.get(conn_id)
        if last_seq is None or last_group is None:
            ids = ace_read_01_outer_ids(template)
            if not ids:
                return False
            last_seq, last_group = ids
        seq, group = ace_next_01_outer_ids(last_seq, last_group, bump_group=True)
        frame = ace_bump_01_keepalive_frame(template, seq=seq, group=group)
        if not frame:
            return False
        try:
            writer.write(frame)
            await writer.drain()
        except Exception:
            return False
        self._01_keepalive_template[conn_id] = frame
        self._01_last_inject[conn_id] = now
        self._01_keepalive_forging.add(conn_id)
        self._01_seq_desynced.add(conn_id)
        self._note_01_client_outer(conn_id, frame)
        self._log_01_keepalive_once(client_ip, conn_id, frame)
        try:
            log_bus.stream_sent_data.emit(conn_id, "↓DOWN", len(frame), frame)
        except Exception:
            pass
        return True

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

        # 录制会话统一在鉴权成功后启动（见下方 AUTH_OK 之后的逻辑）
        _rec_joined = False   # 标记本连接是否已向 recording_pool 注册（需要配对 stop）

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
                    # 按游戏ID判定：同一代理用户下，录制口与重放口、不同 IP，
                    # 只要游戏ID相同即视为同一个人，允许共存。
                    # 鉴权时尚无游戏ID，先注册连接，等 01/3366 识别后再踢不同游戏ID。
                    ip_map = self._user_active_conns.setdefault(uname, {})

                    # 是否是该 IP 本次会话的第一条连接（后续并发连接不重复打上线日志）
                    is_first_conn = client_ip not in ip_map

                    # 注册本次连接（同 IP 可并发多条）
                    ip_map.setdefault(client_ip, set()).add(conn_id)
                    self._conn_client_writers[conn_id] = writer

                    if is_first_conn:
                        _event("AUTH_OK", self.label,
                               f"用户 [{uname}] 登录成功  来源={conn_id}")
                    # 后续并发连接只记录 DEBUG 级别（不污染主日志）

                    # 鉴权成功后启动录制会话（AUTH_OK 之后，保证日志顺序正确）
                    if actual_mode == "record":
                        _is_new_rec = recording_pool.new_session(
                            client_ip,
                            proxy_username=uname,
                            record_role="player",
                        )
                        _rec_joined = True
                        if _is_new_rec:
                            _event(
                                "RECORD",
                                self.label,
                                f"[{client_ip}] 开始录制会话 "
                                f"代理账号={uname} 类型=player",
                            )

                    # ── 重放端口：仅首条连接打上线日志 ────
                    if actual_mode == "replay" and is_first_conn:
                        # 允许边录边播：不强制停止录制，直接获取池引用
                        preview_pools = recording_pool.get_all_ip_pools(client_ip)
                        if preview_pools:
                            known_gids = [g for g in preview_pools.keys() if g]
                            pool_total = sum(
                                len(p.get("pool_01", [])) + len(p.get("pool_33", []))
                                for p in preview_pools.values()
                            )
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
                                   f"代理用户=[{uname}]({client_ip}) 上线 — 无录制池，"
                                   f"待首帧 33/01 解析 UID 后再匹配（非立即透传）")
                            log_bus.conn_detail.emit(
                                client_ip,
                                f"[上线] 代理用户={uname}  来源={conn_id}  "
                                f"【无录制池，待 UID 后匹配；无模板则只删叶/改写】")
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
            self._conn_target_ports[conn_id] = target_port
            dst_str = f"{target_host}:{target_port}"
            _event("CONNECT", self.label,
                   f"[{username}] → {dst_str}")
            log_bus.conn_added.emit(conn_id, conn_id, dst_str, username, actual_mode)

            # 手动开关或当前 IP 的 01 阈值状态：拒绝新 3366 CONNECT，其他连接保持原流程。
            if self.should_reject_manual_3366(target_port, actual_mode, client_ip):
                _event(
                    "BLOCK",
                    self.label,
                    f"[{username}] 阻断3366新连接 → {dst_str}；01通道继续",
                )
                log_bus.conn_detail.emit(
                    client_ip,
                    f"[3366阻断] 拒绝新连接 {dst_str}；01通道继续",
                )
                writer.write(b"\x05\x02\x00\x01" + b"\x00" * 6)
                await writer.drain()
                return

            # ④ 本地重放优先检查：命中则跳过真实连接，直接返回本地文件
            # 必须在 _connect_remote 之前，避免无谓的真实连接超时和强制断开报错
            if LEGACY_LOCAL_MAP_RUNTIME_ENABLED and target_port == 80:
                local_file = local_map_manager.get_file(target_host)
                if local_file and os.path.isfile(local_file):
                    # 按录制/重放模式自动切换同目录下的 record.html / replay.html
                    _html_dir = os.path.dirname(local_file)
                    _mode_file = os.path.join(
                        _html_dir,
                        "record.html" if actual_mode == "record" else "replay.html"
                    )
                    if os.path.isfile(_mode_file):
                        local_file = _mode_file
                    # 查询当前用户到期时间用于模板注入
                    _expire = user_manager.get_expire(username) if username and username != "Anonymous" else "-"
                    writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                    await writer.drain()
                    await _local_map_serve(reader, writer, local_file, target_host,
                                           username=username, expire=_expire,
                                           port=str(self.port))
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
                    # 同 IP 无录制：检查是否有其他 IP 录制过（跨 IP 匹配）
                    global_gids = recording_pool.get_all_game_ids()
                    if global_gids:
                        # 有全局录制数据，保持等待状态，游戏ID到来后跨 IP 查找
                        self._replay_all_pools[conn_id]   = {}   # 同IP无，跨IP待查
                        self._replay_gid_checked[conn_id] = False
                        log_bus.conn_mode_update.emit(client_ip, "待匹配(跨IP)")
                        _event("REPLAY", self.label,
                               f"代理用户=[{username}]({client_ip}) 上线 — "
                               f"本IP无录制，将跨IP按游戏账号匹配（全局账号: {', '.join(global_gids[:3])}）")
                    else:
                        # 全局无任何录制：不在 CONNECT 阶段阻断（TLS/首包无 UID）；
                        # 待上行出现 33 握手或 01(0A00 23) 解析 UID 后再匹配，无模板则只删叶/改写。
                        self._replay_all_pools[conn_id] = {}
                        self._replay_gid_checked[conn_id] = False
                        log_bus.conn_mode_update.emit(client_ip, "待匹配(无池)")
                        _event("DEBUG", self.label,
                               f"[{conn_id}] 重放 {dst_str}：全局无录制池，待 33/01 出 UID 后再匹配")
                # IP 已有 UID → 需先等到 42B 加入包再做 UID 匹配，防止旧 0A 00 23 包误触发
                if self._ip_game_uid.get(client_ip):
                    self._replay_await_join.add(conn_id)

            # ⑤ 双向转发
            # half_close=True：上行读完 EOF 后只发 TCP FIN（半关闭写端），
            # 保持连接供下行读取服务器响应，修复 HTTP 明文请求返回空白的问题
            up_count = [0]
            dn_count = [0]
            shared_ts = [time.time()]  # 连接级活跃时间戳，上下行共享，任意方向有数据即刷新
            await asyncio.gather(
                self._forward(
                    reader,
                    rw,
                    "↑UP",
                    conn_id,
                    username,
                    up_count,
                    client_ip=client_ip,
                    mode=actual_mode,
                    half_close=True,
                    dst_str=dst_str,
                    shared_ts=shared_ts,
                ),
                self._forward(
                    rr,
                    writer,
                    "↓DOWN",
                    conn_id,
                    username,
                    dn_count,
                    client_ip=client_ip,
                    mode=actual_mode,
                    dst_str=dst_str,
                    shared_ts=shared_ts,
                ),
                return_exceptions=True,
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
            # 先保留逻辑游戏会话快照，再清理传输连接状态。后续连接只有
            # 42B会话值只建候选，首个Live报告序号确认后才续接快照。
            _v130_disconnect = self._replay_game_sessions_v130.disconnect(conn_id)
            if _v130_disconnect.get("game_id"):
                traffic_file_logger.log_01_reconnect_event(
                    phase="DISCONNECT_OBSERVED",
                    username=username,
                    client_ip=client_ip,
                    conn_id=conn_id,
                    game_id=str(_v130_disconnect.get("game_id") or ""),
                    details={
                        "session_token_u32": _v130_disconnect.get(
                            "session_token_u32"
                        ),
                        "join_unix_time_u32": _v130_disconnect.get(
                            "join_unix_time_u32"
                        ),
                        "logical_elapsed_seconds": _v130_disconnect.get(
                            "logical_elapsed_seconds"
                        ),
                        "stale_connection_ignored": bool(
                            _v130_disconnect.get("stale_connection_ignored")
                        ),
                    },
                )
            self._replay_index.pop(conn_id, None)
            self._replay_index_33.pop(conn_id, None)
            self._replay_pools.pop(conn_id, None)
            self._replay_all_pools.pop(conn_id, None)
            self._replay_gid_checked.pop(conn_id, None)
            self._stream_bufs.pop(conn_id, None)
            self._stream_bufs.pop(f"{conn_id}_rec_↑UP", None)
            self._stream_bufs.pop(f"{conn_id}_rec_↓DOWN", None)
            self._stream_bufs.pop(f"{conn_id}_rep_↑UP", None)
            self._stream_bufs.pop(f"{conn_id}_rep_↓DOWN", None)
            self._st3366_up.pop(conn_id, None)
            self._st3366_down.pop(conn_id, None)
            self._3366_key_logged.discard(conn_id)
            self._3366_prod_logged.discard(conn_id)
            self._3366_decrypt_skip_logged.discard(conn_id)
            self._3366_unknown_strat_logged.discard(conn_id)
            self._conn_carries_3366.discard(conn_id)
            self._record_blocked_conns.discard(conn_id)
            self._pending_01_handshake.pop(conn_id, None)
            self._replay_01_fragment_groups.pop(f"{conn_id}_rep_↑UP", None)
            self._replay_01_fragment_groups.pop(f"{conn_id}_rep_↓DOWN", None)
            self._replay_gid_fail.pop(conn_id, None)
            self._replay_ace_recheck.discard(conn_id)
            self._replay_await_join.discard(conn_id)
            self._replay_join_triggered.discard(conn_id)
            self._replay_01_join_started.pop(conn_id, None)
            for _attr in (
                "_3366_no_items_logged",
                "_3366_no_kv_logged",
                "_3366_decrypt_fail_logged",
            ):
                _s = getattr(self, _attr, None)
                if _s is not None:
                    _s.discard(conn_id)
            self._dl_intercept_bufs.pop(conn_id, None)
            self._3366_hs_uid.pop(conn_id, None)
            self._conn_live_gid.pop(conn_id, None)
            self._01_keepalive_template.pop(conn_id, None)
            self._01_last_real_down.pop(conn_id, None)
            self._01_last_inject.pop(conn_id, None)
            self._01_client_seq.pop(conn_id, None)
            self._01_client_group.pop(conn_id, None)
            self._01_last_ace_group.pop(conn_id, None)
            self._01_keepalive_logged.discard(conn_id)
            self._01_keepalive_forging.discard(conn_id)
            self._01_seq_desynced.discard(conn_id)
            self._01_client_gone.discard(conn_id)
            
            # 注销多开跟踪
            self._conn_client_writers.pop(conn_id, None)
            self._conn_target_ports.pop(conn_id, None)
            self._manual_3366_drop_logged.discard(conn_id)
            if username:
                ip_map = self._user_active_conns.get(username, {})
                ip_conns = ip_map.get(client_ip, set())
                ip_conns.discard(conn_id)
                if not ip_conns:
                    ip_map.pop(client_ip, None)
                if not ip_map:
                    self._user_active_conns.pop(username, None)
            # 该 IP 所有连接已断开时：清理 IP 级共享状态 + 自动断线处理
            _remaining_for_ip = 0
            for _uname, ip_map in self._user_active_conns.items():
                _remaining_for_ip += len(ip_map.get(client_ip, set()))
            if _remaining_for_ip == 0:
                # _ip_game_uid / plugin_key_store 保留：下次连接时直接回填 UID 与游戏ID，
                # 避免握手延迟导致拦截状态表行消失（_3366_aes 同理持久化）
                self._plugin_key_wait_done.discard(client_ip)
                self._plugin_game_notified.discard(client_ip)
                self._3366_ab_cn_first_hs.discard(client_ip)
                self._replay_ready_logged.discard(client_ip)
                if actual_mode == "record" and client_ip in self._auto_disconnect_blocked:
                    self._auto_disconnect_blocked.discard(client_ip)
                    self._01_hold_logged.discard(client_ip)
                    _event("RECORD", self.label, f"[{client_ip}] 所有连接已断开，可重新连接")
                    try:
                        log_bus.record_updated.emit()
                    except Exception:
                        pass
            elif actual_mode == "record" and client_ip in self._auto_disconnect_blocked:
                # 还有其他连接存活，仅做原有的自动断线检查
                pass
            _safe_close(writer)
            log_bus.conn_closed.emit(conn_id)

    def _peer_servers(self) -> list["Socks5Server"]:
        """录制口与重放口都纳入多开判定（同一游戏ID视为同一个人）。"""
        servers: list[Socks5Server] = []
        seen: set[int] = set()
        try:
            peers = (engine.server_1080, engine.server_1081)
        except NameError:
            peers = ()
        for srv in (*peers, self):
            if srv is not None and id(srv) not in seen:
                seen.add(id(srv))
                servers.append(srv)
        return servers

    def _known_game_id_for_conn(self, conn_id: str, client_ip: str) -> str:
        """只认本条连接已解析的游戏ID；不用 IP 缓存，避免未上号连接被旧 UID 误踢。"""
        gid = str(self._conn_live_gid.get(conn_id) or "").strip()
        if gid:
            return gid
        if self.mode == "record":
            try:
                return str(recording_pool.game_id(client_ip) or "").strip()
            except Exception:
                return ""
        return ""

    def _remember_conn_game_id(
        self, username: str, conn_id: str, client_ip: str, game_id: str
    ) -> None:
        """连接识别到游戏ID后记录，并按游戏ID执行多开踢人。"""
        gid = str(game_id or "").strip()
        if not gid:
            return
        prev = str(self._conn_live_gid.get(conn_id) or "").strip()
        self._conn_live_gid[conn_id] = gid
        self._ip_game_uid[client_ip] = gid
        if prev != gid:
            self._enforce_multi_open_by_game_id(username, conn_id, gid)

    def _enforce_multi_open_by_game_id(
        self, username: str, conn_id: str, game_id: str
    ) -> None:
        """未开多开时，同一代理用户只允许一个游戏ID在线。

        录制与重放、不同 IP，游戏ID相同 → 同一个人，不踢。
        出现另一个游戏ID → 踢掉旧的那批连接。
        尚未识别游戏ID的连接先保留，等识别后再判定。
        """
        if not username or username == "Anonymous" or not game_id:
            return
        try:
            if user_manager.get_allow_multi(username):
                return
        except Exception:
            return

        my_gid = str(game_id)
        kicked = 0
        kicked_gids: set[str] = set()
        for srv in self._peer_servers():
            ip_map = srv._user_active_conns.get(username, {})
            for ip, cids in list(ip_map.items()):
                other_gids = {
                    srv._known_game_id_for_conn(cid, ip)
                    for cid in list(cids)
                }
                other_gids.discard("")
                if not other_gids or other_gids <= {my_gid}:
                    continue
                kicked_gids.update(other_gids - {my_gid})
                for cid in list(cids):
                    w = srv._conn_client_writers.pop(cid, None)
                    if w:
                        try:
                            w.close()
                        except Exception:
                            pass
                    kicked += 1
                ip_map.pop(ip, None)
            if not ip_map:
                srv._user_active_conns.pop(username, None)
        if kicked:
            old = "/".join(sorted(kicked_gids)) or "?"
            _event(
                "WARN",
                self.label,
                f"[{username}] 不允许多开，游戏ID=[{my_gid}] "
                f"踢出其他游戏ID[{old}] 的连接 {kicked} 个"
                f"  新来源={conn_id}",
            )

    def _replay_bind_empty_pool(
        self,
        conn_id: str,
        client_ip: str,
        live_gid: str,
        detail: str,
        *,
        username: str = "",
    ) -> tuple[list, list]:
        """录制池没有该 UID 时仍进入重放：空模板，只做删叶/改写。"""
        empty = {
            "pool_01": [],
            "pool_33": [],
            "tiered": False,
            "game_id": str(live_gid or ""),
        }
        self._replay_pools[conn_id] = empty
        if username and live_gid:
            self._v130_new_replay_index(
                conn_id, username, live_gid, client_ip=client_ip
            )
        else:
            self._replay_index[conn_id] = [0, 0]
        self._replay_index_33[conn_id] = {
            "09": [0, 0], "21": [0, 0], "01_fb": [0, 0],
        }
        self._replay_gid_checked[conn_id] = True
        log_bus.conn_detail.emit(client_ip, detail)
        log_bus.conn_mode_update.emit(client_ip, "无匹配录制")
        return empty["pool_01"], self._replay_index[conn_id]

    def _v130_new_replay_index(
        self,
        conn_id: str,
        username: str,
        game_id: str,
        *,
        client_ip: str = "",
    ) -> tuple[list, dict]:
        now = time.monotonic()
        fresh_started = self._replay_01_join_started.get(conn_id, now)
        context, started, detail = self._replay_game_sessions_v130.bind(
            conn_id,
            username,
            game_id,
            {},
            fresh_started_monotonic=fresh_started,
            now=now,
        )
        self._replay_01_join_started[conn_id] = started
        index = [0, 0, context]
        self._replay_index[conn_id] = index
        self._replay_game_sessions_v130.attach_context(conn_id, context)
        v128_state = context.get("v128_replenish") or {}
        player_state = v128_state.get("same_device_player") or {}
        traffic_file_logger.log_01_reconnect_event(
            phase="BIND_DECISION",
            username=username,
            client_ip=client_ip,
            conn_id=conn_id,
            game_id=game_id,
            details={
                **detail,
                "logical_elapsed_seconds": max(0.0, now - started),
                "semantic_state_inherited": bool(detail.get("continued")),
                "inherited_emitted_count": len(v128_state.get("emitted") or []),
                "inherited_satisfied_count": len(
                    v128_state.get("satisfied_keys") or []
                ),
                "inherited_player_consumed_count": len(
                    player_state.get("consumed") or []
                ),
                "inherited_device_context": dict(
                    context.get("live_device_context") or {}
                ),
                "transport_offsets_after_bind": {
                    key: int(v128_state.get(key) or 0)
                    for key in (
                        "report_offset",
                        "leaf_offset",
                        "frame_offset",
                        "group_offset",
                    )
                },
            },
        )
        if detail.get("candidate"):
            _event(
                "REPLAY",
                self.label,
                f"[{username}] v1.128.10重连候选 game_id=[{game_id}] "
                f"42B会话值=0x{int(detail.get('current_session_token_u32') or 0):08X}，"
                "等待首个Live报告确认",
            )
        # 冷启动 / 重开局没有 v130_pending_reconnect，不能等 Live 才标模式。
        # 先标首次重放；只有首个 Live 序号确认续连后才改成续连重放。
        self._emit_replay_phase(client_ip, context, continued=False)
        return index, detail

    def _emit_replay_phase(
        self,
        client_ip: str,
        context: dict,
        *,
        continued: bool,
    ) -> None:
        phase = replay_phase_label(continued=continued)
        if context.get("ui_replay_phase") == phase:
            return
        context["ui_replay_phase"] = phase
        if client_ip:
            log_bus.conn_replay_phase.emit(client_ip, phase)

    def _v130_finalize_live_report(
        self,
        conn_id: str,
        username: str,
        client_ip: str,
        game_id: str,
        replay_index: list,
    ) -> None:
        if len(replay_index) < 3 or not isinstance(replay_index[2], dict):
            return
        context = replay_index[2]
        result = context.pop("v130_reconnect_result", None)
        if not isinstance(result, dict):
            # FIRST_JOIN 没有重连候选，绑定阶段已经标过首次重放。
            return
        continued = bool(result.get("continued"))
        if continued:
            started = self._replay_01_join_started.get(
                conn_id, time.monotonic()
            )
        else:
            started = float(
                result.get("started_monotonic") or time.monotonic()
            )
            self._replay_01_join_started[conn_id] = started
        self._replay_game_sessions_v130.finalize_live_report(
            conn_id,
            context,
            started_monotonic=started,
        )
        traffic_file_logger.log_01_reconnect_event(
            phase="LIVE_REPORT_DECISION",
            username=username,
            client_ip=client_ip,
            conn_id=conn_id,
            game_id=game_id,
            details=result,
        )
        _event(
            "REPLAY",
            self.label,
            f"[{username}] v1.128.10首个Live报告判定 "
            f"game_id=[{game_id}] 结果={result.get('classification')} "
            f"leaf={result.get('previous_last_live_leaf_sequence')}→"
            f"{result.get('current_first_live_leaf_sequence')} "
            f"delta={result.get('forward_delta')}",
        )
        # 42B 候选只在这里升格为续连，避免把普通新连接误标为续连。
        self._emit_replay_phase(client_ip, context, continued=continued)

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

    async def _forward(
        self,
        reader,
        writer,
        direction,
        conn_id,
        username,
        counter,
        client_ip: str = "",
        mode: str = "",
        half_close: bool = False,
        dst_str: str = "",
        shared_ts: list = None,
    ):

        def _emit_progress_detail(conn_id: str, client_ip: str) -> None:
            """汇总 01/33 进度并发送 detail 信号（33 细分 09/21/01回退）"""
            try:
                pools = self._replay_pools.get(conn_id)
                ri = self._replay_index.get(conn_id)
                ri33 = self._replay_index_33.get(conn_id)
                cur01 = ri[1] if ri else 0
                total01 = len(pools.get("pool_01", [])) if pools else 0
                pool_33 = list(pools.get("pool_33", [])) if pools else []
                pool_33_09 = [it for it in pool_33 if "09" in str(it.get("source", ""))]
                pool_33_21 = [it for it in pool_33 if "21" in str(it.get("source", ""))]
                cur09 = ri33["09"][1] if ri33 else 0
                total09 = len(pool_33_09)
                cur21 = ri33["21"][1] if ri33 else 0
                total21 = len(pool_33_21)
                cur01_fb = ri33["01_fb"][1] if ri33 else 0
                cur33 = cur09 + cur21 + cur01_fb
                total33 = len(pool_33)
                log_bus.replay_progress_detail.emit(
                    client_ip, cur01, total01, cur33, total33,
                    cur09, total09, cur21, total21, cur01_fb,
                )
            except Exception:
                _log_exc("emit_progress_detail")

        def _make_on_replace(ri_ref: list, client_ip: str, conn_id: str) -> callable:
            """01录制叶子替换回调；只发送已知语义和显式热规则改写。"""
            def _on_replace(detail: dict):
                # 专属分析日志记录 REPLACE / PASS_LIVE / PASS_NON_TARGET / DROP；
                # 其中 1D、52 等非 09 包只透传，不占用模板游标和替换进度。
                try:
                    traffic_file_logger.log_01_replay_analysis_event(
                        detail=detail,
                        username=username,
                        client_ip=client_ip,
                        conn_id=conn_id,
                    )
                except Exception:
                    pass

                try:
                    self._v130_finalize_live_report(
                        conn_id,
                        username,
                        client_ip,
                        str(self._conn_live_gid.get(conn_id) or ""),
                        ri_ref,
                    )
                except Exception:
                    _log_exc("v130_finalize_live_report")

                decision = detail.get("decision")

                if decision == "PASS_NON_TARGET":
                    return
                if decision == "PASS_LIVE":
                    ri_ref[1] += 1
                    log_bus.replay_progress.emit(
                        client_ip, ri_ref[1], detail.get("pool_total", 0)
                    )
                    _emit_progress_detail(conn_id, client_ip)
                    decoded = detail.get("online_decode") or {}
                    live_decoded = decoded.get("live") or {}
                    template_decoded = decoded.get("template") or {}
                    facts = decoded.get("facts") or {}
                    shadow = detail.get("shadow_rebuild") or {}
                    live_seq = live_decoded.get("leaf_sequences") or []
                    template_seq = template_decoded.get("leaf_sequences") or []
                    line = (
                        f"[01候选门控透传] #{ri_ref[1]} "
                        f"报告={detail.get('report_index', '?')}  "
                        f"原因={detail.get('reason', '')}  "
                        f"live叶子={live_decoded.get('child_count', '?')} "
                        f"seq={live_seq}  "
                        f"模板叶子={template_decoded.get('child_count', '?')} "
                        f"seq={template_seq}  "
                        f"签名匹配={facts.get('signature_match')}  "
                        f"影子={shadow.get('status', '-')} "
                        f"{shadow.get('matched_leaves', 0)}/"
                        f"{shadow.get('total_leaves', 0)} "
                        f"语义={shadow.get('semantic_ready_leaves', 0)}/"
                        f"{shadow.get('total_leaves', 0)}  "
                        f"最终=实时原包"
                    )
                    log_bus.conn_detail.emit(client_ip, line)
                    try:
                        output_packet = b"".join(detail.get("output_frames") or [])
                        if output_packet:
                            traffic_file_logger.log_01_sliced(
                                kind="sent_live",
                                direction="↑UP",
                                uid=detail.get("account_id", "") or "",
                                data=output_packet,
                                username=username,
                            )
                    except Exception:
                        pass
                    return
                if (
                    decision == "DROP"
                    and detail.get("reason") == "SPECIAL_DROP_ROOT_REPORT"
                ):
                    ri_ref[1] += 1
                    log_bus.replay_progress.emit(
                        client_ip, ri_ref[1], detail.get("pool_total", 0)
                    )
                    _emit_progress_detail(conn_id, client_ip)
                    log_bus.conn_detail.emit(
                        client_ip,
                        f"[01专项抑制] #{ri_ref[1]} "
                        f"报告={detail.get('report_index', '?')} "
                        "根叶已改成空结果0x2000，报告序号保留",
                    )
                    _event(
                        "INFO",
                        self.label,
                        f"[{client_ip}] 0x9000根叶专项抑制完成",
                    )
                    return
                if decision == "DROP" or not detail.get("validation_ok"):
                    errors = "；".join(detail.get("validation_errors") or ["未知校验错误"])
                    log_bus.conn_detail.emit(
                        client_ip,
                        f"[01模板丢弃] 游戏ID={detail.get('account_id') or '未知'}  {errors}",
                    )
                    _event(
                        "ERROR",
                        self.label,
                        f"[{client_ip}] 01完整模板最终校验失败，已丢弃：{errors}",
                    )
                    return

                ri_ref[1] += 1
                log_bus.replay_progress.emit(
                    client_ip, ri_ref[1], detail["pool_total"]
                )
                _emit_progress_detail(conn_id, client_ip)
                detailed = ri_ref[1] <= 10
                report = detail.get("report_index")
                template_report = detail.get("template_report_index")
                shadow = detail.get("shadow_rebuild") or {}
                replacement_level = detail.get("replacement_level", "KNOWN_CLEAN")
                replacement_title = (
                    "01周期补报告"
                    if replacement_level == "V128_PERIODIC_80XX_REPORT"
                    else "01序号平移"
                    if replacement_level == "V128_SEQUENCE_OFFSET"
                    else "01根叶改空2000"
                    if detail.get("reason")
                    == "SPECIAL_DROP_ROOT_TO_CLEAN_2000_REPLACE"
                    else "01稳定80xx插叶"
                    if detail.get("replacement_level") == "SPECIAL_INSERT_LEAF"
                    or detail.get("reason") == "STABLE_80XX_INSERT_LEAF"
                    else "01已知干净替换"
                )
                pool_idx = detail.get("pool_idx")
                pool_label = (
                    "内置模型"
                    if pool_idx is None
                    else f"#{int(pool_idx) + 1}/{int(detail.get('pool_total') or 0)}"
                )
                line = (
                    f"[{replacement_title}] #{ri_ref[1]} "
                    f"来源={pool_label}  "
                    f"游戏ID={detail['account_id']}  "
                    f"实时报告={report if report is not None else '?'}"
                    f"(对照={template_report if template_report is not None else '?'})  "
                    f"CRC={detail['crc_hex']}  会话标签={detail['routing_hex']}  "
                    f"影子={shadow.get('status', '-')}  "
                    f"叶子={shadow.get('matched_leaves', 0)}/"
                    f"{shadow.get('total_leaves', 0)}  "
                    f"干净变化={shadow.get('clean_changed_leaves', 0)}  "
                    f"未知透传={shadow.get('unmapped_pass_live_leaves', 0)}  "
                    f"上下文保活={shadow.get('live_context_pass_live_leaves', 0)}  "
                    f"插叶={shadow.get('inserted_leaves', 0)}"
                    f"{(' ' + ','.join(shadow.get('inserted_message_ids') or [])) if shadow.get('inserted_leaves') else ''}  "
                    f"分片={detail['fragment_count_after']}  校验=通过"
                )
                if detailed:
                    line += (
                        f"\n  [前10包详细校验] 总长度 "
                        f"{detail['orig_pkt_len']}B→{detail['new_pkt_len']}B，"
                        f"payload {detail['orig_payload_len']}B→{detail['new_payload_len']}B，"
                        f"实时物理头/叶子序号已继承并重算双CRC，"
                        f"长度/分片/CRC/游戏ID/叶子序列 全部通过"
                    )
                if detailed and app_config.get("detail_01_log"):
                    def _hex_lines(b: bytes, per_line: int = 32) -> str:
                        rows = []
                        for i in range(0, len(b), per_line):
                            rows.append(" ".join(f"{x:02X}" for x in b[i:i + per_line]))
                        return "\n  ".join(rows)
                    line += (
                        f"\n  【实时输入】{detail['orig_pkt_len']}B:\n"
                        f"  {_hex_lines(detail.get('orig_packet', b''))}\n"
                        f"  【最终语义替换包】{detail['new_pkt_len']}B:\n"
                        f"  {_hex_lines(detail.get('new_packet', b''))}"
                    )
                log_bus.conn_detail.emit(client_ip, line)
                try:
                    _orig_pkt = detail.get("orig_packet") or b""
                    _new_pkt  = detail.get("new_packet") or b""
                    _uid_rep  = detail.get("account_id", "") or ""
                    traffic_file_logger.log_01_replace(
                        orig_packet=_orig_pkt,
                        new_packet=_new_pkt,
                        pool_idx=int(
                            detail.get("pool_idx")
                            if detail.get("pool_idx") is not None else -1
                        ),
                        uid=_uid_rep,
                        username=username,
                    )
                    # 同时写入 01_sliced.log（kind=sent：实际发出的封包切片）
                    if _new_pkt:
                        traffic_file_logger.log_01_sliced(
                            kind="sent",
                            direction="↑UP",
                            uid=_uid_rep,
                            data=_new_pkt,
                            username=username,
                        )
                except Exception:
                    pass
            return _on_replace

        try:
            while True:
                # 连接级空闲超时：上行/下行任意方向有数据都刷新 shared_ts[0]。
                # 用 ≤5s 的短轮询代替单次长等待，轮询超时后检查距上次任意方向活跃
                # 的时间间隔，只有超过阈值才真正断开，防止"下行刚推完就被上行计时踢掉"。
                _idle_sec = 0
                if mode == "record":
                    try:
                        _idle_sec = int(app_config.get("record_idle_timeout") or 0)
                    except (TypeError, ValueError):
                        _idle_sec = 0
                elif mode == "replay":
                    try:
                        _idle_sec = int(app_config.get("replay_idle_timeout") or 0)
                    except (TypeError, ValueError):
                        _idle_sec = 0
                _hold_down = (
                    direction == "↓DOWN"
                    and mode == "record"
                    and self.is_01_hold_active(client_ip)
                )
                _remote_closed = ""
                if _hold_down or (_idle_sec > 0 and shared_ts is not None):
                    if _hold_down:
                        try:
                            _keep_sec = float(app_config.get("hold_01_keepalive_sec") or 8)
                        except (TypeError, ValueError):
                            _keep_sec = 8.0
                        _poll = min(2.0, max(1.0, _keep_sec))
                    else:
                        _poll = min(5.0, float(_idle_sec))
                    try:
                        data = await asyncio.wait_for(reader.read(65536), timeout=_poll)
                        if data and shared_ts is not None:
                            shared_ts[0] = time.time()
                    except asyncio.TimeoutError:
                        if _hold_down:
                            await self._maybe_inject_01_keepalive(
                                conn_id, client_ip, writer
                            )
                        if (
                            _idle_sec > 0
                            and not self.is_01_hold_active(client_ip)
                            and shared_ts is not None
                            and time.time() - shared_ts[0] > _idle_sec
                        ):
                            _mode_label = "录制" if mode == "record" else "重放"
                            _event("RECORD" if mode == "record" else "INFO", self.label,
                                   f"[{client_ip}] {_mode_label}连接空闲超过 {_idle_sec}s，主动断开")
                            break
                        continue
                    except (
                        ConnectionResetError,
                        ConnectionAbortedError,
                        BrokenPipeError,
                        asyncio.IncompleteReadError,
                        OSError,
                    ) as ex:
                        data = b""
                        _remote_closed = type(ex).__name__
                else:
                    try:
                        data = await reader.read(65536)
                    except (
                        ConnectionResetError,
                        ConnectionAbortedError,
                        BrokenPipeError,
                        asyncio.IncompleteReadError,
                        OSError,
                    ) as ex:
                        data = b""
                        _remote_closed = type(ex).__name__
                if not data:
                    if direction == "↑UP" and self.is_01_hold_active(client_ip):
                        self._01_client_gone.add(conn_id)
                    if _hold_down:
                        why = _remote_closed or "FIN/EOF"
                        _event(
                            "RECORD",
                            self.label,
                            f"[{client_ip}] 远程01下行已断开（{why}），客户端连接保持，改本地心跳",
                        )
                        log_bus.conn_detail.emit(
                            client_ip,
                            f"[01远程断开] {why}；ACE 这边没了，客户端端口不断，改本地心跳。"
                            "除非客户端自己断开。若 ACE 后来又下发，真包不丢，序号接到本地心跳后面再转",
                        )
                        TrafficSessionLog.write_experiment_marker(
                            "THRESHOLD_01_REMOTE_CLOSE",
                            enabled=True,
                            details={
                                "server": self.label,
                                "client_ip": client_ip,
                                "conn_id": conn_id,
                                "reason": why,
                            },
                        )
                        try:
                            _keep_sec = float(app_config.get("hold_01_keepalive_sec") or 8)
                        except (TypeError, ValueError):
                            _keep_sec = 8.0
                        while self.is_01_hold_active(client_ip):
                            if conn_id in self._01_client_gone:
                                break
                            try:
                                if writer.is_closing():
                                    break
                            except Exception:
                                break
                            injected = await self._maybe_inject_01_keepalive(
                                conn_id, client_ip, writer, force=True
                            )
                            if not injected and conn_id in self._01_keepalive_template:
                                break
                            await asyncio.sleep(max(2.0, _keep_sec))
                    elif _remote_closed:
                        _event(
                            "RECORD" if mode == "record" else "INFO",
                            self.label,
                            f"[{client_ip}] 远程{direction}断开 {_remote_closed}",
                        )
                    break
                counter[0] += 1

                dfm_3366_raw_chunk = bool(
                    DFM_3366_PASSTHROUGH_ONLY
                    and (
                        self.is_manual_3366_connection(conn_id)
                        or _find_valid_magic(data, 0) >= 0
                    )
                )
                # 三角洲3366纯透传不进入原始流面板和持久TCP详单。
                if not dfm_3366_raw_chunk:
                    log_bus.stream_raw_data.emit(conn_id, direction, len(data), data)
                    try:
                        traffic_file_logger.log_tcp_chunk(
                            conn_id=conn_id,
                            direction=direction,
                            dst=dst_str or "?",
                            mode=mode,
                            label=self.label,
                            data=data,
                            username=username,
                        )
                    except Exception:
                        pass

                # ── 静默录制：TCP 流重组，提取完整的 01 包 ──────────────────
                is_record_01_chunk = False
                if mode == "record":
                    rec_key = f"{conn_id}_rec_{direction}"
                    in_rec_stream = rec_key in self._stream_bufs
                    is_record_01_chunk = in_rec_stream or (
                        len(data) >= 2 and data[0] == 0x01 and data[1] == 0x00
                    )
                    if is_record_01_chunk:
                        rec_buf = self._stream_bufs.setdefault(rec_key, bytearray())
                        rec_buf += data
                        pos = 0
                        down_out: list[bytes] = []
                        while pos + 5 <= len(rec_buf):
                            # 对已拼接数据头进行极其严格的 01 00 00 校验
                            # 由于分包到达时，第一包已经被确认为 01 00（前面逻辑保障了），
                            # 这里的目的是防止在拼接过程或是杂乱数据中把 01 XX XX 误当包头
                            if rec_buf[pos] != 0x01 or rec_buf[pos+1] != 0x00:
                                pos += 1
                                continue
                            pkt_len = (rec_buf[pos + 3] << 8) | rec_buf[pos + 4]
                            
                            # 【修正】有些 01 包头部可能没有连续的 00 00（例如 01 2C 18 ... 如果真的是有效包的话）
                            # 所以不能强求 rec_buf[pos+1]==0 and rec_buf[pos+2]==0。
                            # 我们可以通过合理的长度上限，以及对总长度的把控来过滤掉绝大部分的密文碰撞。
                            if pkt_len < 5 or pkt_len > 10000:  # 01 包一般不会超过10KB
                                pos += 1
                                continue
                            if pos + pkt_len > len(rec_buf):
                                break
                            sub = bytes(rec_buf[pos : pos + pkt_len])
                            if len(sub) == 42:
                                _register_01_42_handshake_hint(client_ip, sub)
                            sent = sub
                            if direction == "↓DOWN":
                                sent = self._prepare_record_01_downlink(
                                    conn_id, client_ip, sub
                                )
                                down_out.append(sent)

                            # 录制模式向数据流面板发送组装好的单个原始 01 帧（panel②：分包还原/替换前）
                            log_bus.stream_parsed_data.emit(conn_id, direction, "01", len(sub), sub)
                            try:
                                _uid_01 = self._conn_live_gid.get(conn_id, "")
                                traffic_file_logger.log_01_sliced(
                                    kind="recv",
                                    direction=direction,
                                    uid=_uid_01,
                                    data=sub,
                                    username=username,
                                )
                                traffic_file_logger.log_persistent_01_record_packet(
                                    direction=direction,
                                    client_ip=client_ip,
                                    conn_id=conn_id,
                                    uid=_uid_01,
                                    data=sub,
                                    username=username,
                                )
                                if direction == "↓DOWN":
                                    traffic_file_logger.log_01_downlink_packet(
                                        mode="record",
                                        client_ip=client_ip,
                                        conn_id=conn_id,
                                        uid=_uid_01,
                                        data=sent,
                                        username=username,
                                        disposition="FORWARD",
                                        reason=(
                                            "RECORD_SERVER_DOWNLINK_RESTAMP"
                                            if sent != sub
                                            else "RECORD_SERVER_DOWNLINK"
                                        ),
                                    )
                            except Exception:
                                pass
                            
                            if direction == "↑UP":
                                try:
                                    if conn_id in self._record_blocked_conns:
                                        pass  # 已确认 uid 在重放，后续所有包透传不入池
                                    elif len(sub) == 42:
                                        # 42B 加入包明确表示一轮新的 01 录制：
                                        # 原地清空旧 01 池（保留 33），再等下一帧确认 UID。
                                        recording_pool.begin_01_join(client_ip)
                                        self._pending_01_handshake[conn_id] = sub
                                    elif conn_id in self._pending_01_handshake:
                                        # 第二步：42握手包之后的帧，尝试提取 uid
                                        _rec_uid = _parse_ace_account_id(sub)
                                        if _rec_uid:
                                            self._remember_conn_game_id(
                                                username, conn_id, client_ip, _rec_uid)
                                            if recording_pool.is_game_id_being_replayed(_rec_uid):
                                                # uid 正在重放：42包和本帧都不入池，标记透传
                                                self._pending_01_handshake.pop(conn_id, None)
                                                self._record_blocked_conns.add(conn_id)
                                                _event("INFO", self.label,
                                                       f"[{client_ip}] 01通道 uid=[{_rec_uid}] 正在重放，跳过入池（透传）")
                                            else:
                                                # uid 不在重放：42包无需入池，本帧正常入池
                                                self._pending_01_handshake.pop(conn_id, None)
                                                recording_pool.append(client_ip, sub)
                                        else:
                                            # 本帧仍无 uid（少见），42包无需入池，本帧正常入池，退出等待
                                            self._pending_01_handshake.pop(conn_id, None)
                                            recording_pool.append(client_ip, sub)
                                    else:
                                        _rec_uid = _parse_ace_account_id(sub)
                                        if _rec_uid:
                                            self._remember_conn_game_id(
                                                username, conn_id, client_ip, _rec_uid)
                                        recording_pool.append(client_ip, sub)
                                except Exception:
                                    _log_exc("pending_01_handshake")
                                try:
                                    self.maybe_block_3366_after_01_threshold(client_ip)
                                except Exception:
                                    _log_exc("01_threshold_3366_block")
                            pos += pkt_len
                        del rec_buf[:pos]
                        # 缓冲区为空时必须清理，否则后续 3366 流量会错误进入此分支
                        if not rec_buf:
                            self._stream_bufs.pop(rec_key, None)
                        if (
                            direction == "↓DOWN"
                            and conn_id in self._01_seq_desynced
                        ):
                            # 本地已伪过心跳：只发改过序号的完整帧，半包留缓冲。
                            data = b"".join(down_out)

                # ── 重放替换：流重组缓冲区 ──────────────────────────────────────
                # TCP 分包问题：一次 read 可能只包含某个 01 子包的一部分，
                # 下次 read 才是续体（不以 01 开头）。
                # 方案：维护 per-connection 流缓冲区，逐步提取完整子包，
                #        不完整尾部留缓冲等下次 read，所有处理后子包拼一起发出。
                if mode == "replay":
                    ri   = self._replay_index.get(conn_id)
                    pools = self._replay_pools.get(conn_id)
                    pool = (pools.get("pool_01", []) if pools else []) if ri is not None else []
                    
                    rep_key = f"{conn_id}_rep_{direction}"
                    in_stream = rep_key in self._stream_bufs

                    # 始终缓冲并拼装 01 流，无论是否匹配重放池（为了 UI 和后续正确解析）
                    # 下发 01 包有时候不一定是纯粹的 `01 00 ...` 开头，比如在下载或复杂情况下可能有杂质前缀。
                    # 如果不需要重放替换（下行），尽量保持原样透传。但由于我们需要 UI 解析，这里还是要拼接。
                    if in_stream or (len(data) >= 2 and data[0] == 0x01 and data[1] == 0x00):
                        buf = self._stream_bufs.setdefault(rep_key, bytearray())
                        buf += data

                        on_replace = _make_on_replace(ri, client_ip, conn_id) if ri is not None else None
                        output = bytearray()
                        pos = 0

                        while pos + 5 <= len(buf):
                            # 同上，重放模式拼接同样严格要求 01 00
                            if buf[pos] != 0x01 or buf[pos+1] != 0x00:
                                output.append(buf[pos])
                                pos += 1
                                continue

                            pkt_len = (buf[pos + 3] << 8) | buf[pos + 4]
                            
                            # 【修正】不能强求 buf[pos+1]==0 and buf[pos+2]==0，可能存在有效的 01 xx xx...
                            if pkt_len < 5 or pkt_len > 10000:
                                output.append(buf[pos])
                                pos += 1
                                continue

                            if pos + pkt_len > len(buf):
                                # 之前这里直接 break，导致如果不完整的包是最后一段，那么前面累积的杂乱字节（如果有）虽然被加到了 output 里，但是没有通过后面的 bytes(output) 保留到 buf 里的未处理数据之前！
                                # 正确做法是把剩余的所有字节都保留在 buf 中！
                                break

                            sub = bytes(buf[pos : pos + pkt_len])
                            if len(sub) == 42:
                                _register_01_42_handshake_hint(client_ip, sub)
                                if direction == "↑UP":
                                    TrafficSessionLog.reset_ai_connection_state(conn_id)
                                    _join_now = time.monotonic()
                                    self._replay_01_join_started[conn_id] = _join_now
                                    _join_fields = self._replay_game_sessions_v130.observe_join(
                                        conn_id,
                                        username,
                                        sub,
                                        now=_join_now,
                                    )
                                    if _join_fields is not None:
                                        traffic_file_logger.log_01_reconnect_event(
                                            phase="JOIN_42_OBSERVED",
                                            username=username,
                                            client_ip=client_ip,
                                            conn_id=conn_id,
                                            game_id=self._conn_live_gid.get(conn_id, ""),
                                            details={
                                                "session_token_u32": _join_fields[
                                                    "session_token_u32"
                                                ],
                                                "session_token_hex": (
                                                    f"0x{_join_fields['session_token_u32']:08X}"
                                                ),
                                                "unix_time_u32": _join_fields[
                                                    "unix_time_u32"
                                                ],
                                                "unix_time_hex": (
                                                    f"0x{_join_fields['unix_time_u32']:08X}"
                                                ),
                                                "join_frame_hex": sub.hex().upper(),
                                            },
                                        )

                            # 向数据流面板发送组装好的单个原始 01 帧（panel②：分包还原/替换前）
                            log_bus.stream_parsed_data.emit(conn_id, direction, "01", len(sub), sub)
                            try:
                                _uid_rep_r = self._conn_live_gid.get(conn_id, "")
                                traffic_file_logger.log_01_sliced(
                                    kind="recv",
                                    direction=direction,
                                    uid=_uid_rep_r,
                                    data=sub,
                                    username=username,
                                )
                                if direction == "↓DOWN":
                                    _dl_scan = bool(
                                        app_config.get("dl_01_block_enabled")
                                        or app_config.get(
                                            "dl_01_mrpcs_mutate_enabled"
                                        )
                                    )
                                    traffic_file_logger.log_01_downlink_packet(
                                        mode="replay",
                                        client_ip=client_ip,
                                        conn_id=conn_id,
                                        uid=_uid_rep_r,
                                        data=sub,
                                        username=username,
                                        disposition=(
                                            "INTERCEPT_SCAN" if _dl_scan else "FORWARD"
                                        ),
                                        reason=(
                                            "TYPE8_ZIP_AND_TYPE9_MRPCS_SCAN"
                                            if _dl_scan
                                            else "REPLAY_SERVER_DOWNLINK"
                                        ),
                                    )
                            except Exception:
                                pass

                            # ── 游戏ID匹配：先等 42B 加入包（IP已有UID时），再用 0A 00 23 选定重放池 ──
                            if direction == "↑UP" and not self._replay_gid_checked.get(conn_id, True):
                                # 42B 加入包到达 → 解除等待，允许后续 0A 00 23 匹配
                                if (len(sub) == 42
                                        and b"\x0A\x00\x23" not in sub
                                        and conn_id in self._replay_await_join):
                                    self._replay_await_join.discard(conn_id)
                                    self._replay_join_triggered.add(conn_id)  # 标记已由42B解锁
                                    log_bus.conn_detail.emit(
                                        client_ip,
                                        "[加入包] 收到42B加入包，开始等待UID匹配")
                                # 还未见到 42B 加入包时，忽略 0A 00 23（防旧包误匹配）
                                if (b"\x0A\x00\x23" in sub
                                        and conn_id not in self._replay_await_join):
                                    live_gid  = _parse_ace_account_id(sub)
                                    if live_gid:
                                        self._remember_conn_game_id(
                                            username, conn_id, client_ip, live_gid)
                                        log_bus.conn_game_id_update.emit(client_ip, str(live_gid), "重放")
                                    all_pools = self._replay_all_pools.get(conn_id, {})
                                    matched = (
                                        recording_pool.find_v129_01_pool(
                                            str(live_gid),
                                            client_version=app_config.get(
                                                "dfm_client_version", "auto"
                                            ),
                                            include_official=False,
                                            enable_device_cross_account=True,
                                        )
                                        if live_gid else None
                                    )
                                    if not matched:
                                        matched = all_pools.get(live_gid) if live_gid else None
                                    # 同IP池未命中 → 跨IP按游戏账号查找
                                    if not matched and live_gid:
                                        matched = recording_pool.find_pool_by_game_id(str(live_gid))
                                        if matched:
                                            _event("REPLAY", self.label,
                                                   f"[{username}({client_ip})] 跨IP匹配成功："
                                                   f"游戏账号={live_gid} 来自其他录制IP")
                                    if matched:
                                        if matched.get("tiered"):
                                            try:
                                                traffic_file_logger.log_01_replay_template_selection(
                                                    username=username,
                                                    client_ip=client_ip,
                                                    conn_id=conn_id,
                                                    live_game_id=str(live_gid),
                                                    selected=matched,
                                                )
                                            except Exception:
                                                pass
                                            _event(
                                                "REPLAY",
                                                self.label,
                                                f"[{username}({client_ip})] 玩家设备池："
                                                f"候选={matched.get('personal_01_count', 0)} "
                                                f"跨账号={bool(matched.get('device_cross_account'))}",
                                            )
                                        # 找到匹配的录制会话 → 激活重放（01/33 分池）
                                        self._replay_pools[conn_id] = matched
                                        self._v130_new_replay_index(
                                            conn_id,
                                            username,
                                            str(live_gid),
                                            client_ip=client_ip,
                                        )
                                        self._replay_index_33[conn_id] = {
                                            "09": [0, 0], "21": [0, 0], "01_fb": [0, 0]
                                        }
                                        pool_01 = matched.get("pool_01", [])
                                        pool_33 = matched.get("pool_33", [])
                                        pool = pool_01
                                        ri = self._replay_index[conn_id]
                                        on_replace = _make_on_replace(ri, client_ip, conn_id)
                                        n01, n33 = len(pool_01), len(pool_33)
                                        log_bus.replay_progress.emit(client_ip, 0, n01 + n33)
                                        n09 = len([it for it in pool_33 if "09" in str(it.get("source", ""))])
                                        n21 = len([it for it in pool_33 if "21" in str(it.get("source", ""))])
                                        log_bus.replay_progress_detail.emit(
                                            client_ip, 0, n01, 0, n33, 0, n09, 0, n21, 0,
                                        )
                                        # 同 IP 只打一次"重放就绪"，后续连接静默匹配
                                        if client_ip not in self._replay_ready_logged:
                                            self._replay_ready_logged.add(client_ip)
                                        log_bus.conn_detail.emit(
                                            client_ip,
                                            f"[重放就绪] 游戏ID=[{live_gid}]  01池={n01} 33池={n33}"
                                            + (
                                                f"  跨账号donor=[{matched.get('donor_game_id')}]"
                                                if matched.get("cross_account") else ""
                                            ))
                                        # 标记本连接已完成 UID 匹配，防止后续 0A 00 23 重置重放索引
                                        self._replay_gid_checked[conn_id] = True
                                    else:
                                        # 无匹配录制：不阻断，空模板继续走删叶/改写
                                        gid_str = f"[{live_gid}]" if live_gid else "[未知]"
                                        if conn_id in self._replay_join_triggered:
                                            self._replay_join_triggered.discard(conn_id)
                                            pool, ri = self._replay_bind_empty_pool(
                                                conn_id,
                                                client_ip,
                                                str(live_gid or ""),
                                                f"[无匹配录制] UID={gid_str}，跳过叶子替换，保留删叶/改写",
                                                username=username,
                                            )
                                            on_replace = _make_on_replace(
                                                ri, client_ip, conn_id
                                            )
                                        else:
                                            fail_cnt = self._replay_gid_fail.get(conn_id, 0) + 1
                                            self._replay_gid_fail[conn_id] = fail_cnt
                                            _max_fail = 3
                                            if fail_cnt < _max_fail:
                                                log_bus.conn_detail.emit(
                                                    client_ip,
                                                    f"[跳过] 无匹配录制 游戏ID={gid_str}"
                                                    f"  (第{fail_cnt}/{_max_fail}次，等待正确账号包)")
                                                self._replay_gid_checked[conn_id] = False
                                                pos += pkt_len
                                                continue
                                            _event(
                                                "WARN",
                                                self.label,
                                                f"[{username}] 无匹配录制 游戏ID={gid_str}，"
                                                f"跳过叶子替换，保留删叶/改写",
                                            )
                                            pool, ri = self._replay_bind_empty_pool(
                                                conn_id,
                                                client_ip,
                                                str(live_gid or ""),
                                                f"[无匹配录制] 游戏ID={gid_str}  "
                                                f"（已重试{fail_cnt}次，不替换叶子）",
                                                username=username,
                                            )
                                            on_replace = _make_on_replace(
                                                ri, client_ip, conn_id
                                            )

                            # ── 重放进行中的 ACE 重握手检测 ────────────────────────────
                            # 42B 加入包到来 → 标记等待新 UID。
                            # 随后 0A 00 23：
                            #   UID 在录制池 → 42B建候选，首个Live报告完成最终判定
                            #   UID 不在录制池 → 直接丢弃本包
                            if direction == "↑UP" and ri is not None:
                                if len(sub) == 42 and b"\x0A\x00\x23" not in sub:
                                    # 42字节加入包：标记"等待新UID校验"
                                    self._replay_ace_recheck.add(conn_id)
                                    log_bus.conn_detail.emit(
                                        client_ip,
                                        "[ACE重握手] 重放中收到42B加入包，等待UID校验")
                                elif b"\x0A\x00\x23" in sub and conn_id in self._replay_ace_recheck:
                                    self._replay_ace_recheck.discard(conn_id)
                                    _recheck_uid = _parse_ace_account_id(sub)
                                    # 在所有已知录制池中查找新 UID
                                    _rc_all = self._replay_all_pools.get(conn_id, {})
                                    _rc_matched = _rc_all.get(str(_recheck_uid)) if _recheck_uid else None
                                    if not _rc_matched and _recheck_uid:
                                        _rc_matched = recording_pool.find_v129_01_pool(
                                            str(_recheck_uid),
                                            client_version=app_config.get(
                                                "dfm_client_version", "auto"
                                            ),
                                            include_official=False,
                                            enable_device_cross_account=True,
                                        )
                                        if not _rc_matched:
                                            _rc_matched = recording_pool.find_pool_by_game_id(str(_recheck_uid))
                                    if _rc_matched:
                                        # UID 在录制池：新传输游标归零；游戏语义状态仅在
                                        # 42B会话值只建候选；首个Live报告确认后才继承。
                                        self._replay_pools[conn_id] = _rc_matched
                                        pools = _rc_matched          # 更新局部变量
                                        pool  = pools.get("pool_01", [])
                                        _new_ri, _resume_detail = self._v130_new_replay_index(
                                            conn_id,
                                            username,
                                            str(_recheck_uid),
                                            client_ip=client_ip,
                                        )
                                        ri[:] = _new_ri              # 保持当前处理循环引用不变
                                        self._replay_index[conn_id] = ri
                                        self._replay_game_sessions_v130.attach_context(
                                            conn_id, ri[2]
                                        )
                                        _ri33_reset = self._replay_index_33.get(conn_id)
                                        if _ri33_reset:
                                            for _k33 in _ri33_reset:
                                                _ri33_reset[_k33] = [0, 0]
                                        if _recheck_uid:
                                            self._remember_conn_game_id(
                                                username, conn_id, client_ip, _recheck_uid)
                                            log_bus.conn_game_id_update.emit(
                                                client_ip, str(_recheck_uid), "重放")
                                        log_bus.conn_detail.emit(
                                            client_ip,
                                            f"[重连] UID=[{_recheck_uid}] "
                                            f"判定={_resume_detail.get('decision')}，"
                                            "传输索引归零")
                                    else:
                                        log_bus.conn_detail.emit(
                                            client_ip,
                                            f"[丢包] 重连UID=[{_recheck_uid or '未知'}] 不在录制池")
                                    # 无论是否在录制池，0A 00 23 包本身均丢弃不发送
                                    pos += pkt_len
                                    continue

                            if ri is None or direction == "↓DOWN":
                                _dl_zip_enabled = bool(
                                    app_config.get("dl_01_block_enabled")
                                )
                                _dl_mrpcs_enabled = bool(
                                    app_config.get("dl_01_mrpcs_mutate_enabled")
                                )
                                if direction == "↓DOWN" and (
                                    _dl_zip_enabled or _dl_mrpcs_enabled
                                ):
                                    _dl_meta = _ace_01_frame_meta(sub)
                                    _dl_frames = [sub]
                                    _dl_group_key = None
                                    if _dl_meta and int(_dl_meta["fragment_count"]) > 1:
                                        _dl_group_key = _ace_01_fragment_key(sub)
                                        if _dl_group_key is not None:
                                            _dl_groups = self._replay_01_fragment_groups.setdefault(
                                                rep_key, {}
                                            )
                                            _dl_slots = _dl_groups.setdefault(
                                                _dl_group_key, {}
                                            )
                                            _dl_slots[int(_dl_meta["fragment_number"])] = sub
                                            if len(_dl_slots) < int(_dl_meta["fragment_count"]):
                                                pos += pkt_len
                                                continue
                                            _dl_frames = [
                                                _dl_slots[index]
                                                for index in sorted(_dl_slots)
                                            ]
                                            _dl_groups.pop(_dl_group_key, None)
                                            if not _dl_groups:
                                                self._replay_01_fragment_groups.pop(
                                                    rep_key, None
                                                )

                                    _dl_output = _dl_frames
                                    _game_uid = (
                                        self._conn_live_gid.get(conn_id)
                                        or self._3366_hs_uid.get(conn_id)
                                        or (
                                            self._replay_pools.get(conn_id, {})
                                        ).get("game_id")
                                        or self._ip_game_uid.get(client_ip, "")
                                    )
                                    _proxy_user = username or ""
                                    _conn_label = (
                                        f"{_game_uid}({_proxy_user})"
                                        if _game_uid and _proxy_user
                                        and str(_game_uid) != _proxy_user
                                        else str(_game_uid) or _proxy_user or client_ip
                                    )
                                    _dl_changed = False
                                    _dl_change_reasons: list[str] = []

                                    if _dl_mrpcs_enabled:
                                        _dl_output, _mrpcs_info = (
                                            ace_mutate_01_downlink_mrpcs_frames(
                                                _dl_output
                                            )
                                        )
                                        if _mrpcs_info.get("changed"):
                                            _dl_changed = True
                                            _names = ", ".join(
                                                f"{row.get('before')}->{row.get('after')}"
                                                for row in _mrpcs_info.get("matches", [])
                                            )
                                            log_bus.dl_intercept_event.emit(
                                                _conn_label,
                                                "01_drop",
                                                "01下行MRPCS文件名已混淆: "
                                                f"matches={_mrpcs_info.get('match_count', 0)} "
                                                f"{_names} frames={len(_dl_output)}",
                                            )
                                            _dl_change_reasons.append(
                                                "MRPCS:" + (_names or "MATCHED")
                                            )

                                    if _dl_zip_enabled:
                                        _dl_output, _zip_info = (
                                            ace_corrupt_01_downlink_zip_frames(
                                                _dl_output
                                            )
                                        )
                                        if _zip_info.get("changed"):
                                            _dl_changed = True
                                            log_bus.dl_intercept_event.emit(
                                                _conn_label,
                                                "01_drop",
                                                "01下行ZIP已解密并破坏: "
                                                f"file={_zip_info.get('filename') or '-'} "
                                                f"zip_offset=0x{int(_zip_info['zip_offset']):X} "
                                                f"PK->PZ selector={_zip_info.get('selector')} "
                                                f"key={_zip_info.get('key_index')} "
                                                f"frames={len(_dl_output)}",
                                            )
                                            _dl_change_reasons.append(
                                                "ZIP:"
                                                + str(_zip_info.get("filename") or "-")
                                            )

                                    if _dl_changed:
                                        _reason = ";".join(_dl_change_reasons) or "DOWNLINK_MUTATED"
                                        try:
                                            for _original_frame in _dl_frames:
                                                traffic_file_logger.log_01_downlink_packet(
                                                    mode="replay",
                                                    client_ip=client_ip,
                                                    conn_id=conn_id,
                                                    uid=str(_game_uid or ""),
                                                    data=_original_frame,
                                                    username=username,
                                                    disposition="MATCHED_BEFORE_MUTATE",
                                                    reason=_reason,
                                                )
                                            for _changed_frame in _dl_output:
                                                traffic_file_logger.log_01_downlink_packet(
                                                    mode="replay",
                                                    client_ip=client_ip,
                                                    conn_id=conn_id,
                                                    uid=str(_game_uid or ""),
                                                    data=_changed_frame,
                                                    username=username,
                                                    disposition="OUTPUT_AFTER_MUTATE",
                                                    reason=_reason,
                                                )
                                        except Exception:
                                            pass

                                    if _dl_changed or len(_dl_frames) > 1:
                                        output.extend(b"".join(_dl_output))
                                        pos += pkt_len
                                        continue

                                # 还没选定池（等待 0A 00 23 包），或者当前包是下行，当前包透传
                                output.extend(sub)
                                pos += pkt_len
                                continue

                            # 01 简单模式：按游戏ID选定池后，完整干净模板按游标循环。
                            # payload/长度/CRC 使用模板值，只覆盖实时外层会话头。
                            expected_gid = (
                                self._conn_live_gid.get(conn_id)
                                or self._ip_game_uid.get(client_ip)
                                or ""
                            )
                            _selected_pool_meta = self._replay_pools.get(conn_id, {})
                            _cross_account_01 = bool(
                                _selected_pool_meta.get("device_cross_account")
                            )
                            _donor_game_id = str(
                                _selected_pool_meta.get("donor_game_id") or ""
                            )
                            frame_meta = _ace_01_frame_meta(sub)
                            if frame_meta and frame_meta["fragment_count"] > 1:
                                frame_key = _ace_01_fragment_key(sub)
                                groups = self._replay_01_fragment_groups.setdefault(
                                    rep_key, {}
                                )
                                slots = groups.setdefault(frame_key, {})
                                slots[frame_meta["fragment_number"]] = sub
                                if len(slots) < frame_meta["fragment_count"]:
                                    # 先收齐完整逻辑包；CRC 和记录边界都依赖全部分片。
                                    pos += pkt_len
                                    continue
                                frames = [slots[i] for i in sorted(slots)]
                                groups.pop(frame_key, None)
                                if not groups:
                                    self._replay_01_fragment_groups.pop(rep_key, None)
                                rebuilt_frames, _ = _ace_try_replay_template(
                                    frames,
                                    pool,
                                    ri,
                                    expected_game_id=str(expected_gid),
                                    allow_cross_account=_cross_account_01,
                                    donor_game_id=_donor_game_id,
                                    device_mode=app_config.get(
                                        "type9_device_mode", "inherit_live"
                                    ),
                                    on_log=on_replace,
                                    session_elapsed_seconds=(
                                        time.monotonic()
                                        - self._replay_01_join_started.setdefault(
                                            conn_id, time.monotonic()
                                        )
                                    ),
                                )
                                output.extend(b"".join(rebuilt_frames))
                            else:
                                rebuilt_frames, _ = _ace_try_replay_template(
                                    [sub],
                                    pool,
                                    ri,
                                    expected_game_id=str(expected_gid),
                                    allow_cross_account=_cross_account_01,
                                    donor_game_id=_donor_game_id,
                                    device_mode=app_config.get(
                                        "type9_device_mode", "inherit_live"
                                    ),
                                    on_log=on_replace,
                                    session_elapsed_seconds=(
                                        time.monotonic()
                                        - self._replay_01_join_started.setdefault(
                                            conn_id, time.monotonic()
                                        )
                                    ),
                                )
                                output.extend(b"".join(rebuilt_frames))
                            pos += pkt_len

                        # 【修复】：把没有被处理的不完整包的前置游散字节也作为合法数据透传出去
                        # 否则这些散字节会被错误地丢弃或滞留
                        if pos < len(buf):
                            pass

                        del buf[:pos]
                        
                        # 凡是进入了这个 if 分支（data 以 01 00 开头，或 in_stream 续包），
                        # data 的归宿只有两种：有通过拦截的包 → output；全被拦截/数据不完整 → 空。
                        # 不能让原始 data 泄漏到后续 3366 / writer.write 路径。
                        if output:
                            data = bytes(output)
                        else:
                            # output 为空：要么所有包都被拦截，要么数据全进 buf 等待续包。
                            # 无论 in_stream 初始值为 True 还是 False，都必须清空 data。
                            # （旧逻辑 elif in_stream 漏掉了"第一次遇到 01 00 且全被拦截"的情形）
                            data = b""
                        # 不满足 01 00 且 in_stream=False 的纯透传数据不会进入此分支，data 原样保留。
                        # 缓冲区为空时必须清理，否则后续 3366 流量会错误进入此分支
                        if not buf:
                            self._stream_bufs.pop(rep_key, None)

                # ── 33 66：切帧、Hex、录制、首下行 Key/IV、产品 ID（如 00 00 09 4E）──
                st3366 = (
                    self._st3366_down if direction == "↓DOWN" else self._st3366_up
                ).setdefault(conn_id, Conn3366State())
                valid_3366_magic = _find_valid_magic(data, 0) >= 0
                need_3366 = bool(st3366.buf) or valid_3366_magic
                dfm_3366_passthrough = bool(
                    DFM_3366_PASSTHROUGH_ONLY and need_3366 and data
                )

                # 三角洲3366隔离路径：仅用无密钥流切帧确认协议，以支持手动阻断。
                # 不解析账号/产品、不解密、不入录制池、不选择01模板，也不改变独立01游标。
                if dfm_3366_passthrough:
                    detected_frames = feed_3366_stream(st3366, data)
                    if valid_3366_magic or detected_frames:
                        self._conn_carries_3366.add(conn_id)
                        self.detach_3366_from_01_replay(conn_id)
                    if (
                        self.should_block_detected_3366(client_ip)
                        and self.is_manual_3366_connection(conn_id)
                    ):
                        if conn_id not in self._manual_3366_drop_logged:
                            self._manual_3366_drop_logged.add(conn_id)
                            _event(
                                "BLOCK",
                                self.label,
                                f"[{client_ip}] 已识别3366协议并断开 {dst_str or conn_id}；"
                                "独立01连接与重放游标保持不变",
                            )
                            log_bus.conn_detail.emit(
                                client_ip,
                                f"[3366阻断] 已识别协议并断开 {dst_str or conn_id}",
                            )
                        _safe_close(writer)
                        client_writer = self._conn_client_writers.get(conn_id)
                        if client_writer is not writer:
                            _safe_close(client_writer)
                        return

                # 在进入 3366 组装前，先处理外层包裹（如果它是 01 包，前面可能带有 01 00 xx xx 的头）
                # 由于之前的流缓冲区已经合并了 01 包，如果 data 本身就是带有外层头的（例如 01 xx... + 33 66），
                # 后面简单的 replace 可能会导致长度不一致问题。但这需要看后续重组策略。
                # 目前直接使用 data.replace() 来替换整个 3366 帧的内容。

                if need_3366 and data and not dfm_3366_passthrough:
                    # ── 插件 Key 等待：10 01/10 02 交换完成但无法从包内取 Key 时
                    #    阻塞等待插件提交 Key，再放行 20 01/20 02/40 13 ──
                    # 录制模式仅录 01 通道，3366 不解密也不入池，无需等待 Key
                    # skip_33=True 时跳过等待（全局调试开关：仅 01 重放）
                    if (mode == "replay"
                            and not app_config.get("skip_33", False)
                            and not self._3366_aes.get(client_ip)
                            and client_ip not in self._plugin_key_wait_done):
                        # 三角洲：改为用 1002 + 固定客户端密钥本地推导 key，不再等待插件注入
                        if plugin_key_store.get_game(client_ip) == "0a92":
                            self._plugin_key_wait_done.add(client_ip)
                        else:
                            _down_st_ck = self._st3366_down.get(conn_id)
                            if _down_st_ck and _down_st_ck.seen_server_first and not _down_st_ck.key:
                                pk = plugin_key_store.get(client_ip)
                                if pk:
                                    self._3366_aes[client_ip] = pk
                                    _event("INFO", self.label,
                                           f"[{client_ip}] 插件Key已就绪 key={pk[0].hex()[:16]}...")
                                    self._plugin_key_wait_done.add(client_ip)
                                else:
                                    _timeout = 15
                                    try:
                                        _timeout = int(app_config.get("plugin_key_wait_timeout") or 15)
                                    except (TypeError, ValueError):
                                        pass
                                    _event("INFO", self.label,
                                           f"[{client_ip}] 10_02已到但无法取Key，等待插件Key (最多{_timeout}s)...")
                                    for _pw_i in range(_timeout * 2):
                                        await asyncio.sleep(0.5)
                                        pk = plugin_key_store.get(client_ip)
                                        if pk:
                                            self._3366_aes[client_ip] = pk
                                            _event("INFO", self.label,
                                                   f"[{client_ip}] 插件Key已接收 ({(_pw_i+1)*0.5:.1f}s) "
                                                   f"key={pk[0].hex()[:16]}...")
                                            break
                                    else:
                                        _event("WARN", self.label,
                                               f"[{client_ip}] 等待插件Key超时({_timeout}s)，透传")
                                    self._plugin_key_wait_done.add(client_ip)

                    ko = app_config.get("3366_key_offset")
                    io = app_config.get("3366_iv_offset")
                    k_off = ko if isinstance(ko, int) else None
                    iv_off = io if isinstance(io, int) else None
                    reg = merge_3366_product_registry(
                        app_config.get("3366_products")
                    )
                    need_downlink_key_extract = registry_needs_downlink_key_extraction(
                        reg
                    )

                    def _on3366(fr: bytes, info: dict | None, sst: Conn3366State):
                        # 端口不固定时也用协议帧确认连接类型，供手动3366阻断开关使用。
                        self._conn_carries_3366.add(conn_id)
                        # 三角洲：1002 到达时常早于 01 握手写入 0a92；若先判 0a92 会永远不推导 key。
                        # 暗区国服 10 02 内嵌 Key（payload[4:7]==10 02 10）走首包抽取，禁止走 DH。
                        if direction == "↓DOWN" and info and info.get("msg") == MSG_SERVER_KEY:
                            if not plugin_key_store.get(client_ip):
                                if not is_breakout_cn_1002_embedded_aes_key(fr):
                                    _k = try_derive_aes_key_from_1002(fr)
                                    if _k:
                                        plugin_key_store.set_key(
                                            client_ip,
                                            _k.hex(),
                                            game="0a92",
                                            uid=str(self._ip_game_uid.get(client_ip, "")) if self._ip_game_uid.get(client_ip) else "",
                                        )
                                        _pk = plugin_key_store.get(client_ip)
                                        if _pk:
                                            self._3366_aes[client_ip] = _pk
                                        _event("INFO", self.label,
                                               f"[{client_ip}] 三角洲1002已推导Key key={_k.hex()[:16]}...")

                        if direction == "↑UP":
                            # 10 01 总长：75=暗区国服通道；206=三角洲启发式（二者不同，勿混用）
                            if info and info.get("msg") == MSG_HANDSHAKE:
                                if len(fr) == HS_LEN_AB_BREAKOUT_CN_1001:
                                    plugin_key_store.clear_game_hint(client_ip)
                                    self._3366_ab_cn_first_hs.add(client_ip)
                                elif (
                                    LEGACY_GAME_RUNTIME_ENABLED
                                    and len(fr) == HS_LEN_DZ_HEURISTIC_1001
                                    and client_ip not in self._3366_ab_cn_first_hs
                                ):
                                    plugin_key_store.set_game_hint(client_ip, "0a92")
                            _hs_uid_any = extract_handshake_user_id(fr)
                            if _hs_uid_any:
                                self._3366_hs_uid[conn_id] = _hs_uid_any
                                self._remember_conn_game_id(
                                    username, conn_id, client_ip, _hs_uid_any)
                                # 只要拿到了 uid 就通知前端表格更新（无论之后是否匹配重放池）
                                log_bus.conn_game_id_update.emit(client_ip, str(_hs_uid_any), mode if mode == "record" else "重放")
                            _hs_uid_check = _hs_uid_any
                            _dl_reset_active = (
                                app_config.get("dz_dl_intercept_enabled")
                                or bool(app_config.get("pb_cmd_blacklist"))
                                or (
                                    LEGACY_GAME_RUNTIME_ENABLED
                                    and (
                                        app_config.get("az_dl_intercept_enabled")
                                        or app_config.get("hok_dl_intercept_enabled")
                                    )
                                )
                            )
                            if _hs_uid_check and _dl_reset_active:
                                # 新 10_01 登录帧 → 重置下发拦截"已完成"标志，使下次重新拦截
                                from core.dl_intercept import reset_dl_intercept_done
                                reset_dl_intercept_done(self._dl_intercept_bufs, conn_id)
                                
                                if mode == "replay":
                                    _proxy_user = username or ""
                                    if _hs_uid_check and _proxy_user and str(_hs_uid_check) != _proxy_user:
                                        _conn_label = f"{_hs_uid_check}({_proxy_user})"
                                    else:
                                        _conn_label = str(_hs_uid_check) or _proxy_user or client_ip
                                    log_bus.dl_intercept_event.emit(_conn_label, "reset", "重放账号上线，重置统计")
                        if mode == "record" and direction == "↑UP":
                            # 阈值已触发（01满）：持续断开所有新建33连接，无论uid是否在重放
                            if client_ip in self._auto_disconnect_blocked:
                                if conn_id not in self._record_blocked_conns:
                                    self._record_blocked_conns.add(conn_id)
                                    _event("INFO", self.label,
                                           f"[{client_ip}] 33通道 01已达阈值，断开重连")
                                    _w33 = self._conn_client_writers.get(conn_id)
                                    if _w33:
                                        try:
                                            _w33.close()
                                        except Exception:
                                            pass
                                return
                            _hs_uid = extract_handshake_user_id(fr)
                            if _hs_uid:
                                if recording_pool.is_game_id_being_replayed(_hs_uid):
                                    # uid 正在被重放，断开此条 33 连接，阻止继续录制
                                    self._record_blocked_conns.add(conn_id)
                                    _event("INFO", self.label,
                                           f"[{client_ip}] 33通道 uid=[{_hs_uid}] 正在重放，断开连接")
                                    _w33 = self._conn_client_writers.get(conn_id)
                                    if _w33:
                                        try:
                                            _w33.close()
                                        except Exception:
                                            pass
                                else:
                                    recording_pool.apply_3366_handshake_user_id(
                                        client_ip, _hs_uid
                                    )
                        # 重放：33 10 01 握手帧含游戏用户 ID，优先于 01 0A 00 23 触发匹配
                        if mode == "replay" and direction == "↑UP":
                            _hs_uid = extract_handshake_user_id(fr)
                            if _hs_uid and not self._replay_gid_checked.get(conn_id, True):
                                all_pools = self._replay_all_pools.get(conn_id, {})
                                # 3366握手必须保持账号级匹配；同设备跨账号候选
                                # 只含01素材，放到这里会得到空33池。
                                matched = recording_pool.find_tiered_01_pool(
                                    str(_hs_uid),
                                    client_version=app_config.get(
                                        "dfm_client_version", "auto"
                                    ),
                                    include_official=False,
                                )
                                if not matched:
                                    matched = all_pools.get(_hs_uid)
                                # 同IP池未命中 → 跨IP按游戏账号查找
                                if not matched and _hs_uid:
                                    matched = recording_pool.find_pool_by_game_id(str(_hs_uid))
                                    if matched:
                                        _event("REPLAY", self.label,
                                               f"[{username}({client_ip})] 跨IP匹配成功(33握手)："
                                               f"游戏账号={_hs_uid} 来自其他录制IP")
                                if matched:
                                    if matched.get("tiered"):
                                        try:
                                            traffic_file_logger.log_01_replay_template_selection(
                                                username=username,
                                                client_ip=client_ip,
                                                conn_id=conn_id,
                                                live_game_id=str(_hs_uid),
                                                selected=matched,
                                            )
                                        except Exception:
                                            pass
                                    pool_01 = matched.get("pool_01", [])
                                    pool_33 = matched.get("pool_33", [])
                                    self._replay_pools[conn_id] = matched
                                    self._replay_index[conn_id] = [0, 0]
                                    self._replay_index_33[conn_id] = {
                                        "09": [0, 0], "21": [0, 0], "01_fb": [0, 0]
                                    }
                                    self._replay_gid_checked[conn_id] = True
                                    log_bus.conn_game_id_update.emit(client_ip, str(_hs_uid), "重放")
                                    n01, n33 = len(pool_01), len(pool_33)
                                    log_bus.replay_progress.emit(client_ip, 0, n01 + n33)
                                    n09 = len([it for it in pool_33 if "09" in str(it.get("source", ""))])
                                    n21 = len([it for it in pool_33 if "21" in str(it.get("source", ""))])
                                    log_bus.replay_progress_detail.emit(
                                        client_ip, 0, n01, 0, n33, 0, n09, 0, n21, 0,
                                    )
                                    log_bus.conn_detail.emit(
                                        client_ip,
                                        f"[重放就绪] 游戏ID=[{_hs_uid}] 33握手触发  01池={n01} 33池={n33}"
                                        + (
                                            f"  跨账号donor=[{matched.get('donor_game_id')}]"
                                            if matched.get("cross_account") else ""
                                        ),
                                    )
                                    log_bus.conn_mode_update.emit(client_ip, "重放")
                                else:
                                    # 33通道无匹配录制：3366 透传，01 走空模板删叶/改写
                                    gid_str = f"[{_hs_uid}]"
                                    _event(
                                        "WARN",
                                        self.label,
                                        f"[{username}] 33通道无匹配录制 游戏ID={gid_str}，"
                                        f"跳过叶子替换，保留删叶/改写",
                                    )
                                    self._replay_bind_empty_pool(
                                        conn_id,
                                        client_ip,
                                        str(_hs_uid or ""),
                                        f"[无匹配录制] 33握手 UID={gid_str}，不替换叶子",
                                    )
                                    self._replay_gid_checked[conn_id] = True
                        msg_h = info.get("msg_hex", "??") if info else "??"
                        seq_v = info.get("seq") if info else None
                        prod = sst.product_name or ""
                        prod_bracket = f" product={prod}" if prod else ""
                        prev = format_3366_log_preview(fr)
                        line = f"[3366 msg={msg_h} seq={seq_v}]{prod_bracket} {prev}"
                        # 重放上行且会执行 replace 时，由 on_frame_hex 发射 stream_parsed_data，避免 process_3366_chunk 流缓冲导致面板慢一步
                        will_replace = (
                            mode == "replay" and direction == "↑UP"
                            and self._3366_aes.get(client_ip)
                            and self._replay_pools.get(conn_id)
                            and self._replay_index_33.get(conn_id)
                        )
                        if not will_replace:
                            log_bus.stream_parsed_data.emit(conn_id, direction, "3366", len(fr), fr)

                        if sst.product_hex:
                            self._3366_prod_hex[client_ip] = sst.product_hex
                        pid = self._3366_prod_hex.get(client_ip)
                        meta = reg.get(pid) if pid else None
                        strat = (meta or {}).get("decrypt") if meta else None
                        if pid:
                            _pn = ((meta or {}).get("name") or prod or "").strip()
                            recording_pool.set_session_3366_product(
                                client_ip, pid, _pn
                            )

                        down_st = self._st3366_down.get(conn_id)
                        use_sess_kv = product_uses_downlink_session_key(meta, strat)
                        if (
                            strat == "aes_cbc_4013"
                            and use_sess_kv
                            and down_st
                            and down_st.key
                            and down_st.iv
                        ):
                            self._3366_aes[client_ip] = (down_st.key, down_st.iv)
                            recording_pool.set_session_3366_key_ready(client_ip)
                        elif (
                            not pid
                            and down_st
                            and down_st.key
                            and down_st.iv
                            and need_downlink_key_extract
                            and ACE_SHORT_PRODUCT_TO_3366_PRODUCT.get(
                                (plugin_key_store.get_game_hint(client_ip) or "").strip().lower()
                            )
                        ):
                            hint = (plugin_key_store.get_game_hint(client_ip) or "").strip().lower()
                            hint_pid = ACE_SHORT_PRODUCT_TO_3366_PRODUCT.get(hint)
                            hint_meta = reg.get(hint_pid) if hint_pid else None
                            hint_strat = (hint_meta or {}).get("decrypt") if hint_meta else None
                            if (
                                hint_pid
                                and hint_meta
                                and hint_strat == "aes_cbc_4013"
                                and product_uses_downlink_session_key(hint_meta, hint_strat)
                            ):
                                self._3366_prod_hex[client_ip] = hint_pid
                                self._3366_aes[client_ip] = (down_st.key, down_st.iv)
                                pid = hint_pid
                                meta = hint_meta
                                strat = hint_strat
                                recording_pool.set_session_3366_product(
                                    client_ip,
                                    hint_pid,
                                    hint_meta.get("name") or hint_pid,
                                )
                                recording_pool.set_session_3366_key_ready(client_ip)
                        elif (
                            not pid
                            and down_st
                            and down_st.key
                            and down_st.iv
                            and need_downlink_key_extract
                        ):
                            single = [
                                (k, v)
                                for k, v in reg.items()
                                if product_uses_downlink_session_key(
                                    v, v.get("decrypt")
                                )
                            ]
                            if len(single) == 1:
                                _pid, _meta = single[0]
                                _strat = _meta.get("decrypt")
                                if _strat == "aes_cbc_4013":
                                    self._3366_prod_hex[client_ip] = _pid
                                    self._3366_aes[client_ip] = (
                                        down_st.key,
                                        down_st.iv,
                                    )
                                    pid = _pid
                                    meta = _meta
                                    strat = _strat
                                    recording_pool.set_session_3366_product(
                                        client_ip,
                                        _pid,
                                        _meta.get("name") or _pid,
                                    )
                                    recording_pool.set_session_3366_key_ready(client_ip)
                        kv = self._3366_aes.get(client_ip)

                        # ── 插件 Key 处理（必须在 kv 赋值后立即执行）──────────────
                        # 三角洲等插件游戏与暗区共用 ACE 产品 ID，down_st 提取的 key
                        # 是暗区握手 key，对插件游戏完全错误。因此插件游戏必须在此处
                        # 强制覆盖 kv，而非走"if not kv"兜底逻辑。
                        _ab33 = client_ip in self._3366_ab_cn_first_hs
                        _plugin_game_id = _plugin_game_id_from_store(
                            client_ip, ab_cn_33_first_seen=_ab33
                        )
                        if _plugin_game_id:
                            # 强制用插件注入的 Key 覆盖（即使 down_st 已设置了错误 key）
                            _pk = plugin_key_store.get(client_ip)
                            if _pk:
                                self._3366_aes[client_ip] = _pk
                                kv = _pk
                            # 强制覆盖策略和 meta（不受 3366_products 暗区配置干扰）
                            _pg_profiles = app_config.get("plugin_games") or {}
                            _pg_profile = _pg_profiles.get(_plugin_game_id, {})
                            strat = _pg_profile.get("decrypt") or strat or "aes_cbc_4013"
                            meta = _pg_profile
                            use_sess_kv = True
                        elif not kv:
                            # 非插件游戏兜底：查插件 Key 存储
                            _pk = plugin_key_store.get(client_ip)
                            if _pk:
                                self._3366_aes[client_ip] = _pk
                                kv = _pk
                        # ── 首次识别到插件游戏时推送游戏名到连接表 UI ──
                        if _plugin_game_id and client_ip not in self._plugin_game_notified:
                            self._plugin_game_notified.add(client_ip)
                            _pg_all = app_config.get("plugin_games") or {}
                            _pg_name = (_pg_all.get(_plugin_game_id) or {}).get("name", _plugin_game_id)
                            try:
                                log_bus.conn_3366_product.emit(client_ip, _plugin_game_id, _pg_name)
                            except Exception:
                                pass

                        plain = None
                        if info and info.get("msg") == MSG_DATA:
                            if strat == "aes_cbc_4013":
                                if use_sess_kv and kv:
                                    plain = decrypt_plain_for_strategy(
                                        strat, fr, kv[0], kv[1]
                                    )
                            elif strat:
                                k0 = kv[0] if (kv and use_sess_kv) else None
                                k1 = kv[1] if (kv and use_sess_kv) else None
                                plain = decrypt_plain_for_strategy(
                                    strat, fr, k0, k1
                                )

                        try:
                            _conn_uid = self._3366_hs_uid.get(conn_id, "")
                            # 所有 3366 帧均记录（替换前），plain=None 时也记录密文，等同于 01_sliced.log 对 01 帧的处理
                            _plain_for_log = plain if (plain and info and info.get("msg") == MSG_DATA) else None
                            if direction == "↑UP":
                                traffic_file_logger.log_33_uplink(
                                    conn_id=conn_id,
                                    client_ip=client_ip,
                                    uid=_conn_uid,
                                    mode=mode,
                                    cipher_bytes=fr,
                                    plain_bytes=_plain_for_log,
                                    username=username,
                                )
                            elif direction == "↓DOWN":
                                traffic_file_logger.log_33_downlink(
                                    conn_id=conn_id,
                                    client_ip=client_ip,
                                    cipher_bytes=fr,
                                    plain_bytes=_plain_for_log,
                                    username=username,
                                    uid=_conn_uid,
                                    mode=mode,
                                )
                        except Exception:
                            pass

                        # ── 3366 dump（插件 Key 游戏研究用）──
                        if _plugin_game_id:
                            _pg_profiles_dump = app_config.get("plugin_games") or {}
                            _pg_dump_cfg = _pg_profiles_dump.get(_plugin_game_id, {})
                            if _pg_dump_cfg.get("dump_3366", False):
                                dump_3366_frame(
                                    _plugin_game_id, client_ip, direction,
                                    fr, info, plain=plain,
                                )

                        if mode == "record" and info and info.get("msg") == MSG_DATA:
                            # skip_33 全局开关：跳过所有 3366 录制（调试：仅录 01 通道）
                            if app_config.get("skip_33", False):
                                pass
                            # 插件 Key 游戏：3366 数据不入录制池（因插件存在导致数据"脏"）
                            elif _plugin_game_id:
                                _pg_profiles_rec = app_config.get("plugin_games") or {}
                                _pg_rec = _pg_profiles_rec.get(_plugin_game_id, {})
                                if not _pg_rec.get("record_3366", False):
                                    pass  # 跳过 3366 录制，仅录 01 通道
                                elif plain:
                                    items = extract_pool_items_from_3366_plaintext(plain)
                                    if items:
                                        recording_pool.append_from_3366_plain(
                                            client_ip, plain, items,
                                            conn_uid=self._3366_hs_uid.get(conn_id, ""),
                                        )
                                        self._conn_carries_3366.add(conn_id)
                            elif plain:
                                items = extract_pool_items_from_3366_plaintext(plain)
                                if items:
                                    recording_pool.append_from_3366_plain(
                                        client_ip, plain, items,
                                        conn_uid=self._3366_hs_uid.get(conn_id, ""),
                                    )
                                    self._conn_carries_3366.add(conn_id)
                                elif conn_id not in getattr(
                                    self, "_3366_no_items_logged", set()
                                ):
                                    self._3366_no_items_logged = getattr(
                                        self, "_3366_no_items_logged", set()
                                    ) | {conn_id}
                                    try:
                                        traffic_file_logger.log_3366_record_reason(
                                            client_ip=client_ip,
                                            conn_id=conn_id,
                                            reason="明文无01_0A_00_09/21",
                                            detail=f"plain_len={len(plain)}",
                                            username=username,
                                            uid=self._3366_hs_uid.get(conn_id, ""),
                                        )
                                    except Exception:
                                        pass
                            elif not kv and conn_id not in getattr(
                                self, "_3366_no_kv_logged", set()
                            ):
                                self._3366_no_kv_logged = getattr(
                                    self, "_3366_no_kv_logged", set()
                                ) | {conn_id}
                                try:
                                    traffic_file_logger.log_3366_record_reason(
                                        client_ip=client_ip,
                                        conn_id=conn_id,
                                        reason="Key/IV未就绪",
                                        detail="等待首下行10_02取Key",
                                        username=username,
                                        uid=self._3366_hs_uid.get(conn_id, ""),
                                    )
                                except Exception:
                                    pass
                            elif (
                                kv
                                and not plain
                                and conn_id not in getattr(
                                    self, "_3366_decrypt_fail_logged", set()
                                )
                            ):
                                self._3366_decrypt_fail_logged = getattr(
                                    self, "_3366_decrypt_fail_logged", set()
                                ) | {conn_id}
                                try:
                                    traffic_file_logger.log_3366_record_reason(
                                        client_ip=client_ip,
                                        conn_id=conn_id,
                                        reason="40_13解密失败",
                                        detail="请调整3366_key_offset/3366_iv_offset",
                                        username=username,
                                        uid=self._3366_hs_uid.get(conn_id, ""),
                                    )
                                except Exception:
                                    pass
                            elif strat == "aes_cbc_4013" and use_sess_kv and not kv:
                                pass
                            elif (
                                strat
                                and strat != "aes_cbc_4013"
                                and conn_id not in self._3366_unknown_strat_logged
                            ):
                                self._3366_unknown_strat_logged.add(conn_id)
                                _event(
                                    "WARN",
                                    self.label,
                                    f"[{client_ip}] 3366 产品={pid} 的 decrypt=\"{strat}\" "
                                    f"尚未实现或非下行 Key 流程，跳过 40 13（扩展 decrypt_plain_for_strategy）",
                                )
                            elif (
                                not strat
                                and pid
                                and conn_id not in self._3366_decrypt_skip_logged
                            ):
                                self._3366_decrypt_skip_logged.add(conn_id)
                                _event(
                                    "INFO",
                                    self.label,
                                    f"[{client_ip}] 3366 产品 ID={pid} 未配置 decrypt 策略，"
                                    f"跳过 40 13 解密入池（请在 config.json 的 3366_products 中配置）",
                                )

                        if app_config.get("record_raw_3366_frames") and mode == "record":
                            self._conn_carries_3366.add(conn_id)
                            recording_pool.append_3366(
                                client_ip,
                                direction,
                                fr,
                                product_label=prod if prod else None,
                            )
                        if (prod or _plugin_game_id) and conn_id not in self._3366_prod_logged:
                            self._3366_prod_logged.add(conn_id)
                            st_txt = strat if strat else "仅识别"
                            if _plugin_game_id:
                                _pg_all2 = app_config.get("plugin_games") or {}
                                _pg_name2 = (_pg_all2.get(_plugin_game_id) or {}).get("name", _plugin_game_id)
                                _ace_note = f"  ACE产品={pid}" if pid else ""
                                _event(
                                    "RECORD" if mode == "record" else "INFO",
                                    self.label,
                                    f"[{client_ip}] 3366 插件游戏: {_pg_name2} ({_plugin_game_id})  解密={st_txt}{_ace_note}",
                                )
                            else:
                                _event(
                                    "RECORD" if mode == "record" else "INFO",
                                    self.label,
                                    f"[{client_ip}] 3366 产品: {prod}  (ID={pid})  解密={st_txt}",
                                )
                        if (
                            direction == "↓DOWN"
                            and conn_id not in self._3366_key_logged
                            and down_st
                            and down_st.key
                            and down_st.iv
                            and strat == "aes_cbc_4013"
                            and product_uses_downlink_session_key(meta, strat)
                        ):
                            self._3366_key_logged.add(conn_id)
                            _event(
                                "INFO",
                                self.label,
                                f"[{client_ip}] 3366 首下行已取候选 Key/IV（游戏 {pid or '?'} / aes_cbc_4013；"
                                f"若解密失败请调整 3366_key_offset / 3366_iv_offset） "
                                f"key={down_st.key.hex()} iv={down_st.iv.hex()}",
                            )
                            try:
                                traffic_file_logger.log_3366_record_reason(
                                    client_ip=client_ip,
                                    conn_id=conn_id,
                                    reason="Key已取",
                                    detail="等待40_13帧解密入池",
                                    username=username,
                                    uid=self._3366_hs_uid.get(conn_id, ""),
                                )
                            except Exception:
                                pass

                    process_3366_chunk(
                        st3366,
                        data,
                        is_downlink=(direction == "↓DOWN"),
                        on_frame=_on3366,
                        key_off=k_off,
                        iv_off=iv_off,
                        product_registry=reg,
                        extract_downlink_key=need_downlink_key_extract,
                    )

                    # 连接建立后才识别出3366的情况：当前块不再转发，并关闭连接。
                    if (
                        self.should_block_detected_3366(client_ip)
                        and self.is_manual_3366_connection(conn_id)
                    ):
                        if conn_id not in self._manual_3366_drop_logged:
                            self._manual_3366_drop_logged.add(conn_id)
                            _event(
                                "BLOCK",
                                self.label,
                                f"[{client_ip}] 已识别3366协议并断开 {dst_str or conn_id}；"
                                "01通道继续",
                            )
                            log_bus.conn_detail.emit(
                                client_ip,
                                f"[3366阻断] 已识别协议并断开 {dst_str or conn_id}",
                            )
                        _safe_close(writer)
                        client_writer = self._conn_client_writers.get(conn_id)
                        if client_writer is not writer:
                            _safe_close(client_writer)
                        return

                    # skip_33=True（全局开关）时完全跳过 33 重放，直接透传
                    if app_config.get("skip_33", False) and mode == "replay":
                        pass  # 33 重放/替换已全局禁用
                    elif mode == "replay" and direction == "↑UP":
                        # 暗区突围国服：33 只关心 40_13 内 01_0A_00_09 池替换，不走三角洲 PB_ACE
                        _prod_hex = (self._3366_prod_hex.get(client_ip) or "").upper()
                        _is_hok_3366 = bool(
                            LEGACY_GAME_RUNTIME_ENABLED and _prod_hex == "00000A11"
                        )
                        _is_az_breakout_3366 = bool(
                            LEGACY_GAME_RUNTIME_ENABLED
                            and _prod_hex in ("0000094E", "00000A11")
                        )
                        kv = self._3366_aes.get(client_ip)
                        pools = self._replay_pools.get(conn_id)
                        ri33 = self._replay_index_33.get(conn_id)
                        # 3366 握手池未匹配（extract_handshake_user_id 失败或未找到）
                        # 尝试用同 IP 已知游戏 UID 懒加载匹配（由 01 路径写入 _ip_game_uid）
                        if kv and not pools:
                            _lazy_gid = (self._3366_hs_uid.get(conn_id)
                                         or self._conn_live_gid.get(conn_id)
                                         or self._ip_game_uid.get(client_ip))
                            if _lazy_gid:
                                # 3366延迟匹配同样只使用账号级池。
                                _lazy_pool = recording_pool.find_tiered_01_pool(
                                    str(_lazy_gid),
                                    client_version=app_config.get(
                                        "dfm_client_version", "auto"
                                    ),
                                    include_official=False,
                                )
                                if not _lazy_pool:
                                    _lazy_pool = recording_pool.find_pool_by_game_id(str(_lazy_gid))
                                if _lazy_pool:
                                    if _lazy_pool.get("tiered"):
                                        try:
                                            traffic_file_logger.log_01_replay_template_selection(
                                                username=username,
                                                client_ip=client_ip,
                                                conn_id=conn_id,
                                                live_game_id=str(_lazy_gid),
                                                selected=_lazy_pool,
                                            )
                                        except Exception:
                                            pass
                                    self._replay_pools[conn_id] = _lazy_pool
                                    self._replay_index_33[conn_id] = {
                                        "09": [0, 0], "21": [0, 0], "01_fb": [0, 0]
                                    }
                                    pools = _lazy_pool
                                    ri33 = self._replay_index_33[conn_id]
                                    _lazy_n01 = len(_lazy_pool.get("pool_01", []))
                                    _lazy_n33 = len(_lazy_pool.get("pool_33", []))
                                    log_bus.conn_detail.emit(
                                        client_ip,
                                        f"[重放就绪(延迟)] 游戏ID=[{_lazy_gid}]"
                                        f"  01池={_lazy_n01} 33池={_lazy_n33}",
                                    )
                        if kv and pools and ri33:
                            pool_33 = pools.get("pool_33", [])
                            pool_01 = pools.get("pool_01", [])
                            try:
                                lt = int(app_config.get("replay_length_match_tol", 300))
                            except (TypeError, ValueError):
                                lt = 300
                            def _on_33_replace(fr: bytes, nf: bytes, oc: bytes, op: bytes, np: bytes, nc: bytes, seq_val: int | None = None):
                                try:
                                    _uid_33 = self._3366_hs_uid.get(conn_id, "") or self._conn_live_gid.get(conn_id, "")
                                    traffic_file_logger.log_33_replace(
                                        conn_id=conn_id,
                                        client_ip=client_ip,
                                        uid=_uid_33,
                                        orig_frame=fr,
                                        new_frame=nf,
                                        orig_cipher=oc,
                                        orig_plain=op,
                                        new_plain=np,
                                        new_cipher=nc,
                                        seq=seq_val,
                                        username=username,
                                    )
                                except Exception:
                                    pass
                            def _on_skip(reason: str, frame: bytes, plain: bytes | None):
                                try:
                                    if reason.startswith("[UL清除]") or reason.startswith("[UL截断]"):
                                        # 上行处理日志 → 账户级弹窗
                                        _uid_sk = (self._3366_hs_uid.get(conn_id, "")
                                                   or self._conn_live_gid.get(conn_id, ""))
                                        _label_sk = (f"{_uid_sk}({username})"
                                                     if username else _uid_sk) or client_ip
                                        log_bus.dl_intercept_event.emit(
                                            _label_sk, "ul_log", reason)
                                        # ✅/❌ 结果同步到 conn_detail，让 seq 不消失
                                        if " ✅ " in reason or " ❌ " in reason:
                                            log_bus.conn_detail.emit(client_ip, f"[33] {reason}")
                                    elif reason.startswith("[PB_BL]"):
                                        # 上行 Protobuf 命令黑名单：进拦截管理「上行日志」+ 统计，不进重放详情
                                        _uid_pb = (self._3366_hs_uid.get(conn_id, "")
                                                   or self._conn_live_gid.get(conn_id, ""))
                                        _label_pb = (f"{_uid_pb}({username})"
                                                     if username else _uid_pb) or client_ip
                                        log_bus.dl_intercept_event.emit(
                                            _label_pb, "ul_log", reason)
                                    elif reason.startswith("[PB_ACE] 已替换"):
                                        # ACE 成功 reason 含「已替换」，不可再套「未替换:」前缀（池路径字面「已替换」仍不发此行避免重复）
                                        info = parse_3366_header(frame)
                                        seq_val = info.get("seq") if info else None
                                        seq_str = f"seq={seq_val}" if seq_val is not None else "seq=?"
                                        log_bus.conn_detail.emit(
                                            client_ip,
                                            f"[33] {seq_str} 帧{len(frame)}B  {reason}",
                                        )
                                    elif reason != "已替换":
                                        if _is_az_breakout_3366 and reason.startswith(
                                            "非40_13帧"
                                        ):
                                            pass
                                        else:
                                            info = parse_3366_header(frame)
                                            seq_val = info.get("seq") if info else None
                                            seq_str = f"seq={seq_val}" if seq_val is not None else "seq=?"
                                            log_bus.conn_detail.emit(
                                                client_ip,
                                                f"[33] {seq_str} 帧{len(frame)}B  未替换: {reason}",
                                            )
                                except Exception:
                                    pass
                            def _on_33_detail(block: str, src: str, pool_idx: int, count: int,
                                              frame_len: int, orig_high: int, new_len: int, seq_val: int | None):
                                seq_str = f" seq={seq_val}" if seq_val is not None else ""
                                log_bus.conn_detail.emit(
                                    client_ip,
                                    f"[33] {block} 用{src}第{pool_idx}个  累计{count}次{seq_str}  "
                                    f"帧{frame_len}B 高熵{orig_high}B→{new_len}B",
                                )
                            on_33 = lambda: _emit_progress_detail(conn_id, client_ip)
                            def _on_frame_hex(fr: bytes):
                                log_bus.stream_parsed_data.emit(conn_id, direction, "3366", len(fr), fr)

                            # 上行黑名单字符串 + 脏数据清除开关
                            _ul_dirty_enabled = bool(app_config.get("ul_dirty_clean_enabled"))
                            _bl_raw: list = app_config.get("ul_blacklist_strings") or []
                            _dirty_strs: list[bytes] = [
                                item["str"].encode()
                                for item in _bl_raw
                                if isinstance(item, dict) and item.get("str")
                            ] or None  # type: ignore[assignment]

                            def _on_ul_dirty_clean(
                                orig_frame: bytes, clean_plain: bytes, hit_strings: list[str]
                            ):
                                try:
                                    _uid_dc = (self._3366_hs_uid.get(conn_id, "")
                                               or self._conn_live_gid.get(conn_id, ""))
                                    _label_dc = (f"{_uid_dc}({username})"
                                                 if username else _uid_dc) or client_ip
                                    # 每帧只计 1 次上行命中，message 含所有命中字符串（去重，逗号分隔）
                                    _unique = list(dict.fromkeys(hit_strings or ["unknown"]))
                                    log_bus.dl_intercept_event.emit(
                                        _label_dc, "ul_hit", ",".join(_unique))
                                except Exception:
                                    pass

                            _ul_trunc_enabled = bool(app_config.get("ul_truncate_abab_enabled"))
                            _ul_trunc_min = int(app_config.get("ul_truncate_abab_min_len") or 500)

                            def _on_ul_truncate(orig_frame: bytes, trunc_plain: bytes):
                                try:
                                    _uid_tr = (self._3366_hs_uid.get(conn_id, "")
                                               or self._conn_live_gid.get(conn_id, ""))
                                    _label_tr = (f"{_uid_tr}({username})"
                                                 if username else _uid_tr) or client_ip
                                    log_bus.dl_intercept_event.emit(
                                        _label_tr, "ul_trunc",
                                        f"{len(orig_frame)}B→{len(trunc_plain)}B")
                                except Exception:
                                    pass

                            # 插件游戏：仅 plugin_games 内的 ID（如 0a92）走 PB；33 先到 75B 时强制暗区
                            _replay_pgid = _plugin_game_id_from_store(
                                client_ip,
                                ab_cn_33_first_seen=(
                                    client_ip in self._3366_ab_cn_first_hs
                                ),
                            )
                            if _is_az_breakout_3366:
                                _replay_pgid = ""
                            _pb_ace_enabled = bool(_replay_pgid)
                            _pb_cmd_bl: list[str] = []
                            if _replay_pgid and app_config.get("dz_cmd_bl_enabled", True):
                                _pb_cmd_bl = [
                                    e["cmd"] for e in (app_config.get("pb_cmd_blacklist") or [])
                                    if isinstance(e, dict) and e.get("cmd")
                                ]
                            _pool_replace_enabled = (
                                not _is_hok_3366
                                or bool(app_config.get("hok_33_replay_replace_enabled"))
                            )
                            _pool_33_for_replace = pool_33 if _pool_replace_enabled else []
                            _pool_01_for_replace = pool_01 if _pool_replace_enabled else []

                            data = replace_3366_40_13_frames_in_buffer(
                                bytearray(data), kv, _pool_33_for_replace, _pool_01_for_replace,
                                ri33["09"], ri33["21"], ri33["01_fb"],
                                len_tol=lt,
                                on_replace_33=on_33,
                                on_replace_log=_on_33_replace,
                                on_skip_frame=_on_skip,
                                on_replace_33_detail=_on_33_detail,
                                on_frame_hex=_on_frame_hex,
                                drop_raw_high_entropy=bool(app_config.get("drop_3366_raw_high_entropy")),
                                ul_dirty_clean=_ul_dirty_enabled,
                                ul_dirty_strings=_dirty_strs,
                                on_ul_dirty_clean=_on_ul_dirty_clean,
                                ul_truncate_abab=_ul_trunc_enabled,
                                ul_truncate_min_len=_ul_trunc_min,
                                on_ul_truncate=_on_ul_truncate,
                                plugin_game_id=_replay_pgid,
                                pb_ace_replace_enabled=_pb_ace_enabled,
                                pb_cmd_blacklist=_pb_cmd_bl or None,
                            )
                        elif need_3366 and _find_valid_magic(data, 0) >= 0:
                            for fr, mh in iter_3366_frames_in_buffer(data):
                                try:
                                    plain_hex = None
                                    if mh != "4013":
                                        if _is_az_breakout_3366:
                                            continue
                                        reason = "非40_13帧，无需替换"
                                    elif not kv:
                                        reason = "未进入替换: Key未就绪（等待首下行10_02取Key）"
                                    elif not pools:
                                        reason = "未进入替换: 重放池未匹配（等待游戏账号识别）"
                                    elif not ri33:
                                        reason = "未进入替换: 33重放索引未初始化"
                                    else:
                                        base_reason = "未进入替换: 无匹配池或重放未激活"
                                        _pgid_fb = _plugin_game_id_from_store(
                                            client_ip,
                                            ab_cn_33_first_seen=(
                                                client_ip in self._3366_ab_cn_first_hs
                                            ),
                                        )
                                        if _is_az_breakout_3366:
                                            _pgid_fb = ""
                                        if _pgid_fb:
                                            plain = try_decrypt_4013_frame_raw(fr, kv[0], kv[1])
                                        else:
                                            plain = try_decrypt_4013_frame(fr, kv[0], kv[1])
                                        if plain:
                                            plain_hex = plain.hex().upper()
                                            reason = base_reason + "（明文已解密，可核对是否含01_0A_00_09/21）"
                                        else:
                                            reason = base_reason + "（解密失败，请检查Key/IV）"
                                    info_fb = parse_3366_header(fr)
                                    seq_fb = info_fb.get("seq") if info_fb else None
                                    seq_str_fb = f"seq={seq_fb}" if seq_fb is not None else "seq=?"
                                    log_bus.conn_detail.emit(
                                        client_ip,
                                        f"[33] {seq_str_fb} 帧{len(fr)}B  未替换: {reason}",
                                    )
                                    _plain_b = bytes.fromhex(plain_hex) if plain_hex else None
                                    _uid_fb = self._3366_hs_uid.get(conn_id, "") or self._conn_live_gid.get(conn_id, "")
                                    traffic_file_logger.log_33_uplink(
                                        conn_id=conn_id,
                                        client_ip=client_ip,
                                        uid=_uid_fb,
                                        mode="replay",
                                        cipher_bytes=fr,
                                        plain_bytes=_plain_b,
                                        username=username,
                                    )
                                except Exception:
                                    pass

                # 只有非 3366 且未被 01 流缓冲处理的剩余纯透传数据才在这里整体发射
                in_01_stream = (mode == "record" and f"{conn_id}_rec_{direction}" in self._stream_bufs) or (mode == "replay" and f"{conn_id}_rep_{direction}" in self._stream_bufs)
                
                # 如果这个数据包已经被当做 01 包发过了（即处于 01 流中或符合 01 包特征且处于 record/replay 模式），就不要再发透传了
                # 在录制模式下，其实 01 包并没有从 `data` 中切走，所以 `data` 原封不动。我们应该直接透传它，不要让它被拦截掉。
                is_01_handled = False
                if mode == "replay" and direction == "↑UP":
                    if len(data) >= 2 and data[0] == 0x01 and data[1] == 0x00:
                        is_01_handled = True
                        
                # 注意：如果之前有半截数据在流里面（in_01_stream），哪怕现在进来的包不是以 01 00 开头，它也属于 01 协议流的后续部分，已经被上方 emit 过了
                if data and not need_3366 and not in_01_stream and not is_01_handled:
                    log_bus.stream_parsed_data.emit(conn_id, direction, "透传", len(data), data)
                # 3366 原始含 01 0A 00 09 或 01 0A 00 23 时不发送，但会记录
                if (
                    data
                    and not dfm_3366_passthrough
                    and app_config.get("drop_3366_raw_high_entropy")
                    and _find_valid_magic(data, 0) >= 0
                ):
                    def _on_drop(frame: bytes, msg_hex: str):
                        _event("RECORD", self.label,
                               f"[{client_ip}] 3366 含01_0A_00_09/23 已丢包 msg={msg_hex} len={len(frame)}B")
                        try:
                            traffic_file_logger.log_3366_raw_high_entropy_drop(
                                conn_id=conn_id,
                                client_ip=client_ip,
                                direction=direction,
                                msg_hex=msg_hex,
                                frame_len=len(frame),
                                frame_full_hex=frame.hex().upper(),
                                username=username,
                            )
                        except Exception:
                            pass
                        log_bus.conn_detail.emit(
                            client_ip,
                            f"[3366丢包] msg={msg_hex} len={len(frame)}B 含01_0A_00_09/23",
                        )

                    data = filter_3366_frames_with_raw_high_entropy(
                        data, on_drop=_on_drop, never_drop_handshake=(mode == "replay")
                    )
                if (
                    data
                    and is_record_01_chunk
                    and self.should_hold_record_01(client_ip, direction)
                ):
                    self._log_01_hold_once(client_ip)
                    continue
                if data and dfm_3366_passthrough:
                    # 纯透传不向3366解析/发送面板发射数据，也不写持久日志。
                    writer.write(data)
                    await writer.drain()
                    continue
                if data:  # 可能 output 为空（所有包都不完整，等待下次 read）
                    _dl_pgid = _plugin_game_id_from_store(
                        client_ip,
                        ab_cn_33_first_seen=(
                            client_ip in self._3366_ab_cn_first_hs
                        ),
                    )
                    _dl_prod = (self._3366_prod_hex.get(client_ip) or "").upper()
                    _dl_hint = (plugin_key_store.get_game_hint(client_ip) or "").strip().lower()
                    _dl_hint_pid = ACE_SHORT_PRODUCT_TO_3366_PRODUCT.get(_dl_hint, "")
                    _dl_game_id = _dl_pgid or (
                        (
                            "hok"
                            if (_dl_prod == "00000A11" or _dl_hint_pid == "00000A11")
                            else "az"
                        )
                        if LEGACY_GAME_RUNTIME_ENABLED else "0a92"
                    )
                    # 字符串替换：三角洲等 plugin_games 走 dz_*；王者荣耀走 hok_*；暗区走 az_*。
                    _is_dz = bool(_dl_pgid)
                    if _is_dz:
                        _dl_str_enabled = app_config.get("dz_dl_intercept_enabled")
                    elif LEGACY_GAME_RUNTIME_ENABLED and _dl_game_id == "hok":
                        _dl_str_enabled = app_config.get("hok_dl_intercept_enabled")
                    elif LEGACY_GAME_RUNTIME_ENABLED:
                        _dl_str_enabled = app_config.get("az_dl_intercept_enabled")
                    else:
                        _dl_str_enabled = False
                    _dl_search = (app_config.get("dl_search_str", "") or "") if _dl_str_enabled else ""
                    _dl_replace = (app_config.get("dl_replace_str", "") or "") if _dl_str_enabled else ""
                    # 命令黑名单：三角洲专用，始终生效
                    _dl_pb_bl: list[str] = []
                    if _dl_pgid and app_config.get("dz_cmd_bl_enabled", True):
                        _dl_pb_bl = [
                            e["cmd"] for e in (app_config.get("pb_cmd_blacklist") or [])
                            if isinstance(e, dict) and e.get("cmd")
                        ]
                    _dl_active = bool(_dl_search) or bool(_dl_pb_bl)
                    if _dl_active and direction == "↓DOWN" and mode == "replay":
                        from core.dl_intercept import process_dl_intercept_3366
                        kv_intercept = self._3366_aes.get(client_ip)
                        _game_uid = (self._3366_hs_uid.get(conn_id)
                                     or self._conn_live_gid.get(conn_id)
                                     or self._ip_game_uid.get(client_ip, ""))
                        # 如果本地还没拿到 UID，尝试从插件 Key 信息里取（插件可选携带 uid 参数）
                        if not _game_uid:
                            _pk_info = plugin_key_store.get_info(client_ip)
                            _game_uid = (_pk_info or {}).get("uid", "") or ""
                        _proxy_user = username or ""
                        if _game_uid and _proxy_user and _game_uid != _proxy_user:
                            conn_label = f"{_game_uid}({_proxy_user})"
                        else:
                            conn_label = _game_uid or _proxy_user or client_ip
                        out_data = process_dl_intercept_3366(
                            conn_id=conn_id,
                            client_ip=client_ip,
                            buf_dict=self._dl_intercept_bufs,
                            data=data,
                            kv=kv_intercept,
                            search_str=_dl_search,
                            replace_str=_dl_replace,
                            conn_label=conn_label,
                            plugin_game_id=_dl_pgid,
                            intercept_game_id=_dl_game_id,
                            pb_dl_cmd_blacklist=_dl_pb_bl or None,
                        )
                        if out_data:
                            log_bus.stream_sent_data.emit(conn_id, direction, len(out_data), out_data)
                            writer.write(out_data)
                            await writer.drain()
                        # else: 帧不完整，暂留缓冲区等下次 read
                    else:
                        log_bus.stream_sent_data.emit(conn_id, direction, len(data), data)
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


async def _local_map_serve(client_reader, client_writer, filepath: str, host: str,
                           username: str = "", expire: str = "", port: str = ""):
    """
    本地重放：读取本地文件，以 HTTP/1.1 200 OK 回应客户端，
    不访问真实服务器（仅拦截 HTTP:80 请求）。
    HTML 文件中的 {{USERNAME}} / {{EXPIRE}} 占位符会被替换为实际用户信息。
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

        # HTML 模板变量替换：{{USERNAME}} / {{EXPIRE}} / {{PORT}}
        ext_check = os.path.splitext(filepath)[1].lower()
        if ext_check in (".html", ".htm") and (username or expire or port):
            try:
                text = body.decode("utf-8")
                text = text.replace("{{USERNAME}}", username or "-")
                text = text.replace("{{EXPIRE}}", expire or "-")
                text = text.replace("{{PORT}}", port or "-")
                body = text.encode("utf-8")
            except Exception:
                pass

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
        self.admin_api: AdminApiServer | None = None
        self.running = False
        self.manual_3366_block_enabled = False

    @property
    def replay_3366_block_enabled(self) -> bool:
        """兼容旧字段名；当前值代表录制与重放共用开关。"""
        return self.manual_3366_block_enabled

    @replay_3366_block_enabled.setter
    def replay_3366_block_enabled(self, enabled: bool) -> None:
        self.manual_3366_block_enabled = bool(enabled)

    def start(self, cfg: dict):
        if self.running:
            return
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, args=(cfg,), daemon=True)
        self._thread.start()

    def _run(self, cfg):
        asyncio.set_event_loop(self.loop)
        # v1.129 operation audit: allocate the run before rule bootstrap so a
        # forced reload/counter reset is preserved in control_events.jsonl.
        persistent_01_path = TrafficSessionLog.begin_persistent_01_record_run()
        if persistent_01_path:
            _event(
                "INFO",
                "Engine",
                f"AI机器日志录制帧: {persistent_01_path}",
            )
        try:
            from core.type9_special_rules import type9_hot_rule_store
            rule_status = type9_hot_rule_store.bootstrap()
            _event(
                "INFO" if rule_status.get("ok") else "WARN",
                "Type9Rules",
                "v121热规则 "
                f"generation={rule_status.get('generation')} "
                f"active={rule_status.get('active_rule_count')} "
                f"revision={rule_status.get('document', {}).get('revision') or '-'} "
                f"error={rule_status.get('last_error') or '-'}",
            )
        except Exception as ex:
            _event("WARN", "Type9Rules", f"热规则初始化异常，继续使用内存空规则: {ex}")
            rule_status = {}
        try:
            from core.ai_log_v128 import ai_log_v128

            ai_log_v128.write_control_event(
                source="engine",
                actor="runtime",
                action="proxy_run_started",
                phase="startup",
                details={
                    "record_port": int(cfg.get("port_1081", 1081)),
                    "replay_port": int(cfg.get("port_1080", 1080)),
                },
                state={
                    "engine": {
                        "running": bool(self.running),
                        "starting": True,
                        "manual_3366_block_enabled": bool(
                            self.manual_3366_block_enabled
                        ),
                    },
                    "config_flags": {
                        "replenish_01_mode": bool(
                            app_config.get("replenish_01_mode")
                        ),
                        "full_rebuild_01_mode": bool(
                            app_config.get("full_rebuild_01_mode")
                        ),
                        "hold_01_after_threshold": bool(
                            app_config.get("hold_01_after_threshold")
                        ),
                        "detail_01_log": bool(
                            app_config.get("detail_01_log", True)
                        ),
                        "dl_01_block_enabled": bool(
                            app_config.get("dl_01_block_enabled")
                        ),
                        "dl_01_mrpcs_mutate_enabled": bool(
                            app_config.get("dl_01_mrpcs_mutate_enabled")
                        ),
                    },
                    "hot_rules": {
                        "generation": int(rule_status.get("generation") or 0),
                        "revision": str(
                            (rule_status.get("document") or {}).get("revision")
                            or ""
                        ),
                        "active_rule_count": int(
                            rule_status.get("active_rule_count") or 0
                        ),
                        "rule_changed_counts": dict(
                            rule_status.get("rule_changed_counts") or {}
                        ),
                    },
                },
            )
        except (OSError, TypeError, ValueError, RuntimeError):
            pass
        analysis_01_dir = TrafficSessionLog.begin_01_replay_analysis_run()
        if analysis_01_dir:
            _event(
                "INFO",
                "Engine",
                f"AI机器日志运行目录: {analysis_01_dir}",
            )
        # 详单清理勿放主线程：listdir/rmtree 在网络盘、大目录或杀软扫盘时会让界面假死数秒至更久
        try:
            if app_config.get("clear_traffic_logs_on_proxy_start", True):
                n = TrafficSessionLog.clear_previous_run_dirs_and_reset_state()
                if n:
                    _event(
                        "INFO",
                        "Engine",
                        f"已清理运行目录下 {n} 个流量详单目录 (PyProxyTrafficLogs_*)，内存录制池未清空",
                    )
            else:
                TrafficSessionLog.reset_session_state_only()
            # 预创建详单目录，确保用户登录等流量到达时能立即写入
            d = TrafficSessionLog.ensure_log_dir_ready()
            if d:
                _event("INFO", "Engine", f"AI机器日志目录已就绪: {d}")
        except Exception as ex:
            _event("WARN", "Engine", f"清理流量详单目录异常（已跳过）: {ex}")
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
            auth_required=True,
            users=cfg.get("users_record", {}),
            external_proxy=ext,
            label="录制",
            mode="record",
            tool_auth_ok=tool_auth_ok,
            tool_debug=tool_debug
        )
        self.server_1080 = Socks5Server(
            port=cfg.get("port_1080", 1080),
            auth_required=True,
            users=cfg.get("users_replay", {}),
            external_proxy=ext,
            label="重放",
            mode="replay",
            tool_auth_ok=tool_auth_ok,
            tool_debug=tool_debug
        )
        for server in (self.server_1080, self.server_1081):
            server._manual_3366_block_enabled = bool(
                self.manual_3366_block_enabled
            )

        # 远程账号管理（浏览器）
        try:
            if cfg.get("admin_enabled", True):
                bind = cfg.get("admin_bind", "0.0.0.0")
                port = int(cfg.get("admin_port", 8787))
                token = cfg.get("admin_token", "") or ""

                def _reload():
                    self.reload_users()

                self.admin_api = AdminApiServer(bind=bind, port=port, token=token, on_users_changed=_reload)
                self.admin_api.start()
                # 写回 token（若自动生成）
                if self.admin_api.token and self.admin_api.token != token:
                    cfg["admin_token"] = self.admin_api.token
        except Exception as ex:
            # Do not keep a half-started instance: the UI uses this field to
            # decide whether the management endpoint is actually available.
            if self.admin_api:
                try:
                    self.admin_api.stop()
                except Exception:
                    pass
            self.admin_api = None
            _event("WARN", "AdminAPI", f"启动失败: {ex}")

        # 启动时打印 skip_33 全局开关状态，方便确认配置是否生效
        if app_config.get("skip_33", False):
            _event("WARN", "Engine",
                   "skip_33=True【全局】：33录制/重放/替换已全部关闭，仅处理01通道（调试模式）")

        try:
            self.running = True
            try:
                from core.ai_log_v128 import ai_log_v128
                ai_log_v128.write_control_event(
                    source="engine",
                    actor="runtime",
                    action="proxy_listeners_starting",
                    state={
                        "engine": {
                            "running": bool(self.running),
                            "manual_3366_block_enabled": bool(
                                self.manual_3366_block_enabled
                            ),
                            "record_server_present": self.server_1081 is not None,
                            "replay_server_present": self.server_1080 is not None,
                        }
                    },
                )
            except (OSError, TypeError, ValueError, RuntimeError):
                pass
            self.loop.run_until_complete(asyncio.gather(
                self.server_1081.start(),
                self.server_1080.start(),
            ))
        except Exception as ex:
            _event("ERROR", "Engine", f"崩溃: {ex}")
        finally:
            self.running = False

    def stop(self):
        try:
            from core.ai_log_v128 import ai_log_v128
            ai_log_v128.write_control_event(
                source="engine",
                actor="runtime",
                action="proxy_stop_requested",
                phase="before",
                state={
                    "engine": {
                        "running": bool(self.running),
                        "manual_3366_block_enabled": bool(
                            self.manual_3366_block_enabled
                        ),
                    }
                },
            )
        except (OSError, TypeError, ValueError, RuntimeError):
            pass
        self.manual_3366_block_enabled = False
        try:
            recording_pool.save_snapshot()
            recording_pool.save_official_templates()
        except Exception:
            pass
        if self.server_1080: self.server_1080.stop()
        if self.server_1081: self.server_1081.stop()
        if self.admin_api:
            try:
                self.admin_api.stop()
            except Exception:
                pass
            self.admin_api = None
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.running = False
        try:
            from core.ai_log_v128 import ai_log_v128
            ai_log_v128.write_control_event(
                source="engine",
                actor="runtime",
                action="proxy_stopped",
                state={
                    "engine": {
                        "running": bool(self.running),
                        "manual_3366_block_enabled": bool(
                            self.manual_3366_block_enabled
                        ),
                    }
                },
            )
        except (OSError, TypeError, ValueError, RuntimeError):
            pass

    def set_3366_block(self, enabled: bool) -> None:
        """线程安全切换录制与重放3366阻断；独立01连接不在目标集合中。"""
        previous = bool(self.manual_3366_block_enabled)
        self.manual_3366_block_enabled = bool(enabled)
        servers = tuple(
            server
            for server in (self.server_1080, self.server_1081)
            if server is not None
        )
        if self.loop and self.loop.is_running():
            for server in servers:
                self.loop.call_soon_threadsafe(
                    server.set_manual_3366_block,
                    bool(enabled),
                )
        else:
            for server in servers:
                server.set_manual_3366_block(bool(enabled))
        if previous != bool(enabled):
            try:
                from core.ai_log_v128 import ai_log_v128
                ai_log_v128.write_control_event(
                    source="engine",
                    actor="runtime",
                    action="manual_3366_block_changed",
                    details={"before": previous, "after": bool(enabled)},
                    state={
                        "engine": {
                            "running": bool(self.running),
                            "manual_3366_block_enabled": bool(
                                self.manual_3366_block_enabled
                            ),
                        }
                    },
                )
            except (OSError, TypeError, ValueError, RuntimeError):
                pass

    def set_replay_3366_block(self, enabled: bool) -> None:
        """兼容旧调用；当前开关同时作用于录制与重放端口。"""
        self.set_3366_block(enabled)

    def reload_users(self):
        """动态重载用户列表（无需重启代理）"""
        users_record = user_manager.to_dict("record")
        users_replay = user_manager.to_dict("replay")
        if self.server_1081:
            self.server_1081.users = users_record
        if self.server_1080:
            self.server_1080.users = users_replay
        _event(
            "INFO",
            "UserMgr",
            f"用户列表已重载：录制={len(users_record)} 重放={len(users_replay)}"
        )
        from core.events import log_bus
        log_bus.users_updated.emit()

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
