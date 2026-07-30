import asyncio
import os
import socket
import struct
import time
import threading

from core.config import app_config
from core.events import log_bus, _event, _log_exc
from core.managers import user_manager, local_map_manager
from core.crypto import (
    AceReplayAssembler,
    _ace_try_replace,
    _parse_ace_account_id,
    extract_pool_items_from_3366_plaintext,
    try_replace_3366_4013_plain,
)
from core.protocol_3366 import (
    MAGIC as MAGIC_3366,
    MSG_DATA,
    MSG_HANDSHAKE,
    MSG_SERVER_KEY,
    Conn3366State,
    process_3366_chunk,
    format_3366_log_preview,
    merge_3366_product_registry,
    decrypt_plain_for_strategy,
    registry_needs_downlink_key_extraction,
    product_uses_downlink_session_key,
    try_decrypt_4013_frame,
    replace_3366_40_13_frames_in_buffer,
    iter_3366_frames_in_buffer,
    extract_handshake_user_id,
    filter_3366_frames_with_raw_high_entropy,
    parse_3366_header,
    _find_valid_magic,
)
from core.pool import recording_pool
from core.admin_api import AdminApiServer
from core.traffic_session_log import (
    TrafficSessionLog,
    traffic_file_logger,
    hex_slice_from_01_0a_00_09,
)
from core.packet_verify import get_01_packet_verify_summary


# 暗区突围国服上行首条 10 01 握手总长。
HS_LEN_AB_BREAKOUT_CN_1001 = 75


def _format_01_replace_mode_label(detail: dict) -> str:
    """
    01 重放替换日志首段的策略说明（中文）。
    detail 由 crypto 的 type-9 字段重建流程产生。
    """
    rm = detail.get("replace_mode", "anchor")
    if rm == "type9_crc32_rebuild":
        return "字段重建·CRC32重算"
    if rm == "length_fallback":
        return "无锚点·包尾长度匹配"
    return "顺序样本池"

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
        self._ace_replay_assemblers: dict[str, AceReplayAssembler] = {}
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
        # 多开控制：username → 当前活跃的 conn_id 集合
        self._user_active_conns: dict[str, set[str]] = {}
        # conn_id → client StreamWriter（用于踢人时强制断开）
        self._conn_client_writers: dict[str, "asyncio.StreamWriter"] = {}
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
        # 自动断线：01 包达阈值后，该 IP 的新连接将被拒绝，直到所有连接断开
        self._auto_disconnect_blocked: set[str] = set()
        # 携带 33（3366）数据的 conn_id 集合，用于 01 满时断开 33 连接
        self._conn_carries_3366: set[str] = set()
        # 录制阻止：uid 正在被重放时，标记该 conn_id 不录制（01 不入池；33 直接断开连接）
        self._record_blocked_conns: set[str] = set()
        # 01 两步握手判断：收到42握手包后暂存，等下一帧uid确认是否在重放，再决定是否入池
        self._pending_01_handshake: dict[str, bytes] = {}
        # 重放 01 UID 匹配失败计数（游戏可能随机发送错误UID包，容忍若干次后再严格阻断）
        self._replay_gid_fail: dict[str, int] = {}
        # 重放进行中 ACE 重握手检测：收到42字节加入包后标记，随后的 0A 00 23 包若UID不匹配则丢弃
        self._replay_ace_recheck: set[str] = set()
        # 下发拦截缓冲（只拼装 payload，不包含 3366 头）
        self._dl_intercept_bufs: dict[str, bytearray] = {}
        # HTTPS 下行拦截：记录需要丢弃下行数据的 conn_id（连接放行，但服务器响应不转给客户端）
        self._https_block_conns: set[str] = set()
        # 严格模式阻断：无录制/无匹配时标记该 client_ip，所有后续连接（01+3366）全部拒绝
        # 该 IP 完全断线后自动清除，重新上线时重新判断
        self._strict_blocked_ips: set[str] = set()
        # conn_id → 3366 10_01 解析出的游戏账户（供下发拦截统计「游戏账户」列显示）
        self._3366_hs_uid: dict[str, str] = {}
        # client_ip → 游戏 UID（跨 conn_id 共享；01 连接和 3366 连接各自写入，互为兜底）
        self._ip_game_uid: dict[str, str] = {}
        # 该 IP 已出现暗区国服特征首帧：上行 10 01 总长 == HS_LEN_AB_BREAKOUT_CN_1001（75B）
        self._3366_ab_cn_first_hs: set[str] = set()
        # 重放就绪日志去重：同 IP 首次匹配成功后记录，后续连接静默匹配
        self._replay_ready_logged: set[str] = set()
        # IP 已有 UID 时，新连接须先收到 42B 加入包才允许 0A 00 23 匹配（防止早到的旧包误匹配）
        self._replay_await_join: set[str] = set()
        # 已经由 42B 加入包解锁的连接：0A 00 23 不在录制池时直接丢弃，不走重试逻辑
        self._replay_join_triggered: set[str] = set()

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

                    # 鉴权成功后启动录制会话（AUTH_OK 之后，保证日志顺序正确）
                    if actual_mode == "record":
                        _is_new_rec = recording_pool.new_session(client_ip)
                        _rec_joined = True
                        if _is_new_rec:
                            _event("RECORD", self.label, f"[{client_ip}] 开始录制会话")

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
                                f"【无录制池，待 UID 后严格匹配】")
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

            # ④-b HTTPS 域名拦截：放行 CONNECT，但标记该 conn_id 下行数据不转发给客户端
            # 【之前逻辑】直接返回 \x05\x05 拒绝整个 CONNECT 请求（请求和响应都被阻断）
            # 【当前逻辑】允许连接建立，客户端请求正常到达服务器；
            #             _forward 里 ↓DOWN 方向检测到该 conn_id 时直接丢弃服务器下发数据
            if app_config.get("ace_https_block_enabled"):
                replay_only = app_config.get("ace_https_block_replay_only")
                # 仅重放模式：录制端口(record)上线不拦截，只有重放端口(replay)拦截
                _should_block = (not replay_only) or (actual_mode == "replay")
                if _should_block:
                    block_host = (app_config.get("ace_https_block_host") or "").strip().lower()
                    if block_host and target_host.lower() == block_host:
                        self._https_block_conns.add(conn_id)
                        _event("BLOCK", self.label,
                               f"[{username}] HTTPS 下行拦截标记 → {dst_str}（连接放行，下行数据丢弃）")

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
                        # 待上行出现 33 握手或 01(0A00 23) 解析 UID 后，再走既有「无匹配则严格阻断」逻辑。
                        self._replay_all_pools[conn_id] = {}
                        self._replay_gid_checked[conn_id] = False
                        log_bus.conn_mode_update.emit(client_ip, "待匹配(无池)")
                        _event("DEBUG", self.label,
                               f"[{conn_id}] 重放 {dst_str}：全局无录制池，待 33/01 出 UID 后再严格判定")
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
            self._replay_index.pop(conn_id, None)
            self._ace_replay_assemblers.pop(conn_id, None)
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
            self._replay_gid_fail.pop(conn_id, None)
            self._replay_ace_recheck.discard(conn_id)
            self._replay_await_join.discard(conn_id)
            self._replay_join_triggered.discard(conn_id)
            for _attr in (
                "_3366_no_items_logged",
                "_3366_no_kv_logged",
                "_3366_decrypt_fail_logged",
            ):
                _s = getattr(self, _attr, None)
                if _s is not None:
                    _s.discard(conn_id)
            self._dl_intercept_bufs.pop(conn_id, None)
            self._https_block_conns.discard(conn_id)
            self._3366_hs_uid.pop(conn_id, None)
            self._conn_live_gid.pop(conn_id, None)
            
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
            # 该 IP 所有连接已断开时：清理 IP 级共享状态 + 自动断线处理
            _remaining_for_ip = 0
            for _uname, ip_map in self._user_active_conns.items():
                _remaining_for_ip += len(ip_map.get(client_ip, set()))
            if _remaining_for_ip == 0:
                # _ip_game_uid 保留：下次连接时直接回填 UID，
                # 避免握手延迟导致拦截状态表行消失（_3366_aes 同理持久化）
                self._strict_blocked_ips.discard(client_ip)   # IP 全部断线 → 解除阻断
                self._3366_ab_cn_first_hs.discard(client_ip)
                self._replay_ready_logged.discard(client_ip)
                if actual_mode == "record" and client_ip in self._auto_disconnect_blocked:
                    self._auto_disconnect_blocked.discard(client_ip)
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

    def _block_ip_strict(self, client_ip: str, reason: str) -> None:
        """严格模式：标记该 IP 并立即踢掉所有活跃连接（01 + 3366 同时断开）。
        IP 完全断线后 _on_disconnect 会自动解除标记。"""
        self._strict_blocked_ips.add(client_ip)
        _event("BLOCK", self.label, f"[{client_ip}] 严格阻断：{reason}，踢出所有活跃连接")
        for _uname, ip_map in self._user_active_conns.items():
            for cid in list(ip_map.get(client_ip, set())):
                w = self._conn_client_writers.get(cid)
                if w:
                    try:
                        w.close()
                    except Exception:
                        pass

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
            """构造替换回调，捕获 ri 引用和 client_ip"""
            def _on_replace(detail: dict):
                d2 = dict(detail)
                ri_ref[1] += 1
                log_bus.replay_progress.emit(client_ip, ri_ref[1], d2["pool_total"])
                _emit_progress_detail(conn_id, client_ip)
                prev = " ".join(f"{b:02X}" for b in d2["payload_preview"][:64])
                if len(d2["payload_preview"]) > 64:
                    prev += " …"
                mode_label = _format_01_replace_mode_label(d2)
                new_pkt = d2.get("new_packet") or b""
                verify_sum = (
                    get_01_packet_verify_summary(new_pkt)
                    if new_pkt and d2.get("new_fragment_count", 1) == 1
                    else ""
                )
                line = (
                    f"[01] 替换|{mode_label} 池#{d2['pool_idx']+1}/{d2['pool_total']}  "
                    f"逻辑载荷 {d2['orig_payload_len']}B→{d2['new_payload_len']}B  "
                    f"总包长 {d2['orig_pkt_len']}→{d2['new_pkt_len']}  "
                    f"CRC {d2.get('old_crc_hex', '?')}→{d2['crc_hex']}  "
                    f"分片 {d2.get('old_fragment_count', 1)}→{d2.get('new_fragment_count', 1)}  "
                    f"标签={d2['routing_hex']}  "
                    f"账号={d2['account_id']}  {verify_sum}\n"
                    f"  替换记录前64B: {prev}"
                )
                if app_config.get("detail_01_log"):
                    def _hex_lines(b: bytes, per_line: int = 32) -> str:
                        rows = []
                        for i in range(0, len(b), per_line):
                            rows.append(" ".join(f"{x:02X}" for x in b[i:i + per_line]))
                        return "\n  ".join(rows)
                    line += (
                        f"\n  【原始请求】{d2['orig_pkt_len']}B:\n"
                        f"  {_hex_lines(d2.get('orig_packet', b''))}\n"
                        f"  【替换后封包】{d2['new_pkt_len']}B:\n"
                        f"  {_hex_lines(d2.get('new_packet', b''))}"
                    )
                log_bus.conn_detail.emit(client_ip, line)
                try:
                    _orig_pkt = d2.get("orig_packet") or b""
                    _new_pkt  = d2.get("new_packet") or b""
                    _uid_rep  = d2.get("account_id", "") or ""
                    traffic_file_logger.log_01_replace(
                        orig_packet=_orig_pkt,
                        new_packet=_new_pkt,
                        pool_idx=int(d2.get("pool_idx", -1)),
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
                if _idle_sec > 0 and shared_ts is not None:
                    _poll = min(5.0, float(_idle_sec))
                    try:
                        data = await asyncio.wait_for(reader.read(65536), timeout=_poll)
                        shared_ts[0] = time.time()  # 读到数据，刷新连接级时间戳
                    except asyncio.TimeoutError:
                        if time.time() - shared_ts[0] > _idle_sec:
                            _mode_label = "录制" if mode == "record" else "重放"
                            _event("RECORD" if mode == "record" else "INFO", self.label,
                                   f"[{client_ip}] {_mode_label}连接空闲超过 {_idle_sec}s，主动断开")
                            break
                        continue  # 未超总阈值，继续等待
                else:
                    data = await reader.read(65536)
                if not data:
                    break
                counter[0] += 1

                # ── 严格模式 IP 阻断：无录制/无匹配时该 IP 所有通道全部拒绝 ──────────
                if mode == "replay" and client_ip in self._strict_blocked_ips:
                    log_bus.conn_detail.emit(
                        client_ip,
                        f"[断开] 严格阻断（{direction}）：无录制，所有通道已关闭")
                    return

                # ── HTTPS 下行拦截：服务器下发数据直接丢弃，不转发给客户端 ──────────────
                # 连接本身已放行（CONNECT 未被拒绝），客户端请求可以到达服务器；
                # 服务器响应（↓DOWN）在此被吞掉，客户端收不到文件数据，下载自然失败。
                if direction == "↓DOWN" and conn_id in self._https_block_conns:
                    log_bus.dl_intercept_log.emit(
                        f"[{conn_id}] HTTPS 下行数据丢弃 {len(data)}B ← {dst_str or '?'}"
                    )
                    continue  # 不写给客户端，读下一块

                # ── 发送原始抓包数据 (TCP 流，无处理) ──
                log_bus.stream_raw_data.emit(conn_id, direction, len(data), data)

                # ── 记录所有经过代理的原始 TCP 数据（未分包前，长度≥traffic_log_min_len）
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
                if mode == "record":
                    rec_key = f"{conn_id}_rec_{direction}"
                    in_rec_stream = rec_key in self._stream_bufs
                    if in_rec_stream or (len(data) >= 2 and data[0] == 0x01 and data[1] == 0x00):
                        rec_buf = self._stream_bufs.setdefault(rec_key, bytearray())
                        rec_buf += data
                        pos = 0
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
                            except Exception:
                                pass
                            
                            if direction == "↑UP":
                                try:
                                    if conn_id in self._record_blocked_conns:
                                        pass  # 已确认 uid 在重放，后续所有包透传不入池
                                    elif conn_id in self._pending_01_handshake:
                                        # 第二步：42握手包之后的帧，尝试提取 uid
                                        _rec_uid = _parse_ace_account_id(sub)
                                        if _rec_uid:
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
                                        if len(sub) == 42:
                                            # 新连接再次出现加入包时，录制池按新生命周期清空。
                                            recording_pool.note_join_packet(
                                                client_ip, conn_id
                                            )
                                            # 第一步：暂存，等下一帧判断 uid
                                            self._pending_01_handshake[conn_id] = sub
                                        else:
                                            recording_pool.append(client_ip, sub)
                                except Exception:
                                    _log_exc("pending_01_handshake")
                                # 自动断线：01 包达阈值且存在 33 录制时，断开携带 33 的连接
                                try:
                                    n01 = recording_pool.get_active_01_count(client_ip)
                                    n33 = recording_pool.get_active_33_count(client_ip)
                                    thresh = app_config.get("auto_disconnect_01_threshold") or 100
                                    if (n01 >= thresh and n33 > 0 and
                                            client_ip not in self._auto_disconnect_blocked):
                                        self._auto_disconnect_blocked.add(client_ip)
                                        conns_33 = [
                                            cid for _uname, ip_map in self._user_active_conns.items()
                                            for cid in ip_map.get(client_ip, set())
                                            if cid in self._conn_carries_3366
                                        ]
                                        for cid in conns_33:
                                            w = self._conn_client_writers.get(cid)
                                            if w:
                                                try:
                                                    w.close()
                                                except Exception:
                                                    pass
                                        _event("RECORD", self.label,
                                               f"[{client_ip}] 01包已达{n01}个、33有{n33}个，断开{len(conns_33)}个33连接")
                                except Exception:
                                    pass
                            pos += pkt_len
                        del rec_buf[:pos]
                        # 缓冲区为空时必须清理，否则后续 3366 流量会错误进入此分支
                        if not rec_buf:
                            self._stream_bufs.pop(rec_key, None)
                        
                        # 静默录制模式只读不发，发是由原始透传完成的。
                        # 因此这里不再覆盖 `data`
                        pass

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
                                        self._conn_live_gid[conn_id] = str(live_gid)
                                        self._ip_game_uid[client_ip] = str(live_gid)
                                        log_bus.conn_game_id_update.emit(client_ip, str(live_gid), "重放")
                                    all_pools = self._replay_all_pools.get(conn_id, {})
                                    matched   = all_pools.get(live_gid) if live_gid else None
                                    # 同IP池未命中 → 跨IP按游戏账号查找
                                    if not matched and live_gid:
                                        matched = recording_pool.find_pool_by_game_id(str(live_gid))
                                        if matched:
                                            _event("REPLAY", self.label,
                                                   f"[{username}({client_ip})] 跨IP匹配成功："
                                                   f"游戏账号={live_gid} 来自其他录制IP")
                                    if matched:
                                        # 找到匹配的录制会话 → 激活重放（01/33 分池）
                                        self._replay_pools[conn_id] = matched
                                        self._replay_index[conn_id] = [0, 0]
                                        self._replay_index_33[conn_id] = {
                                            "09": [0, 0], "21": [0, 0], "01_fb": [0, 0]
                                        }
                                        pool_01 = matched.get("pool_01", [])
                                        pool_33 = matched.get("pool_33", [])
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
                                                f"[重放就绪] 游戏ID=[{live_gid}]  01池={n01} 33池={n33}")
                                        # 标记本连接已完成 UID 匹配，防止后续 0A 00 23 重置重放索引
                                        self._replay_gid_checked[conn_id] = True
                                        # 宽松模式：0A 00 23 UID 包本身丢弃，不发送给服务器
                                        if not app_config.get("replay_strict_match", True):
                                            pos += pkt_len
                                            continue
                                    else:
                                        # 无匹配录制
                                        gid_str = f"[{live_gid}]" if live_gid else "[未知]"
                                        _strict = app_config.get("replay_strict_match", True)
                                        # 经 42B 加入包解锁的连接，UID 不在录制池 → 直接丢弃，不重试
                                        if conn_id in self._replay_join_triggered:
                                            self._replay_join_triggered.discard(conn_id)
                                            log_bus.conn_detail.emit(
                                                client_ip,
                                                f"[丢包] 42B解锁后UID={gid_str}不在录制池，直接丢弃")
                                            log_bus.conn_mode_update.emit(client_ip, "无匹配录制")
                                            self._replay_gid_checked[conn_id] = True
                                        else:
                                            fail_cnt = self._replay_gid_fail.get(conn_id, 0) + 1
                                            self._replay_gid_fail[conn_id] = fail_cnt
                                            _max_fail = 3  # 容忍游戏随机发送错误UID包，最多重试3次
                                            if fail_cnt < _max_fail:
                                                # 未达上限：丢弃本次错误UID，继续等待正确的账号包
                                                log_bus.conn_detail.emit(
                                                    client_ip,
                                                    f"[跳过] 无匹配录制 游戏ID={gid_str}"
                                                    f"  (第{fail_cnt}/{_max_fail}次，等待正确账号包)")
                                                # 重置检测标志，允许下一个 0A 00 23 包重新提取
                                                self._replay_gid_checked[conn_id] = False
                                            else:
                                                # 达到上限：按严格/宽松模式处理
                                                if _strict:
                                                    _event("WARN", self.label,
                                                           f"[{username}] 无匹配录制 游戏ID={gid_str}，"
                                                           f"严格模式阻断全部连接（已重试{fail_cnt}次）")
                                                    log_bus.conn_detail.emit(
                                                        client_ip,
                                                        f"[断开] 无匹配录制  游戏ID={gid_str}  （严格模式，01+3366全断）")
                                                    log_bus.conn_mode_update.emit(client_ip, "无匹配录制")
                                                    self._block_ip_strict(client_ip,
                                                                           f"01通道无匹配录制 游戏ID={gid_str}")
                                                else:
                                                    # 宽松模式：不断开，但后续上行 01 包全部丢弃（不透传）
                                                    _event("WARN", self.label,
                                                           f"[{username}] 无匹配录制 游戏ID={gid_str}，宽松模式丢包（不透传）")
                                                    log_bus.conn_detail.emit(
                                                        client_ip,
                                                        f"[丢包] 无匹配录制  游戏ID={gid_str}  （宽松模式，不断开不透传）")
                                                    log_bus.conn_mode_update.emit(client_ip, "无匹配录制")
                                                self._replay_gid_checked[conn_id] = True

                            # ── 重放进行中的 ACE 重握手检测 ────────────────────────────
                            # 42B 加入包到来 → 标记等待新 UID。
                            # 随后 0A 00 23：
                            #   UID 在录制池 → 视为重连，重置重放索引从 0 开始，丢弃本包
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
                                        _rc_matched = recording_pool.find_pool_by_game_id(str(_recheck_uid))
                                    if _rc_matched:
                                        # UID 在录制池 → 重连，从 0 开始重放
                                        self._replay_pools[conn_id] = _rc_matched
                                        pools = _rc_matched          # 更新局部变量
                                        pool  = pools.get("pool_01", [])
                                        ri[0] = 0                    # 原地重置，保持引用不变
                                        ri[1] = 0
                                        _ri33_reset = self._replay_index_33.get(conn_id)
                                        if _ri33_reset:
                                            for _k33 in _ri33_reset:
                                                _ri33_reset[_k33] = [0, 0]
                                        if _recheck_uid:
                                            self._conn_live_gid[conn_id] = str(_recheck_uid)
                                            self._ip_game_uid[client_ip] = str(_recheck_uid)
                                            log_bus.conn_game_id_update.emit(
                                                client_ip, str(_recheck_uid), "重放")
                                        log_bus.conn_detail.emit(
                                            client_ip,
                                            f"[重连] UID=[{_recheck_uid}] 在录制池，索引归零重放")
                                    else:
                                        log_bus.conn_detail.emit(
                                            client_ip,
                                            f"[丢包] 重连UID=[{_recheck_uid or '未知'}] 不在录制池")
                                    # 无论是否在录制池，0A 00 23 包本身均丢弃不发送
                                    pos += pkt_len
                                    continue

                            if ri is None or direction == "↓DOWN":
                                # 01 下行大包拦截（仅重放、仅下行）
                                if (direction == "↓DOWN"
                                        and app_config.get("dl_01_block_enabled")
                                        and pkt_len > (app_config.get("dl_01_block_threshold") or 1000)):
                                    _thresh = app_config.get("dl_01_block_threshold") or 1000
                                    _game_uid = self._conn_live_gid.get(conn_id) or self._3366_hs_uid.get(conn_id)
                                    if not _game_uid:
                                        if mode == "replay" and conn_id in self._replay_pools:
                                            _game_uid = self._replay_pools[conn_id].get("game_id")
                                        elif mode == "record":
                                            _s_ids = recording_pool.get_active_session_ace_ids(client_ip)
                                            _game_uid = _s_ids[0] if _s_ids[0] else (_s_ids[1] if _s_ids[1] else "")
                                    # 跨连接兜底：01 连接下发时 uid 可能由 3366 连接写入（或反之）
                                    if not _game_uid:
                                        _game_uid = self._ip_game_uid.get(client_ip, "")
                                    _proxy_user = username or ""
                                    if _game_uid and _proxy_user and str(_game_uid) != _proxy_user:
                                        _conn_label = f"{_game_uid}({_proxy_user})"
                                    else:
                                        _conn_label = str(_game_uid) if _game_uid else (_proxy_user or client_ip)
                                    log_bus.dl_intercept_event.emit(
                                        _conn_label, "01_drop",
                                        f"01下行大包拦截: {pkt_len}字节 > 阈值{_thresh}字节",
                                    )
                                    pos += pkt_len
                                    continue
                                # 宽松模式：无匹配录制且已放弃等待 → 上行包丢弃（不透传）
                                if (direction == "↑UP"
                                        and ri is None
                                        and self._replay_gid_checked.get(conn_id, False)
                                        and not app_config.get("replay_strict_match", True)):
                                    pos += pkt_len
                                    continue
                                # 还没选定池（等待 0A 00 23 包），或者当前包是下行，当前包透传
                                output.extend(sub)
                                pos += pkt_len
                                continue

                            # 暗区 type-9：先收齐逻辑包，再替换记录并重算 CRC/长度/分片。
                            assembler = self._ace_replay_assemblers.setdefault(
                                conn_id, AceReplayAssembler()
                            )
                            replaced, _ = assembler.feed(
                                sub, pool, ri, on_log=on_replace
                            )
                            output.extend(replaced)
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
                need_3366 = bool(st3366.buf) or (_find_valid_magic(data, 0) >= 0)

                # 在进入 3366 组装前，先处理外层包裹（如果它是 01 包，前面可能带有 01 00 xx xx 的头）
                # 由于之前的流缓冲区已经合并了 01 包，如果 data 本身就是带有外层头的（例如 01 xx... + 33 66），
                # 后面简单的 replace 可能会导致长度不一致问题。但这需要看后续重组策略。
                # 目前直接使用 data.replace() 来替换整个 3366 帧的内容。

                if need_3366 and data:
                    ko = app_config.get("3366_key_offset")
                    io = app_config.get("3366_iv_offset")
                    k_off = ko if isinstance(ko, int) else None
                    iv_off = io if isinstance(io, int) else None
                    reg = merge_3366_product_registry(app_config.get("3366_products"))
                    need_downlink_key_extract = registry_needs_downlink_key_extraction(
                        reg
                    )

                    def _on3366(fr: bytes, info: dict | None, sst: Conn3366State):
                        if direction == "↑UP":
                            if info and info.get("msg") == MSG_HANDSHAKE:
                                if len(fr) == HS_LEN_AB_BREAKOUT_CN_1001:
                                    self._3366_ab_cn_first_hs.add(client_ip)
                            _hs_uid_any = extract_handshake_user_id(fr)
                            if _hs_uid_any:
                                self._3366_hs_uid[conn_id] = _hs_uid_any
                                self._conn_live_gid[conn_id] = str(_hs_uid_any)
                                self._ip_game_uid[client_ip] = str(_hs_uid_any)
                                # 只要拿到了 uid 就通知前端表格更新（无论之后是否匹配重放池）
                                log_bus.conn_game_id_update.emit(client_ip, str(_hs_uid_any), mode if mode == "record" else "重放")
                            _hs_uid_check = _hs_uid_any
                            _dl_reset_active = (
                                app_config.get("az_dl_intercept_enabled")
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
                                matched = all_pools.get(_hs_uid)
                                # 同IP池未命中 → 跨IP按游戏账号查找
                                if not matched and _hs_uid:
                                    matched = recording_pool.find_pool_by_game_id(str(_hs_uid))
                                    if matched:
                                        _event("REPLAY", self.label,
                                               f"[{username}({client_ip})] 跨IP匹配成功(33握手)："
                                               f"游戏账号={_hs_uid} 来自其他录制IP")
                                if matched:
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
                                        f"[重放就绪] 游戏ID=[{_hs_uid}] 33握手触发  01池={n01} 33池={n33}",
                                    )
                                    log_bus.conn_mode_update.emit(client_ip, "重放")
                                else:
                                    # 33通道无匹配录制
                                    gid_str = f"[{_hs_uid}]"
                                    _strict = app_config.get("replay_strict_match", True)
                                    if _strict:
                                        _event("WARN", self.label,
                                               f"[{username}] 33通道无匹配录制 游戏ID={gid_str}，严格模式阻断全部连接")
                                        log_bus.conn_detail.emit(
                                            client_ip,
                                            f"[断开] 33通道无匹配录制  游戏ID={gid_str}  （严格模式，01+3366全断）")
                                        log_bus.conn_mode_update.emit(client_ip, "无匹配录制")
                                        self._block_ip_strict(client_ip,
                                                               f"33通道无匹配录制 游戏ID={gid_str}")
                                    else:
                                        _event("WARN", "",
                                               f"[{username}] 33通道无匹配录制 游戏ID={gid_str}，透传（宽松模式）")
                                        log_bus.conn_detail.emit(
                                            client_ip,
                                            f"[透传] 33通道无匹配录制  游戏ID={gid_str}  （宽松模式）")
                                        log_bus.conn_mode_update.emit(client_ip, "无匹配录制")
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
                                )
                        except Exception:
                            pass

                        if mode == "record" and info and info.get("msg") == MSG_DATA:
                            # skip_33 全局开关：跳过所有 3366 录制（调试：仅录 01 通道）
                            if app_config.get("skip_33", False):
                                pass
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
                        if prod and conn_id not in self._3366_prod_logged:
                            self._3366_prod_logged.add(conn_id)
                            st_txt = strat if strat else "仅识别"
                            _event(
                                "RECORD" if mode == "record" else "INFO",
                                self.label,
                                f"[{client_ip}] 暗区突围 3366: {prod}  (ID={pid})  解密={st_txt}",
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

                    # skip_33=True（全局开关）时完全跳过 33 重放，直接透传
                    if app_config.get("skip_33", False) and mode == "replay":
                        pass  # 33 重放/替换已全局禁用
                    elif mode == "replay" and direction == "↑UP":
                        # 暗区突围国服：33 只处理 40_13 内 01_0A_00_09/21。
                        _prod_hex = (self._3366_prod_hex.get(client_ip) or "").upper()
                        _is_az_breakout_3366 = _prod_hex == "0000094E"
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
                                _lazy_pool = recording_pool.find_pool_by_game_id(str(_lazy_gid))
                                if _lazy_pool:
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

                            data = replace_3366_40_13_frames_in_buffer(
                                bytearray(data), kv, pool_33, pool_01,
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
                if data and app_config.get("drop_3366_raw_high_entropy") and _find_valid_magic(data, 0) >= 0:
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
                if data:  # 可能 output 为空（所有包都不完整，等待下次 read）
                    _dl_str_enabled = app_config.get("az_dl_intercept_enabled")
                    _dl_search = (app_config.get("dl_search_str", "") or "") if _dl_str_enabled else ""
                    _dl_replace = (app_config.get("dl_replace_str", "") or "") if _dl_str_enabled else ""
                    _dl_active = bool(_dl_search)
                    if _dl_active and direction == "↓DOWN" and mode == "replay":
                        from core.dl_intercept import process_dl_intercept_3366
                        kv_intercept = self._3366_aes.get(client_ip)
                        _game_uid = (self._3366_hs_uid.get(conn_id)
                                     or self._conn_live_gid.get(conn_id)
                                     or self._ip_game_uid.get(client_ip, ""))
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

    def start(self, cfg: dict):
        if self.running:
            return
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, args=(cfg,), daemon=True)
        self._thread.start()

    def _run(self, cfg):
        asyncio.set_event_loop(self.loop)
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
                _event("INFO", "Engine", f"流量详单目录已就绪: {d}")
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
            _event("WARN", "AdminAPI", f"启动失败: {ex}")

        # 启动时打印 skip_33 全局开关状态，方便确认配置是否生效
        if app_config.get("skip_33", False):
            _event("WARN", "Engine",
                   "skip_33=True【全局】：33录制/重放/替换已全部关闭，仅处理01通道（调试模式）")

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
        if self.admin_api:
            try:
                self.admin_api.stop()
            except Exception:
                pass
            self.admin_api = None
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.running = False

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
