import struct
from core.events import log_bus
from core.config import app_config


def process_dl_intercept(
    conn_id: str, client_ip: str, data: bytes, search_str: str, replace_str: str,
    conn_label: str = "",
    *,
    emit_event_diag: bool = True,
) -> "tuple[bytes, bool]":
    """
    对解密后的 3366 40_13 帧明文做字节替换或区间填充。

    • 毁掉模式（dl_destroy_mode_enabled=True）：
        用 search_str 定位目标帧，命中后对 [第N个start_marker, stop_marker) 区间整体填充；
        区间标记未配置或未找到时退化为等长 0x00 覆盖。忽略 replace_str。

    • 普通模式（dl_destroy_mode_enabled=False）：
        replace_str 非空 → 直接 bytes.replace()；
        replace_str 为空 → 等长 0x00 覆盖（只覆盖搜索串本身，不扩大范围）。

    返回 (result_bytes, was_replaced)：
      was_replaced=True  → 发生了替换，调用方可据此标记"本连接无需再拦截"
      was_replaced=False → 未命中，原样放行
    """
    if not data or not search_str:
        return data, False

    # 同时写 dl_intercept_log；可按需控制是否进入账户详情。
    def _diag(msg: str):
        log_bus.dl_intercept_log.emit(msg)
        if conn_label and emit_event_diag:
            log_bus.dl_intercept_event.emit(conn_label, "diag", msg)

    s_bytes = search_str.encode('utf-8')

    # 先确认目标帧中存在搜索字符串
    if s_bytes not in data:
        _diag(
            f"[{conn_id}] [原因①] 明文不含 '{search_str}' → 原样放行"
            f"（明文共{len(data)}B，头16字节: {data[:16].hex()}）"
        )
        return data, False

    # ── 毁掉模式：区间整体填充 ────────────────────────────────────────────
    if app_config.get("dl_destroy_mode_enabled"):
        _diag(f"[{conn_id}] 毁掉模式已启用，'{search_str}' 命中，开始查找区间标记...")
        start_marker_hex = (app_config.get("ace_chunk_block_start_marker") or "").replace(" ", "")
        stop_marker_str  = (app_config.get("ace_chunk_block_stop_marker") or "").strip()
        start_marker_nth = max(1, int(app_config.get("ace_chunk_block_start_marker_nth") or 2))
        fill_hex = (app_config.get("ace_chunk_block_fill_byte") or "00").strip()
        try:
            fill_val = int(fill_hex, 16) & 0xFF
        except ValueError:
            fill_val = 0

        fill_start, fill_end = None, None

        # 找第 N 个 start_marker
        if start_marker_hex:
            try:
                sm_bytes = bytes.fromhex(start_marker_hex)
                found_idx, search_from = -1, 0
                for _ in range(start_marker_nth):
                    found_idx = data.find(sm_bytes, search_from)
                    if found_idx < 0:
                        break
                    search_from = found_idx + 1
                if found_idx >= 0:
                    fill_start = found_idx
                    _diag(f"[{conn_id}]   start_marker={start_marker_hex} 第{start_marker_nth}次 → offset=0x{fill_start:x}")
                else:
                    _diag(f"[{conn_id}]   start_marker={start_marker_hex} 第{start_marker_nth}次 → 未找到")
            except ValueError:
                _diag(f"[{conn_id}]   start_marker={start_marker_hex} 非法 Hex")
        else:
            _diag(f"[{conn_id}]   start_marker 未配置")

        # 找 stop_marker
        if stop_marker_str:
            idx_stop = data.find(stop_marker_str.encode("utf-8"))
            if idx_stop >= 0:
                fill_end = idx_stop
                _diag(f"[{conn_id}]   stop_marker='{stop_marker_str}' → offset=0x{fill_end:x}")
            else:
                _diag(f"[{conn_id}]   stop_marker='{stop_marker_str}' → 未找到")
        else:
            _diag(f"[{conn_id}]   stop_marker 未配置")

        if fill_start is not None and fill_end is not None and fill_start < fill_end:
            fill_len = fill_end - fill_start
            result = data[:fill_start] + bytes([fill_val]) * fill_len + data[fill_end:]
            _diag(
                f"[{conn_id}] ✔ 毁掉模式区间填充成功："
                f" 0x{fill_start:x}～0x{fill_end:x}"
                f"，填充 0x{fill_val:02X}×{fill_len}B，总明文 {len(data)}B"
            )
            return result, True

        # 区间标记未配置/未找到 → 退化为等长 0x00 覆盖
        _diag(
            f"[{conn_id}] [WARN] 区间标记未完整命中，退化为等长 0x00 覆盖"
            f"（start={'0x'+hex(fill_start)[2:] if fill_start is not None else '未找到'}"
            f"，stop={'0x'+hex(fill_end)[2:] if fill_end is not None else '未找到'}）"
        )
        result = data.replace(s_bytes, bytes(len(s_bytes)))
        _diag(f"[{conn_id}] ✔ 等长覆盖（退化）'{search_str}' → <{len(s_bytes)}×0x00>")
        return result, True

    # ── 普通模式：字符串替换 ──────────────────────────────────────────────
    if not replace_str or str(replace_str).strip().lower() in ("0", "null", "zero"):
        r_bytes = bytes(len(s_bytes))
        replace_display = f"<{len(s_bytes)}个0x00>"
    else:
        r_bytes = replace_str.encode('utf-8')
        replace_display = replace_str

    count  = data.count(s_bytes)
    result = data.replace(s_bytes, r_bytes)
    log_bus.dl_intercept_log.emit(
        f"[{conn_id}] ✓ 直接替换 '{search_str}' → '{replace_display}'，共 {count} 处"
        f"（明文 {len(data)}B → {len(result)}B）"
    )
    return result, True


# ─────────────────────────────────────────
# 3366 帧级下发拦截（缓冲式，解决 TCP 分包问题）
# ─────────────────────────────────────────

def _intercept_one_3366_frame(
    frame: bytes,
    kv: tuple,
    search_str: str,
    replace_str: str,
    conn_id: str,
    client_ip: str,
    conn_label: str = "",
    skip_chunk_block: bool = False,
) -> "tuple[bytes, bool, bool]":
    """
    对单个完整的暗区 3366 帧做解密 → 拦截替换/块填充 → 重加密。
    仅处理 MSG_DATA (40 13) 帧；其他帧原样返回。

    返回 (result_frame, was_str_replaced, was_chunk_dropped)：
      was_str_replaced=True  → 字符串替换成功，调用方可据此停止后续字符串拦截
      was_chunk_dropped=True → 块下载帧已填充清零，调用方不应设置 DONE_KEY（持续拦截）
      两者均 False            → 未处理（非数据帧 / 解密失败 / 未命中）
    
    可能的失败原因：
    [A] parse_3366_header 失败 → 帧头不足 16 字节或 MAGIC 不对（应由调用方保证）
    [B] 不是 40 13 帧 → 非数据帧，正常跳过
    [C] try_decrypt_4013_frame 返回 None → 解密失败：
        - Key/IV 偏移量配置错误（3366_key_offset / 3366_iv_offset）
        - 该帧用了与当前 kv 不同的加密方式（如 TAES 固定 IV 路径）
        - 帧内 enc_len 字段为 0 或非 16 的倍数
        - PyCryptodome 未安装（ImportError 被吞掉返回 None）
    [D] process_dl_intercept 返回与原明文相同 → 未命中搜索字符串
    [E] 重加密失败（_taes_encrypt 和 PKCS7 均失败）：
        - PyCryptodome 未安装
        - key/iv 长度不是 16 字节
    [F] _extract_4013_cipher_by_spec 失败 → 帧长 < 25 字节或 enc_len 异常
        → 帧头重建使用降级路径（无 tail 保留）
    """
    from core.protocol_3366 import (
        try_decrypt_4013_frame,
        _taes_encrypt, _aes128_cbc_encrypt,
        MSG_DATA, parse_3366_header, _extract_4013_cipher_by_spec,
    )

    def _diag(msg: str):
        log_bus.dl_intercept_log.emit(msg)
        if conn_label:
            log_bus.dl_intercept_event.emit(conn_label, "diag", msg)

    info = parse_3366_header(frame)
    if not info:
        # 原因[A]
        _diag(
            f"[{conn_id}] [A] parse_3366_header 失败，帧头异常，原样放行"
            f"（帧长={len(frame)}，头8字节={frame[:8].hex()}）"
        )
        return frame, False, False

    msg_hex = info.get("msg_hex", "??")
    if info.get("msg") != MSG_DATA:
        # 原因[B]：正常路径，不需要打印
        return frame, False, False

    key, iv = kv
    _diag(
        f"[{conn_id}] 收到 40_13 帧，帧长={len(frame)}B，"
        f"开始解密（key={key.hex()[:8]}…，iv={iv.hex()[:8]}…）"
    )
    plain = try_decrypt_4013_frame(frame, key, iv)
    if not plain:
        # 原因[C]
        _diag(
            f"[{conn_id}] [C] 40_13 帧解密失败，原样放行"
            f"（帧长={len(frame)}B  msg={msg_hex}  "
            f"key={key.hex()}  iv={iv.hex()}  "
            f"帧[16:25]={frame[16:25].hex() if len(frame) >= 25 else frame[16:].hex()}）"
            f"\n    排查：① 检查 3366_key_offset / 3366_iv_offset 是否正确"
            f"\n          ② 确认 PyCryptodome 已安装（pip install pycryptodome）"
            f"\n          ③ 帧[19:21]={frame[19:21].hex() if len(frame) >= 21 else '太短'} "
            f"（enc_len 应为 16 的倍数且 > 0）"
        )
        return frame, False, False

    _diag(
        f"[{conn_id}] ✔ 解密成功，明文={len(plain)}B，"
        f"头16字节={plain[:16].hex()}，送入块/字符串拦截..."
    )

    # ── 暗区块填充检测 ────────────────────────────────────────────────────
    was_chunk_dropped = False
    if app_config.get("ace_chunk_block_enabled") and not skip_chunk_block:
        pat_hex = (app_config.get("ace_chunk_block_pattern") or "").replace(" ", "")
        if pat_hex:
            try:
                pat_bytes = bytes.fromhex(pat_hex)
                if plain[:len(pat_bytes)] == pat_bytes:
                    # try_decrypt_4013_frame 已剥除 TAES 填充，plain 即真实明文，
                    # TAES 填充由 _taes_encrypt 重加密时自动补回。
                    fill_hex = (app_config.get("ace_chunk_block_fill_byte") or "00").strip()
                    try:
                        fill_val = int(fill_hex, 16) & 0xFF
                    except ValueError:
                        fill_val = 0
                    fill_len = len(plain)
                    msg = (
                        f"[{conn_id}] ★ 块填充命中（前缀={pat_hex}），整体清零 0x{fill_val:02X}×{fill_len}B"
                        f"（TAES填充由重加密自动补回），总明文 {len(plain)}B → 重新加密发出"
                    )
                    log_bus.dl_intercept_log.emit(msg)
                    log_bus.dl_intercept_event.emit(conn_label, "chunk_drop", msg)
                    plain = bytes([fill_val]) * fill_len
                    was_chunk_dropped = True
                else:
                    _diag(
                        f"[{conn_id}] 块填充前缀未命中"
                        f"（期望={pat_hex}，实际={plain[:len(pat_bytes)].hex()}），跳过"
                    )
            except ValueError:
                _diag(f"[{conn_id}] [WARN] ace_chunk_block_pattern 不是合法 Hex 字符串，跳过块填充")
    else:
        if not app_config.get("ace_chunk_block_enabled"):
            _diag(f"[{conn_id}] 块填充未启用，直接进行字符串匹配")
        # skip_chunk_block=True：enc_len != 1056，帧大小不符，不记日志

    if was_chunk_dropped:
        new_plain = plain
        was_replaced = False
    else:
        new_plain, was_replaced = process_dl_intercept(
            conn_id,
            client_ip,
            plain,
            search_str,
            replace_str,
            conn_label=conn_label,
            emit_event_diag=True,
        )
        if not was_replaced:
            # 原因[D]
            _diag(
                f"[{conn_id}] [D] 明文中未找到 '{search_str}'，原样放行"
                f"（明文共{len(plain)}B，头16字节={plain[:16].hex()}）"
            )
            return frame, False, False
        # 发射账户级事件（区分毁掉模式 / 普通替换，message 由 process_dl_intercept 已发 diag，此处仅发统计事件）
        if conn_label:
            if app_config.get("dl_destroy_mode_enabled"):
                ev_msg = f"[{conn_id}] ✓ 毁掉模式区间填充完成（'{search_str}' 命中），明文 {len(plain)}B"
            else:
                _rd = f"<{len(search_str.encode('utf-8'))}个0x00>" if (not replace_str or str(replace_str).strip().lower() in ("0", "null", "zero")) else replace_str
                ev_msg = f"[{conn_id}] ✓ 字符串替换 '{search_str}'→'{_rd}'，明文 {len(plain)}B"
            log_bus.dl_intercept_event.emit(conn_label, "str_replace", ev_msg)

    # ── 重加密：先尝试 TAES 填充，再 fallback 到 PKCS7 ──────────────────
    _diag(f"[{conn_id}] 开始重加密，明文改写后={len(new_plain)}B...")
    new_cipher = _taes_encrypt(new_plain, key, iv)
    used_taes = new_cipher is not None
    if not new_cipher:
        _diag(
            f"[{conn_id}] TAES 重加密失败，尝试 PKCS7 fallback"
            f"（new_plain 长={len(new_plain)}B）"
        )
        pad_len = 16 - (len(new_plain) % 16)
        if pad_len == 0:
            pad_len = 16
        new_plain_padded = new_plain + bytes([pad_len] * pad_len)
        new_cipher = _aes128_cbc_encrypt(new_plain_padded, key, iv)

    if not new_cipher:
        # 原因[E]
        _diag(
            f"[{conn_id}] [E] TAES 和 PKCS7 重加密均失败，原样放行"
            f"（请检查 PyCryptodome 安装，key/iv 长度是否均为 16 字节）"
        )
        return frame, False, False

    new_len = len(new_cipher)
    _diag(
        f"[{conn_id}] ✔ 重加密成功（{'TAES' if used_taes else 'PKCS7 fallback'}），"
        f"密文: {len(frame) - 25 if len(frame) >= 25 else '?'}B → {new_len}B"
    )

    # ── 重建帧头 ─────────────────────────────────────────────────────────
    spec = _extract_4013_cipher_by_spec(frame)
    if spec and len(frame) >= 25:
        orig_enc_len = spec[1]
        new_header = bytearray(frame[:25])
        new_header[19:21] = struct.pack(">H", new_len)
        tail = frame[25 + orig_enc_len:]    # 原始密文后的尾部字节（若有）
        new_frame = bytes(new_header) + new_cipher + tail
        if tail:
            log_bus.dl_intercept_log.emit(
                f"[{conn_id}]   帧尾 tail={len(tail)}B 已保留（{tail[:8].hex()}...）"
            )
    elif len(frame) >= 25:
        # 原因[F] 降级路径：_extract_4013_cipher_by_spec 失败，无 tail
        log_bus.dl_intercept_log.emit(
            f"[{conn_id}] [F] _extract_4013_cipher_by_spec 失败，使用降级路径重建帧头（tail 丢弃）"
            f"（帧[19:21]={frame[19:21].hex()}，enc_len 可能为 0 或非 16 倍数）"
        )
        new_header = bytearray(frame[:25])
        new_header[19:21] = struct.pack(">H", new_len)
        new_frame = bytes(new_header) + new_cipher
    else:
        # 原因[F] 极端情况：帧本身 < 25 字节
        log_bus.dl_intercept_log.emit(
            f"[{conn_id}] [F] 帧长 {len(frame)}B < 25，无法重建帧头，原样放行"
        )
        return frame, False, False

    action = "块填充" if was_chunk_dropped else "字符串替换"
    log_bus.dl_intercept_log.emit(
        f"[{conn_id}] ✓ {action}全流程完成，帧: {len(frame)}B → {len(new_frame)}B"
    )
    return new_frame, was_replaced, was_chunk_dropped


def process_dl_intercept_3366(
    conn_id: str,
    client_ip: str,
    buf_dict: dict,
    data: bytes,
    kv: "tuple | None",
    search_str: str,
    replace_str: str,
    conn_label: str = "",
) -> bytes:
    """
    缓冲式 3366 下行拦截（解决 TCP 分包问题）。

    将 data 追加到 buf_dict[conn_id] 的原始字节缓冲区，提取所有已到达的完整
    3366 帧，对 40 13 帧执行解密→拦截→重加密，返回可以立即发给客户端的字节。
    不完整的末尾帧留在缓冲区等待后续 TCP 读取。

    替换完成后自动切换到透传模式（本连接不再解密/拦截），直到 server.py 检测到
    新的 10 01 登录帧并调用 reset_dl_intercept_done(buf_dict, conn_id) 重置。

    可能的失败原因（返回 b"" 时说明数据还在缓冲等待）：
    [I]  kv 为 None → 10 02 密钥帧尚未处理完，Key/IV 还没就绪；此时全部透传不拦截。
         排查：看 server.py 的 _on3366 是否成功调用了 self._3366_aes[client_ip] = (key, iv)
    [II] 40 13 帧 enc_len == 0 或非 16 倍数 → MAGIC 处是碰撞字节，跳过继续扫描。
    [III]40 13 帧 enc_len 合法但数据未到齐 → 正常 TCP 分包等待，下次 read 继续。
    [IV] 非数据帧（10 01/10 02）：始终立即透传，绝不缓冲（防止握手死锁）。
    [V]  返回空字节 b"" → 本轮所有到达字节都进了缓冲区，没有可输出的完整帧，
         这是正常现象，不代表错误；client 不会收到任何字节，等下次 read 补全。
    [DONE] 本连接已替换成功 → 全部直接透传，不再解密。由新 10_01 帧触发重置。
    """
    from core.protocol_3366 import _find_valid_magic, MSG_DATA

    # buf_dict 内部用 '\x00done' 后缀作为"替换完成"标志键，与 bytearray 缓冲键区分
    _DONE_KEY = conn_id + '\x00done'
    # '\x00game' 后缀标记本连接已发送 game_init 事件，避免重复发送
    _GAME_KEY = conn_id + '\x00game'

    if not data:
        return b""

    raw_buf = buf_dict.setdefault(conn_id, bytearray())
    raw_buf.extend(data)

    # ── 已替换过：直接透传，跳过所有解密逻辑 ────────────────────────────
    # 块填充已启用时仍需逐帧解密检测块前缀。
    if buf_dict.get(_DONE_KEY) and not app_config.get("ace_chunk_block_enabled"):
        out = bytes(raw_buf)
        del raw_buf[:]
        return out

    if not kv:
        # 原因[I]：Key/IV 尚未就绪，全部透传（不缓冲，避免阻塞客户端）
        # 注意：kv=None 说明这条连接尚未确认为 3366 通道（如 down.anticheatexpert.com:443 等 TLS 连接），
        # 不发 game_init 事件，避免把非 3366 连接误注册进拦截状态表。
        log_bus.dl_intercept_log.emit(
            f"[{conn_id}] [I] Key/IV 未就绪，跳过拦截，透传 {len(raw_buf)}B"
            f"（排查：确认 10_02 帧已正常处理并写入 self._3366_aes）"
        )
        out = bytes(raw_buf)
        del raw_buf[:]
        return out

    # ── game_init：kv 已就绪，说明是真正的 3366 通道，可安全注册到状态表 ──
    # 暗区专项版固定使用 az。
    if conn_label:
        _new_gid = "az"
        _stored_gid = buf_dict.get(_GAME_KEY)
        if _stored_gid != _new_gid:
            buf_dict[_GAME_KEY] = _new_gid
            log_bus.dl_intercept_event.emit(conn_label, "game_init", _new_gid)

    output = bytearray()
    pos = 0

    while pos < len(raw_buf):
        fp = _find_valid_magic(raw_buf, pos)
        if fp < 0:
            # 剩余均为非 3366 字节，直接透传
            output.extend(raw_buf[pos:])
            pos = len(raw_buf)
            break

        # MAGIC 之前的字节立即透传
        if fp > pos:
            output.extend(raw_buf[pos:fp])
            pos = fp

        # 至少需要 8 字节才能判断消息类型
        if pos + 8 > len(raw_buf):
            # 原因[III/IV] 的前置条件：帧头不足
            break

        msg = bytes(raw_buf[pos + 6: pos + 8])

        if msg == MSG_DATA:
            # 40 13 帧：用 enc_len 精确确定帧边界，不依赖下一个 MAGIC
            if pos + 25 > len(raw_buf):
                # 原因[III]：帧头（25字节）还未完全到达
                log_bus.dl_intercept_log.emit(
                    f"[{conn_id}] [III] 40_13 帧头不完整，缓冲等待"
                    f"（已有={len(raw_buf) - pos}B，需要至少 25B）"
                )
                break
            enc_len = struct.unpack_from(">H", raw_buf, pos + 19)[0]
            if enc_len == 0 or enc_len % 16 != 0:
                # 原因[II]：MAGIC 是碰撞字节
                log_bus.dl_intercept_log.emit(
                    f"[{conn_id}] [II] pos={pos} 处的 MAGIC 为碰撞字节"
                    f"（enc_len={enc_len} 不合法，应为 16 的正整数倍），跳过 1 字节继续扫描"
                )
                output.append(raw_buf[pos])
                pos += 1
                continue
            frame_end = pos + 25 + enc_len
            if frame_end > len(raw_buf):
                # 原因[III]：密文尚未完整到达
                log_bus.dl_intercept_log.emit(
                    f"[{conn_id}] [III] 40_13 帧密文未到齐，缓冲等待"
                    f"（已有={len(raw_buf) - pos}B，需要={25 + enc_len}B，"
                    f"enc_len={enc_len}，缺={frame_end - len(raw_buf)}B）"
                )
                break

            frame = bytes(raw_buf[pos:frame_end])
            frame_total = 25 + enc_len   # 总帧字节数（头25B + 密文enc_len B）

            # 小帧不含暗区目标串也不是块下发帧，直接透传。
            _STRING_MIN_FRAME = 1000
            if frame_total <= _STRING_MIN_FRAME:
                output.extend(frame)
                pos = frame_end
                continue

            # ── 帧类型判断 ────────────────────────────────────────────────────
            # 1081B（enc_len=1056）= 块下发帧 → 走块填充检测，不做字符串替换
            # 其他大帧（>1000B）   = 普通大包 → 走字符串替换检测，跳过块填充
            _CHUNK_ENC_LEN = 1056
            _is_block_frame = (enc_len == _CHUNK_ENC_LEN)

            _skip_chunk = (
                app_config.get("ace_chunk_block_enabled")
                and not _is_block_frame   # 非1081B帧跳过块填充
            )
            _eff_search = "" if _is_block_frame else search_str  # 1081B帧不做字符串替换

            # 两项均不需要时直接透传。
            if _skip_chunk and not _eff_search:
                output.extend(frame)
                pos = frame_end
                continue

            modified, was_str_replaced, was_chunk_dropped = \
                _intercept_one_3366_frame(
                    frame, kv, _eff_search, replace_str, conn_id, client_ip, conn_label,
                    skip_chunk_block=_skip_chunk,
                )
            output.extend(modified)
            pos = frame_end

            if was_str_replaced:
                # 字符串替换成功：标记本连接已完成，剩余缓冲全部透传，退出拦截循环
                buf_dict[_DONE_KEY] = True
                log_bus.dl_intercept_log.emit(
                    f"[{conn_id}] [DONE] 字符串替换成功，本连接后续帧全部直接透传"
                    f"（等待新 10_01 登录帧触发重置）"
                )
                output.extend(raw_buf[pos:])
                pos = len(raw_buf)
                break
            # was_chunk_dropped=True：不设 DONE_KEY，继续扫描后续帧

        else:
            # 非数据帧（10 01 握手 / 10 02 密钥下发等）：原样透传，绝不缓冲。
            # 【重要】若此处 break 等待下一帧 MAGIC，握手帧会被憋在缓冲区，
            # 客户端收不到就不会发下一请求，服务端也不会再发数据，形成死锁导致登录失败。
            msg_hex_str = msg.hex().upper()
            nxt = _find_valid_magic(raw_buf, pos + 2)
            if nxt < 0:
                # 后面没有更多 3366 帧 → 剩余字节全部立即透传，结束本轮
                log_bus.dl_intercept_log.emit(
                    f"[{conn_id}] [IV] 非数据帧 msg={msg_hex_str}，"
                    f"无后续 MAGIC，透传剩余 {len(raw_buf) - pos}B"
                )
                output.extend(raw_buf[pos:])
                pos = len(raw_buf)
                break
            # 找到下一帧 MAGIC → 把当前帧（到 nxt）立即透传
            log_bus.dl_intercept_log.emit(
                f"[{conn_id}] [IV] 非数据帧 msg={msg_hex_str}，"
                f"透传 {nxt - pos}B（到下一帧 MAGIC pos={nxt}）"
            )
            output.extend(raw_buf[pos:nxt])
            pos = nxt

    del raw_buf[:pos]

    if not output and len(raw_buf) > 0:
        # 原因[V]：本轮没有任何可输出字节
        log_bus.dl_intercept_log.emit(
            f"[{conn_id}] [V] 本轮无可输出字节，{len(raw_buf)}B 在缓冲区等待后续数据"
        )
    return bytes(output)


def reset_dl_intercept_done(buf_dict: dict, conn_id: str) -> None:
    """
    重置连接的"替换完成"标志，使下次下发拦截重新生效。
    应在 server.py 检测到新的 10 01（登录）帧时调用。
    """
    done_key = conn_id + '\x00done'
    buf_dict.pop(conn_id + '\x00game', None)  # 允许下次重新发送 game_init
    if buf_dict.pop(done_key, None) is not None:
        log_bus.dl_intercept_log.emit(
            f"[{conn_id}] [RESET] 检测到新 10_01 登录帧，拦截状态已重置"
        )
