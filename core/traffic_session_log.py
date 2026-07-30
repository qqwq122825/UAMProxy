# ─────────────────────────────────────────
# 运行目录下的会话级流量详单
# 日志文件说明：
#   tcp_raw.log               — 经过代理的 TCP 原始分片（上下行，长度>=阈值）
#   01_sliced.log             — 01 通道切片：录制收到的 / 3366明文中提取的 / 重放实际发出的
#   01_replace.log            — 01 重放替换详情（原始封包、替换后封包、verify 输出、UID）
#   33_uplink.log             — 33 上行帧：原始密文、解密明文、ASCII 可读显示
#   33_replace.log            — 33 重放替换详情（原始密文/明文 → 替换明文 → 重加密密文）
#   33_downlink.log           — 33 下行帧：前64B密文（用于对照 tcp_raw.log）+ 明文可打印字符串
#   3366_record_reason.log    — 33 未入池原因（Key未取、解密失败、明文无01切片等）
#   3366_raw_high_entropy_drop.log — 3366 含 01_0A_00_09/23 的丢包记录
# ─────────────────────────────────────────
from __future__ import annotations

import os
import re
import shutil
import threading
from datetime import datetime

from core.config import app_config
from core.packet_verify import format_01_packet_verify_report

MARKER_01_0A_00_09 = b"\x01\x0A\x00\x09"

_RUN_DIR_PATTERN = re.compile(r"^PyProxyTrafficLogs_\d{8}_\d{6}$")


def hex_slice_from_01_0a_00_09(data: bytes) -> str | None:
    """从首个 01 0A 00 09 起截到缓冲区末尾，转连续大写 hex（无空格）。"""
    i = data.find(MARKER_01_0A_00_09)
    if i < 0:
        return None
    return data[i:].hex().upper()


class TrafficSessionLog:
    """
    在进程首次写日志时于 os.getcwd() 下创建目录：
      PyProxyTrafficLogs_<YYYYMMDD_HHMMSS>/
    """

    _lock = threading.Lock()
    _dir: str | None = None

    @classmethod
    def enabled(cls) -> bool:
        # 专项采集开启时禁止常规详单落盘；专项文件由独立写入函数处理。
        return (
            bool(app_config.get("traffic_session_log_enabled", True))
            and not bool(app_config.get("special_dual_capture_mode_enabled", False))
        )

    @classmethod
    def _allow(cls, username: str) -> bool:
        """检查该用户是否在日志白名单内。白名单为空则允许所有用户。"""
        raw = (app_config.get("traffic_log_user_filter") or "").strip()
        if not raw:
            return True
        allowed = {u.strip() for u in raw.split(",") if u.strip()}
        return username in allowed

    @classmethod
    def clear_previous_run_dirs_and_reset_state(cls) -> int:
        """
        删除当前工作目录下所有 PyProxyTrafficLogs_<日期>_<时间>/ 目录，
        并重置本进程的详单目录句柄（下次写入会建新目录）。
        不修改录制内存池 recording_pool。
        返回成功删除的目录个数。
        """
        removed = 0
        base = os.getcwd()
        with cls._lock:
            cls._dir = None
            try:
                for name in os.listdir(base):
                    if not _RUN_DIR_PATTERN.match(name):
                        continue
                    path = os.path.join(base, name)
                    if not os.path.isdir(path):
                        continue
                    try:
                        shutil.rmtree(path, ignore_errors=True)
                        removed += 1
                    except OSError:
                        pass
            except OSError:
                pass
        return removed

    @classmethod
    def reset_session_state_only(cls) -> None:
        """仅清空当前进程内的详单目录句柄，不删磁盘目录（下次写入会新建 PyProxyTrafficLogs_*）。"""
        with cls._lock:
            cls._dir = None

    @classmethod
    def ensure_log_dir_ready(cls) -> str | None:
        """代理启动时预创建详单目录，确保用户登录等流量到达时能立即写入。"""
        return cls._ensure_dir()

    @classmethod
    def min_len(cls) -> int:
        try:
            return max(0, int(app_config.get("traffic_log_min_len", 10)))
        except (TypeError, ValueError):
            return 10

    @classmethod
    def _ensure_dir(cls) -> str | None:
        if not cls.enabled():
            return None
        if cls._dir and os.path.isdir(cls._dir):
            return cls._dir
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.getcwd()
        cls._dir = os.path.join(base, f"PyProxyTrafficLogs_{stamp}")
        os.makedirs(cls._dir, exist_ok=True)
        readme = os.path.join(cls._dir, "README.txt")
        try:
            with open(readme, "w", encoding="utf-8") as f:
                f.write(
                    "本目录为 UAMProxy 自动生成的流量详单。\n"
                    "- tcp_raw.log                    : 经过代理的 TCP 原始分片（上下行，长度>=配置阈值）\n"
                    "- 01_sliced.log                  : 01 通道切片（录制收到 / 3366明文提取 / 重放实际发出）\n"
                    "- 01_replace.log                 : 01 重放替换（原始封包、替换后封包、verify 输出、UID）\n"
                    "- 33_uplink.log                  : 33 上行帧（原始密文、解密明文、ASCII 可读显示）\n"
                    "- 33_replace.log                 : 33 重放替换（原始密文/明文 → 替换明文 → 重加密密文）\n"
                    "- 33_downlink.log                : 33 下行帧（前64B密文 + 明文可打印字符串，对照 tcp_raw.log）\n"
                    "- 3366_record_reason.log         : 33 未入池原因（Key未取、解密失败、明文无01切片等）\n"
                    "- 3366_raw_high_entropy_drop.log : 3366 含 01_0A_00_09/23 的丢包记录\n"
                )
        except OSError:
            pass
        return cls._dir

    @classmethod
    def _append(cls, filename: str, text: str) -> None:
        if not cls.enabled():
            return
        with cls._lock:
            d = cls._ensure_dir()
            if not d:
                return
            path = os.path.join(d, filename)
            try:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(text)
            except OSError:
                pass

    # ── 格式化工具 ──────────────────────────────────────────────────

    @classmethod
    def _wrap_hex(cls, hex_str: str, chars_per_line: int = 64) -> str:
        """将长 hex 按行换行，避免单行过长难以阅读"""
        if len(hex_str) <= chars_per_line:
            return hex_str
        lines = []
        for i in range(0, len(hex_str), chars_per_line):
            lines.append(hex_str[i: i + chars_per_line])
        return "\n".join(lines)

    @classmethod
    def _hexdump(cls, data: bytes, bytes_per_line: int = 16) -> str:
        """hexdump 风格：偏移 + 空格分隔 hex + ASCII 列（不可打印用 '.'）"""
        lines = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i: i + bytes_per_line]
            hex_col = " ".join(f"{b:02X}" for b in chunk)
            asc_col = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            lines.append(f"  {i:04X}  {hex_col:<{bytes_per_line * 3}}  {asc_col}")
        return "\n".join(lines)

    @classmethod
    def _extract_printable(cls, data: bytes, min_run: int = 4) -> str:
        """
        从 bytes 中提取连续可打印 ASCII 字符串（长度 >= min_run），
        用 ' | ' 分隔，供 33 下行日志快速识别内容。
        """
        result: list[str] = []
        run: list[str] = []
        for b in data:
            if 0x20 <= b < 0x7F:
                run.append(chr(b))
            else:
                if len(run) >= min_run:
                    result.append("".join(run))
                run = []
        if len(run) >= min_run:
            result.append("".join(run))
        return " | ".join(result) if result else "(无可打印字符串)"

    @classmethod
    def _decode_utf8_text(cls, data: bytes) -> str:
        """尝试 UTF-8 解码，不可解码字节用 · 替代，控制字符用 · 替代"""
        text = data.decode("utf-8", errors="replace")
        out = []
        for ch in text:
            if ch == "\ufffd" or (ord(ch) < 0x20 and ch not in "\n\r\t"):
                out.append("·")
            else:
                out.append(ch)
        return "".join(out)

    # ── 日志函数 ────────────────────────────────────────────────────

    @classmethod
    def log_tcp_raw(
        cls,
        *,
        conn_id: str,
        direction: str,
        dst: str,
        mode: str,
        label: str,
        data: bytes,
        username: str = "",
    ) -> None:
        """tcp_raw.log — 经过代理的 TCP 原始分片（上下行，全量记录）"""
        if not cls._allow(username):
            return
        if not data:
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        hx = data.hex().upper()
        meta = f"{ts}\t{label}\t{mode}\t{conn_id}\t{direction}\t{dst}\t{len(data)}"
        if len(hx) <= 64:
            line = f"{meta}\t{hx}\n"
        else:
            line = f"{meta}\n{cls._wrap_hex(hx)}\n"
        cls._append("tcp_raw.log", line)

    @classmethod
    def log_01_sliced(
        cls,
        *,
        kind: str,
        direction: str = "",
        uid: str = "",
        data: bytes,
        username: str = "",
    ) -> None:
        """
        01_sliced.log — 01 00 协议 TCP 原始帧记录（完整帧，不做子段提取）。
          kind="recv"   录制/重放端从网络收到的完整 01 00 帧
          kind="sent"   重放端替换后实际发出的完整 01 00 帧
        上下行（direction=↑UP/↓DOWN）、UID 均记录，数据为连续大写 hex。
        """
        if not cls._allow(username):
            return
        if not data:
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        dir_tag = direction if direction else "-"
        uid_tag = uid if uid else "-"
        hx = data.hex().upper()
        header = f"{ts}  kind={kind}  dir={dir_tag}  uid={uid_tag}  LEN={len(data)}\n"
        if len(hx) <= 128:
            body = f"  {hx}\n"
        else:
            body = f"  {cls._wrap_hex(hx)}\n"
        cls._append("01_sliced.log", header + body + "\n")

    @classmethod
    def log_01_replace(
        cls,
        *,
        orig_packet: bytes,
        new_packet: bytes,
        pool_idx: int,
        uid: str = "",
        username: str = "",
    ) -> None:
        """
        01_replace.log — 01 重放替换详情（无条数上限，由用户过滤控制）。
        记录：原始封包 hexdump、替换后封包 hexdump、双份 verify 输出、UID。
        """
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        uid_tag = uid if uid else "-"
        blk = [
            f"\n{'=' * 64}\n",
            f"{ts}  01 REPLACE  uid={uid_tag}  pool_idx={pool_idx}\n",
            "----- 原始封包 HEX+ASCII -----\n",
            cls._hexdump(orig_packet),
            "\n",
            format_01_packet_verify_report(orig_packet),
            "\n----- 替换后封包 HEX+ASCII（实际发出） -----\n",
            cls._hexdump(new_packet),
            "\n",
            format_01_packet_verify_report(new_packet),
            "\n",
        ]
        cls._append("01_replace.log", "".join(blk))

    @classmethod
    def log_33_uplink(
        cls,
        *,
        conn_id: str,
        client_ip: str,
        uid: str = "",
        mode: str = "",
        cipher_bytes: bytes,
        plain_bytes: bytes | None,
        username: str = "",
    ) -> None:
        """
        33_uplink.log — 33 上行帧（录制 / 重放两侧均记录）。
        记录：原始密文 hex、解密明文 hex、明文 ASCII 显示。
        """
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        uid_tag = uid if uid else "-"
        plain_len = len(plain_bytes) if plain_bytes else 0
        header = (
            f"{ts}  ↑UP  {conn_id}  {client_ip}  uid={uid_tag}  mode={mode or '-'}  "
            f"CIPHER={len(cipher_bytes)}B  PLAIN={plain_len}B\n"
        )
        parts = [header]
        parts.append(f"  CIPHER({len(cipher_bytes)}B):\n{cls._hexdump(cipher_bytes)}\n")
        if plain_bytes:
            printable = cls._extract_printable(plain_bytes)
            parts.append(f"  PLAIN_PRINTABLE: {printable}\n")
            parts.append(f"  PLAIN_FULL({plain_len}B):\n{cls._hexdump(plain_bytes)}\n")
            parts.append(f"  PLAIN_TEXT:\n  {cls._decode_utf8_text(plain_bytes)}\n")
        else:
            parts.append("  PLAIN: (未解密)\n")
        cls._append("33_uplink.log", "".join(parts) + "\n")

    @classmethod
    def log_33_replace(
        cls,
        *,
        conn_id: str,
        client_ip: str,
        uid: str = "",
        orig_frame: bytes,
        new_frame: bytes,
        orig_cipher: bytes,
        orig_plain: bytes,
        new_plain: bytes,
        new_cipher: bytes,
        seq: int | None = None,
        username: str = "",
    ) -> None:
        """
        33_replace.log — 33 重放替换详情（无条数上限，由用户过滤控制）。
        记录：原始密文、原始明文（+ASCII）、替换后明文（+ASCII）、重加密密文。
        """
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        uid_tag = uid if uid else "-"
        seq_str = f"  seq={seq}" if seq is not None else ""
        orig_plain_asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in orig_plain)
        new_plain_asc  = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in new_plain)
        blk = [
            f"\n{'=' * 64}\n",
            f"{ts}  33 REPLACE  uid={uid_tag}  conn={conn_id}  ip={client_ip}"
            f"  frame={len(orig_frame)}B  cipher={len(orig_cipher)}B  plain={len(orig_plain)}B{seq_str}\n",
            "----- 原始密文 HEX -----\n",
            cls._wrap_hex(orig_cipher.hex().upper()),
            "\n----- 原始明文 HEX -----\n",
            cls._wrap_hex(orig_plain.hex().upper()),
            f"\n  ASCII: {orig_plain_asc}\n",
            "----- 替换后明文 HEX -----\n",
            cls._wrap_hex(new_plain.hex().upper()),
            f"\n  ASCII: {new_plain_asc}\n",
            "----- 重加密密文 HEX（实际发出） -----\n",
            cls._wrap_hex(new_cipher.hex().upper()),
            "\n",
        ]
        cls._append("33_replace.log", "".join(blk))

    @classmethod
    def log_33_downlink(
        cls,
        *,
        conn_id: str,
        client_ip: str,
        cipher_bytes: bytes,
        plain_bytes: bytes | None,
        username: str = "",
    ) -> None:
        """
        33_downlink.log — 33 下行帧（所有帧均记录，无论能否解密）。
        记录前 64B 原始密文 hex（便于在 tcp_raw.log 中定位）+ 明文中的可打印字符串。
        """
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        cipher_head = cipher_bytes[:64]
        plain_len = len(plain_bytes) if plain_bytes else 0
        header = (
            f"{ts}  ↓DOWN  {conn_id}  {client_ip}  "
            f"CIPHER={len(cipher_bytes)}B  PLAIN={plain_len}B\n"
        )
        parts = [header]
        parts.append(f"  CIPHER({len(cipher_bytes)}B):\n{cls._hexdump(cipher_bytes)}\n")
        if plain_bytes:
            printable = cls._extract_printable(plain_bytes)
            parts.append(f"  PLAIN_PRINTABLE: {printable}\n")
            parts.append(f"  PLAIN_FULL({plain_len}B):\n{cls._hexdump(plain_bytes)}\n")
            parts.append(f"  PLAIN_TEXT:\n  {cls._decode_utf8_text(plain_bytes)}\n")
        else:
            parts.append("  PLAIN: (未解密)\n")
        parts.append("\n")
        cls._append("33_downlink.log", "".join(parts))

    @classmethod
    def log_3366_record_reason(
        cls,
        *,
        client_ip: str,
        conn_id: str,
        reason: str,
        detail: str = "",
        username: str = "",
        uid: str = "",
    ) -> None:
        """3366_record_reason.log — 33 未入池时写入原因，便于排查"""
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        uid_tag = f"\tUID={uid}" if uid else ""
        line = f"{ts}\t{client_ip}\t{conn_id}{uid_tag}\t{reason}"
        if detail:
            line += f"\t{detail}"
        line += "\n"
        cls._append("3366_record_reason.log", line)

    @classmethod
    def log_3366_raw_high_entropy_drop(
        cls,
        *,
        conn_id: str,
        client_ip: str,
        direction: str,
        msg_hex: str,
        frame_len: int,
        frame_full_hex: str | None = None,
        username: str = "",
    ) -> None:
        """3366_raw_high_entropy_drop.log — 3366 含 01 0A 00 09 或 01 0A 00 23 丢包记录"""
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        line = (
            f"\n{ts}\t{conn_id}\t{client_ip}\t{direction}\tmsg={msg_hex}\t"
            f"frame_len={frame_len}B\n"
        )
        if frame_full_hex:
            line += "----- 原始请求完整 HEX -----\n"
            line += cls._wrap_hex(frame_full_hex)
            line += "\n\n"
        cls._append("3366_raw_high_entropy_drop.log", line)

    # ── 旧接口兼容层（转发到新函数，调用点逐步迁移后可移除） ─────────

    @classmethod
    def log_tcp_chunk(cls, *, conn_id, direction, dst, mode, label, data, username=""):
        cls.log_tcp_raw(conn_id=conn_id, direction=direction, dst=dst,
                        mode=mode, label=label, data=data, username=username)

    @classmethod
    def log_sliced_01_0a_line(cls, source: str, data: bytes, username: str = "") -> None:
        pass  # 已由 log_01_sliced 替代，此接口废弃

    @classmethod
    def log_3366_trace(cls, **kwargs) -> None:
        pass  # 已拆分到 33_uplink.log / 33_downlink.log

    @classmethod
    def log_3366_user_detail(cls, **kwargs) -> None:
        pass  # 已合并到 33_uplink.log

    @classmethod
    def log_3366_replay_replace(cls, *, conn_id, client_ip, orig_frame, new_frame,
                                 orig_cipher, orig_plain, new_plain, new_cipher,
                                 seq=None, username=""):
        cls.log_33_replace(conn_id=conn_id, client_ip=client_ip,
                           orig_frame=orig_frame, new_frame=new_frame,
                           orig_cipher=orig_cipher, orig_plain=orig_plain,
                           new_plain=new_plain, new_cipher=new_cipher,
                           seq=seq, username=username)

    @classmethod
    def log_3366_replay_uplink_frame(cls, *, conn_id, client_ip, msg_hex,
                                      frame, plain_hex=None, skip_reason, username=""):
        plain_bytes = bytes.fromhex(plain_hex) if plain_hex else None
        cls.log_33_uplink(conn_id=conn_id, client_ip=client_ip, mode="replay",
                          cipher_bytes=frame, plain_bytes=plain_bytes, username=username)

    @classmethod
    def log_3366_replay_downlink_trace(cls, *, conn_id, client_ip, msg_hex,
                                        frame, plain_bytes, username=""):
        cls.log_33_downlink(conn_id=conn_id, client_ip=client_ip,
                            cipher_bytes=frame, plain_bytes=plain_bytes, username=username)

    @classmethod
    def log_01_replay_replace_pair(cls, *, orig_packet, new_packet, pool_idx, username=""):
        cls.log_01_replace(orig_packet=orig_packet, new_packet=new_packet,
                           pool_idx=pool_idx, username=username)


traffic_file_logger = TrafficSessionLog
