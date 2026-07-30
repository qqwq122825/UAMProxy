from __future__ import annotations
import os
import traceback
from datetime import datetime
from PySide6.QtCore import QObject, Signal

# ─────────────────────────────────────────
# 全局事件总线
# ─────────────────────────────────────────
class LogBus(QObject):
    # 业务事件日志（显示在系统日志 Tab）
    event_log  = Signal(str, str, str)   # (level, tag, message)
    # 连接状态
    conn_added = Signal(str, str, str, str, str)   # (conn_id, src, dst, user, mode)
    conn_closed= Signal(str)                   # conn_id
    stream_raw_data = Signal(str, str, int, bytes)        # (conn_id, direction, length, raw_bytes)
    stream_parsed_data = Signal(str, str, str, int, bytes)# (conn_id, direction, hex_str_preview, length, raw_bytes)
    stream_sent_data = Signal(str, str, int, bytes)       # (conn_id, direction, length, raw_bytes)

    # 录制池结构变化（新会话/停止/游戏ID就绪）→ 全量刷新录制管理 Tab
    record_updated = Signal()
    # 录制计数轻量更新（每包）→ 只更新对应行的"加密区数"列，不重建表
    record_count   = Signal(str, int)          # (sid, pool_count)
    # 重放连接详情日志（每条替换记录）→ 详情对话框
    conn_detail    = Signal(str, str)          # (client_ip, log_line)
    # 重放进度更新 → 连接表"重放进度"列
    replay_progress = Signal(str, int, int)    # (client_ip, current_idx, total) 兼容旧逻辑
    # 重放进度详情（01/33 分开展示，33 细分 09/21/01回退）
    replay_progress_detail = Signal(
        str, int, int, int, int, int, int, int, int, int
    )  # (client_ip, cur01, total01, cur33, total33, cur09, total09, cur21, total21, cur01_fb)
    # 连接模式更新 → 连接表"模式"列（"重放(待验证)" / "重放" / "透传"）
    conn_mode_update = Signal(str, str)        # (client_ip, mode_text)
    # 游戏 ID 更新 -> 连接表 "游戏 ID" 列
    conn_game_id_update = Signal(str, str, str)     # (client_ip, game_id, mode)
    # 3366 产品识别 -> 连接表「账户/游戏」列回退显示（如暗区 0000094E）
    conn_3366_product = Signal(str, str, str)     # (client_ip, product_hex8, product_name)
    # 01 / 3366 两侧账号串任一更新 → 刷新连接表「账户/游戏」对账显示
    conn_ace_channels_updated = Signal(str)       # (client_ip)
    # 远程管理日志（登录 IP、创建账号等）-> 远程管理 Tab 专用
    admin_log = Signal(str)                         # (formatted_line)
    # 下发拦截日志 -> 下发拦截 Tab 专用（全局文本框，调试用）
    dl_intercept_log = Signal(str)                  # (formatted_line)
    # 下发拦截事件 -> 按账户统计 + 详情弹窗
    # event_type: "str_replace" | "chunk_drop"
    dl_intercept_event = Signal(str, str, str)      # (account_label, event_type, message)
    # 用户列表更新
    users_updated = Signal()

log_bus = LogBus()


def _event(level: str, tag: str, msg: str):
    """业务事件日志，会显示在系统日志 Tab（不含原始 Hex）"""
    log_bus.event_log.emit(level, tag, msg)


def _admin_log(msg: str):
    """远程管理专用日志，显示在远程管理 Tab"""
    log_bus.admin_log.emit(msg)


_ERR_LOG_PATH: str | None = None

def _log_exc(tag: str = "") -> None:
    """
    将当前异常的完整 traceback 追加写入运行目录下的 error.log。
    · append 模式，重启不清空，便于长期运行时排查偶发异常。
    · 写入失败时静默忽略，绝不因日志本身影响主流程。
    """
    global _ERR_LOG_PATH
    try:
        if _ERR_LOG_PATH is None:
            _ERR_LOG_PATH = os.path.join(os.getcwd(), "error.log")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tb = traceback.format_exc()
        line = f"[{ts}] [{tag}]\n{tb}\n"
        with open(_ERR_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def _fmt_dur(seconds: int) -> str:
    """将秒数格式化为可读时长：刚刚 / Xm / Xh Ym"""
    if seconds < 60:
        return "刚刚"
    m = seconds // 60
    if m < 60:
        return f"{m}分"
    h, rm = divmod(m, 60)
    return f"{h}小时{rm}分" if rm else f"{h}小时"
