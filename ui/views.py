import os
import re
import time
from datetime import datetime, date
import asyncio
import threading
from core.build_info import BUILD_GIT_SHA, BUILD_TIME_UTC

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QPlainTextEdit, QGroupBox,
    QCheckBox, QSpinBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QStatusBar, QDateEdit, QMessageBox,
    QDialog, QFormLayout, QDialogButtonBox, QAbstractItemView, QFileDialog,
    QComboBox, QFrame, QSizePolicy, QGridLayout,
)
from PySide6.QtCore import Qt, Signal, QObject, QDate, QTimer, QUrl
from PySide6.QtGui import QColor, QFont, QTextCursor, QDesktopServices

APP_VERSION = "v1.102"

from core.config import app_config
from core.ace_display import build_ace_identifier_lookup, ace_identifier_display
from core.events import log_bus, _event, _fmt_dur
from core.managers import user_manager, local_map_manager
from core.pool import recording_pool
from core.server import engine, _check_external_proxy
from core.special_capture import special_capture_manager

# 录制池「前16字节」列说明：仅记录 01 0A 00 09/21 块，以 01 0A 00 09 或 0A 00 09 开头
_REC_ANCHOR_TOOLTIP = {
    "01_0a_09": "锚点 01 0A 00 09，以下为该头之后 +14 字节起的高熵替换区（列表 Hex 不含 01 0A 00 09）。",
    "01_0a_21": "锚点 01 0A 00 21，以下为该头之后 +14 字节起的高熵替换区。",
    "01_0a_xx": "01 0A 00 09/21 相关锚点，高熵区起点已按协议偏移。",
    "legacy_0a_09": "旧版锚点 0A 00 09（+3 字节）之后的高熵区，非 01 0A 00 09 结构。",
}

# ─────────────────────────────────────────
# 连接重放详情对话框（非模态，可多开）
# ─────────────────────────────────────────
class ConnDetailDialog(QDialog):
    """
    显示单个来源 IP 的重放详细日志：
      · 01 替换：每条 01 00 包的替换记录（池索引、加密区长度等）
      · 33 替换：09/21 用 33 池或 01 池回退的第几个、累计次数
    """
    def __init__(self, client_ip: str, parent=None):
        super().__init__(parent)
        self.client_ip = client_ip
        self.setWindowTitle(f"重放详情 — {client_ip}")
        self.resize(780, 560)
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinimizeButtonHint)

        v = QVBoxLayout(self)
        v.setContentsMargins(8, 8, 8, 6)

        # 进度条文字
        self.lbl_progress = QLabel("重放进度：—")
        self.lbl_progress.setStyleSheet("font-weight:bold;color:#ce93d8;")
        v.addWidget(self.lbl_progress)

        # 01 / 33 分 Tab 日志
        from PySide6.QtWidgets import QTabWidget
        self.tabs = QTabWidget()
        self.log_01 = QTextEdit()
        self.log_01.setReadOnly(True)
        self.log_01.setFont(QFont("Consolas", 9))
        self.log_01.setStyleSheet("background:#0d1117;color:#c9d1d9;")
        self.log_01.setPlaceholderText("01 包替换记录（池索引、加密区长度等）")
        self.log_33 = QTextEdit()
        self.log_33.setReadOnly(True)
        self.log_33.setFont(QFont("Consolas", 9))
        self.log_33.setStyleSheet("background:#0d1117;color:#c9d1d9;")
        self.log_33.setPlaceholderText("33 帧替换记录（09/21 用 33 池或 01 池回退第几个）")
        self.tabs.addTab(self.log_01, "01 替换")
        self.tabs.addTab(self.log_33, "33 替换")
        v.addWidget(self.tabs)
        self.log = self.log_01  # 兼容 append 调用

        # 底部按钮
        bar = QHBoxLayout()
        bar.addStretch()
        btn_clr = QPushButton("清空日志"); btn_clr.setFixedWidth(80)
        btn_clr.clicked.connect(self._clear_logs)
        btn_close = QPushButton("关闭"); btn_close.setFixedWidth(60)
        btn_close.clicked.connect(self.close)
        bar.addWidget(btn_clr); bar.addWidget(btn_close)
        v.addLayout(bar)

    def closeEvent(self, event):
        if self.parent() and hasattr(self.parent(), "_detail_dialogs"):
            self.parent()._detail_dialogs.pop(self.client_ip, None)
        event.accept()

    def _clear_logs(self):
        self.log_01.clear()
        self.log_33.clear()

    def append(self, line: str):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        escaped = _esc(line).replace("\n", "<br>")
        html = f'<span style="color:#555">[{ts}]</span> {escaped}'
        if line.strip().startswith("[33]"):
            self.log_33.append(html)
            self.log_33.ensureCursorVisible()
        else:
            self.log_01.append(html)
            self.log_01.ensureCursorVisible()

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

    def set_progress_detail(
        self,
        cur01: int, total01: int, cur33: int, total33: int,
        cur09: int = 0, total09: int = 0, cur21: int = 0, total21: int = 0,
        cur01_fb: int = 0,
    ):
        """更新进度标签为 01/33 分开展示"""
        if total01 <= 0 and total33 <= 0:
            return
        parent = self.parent()
        if parent and hasattr(parent, "_format_replay_progress_text"):
            text = parent._format_replay_progress_text(
                cur01, total01, cur33, total33, cur09, total09, cur21, total21, cur01_fb,
            )
            if text and text != "—":
                self.lbl_progress.setText(
                    f"重放进度：<b style='color:#ce93d8'>{text}</b>"
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
        self.edit_passwd = QLineEdit()
        self.edit_note   = QLineEdit()
        self.cb_never    = QCheckBox("永不过期"); self.cb_never.setChecked(True)
        self.date_expire = QDateEdit(QDate.currentDate().addYears(1))
        self.date_expire.setCalendarPopup(True)
        self.date_expire.setEnabled(False)
        self.cb_never.toggled.connect(lambda v: self.date_expire.setEnabled(not v))
        self.cb_multi    = QCheckBox("允许同账户多 IP 同时在线（测试/内部使用）")
        self.cb_multi.setChecked(False)
        self.cb_perm     = QComboBox()
        self.cb_perm.addItem("录制 + 重放", "both")
        self.cb_perm.addItem("仅录制", "record")
        self.cb_perm.addItem("仅重放", "replay")

        form.addRow("用户名:", self.edit_uname)
        form.addRow("密码:",   self.edit_passwd)
        form.addRow("备注:",   self.edit_note)
        expire_row = QHBoxLayout()
        expire_row.addWidget(self.cb_never)
        expire_row.addWidget(self.date_expire)
        form.addRow("到期时间:", expire_row)
        form.addRow("权限类型:", self.cb_perm)
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
            "perm":        self.cb_perm.currentData(),
        }


# ─────────────────────────────────────────
# 下发拦截详情对话框（非模态，可多开）
# ─────────────────────────────────────────
class DlInterceptDetailDialog(QDialog):
    """
    显示单个账户的下发拦截实时日志：
      · 绿色 ✓ = 字符串替换事件
      · 蓝色 ★ = 块填充事件
    """
    def __init__(self, account_label: str, parent=None):
        super().__init__(parent)
        self.account_label = account_label
        self.setWindowTitle(f"下发拦截详情 — {account_label}")
        self.resize(700, 460)
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinimizeButtonHint)

        v = QVBoxLayout(self)
        v.setContentsMargins(8, 8, 8, 6)

        self.lbl_summary = QLabel(
            "下发拦截统计（与主表「下发」列一致，不含上行命中）"
        )
        self.lbl_summary.setStyleSheet(
            "font-weight:bold; color:#4ade80; font-size:12px; padding:2px 0;"
        )
        v.addWidget(self.lbl_summary)

        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Consolas", 9))
        self.log_edit.setStyleSheet("background:#0d1117; color:#c9d1d9;")
        v.addWidget(self.log_edit)

        bar = QHBoxLayout()
        bar.addStretch()
        btn_clr = QPushButton("清空日志")
        btn_clr.setFixedWidth(80)
        btn_clr.clicked.connect(self.log_edit.clear)
        btn_close = QPushButton("关闭")
        btn_close.setFixedWidth(60)
        btn_close.clicked.connect(self.close)
        bar.addWidget(btn_clr)
        bar.addWidget(btn_close)
        v.addLayout(bar)

    def closeEvent(self, event):
        if self.parent() and hasattr(self.parent(), "_dl_intercept_detail_dialogs"):
            self.parent()._dl_intercept_detail_dialogs.pop(self.account_label, None)
        event.accept()

    def append_event(self, event_type: str, message: str):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if event_type == "str_replace":
            color, icon = "#4ade80", "✓"
        elif event_type == "chunk_drop":
            color, icon = "#60a5fa", "★"
        elif event_type == "01_drop":
            color, icon = "#f59e0b", "▼"
        else:  # "diag" 诊断信息
            color, icon = "#888888", "·"
        escaped = _esc(message).replace("\n", "<br>")
        html = (
            f'<span style="color:#555">[{ts}]</span> '
            f'<span style="color:{color}">{icon}</span> {escaped}'
        )
        self.log_edit.append(html)
        self.log_edit.ensureCursorVisible()

    def update_summary_from_stats(self, stats: dict) -> None:
        self.lbl_summary.setText(
            f"01拦截: {stats.get('01_drop', 0)}  |  "
            f"33替换: {stats.get('str_replace', 0)}  |  "
            f"块清零: {stats.get('chunk_drop', 0)}"
        )


# ─────────────────────────────────────────
# 上行拦截日志弹窗
# ─────────────────────────────────────────
class UlInterceptDetailDialog(QDialog):
    """显示单个账户的上行拦截扫描诊断日志"""

    def __init__(self, account_label: str, parent=None):
        super().__init__(parent)
        self.account_label = account_label
        self.setWindowTitle(f"上行拦截日志 — {account_label}")
        self.resize(760, 460)
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinimizeButtonHint)

        v = QVBoxLayout(self)
        v.setContentsMargins(8, 8, 8, 6)

        self.lbl_summary = QLabel("上行命中: 0  |  扫描帧: 0")
        self.lbl_summary.setStyleSheet(
            "font-weight:bold; color:#fb923c; font-size:12px; padding:2px 0;"
        )
        v.addWidget(self.lbl_summary)

        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Consolas", 9))
        self.log_edit.setStyleSheet("background:#0d1117; color:#c9d1d9;")
        v.addWidget(self.log_edit)

        bar = QHBoxLayout()
        bar.addStretch()
        btn_clr = QPushButton("清空日志")
        btn_clr.setFixedWidth(80)
        btn_clr.clicked.connect(self.log_edit.clear)
        btn_close = QPushButton("关闭")
        btn_close.setFixedWidth(60)
        btn_close.clicked.connect(self.close)
        bar.addWidget(btn_clr)
        bar.addWidget(btn_close)
        v.addLayout(bar)

        self._hit_count = 0
        self._scan_count = 0

    def closeEvent(self, event):
        if self.parent() and hasattr(self.parent(), "_ul_detail_dialogs"):
            self.parent()._ul_detail_dialogs.pop(self.account_label, None)
        event.accept()

    def append_log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self._scan_count += 1
        if "✅" in msg:
            color, icon = "#4ade80", "✅"
            self._hit_count += 1
        elif "❌" in msg:
            color, icon = "#f87171", "❌"
        elif "⚠" in msg:
            color, icon = "#facc15", "⚠"
        else:
            color, icon = "#9ca3af", "·"
        escaped = _esc(msg).replace("\n", "<br>")
        html = (
            f'<span style="color:#555">[{ts}]</span> '
            f'<span style="color:{color}">{icon}</span> '
            f'<span style="color:{color}">{escaped}</span>'
        )
        self.log_edit.append(html)
        self.log_edit.ensureCursorVisible()
        self.lbl_summary.setText(f"上行命中: {self._hit_count}  |  扫描帧: {self._scan_count}")


# ─────────────────────────────────────────
# 主界面
# ─────────────────────────────────────────
class MainWindow(QMainWindow):
    # 用于从非 Qt 线程回调到主线程
    _ext_check_done = Signal(bool, str)

    def __init__(self):
        super().__init__()
        build_tag = f" [{BUILD_GIT_SHA}]" if BUILD_GIT_SHA != "dev" else ""
        self.setWindowTitle(
            f"UAMProxy {APP_VERSION}{build_tag}  |  暗区突围专项代理"
        )
        self.setToolTip(
            f"版本: {APP_VERSION}\nGit: {BUILD_GIT_SHA}\n打包时间(UTC): {BUILD_TIME_UTC}"
        )
        self.resize(1150, 740)
        
        # Apply modern global stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f6fa;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #d1d5db;
                border-radius: 6px;
                margin-top: 12px;
                background-color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                color: #374151;
            }
            QTabWidget::pane {
                border: 1px solid #d1d5db;
                background: white;
                border-radius: 4px;
            }
            QTabBar::tab {
                background: #e5e7eb;
                color: #4b5563;
                padding: 8px 16px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: white;
                color: #2563eb;
                border: 1px solid #d1d5db;
                border-bottom-color: white;
                font-weight: bold;
            }
            QTabBar::tab:hover:!selected {
                background: #d1d5db;
            }
            QTableWidget {
                border: 1px solid #e5e7eb;
                gridline-color: #f3f4f6;
                selection-background-color: #eff6ff;
                selection-color: #1e3a8a;
                background-color: white;
            }
            QHeaderView::section {
                background-color: #f9fafb;
                color: #374151;
                font-weight: bold;
                padding: 6px;
                border: none;
                border-right: 1px solid #e5e7eb;
                border-bottom: 1px solid #e5e7eb;
            }
            QPushButton {
                background-color: #ffffff;
                border: 1px solid #d1d5db;
                color: #374151;
                padding: 5px 12px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #f3f4f6;
                border-color: #9ca3af;
            }
            QPushButton:pressed {
                background-color: #e5e7eb;
            }
            QLineEdit, QSpinBox {
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 4px 8px;
                background: white;
                min-height: 20px;
                min-width: 60px;
            }
            QSpinBox {
                padding-right: 20px; /* 给右侧的上下按钮留出空间 */
            }
            QSpinBox::up-button, QSpinBox::down-button {
                width: 16px;
                border: none;
                border-left: 1px solid #d1d5db;
                background: #f9fafb;
            }
            QSpinBox::up-arrow {
                width: 10px;
                height: 10px;
            }
            QSpinBox::down-arrow {
                width: 10px;
                height: 10px;
            }
            QSpinBox::up-button:hover, QSpinBox::down-button:hover {
                background: #e5e7eb;
            }
            QLineEdit:focus, QSpinBox:focus {
                border: 1px solid #3b82f6;
            }
            QCheckBox {
                color: #374151;
            }
        """)

        # 连接表：按 IP 分组，每个 IP 一行
        self._ip_rows:    dict[str, int] = {}    # ip → row index
        self._ip_active:  dict[str, int] = {}    # ip → 当前活跃连接数
        self._ip_rec_active: dict[str, int] = {} # ip → 当前活跃的录制连接数
        self._ip_rep_active: dict[str, int] = {} # ip → 当前活跃的重放连接数
        self._ip_total:   dict[str, int] = {}    # ip → 累计连接次数
        self._ip_rec_game_id: dict[str, str] = {} # ip → 最近录制的游戏 ID
        self._ip_rep_game_id: dict[str, str] = {} # ip → 最近重放的游戏 ID
        self._ip_3366_hex: dict[str, str] = {}   # ip → 3366 产品 8hex
        self._ip_3366_name: dict[str, str] = {}  # ip → 配置或帧内的产品名
        self._conn_info:  dict[str, tuple] = {}  # conn_id → (ip, mode)
        self._ip_last_active:  dict[str, datetime] = {}  # ip → 最后活跃时间（断开/连接）
        self._ip_online_since: dict[str, datetime] = {}  # ip → 本轮上线起始时间
        # 重放进度（连接表 + 详情对话框用）；详情日志仅在对话框打开时实时追加，不存储
        self._ip_replay_progress: dict[str, tuple] = {}        # ip → (current, total) 兼容
        self._ip_replay_progress_detail: dict[str, tuple] = {}  # ip → (cur01,total01,cur33,total33,cur09,total09,cur21,total21,cur01_fb)
        self._detail_dialogs:    dict[str, ConnDetailDialog] = {}  # ip → dialog
        self._rec_sid_rows:      dict[str, int] = {}               # sid → 录制管理表行号
        # 下发拦截统计（按账户）
        self._dl_intercept_stats:   dict[str, dict] = {}           # label → {ul_hit, 01_drop, str_replace, chunk_drop, last_active}
        self._dl_intercept_detail_dialogs: dict[str, DlInterceptDetailDialog] = {}
        self._dl_intercept_history: dict[str, list] = {}           # label → [(event_type, message), ...]
        self._ul_detail_dialogs:    dict[str, UlInterceptDetailDialog] = {}
        # 与 dl_intercept_history_labels 子串匹配的标签会缓存上行诊断日志（未打开弹窗也可稍后查看）
        self._ul_log_history:       dict[str, list[str]] = {}
        # 上行拦截黑名单：匹配字符串 → 命中次数；持久化在 app_config["ul_blacklist_strings"]
        self._ul_blacklist: dict[str, int] = {}                    # string → hit_count
        self._loading_config = False   # 加载期间屏蔽自动保存，防止中间状态覆盖磁盘值
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
        pl.addSpacing(16)
        pl.addWidget(QLabel("会话超时:"))
        self.spin_record_idle_timeout = QSpinBox()
        self.spin_record_idle_timeout.setRange(0, 3600)
        self.spin_record_idle_timeout.setValue(180)
        self.spin_record_idle_timeout.setSuffix(" 秒")
        self.spin_record_idle_timeout.setFixedWidth(80)
        self.spin_record_idle_timeout.setToolTip(
            "录制/重放端口连接超过此时长无数据则主动断开（避免关闭游戏后残留长连接）\n0 = 不超时"
        )
        pl.addWidget(self.spin_record_idle_timeout)
        pl.addSpacing(12)
        self.cb_replay_strict_match = QCheckBox("重放严格模式")
        self.cb_replay_strict_match.setToolTip(
            "开启：解析到游戏 UID（优先 33 握手帧，其次 01 含 0A 00 23）后若无匹配录制池再断开，"
            "不在 CONNECT/TLS 首包阶段误杀（全局无池时亦先等 UID）\n"
            "关闭：无匹配时透传，用于测试或调试"
        )
        self.cb_replay_strict_match.setChecked(True)
        pl.addWidget(self.cb_replay_strict_match)
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
        self.edit_pwd.setMaxLength(6) 
        self.edit_pwd.setFixedWidth(40)
        self.edit_pwd.setStyleSheet("background: transparent; border: none; color: transparent;")
        el.addWidget(self.edit_pwd)

        top.addWidget(eg)

        # 启停
        ctrl = QVBoxLayout()
        self.btn_start = QPushButton("▶  启动代理")
        self.btn_start.setMinimumHeight(34)
        self.btn_start.setStyleSheet("QPushButton{background:#10b981;color:white;font-weight:bold;border:none;border-radius:6px}"
                                     "QPushButton:hover{background:#059669;}"
                                     "QPushButton:disabled{background:#d1d5db;color:#9ca3af;}")
        self.btn_stop = QPushButton("■  停止代理")
        self.btn_stop.setMinimumHeight(34)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("QPushButton{background:#ef4444;color:white;font-weight:bold;border:none;border-radius:6px}"
                                    "QPushButton:hover{background:#dc2626;}"
                                    "QPushButton:disabled{background:#d1d5db;color:#9ca3af;}")
        ctrl.addWidget(self.btn_start)
        ctrl.addWidget(self.btn_stop)
        top.addLayout(ctrl)
        root.addLayout(top)

        # ── 主 Tab ──────────────────────────
        self.tabs = QTabWidget()

        # Tab 0: 事件日志（业务级，无 Hex）
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 10))
        self.log_view.setStyleSheet("background-color:#1e1e1e;color:#d4d4d4;")
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
        self.tabs.addTab(t2, "🔬 连接与重放")

        # Tab 3: 录制管理
        t3 = self._build_record_tab()
        self.tabs.addTab(t3, "📼 录制管理")

        # Tab 4: 本地重放
        t4 = self._build_maplocal_tab()
        self.tabs.addTab(t4, "🗺️ 本地重放")

        # Tab 5: 远程管理
        t5 = self._build_remote_admin_tab()
        self.tabs.addTab(t5, "🌐 远程管理")

        # Tab 6: 网络流监控
        t6 = self._build_stream_monitor_tab()
        self.tabs.addTab(t6, "🌊 网络流监控")

        # Tab 7: 拦截管理
        t7 = self._build_dl_intercept_tab()
        self.tabs.addTab(t7, "🛡️ 拦截管理")

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
        self.btn_add_user    = QPushButton("➕  添加用户")
        self.btn_edit_passwd = QPushButton("🔑  修改密码")
        self.btn_del_user    = QPushButton("🗑  批量删除")
        self.btn_user_select_all = QPushButton("☑  全选")
        self.btn_user_clear_checks = QPushButton("☐  取消全选")
        self.btn_reload_users = QPushButton("🔄  重载到代理")
        for b in [
            self.btn_add_user,
            self.btn_edit_passwd,
            self.btn_del_user,
            self.btn_user_select_all,
            self.btn_user_clear_checks,
            self.btn_reload_users,
        ]:
            b.setFixedHeight(30)
            bar.addWidget(b)
        bar.addStretch()
        bar.addWidget(QLabel("(修改后需点[重载到代理]使账号生效)"))
        v.addLayout(bar)

        # 用户表格
        self.user_table = QTableWidget(0, 8)
        self.user_table.setHorizontalHeaderLabels(
            ["选择", "用户名", "密码", "到期时间", "权限", "备注", "多开", "状态"]
        )
        user_header = self.user_table.horizontalHeader()
        user_header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        for column in range(1, 8):
            user_header.setSectionResizeMode(column, QHeaderView.Stretch)
        self.user_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.user_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.user_table.verticalHeader().setVisible(False)
        v.addWidget(self.user_table)
        return w

    def _build_hex_tab(self) -> QWidget:
        # ── 连接状态总览 ─────────────────────
        conn_wrap = QWidget()
        conn_vlay = QVBoxLayout(conn_wrap); conn_vlay.setContentsMargins(0, 0, 0, 0)
        summary = QHBoxLayout()
        self.conn_summary_labels: dict[str, QLabel] = {}
        for key, title, color in (
            ("record", "录制中", "#ef4444"),
            ("replay", "重放中", "#8b5cf6"),
            ("live", "实时重放", "#0284c7"),
            ("waiting", "待匹配", "#d97706"),
        ):
            card = QLabel(f"{title}\n0")
            card.setAlignment(Qt.AlignCenter)
            card.setMinimumHeight(54)
            card.setStyleSheet(
                f"background:#ffffff;border:1px solid #e5e7eb;border-left:4px solid {color};"
                "border-radius:7px;padding:5px 14px;font-size:12px;font-weight:600;color:#374151;"
            )
            summary.addWidget(card, 1)
            self.conn_summary_labels[key] = card
        conn_vlay.addLayout(summary)

        # ── 连接表工具栏 ─────────────────────
        conn_bar  = QHBoxLayout()
        conn_bar.addWidget(QLabel("连接会话（按来源 IP 聚合）"))
        conn_bar.addStretch()
        self.cb_detail_01 = QCheckBox("详细 01 替换日志")
        self.cb_detail_01.setToolTip("勾选后，重放详情中显示原始请求与替换后封包的完整 Hex")
        conn_bar.addWidget(self.cb_detail_01)
        self.btn_conn_detail = QPushButton("📋 查看重放详情")
        self.btn_conn_detail.setFixedHeight(26)
        self.btn_conn_detail.setToolTip("选中一行后点击，查看该 IP 的逐包重放日志")
        conn_bar.addWidget(self.btn_conn_detail)
        conn_vlay.addLayout(conn_bar)

        self.conn_table = QTableWidget(0, 9)
        self.conn_table.setHorizontalHeaderLabels(
            ["来源 IP", "最近目标", "用户", "账户 / 游戏", "模式", "总连接", "活跃", "重放进度", "状态"])
        hh = self.conn_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)   # 来源 IP
        hh.setSectionResizeMode(1, QHeaderView.Stretch)             # 最近目标（拉伸）
        hh.setSectionResizeMode(2, QHeaderView.ResizeToContents)   # 用户
        hh.setSectionResizeMode(3, QHeaderView.Interactive)       # 账户 / 游戏（可拖拽，默认较宽）
        hh.resizeSection(3, 240)
        hh.setSectionResizeMode(4, QHeaderView.ResizeToContents)   # 模式
        hh.setSectionResizeMode(5, QHeaderView.ResizeToContents)   # 总连接
        hh.setSectionResizeMode(6, QHeaderView.ResizeToContents)   # 活跃
        hh.setSectionResizeMode(7, QHeaderView.ResizeToContents)   # 重放进度
        hh.setSectionResizeMode(8, QHeaderView.ResizeToContents)   # 状态
        self.conn_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.conn_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.conn_table.verticalHeader().setVisible(False)
        conn_vlay.addWidget(self.conn_table)

        return conn_wrap

    def _build_record_tab(self) -> QWidget:
        """
        录制管理 Tab 布局：
          上半：会话表（IP / 游戏ID·产品 / 账户 / 池条目 / 状态）— 池含 01 与 3366 解密 09/21
          下半：左=加密区列表（序号/来源/大小/预览），右=选中项 Hex
        """
        outer = QSplitter(Qt.Vertical)

        # ── 上：会话列表 ──────────────────────
        top_w = QWidget()
        top_v = QVBoxLayout(top_w); top_v.setContentsMargins(0, 0, 0, 0)
        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("录制会话"))
        top_bar.addSpacing(16)
        top_bar.addWidget(QLabel("01 阈值:"))
        self.spin_01_threshold = QSpinBox()
        self.spin_01_threshold.setRange(1, 9999)
        self.spin_01_threshold.setValue(100)
        self.spin_01_threshold.setSuffix(" 包")
        self.spin_01_threshold.setFixedWidth(80)
        self.spin_01_threshold.setToolTip(
            "录制到此数量的 01 包后自动断线（触发录制停止），0~9999\n"
            "修改后立即生效，无需重启代理"
        )
        self.spin_01_threshold.valueChanged.connect(
            lambda v: app_config.set("auto_disconnect_01_threshold", v)
        )
        top_bar.addWidget(self.spin_01_threshold)
        top_bar.addStretch()
        self.btn_rec_refresh = QPushButton("🔄 刷新");   self.btn_rec_refresh.setMinimumWidth(80)
        self.btn_rec_export  = QPushButton("📤 导出");   self.btn_rec_export.setMinimumWidth(80)
        self.btn_rec_import  = QPushButton("📥 导入");   self.btn_rec_import.setMinimumWidth(80)
        self.btn_rec_clear   = QPushButton("🗑 清空全部"); self.btn_rec_clear.setMinimumWidth(95)
        top_bar.addWidget(self.btn_rec_refresh)
        top_bar.addWidget(self.btn_rec_export)
        top_bar.addWidget(self.btn_rec_import)
        top_bar.addWidget(self.btn_rec_clear)
        top_v.addLayout(top_bar)

        capture_bar = QHBoxLayout()
        self.cb_capture_mode = QCheckBox("01 / 3366 双协议采集")
        self.cb_capture_mode.setToolTip(
            "开启后，对目标账号同时保存原始双向 TCP chunk、方向字节流、\n"
            "完整 01/3366 帧、01 逻辑消息及可解密的 3366 明文。\n"
            "不会生成常规流量详单，不写录制池，也不向网络流监控追加数据。\n"
            "请在启动代理前开启。"
        )
        self.cb_capture_mode.setStyleSheet(
            "QCheckBox{font-weight:700;color:#b45309;padding:4px 0;}"
        )
        capture_bar.addWidget(self.cb_capture_mode)
        capture_bar.addSpacing(12)
        capture_bar.addWidget(QLabel("采集账号:"))
        self.edit_capture_user = QLineEdit()
        self.edit_capture_user.setPlaceholderText("test")
        self.edit_capture_user.setFixedWidth(150)
        self.edit_capture_user.setToolTip("仅采集使用此代理账号登录录制端口的双向流量")
        capture_bar.addWidget(self.edit_capture_user)
        self.lbl_capture_hint = QLabel(
            "输出：capture-clean-时间/；停止代理后自检并生成 ZIP"
        )
        self.lbl_capture_hint.setStyleSheet("color:#64748b;font-size:11px;")
        capture_bar.addWidget(self.lbl_capture_hint)
        capture_bar.addStretch()
        top_v.addLayout(capture_bar)
        self.cb_capture_mode.toggled.connect(self._save_config_from_ui)
        self.edit_capture_user.editingFinished.connect(self._save_config_from_ui)

        timeline_bar = QHBoxLayout()
        timeline_bar.addWidget(QLabel("对局时间标记:"))
        self.combo_capture_phase = QComboBox()
        self.combo_capture_phase.addItem("冷启动", "cold_start")
        self.combo_capture_phase.addItem("登录完成", "login_complete")
        self.combo_capture_phase.addItem("大厅", "lobby")
        self.combo_capture_phase.addItem("开始匹配", "matchmaking")
        self.combo_capture_phase.addItem("加载", "loading")
        self.combo_capture_phase.addItem("进入对局", "match_enter")
        self.combo_capture_phase.addItem("首次移动", "first_move")
        self.combo_capture_phase.addItem("首次开枪", "first_shot")
        self.combo_capture_phase.addItem("首次命中", "first_hit")
        self.combo_capture_phase.addItem("首次击杀", "first_kill")
        self.combo_capture_phase.addItem("结算", "settlement")
        self.combo_capture_phase.addItem("返回大厅", "return_lobby")
        self.combo_capture_phase.setFixedWidth(130)
        timeline_bar.addWidget(self.combo_capture_phase)
        self.btn_capture_mark = QPushButton("写入当前标记")
        self.btn_capture_mark.setToolTip(
            "按当前时刻写入 timeline.jsonl；无需选择连接或观察数据包"
        )
        self.btn_capture_mark.clicked.connect(self._on_capture_timeline_mark)
        timeline_bar.addWidget(self.btn_capture_mark)
        self.lbl_capture_mark = QLabel("代理启动后可标记")
        self.lbl_capture_mark.setStyleSheet("color:#64748b;font-size:11px;")
        timeline_bar.addWidget(self.lbl_capture_mark)
        timeline_bar.addStretch()
        top_v.addLayout(timeline_bar)

        rec_summary = QHBoxLayout()
        self.rec_summary_labels: dict[str, QLabel] = {}
        for key, title in (
            ("active", "当前录制"),
            ("ready", "可重放账户"),
            ("templates01", "01 模板"),
            ("templates33", "33 模板"),
        ):
            label = QLabel(f"{title}: 0")
            label.setAlignment(Qt.AlignCenter)
            label.setMinimumHeight(34)
            label.setStyleSheet(
                "background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;"
                "padding:5px 10px;font-weight:600;color:#334155;"
            )
            rec_summary.addWidget(label, 1)
            self.rec_summary_labels[key] = label
        top_v.addLayout(rec_summary)
        _rec_hint = QLabel(
            "新录制上线会先清空上一轮模板；重放按录制顺序循环取池，末尾后回到第一条。"
        )
        _rec_hint.setWordWrap(True)
        _rec_hint.setStyleSheet("color:#8b949e;font-size:11px;padding:4px 0;")
        top_v.addWidget(_rec_hint)

        self.rec_session_table = QTableWidget(0, 7)
        self.rec_session_table.setHorizontalHeaderLabels(
            ["游戏用户ID", "01数", "33数", "来源 IP", "最近录制", "状态", "操作"]
        )
        sh = self.rec_session_table.horizontalHeader()
        sh.setSectionResizeMode(0, QHeaderView.Stretch)   # 游戏用户ID 拉伸填满
        sh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        sh.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        sh.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        sh.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        sh.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        sh.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        sh.setMinimumSectionSize(50)
        self.rec_session_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rec_session_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rec_session_table.verticalHeader().setVisible(False)
        top_v.addWidget(self.rec_session_table)
        outer.addWidget(top_w)

        # ── 下：包列表 + Hex 详情（默认折叠，点击"详情"按钮展开）─────
        detail_wrap = QWidget()
        detail_vlay = QVBoxLayout(detail_wrap); detail_vlay.setContentsMargins(0, 0, 0, 0); detail_vlay.setSpacing(0)

        # 详情标题栏（含当前选中账号 + 关闭按钮）
        det_title_bar = QHBoxLayout()
        self.lbl_rec_detail_title = QLabel("加密区详情")
        self.lbl_rec_detail_title.setStyleSheet("font-weight:bold; padding:2px 4px;")
        det_title_bar.addWidget(self.lbl_rec_detail_title)
        det_title_bar.addStretch()
        btn_close_detail = QPushButton("✕ 收起")
        btn_close_detail.setFixedWidth(64)
        btn_close_detail.setStyleSheet("color:#9ca3af; border:none; font-size:11px;")
        btn_close_detail.clicked.connect(lambda: self._rec_outer_splitter.setSizes([10000, 0]))
        det_title_bar.addWidget(btn_close_detail)
        detail_vlay.addLayout(det_title_bar)

        bottom_split = QSplitter(Qt.Horizontal)

        # 左：包列表
        pkt_w = QWidget()
        pkt_v = QVBoxLayout(pkt_w); pkt_v.setContentsMargins(0, 0, 0, 0)
        pkt_v.addWidget(QLabel("加密区列表（01 0A 00 09/21 块）"))
        self.rec_pkt_table = QTableWidget(0, 4)
        self.rec_pkt_table.setHorizontalHeaderLabels(
            ["序号", "来源", "大小(B)", "原始数据首16B"]
        )
        ph = self.rec_pkt_table.horizontalHeader()
        ph.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        ph.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        ph.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        ph.setSectionResizeMode(3, QHeaderView.Stretch)
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

        detail_vlay.addWidget(bottom_split)
        outer.addWidget(detail_wrap)
        # 默认折叠底部详情区（高度=0）
        self._rec_outer_splitter = outer
        outer.setSizes([10000, 0])

        # 存储当前选中 IP 的包缓存，供包列表点击时快速读取
        self._rec_current_pkts: list[bytes] = []
        self._rec_current_rows: list[dict] = []

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
        self.btn_map_add   = QPushButton("➕ 添加规则"); self.btn_map_add.setMinimumWidth(85)
        self.btn_map_del   = QPushButton("🗑  删除选中"); self.btn_map_del.setMinimumWidth(85)
        self.btn_map_clear = QPushButton("🧹 清空全部"); self.btn_map_clear.setMinimumWidth(85)
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

        # ── HTTPS 域名拦截 ──────────────────────────────────────
        sep_https = QFrame()
        sep_https.setFrameShape(QFrame.HLine)
        sep_https.setStyleSheet("background:#374151; max-height:1px;")
        v.addWidget(sep_https)

        hint_https = QLabel(
            "HTTPS 拦截：命中指定域名的 CONNECT 请求直接拒绝，无需解密 TLS，适用于屏蔽 ACE 等反作弊更新下载。"
        )
        hint_https.setStyleSheet("color:#9ca3af; font-size:11px;")
        hint_https.setWordWrap(True)
        v.addWidget(hint_https)

        https_row = QHBoxLayout()
        self.cb_ace_https_block = QCheckBox("启用 HTTPS 域名拦截")
        https_row.addWidget(self.cb_ace_https_block)
        https_row.addSpacing(10)
        self.cb_ace_https_block_replay_only = QCheckBox("仅重放模式")
        self.cb_ace_https_block_replay_only.setToolTip(
            "勾选后：录制端口(1083)上线不拦截，仅重放端口(1084)触发拦截\n"
            "不勾选：录制与重放端口上线均拦截"
        )
        https_row.addWidget(self.cb_ace_https_block_replay_only)
        https_row.addSpacing(10)
        https_row.addWidget(QLabel("拦截域名:"))
        self.edit_ace_https_block_host = QLineEdit()
        self.edit_ace_https_block_host.setPlaceholderText("down.anticheatexpert.com")
        self.edit_ace_https_block_host.setFixedWidth(240)
        https_row.addWidget(self.edit_ace_https_block_host)
        https_row.addStretch()
        btn_save_https = QPushButton("💾 保存")
        btn_save_https.setFixedWidth(70)
        btn_save_https.clicked.connect(self._save_config_from_ui)
        https_row.addWidget(btn_save_https)
        v.addLayout(https_row)

        return w

    def _build_stream_monitor_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        
        bar = QHBoxLayout()
        self.chk_stream_capture = QCheckBox("启用实时抓取")
        self.chk_stream_capture.setChecked(False)
        bar.addWidget(self.chk_stream_capture)
        self.chk_stream_send_only = QCheckBox("只显示发送")
        self.chk_stream_send_only.setChecked(False)
        bar.addWidget(self.chk_stream_send_only)
        self.chk_stream_auto_scroll = QCheckBox("自动滚动到底部")
        self.chk_stream_auto_scroll.setChecked(True)
        bar.addWidget(self.chk_stream_auto_scroll)
        bar.addStretch()
        bar.addWidget(QLabel("最大记录:"))
        self.spin_stream_max_rows = QSpinBox()
        self.spin_stream_max_rows.setRange(50, 9999)
        self.spin_stream_max_rows.setValue(500)
        self.spin_stream_max_rows.setSuffix(" 条")
        self.spin_stream_max_rows.setFixedWidth(80)
        self.spin_stream_max_rows.setToolTip("每张表最多保留的行数，超出后自动删除最旧的一行")
        bar.addWidget(self.spin_stream_max_rows)
        bar.addSpacing(8)
        btn_clear = QPushButton("清空记录")
        btn_clear.clicked.connect(self._clear_stream_tables)
        bar.addWidget(btn_clear)
        v.addLayout(bar)

        split = QSplitter(Qt.Horizontal)
        
        # 表格1：原始 TCP
        w1 = QWidget(); v1 = QVBoxLayout(w1); v1.setContentsMargins(0,0,0,0)
        v1.addWidget(QLabel("① 原始传入 (TCP 拼装前)"))
        self.tb_stream_raw = self._create_stream_table()
        v1.addWidget(self.tb_stream_raw)
        split.addWidget(w1)

        # 表格2：分包后
        w2 = QWidget(); v2 = QVBoxLayout(w2); v2.setContentsMargins(0,0,0,0)
        v2.addWidget(QLabel("② 分包还原 (替换前)"))
        self.tb_stream_parsed = self._create_stream_table()
        v2.addWidget(self.tb_stream_parsed)
        split.addWidget(w2)

        # 表格3：发出前
        w3 = QWidget(); v3 = QVBoxLayout(w3); v3.setContentsMargins(0,0,0,0)
        v3.addWidget(QLabel("③ 最终发出 (替换后)"))
        self.tb_stream_sent = self._create_stream_table()
        v3.addWidget(self.tb_stream_sent)
        split.addWidget(w3)
        
        v.addWidget(split)
        
        # 数据缓存
        self.stream_raw_data_cache = []
        self.stream_parsed_data_cache = []
        self.stream_sent_data_cache = []
        
        # 为了能够在清空时正常工作，补充一下不存在的初始化
        self.dl_intercept_log = QTextEdit()
        self.dl_intercept_log.setReadOnly(True)
        self.dl_intercept_log.setFont(QFont("Consolas", 9))
        self.dl_intercept_log.setStyleSheet("background-color:#1e1e1e;color:#d4d4d4;")
        self.dl_intercept_log.setMinimumHeight(150)
        
        return w

    def _make_stat_table(self, headers: list[str], ops_col: int) -> QTableWidget:
        """创建统一样式的拦截统计表格"""
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        hdr = t.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        for c in range(1, len(headers)):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        t.setShowGrid(False)
        t.setFont(QFont("Consolas", 9))
        t.setSortingEnabled(True)
        t.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        t.setMinimumHeight(80)
        return t

    def _build_dl_intercept_tab(self) -> QWidget:
        """暗区突围专项拦截面板：状态、上行、下行集中在一个页面。"""
        self.dl_intercept_log = QTextEdit()
        self.dl_intercept_log.setReadOnly(True)
        self.cb_destroy_mode = QCheckBox()
        self.edit_zone_start = QLineEdit()
        self.spin_zone_nth = QSpinBox()
        self.spin_zone_nth.setRange(1, 99)
        self.spin_zone_nth.setValue(2)
        self.edit_zone_stop = QLineEdit()
        self.edit_zone_fill = QLineEdit()

        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)

        title_row = QHBoxLayout()
        title = QLabel("暗区突围 · 专项拦截")
        title.setStyleSheet("font-size:18px;font-weight:700;color:#111827;")
        subtitle = QLabel("仅处理暗区 01 / 3366；所有开关只在重放连接生效")
        subtitle.setStyleSheet("color:#6b7280;font-size:11px;")
        title_col = QVBoxLayout()
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        title_row.addLayout(title_col)
        title_row.addStretch()
        btn_sort = QPushButton("按总数排序")
        btn_sort.clicked.connect(self._on_dl_sort_stats)
        btn_clear = QPushButton("清空统计")
        btn_clear.clicked.connect(self._on_dl_clear_stats)
        title_row.addWidget(btn_sort)
        title_row.addWidget(btn_clear)
        root.addLayout(title_row)

        self.dl_stat_table = self._make_stat_table(
            ["游戏账户", "上行命中", "01拦截", "33拦截", "块填充", "最后活跃", "操作"],
            ops_col=6,
        )
        state_box = QGroupBox("实时状态")
        state_layout = QVBoxLayout(state_box)
        state_layout.addWidget(self.dl_stat_table)
        root.addWidget(state_box, 2)

        settings = QHBoxLayout()

        uplink_box = QGroupBox("上行 33 处理")
        uplink = QVBoxLayout(uplink_box)
        up_switches = QHBoxLayout()
        self.cb_ul_dirty_clean = QCheckBox("脏数据清除")
        self.cb_ul_truncate = QCheckBox("大包截断")
        self.spin_ul_truncate_min = QSpinBox()
        self.spin_ul_truncate_min.setRange(100, 65535)
        self.spin_ul_truncate_min.setValue(500)
        self.spin_ul_truncate_min.setSuffix(" B")
        up_switches.addWidget(self.cb_ul_dirty_clean)
        up_switches.addWidget(self.cb_ul_truncate)
        up_switches.addWidget(QLabel("触发阈值"))
        up_switches.addWidget(self.spin_ul_truncate_min)
        up_switches.addStretch()
        uplink.addLayout(up_switches)

        add_blacklist = QHBoxLayout()
        self.edit_bl_str = QLineEdit()
        self.edit_bl_str.setPlaceholderText("输入明文黑名单字符串")
        btn_add_blacklist = QPushButton("添加")
        btn_add_blacklist.clicked.connect(self._on_blacklist_add)
        add_blacklist.addWidget(self.edit_bl_str)
        add_blacklist.addWidget(btn_add_blacklist)
        uplink.addLayout(add_blacklist)

        self.bl_table = QTableWidget(0, 3)
        self.bl_table.setHorizontalHeaderLabels(["字符串", "命中", "操作"])
        self.bl_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.bl_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.bl_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.bl_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.bl_table.verticalHeader().setVisible(False)
        uplink.addWidget(self.bl_table)
        settings.addWidget(uplink_box, 1)

        downlink_box = QGroupBox("下行 01 / 33 处理")
        downlink = QVBoxLayout(downlink_box)
        self.cb_az_dl_intercept = QCheckBox("启用 33 字符串拦截")
        self.cb_az_dl_intercept.toggled.connect(self._save_config_from_ui)
        downlink.addWidget(self.cb_az_dl_intercept)

        str_row = QHBoxLayout()
        str_row.addWidget(QLabel("查找"))
        self.edit_dl_search = QLineEdit()
        self.edit_dl_search.setPlaceholderText("unzipmrpcs")
        self.lbl_dl_replace = QLabel("替换")
        self.edit_dl_replace = QLineEdit()
        self.edit_dl_replace.setPlaceholderText("留空=等长清零")
        str_row.addWidget(self.edit_dl_search)
        str_row.addWidget(self.lbl_dl_replace)
        str_row.addWidget(self.edit_dl_replace)
        downlink.addLayout(str_row)

        chunk_row = QHBoxLayout()
        self.cb_chunk_block = QCheckBox("启用块填充")
        self.edit_chunk_block_pattern = QLineEdit()
        self.edit_chunk_block_pattern.setPlaceholderText("F802000003")
        chunk_row.addWidget(self.cb_chunk_block)
        chunk_row.addWidget(QLabel("明文前缀"))
        chunk_row.addWidget(self.edit_chunk_block_pattern)
        downlink.addLayout(chunk_row)

        advanced_box = QGroupBox("块填充范围（高级）")
        advanced = QGridLayout(advanced_box)
        self.cb_destroy_mode.setText("字符串命中后改用区间填充")
        self.cb_destroy_mode.setToolTip(
            "开启后不再使用上方“替换”内容，而是按起止标记对命中帧进行定长填充。"
        )
        advanced.addWidget(self.cb_destroy_mode, 0, 0, 1, 4)
        self.edit_zone_start.setPlaceholderText("Hex；留空=从明文开头")
        self.spin_zone_nth.setToolTip("从第几次出现的起始标记开始填充")
        self.edit_zone_stop.setPlaceholderText("UTF-8；留空=到明文结尾")
        self.edit_zone_fill.setPlaceholderText("00")
        self.edit_zone_fill.setMaxLength(2)
        advanced.addWidget(QLabel("起始标记"), 1, 0)
        advanced.addWidget(self.edit_zone_start, 1, 1)
        advanced.addWidget(QLabel("第 N 次"), 1, 2)
        advanced.addWidget(self.spin_zone_nth, 1, 3)
        advanced.addWidget(QLabel("终止标记"), 2, 0)
        advanced.addWidget(self.edit_zone_stop, 2, 1)
        advanced.addWidget(QLabel("填充字节"), 2, 2)
        advanced.addWidget(self.edit_zone_fill, 2, 3)
        downlink.addWidget(advanced_box)

        packet_row = QHBoxLayout()
        self.cb_dl_01_block = QCheckBox("拦截 01 下行大包")
        self.spin_dl_01_threshold = QSpinBox()
        self.spin_dl_01_threshold.setRange(100, 65535)
        self.spin_dl_01_threshold.setValue(1000)
        self.spin_dl_01_threshold.setSuffix(" B")
        packet_row.addWidget(self.cb_dl_01_block)
        packet_row.addWidget(QLabel("阈值"))
        packet_row.addWidget(self.spin_dl_01_threshold)
        packet_row.addStretch()
        downlink.addLayout(packet_row)

        btn_save = QPushButton("保存暗区拦截配置")
        btn_save.setMinimumHeight(34)
        btn_save.clicked.connect(self._save_config_from_ui)
        downlink.addStretch()
        downlink.addWidget(btn_save)
        settings.addWidget(downlink_box, 1)
        root.addLayout(settings, 3)

        def _on_destroy_mode_toggled(checked: bool):
            self.lbl_dl_replace.setEnabled(not checked)
            self.edit_dl_replace.setEnabled(not checked)
            app_config.set("dl_destroy_mode_enabled", checked)

        self.cb_destroy_mode.toggled.connect(_on_destroy_mode_toggled)
        return w

    def _create_stream_table(self) -> QTableWidget:
        tb = QTableWidget(0, 5)
        tb.setHorizontalHeaderLabels(["方向", "套接字", "长度", "数据(首行)", "时间"])
        tb.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        tb.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        tb.setEditTriggers(QAbstractItemView.NoEditTriggers)
        tb.setSelectionBehavior(QAbstractItemView.SelectRows)
        tb.verticalHeader().setVisible(False)
        tb.setShowGrid(False)
        tb.setFont(QFont("Consolas", 9))
        tb.setStyleSheet("background-color:#0d1117; color:#c9d1d9; gridline-color:#30363d; selection-background-color:#1f6feb;")
        tb.doubleClicked.connect(lambda: self._on_stream_table_double_click(tb))
        return tb

    def _clear_stream_tables(self):
        self.tb_stream_raw.setRowCount(0); self.stream_raw_data_cache.clear()
        self.tb_stream_parsed.setRowCount(0); self.stream_parsed_data_cache.clear()
        self.tb_stream_sent.setRowCount(0); self.stream_sent_data_cache.clear()

    def _add_stream_row(self, tb: QTableWidget, cache: list, conn_id: str, direction: str, length: int, raw_bytes: bytes, prefix: str = ""):
        if not hasattr(self, 'chk_stream_capture') or not self.chk_stream_capture.isChecked():
            return
        if hasattr(self, 'chk_stream_send_only') and self.chk_stream_send_only.isChecked() and "UP" not in direction:
            return
            
        max_rows = self.spin_stream_max_rows.value() if hasattr(self, 'spin_stream_max_rows') else 500
        row = tb.rowCount()
        tb.insertRow(row)
        
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        dir_text = "➡ 发送" if "UP" in direction else "⬅ 接收"
        dir_color = "#4ade80" if "UP" in direction else "#60a5fa"
        
        hex_preview = " ".join(f"{b:02X}" for b in raw_bytes[:64]) if raw_bytes else ""
        if raw_bytes and len(raw_bytes) > 64: hex_preview += " ..."
        if prefix: hex_preview = f"[{prefix}] {hex_preview}"
        
        items = [
            QTableWidgetItem(dir_text),
            QTableWidgetItem(conn_id),
            QTableWidgetItem(str(length)),
            QTableWidgetItem(hex_preview),
            QTableWidgetItem(ts)
        ]
        items[0].setForeground(QColor(dir_color))
        items[1].setForeground(QColor("#f0883e"))
        items[2].setForeground(QColor("#d2a8ff"))
        items[3].setForeground(QColor(dir_color))
        items[4].setForeground(QColor("#8b949e"))
        
        for col, it in enumerate(items):
            tb.setItem(row, col, it)
            
        cache.append(raw_bytes)
        
        if tb.rowCount() > max_rows:
            tb.removeRow(0)
            cache.pop(0)
            
        if self.chk_stream_auto_scroll.isChecked():
            tb.scrollToBottom()

    def _on_stream_table_double_click(self, tb: QTableWidget):
        row = tb.currentRow()
        if row < 0: return
        cache = None
        if tb == self.tb_stream_raw: cache = self.stream_raw_data_cache
        elif tb == self.tb_stream_parsed: cache = self.stream_parsed_data_cache
        elif tb == self.tb_stream_sent: cache = self.stream_sent_data_cache
        if not cache or row >= len(cache): return
        
        raw = cache[row]
        if not raw: return
        
        dlg = QDialog(self)
        dlg.setWindowTitle("完整数据")
        dlg.resize(750, 500)
        dv = QVBoxLayout(dlg)

        top_bar = QHBoxLayout()
        info = QLabel(f"<b>长度:</b> {len(raw)} bytes")
        top_bar.addWidget(info)
        top_bar.addStretch()

        btn_copy_pure = QPushButton("📋 复制全部纯 Hex")
        btn_copy_pure.setFixedHeight(26)
        def _copy_pure_hex():
            try:
                hex_str = " ".join(f"{b:02X}" for b in raw)
                QApplication.clipboard().setText(hex_str)
                btn_copy_pure.setText("✅ 已复制")
                QTimer.singleShot(1500, lambda: btn_copy_pure.setText("📋 复制全部纯 Hex"))
            except Exception:
                pass
        btn_copy_pure.clicked.connect(_copy_pure_hex)
        top_bar.addWidget(btn_copy_pure)

        btn_copy_detail = QPushButton("📄 复制全部带格式详情")
        btn_copy_detail.setFixedHeight(26)
        def _copy_detail_hex():
            try:
                QApplication.clipboard().setText(te.toPlainText())
                btn_copy_detail.setText("✅ 已复制")
                QTimer.singleShot(1500, lambda: btn_copy_detail.setText("📄 复制全部带格式详情"))
            except Exception:
                pass
        btn_copy_detail.clicked.connect(_copy_detail_hex)
        top_bar.addWidget(btn_copy_detail)

        dv.addLayout(top_bar)

        te = QTextEdit()
        te.setFont(QFont("Consolas", 10))
        te.setReadOnly(True)
        te.setStyleSheet("background:#1e1e1e;color:#d4d4d4;")
        
        try:
            lines = []
            for i in range(0, len(raw), 16):
                chunk = raw[i:i + 16]
                offset = f"{i:04X}"
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                hex_part = f"{hex_part:<47}"
                asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"{offset}  {hex_part}  {asc_part}")
            te.setPlainText("\n".join(lines))
        except Exception:
            te.setPlainText(raw.hex().upper())
            
        dv.addWidget(te)
        dlg.exec()

    def _build_remote_admin_tab(self) -> QWidget:
        """
        远程管理 Tab：浏览器管理入口，支持手机访问。
        可配置管理端口和密码，修改密码立即生效，修改端口需重启代理。
        """
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(6, 6, 6, 6)
        v.setSpacing(6)

        # 说明标签
        hint = QLabel(
            "通过浏览器远程管理。支持手机访问，输入密码登录后可创建重放账号等。"
            "修改密码立即生效，修改端口需重启代理后生效。"
            "提示：启动代理时会自动保存此处配置；若未设置密码，首次启动会自动生成随机密码（见 config.json）。"
        )
        hint.setStyleSheet("color:#9ca3af; font-size:11px;")
        hint.setWordWrap(True)
        v.addWidget(hint)

        # 端口与密码配置
        cfg_bar = QHBoxLayout()
        cfg_bar.addWidget(QLabel("管理端口:"))
        self.spin_admin_port = QSpinBox()
        self.spin_admin_port.setRange(1, 65535)
        self.spin_admin_port.setValue(8787)
        self.spin_admin_port.setFixedWidth(80)
        cfg_bar.addWidget(self.spin_admin_port)
        cfg_bar.addSpacing(20)
        cfg_bar.addWidget(QLabel("管理密码:"))
        self.edit_admin_token = QLineEdit()
        self.edit_admin_token.setPlaceholderText("登录密码，至少 6 位")
        self.edit_admin_token.setMinimumWidth(180)
        cfg_bar.addWidget(self.edit_admin_token)
        cfg_bar.addStretch()
        self.btn_save_remote = QPushButton("💾 保存")
        self.btn_save_remote.setFixedHeight(28)
        self.btn_save_remote.setMinimumWidth(70)
        self.btn_save_remote.clicked.connect(self._on_save_remote_admin)
        cfg_bar.addWidget(self.btn_save_remote)
        v.addLayout(cfg_bar)

        # 管理地址
        bar = QHBoxLayout()
        bar.addWidget(QLabel("管理地址："))
        port = app_config.get("admin_port") or 8787
        self.lbl_remote_url = QLabel(f"http://localhost:{port}/")
        self.lbl_remote_url.setStyleSheet("color:#3b82f6; font-family:Consolas;")
        self.lbl_remote_url.setToolTip("将 localhost 替换为本机 IP 可从手机访问")
        bar.addWidget(self.lbl_remote_url)
        bar.addStretch()
        self.btn_open_remote = QPushButton("🌐 在浏览器中打开")
        self.btn_open_remote.setMinimumWidth(130)
        self.btn_open_remote.setFixedHeight(28)
        self.btn_open_remote.clicked.connect(self._on_open_remote_admin)
        bar.addWidget(self.btn_open_remote)
        v.addLayout(bar)

        # 远程管理日志
        log_bar = QHBoxLayout()
        log_bar.addWidget(QLabel("远程管理日志（登录 IP、创建账号等）"))
        log_bar.addStretch()
        btn_clr_admin = QPushButton("清空")
        btn_clr_admin.setFixedWidth(50)
        btn_clr_admin.clicked.connect(lambda: self.remote_admin_log.clear())
        log_bar.addWidget(btn_clr_admin)
        v.addLayout(log_bar)
        self.remote_admin_log = QTextEdit()
        self.remote_admin_log.setReadOnly(True)
        self.remote_admin_log.setFont(QFont("Consolas", 9))
        self.remote_admin_log.setStyleSheet("background-color:#1e1e1e;color:#d4d4d4;")
        self.remote_admin_log.setMinimumHeight(120)
        v.addWidget(self.remote_admin_log)

        return w

    def _on_save_remote_admin(self):
        """保存远程管理端口和密码"""
        port = self.spin_admin_port.value()
        token = self.edit_admin_token.text().strip()
        app_config.set("admin_port", port)
        if len(token) >= 6:
            app_config.set("admin_token", token)
        app_config.save()
        # 若代理已运行，立即更新内存中的 token（端口需重启生效）
        if engine.admin_api:
            if len(token) >= 6:
                engine.admin_api.token = token
                _event("INFO", "AdminAPI", "管理密码已更新")
            engine.admin_api.port = port
        self.lbl_remote_url.setText(f"http://localhost:{port}/")
        self.lbl_status.setText("远程管理配置已保存")
        QMessageBox.information(self, "提示", "配置已保存。\n修改密码立即生效；修改端口需重启代理后生效。")

    def _on_admin_log(self, line: str):
        """远程管理日志追加到专用文本框"""
        self.remote_admin_log.append(line)
        self.remote_admin_log.verticalScrollBar().setValue(
            self.remote_admin_log.verticalScrollBar().maximum()
        )

    def _on_dl_intercept_log(self, line: str):
        """下发拦截原始日志（隐藏 widget，仅保留信号兼容）"""
        pass

    def _find_stat_row(self, account_label: str) -> int:
        """通过 UserRole 在对应游戏的统计表中查找账户行号，未找到返回 -1"""
        tbl = self._stat_table_for(account_label)
        for r in range(tbl.rowCount()):
            item = tbl.item(r, 0)
            if item and item.data(Qt.UserRole) == account_label:
                return r
        return -1

    def _stat_table_for(self, account_label: str) -> QTableWidget:
        """暗区专项版只有一张账户统计表。"""
        return self.dl_stat_table

    def _stat_table_for_game(self, gid: str) -> QTableWidget:
        return self.dl_stat_table

    def _make_stat_ops_widget(self, account_label: str) -> QWidget:
        """创建统计表操作列的双按钮容器（下行详情 + 上行日志）"""
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(4, 4, 4, 4)
        h.setSpacing(6)
        btn_style = "QPushButton{padding:5px 12px; min-width:72px;}"
        btn_dl = QPushButton("📋 下行")
        btn_dl.setMinimumHeight(30)
        btn_dl.setStyleSheet(btn_style)
        btn_dl.setToolTip("查看下行拦截详情（字符串替换/块清零/01大包）")
        btn_dl.clicked.connect(lambda _, lbl=account_label: self._on_dl_show_detail(lbl))
        h.addWidget(btn_dl)
        btn_ul = QPushButton("📤 上行")
        btn_ul.setMinimumHeight(30)
        btn_ul.setStyleSheet(btn_style)
        btn_ul.setToolTip("查看上行脏数据清除日志（扫描/命中/诊断）")
        btn_ul.clicked.connect(lambda _, lbl=account_label: self._on_ul_show_detail(lbl))
        h.addWidget(btn_ul)
        return w

    def _intercept_history_label_match(self, account_label: str) -> bool:
        """与下行详情历史一致：config 中 dl_intercept_history_labels 任一串出现在标签中即匹配（如 test → 657932649(test)）"""
        labels = app_config.get("dl_intercept_history_labels") or ["test"]
        return any(lbl in account_label for lbl in labels)

    def _ensure_dl_stat_row(self, account_label: str) -> None:
        """若无拦截统计行则创建。"""
        if account_label in self._dl_intercept_stats:
            return
        tbl = self._stat_table_for(account_label)
        self._dl_intercept_stats[account_label] = {
            "ul_hit": 0, "01_drop": 0, "str_replace": 0, "chunk_drop": 0,
            "last_active": datetime.now()}
        tbl.setSortingEnabled(False)
        row = tbl.rowCount()
        tbl.insertRow(row)
        lbl_item = QTableWidgetItem(account_label)
        lbl_item.setData(Qt.UserRole, account_label)
        lbl_item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        tbl.setItem(row, 0, lbl_item)
        now_str = datetime.now().strftime("%H:%M:%S")
        for col, txt in enumerate(["0"] * 5 + [now_str], start=1):
            it = QTableWidgetItem(txt)
            it.setTextAlignment(Qt.AlignCenter)
            tbl.setItem(row, col, it)
        tbl.setCellWidget(row, 6, self._make_stat_ops_widget(account_label))
        tbl.resizeRowToContents(row)
        tbl.setSortingEnabled(True)

    def _on_dl_intercept_event(self, account_label: str, event_type: str, message: str):
        """拦截事件：更新统计表格 + 黑名单命中计数 + 转发详情弹窗
        event_type: game_init | ul_hit | ul_log | 01_drop | str_replace | chunk_drop | reset
        message: game_init 时为 game_id；ul_hit 时为命中字符串；ul_log 时为诊断日志文本；其他为日志文本
        """
        # 暗区连接初始化。
        if event_type == "game_init":
            self._ensure_dl_stat_row(account_label)
            return

        # ── ul_log：上行扫描诊断日志，写入内存缓存并可选转发到已打开的上行弹窗 ─────────────────
        if event_type == "ul_log":
            if self._intercept_history_label_match(account_label):
                self._ul_log_history.setdefault(account_label, []).append(message)
            dlg = self._ul_detail_dialogs.get(account_label)
            if dlg:
                dlg.append_log(message)
            return

        # ── ul_trunc：大包截断，计入上行命中（不更新黑名单字符串表）─────────
        if event_type == "ul_trunc":
            if account_label not in self._dl_intercept_stats:
                self._on_dl_intercept_event(account_label, "ul_hit", "")  # 初始化行
            stats = self._dl_intercept_stats.get(account_label, {})
            stats["ul_hit"] = stats.get("ul_hit", 0) + 1
            stats["last_active"] = datetime.now()
            row = self._find_stat_row(account_label)
            if row >= 0:
                tbl_trunc = self._stat_table_for(account_label)
                tbl_trunc.setSortingEnabled(False)
                tbl_trunc.item(row, 1).setText(str(stats.get("ul_hit", 0)))
                tbl_trunc.item(row, 5).setText(stats["last_active"].strftime("%H:%M:%S"))
                tbl_trunc.setSortingEnabled(True)
            log_msg = f"[UL截断] ✅ 大包截断 {message}"
            if self._intercept_history_label_match(account_label):
                self._ul_log_history.setdefault(account_label, []).append(log_msg)
            dlg = self._ul_detail_dialogs.get(account_label)
            if dlg:
                dlg.append_log(log_msg)
            return

        if event_type == "reset":
            if account_label in self._dl_intercept_stats:
                self._dl_intercept_stats[account_label].update({
                    "ul_hit": 0, "01_drop": 0, "str_replace": 0, "chunk_drop": 0,
                    "last_active": datetime.now()})
                row = self._find_stat_row(account_label)
                if row >= 0:
                    tbl_rst = self._stat_table_for(account_label)
                    tbl_rst.setSortingEnabled(False)
                    for c in range(1, tbl_rst.columnCount() - 1):
                        item = tbl_rst.item(row, c)
                        if item:
                            item.setText("0")
                    tbl_rst.setSortingEnabled(True)
                dlg = self._dl_intercept_detail_dialogs.get(account_label)
                if dlg:
                    dlg.update_summary_from_stats(
                        {"01_drop": 0, "str_replace": 0, "chunk_drop": 0},
                    )
                    dlg.append_event("diag", "--- 重放上线，统计已重置 ---")
                if account_label in self._dl_intercept_history:
                    self._dl_intercept_history[account_label].clear()
            return

        # ── 初始化账户统计行 ─────────────────────────────────────────────
        tbl = self._stat_table_for(account_label)

        if account_label not in self._dl_intercept_stats:
            self._dl_intercept_stats[account_label] = {
                "ul_hit": 0, "01_drop": 0, "str_replace": 0, "chunk_drop": 0,
                "last_active": datetime.now()}
            tbl.setSortingEnabled(False)
            row = tbl.rowCount()
            tbl.insertRow(row)

            lbl_item = QTableWidgetItem(account_label)
            lbl_item.setData(Qt.UserRole, account_label)
            lbl_item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            tbl.setItem(row, 0, lbl_item)
            now_str = datetime.now().strftime("%H:%M:%S")
            for col, txt in enumerate(["0"] * 5 + [now_str], start=1):
                it = QTableWidgetItem(txt)
                it.setTextAlignment(Qt.AlignCenter)
                tbl.setItem(row, col, it)

            tbl.setCellWidget(row, 6, self._make_stat_ops_widget(account_label))
            tbl.resizeRowToContents(row)
            tbl.setSortingEnabled(True)

        # ── 更新计数 ─────────────────────────────────────────────────────
        stats = self._dl_intercept_stats[account_label]
        stats[event_type] = stats.get(event_type, 0) + 1
        stats["last_active"] = datetime.now()

        # ul_hit：每帧计 1 次；message 含逗号分隔的所有命中字符串，各自更新黑名单计数
        if event_type == "ul_hit" and message:
            for _s in message.split(","):
                _s = _s.strip()
                if _s:
                    self._update_blacklist_hit(_s)

        row = self._find_stat_row(account_label)
        if row >= 0:
            tbl.setSortingEnabled(False)
            tbl.item(row, 1).setText(str(stats.get("ul_hit", 0)))
            tbl.item(row, 2).setText(str(stats.get("01_drop", 0)))
            tbl.item(row, 3).setText(str(stats.get("str_replace", 0)))
            tbl.item(row, 4).setText(str(stats.get("chunk_drop", 0)))
            tbl.item(row, 5).setText(stats["last_active"].strftime("%H:%M:%S"))
            tbl.setSortingEnabled(True)

        # ── 历史日志缓存 ──────────────────────────────────────────────────
        if self._intercept_history_label_match(account_label):
            history = self._dl_intercept_history.setdefault(account_label, [])
            history.append((event_type, message))

        # ── 转发到下行详情弹窗 ────────────────────────────────────────────
        dlg = self._dl_intercept_detail_dialogs.get(account_label)
        if dlg:
            dlg.append_event(event_type, message)
            dlg.update_summary_from_stats(stats)

    def _on_dl_show_detail(self, account_label: str):
        """打开或聚焦指定账户的下发拦截详情弹窗"""
        dlg = self._dl_intercept_detail_dialogs.get(account_label)
        if dlg is None:
            stats = self._dl_intercept_stats.get(account_label, {})
            dlg = DlInterceptDetailDialog(account_label, self)
            dlg.update_summary_from_stats(stats)
            for ev_type, ev_msg in self._dl_intercept_history.get(account_label, []):
                dlg.append_event(ev_type, ev_msg)
            self._dl_intercept_detail_dialogs[account_label] = dlg
            dlg.show()
        else:
            dlg.raise_()
            dlg.activateWindow()

    def _on_dl_sort_stats(self):
        """按总数降序排列暗区统计表。"""
        for tbl in [self.dl_stat_table]:
            rows = tbl.rowCount()
            if rows < 2:
                continue
            data = []
            for r in range(rows):
                lbl = (tbl.item(r, 0).data(Qt.UserRole) if tbl.item(r, 0) else "")
                try:
                    total = sum(
                        int(tbl.item(r, c).text() or 0)
                        for c in range(1, 5)
                        if tbl.item(r, c)
                    )
                except (ValueError, AttributeError):
                    total = 0
                data.append((lbl, total))
            data.sort(key=lambda x: x[1], reverse=True)

            tbl.setSortingEnabled(False)
            tbl.clearContents()
            tbl.setRowCount(0)
            for lbl, _ in data:
                if lbl not in self._dl_intercept_stats:
                    continue
                stats = self._dl_intercept_stats[lbl]
                row = tbl.rowCount()
                tbl.insertRow(row)
                lbl_item = QTableWidgetItem(lbl)
                lbl_item.setData(Qt.UserRole, lbl)
                lbl_item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                tbl.setItem(row, 0, lbl_item)
                ts = stats["last_active"].strftime("%H:%M:%S") if stats.get("last_active") else ""
                vals = [str(stats.get("ul_hit", 0)), str(stats.get("01_drop", 0)),
                        str(stats.get("str_replace", 0)), str(stats.get("chunk_drop", 0)), ts]
                for col, val in enumerate(vals, start=1):
                    it = QTableWidgetItem(val)
                    it.setTextAlignment(Qt.AlignCenter)
                    tbl.setItem(row, col, it)
                tbl.setCellWidget(row, 6, self._make_stat_ops_widget(lbl))
                tbl.resizeRowToContents(row)
            tbl.setSortingEnabled(True)

    def _on_ul_show_detail(self, account_label: str):
        """打开或聚焦上行拦截日志弹窗"""
        dlg = self._ul_detail_dialogs.get(account_label)
        if dlg is None:
            dlg = UlInterceptDetailDialog(account_label, self)
            for msg in self._ul_log_history.get(account_label, []):
                dlg.append_log(msg)
            self._ul_detail_dialogs[account_label] = dlg
            dlg.show()
        else:
            dlg.raise_()
            dlg.activateWindow()

    def _on_dl_clear_stats(self):
        """清空下发拦截统计表格、详情弹窗，并将黑名单「命中次数」归零后写回配置"""
        for dlg in list(self._dl_intercept_detail_dialogs.values()):
            dlg.close()
        self._dl_intercept_detail_dialogs.clear()
        for dlg in list(self._ul_detail_dialogs.values()):
            dlg.close()
        self._ul_detail_dialogs.clear()
        self._ul_log_history.clear()
        self._dl_intercept_stats.clear()
        self._dl_intercept_history.clear()
        self.dl_stat_table.setRowCount(0)
        for k in self._ul_blacklist:
            self._ul_blacklist[k] = 0
        self._refresh_blacklist_table()
        self._save_ul_blacklist_to_config()

    # ── 上行黑名单字符串管理 ──────────────────────────────────────────────

    def _on_blacklist_add(self):
        s = self.edit_bl_str.text().strip()
        if not s or s in self._ul_blacklist:
            return
        self._ul_blacklist[s] = 0
        self.edit_bl_str.clear()
        self._on_dl_clear_stats()

    def _on_blacklist_remove(self, s: str):
        self._ul_blacklist.pop(s, None)
        self._on_dl_clear_stats()

    def _update_blacklist_hit(self, matched_str: str):
        """上行命中时递增该字符串在黑名单表中的计数"""
        if matched_str in self._ul_blacklist:
            self._ul_blacklist[matched_str] = self._ul_blacklist[matched_str] + 1
        else:
            self._ul_blacklist[matched_str] = 1
        # 刷新黑名单表中对应行的命中次数
        for r in range(self.bl_table.rowCount()):
            item = self.bl_table.item(r, 0)
            if item and item.text() == matched_str:
                cnt_item = self.bl_table.item(r, 1)
                if cnt_item:
                    cnt_item.setText(str(self._ul_blacklist[matched_str]))
                break

    def _refresh_blacklist_table(self):
        self.bl_table.setRowCount(0)
        for s, hits in self._ul_blacklist.items():
            row = self.bl_table.rowCount()
            self.bl_table.insertRow(row)
            self.bl_table.setItem(row, 0, QTableWidgetItem(s))
            cnt_item = QTableWidgetItem(str(hits))
            cnt_item.setTextAlignment(Qt.AlignCenter)
            self.bl_table.setItem(row, 1, cnt_item)
            btn_del = QPushButton("🗑 删除")
            btn_del.setMinimumSize(72, 30)
            btn_del.setStyleSheet("QPushButton{padding:4px 8px;}")
            btn_del.clicked.connect(lambda _, _s=s: self._on_blacklist_remove(_s))
            self.bl_table.setCellWidget(row, 2, btn_del)
        self.bl_table.resizeRowsToContents()

    def _save_ul_blacklist_to_config(self):
        app_config.set("ul_blacklist_strings",
                       [{"str": k, "hits": v} for k, v in self._ul_blacklist.items()])
        app_config.save()

    def _on_open_remote_admin(self):
        """在默认浏览器中打开远程管理页面"""
        port = self.spin_admin_port.value()
        url = QUrl(f"http://127.0.0.1:{port}/")
        if QDesktopServices.openUrl(url):
            self.lbl_status.setText(f"已打开 http://127.0.0.1:{port}/")
        else:
            self.lbl_status.setText("打开失败，请确认代理已启动")
            QMessageBox.warning(self, "提示", "无法打开浏览器，请确认代理已启动且管理端口已监听。")

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
        self.btn_edit_passwd.clicked.connect(self._on_edit_passwd)
        self.btn_del_user.clicked.connect(self._on_del_user)
        self.btn_user_select_all.clicked.connect(
            lambda: self._set_all_user_checks(Qt.Checked)
        )
        self.btn_user_clear_checks.clicked.connect(
            lambda: self._set_all_user_checks(Qt.Unchecked)
        )
        self.btn_reload_users.clicked.connect(self._on_reload_users)
        self.user_table.cellDoubleClicked.connect(self._on_user_table_double_click)

        log_bus.event_log.connect(self._on_event_log)
        log_bus.conn_added.connect(self._on_conn_added)
        log_bus.conn_closed.connect(self._on_conn_closed)
        log_bus.record_updated.connect(self._on_record_updated)
        log_bus.record_count.connect(self._on_record_count)
        log_bus.conn_detail.connect(self._on_conn_detail)
        log_bus.replay_progress.connect(self._on_replay_progress)
        log_bus.replay_progress_detail.connect(self._on_replay_progress_detail)
        log_bus.conn_mode_update.connect(self._on_conn_mode_update)
        log_bus.conn_game_id_update.connect(self._on_conn_game_id_update)
        log_bus.conn_3366_product.connect(self._on_conn_3366_product)
        log_bus.conn_ace_channels_updated.connect(self._on_conn_ace_channels_updated)
        log_bus.admin_log.connect(self._on_admin_log)
        log_bus.dl_intercept_log.connect(self._on_dl_intercept_log)
        log_bus.dl_intercept_event.connect(self._on_dl_intercept_event)

        log_bus.stream_raw_data.connect(lambda c, d, l, r: self._add_stream_row(self.tb_stream_raw, self.stream_raw_data_cache, c, d, l, r))
        log_bus.stream_parsed_data.connect(lambda c, d, p, l, r: self._add_stream_row(self.tb_stream_parsed, self.stream_parsed_data_cache, c, d, l, r, prefix=p))
        log_bus.stream_sent_data.connect(lambda c, d, l, r: self._add_stream_row(self.tb_stream_sent, self.stream_sent_data_cache, c, d, l, r))
        log_bus.users_updated.connect(self._refresh_user_table)
        self._ext_check_done.connect(self._on_ext_check_result)

        # 连接表详情按钮 + 双击 + 详细日志勾选
        self.btn_conn_detail.clicked.connect(self._on_show_detail)
        self.conn_table.doubleClicked.connect(lambda _: self._on_show_detail())
        self.cb_detail_01.toggled.connect(self._save_config_from_ui)
        self.cb_replay_strict_match.toggled.connect(self._save_config_from_ui)

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
        self._loading_config = True
        try:
            self._load_config_to_ui_inner()
        finally:
            self._loading_config = False

    def _load_config_to_ui_inner(self):
        self.spin_1081.setValue(app_config.get("port_record"))
        self.spin_1080.setValue(app_config.get("port_replay"))
        self.spin_record_idle_timeout.setValue(app_config.get("record_idle_timeout") or 180)
        self.cb_replay_strict_match.setChecked(app_config.get("replay_strict_match", True))
        self.spin_01_threshold.setValue(app_config.get("auto_disconnect_01_threshold") or 100)
        self.cb_capture_mode.setChecked(
            bool(app_config.get("special_dual_capture_mode_enabled", False))
        )
        self.edit_capture_user.setText(
            str(app_config.get("special_capture_user", "test") or "test")
        )
        self.cb_ext.setChecked(app_config.get("ext_enabled"))
        self.edit_ext_ip.setText(app_config.get("ext_ip"))
        self.spin_ext_port.setValue(app_config.get("ext_port"))
        self.cb_detail_01.setChecked(app_config.get("detail_01_log"))
        self.spin_admin_port.setValue(app_config.get("admin_port") or 8787)
        self.edit_admin_token.setText(app_config.get("admin_token") or "")
        self.edit_dl_search.setText(app_config.get("dl_search_str") or "")
        self.edit_dl_replace.setText(app_config.get("dl_replace_str") or "")
        destroy = app_config.get("dl_destroy_mode_enabled")
        self.cb_destroy_mode.setChecked(bool(destroy))
        self.lbl_dl_replace.setEnabled(not destroy)
        self.edit_dl_replace.setEnabled(not destroy)
        self.cb_ace_https_block.setChecked(app_config.get("ace_https_block_enabled"))
        self.cb_ace_https_block_replay_only.setChecked(app_config.get("ace_https_block_replay_only"))
        self.edit_ace_https_block_host.setText(app_config.get("ace_https_block_host") or "")
        self.cb_az_dl_intercept.setChecked(bool(app_config.get("az_dl_intercept_enabled")))
        self.cb_chunk_block.setChecked(app_config.get("ace_chunk_block_enabled"))
        self.edit_chunk_block_pattern.setText(app_config.get("ace_chunk_block_pattern") or "")
        self.cb_dl_01_block.setChecked(app_config.get("dl_01_block_enabled"))
        self.spin_dl_01_threshold.setValue(app_config.get("dl_01_block_threshold") or 1000)
        self.cb_ul_dirty_clean.setChecked(bool(app_config.get("ul_dirty_clean_enabled")))
        self.cb_ul_truncate.setChecked(bool(app_config.get("ul_truncate_abab_enabled")))
        self.spin_ul_truncate_min.setValue(int(app_config.get("ul_truncate_abab_min_len") or 500))
        # 加载上行黑名单字符串（新格式 ul_blacklist_strings）
        bl_list = app_config.get("ul_blacklist_strings") or []
        self._ul_blacklist = {
            item["str"]: int(item.get("hits", 0))
            for item in bl_list if isinstance(item, dict) and item.get("str")
        }
        self._refresh_blacklist_table()
        # 区间填充：块帧均为二进制数据，start/stop 留空 = 全明文清零（推荐）
        self.edit_zone_start.setText(
            app_config.get("ace_chunk_block_start_marker") or "")
        self.spin_zone_nth.setValue(
            int(app_config.get("ace_chunk_block_start_marker_nth") or 1))
        self.edit_zone_stop.setText(
            app_config.get("ace_chunk_block_stop_marker") or "")
        self.edit_zone_fill.setText(
            app_config.get("ace_chunk_block_fill_byte") or "00")

    def _save_config_from_ui(self):
        """将界面控件值保存到 AppConfig（并写磁盘）"""
        if getattr(self, "_loading_config", False):
            return  # 加载配置阶段，禁止写回（防止中间状态覆盖磁盘值）
        app_config.set("port_record", self.spin_1081.value())
        app_config.set("port_replay", self.spin_1080.value())
        _idle = self.spin_record_idle_timeout.value()
        app_config.set("record_idle_timeout", _idle)
        app_config.set("replay_idle_timeout", _idle)
        app_config.set("replay_strict_match", self.cb_replay_strict_match.isChecked())
        app_config.set(
            "special_dual_capture_mode_enabled",
            self.cb_capture_mode.isChecked(),
        )
        capture_user = self.edit_capture_user.text().strip() or "test"
        app_config.set("special_capture_user", capture_user)
        app_config.set("ext_enabled", self.cb_ext.isChecked())
        app_config.set("ext_ip",      self.edit_ext_ip.text().strip())
        app_config.set("ext_port",    self.spin_ext_port.value())
        app_config.set("detail_01_log", self.cb_detail_01.isChecked())
        app_config.set("admin_port",  self.spin_admin_port.value())
        tok = self.edit_admin_token.text().strip()
        if len(tok) >= 6:  # 仅当输入了有效密码（≥6位）时才覆盖
            app_config.set("admin_token", tok)
        app_config.set("az_dl_intercept_enabled", self.cb_az_dl_intercept.isChecked())
        app_config.set("dl_search_str", self.edit_dl_search.text())
        app_config.set("dl_replace_str", self.edit_dl_replace.text())
        app_config.set("dl_destroy_mode_enabled", self.cb_destroy_mode.isChecked())
        app_config.set("ace_https_block_enabled", self.cb_ace_https_block.isChecked())
        app_config.set("ace_https_block_replay_only", self.cb_ace_https_block_replay_only.isChecked())
        host_val = self.edit_ace_https_block_host.text().strip()
        if host_val:
            app_config.set("ace_https_block_host", host_val)
        app_config.set("ace_chunk_block_enabled", self.cb_chunk_block.isChecked())
        pat_val = self.edit_chunk_block_pattern.text().strip()
        if pat_val:
            app_config.set("ace_chunk_block_pattern", pat_val)
        app_config.set("dl_01_block_enabled", self.cb_dl_01_block.isChecked())
        app_config.set("dl_01_block_threshold", self.spin_dl_01_threshold.value())
        app_config.set("ul_dirty_clean_enabled", self.cb_ul_dirty_clean.isChecked())
        app_config.set("ul_truncate_abab_enabled", self.cb_ul_truncate.isChecked())
        app_config.set("ul_truncate_abab_min_len", self.spin_ul_truncate_min.value())
        app_config.set("ul_blacklist_strings",
                       [{"str": k, "hits": v} for k, v in self._ul_blacklist.items()])
        # 区间填充字段
        app_config.set("ace_chunk_block_start_marker",
                       self.edit_zone_start.text().strip())
        app_config.set("ace_chunk_block_start_marker_nth",
                       self.spin_zone_nth.value())
        app_config.set("ace_chunk_block_stop_marker",
                       self.edit_zone_stop.text().strip())
        app_config.set("ace_chunk_block_fill_byte",
                       self.edit_zone_fill.text().strip())
        app_config.save()

    # ─── 槽 ─────────────────────────────────
    def _on_capture_timeline_mark(self):
        phase = self.combo_capture_phase.currentData()
        label = self.combo_capture_phase.currentText()
        if special_capture_manager.mark_timeline(str(phase or "unknown")):
            self.lbl_capture_mark.setText(
                f"✓ {datetime.now().strftime('%H:%M:%S.%f')[:-3]} {label}"
            )
            self.lbl_capture_mark.setStyleSheet("color:#15803d;font-size:11px;")
        else:
            self.lbl_capture_mark.setText("请先开启采集模式并启动代理")
            self.lbl_capture_mark.setStyleSheet("color:#b45309;font-size:11px;")

    def _on_start(self):
        self._save_config_from_ui()   # 启动时顺手保存当前配置
        cfg = {
            "port_1080":   self.spin_1080.value(),
            "port_1081":   self.spin_1081.value(),
            "users_record": user_manager.to_dict("record"),
            "users_replay": user_manager.to_dict("replay"),
            "ext_enabled": self.cb_ext.isChecked(),
            "ext_ip":      self.edit_ext_ip.text().strip(),
            "ext_port":    self.spin_ext_port.value(),
            "ext_proto":   "SOCKS5",
            "tool_auth_ok": (self.edit_pwd.text().strip() == "999999"),
            "admin_enabled": app_config.get("admin_enabled"),
            "admin_bind": app_config.get("admin_bind"),
            "admin_port": app_config.get("admin_port"),
            "admin_token": app_config.get("admin_token"),
        }
        _event("INFO", "Engine", f"正在启动代理  录制端口={cfg['port_1081']}  重放端口={cfg['port_1080']}")
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
            f"运行中 | 录制:{cfg['port_1081']}(鉴权 {len(cfg['users_record'])} 账号)  "
            f"重放:{cfg['port_1080']}(鉴权 {len(cfg['users_replay'])} 账号)")
        if cfg.get("admin_enabled"):
            _event(
                "INFO",
                "AdminAPI",
                f"浏览器管理：打开 http://<本机IP>:{cfg.get('admin_port', 8787)}/ 输入密码登录 "
                f"(密码在 C:\\PyProxyApp\\config.json 的 admin_token)"
            )

    def _on_stop(self):
        _event("INFO", "Engine", "正在停止代理…")
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
                                    d["note"], d.get("allow_multi", False), d.get("perm", "both")):
                QMessageBox.warning(self, "错误", f"用户名 {d['username']} 已存在")
                return
            self._refresh_user_table()
            _event("INFO", "UserMgr", f"添加用户 [{d['username']}]  权限={d.get('perm','both')}  到期={d['expire']}")

    def _on_edit_passwd(self):
        row = self.user_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "提示", "请先选中要修改密码的用户")
            return
        uname_item = self.user_table.item(row, 1)
        if uname_item is None:
            return
        uname = uname_item.text()

        dlg = QDialog(self)
        dlg.setWindowTitle(f"修改密码 — {uname}")
        dlg.setFixedSize(320, 160)
        form = QFormLayout(dlg)
        form.setSpacing(10)
        form.setContentsMargins(16, 16, 16, 12)

        edit_new  = QLineEdit()
        edit_new.setPlaceholderText("新密码")
        edit_conf = QLineEdit()
        edit_conf.setPlaceholderText("再次输入新密码")
        form.addRow("新密码:", edit_new)
        form.addRow("确认密码:", edit_conf)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        form.addRow(btns)

        if dlg.exec() != QDialog.Accepted:
            return
        new_pass  = edit_new.text()
        conf_pass = edit_conf.text()
        if not new_pass:
            QMessageBox.warning(self, "错误", "新密码不能为空")
            return
        if new_pass != conf_pass:
            QMessageBox.warning(self, "错误", "两次输入的密码不一致")
            return
        user_manager.update_password(uname, new_pass)
        self._refresh_user_table()
        _event("INFO", "UserMgr", f"[{uname}] 密码已修改")
        QMessageBox.information(self, "完成", f"用户 [{uname}] 密码已修改，请点击「重载到代理」使其生效。")

    def _on_del_user(self):
        usernames = []
        for row in range(self.user_table.rowCount()):
            check_item = self.user_table.item(row, 0)
            username_item = self.user_table.item(row, 1)
            if (
                check_item is not None
                and username_item is not None
                and check_item.checkState() == Qt.Checked
            ):
                usernames.append(username_item.text())

        # 兼容原来的单行选择操作：未勾选时使用当前选中行。
        if not usernames:
            selected_rows = sorted({
                item.row() for item in self.user_table.selectedItems()
            })
            usernames = [
                self.user_table.item(row, 1).text()
                for row in selected_rows
                if self.user_table.item(row, 1) is not None
            ]
        if not usernames:
            QMessageBox.information(self, "提示", "请先勾选需要删除的账号")
            return

        preview = "、".join(usernames[:8])
        if len(usernames) > 8:
            preview += f" 等 {len(usernames)} 个账号"
        if QMessageBox.question(
            self,
            "确认批量删除",
            f"确定删除：{preview}？",
        ) == QMessageBox.Yes:
            removed = user_manager.remove_many(usernames)
            self._refresh_user_table()
            _event(
                "INFO",
                "UserMgr",
                f"批量删除 {removed} 个用户：{', '.join(usernames)}",
            )

    def _set_all_user_checks(self, state):
        """全选或取消用户表的批量操作复选框。"""
        for row in range(self.user_table.rowCount()):
            item = self.user_table.item(row, 0)
            if item is not None:
                item.setCheckState(state)

    def _on_user_table_double_click(self, row: int, col: int):
        """双击“多开”列（col=6）快速切换该用户的多开权限。"""
        if col != 6:
            return
        uname_item = self.user_table.item(row, 1)
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
        checked_usernames = set()
        for row in range(self.user_table.rowCount()):
            check_item = self.user_table.item(row, 0)
            username_item = self.user_table.item(row, 1)
            if (
                check_item is not None
                and username_item is not None
                and check_item.checkState() == Qt.Checked
            ):
                checked_usernames.add(username_item.text())

        self.user_table.setRowCount(0)
        today = date.today().isoformat()
        for u in user_manager.all():
            row = self.user_table.rowCount()
            self.user_table.insertRow(row)
            exp = u.get("expire", "never")
            expired = exp != "never" and exp < today
            status  = "⚠ 已过期" if expired else "✅ 有效"
            allow_multi = u.get("allow_multi", False)
            multi_text  = "✅ 允许" if allow_multi else "🔒 禁止"
            perm = (u.get("perm") or "both").lower()
            perm_text = "录制+重放" if perm == "both" else ("仅录制" if perm == "record" else "仅重放")
            check_item = QTableWidgetItem()
            check_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable)
            check_item.setCheckState(
                Qt.Checked if u["username"] in checked_usernames else Qt.Unchecked
            )
            check_item.setTextAlignment(Qt.AlignCenter)
            self.user_table.setItem(row, 0, check_item)
            for col, text in enumerate([u["username"], u["password"], exp, perm_text,
                                        u.get("note", ""), multi_text, status], start=1):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignCenter)
                if expired:
                    item.setForeground(QColor("#888"))
                elif col == 6 and allow_multi:
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
            f'<span style="color:#888888">[{ts}]</span> '
            f'<span style="color:{color};font-weight:bold">[{level}]</span> '
            f'<span style="color:#aaaaaa">&lt;{_esc(tag)}&gt;</span> '
            f'<span style="color:{color}">{_esc(msg)}</span><br>'
        )
        self._append_html(self.log_view, html, max_lines=1000)

    @staticmethod
    def _append_html(edit: QTextEdit, html: str, max_lines: int = 1000):
        """向 QTextEdit 追加 HTML，超出 max_lines 时从头部删除"""
        doc = edit.document()
        cursor = edit.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(html)
        edit.setTextCursor(cursor)
        edit.ensureCursorVisible()
        while doc.blockCount() > max_lines:
            del_cur = QTextCursor(doc.begin())
            del_cur.movePosition(QTextCursor.NextBlock, QTextCursor.KeepAnchor)
            del_cur.removeSelectedText()

    def _display_account_game_cell(
        self, ace_id: str, ip: str, lookup: dict[str, str]
    ) -> tuple[str, str]:
        """
        连接表「账户 / 游戏」：优先 ACE 标识映射；无法映射时用 3366 产品名/ID（暗区等）。
        有账户 ID（如 01 0A 00 23 解析出的数字串）时一并显示，格式：账户ID 游戏名（与表头顺序一致）
        """
        ace_id = (ace_id or "").strip()
        hx = (self._ip_3366_hex.get(ip) or "").strip().upper()
        nm3366 = (self._ip_3366_name.get(ip) or "").strip()
        cfg_name = lookup.get(hx, "") if hx else ""
        game_name = (cfg_name or nm3366 or "").strip()

        def _tip3366(aid: str) -> str:
            lines = []
            if hx:
                lines.append(f"3366 产品 ID: {hx}")
            if cfg_name or (nm3366 and nm3366 != hx):
                lines.append(f"产品名: {cfg_name or nm3366}")
            if aid:
                lines.append(f"ACE 标识 (0A 00 23 等): {aid}")
            return "\n".join(lines) if lines else ""

        def _is_product_hex(s: str) -> bool:
            """8 位 hex 产品 ID（如 0000094E）"""
            t = "".join((s or "").split()).upper()
            return len(t) == 8 and all("0" <= c <= "9" or "A" <= c <= "F" for c in t)

        if not ace_id:
            show = (game_name or hx or "").strip()
            if not show:
                return "—", ""
            return show, _tip3366("")

        txt, tip = ace_identifier_display(ace_id, lookup)
        if txt != "未知":
            extra = _tip3366(ace_id)
            if extra and extra not in (tip or ""):
                return txt, f"{tip}\n{extra}" if tip else extra
            return txt, tip

        # ace_id 未在 lookup 中（多为账户 ID 如 1285734663），按表头顺序显示：账户 ID + 游戏名
        if game_name and ace_id and not _is_product_hex(ace_id):
            return f"{ace_id} {game_name}", _tip3366(ace_id)
        if game_name:
            return game_name, _tip3366(ace_id)
        if hx:
            return hx, _tip3366(ace_id)
        # 仅有账户 ID 无游戏名时直接显示账户 ID
        if ace_id:
            return ace_id, _tip3366(ace_id)
        return txt, tip

    def _pair_account_game_cells(
        self,
        rec_id: str,
        rep_id: str,
        ip: str,
        lookup: dict[str, str],
    ) -> tuple[str, str]:
        tips: list[str] = []
        parts: list[str] = []
        if rec_id:
            dr, tr = self._display_account_game_cell(rec_id, ip, lookup)
            parts.append(f"{dr}(录)")
            if tr:
                tips.append(tr)
        if rep_id:
            dp, tp = self._display_account_game_cell(rep_id, ip, lookup)
            parts.append(f"{dp}(放)")
            if tp:
                tips.append(tp)
        if not parts:
            return "—", ""
        return " / ".join(parts), "\n".join(tips)

    def _update_row_mode_and_id(self, ip: str, row: int) -> tuple[str, int]:
        rec_cnt = self._ip_rec_active.get(ip, 0)
        rep_cnt = self._ip_rep_active.get(ip, 0)
        capture_active = any(
            info[0] == ip and len(info) > 1 and info[1] == "专项采集"
            for info in self._conn_info.values()
        )
        
        rec_id = self._ip_rec_game_id.get(ip, "")
        rep_id = self._ip_rep_game_id.get(ip, "")
        lookup = build_ace_identifier_lookup(app_config)

        if rec_cnt > 0 and rep_cnt > 0:
            if rec_id and rep_id and rec_id == rep_id:
                display_mode = "实时重放"
                mode_color = "#4fc3f7"
                display_id, id_tip = self._display_account_game_cell(rec_id, ip, lookup)
            else:
                display_mode = "重放"
                mode_color = "#8b5cf6"
                if rec_id and rep_id:
                    display_id, id_tip = self._pair_account_game_cells(
                        rec_id, rep_id, ip, lookup
                    )
                elif rec_id or rep_id:
                    display_id, id_tip = self._display_account_game_cell(
                        rec_id or rep_id, ip, lookup
                    )
                else:
                    display_id, id_tip = "—", ""
        elif rec_cnt > 0:
            display_mode = "专项采集" if capture_active else "录制"
            mode_color = "#d97706" if capture_active else "#ef4444"
            display_id, id_tip = (
                self._display_account_game_cell(rec_id, ip, lookup)
                if rec_id
                else self._display_account_game_cell("", ip, lookup)
            )
        elif rep_cnt > 0:
            # 跨IP实时重放：本IP只有重放连接，但其游戏账号正被另一个IP活跃录制
            if rep_id and recording_pool.is_game_id_actively_recording(rep_id):
                display_mode = "实时重放"
                mode_color = "#0284c7"
            else:
                display_mode = "重放"
                mode_color = "#8b5cf6"
            display_id, id_tip = (
                self._display_account_game_cell(rep_id, ip, lookup)
                if rep_id
                else self._display_account_game_cell("", ip, lookup)
            )
        else:
            item = self.conn_table.item(row, 4)
            display_mode = item.text() if item else "未知"
            mode_color = "#666666"
            if rec_id or rep_id:
                display_id, id_tip = self._pair_account_game_cells(
                    rec_id, rep_id, ip, lookup
                )
            else:
                display_id, id_tip = self._display_account_game_cell("", ip, lookup)

        a01, a36 = recording_pool.get_active_session_ace_ids(ip)
        ace_mismatch = bool(a01 and a36 and a01 != a36)
        id_fg = "#374151"
        if ace_mismatch:
            tail = " · ⚠双通道账号不一致"
            if display_id and display_id != "—":
                display_id = display_id + tail
            else:
                display_id = "⚠ 01≠3366"
            extra = (
                f"01 通道账号: {a01}\n3366 通道账号: {a36}\n\n"
                f"会话 game_id 仍以 01 为准；录制不中断。"
            )
            id_tip = f"{id_tip}\n\n{extra}" if id_tip else extra
            id_fg = "#ff9800"

        self._set_cell(row, 3, display_id, tooltip=id_tip, color=id_fg)
        self._set_cell(row, 4, display_mode, color=mode_color)
        
        return display_mode, rep_cnt

    def _refresh_connection_summary(self) -> None:
        if not hasattr(self, "conn_summary_labels"):
            return
        counts = {"record": 0, "replay": 0, "live": 0, "waiting": 0}
        for ip, active in self._ip_active.items():
            if active <= 0:
                continue
            rec = self._ip_rec_active.get(ip, 0)
            rep = self._ip_rep_active.get(ip, 0)
            rep_id = self._ip_rep_game_id.get(ip, "")
            if rec > 0 and rep == 0:
                counts["record"] += 1
            if rep > 0 and not rep_id:
                counts["waiting"] += 1
                continue
            if rep > 0 and (
                (rec > 0 and self._ip_rec_game_id.get(ip) == rep_id)
                or recording_pool.is_game_id_actively_recording(rep_id)
            ):
                counts["live"] += 1
            elif rep > 0:
                counts["replay"] += 1
        titles = {
            "record": "录制中",
            "replay": "重放中",
            "live": "实时重放",
            "waiting": "待匹配",
        }
        for key, label in self.conn_summary_labels.items():
            label.setText(f"{titles[key]}\n{counts[key]}")

    # ─── 连接表（按 IP 分组）────────────────
    def _on_conn_added(self, conn_id: str, src: str, dst: str, user: str, actual_mode: str = ""):
        ip = src.split(":")[0]
        
        # 判断如果是 ACE 或相关端口的特殊处理标识
        is_3366 = "3366" in dst or "0x33" in dst # 如果你需要精确判断3366的特征，这里可以根据dst目标端口进行适配判断，目前这里做通用设计
        
        if actual_mode == "record":
            mode = "录制"
        elif actual_mode == "capture":
            mode = "专项采集"
        elif actual_mode == "replay":
            mode = "重放"
        else:
            mode = "透传"
        
        # 将连接信息也加入 33 66 标识
        self._conn_info[conn_id] = (ip, mode, is_3366)
        self._ip_last_active[ip]  = datetime.now()

        if ip not in self._ip_rows:
            row = self.conn_table.rowCount()
            self._ip_rows[ip]   = row
            self._ip_active[ip] = 0
            self._ip_rec_active[ip] = 0
            self._ip_rep_active[ip] = 0
            self._ip_total[ip]  = 0
            self.conn_table.insertRow(row)
            for col in range(9):
                item = QTableWidgetItem("")
                item.setTextAlignment(Qt.AlignCenter)
                self.conn_table.setItem(row, col, item)

        prev_active = self._ip_active.get(ip, 0)
        self._ip_active[ip] = prev_active + 1
        self._ip_total[ip]  = self._ip_total.get(ip, 0) + 1
        
        if mode in ("录制", "专项采集"):
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
        
        display_mode, rep_cnt = self._update_row_mode_and_id(ip, row)
        
        self._set_cell(row, 5, str(self._ip_total[ip]))
        self._set_cell(row, 6, str(self._ip_active[ip]))
        # 重放进度列：纯录制模式清空缓存并显示 —，重放/实时重放模式保留或恢复缓存
        if display_mode in ("录制", "专项采集"):
            self._ip_replay_progress.pop(ip, None)
            self._ip_replay_progress_detail.pop(ip, None)
            self._set_cell(row, 7, "—", color="#666666")
        else:
            d = self._ip_replay_progress_detail.get(ip)
            if d:
                if len(d) >= 9:
                    prog_text = self._format_replay_progress_text(*d)
                else:
                    prog_text = self._format_replay_progress_text(d[0], d[1], d[2], d[3])
            else:
                prog = self._ip_replay_progress.get(ip, (0, 0))
                prog_text = f"{prog[0]}/{prog[1]}" if prog[1] > 0 else "—"
            self._set_cell(row, 7, prog_text, color="#ce93d8")
        self._set_cell(row, 8, "● 活跃 刚刚", color="#3fb950")
        self._refresh_connection_summary()

    def _on_conn_closed(self, conn_id: str):
        info = self._conn_info.pop(conn_id, None)
        if info is None:
            return
            
        if len(info) == 2:
            ip, mode = info
            is_3366 = False
        else:
            ip, mode, is_3366 = info
        now = datetime.now()
        self._ip_last_active[ip] = now
        self._ip_active[ip] = max(0, self._ip_active.get(ip, 1) - 1)
        
        if mode in ("录制", "专项采集"):
            self._ip_rec_active[ip] = max(0, self._ip_rec_active.get(ip, 1) - 1)
        else:
            self._ip_rep_active[ip] = max(0, self._ip_rep_active.get(ip, 1) - 1)
            
        row = self._ip_rows.get(ip)
        if row is None or row >= self.conn_table.rowCount():
            return
            
        display_mode, rep_cnt = self._update_row_mode_and_id(ip, row)

        # 切回纯录制模式时清空重放进度缓存和进度列
        if display_mode in ("录制", "专项采集") and rep_cnt == 0:
            self._ip_replay_progress.pop(ip, None)
            self._ip_replay_progress_detail.pop(ip, None)
            self._set_cell(row, 7, "—", color="#666666")

        active = self._ip_active[ip]
        self._set_cell(row, 6, str(active))
        if active == 0:
            self._set_cell(row, 8, "○ 空闲 刚刚", color="#666666")
        self._refresh_connection_summary()

    def _set_cell(self, row: int, col: int, text: str, color: str = "", tooltip: str | None = None):
        item = self.conn_table.item(row, col)
        if item is None:
            item = QTableWidgetItem(text)
            item.setTextAlignment(Qt.AlignCenter)
            self.conn_table.setItem(row, col, item)
        else:
            item.setText(text)
        item.setForeground(QColor(color or "#374151"))
        if tooltip is not None:
            item.setToolTip(tooltip)

    # ─── 录制管理 Tab 槽 ─────────────────────
    def _on_record_updated(self):
        """录制池结构变化时全量刷新会话列表（保留当前选中 游戏用户ID）"""
        sessions = recording_pool.get_all_sessions()
        cur_row = self.rec_session_table.currentRow()
        cur_game_id = ""
        if cur_row >= 0:
            it = self.rec_session_table.item(cur_row, 0)
            if it:
                cur_game_id = it.data(Qt.UserRole) or ""

        self.rec_session_table.setRowCount(0)
        self._rec_game_id_rows: dict[str, int] = {}   # game_id → 行号，供轻量更新用
        restore_row = -1
        for i, s in enumerate(sessions):
            self.rec_session_table.insertRow(i)
            gid = (s.get("game_id") or "").strip()
            gid_display = gid if gid else "—"
            gid_item = QTableWidgetItem(gid_display)
            gid_item.setTextAlignment(Qt.AlignCenter)
            gid_item.setData(Qt.UserRole, gid)
            gid_item.setToolTip(gid if gid.startswith("待识别-") else f"游戏用户ID: {gid}")

            n01 = int(s.get("count_01", 0) or 0)
            n3366 = int(s.get("count_3366", 0) or 0)
            n01_item = QTableWidgetItem(str(n01))
            n01_item.setTextAlignment(Qt.AlignCenter)
            n3366_item = QTableWidgetItem(str(n3366))
            n3366_item.setTextAlignment(Qt.AlignCenter)

            ips = s.get("ips", [])
            ip_txt = ", ".join(ips) if ips else "—"
            ip_item = QTableWidgetItem(ip_txt)
            ip_item.setTextAlignment(Qt.AlignCenter)

            # 最近录制时间
            last_t = s.get("last_record_at", 0.0) or 0.0
            if last_t > 0:
                last_str = datetime.fromtimestamp(last_t).strftime("%m-%d %H:%M:%S")
            else:
                last_str = "—"
            last_item = QTableWidgetItem(last_str)
            last_item.setTextAlignment(Qt.AlignCenter)
            if last_t > 0:
                last_item.setToolTip(datetime.fromtimestamp(last_t).strftime("%Y-%m-%d %H:%M:%S"))

            status = "● 录制中" if s.get("active") else "○ 已停止"
            st_item = QTableWidgetItem(status)
            st_item.setTextAlignment(Qt.AlignCenter)

            if s.get("active"):
                for item in (gid_item, n01_item, n3366_item, ip_item, last_item, st_item):
                    item.setForeground(QColor("#ff6b6b"))

            self.rec_session_table.setItem(i, 0, gid_item)
            self.rec_session_table.setItem(i, 1, n01_item)
            self.rec_session_table.setItem(i, 2, n3366_item)
            self.rec_session_table.setItem(i, 3, ip_item)
            self.rec_session_table.setItem(i, 4, last_item)
            self.rec_session_table.setItem(i, 5, st_item)
            # 详情按钮
            btn_detail = QPushButton("详情")
            btn_detail.setFixedSize(52, 22)
            btn_detail.setStyleSheet("font-size:11px; padding:0;")
            btn_detail.clicked.connect(lambda _checked, g=gid, d=gid_display: self._on_rec_detail_btn(g, d))
            self.rec_session_table.setCellWidget(i, 6, btn_detail)
            self._rec_game_id_rows[gid] = i
            if gid == cur_game_id:
                restore_row = i

        if hasattr(self, "rec_summary_labels"):
            active_count = sum(1 for s in sessions if s.get("active"))
            ready_count = sum(
                1 for s in sessions
                if (s.get("game_id") or "").strip()
                and (int(s.get("count_01", 0) or 0) + int(s.get("count_3366", 0) or 0)) > 0
            )
            total_01 = sum(int(s.get("count_01", 0) or 0) for s in sessions)
            total_33 = sum(int(s.get("count_3366", 0) or 0) for s in sessions)
            self.rec_summary_labels["active"].setText(f"当前录制: {active_count}")
            self.rec_summary_labels["ready"].setText(f"可重放账户: {ready_count}")
            self.rec_summary_labels["templates01"].setText(f"01 模板: {total_01}")
            self.rec_summary_labels["templates33"].setText(f"33 模板: {total_33}")

        if restore_row >= 0:
            self.rec_session_table.selectRow(restore_row)

    def _on_record_count(self, sid: str, count: int):
        """轻量更新：按 sid 查找 game_id 后刷新对应行；找不到则全量刷新"""
        gid = recording_pool.get_game_id_for_sid(sid)
        if not gid:
            self._on_record_updated()
            return
        row = getattr(self, "_rec_game_id_rows", {}).get(gid, -1)
        if row < 0:
            self._on_record_updated()
            return
        n01, n3366 = recording_pool.get_aggregated_counts_for_game_id(gid)
        n01_item = self.rec_session_table.item(row, 1)
        n3366_item = self.rec_session_table.item(row, 2)
        if n01_item:
            n01_item.setText(str(n01))
        if n3366_item:
            n3366_item.setText(str(n3366))
        # 同步刷新最近录制时间（列4）
        last_t = recording_pool.get_last_record_at_for_game_id(gid)
        last_item = self.rec_session_table.item(row, 4)
        if last_item:
            if last_t > 0:
                last_item.setText(datetime.fromtimestamp(last_t).strftime("%m-%d %H:%M:%S"))
                last_item.setToolTip(datetime.fromtimestamp(last_t).strftime("%Y-%m-%d %H:%M:%S"))
            else:
                last_item.setText("—")

    def _on_rec_detail_btn(self, game_id: str, display: str):
        """点击"详情"按钮：展开底部面板并加载对应游戏ID的加密区数据"""
        if not game_id:
            return
        # 展开底部详情区
        self._rec_outer_splitter.setSizes([180, 340])
        self.lbl_rec_detail_title.setText(f"加密区详情 — {display}")
        self._load_rec_detail(game_id)

    def _load_rec_detail(self, game_id: str):
        """加载指定 game_id 的加密区列表到底部面板"""
        rows = recording_pool.get_pool_item_rows_by_game_id(game_id)
        self._rec_current_rows = rows or []
        self._rec_current_pkts = [r["payload"] for r in rows]
        self.rec_pkt_table.setRowCount(0)
        self.rec_hex_view.clear()
        for idx, row in enumerate(rows):
            raw_pkt = row.get("raw_packet") or row["payload"]
            pkt = row["payload"]
            self.rec_pkt_table.insertRow(idx)
            n_item = QTableWidgetItem(str(idx + 1))
            n_item.setTextAlignment(Qt.AlignCenter)
            src_val = row.get("source") or "01"
            src_display = "33" if str(src_val).startswith("3366") else src_val
            src_item = QTableWidgetItem(src_display)
            src_item.setTextAlignment(Qt.AlignCenter)
            src_item.setToolTip(row.get("source_detail") or "")
            sz_item = QTableWidgetItem(str(len(raw_pkt)))
            sz_item.setTextAlignment(Qt.AlignCenter)
            preview = " ".join(f"{b:02X}" for b in raw_pkt[:16])
            if len(raw_pkt) > 16:
                preview += " …"
            pr_item = QTableWidgetItem(preview)
            ak = row.get("anchor_kind") or ""
            pr_item.setToolTip(
                "原始 01 0A 00 09/21 块前16B" if raw_pkt and (raw_pkt[:4] == b"\x01\x0a\x00\x09" or raw_pkt[:4] == b"\x01\x0a\x00\x21") else
                "原始 0A 00 09 块前16B" if raw_pkt and raw_pkt[:3] == b"\x0a\x00\x09" else
                _REC_ANCHOR_TOOLTIP.get(ak, "01 0A 00 09/21 或 0A 00 09 块。"),
            )
            self.rec_pkt_table.setItem(idx, 0, n_item)
            self.rec_pkt_table.setItem(idx, 1, src_item)
            self.rec_pkt_table.setItem(idx, 2, sz_item)
            self.rec_pkt_table.setItem(idx, 3, pr_item)
        if rows:
            self.rec_pkt_table.selectRow(0)

    def _on_rec_session_selected(self, current, _previous):
        """选中一条录制会话（键盘/鼠标选行），不自动展开详情，由"详情"按钮控制"""
        pass

    def _on_rec_pkt_selected(self, current, _previous):
        """选中一个包后，在右侧显示前 128 字节的格式化 Hex（含 ASCII）；有 raw_packet 时优先显示原始封包"""
        if current is None:
            return
        row = current.row()
        rows = getattr(self, "_rec_current_rows", [])
        if row < 0 or row >= len(rows):
            return
        r = rows[row]
        pkt = r.get("raw_packet") or r.get("payload") or b""
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
        desc = "原始 01 0A 00 xx 封包" if r.get("raw_packet") else "锚点后的高熵替换区"
        header = (
            f"加密区 #{row + 1}  大小={total}B  显示前 {len(data)}B\n"
            f"说明：{desc}\n"
            f"{'─' * 70}\n"
        )
        self.rec_hex_view.setPlainText(header + "\n".join(lines))

    def _on_rec_full_hex(self):
        """显示选中加密区的完整 Hex（无 ASCII），有 raw_packet 时显示原始封包"""
        row = self.rec_pkt_table.currentRow()
        rows = getattr(self, "_rec_current_rows", [])
        if row < 0 or row >= len(rows):
            return
        r = rows[row]
        pkt = r.get("raw_packet") or r.get("payload") or b""
        lines = []
        per_line = 32
        for i in range(0, len(pkt), per_line):
            chunk = pkt[i:i + per_line]
            lines.append(" ".join(f"{b:02X}" for b in chunk))
        desc = "原始 01 0A 00 xx 封包" if r.get("raw_packet") else "加密区"
        header = f"{desc} #{row + 1}  完整 {len(pkt)}B（纯 Hex 无 ASCII）\n{'─' * 70}\n"
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
            
        self._set_cell(row, 7, status, color=color)
        self._refresh_connection_summary()

    def _on_conn_game_id_update(self, client_ip: str, game_id: str, mode: str):
        """更新连接表"游戏 ID"列"""
        if mode == "录制":
            self._ip_rec_game_id[client_ip] = game_id
        else:
            self._ip_rep_game_id[client_ip] = game_id
        
        row = self._ip_rows.get(client_ip)
        if row is not None:
            self._update_row_mode_and_id(client_ip, row)
        self._refresh_connection_summary()

    def _on_conn_3366_product(self, client_ip: str, product_hex: str, product_name: str):
        """3366 产品就绪：补全连接表显示，与 ACE 数字串映射无关"""
        self._ip_3366_hex[client_ip] = (product_hex or "").strip().upper()
        self._ip_3366_name[client_ip] = (product_name or product_hex or "").strip()
        row = self._ip_rows.get(client_ip)
        if row is not None:
            self._update_row_mode_and_id(client_ip, row)

    def _on_conn_ace_channels_updated(self, client_ip: str):
        """01 / 3366 两侧账号串更新：刷新「账户/游戏」对账样式"""
        row = self._ip_rows.get(client_ip)
        if row is None or row >= self.conn_table.rowCount():
            return
        self._update_row_mode_and_id(client_ip, row)

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
            self._set_cell(row, 8, f"● {_fmt_dur(elapsed)}", color="#3fb950")

        # ── 空闲 IP：刷新空闲时长 + 标记待清理 ──
        for ip, last_t in list(self._ip_last_active.items()):
            if self._ip_active.get(ip, 0) > 0:
                continue
            row = self._ip_rows.get(ip)
            if row is None or row >= self.conn_table.rowCount():
                continue
            elapsed = int((now - last_t).total_seconds())
            self._set_cell(row, 8, f"○ 空闲 {_fmt_dur(elapsed)}", color="#666666")
            if elapsed >= 1800:   # 30 分钟后清理
                to_remove.append(ip)

        # 按行号倒序删除，避免索引漂移
        to_remove.sort(key=lambda x: self._ip_rows.get(x, 0), reverse=True)
        for ip in to_remove:
            self._remove_ip_row(ip)

        # ── 下发拦截统计：清理 12 小时之前的 ──
        to_remove_stats = []
        for account, stats in list(self._dl_intercept_stats.items()):
            last_t = stats.get("last_active")
            if last_t and (now - last_t).total_seconds() >= 12 * 3600:
                to_remove_stats.append(account)

        for account in to_remove_stats:
            row = self._find_stat_row(account)
            if row >= 0:
                self._stat_table_for(account).removeRow(row)
            self._dl_intercept_stats.pop(account, None)
            self._dl_intercept_history.pop(account, None)
            dlg = self._dl_intercept_detail_dialogs.pop(account, None)
            if dlg:
                dlg.close()

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
        self._ip_rec_game_id.pop(ip, None)
        self._ip_rep_game_id.pop(ip, None)
        self._ip_3366_hex.pop(ip, None)
        self._ip_3366_name.pop(ip, None)
        self._ip_last_active.pop(ip, None)
        self._ip_online_since.pop(ip, None)
        self._ip_replay_progress.pop(ip, None)
        self._ip_replay_progress_detail.pop(ip, None)
        # 关闭已打开的详情对话框
        dlg = self._detail_dialogs.pop(ip, None)
        if dlg:
            dlg.close()

    def _on_replay_progress(self, client_ip: str, current: int, total: int):
        """重放进度更新（兼容）：刷新详情对话框"""
        self._ip_replay_progress[client_ip] = (current, total)
        dlg = self._detail_dialogs.get(client_ip)
        if dlg and dlg.isVisible():
            dlg.set_progress(current, total)

    def _on_replay_progress_detail(
        self,
        client_ip: str,
        cur01: int,
        total01: int,
        cur33: int,
        total33: int,
        cur09: int = 0,
        total09: int = 0,
        cur21: int = 0,
        total21: int = 0,
        cur01_fb: int = 0,
    ):
        """重放进度详情（01/33 分开展示，33 细分 09/21/01回退）：刷新连接表 + 详情对话框"""
        self._ip_replay_progress_detail[client_ip] = (
            cur01, total01, cur33, total33, cur09, total09, cur21, total21, cur01_fb,
        )
        row = self._ip_rows.get(client_ip)
        if row is not None:
            text = self._format_replay_progress_text(
                cur01, total01, cur33, total33, cur09, total09, cur21, total21, cur01_fb,
            )
            self._set_cell(row, 7, text, color="#ce93d8")
        dlg = self._detail_dialogs.get(client_ip)
        if dlg and dlg.isVisible():
            dlg.set_progress(cur01 + cur33, total01 + total33)
            dlg.set_progress_detail(
                cur01, total01, cur33, total33, cur09, total09, cur21, total21, cur01_fb,
            )

    def _format_replay_progress_text(
        self,
        cur01: int,
        total01: int,
        cur33: int,
        total33: int,
        cur09: int = 0,
        total09: int = 0,
        cur21: int = 0,
        total21: int = 0,
        cur01_fb: int = 0,
    ) -> str:
        """格式化循环重放进度，并显示当前轮次。"""
        if total01 <= 0 and total33 <= 0:
            return "—"

        def _cycle_progress(current: int, total: int) -> str:
            if total <= 0:
                return "—"
            if current <= 0:
                return f"0/{total}"
            position = (current - 1) % total + 1
            round_number = (current - 1) // total + 1
            result = f"{position}/{total}"
            if round_number > 1:
                result += f" 第{round_number}轮"
            return result

        parts = []
        if total01 > 0:
            parts.append(f"01:{_cycle_progress(cur01, total01)}")
        if total33 > 0 or cur01_fb > 0:
            p33 = []
            if total09 > 0:
                p33.append(f"09 {_cycle_progress(cur09, total09)}")
            if total21 > 0:
                p33.append(f"21 {_cycle_progress(cur21, total21)}")
            if cur01_fb > 0:
                p33.append(f"回退{cur01_fb}")
            if p33:
                parts.append("33:" + " ".join(p33))
            elif total33 > 0:
                parts.append(f"33:{cur33}/{total33}")
        return " | ".join(parts) if parts else "—"

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
        d = self._ip_replay_progress_detail.get(client_ip)
        if d:
            dlg.set_progress(d[0] + d[2], d[1] + d[3])
        else:
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
            self._rec_current_rows = []

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
