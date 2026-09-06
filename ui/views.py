import os
import re
import time
import json
from datetime import datetime, date
import asyncio
import threading

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QPlainTextEdit, QGroupBox,
    QCheckBox, QSpinBox, QDoubleSpinBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QStatusBar, QDateEdit, QMessageBox,
    QDialog, QFormLayout, QDialogButtonBox, QAbstractItemView, QFileDialog,
    QComboBox, QSizePolicy, QScrollArea, QFrame, QGridLayout,
)
from PySide6.QtCore import Qt, Signal, QObject, QDate, QTimer, QUrl, QEvent
from PySide6.QtGui import QColor, QFont, QTextCursor, QDesktopServices

APP_VERSION = "v1.131.1"

from core.config import app_config, DATA_DIR, CONFIG_FILE
from core.edition import APP_DISPLAY_NAME
from core.ace_display import build_ace_identifier_lookup, ace_identifier_display
from core.events import log_bus, _event, _fmt_dur
from core.managers import user_manager, local_map_manager
from core.pool import recording_pool
from core.replay_session_v130 import REPLAY_PHASE_CONTINUE, REPLAY_PHASE_FIRST
from core.server import engine, _check_external_proxy
from core.dfm_message_catalog import (
    DFM_KNOWN_MESSAGE_ID_CATALOG,
    DFM_REPLAY_80XX_MESSAGE_IDS,
    format_recording_period_status,
)

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
            self.lbl_progress.setText(
                f"重放进度：<b style='color:#ce93d8'>{current} / {total}</b>  包"
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
        if total01 <= 0 and total33 <= 0 and cur01 <= 0:
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
        self.setFixedSize(380, 255)

        form = QFormLayout()
        self.edit_uname  = QLineEdit()
        self.edit_passwd = QLineEdit()
        self.edit_note   = QLineEdit()
        self.cb_never    = QCheckBox("永不过期"); self.cb_never.setChecked(True)
        self.date_expire = QDateEdit(QDate.currentDate().addYears(1))
        self.date_expire.setCalendarPopup(True)
        self.date_expire.setEnabled(False)
        self.cb_never.toggled.connect(lambda v: self.date_expire.setEnabled(not v))
        self.cb_multi    = QCheckBox("允许同账户多个游戏ID同时在线（测试/内部使用）")
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


class MultiSelectComboBox(QComboBox):
    """带复选框的多选下拉框，选中值继续使用逗号字符串持久化。"""

    selectionChanged = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setEditable(True)
        self.setInsertPolicy(QComboBox.NoInsert)
        self.lineEdit().setReadOnly(True)
        self.lineEdit().setPlaceholderText("请选择用户")
        self.lineEdit().installEventFilter(self)
        self.view().viewport().installEventFilter(self)
        self.currentIndexChanged.connect(lambda _: self._syncDisplay())
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setAccessibleName("详细日志用户（可多选）")

    def setOptions(self, values: list[str], selected: list[str] | None = None):
        selected_values = list(selected if selected is not None else self.selectedValues())
        options = list(dict.fromkeys(
            str(value).strip() for value in [*values, *selected_values]
            if str(value).strip()
        ))
        self.blockSignals(True)
        self.clear()
        for value in options:
            self.addItem(value, value)
            item = self.model().item(self.count() - 1)
            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable)
            item.setData(
                Qt.Checked if value in selected_values else Qt.Unchecked,
                Qt.CheckStateRole,
            )
        self.setCurrentIndex(-1)
        self.blockSignals(False)
        self._syncDisplay()

    def selectedValues(self) -> list[str]:
        values: list[str] = []
        for row in range(self.count()):
            item = self.model().item(row)
            if item.checkState() == Qt.Checked:
                values.append(str(self.itemData(row) or self.itemText(row)))
        return values

    def text(self) -> str:
        return ",".join(self.selectedValues())

    def setText(self, value: str):
        selected = [part.strip() for part in str(value or "").split(",") if part.strip()]
        self.setOptions(
            [str(self.itemData(row) or self.itemText(row)) for row in range(self.count())],
            selected or ["test"],
        )

    def _syncDisplay(self, *, emit: bool = False):
        values = self.selectedValues()
        display = "、".join(values)
        self.lineEdit().setText(display)
        self.setToolTip(
            f"已选择：{display}\n点击下拉列表可勾选多个用户；这些用户的每次事件都保存完整 Hex。"
            if values else
            "点击下拉列表选择详细日志用户。"
        )
        if emit:
            self.selectionChanged.emit(",".join(values))

    def _toggleIndex(self, index) -> bool:
        if not index.isValid():
            return False
        item = self.model().itemFromIndex(index)
        checked = item.checkState() == Qt.Checked
        # 关闭详细日志应使用外部总开关；下拉框至少保留一个用户，避免空值回退不直观。
        if checked and len(self.selectedValues()) <= 1:
            return True
        item.setCheckState(Qt.Unchecked if checked else Qt.Checked)
        self._syncDisplay(emit=True)
        return True

    def eventFilter(self, watched, event):
        if watched is self.lineEdit() and event.type() == QEvent.MouseButtonRelease:
            self.showPopup()
            return True
        if watched is self.view().viewport():
            if event.type() == QEvent.MouseButtonRelease:
                return self._toggleIndex(self.view().indexAt(event.pos()))
            if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Space:
                return self._toggleIndex(self.view().currentIndex())
        return super().eventFilter(watched, event)

    def hidePopup(self):
        super().hidePopup()
        self._syncDisplay()

    def wheelEvent(self, event):
        event.ignore()


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
        elif event_type == "pb_dl_bl":
            color, icon = "#c084fc", "⛔"
        elif event_type == "pb_dl_scan":
            color, icon = "#94a3b8", "◎"
        else:  # "diag" 诊断信息
            color, icon = "#888888", "·"
        escaped = _esc(message).replace("\n", "<br>")
        html = (
            f'<span style="color:#555">[{ts}]</span> '
            f'<span style="color:{color}">{icon}</span> {escaped}'
        )
        self.log_edit.append(html)
        self.log_edit.ensureCursorVisible()

    def update_summary_from_stats(self, stats: dict, *, is_delta: bool) -> None:
        """下发拦截弹窗顶部摘要：三角洲不含「上行命中」；暗区仅 01/33/块填充。"""
        if is_delta:
            self.lbl_summary.setText(
                f"命令黑名单: {stats.get('pb_dl_bl', 0)}  |  "
                f"01拦截: {stats.get('01_drop', 0)}  |  "
                f"33替换: {stats.get('str_replace', 0)}"
            )
        else:
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
        self.setWindowTitle(f"{APP_DISPLAY_NAME} {APP_VERSION}  |  SOCKS5 双端口代理")
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
        self._ip_replay_phase: dict[str, str] = {} # ip → 首次重放 / 续连重放
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
        self._account_game:         dict[str, str]  = {}           # label → game_id ("az"、"hok" 或 "0a92" 等)
        self._dl_intercept_detail_dialogs: dict[str, DlInterceptDetailDialog] = {}
        self._dl_intercept_history: dict[str, list] = {}           # label → [(event_type, message), ...]
        self._ul_detail_dialogs:    dict[str, UlInterceptDetailDialog] = {}
        # 与 dl_intercept_history_labels 子串匹配的标签会缓存上行诊断日志（未打开弹窗也可稍后查看）
        self._ul_log_history:       dict[str, list[str]] = {}
        # 上行拦截黑名单：匹配字符串 → 命中次数；持久化在 app_config["ul_blacklist_strings"]
        self._ul_blacklist: dict[str, int] = {}                    # string → hit_count
        # 三角洲命令名黑名单：命令名 → 命中次数；持久化在 app_config["pb_cmd_blacklist"]
        self._pb_cmd_blacklist: dict[str, int] = {}                # cmd → hit_count
        self._loading_config = False   # 加载期间屏蔽自动保存，防止中间状态覆盖磁盘值
        self._build_ui()
        self._load_config_to_ui()
        self._connect_signals()
        self._refresh_user_table()
        self._refresh_type9_rule_ui()
        # 定时刷新空闲时长 + 清理超过 60 分钟无活动的行（每 60 秒跑一次）
        self._idle_timer = QTimer(self)
        self._idle_timer.timeout.connect(self._on_cleanup_tick)
        self._idle_timer.start(60_000)
        self._type9_rule_timer = QTimer(self)
        self._type9_rule_timer.timeout.connect(self._refresh_type9_rule_ui)
        self._type9_rule_timer.start(1_000)
        # v1.129：操作审计与周期状态快照。按钮点击、配置位变化、规则
        # generation/计数变化共同写入本次AI日志，便于还原运行中发生的操作。
        for button in self.findChildren(QPushButton):
            button.clicked.connect(
                lambda checked=False, control=button: self._audit_button_click(
                    control, checked
                )
            )
        self._control_audit_timer = QTimer(self)
        self._control_audit_timer.timeout.connect(
            lambda: self._audit_control("periodic_state_snapshot", source="ui_timer")
        )
        self._control_audit_timer.start(60_000)

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
        pg_layout = QVBoxLayout(pg)
        pg_layout.setContentsMargins(12, 18, 12, 10)
        pg_layout.setSpacing(8)
        pl = QHBoxLayout()
        pl.addWidget(QLabel("录制端口:"))
        self.spin_1081 = QSpinBox(); self.spin_1081.setRange(1, 65535); self.spin_1081.setValue(1081)
        pl.addWidget(self.spin_1081)
        pl.addSpacing(10)
        pl.addWidget(QLabel("重放端口:"))
        self.spin_1080 = QSpinBox(); self.spin_1080.setRange(1, 65535); self.spin_1080.setValue(1080)
        pl.addWidget(self.spin_1080)
        pg_layout.addLayout(pl)
        port_badges = QHBoxLayout()
        port_badges.setSpacing(6)
        self.lbl_record_port_summary = QLabel()
        self.lbl_replay_port_summary = QLabel()
        self.lbl_record_port_summary.setStyleSheet(
            "background:#eff6ff;color:#1d4ed8;border-radius:4px;padding:5px 8px;font-size:11px;"
        )
        self.lbl_replay_port_summary.setStyleSheet(
            "background:#f5f3ff;color:#6d28d9;border-radius:4px;padding:5px 8px;font-size:11px;"
        )
        port_badges.addWidget(self.lbl_record_port_summary, 1)
        port_badges.addWidget(self.lbl_replay_port_summary, 1)
        pg_layout.addLayout(port_badges)
        top.addWidget(pg)

        # 外部代理
        eg = QGroupBox("外部上游代理 (SOCKS5)")
        eg_layout = QVBoxLayout(eg)
        eg_layout.setContentsMargins(12, 18, 12, 10)
        eg_layout.setSpacing(8)
        el = QHBoxLayout()
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
        eg_layout.addLayout(el)

        self.lbl_ext_proxy_summary = QLabel()
        self.lbl_ext_proxy_summary.setStyleSheet(
            "background:#f9fafb;color:#6b7280;border-radius:4px;padding:5px 8px;font-size:11px;"
        )
        eg_layout.addWidget(self.lbl_ext_proxy_summary)

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
        self.btn_block_3366 = QPushButton("⛔ 阻断3366")
        self.btn_block_3366.setCheckable(True)
        self.btn_block_3366.setEnabled(False)
        self.btn_block_3366.setMinimumHeight(34)
        self.btn_block_3366.setToolTip(
            "实验开关，同时作用于录制与重放端口：\n"
            "开启后立即断开目标端口3366及已识别的3366协议连接，"
            "并拒绝后续3366连接；独立01通道继续转发。\n"
            "再次点击恢复3366新连接；已经断开的连接由客户端重新建立。\n"
            "默认关闭。用来对照检测是否走3366上报。"
        )
        self._set_3366_block_button_style(False)
        ctrl.addWidget(self.btn_start)
        ctrl.addWidget(self.btn_stop)
        ctrl.addWidget(self.btn_block_3366)
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
        self._connection_replay_page = self._build_hex_tab()
        self._connection_replay_page.setObjectName("connectionReplayPage")
        self.tabs.addTab(self._connection_replay_page, "🔬 连接与重放")

        # Tab 3: 录制管理
        t3 = self._build_record_tab()
        self.tabs.addTab(t3, "📼 录制管理")

        # 本地文件重放：配置 HTTP 域名到本地文件的映射。
        # 页面保存为成员并加入 Tab，确保配置控件在窗口生命周期内有效。
        self._local_file_replay_page = self._build_maplocal_tab()
        self._local_file_replay_page.setObjectName("localFileReplayPage")
        self.tabs.addTab(self._local_file_replay_page, "📄 本地文件重放")

        # Tab 5: 远程管理
        t5 = self._build_remote_admin_tab()
        self.tabs.addTab(t5, "🌐 远程管理")

        # Tab 6: 网络流监控
        t6 = self._build_stream_monitor_tab()
        self.tabs.addTab(t6, "🌊 网络流监控")

        # Tab 7: 拦截管理
        self._intercept_page = self._build_dl_intercept_tab()
        self.tabs.addTab(self._intercept_page, "🛡️ 拦截管理")

        # 拦截管理右侧：集中放置01运行策略开关。
        self._config_page = self._build_config_tab()
        self._config_page.setObjectName("configPage")
        self.tabs.addTab(self._config_page, "⚙️ 配置")

        root.addWidget(self.tabs)

        # 状态栏
        sb = QStatusBar(); self.setStatusBar(sb)
        self.lbl_status = QLabel("就绪"); sb.addWidget(self.lbl_status)
        self.lbl_stats  = QLabel(""); sb.addPermanentWidget(self.lbl_stats)

    def _build_config_tab(self) -> QWidget:
        """集中管理01录制、补数据、连接和日志策略。"""
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(8)

        title = QLabel("运行配置")
        title.setStyleSheet("font-size:16px;font-weight:bold;color:#1f2937;")
        outer.addWidget(title)

        hint = QLabel(
            "设备模式固定为“继承重放设备”。以下开关保存到配置目录，"
            f"新连接按最新配置运行。配置文件：{CONFIG_FILE}"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#6b7280;font-size:11px;")
        outer.addWidget(hint)

        columns = QHBoxLayout()
        columns.setSpacing(10)

        basic_box = QGroupBox("常用配置")
        basic = QVBoxLayout(basic_box)
        basic.setContentsMargins(14, 16, 14, 12)
        basic.setSpacing(7)

        def add_option(checkbox: QCheckBox, description: str):
            basic.addWidget(checkbox)
            label = QLabel(description)
            label.setWordWrap(True)
            label.setStyleSheet(
                "color:#6b7280;font-size:11px;padding-left:22px;"
            )
            basic.addWidget(label)

        self.cb_replenish_01 = QCheckBox("重建模式")
        self.cb_replenish_01.setToolTip(
            "总开关。开启后按下方多选项补发对应数据，并统一维护报告、叶、物理帧和包组序号。"
        )
        add_option(
            self.cb_replenish_01,
            "开启后从下方选择需要重建的类别；各类别互相独立，可只选其中一项。",
        )

        self.rebuild_options_box = QGroupBox("重建内容（可多选）")
        rebuild_shell = QVBoxLayout(self.rebuild_options_box)
        rebuild_shell.setContentsMargins(10, 14, 10, 10)
        rebuild_shell.setSpacing(8)

        def _rebuild_section(
            title: str,
            subtitle: str,
            *,
            accent: str,
            background: str,
        ) -> tuple[QFrame, QVBoxLayout]:
            frame = QFrame()
            frame.setObjectName("rebuildSection")
            frame.setStyleSheet(
                "QFrame#rebuildSection {"
                f"background:{background};"
                f"border:1px solid {accent}40;"
                f"border-left:3px solid {accent};"
                "border-radius:8px;"
                "}"
            )
            body = QVBoxLayout(frame)
            body.setContentsMargins(10, 8, 10, 8)
            body.setSpacing(4)
            head = QLabel(title)
            head.setStyleSheet(
                f"color:{accent};font-size:11px;font-weight:700;border:none;background:transparent;"
            )
            body.addWidget(head)
            if subtitle:
                sub = QLabel(subtitle)
                sub.setWordWrap(True)
                sub.setStyleSheet(
                    "color:#6b7280;font-size:10px;border:none;background:transparent;"
                )
                body.addWidget(sub)
            return frame, body

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setMaximumHeight(248)
        scroll.setMinimumHeight(168)
        scroll.setStyleSheet(
            "QScrollArea{background:transparent;border:none;}"
            "QScrollBar:vertical{"
            "background:#f3f4f6;width:8px;margin:2px;border-radius:4px;}"
            "QScrollBar::handle:vertical{"
            "background:#c4b5fd;min-height:24px;border-radius:4px;}"
            "QScrollBar::handle:vertical:hover{background:#a78bfa;}"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{"
            "height:0;}"
            "QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical{"
            "background:transparent;}"
        )

        scroll_body = QWidget()
        rebuild_options = QVBoxLayout(scroll_body)
        rebuild_options.setContentsMargins(2, 2, 8, 2)
        rebuild_options.setSpacing(8)

        core_frame, core_body = _rebuild_section(
            "基础补发",
            "中央固定类、强检、对局、扫描与 800D 轮次；各类互相独立。",
            accent="#6d28d9",
            background="#f5f3ff",
        )
        core_grid = QGridLayout()
        core_grid.setContentsMargins(0, 2, 0, 0)
        core_grid.setHorizontalSpacing(12)
        core_grid.setVerticalSpacing(4)
        self.cb_rebuild_central9 = QCheckBox("中央9类")
        self.cb_rebuild_central9.setToolTip(
            "补发中央固定九类：8000/8002/8003/8004/800B/8020/8021/8025/8028。"
        )
        self.cb_rebuild_strong_profile = QCheckBox("强检重建（8C03/9100）")
        self.cb_rebuild_strong_profile.setToolTip(
            "检测到对应 mrpcs_i_* 文件对后，8C03 按120-slot、9100 按600-slot补发。"
        )
        self.cb_rebuild_match_events = QCheckBox("对局数据（802A/802B）")
        self.cb_rebuild_match_events.setToolTip(
            "约6分钟大厅静默后开启；之后每隔10～20分钟随机补一对录制正文；"
            "同设备跨账号可发；跨设备不发。"
        )
        self.cb_rebuild_scan_waves = QCheckBox("扫描数据（8027/8029）")
        self.cb_rebuild_scan_waves.setToolTip(
            "使用模板第一完整扫描波，并按录制测得的开扫间隔循环；"
            "扫的是设备环境，同设备跨账号可发；跨设备仍不发。"
        )
        self.cb_rebuild_player_800D = QCheckBox("800D（轮次计数）")
        self.cb_rebuild_player_800D.setToolTip(
            "600-slot 轮次：+0x20=1+cycle×20；优先Live与录制，缺少录制时使用内置离线种子；"
            "跨设备、跨账号均可发；默认关闭。"
        )
        core_grid.addWidget(self.cb_rebuild_central9, 0, 0)
        core_grid.addWidget(self.cb_rebuild_strong_profile, 0, 1)
        core_grid.addWidget(self.cb_rebuild_match_events, 1, 0)
        core_grid.addWidget(self.cb_rebuild_scan_waves, 1, 1)
        core_grid.addWidget(self.cb_rebuild_player_800D, 2, 0, 1, 2)
        core_body.addLayout(core_grid)
        rebuild_options.addWidget(core_frame)

        content_frame, content_body = _rebuild_section(
            "A · 内容/形态未闭环",
            "默认关闭；同设备不同账号时硬拦。仅复放模板已有叶，不做外推。",
            accent="#b45309",
            background="#fffbeb",
        )
        self.cb_rebuild_player_8007 = QCheckBox("8007")
        self.cb_rebuild_player_800A = QCheckBox("800A")
        self.cb_rebuild_player_800C = QCheckBox("800C")
        self.cb_rebuild_player_800F = QCheckBox("800F")
        self.cb_rebuild_player_8023 = QCheckBox("8023")
        for checkbox, tip in (
            (self.cb_rebuild_player_8007, "仅复放模板真实存在的8007叶；不外推。"),
            (self.cb_rebuild_player_800A, "仅复放已录800A slot/正文；不按900或30外推。"),
            (self.cb_rebuild_player_800C, "仅复放已录800C叶；不做周期外推或nearest替换。"),
            (self.cb_rebuild_player_800F, "仅复放已录800F画像；不在全零/非零画像间猜切换。"),
            (self.cb_rebuild_player_8023, "仅复放已录8023一次性叶；不按新连接创建。"),
        ):
            checkbox.setToolTip(tip)
        a_grid = QGridLayout()
        a_grid.setContentsMargins(0, 2, 0, 0)
        a_grid.setHorizontalSpacing(10)
        a_grid.setVerticalSpacing(2)
        for index, checkbox in enumerate(
            (
                self.cb_rebuild_player_8007,
                self.cb_rebuild_player_800A,
                self.cb_rebuild_player_800C,
                self.cb_rebuild_player_800F,
                self.cb_rebuild_player_8023,
            )
        ):
            a_grid.addWidget(checkbox, index // 3, index % 3)
        content_body.addLayout(a_grid)
        rebuild_options.addWidget(content_frame)

        time_frame, time_body = _rebuild_section(
            "B · 时间关系",
            "默认关闭；可继承录制虚拟开机域，不要求 Live 真实重启锚。",
            accent="#1d4ed8",
            background="#eff6ff",
        )
        self.cb_rebuild_player_8024 = QCheckBox("8024（开机/落地时间域）")
        self.cb_rebuild_player_802C = QCheckBox("802C（墙钟与四步链）")
        self.cb_rebuild_player_8024.setToolTip(
            "勾选后继承录制8024的重启时间域；设备后来重启不作为停发条件。"
        )
        self.cb_rebuild_player_802C.setToolTip(
            "勾选后按录制8024、recorded_at和连接链推进；元数据缺失时只复放原叶。"
        )
        time_body.addWidget(self.cb_rebuild_player_8024)
        time_body.addWidget(self.cb_rebuild_player_802C)
        rebuild_options.addWidget(time_frame)
        rebuild_options.addStretch(1)

        scroll.setWidget(scroll_body)
        rebuild_shell.addWidget(scroll)

        # 旧属性名保留给内部兼容；现语义映射到800D单项。
        self.cb_rebuild_player_base = self.cb_rebuild_player_800D

        rebuild_hint = QLabel(
            "例：只勾「强检」→ 仅补 8C03/9100；其余保持关闭。内容超出时可在框内滚动。"
        )
        rebuild_hint.setWordWrap(True)
        rebuild_hint.setStyleSheet("color:#6b7280;font-size:11px;")
        rebuild_shell.addWidget(rebuild_hint)
        basic.addWidget(self.rebuild_options_box)

        self.cb_full_rebuild = self.cb_rebuild_player_base
        self.cb_same_device_replenish = self.cb_rebuild_player_base

        self.cb_hold_01 = QCheckBox("01只收录（阈值后）")
        self.cb_hold_01.setToolTip(
            "录制达到所选数量或80xx覆盖目标后，上行继续入池但停止转发；"
            "客户端连接保持并使用下行或本地短08心跳。"
        )
        add_option(
            self.cb_hold_01,
            "达到录制目标后只收入录制池，独立3366与重放游标保持。",
        )

        self.cb_detail_01 = QCheckBox("记录详细01日志")
        self.cb_detail_01.setToolTip(
            "勾选时仅配置的详细用户保存全量Hex，其他用户保持精简；"
            "同时保存socket原始请求块和01长度切帧后的物理帧；"
            "关闭时所有用户精简记录，异常仍自动升级完整Hex。"
        )
        add_option(
            self.cb_detail_01,
            "开启时指定用户记录原始TCP Hex、切帧01 Hex和报告叶Hex；"
            "关闭时全员精简，异常仍保留完整数据。",
        )

        basic_form = QFormLayout()
        basic_form.setSpacing(7)
        self.spin_01_threshold = QSpinBox()
        self.spin_01_threshold.setRange(0, 9999)
        self.spin_01_threshold.setSuffix(" 包")
        self.spin_01_threshold.setToolTip(
            "按01数量判断时，达到该数量后阻断同IP录制口3366。0表示停用数量条件。"
        )
        self.combo_record_goal = QComboBox()
        self.combo_record_goal.addItem("按01数量", "count")
        self.combo_record_goal.addItem("按80xx完整度", "coverage")
        self.combo_record_goal.addItem(
            "80xx完整度＋周期就绪（同时）",
            "coverage_periodic",
        )
        self.combo_record_goal.addItem("数量或80xx完整度（任一）", "either")
        self.combo_record_goal.addItem("关闭自动结束（持续录制）", "off")
        self.combo_record_goal.setToolTip(
            "录制目标达成后，只断开同一来源IP下的录制口3366连接；其他IP和重放端口不受影响。"
        )
        self.spin_message_coverage_threshold = QSpinBox()
        self.spin_message_coverage_threshold.setRange(1, 100)
        self.spin_message_coverage_threshold.setSuffix(" %")
        self.spin_message_coverage_threshold.setToolTip(
            f"完整度包含 {len(DFM_REPLAY_80XX_MESSAGE_IDS)} 个80xx消息ID覆盖，"
            "8004的9个子型，8007/800D/802C的600-slot、800F的900-slot、"
            "800A按当前模板（稀疏900或三簇一致间隔），"
            "以及8027/8029短波尾巴59或长波递减加第二波开扫。"
        )
        basic_form.addRow("自动结束条件:", self.combo_record_goal)
        basic_form.addRow("01数量阈值:", self.spin_01_threshold)
        basic_form.addRow("80xx完整度阈值:", self.spin_message_coverage_threshold)
        basic.addLayout(basic_form)
        columns.addWidget(basic_box, 1)

        advanced_box = QGroupBox("高级配置")
        advanced = QFormLayout(advanced_box)
        advanced.setContentsMargins(14, 16, 14, 12)
        advanced.setSpacing(8)

        self.edit_detail_01_users = MultiSelectComboBox()
        self.edit_detail_01_users.setOptions([
            str(user.get("username") or "").strip()
            for user in user_manager.all()
            if str(user.get("username") or "").strip()
        ], ["test"])
        advanced.addRow("详细日志用户:", self.edit_detail_01_users)

        self.spin_ai_log_periodic_full = QSpinBox()
        self.spin_ai_log_periodic_full.setRange(0, 100000)
        self.spin_ai_log_periodic_full.setSuffix(" 次")
        self.spin_ai_log_periodic_full.setToolTip(
            "仅作用于未勾选的精简日志用户：每N个同类事件保留一份完整样本；"
            "上方勾选的详细日志用户始终每次保存完整 Hex。0表示其他用户只保留异常和新结构。"
        )
        advanced.addRow("其他用户Hex抽样:", self.spin_ai_log_periodic_full)

        context_row = QWidget()
        context_layout = QHBoxLayout(context_row)
        context_layout.setContentsMargins(0, 0, 0, 0)
        context_layout.setSpacing(5)
        self.spin_ai_log_context_before = QSpinBox()
        self.spin_ai_log_context_before.setRange(0, 1000)
        self.spin_ai_log_context_after = QSpinBox()
        self.spin_ai_log_context_after.setRange(0, 1000)
        context_layout.addWidget(QLabel("前"))
        context_layout.addWidget(self.spin_ai_log_context_before)
        context_layout.addWidget(QLabel("后"))
        context_layout.addWidget(self.spin_ai_log_context_after)
        advanced.addRow("异常上下文:", context_row)

        self.spin_record_idle_timeout = QSpinBox()
        self.spin_record_idle_timeout.setRange(0, 3600)
        self.spin_record_idle_timeout.setSuffix(" 秒")
        self.spin_record_idle_timeout.setToolTip("录制/重放连接空闲超时；0表示持续等待。")
        advanced.addRow("连接空闲超时:", self.spin_record_idle_timeout)

        self.spin_hold_01_keepalive = QSpinBox()
        self.spin_hold_01_keepalive.setRange(1, 300)
        self.spin_hold_01_keepalive.setSuffix(" 秒")
        self.spin_hold_01_keepalive.setToolTip("01只收录后，ACE下行静默多久开始补本地短08。")
        advanced.addRow("本地01心跳间隔:", self.spin_hold_01_keepalive)

        self.spin_ai_log_retention_days = QSpinBox()
        self.spin_ai_log_retention_days.setRange(0, 3650)
        self.spin_ai_log_retention_days.setSuffix(" 天")
        self.spin_ai_log_retention_days.setToolTip("启动新日志时整理更早的run目录；0表示不按天数整理。")
        advanced.addRow("AI日志保留:", self.spin_ai_log_retention_days)

        self.spin_ai_log_max_gb = QDoubleSpinBox()
        self.spin_ai_log_max_gb.setRange(0.0, 1024.0)
        self.spin_ai_log_max_gb.setDecimals(1)
        self.spin_ai_log_max_gb.setSingleStep(0.5)
        self.spin_ai_log_max_gb.setSuffix(" GB")
        self.spin_ai_log_max_gb.setToolTip("按最旧优先整理AI日志目录；0表示不限制容量。")
        advanced.addRow("AI日志最大占用:", self.spin_ai_log_max_gb)
        columns.addWidget(advanced_box, 1)
        outer.addLayout(columns, 1)

        summary_box = QGroupBox("当前生效策略")
        summary_layout = QHBoxLayout(summary_box)
        self.lbl_config_summary = QLabel("")
        self.lbl_config_summary.setWordWrap(True)
        self.lbl_config_summary.setStyleSheet("color:#374151;font-size:11px;")
        summary_layout.addWidget(self.lbl_config_summary, 1)
        outer.addWidget(summary_box)

        actions = QHBoxLayout()
        self.btn_config_save = QPushButton("💾 保存配置")
        self.btn_config_reset = QPushButton("↩ 恢复本页默认")
        self.btn_config_open_dir = QPushButton("📂 打开配置目录")
        self.btn_config_open_ai_log = QPushButton("📂 打开最新AI日志")
        self.btn_config_clear_ai_log = QPushButton("🧹 清空AI日志")
        self.btn_config_clear_ai_log.setToolTip(
            "删除配置目录/AI日志中的全部内容；代理运行时会立即建立新的run目录。"
        )
        self.btn_config_clear_ai_log.setStyleSheet(
            "QPushButton{color:#b91c1c;}"
        )
        self.btn_config_export = QPushButton("📤 导出当前配置")
        for button in (
            self.btn_config_save,
            self.btn_config_reset,
            self.btn_config_open_dir,
            self.btn_config_open_ai_log,
            self.btn_config_clear_ai_log,
            self.btn_config_export,
        ):
            actions.addWidget(button)
        actions.addStretch(1)
        self.lbl_config_save_status = QLabel("")
        self.lbl_config_save_status.setStyleSheet("color:#16a34a;font-size:11px;")
        actions.addWidget(self.lbl_config_save_status)
        outer.addLayout(actions)
        return w

    def _build_user_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        # 操作栏
        bar = QHBoxLayout()
        self.btn_add_user    = QPushButton("➕  添加用户")
        self.btn_edit_passwd = QPushButton("🔑  修改密码")
        self.btn_del_user    = QPushButton("🗑  删除选中")
        self.btn_reload_users = QPushButton("🔄  重载到代理")
        for b in [self.btn_add_user, self.btn_edit_passwd, self.btn_del_user, self.btn_reload_users]:
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
        uh = self.user_table.horizontalHeader()
        uh.setStretchLastSection(False)
        uh.setSectionsMovable(False)
        for column in range(self.user_table.columnCount()):
            uh.setSectionResizeMode(column, QHeaderView.Interactive)
        uh.setSectionResizeMode(5, QHeaderView.Stretch)
        for column, width in {
            0: 58, 1: 150, 2: 150, 3: 115, 4: 105, 6: 105, 7: 105,
        }.items():
            self.user_table.setColumnWidth(column, width)
        self.user_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.user_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.user_table.verticalHeader().setVisible(False)
        v.addWidget(self.user_table)
        return w

    def _build_hex_tab(self) -> QWidget:
        # ── 连接表工具栏 ─────────────────────
        conn_wrap = QWidget()
        conn_vlay = QVBoxLayout(conn_wrap); conn_vlay.setContentsMargins(0, 0, 0, 0)
        conn_bar  = QHBoxLayout()
        conn_bar.addWidget(QLabel("连接列表（按来源 IP 聚合）"))
        conn_bar.addStretch()
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
          上半：会话表（含01数、80xx覆盖率、33数与状态）
          下半：消息覆盖详情（已见/缺失/未知ID），不重复展示原始Hex
        """
        outer = QSplitter(Qt.Vertical)

        # ── 上：会话列表 ──────────────────────
        top_w = QWidget()
        top_v = QVBoxLayout(top_w); top_v.setContentsMargins(0, 0, 0, 0)
        top_bar = QHBoxLayout()
        top_bar.addWidget(QLabel("录制会话"))
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
        _rec_hint = QLabel(
            "AI日志位于配置目录/AI日志/run_*：test可选全量，其他用户精简记录，异常自动保留完整Hex"
        )
        _rec_hint.setWordWrap(True)
        _rec_hint.setStyleSheet("color:#8b949e;font-size:11px;padding:4px 0;")
        top_v.addWidget(_rec_hint)

        self.rec_session_table = QTableWidget(0, 12)
        self.rec_session_table.setHorizontalHeaderLabels(
            ["类型", "游戏用户ID", "代理账号", "设备特征", "01数", "80xx覆盖率", "周期就绪", "33数", "来源 IP", "最近录制", "状态", "操作"]
        )
        sh = self.rec_session_table.horizontalHeader()
        sh.setStretchLastSection(False)
        sh.setSectionsMovable(False)
        for column in range(self.rec_session_table.columnCount()):
            sh.setSectionResizeMode(column, QHeaderView.Interactive)
        # 设备特征吸收窗口剩余空间；其他列给出稳定预算，避免长ID/时间把表头挤乱。
        sh.setSectionResizeMode(3, QHeaderView.Stretch)
        for column, width in {
            0: 105, 1: 195, 2: 95, 4: 58, 5: 105,
            6: 90, 7: 55, 8: 125, 9: 140, 10: 90, 11: 72,
        }.items():
            self.rec_session_table.setColumnWidth(column, width)
        sh.setMinimumSectionSize(50)
        self.rec_session_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rec_session_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rec_session_table.verticalHeader().setVisible(False)
        top_v.addWidget(self.rec_session_table)
        outer.addWidget(top_w)

        # ── 下：消息覆盖详情（默认折叠，点击"详情"按钮展开）─────
        detail_wrap = QWidget()
        detail_vlay = QVBoxLayout(detail_wrap); detail_vlay.setContentsMargins(0, 0, 0, 0); detail_vlay.setSpacing(0)

        # 详情标题栏（含当前选中账号 + 关闭按钮）
        det_title_bar = QHBoxLayout()
        self.lbl_rec_detail_title = QLabel("消息覆盖详情")
        self.lbl_rec_detail_title.setStyleSheet("font-weight:bold; padding:2px 4px;")
        det_title_bar.addWidget(self.lbl_rec_detail_title)
        det_title_bar.addStretch()
        btn_close_detail = QPushButton("✕ 收起")
        btn_close_detail.setFixedWidth(64)
        btn_close_detail.setStyleSheet("color:#9ca3af; border:none; font-size:11px;")
        btn_close_detail.clicked.connect(lambda: self._rec_outer_splitter.setSizes([10000, 0]))
        det_title_bar.addWidget(btn_close_detail)
        detail_vlay.addLayout(det_title_bar)

        self.lbl_rec_coverage_summary = QLabel(
            f"80xx覆盖率 0.0% · 0/{len(DFM_REPLAY_80XX_MESSAGE_IDS)} 个核心消息"
        )
        self.lbl_rec_coverage_summary.setStyleSheet(
            "background:#eef2ff;color:#3730a3;border-radius:5px;"
            "padding:7px 10px;font-weight:bold;"
        )
        detail_vlay.addWidget(self.lbl_rec_coverage_summary)

        bottom_split = QSplitter(Qt.Horizontal)

        # 左：内置消息目录及当前录制命中情况
        pkt_w = QWidget()
        pkt_v = QVBoxLayout(pkt_w); pkt_v.setContentsMargins(0, 0, 0, 0)
        pkt_v.addWidget(QLabel("消息目录（80xx核心优先，其他消息用于长录制分析）"))
        self.rec_coverage_table = QTableWidget(0, 6)
        self.rec_coverage_table.setHorizontalHeaderLabels(
            ["状态", "消息ID", "名称", "次数", "长度(B)", "周期状态"]
        )
        ph = self.rec_coverage_table.horizontalHeader()
        ph.setStretchLastSection(False)
        ph.setSectionsMovable(False)
        for column in range(self.rec_coverage_table.columnCount()):
            ph.setSectionResizeMode(column, QHeaderView.Interactive)
        # 名称列自适应占满；长度只保留多长度列表所需空间，不再吞掉整张表。
        ph.setSectionResizeMode(2, QHeaderView.Stretch)
        for column, width in {
            0: 120, 1: 88, 3: 72, 4: 150, 5: 150,
        }.items():
            self.rec_coverage_table.setColumnWidth(column, width)
        ph.setMinimumSectionSize(60)
        self.rec_coverage_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rec_coverage_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rec_coverage_table.verticalHeader().setVisible(False)
        pkt_v.addWidget(self.rec_coverage_table)
        bottom_split.addWidget(pkt_w)

        # 右：缺失/未知消息及采集质量说明
        hex_w = QWidget()
        hex_v = QVBoxLayout(hex_w); hex_v.setContentsMargins(0, 0, 0, 0)
        hex_v.addWidget(QLabel("录制完整度说明"))
        self.rec_coverage_notes = QTextEdit()
        self.rec_coverage_notes.setReadOnly(True)
        self.rec_coverage_notes.setFont(QFont("Consolas", 9))
        self.rec_coverage_notes.setStyleSheet(
            "background:#f8fafc;color:#334155;border:1px solid #e2e8f0;"
        )
        hex_v.addWidget(self.rec_coverage_notes)
        bottom_split.addWidget(hex_w)
        bottom_split.setSizes([520, 300])

        detail_vlay.addWidget(bottom_split)
        outer.addWidget(detail_wrap)
        # 默认折叠底部详情区（高度=0）
        self._rec_outer_splitter = outer
        outer.setSizes([10000, 0])

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

    def _build_legacy_intercept_compat_controls(self, parent: QWidget):
        """保留历史配置/事件代码依赖的隐藏对象，不再构建旧版拦截界面。"""
        self.dl_intercept_log = QTextEdit(parent)
        self.dl_intercept_log.setReadOnly(True)
        self.cb_destroy_mode = QCheckBox(parent)
        self.edit_zone_start = QLineEdit(parent)
        self.spin_zone_nth = QSpinBox(parent)
        self.spin_zone_nth.setRange(1, 99)
        self.spin_zone_nth.setValue(2)
        self.edit_zone_stop = QLineEdit(parent)
        self.edit_zone_fill = QLineEdit(parent)
        self.cb_ul_intercept_config23 = QCheckBox(parent)

        self.cb_ul_dirty_clean = QCheckBox(parent)
        self.cb_ul_truncate = QCheckBox(parent)
        self.spin_ul_truncate_min = QSpinBox(parent)
        self.spin_ul_truncate_min.setRange(100, 65535)
        self.spin_ul_truncate_min.setValue(500)
        self.edit_bl_str = QLineEdit(parent)
        self.bl_table = QTableWidget(0, 3, parent)
        self.bl_table.setHorizontalHeaderLabels(["字符串", "命中次数", "操作"])

        self.cb_az_dl_intercept = QCheckBox(parent)
        self.cb_chunk_block = QCheckBox(parent)
        self.edit_chunk_block_pattern = QLineEdit(parent)
        self.lbl_dl_replace = QLabel(parent)
        self.edit_dl_replace = QLineEdit(parent)
        self.cb_hok_33_replay_replace = QCheckBox(parent)
        self.cb_hok_dl_intercept = QCheckBox(parent)

        self.cb_dz_cmd_bl_enabled = QCheckBox(parent)
        self.cb_dz_dl_intercept = QCheckBox(parent)
        self.edit_pb_cmd_input = QLineEdit(parent)
        self.pb_cmd_table = QTableWidget(0, 3, parent)
        self.pb_cmd_table.setHorizontalHeaderLabels(["命令名", "命中次数", "操作"])
        self.edit_dl_search = QLineEdit(parent)
        self.cb_dl_01_block = QCheckBox("启用重放端口 01 下行文件破坏", parent)
        self.cb_dl_01_block.setToolTip(
            "扫描服务器下发的全部01逻辑包；命中0x08 ZIP记录后解密并将"
            "ZIP头PK0304改为PZ0304，"
            "随后重算CRC、重新加密并转发。"
        )
        self.cb_dl_01_mrpcs_mutate = QCheckBox(
            "拦截 mrpcs 文件名（.data → 1data）", parent
        )
        self.cb_dl_01_mrpcs_mutate.setToolTip(
            "仅重放端口生效；解密01下行0x08/0x09明文，命中 mrpcs*.data 后"
            "把点号等长改成1，再重算CRC并重新加密。"
        )

        self.dl_stat_table = self._make_stat_table(
            ["游戏账户", "上行命中", "01拦截", "33拦截", "块填充", "最后活跃", "操作"],
            ops_col=6,
        )
        self.dl_stat_table_hok = self._make_stat_table(
            ["游戏账户", "上行命中", "01拦截", "33拦截", "块填充", "最后活跃", "操作"],
            ops_col=6,
        )
        self.dl_stat_table_dz = self._make_stat_table(
            ["游戏账户", "命令黑名单", "01拦截", "33拦截", "最后活跃", "操作"],
            ops_col=5,
        )
        for table in (
            self.dl_stat_table,
            self.dl_stat_table_hok,
            self.dl_stat_table_dz,
        ):
            table.setParent(parent)

        az_page = QWidget(parent)
        az_page.setObjectName("legacyUamInterceptPage")
        hok_page = QWidget(parent)
        hok_page.setObjectName("legacyHokInterceptPage")
        self._legacy_intercept_pages = (az_page, hok_page)

        self._legacy_dz_intercept_widgets = (
            self.cb_dz_cmd_bl_enabled,
            self.cb_dz_dl_intercept,
            self.edit_pb_cmd_input,
            self.pb_cmd_table,
            self.edit_dl_search,
            self.lbl_dl_replace,
            self.edit_dl_replace,
            self.dl_stat_table_dz,
        )
        legacy_widgets = (
            self.dl_intercept_log,
            self.cb_destroy_mode,
            self.edit_zone_start,
            self.spin_zone_nth,
            self.edit_zone_stop,
            self.edit_zone_fill,
            self.cb_ul_intercept_config23,
            self.cb_ul_dirty_clean,
            self.cb_ul_truncate,
            self.spin_ul_truncate_min,
            self.edit_bl_str,
            self.bl_table,
            self.cb_az_dl_intercept,
            self.cb_chunk_block,
            self.edit_chunk_block_pattern,
            self.cb_hok_33_replay_replace,
            self.cb_hok_dl_intercept,
            self.dl_stat_table,
            self.dl_stat_table_hok,
            *self._legacy_dz_intercept_widgets,
            *self._legacy_intercept_pages,
        )
        for widget in legacy_widgets:
            widget.hide()

    def _build_dl_intercept_tab(self) -> QWidget:
        """DFM专版拦截页：仅显示声明式Type9规则文件管理。"""
        w = QWidget()
        self._build_legacy_intercept_compat_controls(w)

        v = QVBoxLayout(w)
        v.setContentsMargins(10, 10, 10, 10)
        v.setSpacing(8)

        type9_rule_box = QGroupBox("01 上行拦截（Type9 规则）")
        type9_rule_v = QVBoxLayout(type9_rule_box)
        type9_rule_v.setSpacing(5)

        type9_rule_bar = QHBoxLayout()
        self.lbl_type9_rule_status = QLabel("规则状态：读取中…")
        self.lbl_type9_rule_status.setStyleSheet(
            "color:#93c5fd; font-weight:bold;"
        )
        type9_rule_bar.addWidget(self.lbl_type9_rule_status, 1)
        self.btn_type9_rule_load = QPushButton("📂 加载规则文件")
        self.btn_type9_rule_load.setToolTip(
            "选择JSON规则文件，完整校验后原子保存并立即切换内存规则。"
        )
        self.btn_type9_rule_load.clicked.connect(self._on_type9_rule_load)
        type9_rule_bar.addWidget(self.btn_type9_rule_load)
        self.btn_type9_rule_reload = QPushButton("🔄 重载当前文件")
        self.btn_type9_rule_reload.setToolTip(
            "重新读取 C:\\PyProxyApp\\type9_hot_rules.json。"
        )
        self.btn_type9_rule_reload.clicked.connect(self._on_type9_rule_reload)
        type9_rule_bar.addWidget(self.btn_type9_rule_reload)
        self.btn_type9_rule_clear_stats = QPushButton("🧹 清空统计")
        self.btn_type9_rule_clear_stats.setToolTip(
            "一键清零热规则和tfp_called内置规则的全部成功改写次数，不影响当前规则配置。"
        )
        self.btn_type9_rule_clear_stats.clicked.connect(
            self._on_type9_rule_clear_stats
        )
        type9_rule_bar.addWidget(self.btn_type9_rule_clear_stats)
        self.btn_type9_rule_export = QPushButton("💾 导出")
        self.btn_type9_rule_export.clicked.connect(self._on_type9_rule_export)
        type9_rule_bar.addWidget(self.btn_type9_rule_export)
        type9_rule_v.addLayout(type9_rule_bar)

        self.type9_rule_table = QTableWidget(0, 8)
        self.type9_rule_table.setHorizontalHeaderLabels(
            ["启用", "规则ID", "中文说明", "recordCode", "messageId", "长度", "动作", "成功改写"]
        )
        type9_rule_hdr = self.type9_rule_table.horizontalHeader()
        type9_rule_hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        type9_rule_hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        type9_rule_hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        for col in range(3, 8):
            type9_rule_hdr.setSectionResizeMode(col, QHeaderView.ResizeToContents)
        self.type9_rule_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.type9_rule_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.type9_rule_table.verticalHeader().setVisible(False)
        self.type9_rule_table.setAlternatingRowColors(True)
        self.type9_rule_table.setShowGrid(False)
        self.type9_rule_table.setMinimumHeight(180)
        type9_rule_v.addWidget(self.type9_rule_table, 1)

        type9_rule_hint = QLabel(
            "规则文件描述普通热规则；tfp_called与内容黑名单删叶作为内置规则显示并统计。"
        )
        type9_rule_hint.setStyleSheet("color:#6b7280; font-size:10px;")
        type9_rule_v.addWidget(type9_rule_hint)
        v.addWidget(type9_rule_box, 1)

        self.dl_01_block_box = QGroupBox("01 下行拦截")
        dl_01_v = QVBoxLayout(self.dl_01_block_box)
        dl_01_v.setSpacing(6)
        dl_01_bar = QHBoxLayout()
        self.cb_dl_01_block.show()
        dl_01_bar.addWidget(self.cb_dl_01_block)
        dl_01_bar.addStretch(1)
        dl_01_v.addLayout(dl_01_bar)

        self.cb_dl_01_mrpcs_mutate.show()
        dl_01_v.addWidget(self.cb_dl_01_mrpcs_mutate)

        self.lbl_dl_01_block_hint = QLabel(
            "仅作用于重放端口的服务器→客户端01流量。勾选后扫描全部01逻辑包："
            "命中ZIP头的0x08记录时执行PK→PZ；命中 mrpcs*.data 时等长改为"
            " mrpcs*1data；未命中内容原样透传。"
        )
        self.lbl_dl_01_block_hint.setWordWrap(True)
        self.lbl_dl_01_block_hint.setStyleSheet("color:#6b7280; font-size:10px;")
        dl_01_v.addWidget(self.lbl_dl_01_block_hint)
        v.addWidget(self.dl_01_block_box)
        return w

    def _refresh_type9_rule_ui(self, status: dict | None = None):
        """刷新拦截管理中的Type9规则摘要与规则表。"""
        if not hasattr(self, "type9_rule_table"):
            return
        try:
            if status is None:
                from core.type9_special_rules import type9_hot_rule_store
                status = type9_hot_rule_store.snapshot()
            status = status or {}
            document = status.get("document") or {}
            revision = str(document.get("revision") or "-")
            generation = int(status.get("generation") or 0)
            active = int(status.get("active_rule_count") or 0)
            from core.type9_content_blacklist import CONTENT_BLACKLIST_RULE_ROWS
            from core.type9_shadow import TFP_CALLED_INTERCEPT_RULE_ROWS
            builtin_rows = (
                list(CONTENT_BLACKLIST_RULE_ROWS)
                + list(TFP_CALLED_INTERCEPT_RULE_ROWS)
            )
            error = str(status.get("last_error") or "")
            state_text = "正常" if status.get("ok") else "校验异常"
            self.lbl_type9_rule_status.setText(
                f"规则状态：{state_text}  revision={revision}  "
                f"generation={generation}  active={active}+{len(builtin_rows)}内置"
            )
            self.lbl_type9_rule_status.setToolTip(
                f"文件：{status.get('path') or '-'}\n"
                f"加载时间：{status.get('loaded_at') or '-'}\n"
                f"错误：{error or '-'}"
            )
            self.lbl_type9_rule_status.setStyleSheet(
                "color:#86efac; font-weight:bold;"
                if status.get("ok") else
                "color:#fca5a5; font-weight:bold;"
            )

            rules = list(document.get("rules") or [])
            rules.extend(
                {
                    "id": row.get("id"),
                    "description": row.get("description"),
                    "enabled": True,
                    "builtin": True,
                    "match": {
                        "record_code": row.get("record_code", "*"),
                        "message_id": "-",
                        "length": "*",
                    },
                    "action": row.get("action", ""),
                }
                for row in builtin_rows
            )
            changed_counts = status.get("rule_changed_counts") or {}
            self.type9_rule_table.setRowCount(0)
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                match = rule.get("match") or {}
                row = self.type9_rule_table.rowCount()
                self.type9_rule_table.insertRow(row)
                values = [
                    "内置" if rule.get("builtin") else
                    "是" if rule.get("enabled", True) else "否",
                    str(rule.get("id") or ""),
                    str(rule.get("description") or ""),
                    str(match.get("record_code") or ""),
                    str(match.get("message_id") or ""),
                    str(match.get("length") or ""),
                    str(rule.get("action") or ""),
                    str(int(changed_counts.get(str(rule.get("id") or ""), 0))),
                ]
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if col == 0:
                        item.setForeground(QColor(
                            "#60a5fa" if value == "内置" else
                            "#4ade80" if value == "是" else "#9ca3af"
                        ))
                    self.type9_rule_table.setItem(row, col, item)
        except Exception as exc:
            self.lbl_type9_rule_status.setText(
                f"规则状态：刷新异常 {type(exc).__name__}: {exc}"
            )
            self.lbl_type9_rule_status.setStyleSheet(
                "color:#fca5a5; font-weight:bold;"
            )

    def _on_type9_rule_load(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "加载Type9热规则",
            "",
            "Type9规则 (*.json);;所有文件 (*)",
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                document = json.load(handle)
            from core.type9_special_rules import type9_hot_rule_store
            status = type9_hot_rule_store.replace_document(document)
            self._refresh_type9_rule_ui(status)
            _event(
                "INFO",
                "Type9Rules",
                "界面热加载规则 "
                f"file={os.path.basename(path)} "
                f"revision={status.get('document', {}).get('revision') or '-'} "
                f"active={status.get('active_rule_count')}",
            )
            QMessageBox.information(
                self,
                "Type9热规则",
                "规则已校验、保存并切换。\n"
                f"启用规则：{status.get('active_rule_count', 0)}\n"
                f"版本：{status.get('document', {}).get('revision') or '-'}",
            )
        except Exception as exc:
            self._refresh_type9_rule_ui()
            QMessageBox.warning(
                self,
                "规则加载失败",
                f"{type(exc).__name__}: {exc}",
            )

    def _on_type9_rule_reload(self):
        try:
            from core.type9_special_rules import type9_hot_rule_store
            status = type9_hot_rule_store.reload(force=True)
            self._refresh_type9_rule_ui(status)
            if status.get("ok"):
                _event(
                    "INFO",
                    "Type9Rules",
                    "界面重载当前规则 "
                    f"generation={status.get('generation')} "
                    f"active={status.get('active_rule_count')}",
                )
            else:
                QMessageBox.warning(
                    self,
                    "规则重载结果",
                    str(status.get("last_error") or "规则校验异常"),
                )
        except Exception as exc:
            self._refresh_type9_rule_ui()
            QMessageBox.warning(
                self,
                "规则重载失败",
                f"{type(exc).__name__}: {exc}",
            )

    def _on_type9_rule_clear_stats(self):
        try:
            from core.type9_special_rules import type9_hot_rule_store
            status = type9_hot_rule_store.clear_changed_counts()
            self._refresh_type9_rule_ui(status)
            _event(
                "INFO",
                "Type9Rules",
                "界面一键清空成功改写统计",
            )
        except Exception as exc:
            self._refresh_type9_rule_ui()
            QMessageBox.warning(
                self,
                "清空统计失败",
                f"{type(exc).__name__}: {exc}",
            )

    def _on_type9_rule_export(self):
        try:
            from core.type9_special_rules import type9_hot_rule_store
            status = type9_hot_rule_store.snapshot()
            revision = re.sub(
                r"[^0-9A-Za-z._-]+",
                "_",
                str(status.get("document", {}).get("revision") or "rules"),
            )
            path, _ = QFileDialog.getSaveFileName(
                self,
                "导出Type9热规则",
                f"type9_hot_rules_{revision}.json",
                "Type9规则 (*.json)",
            )
            if not path:
                return
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(
                    status.get("document") or {},
                    handle,
                    ensure_ascii=False,
                    indent=2,
                )
            QMessageBox.information(self, "Type9热规则", f"已导出：\n{path}")
        except Exception as exc:
            QMessageBox.warning(
                self,
                "规则导出失败",
                f"{type(exc).__name__}: {exc}",
            )

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
        可配置管理端口和密码；代理运行时保存也会立即生效。
        """
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(6, 6, 6, 6)
        v.setSpacing(6)

        # 说明标签
        hint = QLabel(
            "通过浏览器远程管理。支持手机访问，输入密码登录后可创建重放账号等。"
            "修改密码和端口均在保存后立即生效。"
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
        # 若代理已运行，立即更新密码/重绑端口；服务之前启动失败时也会补启动。
        apply_error = self._ensure_remote_admin_running(port, token)
        self.lbl_remote_url.setText(f"http://localhost:{port}/")
        if apply_error:
            self.lbl_status.setText("远程管理端口启动失败")
            QMessageBox.warning(
                self,
                "远程管理启动失败",
                f"配置已保存，但端口 {port} 启动失败：\n{apply_error}",
            )
        else:
            self.lbl_status.setText("远程管理配置已保存并生效")
            QMessageBox.information(self, "提示", "配置已保存并立即生效。")

    def _ensure_remote_admin_running(self, port: int, token: str = "") -> str:
        """确保管理服务监听指定端口；成功返回空字符串。"""
        if not engine.running:
            return ""  # 配置会在下一次启动代理时生效
        effective_token = token if len(token) >= 6 else (app_config.get("admin_token") or "")
        try:
            api = engine.admin_api
            if api is None:
                from core.admin_api import AdminApiServer
                api = AdminApiServer(
                    bind=app_config.get("admin_bind") or "0.0.0.0",
                    port=port,
                    token=effective_token,
                    on_users_changed=engine.reload_users,
                )
                api.start()
                engine.admin_api = api
                if api.token != effective_token:
                    app_config.set("admin_token", api.token)
                    app_config.save()
                    self.edit_admin_token.setText(api.token)
                _event("INFO", "AdminAPI", f"管理服务已补启动，端口 {port}")
                return ""

            if len(token) >= 6:
                api.token = token
                _event("INFO", "AdminAPI", "管理密码已更新")
            actual_port = (
                int(api._httpd.server_address[1])
                if api._httpd is not None
                else -1
            )
            if actual_port != port:
                api.stop()
                api.port = port
                api.start()
                _event("INFO", "AdminAPI", f"管理端口已切换到 {port}")
            return ""
        except Exception as ex:
            engine.admin_api = None
            _event("WARN", "AdminAPI", f"管理端口 {port} 启动失败: {ex}")
            return str(ex)

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
        """根据账户所属游戏返回对应统计表"""
        gid = self._account_game.get(account_label, "0a92")
        if gid == "hok":
            return self.dl_stat_table_hok
        if self._is_delta_game(gid):
            return self.dl_stat_table_dz
        return self.dl_stat_table

    def _is_delta_game(self, gid: str) -> bool:
        return bool(gid and gid not in ("az", "hok"))

    def _is_delta_account(self, account_label: str) -> bool:
        return self._is_delta_game(self._account_game.get(account_label, "0a92"))

    def _stat_table_for_game(self, gid: str) -> QTableWidget:
        if gid == "hok":
            return self.dl_stat_table_hok
        if self._is_delta_game(gid):
            return self.dl_stat_table_dz
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
        """若无拦截统计行则创建（例如首条事件为上行 PB_BL 时尚未走过其它拦截路径）。"""
        if account_label in self._dl_intercept_stats:
            return
        _is_dz = self._is_delta_account(account_label)
        tbl = self._stat_table_for(account_label)
        self._dl_intercept_stats[account_label] = {
            "ul_hit": 0, "01_drop": 0, "str_replace": 0, "chunk_drop": 0, "pb_dl_bl": 0,
            "last_active": datetime.now()}
        tbl.setSortingEnabled(False)
        row = tbl.rowCount()
        tbl.insertRow(row)
        lbl_item = QTableWidgetItem(account_label)
        lbl_item.setData(Qt.UserRole, account_label)
        lbl_item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        tbl.setItem(row, 0, lbl_item)
        now_str = datetime.now().strftime("%H:%M:%S")
        num_cols = 4 if _is_dz else 5
        for col, txt in enumerate(["0"] * num_cols + [now_str], start=1):
            it = QTableWidgetItem(txt)
            it.setTextAlignment(Qt.AlignCenter)
            tbl.setItem(row, col, it)
        ops_col = 5 if _is_dz else 6
        tbl.setCellWidget(row, ops_col, self._make_stat_ops_widget(account_label))
        tbl.resizeRowToContents(row)
        tbl.setSortingEnabled(True)

    def _on_dl_intercept_event(self, account_label: str, event_type: str, message: str):
        """拦截事件：更新统计表格 + 黑名单命中计数 + 转发详情弹窗
        event_type: game_init | ul_hit | ul_log | 01_drop | str_replace | chunk_drop | pb_dl_bl | pb_dl_scan | reset
        message: game_init 时为 game_id；ul_hit 时为命中字符串；ul_log 时为诊断日志文本；其他为日志文本
        """
        # ── game_init：记录账户所属游戏，初始化对应表行 ──────────────────────
        # 当 game 从 "az" 升级为插件游戏（如 "0a92"）时，将已有行从暗区表迁移到三角洲表。
        if event_type == "game_init":
            old_gid = self._account_game.get(account_label, "0a92")
            new_gid = message or "0a92"
            # game_init 仅在服务端判定 game 变化时发出（见 dl_intercept），此处直接迁移 Tab。
            self._account_game[account_label] = new_gid
            # 游戏发生变化 → 把旧表中已存在的行迁移到新表
            if old_gid != new_gid:
                old_tbl = self._stat_table_for_game(old_gid)
                new_tbl = self._stat_table_for_game(new_gid)
                if old_tbl is not new_tbl:
                    old_row = -1
                    for r in range(old_tbl.rowCount()):
                        it = old_tbl.item(r, 0)
                        if it and it.data(Qt.UserRole) == account_label:
                            old_row = r
                            break
                    if old_row >= 0:
                        # 把旧行的统计数据读出后移除，立即在新表创建对应行
                        old_tbl.removeRow(old_row)
                        # 立即在新表建行，避免等待下次事件导致行"消失"
                        self._on_dl_intercept_event(account_label, "ul_hit", "")
            return

        # ── ul_log：上行扫描诊断日志，写入内存缓存并可选转发到已打开的上行弹窗 ─────────────────
        if event_type == "ul_log":
            if self._intercept_history_label_match(account_label):
                self._ul_log_history.setdefault(account_label, []).append(message)
            dlg = self._ul_detail_dialogs.get(account_label)
            if dlg:
                dlg.append_log(message)
            # 三角洲上行 PB 命令黑名单：仅 ✅/❌ 计「命令黑名单」统计；⚠ 扫描未命中只记日志
            if message.startswith("[PB_BL]") and ("✅" in message or "❌" in message):
                mm = re.search(r"(?:命令清零|重加密失败)\s+(\S+)", message)
                if mm:
                    self._update_pb_cmd_hit(mm.group(1).strip())
                _is_dz_pb = self._is_delta_account(account_label)
                if _is_dz_pb:
                    self._ensure_dl_stat_row(account_label)
                    stats_pb = self._dl_intercept_stats[account_label]
                    stats_pb["pb_dl_bl"] = stats_pb.get("pb_dl_bl", 0) + 1
                    stats_pb["last_active"] = datetime.now()
                    row_pb = self._find_stat_row(account_label)
                    if row_pb >= 0:
                        tbl_pb = self._stat_table_for(account_label)
                        tbl_pb.setSortingEnabled(False)
                        tbl_pb.item(row_pb, 1).setText(str(stats_pb.get("pb_dl_bl", 0)))
                        tbl_pb.item(row_pb, 4).setText(
                            stats_pb["last_active"].strftime("%H:%M:%S"))
                        tbl_pb.setSortingEnabled(True)
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
                ts_col = 4 if self._is_delta_account(account_label) else 5
                tbl_trunc.setSortingEnabled(False)
                tbl_trunc.item(row, 1).setText(str(stats.get("ul_hit", 0)))
                tbl_trunc.item(row, ts_col).setText(stats["last_active"].strftime("%H:%M:%S"))
                tbl_trunc.setSortingEnabled(True)
            log_msg = f"[UL截断] ✅ 大包截断 {message}"
            if self._intercept_history_label_match(account_label):
                self._ul_log_history.setdefault(account_label, []).append(log_msg)
            dlg = self._ul_detail_dialogs.get(account_label)
            if dlg:
                dlg.append_log(log_msg)
            return

        # ── pb_dl_scan：三角洲下行 PB 黑名单「扫描未命中」仅进下发详情/历史，不计数 ───────
        if event_type == "pb_dl_scan":
            if self._intercept_history_label_match(account_label):
                self._dl_intercept_history.setdefault(account_label, []).append(
                    (event_type, message))
            dlg_sc = self._dl_intercept_detail_dialogs.get(account_label)
            if dlg_sc:
                dlg_sc.append_event(event_type, message)
            return

        if event_type == "reset":
            if account_label in self._dl_intercept_stats:
                self._dl_intercept_stats[account_label].update({
                    "ul_hit": 0, "01_drop": 0, "str_replace": 0, "chunk_drop": 0, "pb_dl_bl": 0,
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
                    _dz_rst = self._is_delta_account(account_label)
                    dlg.update_summary_from_stats(
                        {"pb_dl_bl": 0, "01_drop": 0, "str_replace": 0, "chunk_drop": 0},
                        is_delta=_dz_rst,
                    )
                    dlg.append_event("diag", "--- 重放上线，统计已重置 ---")
                if account_label in self._dl_intercept_history:
                    self._dl_intercept_history[account_label].clear()
            return

        # ── 初始化账户统计行 ─────────────────────────────────────────────
        _is_dz = self._is_delta_account(account_label)
        tbl = self._stat_table_for(account_label)

        if account_label not in self._dl_intercept_stats:
            self._dl_intercept_stats[account_label] = {
                "ul_hit": 0, "01_drop": 0, "str_replace": 0, "chunk_drop": 0, "pb_dl_bl": 0,
                "last_active": datetime.now()}
            tbl.setSortingEnabled(False)
            row = tbl.rowCount()
            tbl.insertRow(row)

            lbl_item = QTableWidgetItem(account_label)
            lbl_item.setData(Qt.UserRole, account_label)
            lbl_item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            tbl.setItem(row, 0, lbl_item)
            now_str = datetime.now().strftime("%H:%M:%S")
            # 三角洲: 命令黑名单|01拦截|33拦截|最后活跃 (4个数值列, 操作在5)
            # 暗区:   上行命中|01拦截|33拦截|块填充|最后活跃 (5个数值列, 操作在6)
            num_cols = 4 if _is_dz else 5
            for col, txt in enumerate(["0"] * num_cols + [now_str], start=1):
                it = QTableWidgetItem(txt)
                it.setTextAlignment(Qt.AlignCenter)
                tbl.setItem(row, col, it)

            ops_col = 5 if _is_dz else 6
            tbl.setCellWidget(row, ops_col, self._make_stat_ops_widget(account_label))
            tbl.resizeRowToContents(row)
            tbl.setSortingEnabled(True)

        # ── 更新计数 ─────────────────────────────────────────────────────
        stats = self._dl_intercept_stats[account_label]
        stats[event_type] = stats.get(event_type, 0) + 1
        stats["last_active"] = datetime.now()

        if event_type == "pb_dl_bl" and message:
            mm_pb = re.search(r"命令名混淆 '([^']+)'", message)
            if mm_pb:
                self._update_pb_cmd_hit(mm_pb.group(1))

        # ul_hit：每帧计 1 次；message 含逗号分隔的所有命中字符串，各自更新黑名单计数
        if event_type == "ul_hit" and message:
            for _s in message.split(","):
                _s = _s.strip()
                if _s:
                    self._update_blacklist_hit(_s)

        row = self._find_stat_row(account_label)
        if row >= 0:
            tbl.setSortingEnabled(False)
            if _is_dz:
                # 三角洲列: 1=命令黑名单, 2=01拦截, 3=33拦截, 4=最后活跃
                tbl.item(row, 1).setText(str(stats.get("pb_dl_bl", 0)))
                tbl.item(row, 2).setText(str(stats.get("01_drop", 0)))
                tbl.item(row, 3).setText(str(stats.get("str_replace", 0)))
                tbl.item(row, 4).setText(stats["last_active"].strftime("%H:%M:%S"))
            else:
                # 暗区列: 1=上行命中, 2=01拦截, 3=33拦截, 4=块填充, 5=最后活跃
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
            dlg.update_summary_from_stats(stats, is_delta=_is_dz)

    def _on_dl_show_detail(self, account_label: str):
        """打开或聚焦指定账户的下发拦截详情弹窗"""
        dlg = self._dl_intercept_detail_dialogs.get(account_label)
        if dlg is None:
            stats = self._dl_intercept_stats.get(account_label, {})
            dlg = DlInterceptDetailDialog(account_label, self)
            _dz_op = self._is_delta_account(account_label)
            dlg.update_summary_from_stats(stats, is_delta=_dz_op)
            for ev_type, ev_msg in self._dl_intercept_history.get(account_label, []):
                dlg.append_event(ev_type, ev_msg)
            self._dl_intercept_detail_dialogs[account_label] = dlg
            dlg.show()
        else:
            dlg.raise_()
            dlg.activateWindow()

    def _on_dl_sort_stats(self):
        """按总数降序排列各游戏统计表"""
        for tbl, is_dz in [
            (self.dl_stat_table, False),
            (self.dl_stat_table_hok, False),
            (self.dl_stat_table_dz, True),
        ]:
            rows = tbl.rowCount()
            if rows < 2:
                continue
            data = []
            for r in range(rows):
                lbl = (tbl.item(r, 0).data(Qt.UserRole) if tbl.item(r, 0) else "")
                try:
                    num_cols = 4 if is_dz else 5
                    total = sum(
                        int(tbl.item(r, c).text() or 0)
                        for c in range(1, num_cols)
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
                if is_dz:
                    vals = [str(stats.get("pb_dl_bl", 0)), str(stats.get("01_drop", 0)),
                            str(stats.get("str_replace", 0)), ts]
                    ops_col = 5
                else:
                    vals = [str(stats.get("ul_hit", 0)), str(stats.get("01_drop", 0)),
                            str(stats.get("str_replace", 0)), str(stats.get("chunk_drop", 0)), ts]
                    ops_col = 6
                for col, val in enumerate(vals, start=1):
                    it = QTableWidgetItem(val)
                    it.setTextAlignment(Qt.AlignCenter)
                    tbl.setItem(row, col, it)
                tbl.setCellWidget(row, ops_col, self._make_stat_ops_widget(lbl))
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
        self._account_game.clear()
        self.dl_stat_table.setRowCount(0)
        self.dl_stat_table_hok.setRowCount(0)
        self.dl_stat_table_dz.setRowCount(0)
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

    # ── 三角洲命令名黑名单管理 ─────────────────────────────────────────────

    def _on_pb_cmd_add(self):
        s = self.edit_pb_cmd_input.text().strip()
        if not s or s in self._pb_cmd_blacklist:
            return
        self._pb_cmd_blacklist[s] = 0
        self.edit_pb_cmd_input.clear()
        self._refresh_pb_cmd_table()
        self._save_pb_cmd_blacklist_to_config()

    def _on_pb_cmd_remove(self, s: str):
        self._pb_cmd_blacklist.pop(s, None)
        self._refresh_pb_cmd_table()
        self._save_pb_cmd_blacklist_to_config()

    def _update_pb_cmd_hit(self, matched_cmd: str):
        """命令命中时递增计数并刷新表格"""
        self._pb_cmd_blacklist[matched_cmd] = self._pb_cmd_blacklist.get(matched_cmd, 0) + 1
        for r in range(self.pb_cmd_table.rowCount()):
            item = self.pb_cmd_table.item(r, 0)
            if item and item.text() == matched_cmd:
                cnt_item = self.pb_cmd_table.item(r, 1)
                if cnt_item:
                    cnt_item.setText(str(self._pb_cmd_blacklist[matched_cmd]))
                break

    def _refresh_pb_cmd_table(self):
        self.pb_cmd_table.setRowCount(0)
        for s, hits in self._pb_cmd_blacklist.items():
            row = self.pb_cmd_table.rowCount()
            self.pb_cmd_table.insertRow(row)
            self.pb_cmd_table.setItem(row, 0, QTableWidgetItem(s))
            cnt_item = QTableWidgetItem(str(hits))
            cnt_item.setTextAlignment(Qt.AlignCenter)
            self.pb_cmd_table.setItem(row, 1, cnt_item)
            btn_del = QPushButton("🗑 删除")
            btn_del.setMinimumSize(72, 30)
            btn_del.setStyleSheet("QPushButton{padding:4px 8px;}")
            btn_del.clicked.connect(lambda _, _s=s: self._on_pb_cmd_remove(_s))
            self.pb_cmd_table.setCellWidget(row, 2, btn_del)
        self.pb_cmd_table.resizeRowsToContents()

    def _save_pb_cmd_blacklist_to_config(self):
        app_config.set("pb_cmd_blacklist",
                       [{"cmd": k, "hits": v} for k, v in self._pb_cmd_blacklist.items()])
        app_config.save()

    def _on_open_remote_admin(self):
        """在默认浏览器中打开远程管理页面"""
        port = self.spin_admin_port.value()
        err = self._ensure_remote_admin_running(
            port, self.edit_admin_token.text().strip()
        )
        if err:
            self.lbl_status.setText(f"管理端口 {port} 未启动")
            QMessageBox.warning(
                self,
                "远程管理启动失败",
                f"端口 {port} 未启动：\n{err}",
            )
            return
        if not engine.running:
            self.lbl_status.setText("请先启动代理")
            QMessageBox.information(self, "提示", "请先启动代理，再打开远程管理。")
            return
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
        self.btn_block_3366.toggled.connect(self._on_toggle_3366_block)
        self.btn_ext_apply.clicked.connect(self._on_apply_ext)
        self.btn_ext_test.clicked.connect(self._on_test_ext)
        self.btn_add_user.clicked.connect(self._on_add_user)
        self.btn_edit_passwd.clicked.connect(self._on_edit_passwd)
        self.btn_del_user.clicked.connect(self._on_del_user)
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
        log_bus.conn_replay_phase.connect(self._on_conn_replay_phase)
        log_bus.conn_game_id_update.connect(self._on_conn_game_id_update)
        log_bus.conn_3366_product.connect(self._on_conn_3366_product)
        log_bus.conn_ace_channels_updated.connect(self._on_conn_ace_channels_updated)
        log_bus.admin_log.connect(self._on_admin_log)
        log_bus.dl_intercept_log.connect(self._on_dl_intercept_log)
        log_bus.dl_intercept_event.connect(self._on_dl_intercept_event)
        log_bus.threshold_3366_block.connect(self._on_threshold_3366_block)
        log_bus.recording_goal_3366_block.connect(
            self._on_recording_goal_3366_block
        )

        log_bus.stream_raw_data.connect(lambda c, d, l, r: self._add_stream_row(self.tb_stream_raw, self.stream_raw_data_cache, c, d, l, r))
        log_bus.stream_parsed_data.connect(lambda c, d, p, l, r: self._add_stream_row(self.tb_stream_parsed, self.stream_parsed_data_cache, c, d, l, r, prefix=p))
        log_bus.stream_sent_data.connect(lambda c, d, l, r: self._add_stream_row(self.tb_stream_sent, self.stream_sent_data_cache, c, d, l, r))
        log_bus.users_updated.connect(self._refresh_user_table)
        self._ext_check_done.connect(self._on_ext_check_result)

        # 连接表详情按钮 + 双击 + 详细日志勾选
        self.btn_conn_detail.clicked.connect(self._on_show_detail)
        self.conn_table.doubleClicked.connect(lambda _: self._on_show_detail())
        self.cb_replenish_01.toggled.connect(self._save_config_from_ui)
        self.cb_replenish_01.toggled.connect(self._refresh_rebuild_controls)
        for rebuild_checkbox in (
            self.cb_rebuild_central9,
            self.cb_rebuild_strong_profile,
            self.cb_rebuild_match_events,
            self.cb_rebuild_scan_waves,
            self.cb_rebuild_player_800D,
            self.cb_rebuild_player_8007,
            self.cb_rebuild_player_800A,
            self.cb_rebuild_player_800C,
            self.cb_rebuild_player_800F,
            self.cb_rebuild_player_8023,
            self.cb_rebuild_player_8024,
            self.cb_rebuild_player_802C,
        ):
            rebuild_checkbox.toggled.connect(self._save_config_from_ui)
            rebuild_checkbox.toggled.connect(self._refresh_config_summary)
        self.cb_hold_01.toggled.connect(self._save_config_from_ui)
        self.cb_detail_01.toggled.connect(self._save_config_from_ui)
        for checkbox in (
            self.cb_replenish_01,
            self.cb_hold_01,
            self.cb_detail_01,
        ):
            checkbox.toggled.connect(self._refresh_config_summary)
        for spin in (
            self.spin_01_threshold,
            self.spin_message_coverage_threshold,
            self.spin_ai_log_periodic_full,
            self.spin_ai_log_context_before,
            self.spin_ai_log_context_after,
            self.spin_record_idle_timeout,
            self.spin_hold_01_keepalive,
            self.spin_ai_log_retention_days,
            self.spin_ai_log_max_gb,
        ):
            spin.valueChanged.connect(self._save_config_from_ui)
        self.combo_record_goal.currentIndexChanged.connect(
            self._save_config_from_ui
        )
        self.combo_record_goal.currentIndexChanged.connect(
            self._refresh_record_goal_controls
        )
        self.combo_record_goal.currentIndexChanged.connect(
            self._refresh_config_summary
        )
        self.edit_detail_01_users.selectionChanged.connect(
            self._save_config_from_ui
        )
        for control_signal in (
            self.spin_1081.valueChanged,
            self.spin_1080.valueChanged,
            self.cb_ext.toggled,
            self.edit_ext_ip.textChanged,
            self.spin_ext_port.valueChanged,
        ):
            control_signal.connect(self._refresh_top_config_summary)
        self.btn_config_save.clicked.connect(self._on_config_save)
        self.btn_config_reset.clicked.connect(self._on_config_reset)
        self.btn_config_open_dir.clicked.connect(self._on_config_open_dir)
        self.btn_config_open_ai_log.clicked.connect(
            self._on_config_open_ai_log
        )
        self.btn_config_clear_ai_log.clicked.connect(
            self._on_config_clear_ai_log
        )
        self.btn_config_export.clicked.connect(self._on_config_export)
        self.cb_dl_01_block.toggled.connect(self._save_config_from_ui)
        self.cb_dl_01_mrpcs_mutate.toggled.connect(self._save_config_from_ui)

        # 录制管理 Tab 内的按钮
        self.btn_rec_refresh.clicked.connect(self._on_record_updated)
        self.btn_rec_export.clicked.connect(self._on_rec_export)
        self.btn_rec_import.clicked.connect(self._on_rec_import)
        self.btn_rec_clear.clicked.connect(self._on_rec_clear_all)
        self.rec_session_table.currentItemChanged.connect(self._on_rec_session_selected)

        # 本地重放 Tab 内的按钮
        self.btn_map_add.clicked.connect(self._on_map_add)
        self.btn_map_del.clicked.connect(self._on_map_del)
        self.btn_map_clear.clicked.connect(self._on_map_clear)
        self._refresh_map_table()

    # ─── 配置读写 ────────────────────────────
    _AUDIT_CONFIG_KEYS = (
        "replenish_01_mode",
        "full_rebuild_01_mode",
        "rebuild_controls_v2",
        "rebuild_controls_v3",
        "rebuild_player_8007_enabled",
        "rebuild_player_800A_enabled",
        "rebuild_player_800C_enabled",
        "rebuild_player_800D_enabled",
        "rebuild_player_800F_enabled",
        "rebuild_player_8023_enabled",
        "rebuild_player_8024_enabled",
        "rebuild_player_802C_enabled",
        "rebuild_central9_enabled",
        "rebuild_player_base_enabled",
        "rebuild_match_events_enabled",
        "rebuild_scan_waves_enabled",
        "rebuild_central9_only",
        "rebuild_strong_profile",
        "rebuild_match_events",
        "rebuild_scan_waves",
        "hold_01_after_threshold",
        "hold_01_keepalive_sec",
        "detail_01_log",
        "detail_01_log_users",
        "ai_log_periodic_full_every",
        "auto_disconnect_01_policy",
        "auto_disconnect_01_threshold",
        "auto_disconnect_message_coverage_threshold",
        "type9_device_mode",
        "dl_01_block_enabled",
        "dl_01_mrpcs_mutate_enabled",
        "ext_enabled",
        "ext_ip",
        "ext_port",
        "record_idle_timeout",
        "port_record",
        "port_replay",
    )

    def _audit_config_state(self) -> dict:
        return {
            key: app_config.get(key)
            for key in self._AUDIT_CONFIG_KEYS
        }

    def _audit_runtime_state(self) -> dict:
        try:
            from core.type9_special_rules import type9_hot_rule_store
            rule_status = type9_hot_rule_store.snapshot()
        except Exception as exc:
            rule_status = {"last_error": f"{type(exc).__name__}: {exc}"}
        return {
            "engine": {
                "running": bool(getattr(engine, "running", False)),
                "manual_3366_block_enabled": bool(
                    getattr(engine, "manual_3366_block_enabled", False)
                ),
                "record_server_present": bool(getattr(engine, "server_1081", None)),
                "replay_server_present": bool(getattr(engine, "server_1080", None)),
            },
            "ui": {
                "start_enabled": bool(self.btn_start.isEnabled()),
                "stop_enabled": bool(self.btn_stop.isEnabled()),
                "block_3366_enabled": bool(self.btn_block_3366.isEnabled()),
                "block_3366_checked": bool(self.btn_block_3366.isChecked()),
                "active_tab_index": int(self.tabs.currentIndex())
                if hasattr(self, "tabs") else None,
            },
            "config_flags": self._audit_config_state(),
            "hot_rules": {
                "ok": bool(rule_status.get("ok")),
                "generation": int(rule_status.get("generation") or 0),
                "loaded_at": rule_status.get("loaded_at") or None,
                "revision": str(
                    (rule_status.get("document") or {}).get("revision") or ""
                ),
                "active_rule_count": int(
                    rule_status.get("active_rule_count") or 0
                ),
                "rule_changed_counts": dict(
                    rule_status.get("rule_changed_counts") or {}
                ),
                "last_error": rule_status.get("last_error") or None,
            },
            "runtime_counts": {
                "connections": len(self._conn_info),
                "recording_rows": len(self._rec_sid_rows),
            },
        }

    def _audit_control(
        self,
        action: str,
        *,
        source: str = "ui",
        phase: str = "after",
        details: dict | None = None,
    ) -> None:
        try:
            from core.ai_log_v128 import ai_log_v128
            ai_log_v128.write_control_event(
                source=source,
                actor="operator" if source == "ui" else "runtime",
                action=action,
                phase=phase,
                details=dict(details or {}),
                state=self._audit_runtime_state(),
            )
        except (OSError, TypeError, ValueError, RuntimeError):
            pass

    def _audit_button_click(self, control: QPushButton, checked: bool) -> None:
        self._audit_control(
            "button_clicked",
            details={
                "object_name": str(control.objectName() or ""),
                "text": str(control.text() or ""),
                "checkable": bool(control.isCheckable()),
                "checked": bool(checked) if control.isCheckable() else None,
            },
        )

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
        self.spin_record_idle_timeout.setValue(int(
            app_config.get("record_idle_timeout", 180)
        ))
        app_config.set("dz_01_cross_account_template_enabled", False)
        app_config.set("type9_device_mode", "inherit_live")
        self.spin_01_threshold.setValue(int(
            app_config.get("auto_disconnect_01_threshold", 100)
        ))
        policy = str(app_config.get("auto_disconnect_01_policy", "count"))
        policy_index = self.combo_record_goal.findData(policy)
        self.combo_record_goal.setCurrentIndex(max(0, policy_index))
        self.spin_message_coverage_threshold.setValue(int(
            app_config.get("auto_disconnect_message_coverage_threshold", 100)
        ))
        self.cb_replenish_01.setChecked(bool(app_config.get("replenish_01_mode")))
        controls_v2 = bool(app_config.get("rebuild_controls_v2", False))
        controls_v3 = bool(app_config.get("rebuild_controls_v3", False))
        player_ids = ("8007", "800A", "800C", "800D", "800F", "8023", "8024", "802C")
        if controls_v3:
            central9 = bool(app_config.get("rebuild_central9_enabled", True))
            player_values = {
                mid: bool(app_config.get(f"rebuild_player_{mid}_enabled", False))
                for mid in player_ids
            }
            match_events = bool(
                app_config.get("rebuild_match_events_enabled", False)
            )
            scan_waves = bool(
                app_config.get("rebuild_scan_waves_enabled", False)
            )
            strong_profile = bool(
                app_config.get("rebuild_strong_profile", True)
            )
            player_base = player_values["800D"]
        elif controls_v2:
            central9 = bool(app_config.get("rebuild_central9_enabled", True))
            player_base = bool(app_config.get("rebuild_player_base_enabled", False))
            player_values = {mid: False for mid in player_ids}
            if player_base:
                for mid in ("800D", "8024", "802C"):
                    player_values[mid] = True
            match_events = bool(app_config.get("rebuild_match_events_enabled", False))
            scan_waves = bool(app_config.get("rebuild_scan_waves_enabled", False))
            strong_profile = bool(app_config.get("rebuild_strong_profile", True))
        else:
            central_only = bool(
                app_config.get("rebuild_central9_only", False)
            )
            legacy_full = bool(
                app_config.get("full_rebuild_01_mode", False)
                and not central_only
            )
            central9 = True
            player_base = legacy_full
            player_values = {mid: False for mid in player_ids}
            if player_base:
                for mid in ("800D", "8024", "802C"):
                    player_values[mid] = True
            match_events = bool(
                legacy_full
                and str(app_config.get("rebuild_match_events") or "off")
                == "random"
            )
            scan_waves = bool(
                legacy_full
                and str(
                    app_config.get("rebuild_scan_waves") or "repeat_first"
                ) != "off"
            )
            strong_profile = bool(
                app_config.get("rebuild_strong_profile", True)
                and not central_only
            )
        self.cb_rebuild_central9.setChecked(central9)
        self.cb_rebuild_strong_profile.setChecked(strong_profile)
        for mid, checkbox in (
            ("8007", self.cb_rebuild_player_8007),
            ("800A", self.cb_rebuild_player_800A),
            ("800C", self.cb_rebuild_player_800C),
            ("800D", self.cb_rebuild_player_800D),
            ("800F", self.cb_rebuild_player_800F),
            ("8023", self.cb_rebuild_player_8023),
            ("8024", self.cb_rebuild_player_8024),
            ("802C", self.cb_rebuild_player_802C),
        ):
            checkbox.setChecked(player_values[mid])
        self.cb_rebuild_match_events.setChecked(match_events)
        self.cb_rebuild_scan_waves.setChecked(scan_waves)
        self._refresh_rebuild_controls()
        self.cb_hold_01.setChecked(bool(app_config.get("hold_01_after_threshold")))
        self.spin_hold_01_keepalive.setValue(int(
            app_config.get("hold_01_keepalive_sec", 8)
        ))
        self.cb_ext.setChecked(app_config.get("ext_enabled"))
        self.edit_ext_ip.setText(app_config.get("ext_ip"))
        self.spin_ext_port.setValue(app_config.get("ext_port"))
        self.cb_detail_01.setChecked(bool(app_config.get("detail_01_log", True)))
        self.edit_detail_01_users.setText(str(
            app_config.get("detail_01_log_users", "test") or "test"
        ))
        self.spin_ai_log_periodic_full.setValue(int(
            app_config.get("ai_log_periodic_full_every", 100) or 0
        ))
        self.spin_ai_log_context_before.setValue(int(
            app_config.get("ai_log_anomaly_context_before", 10) or 0
        ))
        self.spin_ai_log_context_after.setValue(int(
            app_config.get("ai_log_anomaly_context_after", 5) or 0
        ))
        self.spin_ai_log_retention_days.setValue(int(
            app_config.get("ai_log_retention_days", 7) or 0
        ))
        self.spin_ai_log_max_gb.setValue(float(
            app_config.get("ai_log_max_gb", 10.0) or 0.0
        ))
        self.spin_admin_port.setValue(app_config.get("admin_port") or 8787)
        self.edit_admin_token.setText(app_config.get("admin_token") or "")
        self.edit_dl_search.setText(app_config.get("dl_search_str") or "")
        self.edit_dl_replace.setText(app_config.get("dl_replace_str") or "")
        destroy = app_config.get("dl_destroy_mode_enabled")
        self.cb_destroy_mode.setChecked(bool(destroy))
        self.lbl_dl_replace.setEnabled(not destroy)
        self.edit_dl_replace.setEnabled(not destroy)
        self.cb_az_dl_intercept.setChecked(bool(app_config.get("az_dl_intercept_enabled")))
        self.cb_hok_dl_intercept.setChecked(bool(app_config.get("hok_dl_intercept_enabled")))
        self.cb_hok_33_replay_replace.setChecked(bool(app_config.get("hok_33_replay_replace_enabled")))
        self.cb_dz_dl_intercept.setChecked(bool(app_config.get("dz_dl_intercept_enabled")))
        self.cb_dz_cmd_bl_enabled.setChecked(bool(app_config.get("dz_cmd_bl_enabled", True)))
        self.cb_chunk_block.setChecked(app_config.get("ace_chunk_block_enabled"))
        self.edit_chunk_block_pattern.setText(app_config.get("ace_chunk_block_pattern") or "")
        self.cb_dl_01_block.setChecked(app_config.get("dl_01_block_enabled"))
        self.cb_dl_01_mrpcs_mutate.setChecked(bool(
            app_config.get("dl_01_mrpcs_mutate_enabled")
        ))
        self.cb_ul_dirty_clean.setChecked(bool(app_config.get("ul_dirty_clean_enabled")))
        self.cb_ul_truncate.setChecked(bool(app_config.get("ul_truncate_abab_enabled")))
        self.spin_ul_truncate_min.setValue(int(app_config.get("ul_truncate_abab_min_len") or 500))
        # 三角洲命令名黑名单
        self._pb_cmd_blacklist = {
            item["cmd"]: int(item.get("hits", 0))
            for item in (app_config.get("pb_cmd_blacklist") or [])
            if isinstance(item, dict) and item.get("cmd")
        }
        self._refresh_pb_cmd_table()
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
        self._refresh_top_config_summary()
        self._refresh_record_goal_controls()
        self._refresh_config_summary()

    def _save_config_from_ui(self):
        """将界面控件值保存到 AppConfig（并写磁盘）"""
        if getattr(self, "_loading_config", False):
            return  # 加载配置阶段，禁止写回（防止中间状态覆盖磁盘值）
        audit_before = self._audit_config_state()
        app_config.set("port_record", self.spin_1081.value())
        app_config.set("port_replay", self.spin_1080.value())
        _idle = self.spin_record_idle_timeout.value()
        app_config.set("record_idle_timeout", _idle)
        app_config.set("replay_idle_timeout", _idle)
        app_config.set("dz_01_cross_account_template_enabled", False)
        app_config.set(
            "type9_device_mode",
            "inherit_live",
        )
        app_config.set("auto_disconnect_01_threshold", self.spin_01_threshold.value())
        app_config.set(
            "auto_disconnect_01_policy",
            str(self.combo_record_goal.currentData() or "count"),
        )
        app_config.set(
            "auto_disconnect_message_coverage_threshold",
            self.spin_message_coverage_threshold.value(),
        )
        app_config.set("replenish_01_mode", self.cb_replenish_01.isChecked())
        player_checkboxes = {
            "8007": self.cb_rebuild_player_8007,
            "800A": self.cb_rebuild_player_800A,
            "800C": self.cb_rebuild_player_800C,
            "800D": self.cb_rebuild_player_800D,
            "800F": self.cb_rebuild_player_800F,
            "8023": self.cb_rebuild_player_8023,
            "8024": self.cb_rebuild_player_8024,
            "802C": self.cb_rebuild_player_802C,
        }
        player_category_enabled = bool(
            any(checkbox.isChecked() for checkbox in player_checkboxes.values())
            or self.cb_rebuild_match_events.isChecked()
            or self.cb_rebuild_scan_waves.isChecked()
        )
        app_config.set(
            "full_rebuild_01_mode",
            player_category_enabled,
        )
        app_config.set("rebuild_controls_v2", True)
        app_config.set("rebuild_controls_v3", True)
        app_config.set(
            "rebuild_central9_enabled",
            self.cb_rebuild_central9.isChecked(),
        )
        app_config.set(
            "rebuild_player_base_enabled",
            any(checkbox.isChecked() for checkbox in player_checkboxes.values()),
        )
        for mid, checkbox in player_checkboxes.items():
            app_config.set(f"rebuild_player_{mid}_enabled", checkbox.isChecked())
        app_config.set(
            "rebuild_match_events_enabled",
            self.cb_rebuild_match_events.isChecked(),
        )
        app_config.set(
            "rebuild_scan_waves_enabled",
            self.cb_rebuild_scan_waves.isChecked(),
        )
        app_config.set("rebuild_central9_only", False)
        app_config.set(
            "rebuild_strong_profile",
            self.cb_rebuild_strong_profile.isChecked(),
        )
        app_config.set(
            "rebuild_match_events",
            "random" if self.cb_rebuild_match_events.isChecked() else "off",
        )
        app_config.set(
            "rebuild_scan_waves",
            "repeat_first" if self.cb_rebuild_scan_waves.isChecked() else "off",
        )
        app_config.set("hold_01_after_threshold", self.cb_hold_01.isChecked())
        app_config.set("hold_01_keepalive_sec", self.spin_hold_01_keepalive.value())
        app_config.set("ext_enabled", self.cb_ext.isChecked())
        app_config.set("ext_ip",      self.edit_ext_ip.text().strip())
        app_config.set("ext_port",    self.spin_ext_port.value())
        app_config.set("detail_01_log", self.cb_detail_01.isChecked())
        app_config.set(
            "detail_01_log_users",
            self.edit_detail_01_users.text().strip() or "test",
        )
        app_config.set(
            "ai_log_periodic_full_every",
            self.spin_ai_log_periodic_full.value(),
        )
        app_config.set(
            "ai_log_anomaly_context_before",
            self.spin_ai_log_context_before.value(),
        )
        app_config.set(
            "ai_log_anomaly_context_after",
            self.spin_ai_log_context_after.value(),
        )
        app_config.set(
            "ai_log_retention_days",
            self.spin_ai_log_retention_days.value(),
        )
        app_config.set("ai_log_max_gb", self.spin_ai_log_max_gb.value())
        app_config.set("admin_port",  self.spin_admin_port.value())
        tok = self.edit_admin_token.text().strip()
        if len(tok) >= 6:  # 仅当输入了有效密码（≥6位）时才覆盖
            app_config.set("admin_token", tok)
        app_config.set("az_dl_intercept_enabled", self.cb_az_dl_intercept.isChecked())
        app_config.set("hok_dl_intercept_enabled", self.cb_hok_dl_intercept.isChecked())
        app_config.set("hok_33_replay_replace_enabled", self.cb_hok_33_replay_replace.isChecked())
        app_config.set("dz_dl_intercept_enabled", self.cb_dz_dl_intercept.isChecked())
        app_config.set("dz_cmd_bl_enabled", self.cb_dz_cmd_bl_enabled.isChecked())
        app_config.set("dl_search_str", self.edit_dl_search.text())
        app_config.set("dl_replace_str", self.edit_dl_replace.text())
        app_config.set("dl_destroy_mode_enabled", self.cb_destroy_mode.isChecked())
        app_config.set("ace_chunk_block_enabled", self.cb_chunk_block.isChecked())
        pat_val = self.edit_chunk_block_pattern.text().strip()
        if pat_val:
            app_config.set("ace_chunk_block_pattern", pat_val)
        app_config.set("dl_01_block_enabled", self.cb_dl_01_block.isChecked())
        app_config.set(
            "dl_01_mrpcs_mutate_enabled",
            self.cb_dl_01_mrpcs_mutate.isChecked(),
        )
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
        # 三角洲命令名黑名单（持久化）
        app_config.set("pb_cmd_blacklist",
                       [{"cmd": k, "hits": v} for k, v in self._pb_cmd_blacklist.items()])
        app_config.save()
        self._refresh_config_summary()
        audit_after = self._audit_config_state()
        changed = {
            key: {"before": audit_before.get(key), "after": audit_after.get(key)}
            for key in self._AUDIT_CONFIG_KEYS
            if audit_before.get(key) != audit_after.get(key)
        }
        if changed:
            self._audit_control(
                "config_flags_changed",
                source="config",
                details={"changed": changed},
            )

    def _refresh_config_summary(self, *_):
        if not hasattr(self, "lbl_config_summary"):
            return
        if not self.cb_replenish_01.isChecked():
            rebuild = "重建关闭"
        else:
            selected = []
            if self.cb_rebuild_central9.isChecked():
                selected.append("中央9类")
            if self.cb_rebuild_strong_profile.isChecked():
                selected.append("强检8C03/9100")
            for mid, checkbox in (
                ("800D", self.cb_rebuild_player_800D),
                ("8007", self.cb_rebuild_player_8007),
                ("800A", self.cb_rebuild_player_800A),
                ("800C", self.cb_rebuild_player_800C),
                ("800F", self.cb_rebuild_player_800F),
                ("8023", self.cb_rebuild_player_8023),
                ("8024", self.cb_rebuild_player_8024),
                ("802C", self.cb_rebuild_player_802C),
            ):
                if checkbox.isChecked():
                    selected.append(mid)
            if self.cb_rebuild_match_events.isChecked():
                selected.append("对局802A/B")
            if self.cb_rebuild_scan_waves.isChecked():
                selected.append("扫描8027/8029")
            rebuild = "＋".join(selected) if selected else "未选择重建内容"
        policy = str(self.combo_record_goal.currentData() or "count")
        goal = {
            "count": f"{self.spin_01_threshold.value()}包",
            "coverage": f"80xx完整度{self.spin_message_coverage_threshold.value()}%",
            "either": (
                f"{self.spin_01_threshold.value()}包或80xx完整度"
                f"{self.spin_message_coverage_threshold.value()}%"
            ),
            "off": "持续录制",
        }.get(policy, f"{self.spin_01_threshold.value()}包")
        if policy == "off":
            hold = "持续录制（不自动阻断3366）"
        else:
            hold = f"达到{goal}后" + (
                "只收录" if self.cb_hold_01.isChecked() else "01继续转发"
            )
        users = self.edit_detail_01_users.text().strip() or "test"
        detail = (
            f"{users}完整Hex，其余精简"
            if self.cb_detail_01.isChecked()
            else "全员精简，异常自动完整"
        )
        self.lbl_config_summary.setText(
            f"设备：继承重放设备　｜　补数据：{rebuild}　｜　"
            "模板：同设备优先，跨设备按游戏ID回退\n"
            f"01录制：{hold}　｜　日志：{detail}　｜　"
            f"保留{self.spin_ai_log_retention_days.value()}天 / "
            f"上限{self.spin_ai_log_max_gb.value():.1f}GB"
        )

    def _refresh_rebuild_controls(self, *_):
        replenish_on = bool(self.cb_replenish_01.isChecked())
        self.rebuild_options_box.setEnabled(replenish_on)

    def _refresh_record_goal_controls(self, *_):
        if not hasattr(self, "combo_record_goal"):
            return
        policy = str(self.combo_record_goal.currentData() or "count")
        self.spin_01_threshold.setEnabled(policy in {"count", "either"})
        self.spin_message_coverage_threshold.setEnabled(
            policy in {"coverage", "coverage_periodic", "either"}
        )

    def _refresh_top_config_summary(self, *_):
        if not hasattr(self, "lbl_record_port_summary"):
            return
        self.lbl_record_port_summary.setText(
            f"● 录制 {self.spin_1081.value()} · 实时采集"
        )
        self.lbl_replay_port_summary.setText(
            f"● 重放 {self.spin_1080.value()} · 账号鉴权"
        )
        if self.cb_ext.isChecked():
            target = f"{self.edit_ext_ip.text().strip() or '未填写'}:{self.spin_ext_port.value()}"
            self.lbl_ext_proxy_summary.setText(
                f"● 已启用 · 新连接经 SOCKS5 {target} 转发"
            )
            self.lbl_ext_proxy_summary.setStyleSheet(
                "background:#ecfdf5;color:#047857;border-radius:4px;padding:5px 8px;font-size:11px;"
            )
        else:
            self.lbl_ext_proxy_summary.setText("○ 未启用 · 当前新连接直接访问目标")
            self.lbl_ext_proxy_summary.setStyleSheet(
                "background:#f9fafb;color:#6b7280;border-radius:4px;padding:5px 8px;font-size:11px;"
            )

    def _on_config_save(self):
        self._save_config_from_ui()
        self.lbl_config_save_status.setText("已保存")
        QTimer.singleShot(2500, lambda: self.lbl_config_save_status.setText(""))

    def _on_config_reset(self):
        keys = (
            "replenish_01_mode",
            "full_rebuild_01_mode",
            "rebuild_controls_v2",
            "rebuild_controls_v3",
            "rebuild_player_8007_enabled",
            "rebuild_player_800A_enabled",
            "rebuild_player_800C_enabled",
            "rebuild_player_800D_enabled",
            "rebuild_player_800F_enabled",
            "rebuild_player_8023_enabled",
            "rebuild_player_8024_enabled",
            "rebuild_player_802C_enabled",
            "rebuild_central9_enabled",
            "rebuild_player_base_enabled",
            "rebuild_match_events_enabled",
            "rebuild_scan_waves_enabled",
            "rebuild_central9_only",
            "rebuild_strong_profile",
            "rebuild_match_events",
            "rebuild_scan_waves",
            "hold_01_after_threshold",
            "detail_01_log",
            "auto_disconnect_01_threshold",
            "auto_disconnect_01_policy",
            "auto_disconnect_message_coverage_threshold",
            "detail_01_log_users",
            "ai_log_periodic_full_every",
            "ai_log_anomaly_context_before",
            "ai_log_anomaly_context_after",
            "record_idle_timeout",
            "replay_idle_timeout",
            "hold_01_keepalive_sec",
            "ai_log_retention_days",
            "ai_log_max_gb",
            "type9_device_mode",
        )
        app_config.reset_keys(keys)
        app_config.save()
        self._load_config_to_ui()
        self.lbl_config_save_status.setText("已恢复本页默认")
        QTimer.singleShot(2500, lambda: self.lbl_config_save_status.setText(""))

    @staticmethod
    def _open_directory(path: str) -> bool:
        os.makedirs(path, exist_ok=True)
        return bool(QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path))))

    def _on_config_open_dir(self):
        if not self._open_directory(DATA_DIR):
            QMessageBox.warning(self, "配置目录", f"目录打开异常：\n{DATA_DIR}")

    def _on_config_open_ai_log(self):
        root = os.path.join(DATA_DIR, "AI日志")
        os.makedirs(root, exist_ok=True)
        runs = sorted(
            (
                os.path.join(root, name)
                for name in os.listdir(root)
                if name.startswith("run_")
                and os.path.isdir(os.path.join(root, name))
            ),
            reverse=True,
        )
        target = runs[0] if runs else root
        if not self._open_directory(target):
            QMessageBox.warning(self, "AI日志", f"目录打开异常：\n{target}")

    def _on_config_clear_ai_log(self):
        root = os.path.join(DATA_DIR, "AI日志")
        answer = QMessageBox.question(
            self,
            "清空AI日志",
            "将删除AI日志目录中的全部历史数据。\n"
            "玩家录制池和配置保持原状。\n\n"
            f"目录：{root}\n\n继续清空？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        from core.traffic_session_log import TrafficSessionLog

        try:
            result = TrafficSessionLog.clear_ai_logs_and_rotate(
                start_fresh_run=bool(engine.running)
            )
        except OSError as exc:
            QMessageBox.warning(self, "清空AI日志", f"清理异常：\n{exc}")
            return
        removed = int(result.get("removed_count") or 0)
        reclaimed_mb = float(result.get("reclaimed_bytes") or 0) / (1024 * 1024)
        errors = list(result.get("errors") or [])
        if result.get("fresh_run_started"):
            status = "已清空并建立全新AI日志run"
        else:
            status = "已清空；代理启动时建立新run"
        self.lbl_config_save_status.setText(status)
        QTimer.singleShot(4000, lambda: self.lbl_config_save_status.setText(""))
        self._audit_control(
            "ai_logs_cleared",
            source="config",
            details={
                "removed_count": removed,
                "reclaimed_bytes": int(result.get("reclaimed_bytes") or 0),
                "fresh_run_started": bool(result.get("fresh_run_started")),
                "new_run_id": str(result.get("new_run_id") or ""),
                "errors": errors,
            },
        )
        message = (
            f"已清理 {removed} 项，共 {reclaimed_mb:.2f} MB。\n{status}。"
        )
        if errors:
            message += f"\n另有 {len(errors)} 项清理异常，已写入操作审计。"
        QMessageBox.information(self, "清空AI日志", message)

    def _on_config_export(self):
        default_name = f"dfm_config_{time.strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "导出当前配置",
            os.path.join(DATA_DIR, default_name),
            "JSON 文件 (*.json);;所有文件 (*)",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                app_config.snapshot(),
                handle,
                ensure_ascii=False,
                indent=2,
            )
        self.lbl_config_save_status.setText("已导出")
        QTimer.singleShot(2500, lambda: self.lbl_config_save_status.setText(""))

    # ─── 槽 ─────────────────────────────────
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
        _event(
            "INFO",
            "Engine",
            f"正在启动代理  录制端口={cfg['port_1081']}  重放端口={cfg['port_1080']}  "
            "设备模式=继承重放设备",
        )
        engine.start(cfg)
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_block_3366.blockSignals(True)
        self.btn_block_3366.setChecked(False)
        self.btn_block_3366.blockSignals(False)
        self.btn_block_3366.setEnabled(True)
        self._set_3366_block_button_style(False)
        engine.set_3366_block(False)
        
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
            f"重放:{cfg['port_1080']}(鉴权 {len(cfg['users_replay'])} 账号)  "
            f"设备:{device_mode_text}")
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
        self.btn_block_3366.blockSignals(True)
        self.btn_block_3366.setChecked(False)
        self.btn_block_3366.blockSignals(False)
        self.btn_block_3366.setEnabled(False)
        self._set_3366_block_button_style(False)
        # 恢复默认红色
        self.btn_stop.setStyleSheet("QPushButton{background:#c0392b;color:white;font-weight:bold;border-radius:4px}"
                                    "QPushButton:disabled{background:#555;}")
        self.spin_1080.setEnabled(True)
        self.spin_1081.setEnabled(True)
        self.lbl_status.setText("已停止")

    def _set_3366_block_button_style(self, enabled: bool) -> None:
        if enabled:
            self.btn_block_3366.setText("✓ 恢复3366")
            self.btn_block_3366.setStyleSheet(
                "QPushButton{background:#7c3aed;color:white;font-weight:bold;"
                "border:none;border-radius:6px;}"
                "QPushButton:hover{background:#6d28d9;}"
            )
        else:
            self.btn_block_3366.setText("⛔ 阻断3366")
            self.btn_block_3366.setStyleSheet(
                "QPushButton{background:#f59e0b;color:#111827;font-weight:bold;"
                "border:none;border-radius:6px;}"
                "QPushButton:hover{background:#d97706;}"
                "QPushButton:disabled{background:#d1d5db;color:#9ca3af;}"
            )

    def _on_toggle_3366_block(self, checked: bool) -> None:
        engine.set_3366_block(checked)
        self._set_3366_block_button_style(checked)
        if checked:
            self.lbl_status.setText("实验模式：录制/重放3366已阻断，01通道继续")
            _event(
                "BLOCK",
                "Engine",
                "用户开启录制/重放3366阻断：现有连接立即关闭，新3366连接拒绝，01继续",
            )
        else:
            self.lbl_status.setText("录制/重放3366已恢复；01通道保持运行")
            _event("INFO", "Engine", "用户恢复录制/重放3366新连接")

    def _on_threshold_3366_block(self, client_ip: str, n01: int, thresh: int) -> None:
        hold = "，01上行只收录" if app_config.get("hold_01_after_threshold") else ""
        self.lbl_status.setText(
            f"01已达{n01}（阈值{thresh}），录制口3366已阻断{hold}，重放3366继续  [{client_ip}]"
        )

    def _on_recording_goal_3366_block(
        self, client_ip: str, reason: str, progress: str
    ) -> None:
        hold = "，01上行只收录" if app_config.get("hold_01_after_threshold") else ""
        self.lbl_status.setText(
            f"录制目标已达成（{reason}；{progress}），同IP录制口3366已阻断"
            f"{hold}，重放3366继续  [{client_ip}]"
        )

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
                                    d["note"], d.get("allow_multi", False), d.get("perm", "both"),
                                    d.get("record_role", "player")):
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
        checked_rows = []
        for row in range(self.user_table.rowCount()):
            selector = self.user_table.item(row, 0)
            if selector and selector.checkState() == Qt.Checked:
                checked_rows.append(row)
        # 兼容单行直接选中后点击删除：无需先打勾也可以删除当前行。
        if not checked_rows and self.user_table.currentRow() >= 0:
            checked_rows = [self.user_table.currentRow()]
        if not checked_rows:
            return
        usernames = [
            self.user_table.item(row, 1).text()
            for row in checked_rows
            if self.user_table.item(row, 1)
        ]
        if not usernames:
            return
        preview = "、".join(usernames)
        if QMessageBox.question(
            self, "确认删除", f"删除选中的 {len(usernames)} 个用户？\n{preview}"
        ) == QMessageBox.Yes:
            for uname in usernames:
                user_manager.remove(uname)
            self._refresh_user_table()
            _event("INFO", "UserMgr", f"批量删除用户 [{preview}]")

    def _on_user_table_double_click(self, row: int, col: int):
        """双击多开列，快速切换对应属性。"""
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
        if hasattr(self, "edit_detail_01_users"):
            self.edit_detail_01_users.setOptions(
                [
                    str(user.get("username") or "").strip()
                    for user in user_manager.all()
                    if str(user.get("username") or "").strip()
                ],
                self.edit_detail_01_users.selectedValues(),
            )
        self.user_table.setRowCount(0)
        today = date.today().isoformat()
        for u in user_manager.all():
            row = self.user_table.rowCount()
            self.user_table.insertRow(row)
            selector = QTableWidgetItem("")
            selector.setFlags(
                selector.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled
            )
            selector.setCheckState(Qt.Unchecked)
            selector.setTextAlignment(Qt.AlignCenter)
            self.user_table.setItem(row, 0, selector)
            exp = u.get("expire", "never")
            expired = exp != "never" and exp < today
            status  = "⚠ 已过期" if expired else "✅ 有效"
            allow_multi = u.get("allow_multi", False)
            multi_text  = "✅ 允许" if allow_multi else "🔒 禁止"
            perm = (u.get("perm") or "both").lower()
            perm_text = "录制+重放" if perm == "both" else ("仅录制" if perm == "record" else "仅重放")
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
        
        rec_id = self._ip_rec_game_id.get(ip, "")
        rep_id = self._ip_rep_game_id.get(ip, "")
        lookup = build_ace_identifier_lookup(app_config)

        if rec_cnt > 0 and rep_cnt > 0:
            if rec_id and rep_id and rec_id == rep_id:
                display_mode = "实时重放"
                mode_color = "#4fc3f7"
                display_id, id_tip = self._display_account_game_cell(rec_id, ip, lookup)
            else:
                # 录制和重放的 ID 不同（例如：录制新号，重放老号），或者其中一方还没获取到 ID
                # 这种情况我们定义为"普通重放"（或者你想更明确叫"多开模式"）
                display_mode = "普通重放"
                mode_color = "#4fc3f7"
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
            display_mode = "录制"
            mode_color = ""
            display_id, id_tip = (
                self._display_account_game_cell(rec_id, ip, lookup)
                if rec_id
                else self._display_account_game_cell("", ip, lookup)
            )
        elif rep_cnt > 0:
            # 跨IP实时重放：本IP只有重放连接，但其游戏账号正被另一个IP活跃录制
            if rep_id and recording_pool.is_game_id_actively_recording(rep_id):
                display_mode = "实时重放"
                mode_color = "#4fc3f7"
            else:
                display_mode = REPLAY_PHASE_FIRST
                mode_color = "#66bb6a"
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

        # 重放列只保留首次重放 / 续连重放。绑定后先标首次，
        # 首个 Live 序号确认续连后才升格。
        replay_phase = self._ip_replay_phase.get(ip, "")
        if rec_cnt == 0 and rep_cnt > 0:
            if replay_phase == REPLAY_PHASE_CONTINUE:
                display_mode = REPLAY_PHASE_CONTINUE
                mode_color = "#ab47bc"
            elif display_mode != "实时重放":
                display_mode = REPLAY_PHASE_FIRST
                mode_color = "#66bb6a"

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

    # ─── 连接表（按 IP 分组）────────────────
    def _on_conn_added(self, conn_id: str, src: str, dst: str, user: str, actual_mode: str = ""):
        ip = src.split(":")[0]
        
        # 判断如果是 ACE 或相关端口的特殊处理标识
        is_3366 = "3366" in dst or "0x33" in dst # 如果你需要精确判断3366的特征，这里可以根据dst目标端口进行适配判断，目前这里做通用设计
        
        if actual_mode == "record":
            mode = "录制"
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
        
        if mode == "录制":
            self._ip_rec_active[ip] = self._ip_rec_active.get(ip, 0) + 1
        else:
            self._ip_rep_active[ip] = self._ip_rep_active.get(ip, 0) + 1

        # 从空闲变为活跃时记录本轮上线起始时间
        if prev_active == 0:
            self._ip_online_since[ip] = datetime.now()
            # 新一轮连接先清掉上一轮阶段标记，待首个 Live 报告重新确认。
            self._ip_replay_phase.pop(ip, None)
        row = self._ip_rows[ip]
        self._set_cell(row, 0, ip)
        self._set_cell(row, 1, dst)
        self._set_cell(row, 2, user)
        
        display_mode, rep_cnt = self._update_row_mode_and_id(ip, row)
        
        self._set_cell(row, 5, str(self._ip_total[ip]))
        self._set_cell(row, 6, str(self._ip_active[ip]))
        # 重放进度列：纯录制模式清空缓存并显示 —，重放/实时重放模式保留或恢复缓存
        if display_mode == "录制":
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
        
        if mode == "录制":
            self._ip_rec_active[ip] = max(0, self._ip_rec_active.get(ip, 1) - 1)
        else:
            self._ip_rep_active[ip] = max(0, self._ip_rep_active.get(ip, 1) - 1)
            
        row = self._ip_rows.get(ip)
        if row is None or row >= self.conn_table.rowCount():
            return
            
        display_mode, rep_cnt = self._update_row_mode_and_id(ip, row)

        # 切回纯录制模式时清空重放进度缓存和进度列
        if display_mode == "录制" and rep_cnt == 0:
            self._ip_replay_progress.pop(ip, None)
            self._ip_replay_progress_detail.pop(ip, None)
            self._set_cell(row, 7, "—", color="#666666")

        active = self._ip_active[ip]
        self._set_cell(row, 6, str(active))
        if active == 0:
            self._set_cell(row, 8, "○ 空闲 刚刚", color="#666666")

    def _set_cell(self, row: int, col: int, text: str, color: str = "", tooltip: str | None = None):
        item = self.conn_table.item(row, col)
        if item is None:
            item = QTableWidgetItem(text)
            item.setTextAlignment(Qt.AlignCenter)
            self.conn_table.setItem(row, col, item)
        else:
            item.setText(text)
        if color:
            item.setForeground(QColor(color))
        if tooltip is not None:
            item.setToolTip(tooltip)

    # ─── 录制管理 Tab 槽 ─────────────────────
    @staticmethod
    def _device_identity_ui(identity: dict) -> tuple[str, str, str]:
        """返回录制管理设备列的显示文本、完整提示与颜色。"""
        identity = dict(identity or {})
        context = dict(identity.get("context") or {})
        status = str(identity.get("status") or "pending")
        model = str(
            context.get("model") or context.get("hardware_model") or ""
        )
        system = str(context.get("system_version") or "")
        idfv = str(context.get("device_idfv") or "")
        app_version = str(context.get("app_version") or "")
        fingerprint = str(identity.get("fingerprint_sha256") or "")
        short = str(identity.get("fingerprint_short") or "")
        if status == "multiple":
            text = f"⚠ 多设备({int(identity.get('device_count') or 0)})"
            color = "#dc2626"
        elif status == "complete":
            text = f"{model or '未知型号'} / {system or '?'} / {short}"
            color = "#059669"
        elif status == "partial":
            text = f"{model or '识别中'} / {system or '?'} / 等待IDFV"
            color = "#d97706"
        else:
            text = "等待设备特征"
            color = "#64748b"
        tooltip = (
            f"状态：{status}\n"
            f"model：{model or '-'}\n"
            f"iDevHwModel：{context.get('hardware_model') or '-'}\n"
            f"iDevSysVer：{system or '-'}\n"
            f"iDevIDFV：{idfv or '-'}\n"
            f"app_version：{app_version or '-'}\n"
            f"设备指纹SHA256：{fingerprint or '-'}\n"
            f"换账号设备匹配：{'已就绪' if identity.get('reuse_ready') else '等待完整特征'}\n"
            "模板可用度另看80xx覆盖率与周期就绪"
        )
        if status == "multiple":
            profiles = []
            for index, row in enumerate(identity.get("contexts") or [], 1):
                row = dict(row or {})
                profiles.append(
                    f"设备{index}："
                    f"{row.get('model') or row.get('hardware_model') or '-'} / "
                    f"{row.get('system_version') or '-'} / "
                    f"{row.get('device_idfv') or '-'}"
                )
            if profiles:
                tooltip += "\n\n" + "\n".join(profiles)
        return text, tooltip, color

    def _on_record_updated(self):
        """录制池结构变化时全量刷新会话列表（保留当前选中 游戏用户ID）"""
        sessions = recording_pool.get_all_sessions()
        cur_row = self.rec_session_table.currentRow()
        cur_game_id = ""
        if cur_row >= 0:
            it = self.rec_session_table.item(cur_row, 1)
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
            coverage = s.get("message_coverage") or {}
            coverage_pct = float(
                coverage.get("priority_coverage_percent") or 0.0
            )
            coverage_item = QTableWidgetItem(f"{coverage_pct:.1f}%")
            coverage_item.setTextAlignment(Qt.AlignCenter)
            coverage_item.setToolTip(
                f"80xx已见 {int(coverage.get('seen_priority_count') or 0)} / "
                f"{int(coverage.get('priority_total') or len(DFM_REPLAY_80XX_MESSAGE_IDS))}；"
                f"8004子型 {int(coverage.get('subtype_8004_seen_count') or 0)}/"
                f"{int(coverage.get('subtype_8004_total') or 9)}；"
                f"全量已知覆盖 {float(coverage.get('coverage_percent') or 0.0):.1f}%"
            )
            coverage_item.setForeground(
                QColor("#059669" if coverage_pct >= 100.0 else "#d97706")
            )
            periodic_ready = int(coverage.get("periodic_ready_count") or 0)
            periodic_total = int(coverage.get("periodic_total") or 7)
            periodic_item = QTableWidgetItem(
                f"{periodic_ready}/{periodic_total}"
            )
            periodic_item.setTextAlignment(Qt.AlignCenter)
            periodic_item.setToolTip(
                f"8004子型 {int(coverage.get('subtype_8004_seen_count') or 0)}/"
                f"{int(coverage.get('subtype_8004_total') or 9)}；"
                "8007/800D/802C需两个相差600-slot的连续样本；"
                "800A按当前模板（稀疏900或三簇一致间隔）才就绪，"
                "800F需末两档差900；"
                "8027/8029短波尾巴59或长波递减且见到第二波开扫；"
                f"当前录制完整度 "
                f"{float(coverage.get('recording_completion_percent') or 0.0):.1f}%"
            )
            periodic_item.setForeground(
                QColor("#059669" if periodic_ready >= periodic_total else "#d97706")
            )
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
            type_text = "● 玩家录制"
            type_item = QTableWidgetItem(type_text)
            type_item.setTextAlignment(Qt.AlignCenter)
            type_item.setData(Qt.UserRole, str(s.get("batch_id") or ""))
            owner_item = QTableWidgetItem(str(s.get("owner_username") or "—"))
            owner_item.setTextAlignment(Qt.AlignCenter)
            device_text, device_tip, device_color = self._device_identity_ui(
                s.get("device_identity") or {}
            )
            device_item = QTableWidgetItem(device_text)
            device_item.setTextAlignment(Qt.AlignCenter)
            device_item.setToolTip(device_tip)
            device_item.setForeground(QColor(device_color))
            st_item = QTableWidgetItem(status)
            st_item.setTextAlignment(Qt.AlignCenter)

            if s.get("active"):
                for item in (type_item, gid_item, owner_item, n01_item, coverage_item, periodic_item, n3366_item, ip_item, last_item, st_item):
                    item.setForeground(QColor("#ff6b6b"))

            self.rec_session_table.setItem(i, 0, type_item)
            self.rec_session_table.setItem(i, 1, gid_item)
            self.rec_session_table.setItem(i, 2, owner_item)
            self.rec_session_table.setItem(i, 3, device_item)
            self.rec_session_table.setItem(i, 4, n01_item)
            self.rec_session_table.setItem(i, 5, coverage_item)
            self.rec_session_table.setItem(i, 6, periodic_item)
            self.rec_session_table.setItem(i, 7, n3366_item)
            self.rec_session_table.setItem(i, 8, ip_item)
            self.rec_session_table.setItem(i, 9, last_item)
            self.rec_session_table.setItem(i, 10, st_item)
            # 详情按钮
            btn_detail = QPushButton("详情")
            btn_detail.setFixedSize(52, 22)
            btn_detail.setStyleSheet("font-size:11px; padding:0;")
            btn_detail.clicked.connect(lambda _checked, g=gid, d=gid_display: self._on_rec_detail_btn(g, d))
            self.rec_session_table.setCellWidget(i, 11, btn_detail)
            self._rec_game_id_rows[gid] = i
            if gid == cur_game_id:
                restore_row = i

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
        coverage = recording_pool.get_message_coverage_for_game_id(gid)
        device_item = self.rec_session_table.item(row, 3)
        n01_item = self.rec_session_table.item(row, 4)
        coverage_item = self.rec_session_table.item(row, 5)
        periodic_item = self.rec_session_table.item(row, 6)
        n3366_item = self.rec_session_table.item(row, 7)
        if device_item:
            text, tooltip, color = self._device_identity_ui(
                recording_pool.get_device_identity_for_game_id(gid)
            )
            device_item.setText(text)
            device_item.setToolTip(tooltip)
            device_item.setForeground(QColor(color))
        if n01_item:
            n01_item.setText(str(n01))
        if n3366_item:
            n3366_item.setText(str(n3366))
        if coverage_item:
            coverage_pct = float(
                coverage.get("priority_coverage_percent") or 0.0
            )
            coverage_item.setText(f"{coverage_pct:.1f}%")
            coverage_item.setToolTip(
                f"80xx已见 {coverage.get('seen_priority_count', 0)} / "
                f"{coverage.get('priority_total', 0)}；"
                f"8004子型 {int(coverage.get('subtype_8004_seen_count') or 0)}/"
                f"{int(coverage.get('subtype_8004_total') or 9)}；"
                f"全量已知覆盖 {float(coverage.get('coverage_percent') or 0.0):.1f}%"
            )
        if periodic_item:
            periodic_ready = int(coverage.get("periodic_ready_count") or 0)
            periodic_total = int(coverage.get("periodic_total") or 7)
            periodic_item.setText(f"{periodic_ready}/{periodic_total}")
            periodic_item.setToolTip(
                f"8004子型 {int(coverage.get('subtype_8004_seen_count') or 0)}/"
                f"{int(coverage.get('subtype_8004_total') or 9)}；"
                "8007/800D/802C需两个相差600-slot的连续样本；"
                "800A按当前模板（稀疏900或三簇一致间隔）才就绪，"
                "800F需末两档差900；"
                "8027/8029短波尾巴59或长波递减且见到第二波开扫；"
                f"当前录制完整度 "
                f"{float(coverage.get('recording_completion_percent') or 0.0):.1f}%"
            )
        # 同步刷新最近录制时间
        last_t = recording_pool.get_last_record_at_for_game_id(gid)
        last_item = self.rec_session_table.item(row, 9)
        if last_item:
            if last_t > 0:
                last_item.setText(datetime.fromtimestamp(last_t).strftime("%m-%d %H:%M:%S"))
                last_item.setToolTip(datetime.fromtimestamp(last_t).strftime("%Y-%m-%d %H:%M:%S"))
            else:
                last_item.setText("—")

    def _on_rec_detail_btn(self, game_id: str, display: str):
        """点击详情：展开消息覆盖面板。"""
        if not game_id:
            return
        # 展开底部详情区
        self._rec_outer_splitter.setSizes([180, 340])
        self.lbl_rec_detail_title.setText(f"消息覆盖详情 — {display}")
        self._load_rec_detail(game_id)

    def _load_rec_detail(self, game_id: str):
        """加载指定 game_id 的消息目录命中、缺失与未知项。"""
        coverage = recording_pool.get_message_coverage_for_game_id(game_id)
        device_identity = recording_pool.get_device_identity_for_game_id(game_id)
        device_context = dict(device_identity.get("context") or {})
        device_text, _device_tooltip, _device_color = self._device_identity_ui(
            device_identity
        )
        counts = coverage.get("message_counts") or {}
        lengths = coverage.get("message_lengths") or {}
        seen = set(coverage.get("seen_known_ids") or [])
        periodic_by_id = {
            int(row.get("message_id")): row
            for row in (coverage.get("periodic_rows") or [])
        }
        match_event_mode = (
            "random" if self.cb_rebuild_match_events.isChecked() else "off"
        )
        self.rec_coverage_table.setRowCount(0)
        for idx, (message_id, name) in enumerate(
            sorted(
                DFM_KNOWN_MESSAGE_ID_CATALOG.items(),
                key=lambda row: (
                    0 if row[0] in DFM_REPLAY_80XX_MESSAGE_IDS else 1,
                    row[0],
                ),
            )
        ):
            self.rec_coverage_table.insertRow(idx)
            hit = message_id in seen
            is_priority = message_id in DFM_REPLAY_80XX_MESSAGE_IDS
            periodic_text = format_recording_period_status(
                message_id,
                coverage=coverage,
                match_event_mode=match_event_mode,
                periodic=periodic_by_id.get(message_id),
            )
            values = [
                (
                    "✓ 核心已见" if hit else "○ 核心缺失"
                ) if is_priority else (
                    "✓ 辅助已见" if hit else "· 辅助"
                ),
                f"{message_id:04X}",
                name,
                str(int(counts.get(message_id, 0))),
                ", ".join(str(v) for v in lengths.get(message_id, [])) or "—",
                periodic_text,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col != 2:
                    item.setTextAlignment(Qt.AlignCenter)
                item.setForeground(QColor(
                    "#059669" if hit and is_priority
                    else "#d97706" if is_priority
                    else "#64748b" if hit
                    else "#cbd5e1"
                ))
                self.rec_coverage_table.setItem(idx, col, item)

        pct = float(coverage.get("priority_coverage_percent") or 0.0)
        seen_count = int(coverage.get("seen_priority_count") or 0)
        known_total = int(coverage.get("priority_total") or 0)
        overall_pct = float(coverage.get("coverage_percent") or 0.0)
        overall_seen = int(coverage.get("seen_known_count") or 0)
        overall_total = int(coverage.get("known_total") or 0)
        periodic_ready = int(coverage.get("periodic_ready_count") or 0)
        periodic_total = int(coverage.get("periodic_total") or 0)
        subtype_8004_seen = int(
            coverage.get("subtype_8004_seen_count") or 0
        )
        subtype_8004_total = int(coverage.get("subtype_8004_total") or 0)
        completion_pct = float(
            coverage.get("recording_completion_percent") or 0.0
        )
        self.lbl_rec_coverage_summary.setText(
            f"设备 {device_text} · 80xx覆盖率 {pct:.1f}% · {seen_count}/{known_total} 个核心消息 · "
            f"8004子型 {subtype_8004_seen}/{subtype_8004_total} · "
            f"周期就绪 {periodic_ready}/{periodic_total} · "
            f"录制完整度 {completion_pct:.1f}% · "
            f"解码报告 {int(coverage.get('decoded_reports') or 0)} · "
            f"解码失败 {int(coverage.get('decode_failures') or 0)}"
        )
        missing = coverage.get("missing_priority_ids") or []
        unknown = coverage.get("unknown_ids") or []
        missing_text = "、".join(f"{mid:04X}" for mid in missing) or "无（已达到100%）"
        unknown_text = "、".join(f"{mid:04X}" for mid in unknown) or "无"
        missing_8004 = coverage.get("subtype_8004_missing") or []
        missing_8004_text = (
            "、".join(f"{int(value):08X}" for value in missing_8004)
            or "无（已9/9）"
        )
        periodic_lines = []
        for row in coverage.get("periodic_rows") or []:
            message_id = int(row.get("message_id") or 0)
            if str(row.get("kind") or "") == "scan_wave":
                status = str(row.get("status") or "waiting_wave1")
                if row.get("ready"):
                    period_s = row.get("period_seconds")
                    status_text = (
                        f"就绪，间隔{float(period_s):.0f}s"
                        if period_s
                        else "就绪"
                    )
                elif status == "waiting_wave2":
                    status_text = "等待第二波开扫"
                elif status == "waiting_8029":
                    status_text = "等待配套8029"
                elif status == "period_too_short":
                    status_text = "间隔过短"
                else:
                    status_text = "等待完整第一波"
                periodic_lines.append(f"{message_id:04X}：{status_text}")
                continue
            slots = list(row.get("slots") or [])
            slot_text = ",".join(str(value) for value in slots[-6:]) or "未见"
            if row.get("ready"):
                if (
                    message_id == 0x800A
                    and str(row.get("morphology") or "") == "cluster_30"
                ):
                    status_text = (
                        f"就绪，簇间隔{int(row.get('period') or 0)}"
                    )
                else:
                    status_text = "就绪"
            elif (
                message_id == 0x800A
                and str(row.get("status") or "")
                and str(row.get("status") or "") != "ready"
            ):
                status_text = str(row.get("status"))
            elif len(slots) < 2:
                status_text = "等待第2个周期样本"
            else:
                status_text = (
                    f"末次间隔{row.get('last_interval')}，"
                    f"预期{int(row.get('period') or 0)}"
                )
            periodic_lines.append(
                f"{message_id:04X}：{status_text}；slots={slot_text}"
            )
        periodic_text = "\n".join(periodic_lines) or "无周期项"
        self.rec_coverage_notes.setPlainText(
            "设备画像\n"
            "────────────────────────\n"
            f"model：{device_context.get('model') or '-'}\n"
            f"iDevHwModel：{device_context.get('hardware_model') or '-'}\n"
            f"iDevSysVer：{device_context.get('system_version') or '-'}\n"
            f"iDevIDFV：{device_context.get('device_idfv') or '-'}\n"
            f"app_version：{device_context.get('app_version') or '-'}\n"
            f"设备指纹SHA256：{device_identity.get('fingerprint_sha256') or '-'}\n"
            f"换账号设备匹配：{'已就绪' if device_identity.get('reuse_ready') else '等待完整特征'}\n"
            "模板可用度：结合下方80xx覆盖率与周期就绪判断\n\n"
            "录制完成判定\n"
            "────────────────────────\n"
            f"80xx核心覆盖：{seen_count}/{known_total}（{pct:.1f}%）\n"
            f"缺失80xx：{missing_text}\n\n"
            f"8004子型：{subtype_8004_seen}/{subtype_8004_total}\n"
            f"缺失8004子型：{missing_8004_text}\n\n"
            f"周期就绪：{periodic_ready}/{periodic_total}\n"
            f"{periodic_text}\n\n"
            f"综合录制完整度：{completion_pct:.1f}%\n"
            "综合完整度=20个其他核心ID＋8004的9个子型＋7个周期就绪项。\n\n"
            f"其他已知消息：{overall_seen}/{overall_total}（{overall_pct:.1f}%）\n"
            "其他消息用于长时间录制、版本变化和调试分析，不参与自动结束。\n\n"
            f"新发现/未知ID：{unknown_text}\n\n"
            "说明：主覆盖率按21种80xx去重计算；同一ID重复出现只增加次数。"
            "需要持续调试时，在配置中选择“关闭自动结束（持续录制）”。"
        )

    def _on_rec_session_selected(self, current, _previous):
        """选中一条录制会话（键盘/鼠标选行），不自动展开详情，由"详情"按钮控制"""
        pass

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

    def _on_conn_replay_phase(self, client_ip: str, phase: str):
        """显示本次重放是首次建立，还是断线后的语义续连。"""
        phase = (phase or "").strip()
        if phase not in {REPLAY_PHASE_FIRST, REPLAY_PHASE_CONTINUE}:
            return
        self._ip_replay_phase[client_ip] = phase
        row = self._ip_rows.get(client_ip)
        if row is None:
            return
        self._update_row_mode_and_id(client_ip, row)

    def _on_conn_game_id_update(self, client_ip: str, game_id: str, mode: str):
        """更新连接表"游戏 ID"列"""
        if mode == "录制":
            self._ip_rec_game_id[client_ip] = game_id
        else:
            self._ip_rep_game_id[client_ip] = game_id
        
        row = self._ip_rows.get(client_ip)
        if row is not None:
            self._update_row_mode_and_id(client_ip, row)

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
        """每 60 秒：刷新在线/空闲时长，并清理 30 分钟无活动的连接表行。"""
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
            self._account_game.pop(account, None)
            dlg = self._dl_intercept_detail_dialogs.pop(account, None)
            if dlg:
                dlg.close()

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
        """格式化累计重放进度；超过池总数后继续累计，不再折算循环轮次。"""
        if total01 <= 0 and total33 <= 0:
            # 空池/游戏ID未命中时仍统计实际经过的01报告数。分母用“-”
            # 明确表示没有可匹配的录制总数，避免把实时处理误看成停住。
            return f"{cur01}/-" if cur01 > 0 else "—"
        parts = []
        if total01 > 0:
            parts.append(f"01:{cur01}/{total01}")
        if total33 > 0 or cur01_fb > 0:
            p33 = []
            if total09 > 0:
                p33.append(f"09 {cur09}/{total09}")
            if total21 > 0:
                p33.append(f"21 {cur21}/{total21}")
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
        """导出统一玩家设备模板池。"""
        default_name = f"dfm_device_recordings_{time.strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出录制数据", os.path.join("C:\\PyProxyApp", default_name),
            "JSON 文件 (*.json);;所有文件 (*)"
        )
        if not path:
            return
        ok, msg = recording_pool.export_to_file(path, export_scope="player")
        QMessageBox.information(self, "导出结果", msg) if ok else QMessageBox.warning(self, "导出失败", msg)

    def _on_rec_import(self):
        """从 JSON 文件导入录制数据"""
        path, _ = QFileDialog.getOpenFileName(
            self, "导入录制数据", "C:\\PyProxyApp",
            "JSON 文件 (*.json);;所有文件 (*)"
        )
        if not path:
            return
        inspected, info = recording_pool.inspect_import_file(path)
        if not inspected:
            QMessageBox.warning(self, "导入检查失败", str(info))
            return
        counts = info.get("counts") or {}
        scope_names = {
            "all": "完整备份",
            "player": "玩家录制",
            "official_published": "玩家录制包",
            "legacy_all": "旧版录制包",
        }
        preview = (
            f"格式：v{info.get('version')} / "
            f"{scope_names.get(info.get('export_scope'), info.get('export_scope'))}\n"
            f"会话：{counts.get('sessions', 0)}\n"
            f"玩家：{counts.get('player_sessions', 0)}\n"
            f"玩家录制：{counts.get('player_sessions', 0)}\n\n"
            "是否覆盖相同会话？\n"
            "选择“否”将合并新数据并跳过重复项。"
        )
        overwrite = QMessageBox.question(
            self, "导入预览", preview,
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
            recording_pool.save_snapshot()
            recording_pool.save_official_templates()
            log_bus.record_updated.emit()
            self.rec_coverage_table.setRowCount(0)
            self.rec_coverage_notes.clear()
            self.lbl_rec_coverage_summary.setText(
                f"80xx覆盖率 0.0% · 0/{len(DFM_REPLAY_80XX_MESSAGE_IDS)} 个核心消息"
            )

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
        recording_pool.save_snapshot()
        recording_pool.save_official_templates()
        engine.stop()
        event.accept()


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
