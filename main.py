import sys
import os
import asyncio

# Fix sys.path for PyInstaller environment
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    if sys._MEIPASS not in sys.path:
        sys.path.insert(0, sys._MEIPASS)

from PySide6.QtWidgets import QApplication

from core.config import app_config
from core.managers import user_manager
from core.events import log_bus
from core.server import Socks5Server
from core.traffic_session_log import TrafficSessionLog
from ui.views import MainWindow

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

        if app_config.get("clear_traffic_logs_on_proxy_start", True):
            TrafficSessionLog.clear_previous_run_dirs_and_reset_state()
        else:
            TrafficSessionLog.reset_session_state_only()

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
