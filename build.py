"""
UAMProxy 暗区专项版打包脚本
==================
用法：
    python build.py

产物：
    dist/UAMProxy.exe  (单文件可执行程序，部署到服务器直接运行即可)

服务器部署建议：
    1. 直接拷贝 UAMProxy.exe 到服务器任意目录
    2. 运行：UAMProxy.exe            → 带 UI 的交互模式
             UAMProxy.exe --headless  → 无 UI 后台服务模式

注意：
    - --headless 模式下默认端口 1080(鉴权) + 1081(无鉴权)
    - 如果服务器已有 clash/v2ray 等代理占用端口，在 UI 或配置里修改端口号即可
    - 推荐用 NSSM 或 SC 将 --headless 模式注册为 Windows 服务
"""

import subprocess
import sys
import shutil
import os

APP_NAME    = "UAMProxy"
ENTRY_FILE  = "main.py"
DIST_DIR    = "dist"
BUILD_DIR   = "build"
SPEC_FILE   = f"{APP_NAME}.spec"
ICON_FILE   = None   # 如果有 .ico 文件，填路径，例如 "assets/icon.ico"

def main():
    print("=" * 50)
    print(f"  正在打包 {APP_NAME} → 单文件 EXE")
    print("=" * 50)

    # 清理旧产物
    for d in [DIST_DIR, BUILD_DIR, SPEC_FILE]:
        if os.path.exists(d):
            if os.path.isdir(d):
                shutil.rmtree(d)
            else:
                os.remove(d)
    print("[1/3] 旧产物已清理")

    # ── 实际用到的 PySide6 模块（仅这 3 个）──────────────────────────
    USED_QT = ["QtCore", "QtGui", "QtWidgets"]

    # ── 所有 PySide6 子模块（用于排除不需要的）──────────────────────
    ALL_QT_MODULES = [
        "Qt3DAnimation", "Qt3DCore", "Qt3DExtras", "Qt3DInput",
        "Qt3DLogic", "Qt3DRender", "QtAsyncio", "QtAxContainer",
        "QtBluetooth", "QtCharts", "QtConcurrent", "QtDataVisualization",
        "QtDBus", "QtDesigner", "QtGraphs", "QtHelp", "QtHttpServer",
        "QtLocation", "QtMultimedia", "QtMultimediaWidgets",
        "QtNfc", "QtOpenGL", "QtOpenGLWidgets", "QtPdf", "QtPdfWidgets",
        "QtPositioning", "QtPrintSupport", "QtQml", "QtQuick",
        "QtQuick3D", "QtQuickWidgets", "QtRemoteObjects",
        "QtScxml", "QtSensors", "QtSerialBus", "QtSerialPort",
        "QtSql", "QtStateMachine", "QtSvg", "QtSvgWidgets",
        "QtTest", "QtTextToSpeech", "QtWebChannel", "QtWebEngineCore",
        "QtWebEngineQuick", "QtWebEngineWidgets", "QtWebSockets",
        "QtXml",
    ]
    EXCLUDE_QT = [m for m in ALL_QT_MODULES if m not in USED_QT]

    # 构建 PyInstaller 命令
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",        # 单文件 EXE
        "--windowed",       # 隐藏控制台（带 UI 模式；调试时改 --console）
        f"--name={APP_NAME}",
        "--clean",
        # 只收集 Qt 平台插件 data（样式/字体/平台适配，Windows 必须）
        "--collect-data=PySide6",
        # 明确声明用到的模块
        "--hidden-import=PySide6.QtCore",
        "--hidden-import=PySide6.QtGui",
        "--hidden-import=PySide6.QtWidgets",
        "--hidden-import=asyncio",
    ]

    # 排除所有用不到的 Qt 大模块（每排除一个省几 MB ~ 几十 MB）
    for m in EXCLUDE_QT:
        cmd.append(f"--exclude-module=PySide6.{m}")

    if ICON_FILE and os.path.exists(ICON_FILE):
        cmd.append(f"--icon={ICON_FILE}")

    cmd.append(ENTRY_FILE)

    print(f"[2/3] 执行命令：{' '.join(cmd[2:])}")
    result = subprocess.run(cmd, text=True)

    if result.returncode != 0:
        print("\n[ERROR] 打包失败！请检查以上输出。")
        sys.exit(1)

    exe_path = os.path.join(DIST_DIR, f"{APP_NAME}.exe")
    if not os.path.exists(exe_path):
        print(f"\n[ERROR] 找不到产物 {exe_path}")
        sys.exit(1)

    size_mb = os.path.getsize(exe_path) / 1024 / 1024
    print(f"\n[3/3] 打包完成！")
    print(f"  产物路径 : {os.path.abspath(exe_path)}")
    print(f"  文件大小 : {size_mb:.1f} MB")
    print()
    print("  服务器部署方式：")
    print(f"    带UI模式  ：{APP_NAME}.exe")
    print(f"    无UI服务  ：{APP_NAME}.exe --headless")
    print()
    print("  如需注册为 Windows 后台服务（需安装 NSSM）：")
    print(f"    nssm install {APP_NAME} C:\\path\\to\\{APP_NAME}.exe --headless")
    print(f"    nssm start {APP_NAME}")
    print("=" * 50)


if __name__ == "__main__":
    main()
