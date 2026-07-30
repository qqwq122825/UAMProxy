"""
UAMProxy 暗区专项精简打包脚本（Slim Build）
=====================================
通过手写 .spec 文件精确控制打包内容，目标体积 40-70 MB。

核心思路：
  1. 只打入实际用到的 Qt DLL（Core/Gui/Widgets + shiboken6）
  2. 只打入 Windows 平台插件（qwindows.dll）和基本样式插件
  3. 彻底排除 WebEngine(192MB) / opengl32sw(19MB) / 多媒体编解码器(16MB) / Quick/Qml
  4. 排除所有用不到的 PySide6 Python 模块

用法：
    python build_slim.py
"""

import os
import sys
import re
import shutil
import subprocess
import glob

APP_NAME   = "UAMProxy"
ENTRY_FILE = "main.py"
ICON_FILE  = None  # 填 .ico 路径，如 "assets/icon.ico"

VIEWS_FILE = os.path.join(os.path.dirname(__file__), "ui", "views.py")
_VER_RE    = re.compile(r'^(APP_VERSION\s*=\s*["\'])v(\d+)\.(\d+)(["\'])', re.MULTILINE)


def bump_version() -> str:
    """读取 ui/views.py 中的 APP_VERSION，小版本号 +1 后写回，返回新版本字符串。"""
    with open(VIEWS_FILE, "r", encoding="utf-8") as f:
        src = f.read()
    m = _VER_RE.search(src)
    if not m:
        print("[WARN] 未找到 APP_VERSION，跳过版本号更新")
        return "unknown"
    major, minor = int(m.group(2)), int(m.group(3))
    new_minor = minor + 1
    new_ver   = f"v{major}.{new_minor}"
    new_line  = f'{m.group(1)}{new_ver}{m.group(4)}'
    src = _VER_RE.sub(new_line, src, count=1)
    with open(VIEWS_FILE, "w", encoding="utf-8") as f:
        f.write(src)
    return new_ver

# ──────────────────────────────────────────────────────────────
# PySide6 安装目录
# ──────────────────────────────────────────────────────────────
import PySide6 as _pyside6
PY_SIDE6_DIR = os.path.dirname(_pyside6.__file__)

def p6(rel: str) -> str:
    """返回 PySide6 目录下 rel 的绝对路径"""
    return os.path.join(PY_SIDE6_DIR, rel).replace("\\", "/")

# ──────────────────────────────────────────────────────────────
# 我们需要的最小 DLL 清单
# ──────────────────────────────────────────────────────────────
NEEDED_DLLS = [
    "Qt6Core.dll",
    "Qt6Gui.dll",
    "Qt6Widgets.dll",
    "Qt6Network.dll",      # PySide6 内部偶尔依赖
    "Qt6Svg.dll",          # 图标可能用到（可删）
    "shiboken6.cpython-313-win_amd64.pyd",  # Python-C++ 桥接
]

# 自动把 .pyd 文件也加进来（QtCore/QtGui/QtWidgets 的 Python binding）
NEEDED_PYDS = [
    "QtCore.pyd",
    "QtGui.pyd",
    "QtWidgets.pyd",
]

# ──────────────────────────────────────────────────────────────
# 需要的 Qt 插件
# ──────────────────────────────────────────────────────────────
PLUGIN_RULES = [
    # Windows 平台后端（必须）
    ("plugins/platforms/qwindows.dll",       "PySide6/Qt/plugins/platforms"),
    # Windows Vista 风格（必须，否则控件无样式）
    ("plugins/styles/qwindowsvistastyle.dll", "PySide6/Qt/plugins/styles"),
    # 图片格式（jpg/png/ico 可选）
    ("plugins/imageformats/qjpeg.dll",        "PySide6/Qt/plugins/imageformats"),
    ("plugins/imageformats/qico.dll",         "PySide6/Qt/plugins/imageformats"),
    ("plugins/imageformats/qsvg.dll",         "PySide6/Qt/plugins/imageformats"),
]

# ──────────────────────────────────────────────────────────────
# 大文件黑名单：即使被依赖分析发现也要排除
# ──────────────────────────────────────────────────────────────
EXCLUDE_DLLS = [
    "Qt6WebEngineCore.dll",   # 192 MB
    "Qt6WebEngineWidgets.dll",
    "opengl32sw.dll",         # 19 MB 软件渲染 OpenGL
    "avcodec-61.dll",         # 13 MB 多媒体编解码
    "avformat-61.dll",
    "avutil-58.dll",
    "Qt6Quick.dll",
    "Qt6QuickWidgets.dll",
    "Qt6Qml.dll",
    "Qt6QmlCompiler.dll",
    "Qt6Designer.dll",
    "Qt6DesignerComponents.dll",
    "Qt6Pdf.dll",
    "Qt6PdfWidgets.dll",
    "Qt63DCore.dll",
    "Qt63DRender.dll",
    "Qt63DExtras.dll",
    "Qt63DInput.dll",
    "Qt63DLogic.dll",
    "Qt63DAnimation.dll",
    "Qt6Charts.dll",
    "Qt6Graphs.dll",
    "Qt6DataVisualization.dll",
    "Qt6Multimedia.dll",
    "Qt6MultimediaWidgets.dll",
    "Qt6ShaderTools.dll",
    "Qt6Quick3D.dll",
    "Qt6Quick3DRuntimeRender.dll",
    "Qt6Quick3DUtils.dll",
    "Qt6QuickControls2.dll",
    "Qt6QuickControls2Impl.dll",
    "Qt6QuickDialogs2.dll",
    "Qt6QuickDialogs2QuickImpl.dll",
    "Qt6QuickLayouts.dll",
    "Qt6QuickTemplates2.dll",
    "Qt6Bluetooth.dll",
    "Qt6Location.dll",
    "Qt6Positioning.dll",
    "Qt6Nfc.dll",
    "Qt6Sensors.dll",
    "Qt6SerialPort.dll",
    "Qt6TextToSpeech.dll",
    "Qt6RemoteObjects.dll",
    "Qt6Scxml.dll",
    "Qt6StateMachine.dll",
    "Qt6Test.dll",
    "Qt6HttpServer.dll",
    "Qt6WebSockets.dll",
    "Qt6WebChannel.dll",
    "Qt6OpenGL.dll",
    "Qt6OpenGLWidgets.dll",
    "Qt6VirtualKeyboard.dll",
]

# PySide6 Python 模块排除
EXCLUDE_PY_MODULES = [
    "PySide6.Qt3DAnimation", "PySide6.Qt3DCore", "PySide6.Qt3DExtras",
    "PySide6.Qt3DInput", "PySide6.Qt3DLogic", "PySide6.Qt3DRender",
    "PySide6.QtAsyncio", "PySide6.QtAxContainer", "PySide6.QtBluetooth",
    "PySide6.QtCharts", "PySide6.QtConcurrent", "PySide6.QtDataVisualization",
    "PySide6.QtDBus", "PySide6.QtDesigner", "PySide6.QtGraphs",
    "PySide6.QtHelp", "PySide6.QtHttpServer", "PySide6.QtLocation",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets",
    "PySide6.QtNfc", "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets",
    "PySide6.QtPdf", "PySide6.QtPdfWidgets", "PySide6.QtPositioning",
    "PySide6.QtPrintSupport", "PySide6.QtQml", "PySide6.QtQuick",
    "PySide6.QtQuick3D", "PySide6.QtQuickWidgets", "PySide6.QtRemoteObjects",
    "PySide6.QtScxml", "PySide6.QtSensors", "PySide6.QtSerialBus",
    "PySide6.QtSerialPort", "PySide6.QtSql", "PySide6.QtStateMachine",
    "PySide6.QtSvg", "PySide6.QtSvgWidgets", "PySide6.QtTest",
    "PySide6.QtTextToSpeech", "PySide6.QtWebChannel", "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineQuick", "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebSockets", "PySide6.QtXml",
]


def collect_binaries():
    """收集需要的 DLL / PYD，返回 PyInstaller binaries 列表"""
    bins = []
    for dll in NEEDED_DLLS:
        full = p6(dll)
        if os.path.exists(full):
            bins.append((full, "PySide6"))
        else:
            # 尝试匹配通配（shiboken6 的 .pyd 文件名含 python 版本号）
            pattern = p6(dll.replace("313", "*"))
            matches = glob.glob(pattern)
            for m in matches:
                bins.append((m, "PySide6"))

    for pyd in NEEDED_PYDS:
        full = p6(pyd)
        if os.path.exists(full):
            bins.append((full, "PySide6"))

    for rel, dest in PLUGIN_RULES:
        full = p6(rel)
        if os.path.exists(full):
            bins.append((full, dest))
        else:
            print(f"  [WARN] 插件找不到: {rel}")
    return bins


def write_spec(bins: list, exe_name: str) -> str:
    spec_path = f"{APP_NAME}.spec"
    icon_line = f"icon={repr(ICON_FILE)}," if (ICON_FILE and os.path.exists(ICON_FILE)) else ""

    bins_repr = ",\n            ".join(repr(b) for b in bins)
    excl_mods = ",\n            ".join(repr(m) for m in EXCLUDE_PY_MODULES)
    excl_dlls = ",\n            ".join(repr(d) for d in EXCLUDE_DLLS)

    spec_content = f"""# -*- mode: python ; coding: utf-8 -*-
# Auto-generated by build_slim.py

from PyInstaller.utils.hooks import collect_data_files
import os

block_cipher = None

a = Analysis(
    ['{ENTRY_FILE}'],
    pathex=[],
    binaries=[
        {bins_repr}
    ],
    datas=[],
    hiddenimports=[
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'asyncio',
        'asyncio.runners',
        'json',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[
        {excl_mods},
        {excl_dlls},
        'matplotlib', 'numpy', 'scipy', 'pandas',
        'PIL', 'cv2', 'sklearn', 'tensorflow', 'torch',
        'tkinter', 'wx',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# ── 过滤掉大文件 DLL（即使被依赖分析拉进来也踢出去）──────────
EXCLUDE_DLL_NAMES = {{name.lower() for name in {EXCLUDE_DLLS!r}}}

def filter_bins(toc):
    kept, removed = [], []
    for name, src, kind in toc:
        fname = os.path.basename(name).lower()
        if fname in EXCLUDE_DLL_NAMES:
            removed.append(fname)
        else:
            kept.append((name, src, kind))
    if removed:
        print(f"  [slim] 排除 {{len(removed)}} 个大文件: {{removed[:5]}}...")
    return kept

a.binaries = filter_bins(a.binaries)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='{exe_name}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,           # 使用 UPX 压缩（若已安装可进一步减小体积约 20%）
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,      # 隐藏控制台
    {icon_line}
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
"""
    with open(spec_path, "w", encoding="utf-8") as f:
        f.write(spec_content)
    return spec_path


def main():
    new_ver = bump_version()
    # 版本号中 "v1.2" → 文件名用 "v1.2"，去掉不合法字符
    ver_tag  = new_ver.replace(" ", "_")
    exe_name = f"{APP_NAME}_{ver_tag}"   # e.g. UAMProxy_v1.2

    print("=" * 55)
    print(f"  UAMProxy 暗区专项打包 (Slim Build)  {new_ver}")
    print(f"  输出文件名 : {exe_name}.exe")
    print("=" * 55)

    # 只清理 build 中间产物和旧 spec，保留 dist/ 下的历史版本
    for d in ["build", f"{APP_NAME}.spec"]:
        if os.path.exists(d):
            shutil.rmtree(d) if os.path.isdir(d) else os.remove(d)
    print("[1/4] 中间产物已清理（dist/ 历史版本保留）")

    bins = collect_binaries()
    print(f"[2/4] 收集 {len(bins)} 个必要二进制文件")
    for src, _ in bins:
        name = os.path.basename(src)
        mb = os.path.getsize(src) / 1024 / 1024 if os.path.exists(src) else 0
        print(f"       + {name} ({mb:.1f} MB)")

    spec_path = write_spec(bins, exe_name)
    print(f"[3/4] 生成 spec 文件: {spec_path}")

    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--clean", spec_path],
        text=True
    )
    if result.returncode != 0:
        print("\n[ERROR] 打包失败！")
        sys.exit(1)

    exe_path = os.path.join("dist", f"{exe_name}.exe")
    if not os.path.exists(exe_path):
        print(f"\n[ERROR] 找不到产物 {exe_path}")
        sys.exit(1)

    mb = os.path.getsize(exe_path) / 1024 / 1024
    print(f"\n[4/4] 打包完成！")
    print(f"  产物路径 : {os.path.abspath(exe_path)}")
    print(f"  文件大小 : {mb:.1f} MB")
    # 列出 dist/ 下所有历史版本
    all_exes = sorted(glob.glob(os.path.join("dist", f"{APP_NAME}_v*.exe")))
    if len(all_exes) > 1:
        print(f"  历史版本 :")
        for p in all_exes:
            size = os.path.getsize(p) / 1024 / 1024
            print(f"    {os.path.basename(p)}  ({size:.1f} MB)")
    print("=" * 55)


if __name__ == "__main__":
    main()
