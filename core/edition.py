"""UAMProxy 暗区突围专项版产品边界。

Type9 / UI 框架沿用本地实现；01 通道按暗区 `094e` / `0000094E` 识别。
三角洲 0a92 插件路径保留源码，不作为本专版 01 识别入口。
"""

APP_EDITION = "uam"
APP_DISPLAY_NAME = "UAMProxy 暗区突围专项版"
DFM_PLUGIN_GAME_IDS = frozenset({"0a92"})
UAM_GAME_IDS = frozenset({"094e"})
LEGACY_GAME_RUNTIME_ENABLED = False
LEGACY_GAME_UI_VISIBLE = False
# 本地文件重放属于通用代理能力，专版继续启用。
LEGACY_LOCAL_MAP_RUNTIME_ENABLED = True
# 暗区 3366 走切帧/1002 取钥/4013 解密，并写入 AI 日志。
UAM_3366_PASSTHROUGH_ONLY = False
DFM_3366_PASSTHROUGH_ONLY = UAM_3366_PASSTHROUGH_ONLY
TYPE9_LEARNING_MODE = "118-tiered-pass-live"


def type9_legacy_builtin_intercepts_enabled() -> bool:
    """三角洲遗留：tfp_called 链路与 mtxdfm 黑名单 empty_2000。UAM 专版关闭。"""
    return str(APP_EDITION or "").strip().lower() != "uam"


def type9_uam_content_blacklist_enabled() -> bool:
    """暗区：0x8418 进程上报命中黑名单时替换为 0x8306 固定叶。"""
    return str(APP_EDITION or "").strip().lower() == "uam"


def is_dfm_plugin_game(game_id: object) -> bool:
    return str(game_id or "").strip().lower() in DFM_PLUGIN_GAME_IDS


def is_uam_game(game_id: object) -> bool:
    text = str(game_id or "").strip().lower().replace("0x", "")
    if text in UAM_GAME_IDS:
        return True
    return text.endswith("094e")
