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
# v1.124：支持继承重放设备/替换录制设备两种连接级模式；
# tfp_called对全部Type9叶子扫描，优先使用干净模板，无模板时删除已确认
# 结构字段，未知布局最终等长清零，并记录规则ID与替换统计。
# 暗区3366走切帧/1002取钥/4013解密，并写入AI日志；三角洲透传只留给DFM专版。
DFM_3366_PASSTHROUGH_ONLY = False
TYPE9_LEARNING_MODE = "118-tiered-pass-live"


def is_dfm_plugin_game(game_id: object) -> bool:
    return str(game_id or "").strip().lower() in DFM_PLUGIN_GAME_IDS


def is_uam_game(game_id: object) -> bool:
    text = str(game_id or "").strip().lower().replace("0x", "")
    if text in UAM_GAME_IDS:
        return True
    return text.endswith("094e")
