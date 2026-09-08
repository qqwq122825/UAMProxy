import os
import json
import datetime
import traceback

# ─────────────────────────────────────────
# 路径常量
# 所有持久化数据统一存放在 C:\PyProxyApp\
# 打包为 EXE 后 BASE_DIR 是临时解压目录，必须用固定路径
# ─────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_DIR    = r"C:\PyProxyApp"          # 所有持久化文件的根目录
USERS_FILE  = os.path.join(DATA_DIR, "users.json")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

# ─────────────────────────────────────────
# 应用配置（持久化）
# ─────────────────────────────────────────
class AppConfig:
    """
    持久化界面配置到 C:\\PyProxyApp\\config.json。
    字段：
      port_record   : 录制端口（默认 1081）
      port_replay   : 重放端口（默认 1080）
      ext_enabled   : 是否启用外部代理（默认 False）
      ext_ip        : 外部代理 IP（默认 127.0.0.1）
      ext_port      : 外部代理端口（默认 8889）
    """
    _DEFAULTS = {
        "app_edition": "uam",
        "type9_learning_enabled": True,
        "type9_learning_mode": "118-tiered-pass-live",
        # v1.128.5固定inherit_live：设备字段使用当前重放端Live。
        "type9_device_mode": "inherit_live",
        "dfm_client_version": "auto",
        # v1.117 旧键继续读取，便于回看历史配置；v1.118 网络决策使用下方新键。
        "v117_unmatched_leaf_policy": "pass_live",
        "v117_leaf_prune_experiment_enabled": False,
        # v1.118：未知叶子固定以实时数据为默认；裁剪代码仅由双重实验开关触发。
        "v118_unknown_leaf_policy": "pass_live",
        "v118_leaf_prune_experiment_enabled": False,
        "port_record": 1081,
        "port_replay": 1080,
        "ext_enabled": False,
        "ext_ip":      "127.0.0.1",
        "ext_port":    8889,
        # v1.128.2两级AI日志：勾选时仅 detail_01_log_users 使用全量Hex，
        # 其他用户使用精简日志；取消勾选时所有用户都使用精简日志。
        "detail_01_log": True,
        "detail_01_log_users": "test",
        # 精简用户每N个同类事件保留一份全量样本；0表示只保留异常/新结构。
        "ai_log_periodic_full_every": 100,
        "ai_log_anomaly_context_before": 10,
        "ai_log_anomaly_context_after": 5,
        # AI日志目录自动整理；0表示停用对应限制。
        "ai_log_retention_days": 7,
        "ai_log_max_gb": 10.0,
        # 33 66：首下行 Key/IV 相对「16 字节帧头之后」的 payload 偏移（字节），未设则尝试 payload[0:16]+[16:32]
        "3366_key_offset": None,
        "3366_iv_offset": None,
        # 是否同时录制完整 33 66 原始帧（体积大；默认只录解密后含 01 0A 00 09/21 的加密区入池）
        "record_raw_3366_frames": False,
        # 旧版官方模板开关仅保留配置兼容；当前固定为玩家同设备优先、
        # 设备不匹配时按游戏ID回退。
        "dz_01_cross_account_template_enabled": False,
        "replay_length_match_tol": 300,
        "replay_len_fallback_header": 55,  # 保留子包前若干字节，从该偏移起替换到包尾
        # 33 66 游戏产品（4 字节 ID 的 8 位 hex，如 00 00 09 4E → 0000094E）
        # decrypt: 当前仅实现 "aes_cbc_4013"（40 13 载荷）；null / 省略 则只识别不解密，避免误用暗区算法
        # 01 / 3366 产品识别默认走暗区国服；三角洲 plugin_games/0a92 仍保留源码。
        "3366_products": {
            "0000094E": {
                "name": "暗区突围国服",
                "decrypt": "aes_cbc_4013",
                "needs_downlink_key": True,
            },
        },
        # 远程用户管理（浏览器）
        # 注意：开启后建议在防火墙限制来源 IP，并妥善保管 token
        "admin_enabled": True,
        "admin_bind": "0.0.0.0",
        "admin_port": 8787,
        "admin_token": "",
        # v1.128：配置目录/AI日志/run_* 为唯一默认持久分析日志，
        # 全部使用紧凑JSON/JSONL，并保留原始Hex。
        "ai_log_enabled": True,
        "ai_log_machine_only": True,
        # 保留旧键便于读取历史配置；v1.128.2起AI日志始终覆盖所有用户。
        "ai_log_user_filter": "",
        # 旧PyProxyTrafficLogs_*人类文本详单默认停止产生。
        "legacy_text_log_enabled": False,
        "traffic_session_log_enabled": True,
        "traffic_log_min_len": 10,
        # 录制端口空闲超时（秒）：连接超过此时长没有任何数据则主动断开
        # 0 = 不超时（等连接自然断开）；推荐 120~300
        "record_idle_timeout": 180,
        # 日志用户过滤：逗号分隔的用户名白名单，只有命中的用户才写流量详单
        # 留空 "" 则对所有用户记录；默认只记录 test 用户
        "traffic_log_user_filter": "test",
        "log_3366_replay_uplink_trace": True,  # 重放端口每条33上行帧+原因排查
        # 每次点击「启动代理」时删除 cwd 下全部 PyProxyTrafficLogs_* 目录并重置详单会话（不清理内存录制池）
        "clear_traffic_logs_on_proxy_start": True,
        # 连接表「账户 / 游戏」列：除 3366_products 的 8 位 hex→name 外，可为 ACE 解析出的任意标识串追加别名
        # 例: "MYGAME01": "某游戏"
        "ace_identifier_display_map": {
            "094E": "暗区突围",
            "0000094E": "暗区突围国服",
        },
        # 01 达阈值后只阻断录制口3366（与补数据开关无关），01 默认继续录制/转发
        "auto_disconnect_01_threshold": 100,
        # 自动阻断条件：count=01数量、coverage=80xx完整度、
        # coverage_periodic=完整度与周期就绪同时满足、either=任一满足、off=持续录制。
        "auto_disconnect_01_policy": "count",
        "auto_disconnect_message_coverage_threshold": 100,
        # v1.128补数据：使用内置长01周期模型，在完整Live报告后注入独立80xx报告。
        "replenish_01_mode": False,
        # v1.128.5全额重建：关闭时固定只运行中央九类；开启后按账号、型号、
        # 系统版本、IDFV判断同设备，同设备使用玩家录制时间轴补其余十二类。
        "full_rebuild_01_mode": False,
        # v1.130.12 重建内容多选。False 表示仍按旧 full_rebuild 配置解释；
        # 配置页保存一次后切换为五类独立开关。
        "rebuild_controls_v2": False,
        # v1.130.13：玩家层 8 个消息逐项开关。旧总开关迁移时仅映射
        # 800D/8024/802C，A组五项保持关闭，避免旧配置无意扩大重建范围。
        "rebuild_controls_v3": False,
        "rebuild_player_8007_enabled": False,
        "rebuild_player_800A_enabled": False,
        "rebuild_player_800C_enabled": False,
        "rebuild_player_800D_enabled": False,
        "rebuild_player_800F_enabled": False,
        "rebuild_player_8023_enabled": False,
        "rebuild_player_8024_enabled": False,
        "rebuild_player_802C_enabled": False,
        "rebuild_central9_enabled": False,
        "rebuild_player_base_enabled": False,
        "rebuild_match_events_enabled": False,
        "rebuild_scan_waves_enabled": False,
        # 补数据细分：勾选后只生成中央固定九类，不生成强检或玩家层补发。
        # 旧 v1.130.11 键，仅用于迁移。
        "rebuild_central9_only": False,
        # 强检条件层（mrpcs_i_* 文件对齐后）是否补发 8C03 / 9100。
        "rebuild_strong_profile": True,
        # Hook 后 Live 没有 802A/802B，无法知道进把。off=不补这对；
        # random=约 6 分钟大厅静默后，每隔 10～20 分钟补一对录制正文。
        "rebuild_match_events": "off",
        "match_event_min_seconds": 600,
        "match_event_max_seconds": 1200,
        "match_event_lobby_quiet_seconds": 360,
        # 8027/8029：Hook 后 Live 没有这对。off=不发；repeat_first=默认，
        # 模板有完整第一波且见到第二波开扫首帧时，按该间隔循环第一波。
        "rebuild_scan_waves": "repeat_first",
        # 旧配置键仅用于迁移v1.128.5开发版配置。
        "same_device_replenish_mode": False,
        # 阈值后 01 只收录不转发。默认 False。
        "hold_01_after_threshold": False,
        # 只收录后若 ACE 下行静默超过该秒数，用本连接最近短 08 心跳改序号后本地补给客户端
        "hold_01_keepalive_sec": 8,
        # 3366 原始数据（不解密）中若含 01 0A 00 09 或 01 0A 00 23，不发送但会记录
        "drop_3366_raw_high_entropy": False,
        # 下发拦截详情历史预存账户列表：列表内的账户无论详情弹窗是否打开都会缓存历史日志，
        # 点"📋 详情"时可回放查看替换前的记录；其他账户仅弹窗打开后才记录（节省内存）
        "dl_intercept_history_labels": ["test"],
        # 下发数据拦截：通用配置，各游戏独立开关控制是否生效
        "az_dl_intercept_enabled": False,   # 暗区突围：启用 33 下行字符串拦截
        "hok_dl_intercept_enabled": False,  # 王者荣耀：启用 33 下行字符串拦截
        "hok_33_replay_replace_enabled": False,  # 王者荣耀：启用 33 重放池替换 0A 00 09/21
        "dz_dl_intercept_enabled": False,   # 三角洲行动：启用 33 下行字符串拦截
        "dz_cmd_bl_enabled": True,          # 三角洲行动：启用命令名黑名单
        "dl_search_str": "unzipmrpcs",
        "dl_replace_str": "",       # 普通模式：替换为此字符串；留空则等长 0x00 覆盖
        # 毁掉模式：勾选后忽略替换串，只用查找串定位目标帧，然后对区间整体填充（起止由下方区间标记控制）
        "dl_destroy_mode_enabled": False,
        # 上行 33 协议：拦截含 config2/config3 的 4013 帧，置空载荷使服务端解析失败
        "ul_intercept_config23_enabled": False,
        # 3366 下行块拦截：4013 帧解密后明文前缀匹配时进行拦截
        # 与字符串替换不同：命中后不设 DONE_KEY，每帧持续检测（覆盖分片下发场景）
        # 默认特征：F802000003（5字节前缀），社交消息帧为 F802000004，不受影响
        "ace_chunk_block_enabled": False,
        "ace_chunk_block_pattern": "F802000003",
        # 块下载帧大小固定：总帧 1081B = 25B头 + 1056B密文（enc_len=1056，已在代码中写死）
        # 命中后将明文全部填充为 fill_byte 并重新加密发出（保序列，不断包）：
        #   start_marker     : 填充起始标记，Hex 字符串；留空则从明文 offset 0 开始填充
        #   start_marker_nth : 使用第几次出现（默认 1）；搜索失败则从头填充
        #   stop_marker      : 填充终止标记，UTF-8 字符串；留空则填充到明文末尾
        #   fill_byte        : 填充字节，"00"=清零，"FF"=全 FF（默认 "00"）
        # 建议：start/stop 全留空 → 整段明文清零，最彻底。
        "ace_chunk_block_start_marker": "",
        "ace_chunk_block_start_marker_nth": 1,
        "ace_chunk_block_stop_marker": "",
        "ace_chunk_block_fill_byte": "00",
        # 01 下行文件破坏（仅重放）：扫描全部01逻辑包，命中 0x08 ZIP 记录后，
        # 解密后将 ZIP 本地头 PK0304 改为 PZ0304，再重算内外层 CRC 并重新加密转发。
        "dl_01_block_enabled": False,
        # 01 下行 mrpcs 文件名混淆（仅重放）：解密 0x08/Type9 明文，命中
        # mrpcs*.data 后把扩展名前的 "." 等长改成 "1"，再重算内外层 CRC。
        "dl_01_mrpcs_mutate_enabled": False,
        # 上行脏数据清除（仅重放，暗区）：对 40 13 上行明文扫描 ul_blacklist_strings；启用后每帧在「上行拦截日志」记 [UL清除]（含 ⚠ 无命中）
        "ul_dirty_clean_enabled": False,
        # 上行黑名单字符串列表：[{"str": "auto_defence_start", "hits": 0}, ...]
        "ul_blacklist_strings": [],
        # 上行大包截断（仅重放）：明文长度 ≥ 阈值时，在 ABAB 标记处截断并重加密
        "ul_truncate_abab_enabled": False,
        "ul_truncate_abab_min_len": 500,
        # ─── 插件 Key 注入（DH 密钥交换类游戏）──────────────────────────
        # 插件通过 POST /api/plugin/key 提交从内存读取的会话 Key
        # plugin_api_token: 非空时插件请求须附 X-Plugin-Token 头；留空则无鉴权
        "plugin_api_token": "",
        # 等待插件 Key 的最大秒数（10 01/10 02 交换完但无法从包内取 Key 时）
        "plugin_key_wait_timeout": 15,
        # 全局调试开关：为 True 时完全跳过 3366 的录制、重放、替换，只处理 01 通道
        "skip_33": False,
        # 插件类游戏配置（game 标识 → 行为参数）
        # decrypt: 解密策略，同 3366_products；record_3366: 是否将 3366 数据入录制池
        # dump_3366: 是否 dump 3366 原始帧到文件（研究用）
        # ─── Protobuf 命令名黑名单（三角洲专用，命令名全局唯一）──────────────
        # 上下行共用一份；命中哪边就处理哪边，自动判断方向。
        # CSAceSendAntiDataNtf 由 33 重放替换单独处理，无需加入此列表。
        "pb_cmd_blacklist": [
            {"cmd": "CSTssLoadReportConfigReq", "hits": 0},   # 上行：阻止 TSS 上报规则下发
            {"cmd": "CSGatewayKickPlayerNtf",   "hits": 0},   # 下行：屏蔽踢出/冻结弹窗
        ],
        "plugin_games": {
            "0a92": {
                "name": "三角洲行动",
                # v1.120运行时固定纯透传；保留条目只兼容旧config结构。
                "decrypt": "none",
                "record_3366": False,
                "dump_3366": False,
                # 三角洲无块下发，ace_chunk_block_pattern 留空
                # ACE 替换、命令黑名单、dl_search_str 均使用全局配置
                "ace_chunk_block_pattern": "",
            },
        },
    }

    def __init__(self, path: str = CONFIG_FILE):
        self.path = path
        self._data: dict = dict(self._DEFAULTS)
        self.load()

    def _debug_log(self, msg: str):
        """
        轻量配置读写日志：写入 C:\\PyProxyApp\\config_debug.log。
        用于排查「服务器上手改 config.json 但启动又回默认」的问题。
        """
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            log_path = os.path.join(os.path.dirname(self.path), "config_debug.log")
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] {msg}\n")
        except Exception:
            pass

    def load(self):
        try:
            if os.path.exists(self.path):
                self._debug_log(f"load(): reading {self.path}")
                # 兼容服务器上手工编辑导致的 UTF-8 BOM（\ufeff）
                # json.load 在 encoding="utf-8" 下会报 Unexpected UTF-8 BOM
                with open(self.path, "r", encoding="utf-8-sig") as f:
                    saved = json.load(f)
                # 只覆盖已知字段，保留默认值作为兜底
                for k, v in saved.items():
                    if k in self._DEFAULTS:
                        self._data[k] = v
                if (
                    "full_rebuild_01_mode" not in saved
                    and "same_device_replenish_mode" in saved
                ):
                    self._data["full_rebuild_01_mode"] = bool(
                        saved["same_device_replenish_mode"]
                    )
                if self._data.get("type9_learning_mode") in {
                    "117-tiered-template-pool",
                }:
                    self._data["type9_learning_mode"] = "118-tiered-pass-live"
                # v1.128.5界面移除设备切换，所有会话固定继承当前重放设备。
                self._data["type9_device_mode"] = "inherit_live"
                self._debug_log(
                    "load(): ok "
                    f"port_record={self._data.get('port_record')} "
                    f"port_replay={self._data.get('port_replay')}"
                )
            else:
                self._debug_log(f"load(): {self.path} not found, using defaults")
        except Exception:
            self._debug_log(
                "load(): failed, using defaults. "
                f"err={traceback.format_exc(limit=2).strip()}"
            )

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            self._debug_log(
                "save(): writing "
                f"port_record={self._data.get('port_record')} "
                f"port_replay={self._data.get('port_replay')} "
                f"to {self.path}"
            )
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except Exception:
            self._debug_log(
                "save(): failed. "
                f"err={traceback.format_exc(limit=2).strip()}"
            )

    def get(self, key: str, default=None):
        """获取配置项；若传入 default 则 key 不存在时返回 default，否则用 _DEFAULTS 兜底"""
        if default is not None:
            return self._data.get(key, default)
        return self._data.get(key, self._DEFAULTS.get(key))

    def set(self, key: str, value):
        if key in self._DEFAULTS:
            self._data[key] = value

    def snapshot(self) -> dict:
        """返回当前配置副本，供界面导出与状态摘要使用。"""
        return dict(self._data)

    def reset_keys(self, keys) -> None:
        """把指定已知配置恢复为内置默认值。"""
        for key in keys:
            if key in self._DEFAULTS:
                self._data[key] = self._DEFAULTS[key]


app_config = AppConfig()
