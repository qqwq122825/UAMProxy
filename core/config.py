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
        "port_record": 1081,
        "port_replay": 1080,
        "ext_enabled": False,
        "ext_ip":      "127.0.0.1",
        "ext_port":    8889,
        "detail_01_log": False,  # 详细 01 替换日志（原始+替换后完整 Hex）
        # 33 66：首下行 Key/IV 相对「16 字节帧头之后」的 payload 偏移（字节），未设则尝试 payload[0:16]+[16:32]
        "3366_key_offset": None,
        "3366_iv_offset": None,
        # 是否同时录制完整 33 66 原始帧（体积大；默认只录解密后含 01 0A 00 09/21 的加密区入池）
        "record_raw_3366_frames": False,
        # 重放：01 子包内无 0A 00 09/01 0A 00 09/21 锚点时，按「包尾长度」与池 payload 长度匹配（± 容差）
        "replay_strict_match": True,
        "replay_length_match_tol": 300,
        "replay_len_fallback_header": 55,  # 保留子包前若干字节，从该偏移起替换到包尾
        # 暗区 33 66 产品 ID（00 00 09 4E → 0000094E）
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
        # 运行目录下 PyProxyTrafficLogs_* 详单（TCP≥阈值、3366、01 替换校验）
        "traffic_session_log_enabled": True,
        "traffic_log_min_len": 10,
        # 01/3366 双协议专项采集：原始双向 chunk + 方向字节流 + 完整协议帧，
        # 不生成常规流量详单，也不写入录制池/监控数据。
        "special_dual_capture_mode_enabled": False,
        "special_capture_user": "test",
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
        "ace_identifier_display_map": {},
        # 自动断线：01 包达到该数量且存在 33 录制时，断开携带 33 的连接并拒绝该 IP 新连接，直到所有连接断开
        "auto_disconnect_01_threshold": 100,
        # 3366 原始数据（不解密）中若含 01 0A 00 09 或 01 0A 00 23，不发送但会记录
        "drop_3366_raw_high_entropy": False,
        # 下发拦截详情历史预存账户列表：列表内的账户无论详情弹窗是否打开都会缓存历史日志，
        # 点"📋 详情"时可回放查看替换前的记录；其他账户仅弹窗打开后才记录（节省内存）
        "dl_intercept_history_labels": ["test"],
        # 暗区突围下发数据拦截
        "az_dl_intercept_enabled": False,   # 暗区突围：启用 33 下行字符串拦截
        "dl_search_str": "unzipmrpcs",
        "dl_replace_str": "",       # 普通模式：替换为此字符串；留空则等长 0x00 覆盖
        # 毁掉模式：勾选后忽略替换串，只用查找串定位目标帧，然后对区间整体填充（起止由下方区间标记控制）
        "dl_destroy_mode_enabled": False,
        # 上行 33 协议：拦截含 config2/config3 的 4013 帧，置空载荷使服务端解析失败
        "ul_intercept_config23_enabled": False,
        # HTTPS 域名拦截：命中指定域名的 SOCKS5 CONNECT 请求时直接拒绝，无需解密
        "ace_https_block_enabled": False,
        "ace_https_block_host": "down.anticheatexpert.com",
        # 仅重放模式：勾选后录制端口(record)上线不触发 HTTPS 拦截，仅重放端口(replay)拦截
        "ace_https_block_replay_only": False,
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
        # 01 下行大包拦截（仅重放）：整包 TCP 还原后超过阈值直接丢弃，不转发给客户端
        # 正常 01 心跳包约 105 字节；反作弊文件下发通常超过 1000 字节
        "dl_01_block_enabled": False,
        "dl_01_block_threshold": 1000,
        # 上行脏数据清除（仅重放，暗区）：对 40 13 上行明文扫描 ul_blacklist_strings；启用后每帧在「上行拦截日志」记 [UL清除]（含 ⚠ 无命中）
        "ul_dirty_clean_enabled": False,
        # 上行黑名单字符串列表：[{"str": "auto_defence_start", "hits": 0}, ...]
        "ul_blacklist_strings": [],
        # 上行大包截断（仅重放）：明文长度 ≥ 阈值时，在 ABAB 标记处截断并重加密
        "ul_truncate_abab_enabled": False,
        "ul_truncate_abab_min_len": 500,
        # 全局调试开关：为 True 时完全跳过 3366 的录制、重放、替换，只处理 01 通道
        "skip_33": False,
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


app_config = AppConfig()
