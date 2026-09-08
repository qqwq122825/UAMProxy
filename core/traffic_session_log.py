# ─────────────────────────────────────────
# v1.128.2默认写入 DATA_DIR/AI日志/run_*/ 机器JSON/JSONL。
# test可选全量Hex，其他用户始终保留可回溯的精简记录，异常自动升级全量Hex。
# 下方旧详单函数仅作历史兼容，legacy_text_log_enabled=True时才写入。
# 运行目录下的会话级流量详单
# 日志文件说明：
#   tcp_raw.log               — 经过代理的 TCP 原始分片（上下行，长度>=阈值）
#   01_sliced.log             — 01 通道切片：录制收到的 / 3366明文中提取的 / 重放实际发出的
#   01_replace.log            — 01 重放替换详情（原始封包、替换后封包、verify 输出、UID）
#   33_uplink.log             — 33 上行帧：原始密文、解密明文、ASCII 可读显示
#   33_replace.log            — 33 重放替换详情（原始密文/明文 → 替换明文 → 重加密密文）
#   33_downlink.log           — 33 下行帧：前64B密文（用于对照 tcp_raw.log）+ 明文可打印字符串
#   3366_record_reason.log    — 33 未入池原因（Key未取、解密失败、明文无01切片等）
#   3366_raw_high_entropy_drop.log — 3366 含 01_0A_00_09/23 的丢包记录
# ─────────────────────────────────────────
from __future__ import annotations

import os
import re
import shutil
import threading
import csv
import hashlib
import json
from datetime import datetime

from core.config import DATA_DIR, app_config
from core.packet_verify import format_01_packet_verify_report
from core.ai_log_v128 import ai_log_v128

MARKER_01_0A_00_09 = b"\x01\x0A\x00\x09"

_RUN_DIR_PATTERN = re.compile(r"^PyProxyTrafficLogs_\d{8}_\d{6}$")


def hex_slice_from_01_0a_00_09(data: bytes) -> str | None:
    """从首个 01 0A 00 09 起截到缓冲区末尾，转连续大写 hex（无空格）。"""
    i = data.find(MARKER_01_0A_00_09)
    if i < 0:
        return None
    return data[i:].hex().upper()


class TrafficSessionLog:
    """
    在进程首次写日志时于 os.getcwd() 下创建目录：
      PyProxyTrafficLogs_<YYYYMMDD_HHMMSS>/
    """

    _lock = threading.Lock()
    _dir: str | None = None
    _persistent_01_lock = threading.Lock()
    _persistent_01_path: str | None = None
    _persistent_01_downlink_path: str | None = None
    _persistent_01_message_leaf_path: str | None = None
    _persistent_01_downlink_event_id = 0
    _persistent_01_message_leaf_event_id = 0
    _persistent_record_session_event_id = 0
    _analysis_01_lock = threading.Lock()
    _analysis_01_dir: str | None = None
    _analysis_01_event_id = 0
    _analysis_01_downlink_event_id = 0
    _analysis_01_selection_event_id = 0
    _analysis_01_usage_event_id = 0
    _analysis_01_conn_state: dict[str, dict[str, int]] = {}
    _analysis_01_game_state: dict[str, dict] = {}
    _analysis_01_unknown_leaf_stats: dict[str, dict] = {}
    _analysis_01_tfp_called_stats: dict[str, object] = {}
    _analysis_01_learning = None
    _NORMAL_UNKNOWN_LEAF_SAMPLE_LIMIT = 3

    @classmethod
    def enabled(cls) -> bool:
        return bool(app_config.get("legacy_text_log_enabled", False))

    @classmethod
    def ai_machine_enabled(cls) -> bool:
        return bool(
            app_config.get("ai_log_enabled", True)
            and app_config.get("ai_log_machine_only", True)
        )

    @classmethod
    def _ai_allow(cls, username: str) -> bool:
        """v1.128.2不丢弃任何用户；数据量由full/compact分级控制。"""
        return True

    @classmethod
    def _allow(cls, username: str) -> bool:
        """检查该用户是否在日志白名单内。白名单为空则允许所有用户。"""
        raw = (app_config.get("traffic_log_user_filter") or "").strip()
        if not raw:
            return True
        allowed = {u.strip() for u in raw.split(",") if u.strip()}
        return username in allowed

    @classmethod
    def clear_previous_run_dirs_and_reset_state(cls) -> int:
        """
        删除当前工作目录下所有 PyProxyTrafficLogs_<日期>_<时间>/ 目录，
        并重置本进程的详单目录句柄（下次写入会建新目录）。
        不修改录制内存池 recording_pool。
        返回成功删除的目录个数。
        """
        removed = 0
        base = os.getcwd()
        with cls._lock:
            cls._dir = None
            try:
                for name in os.listdir(base):
                    if not _RUN_DIR_PATTERN.match(name):
                        continue
                    path = os.path.join(base, name)
                    if not os.path.isdir(path):
                        continue
                    try:
                        shutil.rmtree(path, ignore_errors=True)
                        removed += 1
                    except OSError:
                        pass
            except OSError:
                pass
        return removed

    @classmethod
    def reset_session_state_only(cls) -> None:
        """仅清空当前进程内的详单目录句柄，不删磁盘目录（下次写入会新建 PyProxyTrafficLogs_*）。"""
        with cls._lock:
            cls._dir = None

    @classmethod
    def clear_ai_logs_and_rotate(cls, *, start_fresh_run: bool) -> dict:
        """清空AI日志目录，并让运行中的采集立即切换到全新run。"""
        result = ai_log_v128.clear_all_logs(
            DATA_DIR,
            app_config,
            start_fresh_run=bool(start_fresh_run),
        )
        with cls._persistent_01_lock:
            cls._persistent_01_path = ai_log_v128.path("record_frames")
            cls._persistent_01_downlink_path = ai_log_v128.path(
                "downlink_events"
            )
            cls._persistent_01_message_leaf_path = ai_log_v128.path(
                "record_reports"
            )
            cls._persistent_01_downlink_event_id = 0
            cls._persistent_01_message_leaf_event_id = 0
            cls._persistent_record_session_event_id = 0
        with cls._analysis_01_lock:
            cls._analysis_01_dir = ai_log_v128.run_dir
            cls._analysis_01_event_id = 0
            cls._analysis_01_downlink_event_id = 0
            cls._analysis_01_selection_event_id = 0
            cls._analysis_01_usage_event_id = 0
            cls._analysis_01_conn_state = {}
            cls._analysis_01_game_state = {}
            cls._analysis_01_unknown_leaf_stats = {}
            cls._analysis_01_tfp_called_stats = {}
            cls._analysis_01_learning = None
        return result

    @classmethod
    def begin_persistent_01_record_run(cls) -> str | None:
        """
        为本次代理启动分配 test 录制帧日志。

        文件位于 C:\\PyProxyApp\\01RecordPackets，独立于会被启动清理的
        PyProxyTrafficLogs_* 目录；每次启动使用新的时间文件，历史文件持续保留。
        """
        if cls.ai_machine_enabled():
            try:
                run_dir = ai_log_v128.start_run(
                    DATA_DIR,
                    app_config,
                    force_new=True,
                )
                cls._analysis_01_dir = run_dir
                cls._persistent_01_path = ai_log_v128.path("record_frames")
                cls._persistent_01_downlink_path = ai_log_v128.path(
                    "downlink_events"
                )
                cls._persistent_01_message_leaf_path = ai_log_v128.path(
                    "record_reports"
                )
                cls._persistent_01_downlink_event_id = 0
                cls._persistent_01_message_leaf_event_id = 0
                cls._persistent_record_session_event_id = 0
                return cls._persistent_01_path
            except OSError:
                return None
        with cls._persistent_01_lock:
            try:
                folder = os.path.join(DATA_DIR, "01RecordPackets")
                os.makedirs(folder, exist_ok=True)
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                cls._persistent_01_path = os.path.join(
                    folder, f"test_01_sliced_{stamp}.log"
                )
                cls._persistent_01_downlink_path = os.path.join(
                    folder, f"test_01_downlink_{stamp}.jsonl"
                )
                cls._persistent_01_message_leaf_path = os.path.join(
                    folder, f"test_01_message_leaves_{stamp}.jsonl"
                )
                cls._persistent_01_downlink_event_id = 0
                cls._persistent_01_message_leaf_event_id = 0
                cls._persistent_record_session_event_id = 0
                return cls._persistent_01_path
            except OSError:
                cls._persistent_01_path = None
                cls._persistent_01_downlink_path = None
                cls._persistent_01_message_leaf_path = None
                return None

    @classmethod
    def begin_01_replay_analysis_run(cls) -> str | None:
        """为本次启动创建持久化 01 重放分析目录；历史目录不参与启动清理。"""
        if cls.ai_machine_enabled():
            try:
                run_dir = ai_log_v128.ensure_run(DATA_DIR, app_config)
                cls._analysis_01_dir = run_dir
                cls._analysis_01_event_id = 0
                cls._analysis_01_downlink_event_id = 0
                cls._analysis_01_selection_event_id = 0
                cls._analysis_01_usage_event_id = 0
                cls._analysis_01_conn_state = {}
                cls._analysis_01_game_state = {}
                cls._analysis_01_unknown_leaf_stats = {}
                cls._analysis_01_tfp_called_stats = {}
                cls._analysis_01_learning = None
                return run_dir
            except OSError:
                cls._analysis_01_dir = None
                return None
        with cls._analysis_01_lock:
            try:
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                root = os.path.join(DATA_DIR, "01ReplayAnalysis")
                run_dir = os.path.join(root, f"run_{stamp}")
                os.makedirs(run_dir, exist_ok=True)
                cls._analysis_01_dir = run_dir
                cls._analysis_01_event_id = 0
                cls._analysis_01_downlink_event_id = 0
                cls._analysis_01_selection_event_id = 0
                cls._analysis_01_usage_event_id = 0
                cls._analysis_01_conn_state = {}
                cls._analysis_01_game_state = {}
                cls._analysis_01_unknown_leaf_stats = {}
                cls._analysis_01_tfp_called_stats = {
                    "schema": "dfm-tfp-called-stats-v1",
                    "detected_leaves": 0,
                    "successful_rewrite_leaves": 0,
                    "pass_or_blocked_leaves": 0,
                    "template_replaced_leaves": 0,
                    "structured_removed_leaves": 0,
                    "zeroed_leaves": 0,
                    "residual_leaves": 0,
                    "rule_ids": {},
                    "record_codes": {},
                }
                cls._analysis_01_learning = None
                detailed = bool(app_config.get("detail_01_log", False))
                if app_config.get("type9_learning_enabled", True):
                    from core.type9_learning import Type9LearningRegistry

                    cls._analysis_01_learning = Type9LearningRegistry(
                        data_dir=DATA_DIR,
                        run_dir=run_dir,
                        detailed=detailed,
                    )
                manifest = {
                    "schema": "dfm-01-replay-v6",
                    "semantic_ruleset": "v1.124-tfp-called-global-clean-rules",
                    "edition": "dfm",
                    "learning_mode": app_config.get(
                        "type9_learning_mode", "118-tiered-pass-live"
                    ),
                    "learning_enabled": bool(
                        app_config.get("type9_learning_enabled", True)
                    ),
                    "device_mode": app_config.get(
                        "type9_device_mode", "inherit_live"
                    ),
                    "log_mode": "detailed" if detailed else "normal",
                    "created_at": datetime.now().isoformat(timespec="milliseconds"),
                    "packet_scope": "v1.124 dual device-profile Type9 replay and global tfp_called cleanup",
                    "3366_policy": "dfm byte-for-byte pass-through; no decrypt, record, template selection, or 01 state mutation",
                    "source_map": {
                        "network_output": "mechanically verified changed candidate; otherwise live frames",
                        "shadow_live": [
                            "physical frame layout",
                            "logical batch structure/order",
                            "leaf common header 0x00..0x0D including recordSequence",
                            "selector and key_index",
                        ],
                        "shadow_template": "same recordCode/messageId/length leaf body",
                        "shadow_semantic": [
                            "nearest recordSequence template",
                            "internal subtype/cycle exact match",
                            "live counter/time/session overlays",
                            "0x1105 live 0x00..0x23 plus same-key template tail",
                            "0x01122388 complete live leaf inheritance",
                            "unmapped matched leaf body is copied for aggressive diagnosis",
                            "recordSequence distance is diagnostic only and never forces whole-leaf live fallback",
                            "dynamic record/message and stale timestamp guards; sequence distance is diagnostic only",
                            "watched/new identity/new length shadow-only field diffs",
                            "cross-account donor UID rewrite with live identity guard",
                            "inherit_live keeps replay device identity and gates device-sensitive templates",
                            "replace_recorded pins one template session per connection and uses its device identity/reports",
                            "recorded profile includes model/hardware model/system/IDFV/resolution/app version/app Mach UUID",
                            "all recordCodes scan tfp_called; clean same/confirmed donor slot first, structured field removal second, equal-length zero marker final fallback",
                            "player template first, published official template second",
                            "unmatched child leaves keep their complete live bytes by default",
                            "optional leaf-prune experiment with recursive length rebuild",
                            "v1.128 built-in periodic stable 80xx independent-report "
                            "replenish with report/leaf/frame/group offsets; "
                            "v1.128.1 sequence-safe DROP_LEAF compaction; "
                            "0207 forced patch_live at historical +0x48/+0x50 fields; "
                            "9000 becomes sequence-safe empty 2000; "
                            "2001/8028/8002 patch_live; "
                            "100B/8027/8029 replace_template_nearest allow_cross_device; "
                            "1105 replace_template_nearest inherit 36; "
                            "2000 replace_template_nearest, missing template becomes empty 2000; "
                            "100C/100F inherit Live; "
                            "device-mode base policy handles 1007/1008/1009",
                            "persistent unknown schema registry and byte variability profiles",
                        ],
                        "shadow_recalculated": [
                            "Type9 plaintext_crc32",
                            "Type9 ciphertext",
                            "01 outer_crc32",
                        ],
                    },
                }
                with open(os.path.join(run_dir, "manifest.json"), "w", encoding="utf-8") as f:
                    json.dump(manifest, f, ensure_ascii=False, indent=2)
                with open(os.path.join(run_dir, "README.txt"), "w", encoding="utf-8") as f:
                    f.write(
                        "DFMProxy 01 重放专属分析目录\n"
                        f"- 当前日志模式: {'详细' if detailed else '普通'}\n"
                        "- 01_replace_events.jsonl: 每次 REPLACE/PASS_LIVE/PASS_NON_TARGET/DROP 的事件\n"
                        "- 01_replace_summary.csv: 可直接用表格查看的摘要\n"
                        "- 01_replace_errors.jsonl: DROP 或字段/CRC检查异常事件\n"
                        "- 01_unknown_leaf_samples.jsonl: 每类未命中叶子的前3份原始样本\n"
                        "- 01_unknown_context_samples.jsonl: 未知样本对应的完整01帧与Type9明文\n"
                        "- 01_unknown_leaf_stats.json: 未知叶子累计次数与样本数量\n"
                        "- 01_tfp_called_events.jsonl: 每次tfp_called命中、规则ID及替换前后摘要\n"
                        "- 01_tfp_called_stats.json: tfp_called累计命中、模板替换、结构删除、清零和残留统计\n"
                        "- 每个09事件的 shadow_candidate/shadow_rebuild: 录制叶子候选包与回验结果\n"
                        "- replacement_level=KNOWN_CLEAN: 已知字段规则替换\n"
                        "- replacement_level=UNMAPPED_BODY_PASS_LIVE: 未映射正文完整保留Live\n"
                        "- replacement_level=LIVE_CONTEXT_PASS_LIVE: 候选改变设备/版本/inc_id/obf_id时整叶保留Live\n"
                        "- replacement_level=UNMATCHED_LEAF_PASS_LIVE: 玩家/官方两级模板未命中后保留实时叶子\n"
                        "- replacement_level=UNMATCHED_LEAF_PRUNE: 仅显式专项实验切除叶子\n"
                        "- replacement_level=SPECIAL_UNKNOWN_RULE: 精确结构专项处理器命中\n"
                        "- replacement_level=SPECIAL_DROP_LEAF: 命中型专项叶子删除并完成容器/CRC重建\n"
                        "- replacement_level=SPECIAL_EMPTY_2000: 命中叶改成真实44字节空结果0x2000并保留Live序号\n"
                        "- block_reason=UNMAPPED_BODY_PASS_LIVE: 未建模正文保留Live，录制主体仅用于影子差异\n"
                        "- 01_suspect_diffs.jsonl: 专项叶子完整实时明文与旁路候选差异\n"
                        "- cross_account: 实时账号、donor账号、身份改写与最终账号校验\n"
                        "- 01_schema_registry.json: 持久结构注册表快照\n"
                        "- 01_field_profiles.json: 实时/模板字节稳定度与变化区间\n"
                        "- 01_learning_decisions.jsonl: 新ID/新长度/新字段模式决策\n"
                        "- NeedsAIAnalysis/: 仅有新结构或冲突时创建，可直接打包分析\n"
                        "- unknown_diff_offsets 与 live/template/candidate HEX 用于定位未继承字段\n"
                        "- 01_downlink_events.jsonl: 重放连接收到的完整01下行帧及处置结果\n"
                        "- template_selection_events.jsonl: 每条连接选择个人/官方模板池的结果\n"
                        "- template_usage_events.jsonl: 每个报告实际使用的玩家/官方叶子数量\n"
                        "- experiment_markers.jsonl: 手动3366阻断/恢复的精确时间点与断开数量\n"
                        "普通模式省略整包 HEX，但保留未知叶子原始 HEX；详细模式保留全部整包和候选 HEX。\n"
                        "已命中录制叶子且机械回验通过时发送已变化候选包。\n"
                        "42/54 等匹配前握手帧继续见常规 01_sliced.log。\n"
                    )
                return run_dir
            except OSError:
                cls._analysis_01_dir = None
                cls._analysis_01_learning = None
                return None

    @classmethod
    def write_experiment_marker(
        cls,
        marker: str,
        *,
        enabled: bool,
        details: dict | None = None,
    ) -> str | None:
        """写入运行期实验时间点，便于把后续01事件与按钮操作精确对齐。"""
        if cls.ai_machine_enabled():
            try:
                return ai_log_v128.write_marker(
                    data_dir=DATA_DIR,
                    config=app_config,
                    marker=str(marker),
                    enabled=enabled,
                    details=details,
                )
            except (OSError, TypeError, ValueError):
                return None
        if not cls._analysis_01_dir:
            return None
        with cls._analysis_01_lock:
            try:
                path = os.path.join(
                    cls._analysis_01_dir,
                    "experiment_markers.jsonl",
                )
                row = {
                    "schema": "dfm-experiment-marker-v1",
                    "time": datetime.now().isoformat(timespec="milliseconds"),
                    "marker": str(marker),
                    "enabled": bool(enabled),
                    "details": dict(details or {}),
                }
                with open(path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                return path
            except OSError:
                return None

    @classmethod
    def log_01_reconnect_event(
        cls,
        *,
        phase: str,
        username: str,
        client_ip: str,
        conn_id: str,
        game_id: str = "",
        details: dict | None = None,
    ) -> str | None:
        """记录128.10的42B候选、Live报告判定与断开时间点。"""
        try:
            return ai_log_v128.write_reconnect_event(
                data_dir=DATA_DIR,
                config=app_config,
                phase=phase,
                username=username,
                client_ip=client_ip,
                conn_id=conn_id,
                game_id=game_id,
                details=details,
            )
        except (OSError, TypeError, ValueError):
            return None

    @classmethod
    def log_record_session_event(
        cls,
        *,
        action: str,
        session: dict,
        client_ip: str = "",
        reason: str = "",
    ) -> str | None:
        """持久记录录制会话生命周期；该文件跨进程启动持续追加。"""
        if cls.ai_machine_enabled():
            try:
                return ai_log_v128.write_record_session(
                    data_dir=DATA_DIR,
                    config=app_config,
                    action=action,
                    session=session,
                    client_ip=client_ip,
                    reason=reason,
                )
            except (OSError, TypeError, ValueError):
                return None
        with cls._persistent_01_lock:
            try:
                folder = os.path.join(DATA_DIR, "01RecordPackets")
                os.makedirs(folder, exist_ok=True)
                path = os.path.join(folder, "01_record_sessions.jsonl")
                cls._persistent_record_session_event_id += 1
                pool = list(session.get("pool_items") or [])
                event = {
                    "schema": "dfm-01-record-session-v1",
                    "event_id": cls._persistent_record_session_event_id,
                    "time": datetime.now().isoformat(timespec="milliseconds"),
                    "action": str(action or "UPDATE").upper(),
                    "reason": str(reason or ""),
                    "sid": str(session.get("sid") or ""),
                    "client_ip": str(client_ip or ""),
                    "proxy_username": str(session.get("owner_username") or ""),
                    "game_id": str(session.get("game_id") or ""),
                    "record_role": (
                        "official"
                        if str(session.get("pool_scope") or "").startswith("official")
                        else "player"
                    ),
                    "pool_scope": str(session.get("pool_scope") or "player"),
                    "batch_id": str(session.get("batch_id") or ""),
                    "batch_name": str(session.get("batch_name") or ""),
                    "client_version": str(
                        session.get("client_version") or "auto"
                    ),
                    "published": bool(session.get("published")),
                    "published_at": float(session.get("published_at") or 0.0),
                    "active": bool(session.get("active")),
                    "created_at": float(session.get("created_at") or 0.0),
                    "last_record_at": float(session.get("last_record_at") or 0.0),
                    "counts": {
                        "01": sum(
                            1 for item in pool
                            if not str(item.get("source") or "").startswith("3366")
                        ),
                        "33": sum(
                            1 for item in pool
                            if str(item.get("source") or "").startswith("3366")
                        ),
                        "total": len(pool),
                    },
                }
                with open(path, "a", encoding="utf-8") as stream:
                    stream.write(
                        json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                        + "\n"
                    )
                return path
            except (OSError, TypeError, ValueError):
                return None

    @classmethod
    def log_01_replay_template_selection(
        cls,
        *,
        username: str,
        client_ip: str,
        conn_id: str,
        live_game_id: str,
        selected: dict,
    ) -> str | None:
        """记录连接级模板池选择，覆盖所有重放代理账号。"""
        if cls.ai_machine_enabled():
            if not cls._ai_allow(username):
                return None
            try:
                return ai_log_v128.write_template_selection(
                    data_dir=DATA_DIR,
                    config=app_config,
                    username=username,
                    client_ip=client_ip,
                    conn_id=conn_id,
                    live_game_id=live_game_id,
                    selected=selected,
                )
            except (OSError, TypeError, ValueError):
                return None
        if not cls._analysis_01_dir:
            cls.begin_01_replay_analysis_run()
        with cls._analysis_01_lock:
            try:
                run_dir = cls._analysis_01_dir
                if not run_dir:
                    return None
                cls._analysis_01_selection_event_id += 1
                personal = int(selected.get("personal_01_count") or 0)
                official = int(selected.get("official_01_count") or 0)
                if personal and official:
                    mode = "player_primary_with_official_fallback"
                elif personal:
                    mode = "player_only"
                elif official:
                    mode = "official_fallback"
                else:
                    mode = "no_01_template"
                event = {
                    "schema": "dfm-01-template-selection-v1",
                    "event_id": cls._analysis_01_selection_event_id,
                    "time": datetime.now().isoformat(timespec="milliseconds"),
                    "template_mode": mode,
                    "proxy_username": str(username or ""),
                    "live_game_id": str(live_game_id or ""),
                    "connection": {"client_ip": client_ip, "conn_id": conn_id},
                    "client_version": str(
                        selected.get("client_version") or "auto"
                    ),
                    "personal_01_count": personal,
                    "official_01_count": official,
                    "official_sources": list(selected.get("official_sources") or []),
                }
                path = os.path.join(run_dir, "template_selection_events.jsonl")
                with open(path, "a", encoding="utf-8") as stream:
                    stream.write(
                        json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                        + "\n"
                    )
                return path
            except (OSError, TypeError, ValueError):
                return None

    @classmethod
    def _log_01_template_usage_event(
        cls,
        *,
        detail: dict,
        username: str,
        client_ip: str,
        conn_id: str,
    ) -> str | None:
        """记录每个报告实际使用的来源；内容精简，因此覆盖所有账号。"""
        if not cls._analysis_01_dir:
            cls.begin_01_replay_analysis_run()
        with cls._analysis_01_lock:
            try:
                run_dir = cls._analysis_01_dir
                if not run_dir:
                    return None
                shadow = detail.get("shadow_rebuild") or {}
                leaves = list(shadow.get("leaf_results") or [])
                player_leaves = sum(
                    1 for leaf in leaves if leaf.get("template_scope") == "player"
                )
                official_leaves = sum(
                    1 for leaf in leaves if leaf.get("template_scope") == "official"
                )
                pruned = int(shadow.get("pruned_leaves") or 0)
                unmatched_pass_live = int(
                    shadow.get("unmatched_pass_live_leaves") or 0
                )
                special_handled = int(shadow.get("special_handled_leaves") or 0)
                inserted_leaves = int(shadow.get("inserted_leaves") or 0)
                cross_record_replaced = int(
                    shadow.get("cross_record_replaced_leaves") or 0
                )
                tfp_called_detected = int(
                    shadow.get("tfp_called_detected_leaves") or 0
                )
                tfp_called_template_replaced = int(
                    shadow.get("tfp_called_template_replaced_leaves") or 0
                )
                tfp_called_structured_removed = int(
                    shadow.get("tfp_called_structured_removed_leaves") or 0
                )
                tfp_called_zeroed = int(
                    shadow.get("tfp_called_zeroed_leaves") or 0
                )
                tfp_called_residual = int(
                    shadow.get("tfp_called_residual_leaves") or 0
                )
                device_context_pass_live = int(
                    shadow.get("device_context_pass_live_leaves") or 0
                )
                if official_leaves and player_leaves:
                    mode = "mixed"
                elif official_leaves:
                    mode = "official_fallback"
                elif player_leaves:
                    mode = "player"
                elif inserted_leaves:
                    mode = "stable_80xx_insert"
                elif (
                    special_handled
                    or cross_record_replaced
                    or tfp_called_structured_removed
                ):
                    mode = "special_rule"
                elif pruned:
                    mode = "prune"
                else:
                    mode = "live"
                cls._analysis_01_usage_event_id += 1
                event = {
                    "schema": "dfm-01-template-usage-v1",
                    "event_id": cls._analysis_01_usage_event_id,
                    "time": datetime.now().isoformat(timespec="milliseconds"),
                    "proxy_username": str(username or ""),
                    "live_game_id": str(
                        detail.get("live_game_id")
                        or detail.get("account_id")
                        or ""
                    ),
                    "connection": {"client_ip": client_ip, "conn_id": conn_id},
                    "decision": str(detail.get("decision") or ""),
                    "reason": str(detail.get("reason") or ""),
                    "replacement_level": str(
                        detail.get("replacement_level")
                        or shadow.get("replacement_level")
                        or "NONE"
                    ),
                    "template_mode": mode,
                    "player_template_leaves": player_leaves,
                    "official_template_leaves": official_leaves,
                    "pruned_leaves": pruned,
                    "unmatched_pass_live_leaves": unmatched_pass_live,
                    "special_handled_leaves": special_handled,
                    "inserted_leaves": inserted_leaves,
                    "inserted_message_ids": list(
                        shadow.get("inserted_message_ids") or []
                    ),
                    "insert_skipped_reason": str(
                        shadow.get("insert_skipped_reason") or ""
                    ),
                    "insert_skipped_live_80xx": list(
                        shadow.get("insert_skipped_live_80xx") or []
                    ),
                    "cross_record_replaced_leaves": cross_record_replaced,
                    "tfp_called_detected_leaves": tfp_called_detected,
                    "tfp_called_template_replaced_leaves": (
                        tfp_called_template_replaced
                    ),
                    "tfp_called_structured_removed_leaves": (
                        tfp_called_structured_removed
                    ),
                    "tfp_called_zeroed_leaves": tfp_called_zeroed,
                    "tfp_called_residual_leaves": tfp_called_residual,
                    "tfp_called_rule_ids": shadow.get(
                        "tfp_called_rule_ids", []
                    ),
                    "device_context_pass_live_leaves": device_context_pass_live,
                    "official_batch_ids": sorted({
                        str(leaf.get("template_batch_id") or "")
                        for leaf in leaves
                        if leaf.get("template_scope") == "official"
                        and leaf.get("template_batch_id")
                    }),
                    "official_donor_game_ids": sorted({
                        str(leaf.get("donor_game_id") or "")
                        for leaf in leaves
                        if leaf.get("template_scope") == "official"
                        and leaf.get("donor_game_id")
                    }),
                }
                path = os.path.join(run_dir, "template_usage_events.jsonl")
                with open(path, "a", encoding="utf-8") as stream:
                    stream.write(
                        json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                        + "\n"
                    )
                return path
            except (OSError, TypeError, ValueError):
                return None

    @classmethod
    def _analysis_packet_snapshot(cls, frames: list[bytes] | None) -> dict | None:
        if not frames:
            return None
        from core.crypto import (
            _ace_01_reassemble_frames,
            _ace_01_verify_frames,
            _ace_01_virtual_packet,
            _ace_find_encrypted_record,
        )

        frame_list = [bytes(frame) for frame in frames]
        assembled = _ace_01_reassemble_frames(frame_list)
        checked = _ace_01_verify_frames(frame_list)
        logical = assembled[1] if assembled else b""
        ordered = assembled[0] if assembled else frame_list
        first = ordered[0] if ordered else b""
        marker_types = sorted({
            f"{logical[i + 3]:02X}"
            for i in range(len(logical) - 3)
            if logical[i:i + 3] == b"\x01\x0A\x00"
        })
        virtual = _ace_01_virtual_packet(frame_list)
        record_meta = None
        if virtual:
            found = _ace_find_encrypted_record(virtual)
            if found:
                start, end, _, _ = found
                record = virtual[start:end]
                record_meta = {
                    "selector": record[0] if len(record) >= 1 else None,
                    "key_index": record[1] if len(record) >= 2 else None,
                    "plain_crc32": record[2:6].hex().upper() if len(record) >= 6 else "",
                    "ciphertext_length": (
                        int.from_bytes(record[6:8], "big") if len(record) >= 8 else None
                    ),
                    "sha256": hashlib.sha256(record).hexdigest(),
                }
        return {
            "frame_count": len(frame_list),
            "frame_lengths": [len(frame) for frame in frame_list],
            "total_length": sum(map(len, frame_list)),
            "frames_hex": [frame.hex().upper() for frame in frame_list],
            "sha256": hashlib.sha256(b"".join(frame_list)).hexdigest(),
            "logical_payload_length": len(logical),
            "logical_payload_sha256": hashlib.sha256(logical).hexdigest() if logical else "",
            "marker_types": marker_types,
            "report_index": checked.get("report_index"),
            "game_id": checked.get("account_id", ""),
            "frame_sequence": int.from_bytes(first[8:10], "big") if len(first) >= 10 else None,
            "packet_group": int.from_bytes(first[36:38], "big") if len(first) >= 38 else None,
            "transport_tag": f"{first[47]:02X}" if len(first) > 47 else "",
            "outer_crc32": checked.get("crc_hex", ""),
            "calculated_crc32": checked.get("calculated_crc_hex", ""),
            "crc_ok": (
                bool(checked.get("crc_hex"))
                and checked.get("crc_hex") == checked.get("calculated_crc_hex")
            ),
            "validation_ok": checked.get("ok", False),
            "validation_errors": checked.get("errors", []),
            "encrypted_record": record_meta,
            "message_ids": cls._packet_message_ids(logical),
        }

    @staticmethod
    def _packet_message_ids(logical: bytes) -> list[str]:
        if not logical:
            return []
        try:
            from core.type9_shadow import decode_material

            decoded = decode_material(logical)
        except (OSError, TypeError, ValueError):
            return []
        if not decoded.get("ok"):
            return []
        ids = []
        for leaf in decoded.get("leaves") or []:
            message_id = leaf.get("message_id")
            if message_id is None:
                continue
            ids.append(f"0x{int(message_id):04X}")
        return ids

    @staticmethod
    def _compact_packet_snapshot(snapshot: dict | None) -> dict | None:
        if not snapshot:
            return snapshot
        return {
            key: value for key, value in snapshot.items() if key != "frames_hex"
        }

    @staticmethod
    def _compact_online_decode(value: dict | None) -> dict | None:
        if not isinstance(value, dict):
            return value
        keep = {
            "parse_ok", "plain_crc_ok", "errors", "selector", "algorithm",
            "key_index", "stored_plain_crc32", "calculated_plain_crc32",
            "ciphertext_length", "plaintext_length", "plaintext_sha256",
            "top_record_code", "top_record_sequence", "child_count", "leaves",
            "leaf_sequences", "signature", "timestamps",
        }
        result = {}
        for side in ("live", "template"):
            row = value.get(side)
            if isinstance(row, dict):
                result[side] = {key: row[key] for key in keep if key in row}
        if isinstance(value.get("facts"), dict):
            result["facts"] = value["facts"]
        return result

    @staticmethod
    def _compact_leaf_result(leaf: dict) -> dict:
        keep = {
            "path",
            "record_code",
            "message_id",
            "length",
            "candidate_length",
            "template_length",
            "live_sequence",
            "structural_match",
            "matched",
            "semantic_ready",
            "semantic_rule",
            "replacement_level",
            "special_rule_id",
            "special_rule_action",
            "special_rule_error",
            "block_reason",
            "tfp_called_detected",
            "tfp_called_rule_id",
            "tfp_called_action",
            "tfp_called_replacement",
            "tfp_called_remove_info",
            "suspect_watch",
            "suspect_flags",
            "available_template_lengths",
            "sequence_distance",
            "template_pool_idx",
            "template_path",
            "template_sequence",
            "template_scope",
            "template_batch_id",
            "inserted_from_report_index",
        }
        result = {key: leaf[key] for key in keep if key in leaf}
        result["clean_diff_count"] = len(leaf.get("clean_diff_offsets") or [])
        result["unknown_diff_count"] = len(leaf.get("unknown_diff_offsets") or [])
        result["shadow_only_diff_count"] = len(
            leaf.get("shadow_only_diff_offsets") or []
        )
        identity = leaf.get("identity_rewrite") or {}
        if identity:
            result["identity_rewrite"] = {
                "status": identity.get("status"),
                "blocked": bool(identity.get("blocked")),
                "range_count": len(identity.get("ranges") or []),
            }
        dynamic = leaf.get("dynamic_guard") or {}
        if dynamic:
            result["dynamic_guard"] = {
                "blocked": bool(dynamic.get("blocked")),
                "reason": dynamic.get("reason", ""),
            }
        return result

    @classmethod
    def _compact_shadow_rebuild(cls, value: dict | None) -> dict | None:
        if not isinstance(value, dict):
            return value
        heavy = {"suspect_live_plaintext_hex", "decoded"}
        result = {key: item for key, item in value.items() if key not in heavy}
        result["leaf_results"] = [
            cls._compact_leaf_result(leaf)
            for leaf in (value.get("leaf_results") or [])
        ]
        return result

    @classmethod
    def _write_tfp_called_events(
        cls,
        *,
        run_dir: str,
        event: dict,
        leaf_results: list[dict],
    ) -> None:
        """记录每次tfp_called命中、规则ID、动作和替换前后摘要。"""
        matched = [
            leaf for leaf in leaf_results
            if bool(leaf.get("tfp_called_detected"))
        ]
        if not matched:
            return
        stats = cls._analysis_01_tfp_called_stats
        rule_counts = stats.setdefault("rule_ids", {})
        record_counts = stats.setdefault("record_codes", {})
        path = os.path.join(run_dir, "01_tfp_called_events.jsonl")
        with open(path, "a", encoding="utf-8") as stream:
            for leaf in matched:
                action = str(leaf.get("tfp_called_action") or "")
                rule_id = str(leaf.get("tfp_called_rule_id") or "")
                record_code = f"0x{int(leaf.get('record_code') or 0):08X}"
                replacement = dict(leaf.get("tfp_called_replacement") or {})
                candidate_has_marker = bool(
                    replacement.get("candidate_marker_present")
                )
                final_rewrite = bool(
                    (event.get("checks") or {}).get("replacement_changed")
                    and not candidate_has_marker
                )
                stats["detected_leaves"] = int(
                    stats.get("detected_leaves") or 0
                ) + 1
                final_key = (
                    "successful_rewrite_leaves"
                    if final_rewrite else "pass_or_blocked_leaves"
                )
                stats[final_key] = int(stats.get(final_key) or 0) + 1
                if action == "CLEAN_TEMPLATE_REPLACE":
                    key = "template_replaced_leaves"
                elif action == "STRUCTURED_FIELD_REMOVE":
                    key = "structured_removed_leaves"
                elif "ZERO_MARKER" in action:
                    key = "zeroed_leaves"
                else:
                    key = "residual_leaves"
                stats[key] = int(stats.get(key) or 0) + 1
                if candidate_has_marker and key != "residual_leaves":
                    stats["residual_leaves"] = int(
                        stats.get("residual_leaves") or 0
                    ) + 1
                if rule_id:
                    rule_counts[rule_id] = int(rule_counts.get(rule_id) or 0) + 1
                record_counts[record_code] = int(
                    record_counts.get(record_code) or 0
                ) + 1
                row = {
                    "schema": "dfm-tfp-called-event-v1",
                    "event_id": event.get("event_id"),
                    "time": event.get("time"),
                    "game_id": event.get("game_id", ""),
                    "connection": event.get("connection"),
                    "report_index": (event.get("ordinals") or {}).get(
                        "report_index"
                    ),
                    "path": leaf.get("path"),
                    "record_code": record_code,
                    "message_id": leaf.get("message_id"),
                    "record_sequence": leaf.get("live_sequence"),
                    "live_length": leaf.get("length"),
                    "candidate_length": leaf.get("candidate_length"),
                    "rule_id": rule_id,
                    "action": action,
                    "replacement_level": leaf.get("replacement_level"),
                    "template_pool_idx": leaf.get("template_pool_idx"),
                    "template_record_sequence": leaf.get("template_sequence"),
                    "template_length": leaf.get("template_length"),
                    "replacement": replacement,
                    "final_report_changed": bool(
                        (event.get("checks") or {}).get("replacement_changed")
                    ),
                    "final_equals_live": bool(
                        (event.get("checks") or {}).get("final_equals_live")
                    ),
                }
                stream.write(
                    json.dumps(row, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                )
        temp_path = os.path.join(run_dir, ".01_tfp_called_stats.json.tmp")
        final_path = os.path.join(run_dir, "01_tfp_called_stats.json")
        with open(temp_path, "w", encoding="utf-8") as stream:
            json.dump(stats, stream, ensure_ascii=False, indent=2)
        os.replace(temp_path, final_path)

    @classmethod
    def _write_unknown_leaf_samples(
        cls,
        *,
        run_dir: str,
        event: dict,
        leaf_results: list[dict],
        live_snapshot: dict | None,
    ) -> None:
        """普通/详细模式都保留未知叶子；每个结构最多写三份原始样本。"""
        changed = False
        context_needed = False
        for leaf in leaf_results:
            if leaf.get("matched"):
                continue
            record_code = int(leaf.get("record_code") or 0)
            message_id = leaf.get("message_id")
            length = int(leaf.get("length") or 0)
            message_tag = (
                f"{int(message_id):04X}"
                if isinstance(message_id, int) else "NONE"
            )
            schema_key = f"{record_code:08X}:{message_tag}:{length}"
            match_fields = list(leaf.get("match_fields") or [])
            if match_fields:
                match_signature = "|".join(
                    f"{field.get('name', '')}@{field.get('offset', '')}="
                    f"{field.get('live_hex', '')}"
                    for field in match_fields
                )
                variant = hashlib.sha256(
                    match_signature.encode("utf-8")
                ).hexdigest()[:8]
                schema_key = f"{schema_key}:{variant}"
            stats = cls._analysis_01_unknown_leaf_stats.setdefault(
                schema_key,
                {
                    "schema_key": schema_key,
                    "record_code": f"0x{record_code:08X}",
                    "message_id": (
                        f"0x{int(message_id):04X}"
                        if isinstance(message_id, int) else None
                    ),
                    "length": length,
                    "match_fields": match_fields,
                    "occurrences": 0,
                    "samples_written": 0,
                    "first_seen": event["time"],
                    "last_seen": event["time"],
                },
            )
            stats["occurrences"] += 1
            stats["last_seen"] = event["time"]
            changed = True
            raw_hex = str(leaf.get("live_hex") or "")
            if (
                raw_hex
                and stats["samples_written"]
                < cls._NORMAL_UNKNOWN_LEAF_SAMPLE_LIMIT
            ):
                try:
                    raw = bytes.fromhex(raw_hex)
                except ValueError:
                    continue
                stats["samples_written"] += 1
                context_needed = True
                sample = {
                    "schema": "dfm-01-unknown-leaf-sample-v1",
                    "schema_key": schema_key,
                    "sample_index": stats["samples_written"],
                    "occurrence": stats["occurrences"],
                    "time": event["time"],
                    "event_id": event["event_id"],
                    "context_event_id": event["event_id"],
                    "game_id": event["game_id"],
                    "connection": event["connection"],
                    "report_index": event["ordinals"]["report_index"],
                    "path": leaf.get("path"),
                    "record_sequence": leaf.get("live_sequence"),
                    "record_code": stats["record_code"],
                    "message_id": stats["message_id"],
                    "actual_length": length,
                    "replacement_level": leaf.get("replacement_level"),
                    "structural_match": bool(leaf.get("structural_match")),
                    "available_template_lengths": leaf.get(
                        "available_template_lengths", []
                    ),
                    "raw_leaf_sha256": hashlib.sha256(raw).hexdigest(),
                    "raw_leaf_hex": raw_hex,
                    "raw_frame_length": (live_snapshot or {}).get("total_length"),
                    "raw_frame_sha256": (live_snapshot or {}).get("sha256", ""),
                }
                with open(
                    os.path.join(run_dir, "01_unknown_leaf_samples.jsonl"),
                    "a",
                    encoding="utf-8",
                ) as stream:
                    stream.write(
                        json.dumps(sample, ensure_ascii=False, separators=(",", ":"))
                        + "\n"
                    )
        if context_needed:
            plaintext_hex = str(
                (event.get("shadow_rebuild") or {}).get(
                    "suspect_live_plaintext_hex", ""
                )
                or ""
            )
            try:
                plaintext_sha256 = hashlib.sha256(
                    bytes.fromhex(plaintext_hex)
                ).hexdigest()
            except ValueError:
                plaintext_sha256 = ""
            context = {
                "schema": "dfm-01-unknown-context-v1",
                "event_id": event["event_id"],
                "time": event["time"],
                "game_id": event["game_id"],
                "connection": event["connection"],
                "report_index": event["ordinals"]["report_index"],
                "raw_frame_count": (live_snapshot or {}).get("frame_count", 0),
                "raw_frame_lengths": (live_snapshot or {}).get(
                    "frame_lengths", []
                ),
                "raw_frames_hex": (live_snapshot or {}).get("frames_hex", []),
                "raw_type9_plaintext_hex": plaintext_hex,
                "raw_type9_plaintext_sha256": plaintext_sha256,
            }
            with open(
                os.path.join(run_dir, "01_unknown_context_samples.jsonl"),
                "a",
                encoding="utf-8",
            ) as stream:
                stream.write(
                    json.dumps(context, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                )
        if changed:
            path = os.path.join(run_dir, "01_unknown_leaf_stats.json")
            temp = f"{path}.tmp"
            with open(temp, "w", encoding="utf-8") as stream:
                json.dump(
                    {
                        "schema": "dfm-01-unknown-leaf-stats-v1",
                        "updated_at": event["time"],
                        "sample_limit_per_schema": cls._NORMAL_UNKNOWN_LEAF_SAMPLE_LIMIT,
                        "schemas": cls._analysis_01_unknown_leaf_stats,
                    },
                    stream,
                    ensure_ascii=False,
                    indent=2,
                )
            os.replace(temp, path)

    @classmethod
    def log_01_replay_analysis_event(
        cls,
        *,
        detail: dict,
        username: str,
        client_ip: str,
        conn_id: str,
    ) -> str | None:
        """写入可直接交给分析工具的 REPLACE/PASS/DROP 三态 JSONL 事件。"""
        if cls.ai_machine_enabled():
            if not cls._ai_allow(username):
                return None
            try:
                return ai_log_v128.write_replay_event(
                    data_dir=DATA_DIR,
                    config=app_config,
                    detail=detail,
                    username=username,
                    client_ip=client_ip,
                    conn_id=conn_id,
                )
            except (OSError, TypeError, ValueError, IndexError, KeyError):
                return None
        cls._log_01_template_usage_event(
            detail=detail,
            username=username,
            client_ip=client_ip,
            conn_id=conn_id,
        )
        if (username or "").strip().lower() != "test":
            return None
        if not cls._analysis_01_dir:
            cls.begin_01_replay_analysis_run()
        with cls._analysis_01_lock:
            run_dir = cls._analysis_01_dir
            if not run_dir:
                return None
            try:
                decision = str(detail.get("decision") or "DROP")
                cls._analysis_01_event_id += 1
                state = cls._analysis_01_conn_state.setdefault(
                    conn_id, {"decision": 0, "target_09": 0}
                )
                state["decision"] += 1
                if decision != "PASS_NON_TARGET":
                    state["target_09"] += 1

                game_key = str(detail.get("account_id") or username or "unknown")
                game_state = cls._analysis_01_game_state.setdefault(
                    game_key, {"target_09": 0, "last_leaf_sequence": None}
                )
                live_decode = (detail.get("online_decode") or {}).get("live") or {}
                live_sequences = [
                    int(value) for value in (live_decode.get("leaf_sequences") or [])
                ]
                leaf_continuity = None
                previous_leaf_sequence = game_state.get("last_leaf_sequence")
                if decision != "PASS_NON_TARGET":
                    game_state["target_09"] += 1
                    if live_sequences:
                        if previous_leaf_sequence is not None:
                            leaf_continuity = (
                                live_sequences[0] == previous_leaf_sequence + 1
                            )
                        game_state["last_leaf_sequence"] = live_sequences[-1]

                live = cls._analysis_packet_snapshot(detail.get("live_frames"))
                template = cls._analysis_packet_snapshot(detail.get("template_frames"))
                shadow = cls._analysis_packet_snapshot(detail.get("shadow_frames"))
                output = cls._analysis_packet_snapshot(detail.get("output_frames"))
                shadow_rebuild = detail.get("shadow_rebuild") or None
                shadow_checks = (shadow_rebuild or {}).get("checks") or {}
                leaf_results = list((shadow_rebuild or {}).get("leaf_results") or [])
                player_template_leaves = sum(
                    1 for leaf in leaf_results
                    if leaf.get("template_scope") == "player"
                )
                official_template_leaves = sum(
                    1 for leaf in leaf_results
                    if leaf.get("template_scope") == "official"
                )
                official_batch_ids = sorted({
                    str(leaf.get("template_batch_id") or "")
                    for leaf in leaf_results
                    if leaf.get("template_scope") == "official"
                    and leaf.get("template_batch_id")
                })
                if official_template_leaves and player_template_leaves:
                    template_mode = "mixed"
                elif official_template_leaves:
                    template_mode = "official_fallback"
                elif player_template_leaves:
                    template_mode = "player"
                elif int((shadow_rebuild or {}).get("inserted_leaves") or 0):
                    template_mode = "stable_80xx_insert"
                elif int(
                    (shadow_rebuild or {}).get("special_handled_leaves") or 0
                ):
                    template_mode = "special_rule"
                elif int((shadow_rebuild or {}).get("pruned_leaves") or 0):
                    template_mode = "prune"
                else:
                    template_mode = "live"
                checks = {
                    "report_inherited": bool(
                        live and output
                        and live.get("report_index") == output.get("report_index")
                    ),
                    "blue_06_09_inherited": False,
                    "blue_12_25_inherited": False,
                    "blue_2f_inherited": False,
                    "encrypted_record_from_template": None,
                    "final_equals_live": bool(
                        live and output and live.get("sha256") == output.get("sha256")
                    ),
                    "final_equals_shadow": (
                        bool(
                            shadow and output
                            and shadow.get("sha256") == output.get("sha256")
                        ) if shadow_rebuild is not None else None
                    ),
                    "replacement_changed": bool(
                        decision == "REPLACE"
                        and live and output
                        and live.get("sha256") != output.get("sha256")
                    ),
                    "output_crc_ok": bool(output and output.get("crc_ok")),
                    "output_validation_ok": bool(output and output.get("validation_ok")),
                    "shadow_candidate_ready": (
                        bool((shadow_rebuild or {}).get("ready"))
                        if shadow_rebuild is not None else None
                    ),
                    "shadow_mechanical_ready": (
                        bool((shadow_rebuild or {}).get("mechanical_ready"))
                        if shadow_rebuild is not None else None
                    ),
                    "shadow_semantic_ready": (
                        bool((shadow_rebuild or {}).get("semantic_ready"))
                        if shadow_rebuild is not None else None
                    ),
                    "shadow_send_ready": (
                        bool((shadow_rebuild or {}).get("send_ready"))
                        if shadow_rebuild is not None else None
                    ),
                    "shadow_outer_crc_ok": (
                        bool(shadow_checks.get("outer_crc_ok"))
                        if shadow_rebuild is not None else None
                    ),
                    "shadow_decode_ok": (
                        bool(shadow_checks.get("decode_ok"))
                        if shadow_rebuild is not None else None
                    ),
                    "shadow_signature_equal_live": (
                        bool(shadow_checks.get("signature_equal_live"))
                        if shadow_rebuild is not None else None
                    ),
                    "shadow_sequences_equal_live": (
                        bool(shadow_checks.get("sequences_equal_live"))
                        if shadow_rebuild is not None else None
                    ),
                    "leaf_sequence_continuous_from_previous": leaf_continuity,
                }
                live_frames = detail.get("live_frames") or []
                template_frames = detail.get("template_frames") or []
                output_frames = detail.get("output_frames") or []
                if live_frames and output_frames:
                    lf, of = live_frames[0], output_frames[0]
                    checks["blue_06_09_inherited"] = of[6:10] == lf[6:10]
                    checks["blue_12_25_inherited"] = of[18:38] == lf[18:38]
                    checks["blue_2f_inherited"] = len(of) > 47 and len(lf) > 47 and of[47] == lf[47]
                event = {
                    "schema": "dfm-01-replay-v6",
                    "event_id": cls._analysis_01_event_id,
                    "time": datetime.now().isoformat(timespec="milliseconds"),
                    "decision": decision,
                    "reason": detail.get("reason", ""),
                    "replacement_level": detail.get(
                        "replacement_level",
                        (shadow_rebuild or {}).get("replacement_level", "NONE"),
                    ),
                    "user": username,
                    "game_id": detail.get("account_id", ""),
                    "cross_account": {
                        "enabled": bool(detail.get("cross_account")),
                        "live_game_id": detail.get("live_game_id", ""),
                        "donor_game_id": detail.get("donor_game_id", ""),
                        "final_identity_check": detail.get(
                            "final_identity_check"
                        ),
                        "identity_rewrite_count": (shadow_rebuild or {}).get(
                            "identity_rewrite_count", 0
                        ),
                        "identity_blocked_leaves": (shadow_rebuild or {}).get(
                            "identity_blocked_leaves", 0
                        ),
                    },
                    "connection": {"client_ip": client_ip, "conn_id": conn_id},
                    "template_usage": {
                        "mode": template_mode,
                        "player_template_leaves": player_template_leaves,
                        "official_template_leaves": official_template_leaves,
                        "official_batch_ids": official_batch_ids,
                        "pruned_leaves": int(
                            (shadow_rebuild or {}).get("pruned_leaves") or 0
                        ),
                        "unmatched_pass_live_leaves": int(
                            (shadow_rebuild or {}).get(
                                "unmatched_pass_live_leaves"
                            )
                            or 0
                        ),
                        "special_handled_leaves": int(
                            (shadow_rebuild or {}).get("special_handled_leaves")
                            or 0
                        ),
                        "cross_record_replaced_leaves": int(
                            (shadow_rebuild or {}).get(
                                "cross_record_replaced_leaves"
                            )
                            or 0
                        ),
                        "tfp_called_detected_leaves": int(
                            (shadow_rebuild or {}).get(
                                "tfp_called_detected_leaves"
                            )
                            or 0
                        ),
                        "tfp_called_template_replaced_leaves": int(
                            (shadow_rebuild or {}).get(
                                "tfp_called_template_replaced_leaves"
                            )
                            or 0
                        ),
                        "tfp_called_structured_removed_leaves": int(
                            (shadow_rebuild or {}).get(
                                "tfp_called_structured_removed_leaves"
                            )
                            or 0
                        ),
                        "tfp_called_zeroed_leaves": int(
                            (shadow_rebuild or {}).get(
                                "tfp_called_zeroed_leaves"
                            )
                            or 0
                        ),
                        "tfp_called_residual_leaves": int(
                            (shadow_rebuild or {}).get(
                                "tfp_called_residual_leaves"
                            )
                            or 0
                        ),
                        "tfp_called_rule_ids": list(
                            (shadow_rebuild or {}).get(
                                "tfp_called_rule_ids"
                            )
                            or []
                        ),
                        "device_context_pass_live_leaves": int(
                            (shadow_rebuild or {}).get(
                                "device_context_pass_live_leaves"
                            )
                            or 0
                        ),
                        "inserted_leaves": int(
                            (shadow_rebuild or {}).get("inserted_leaves") or 0
                        ),
                        "inserted_message_ids": list(
                            (shadow_rebuild or {}).get("inserted_message_ids")
                            or []
                        ),
                        "insert_skipped_reason": str(
                            (shadow_rebuild or {}).get("insert_skipped_reason")
                            or ""
                        ),
                        "insert_skipped_live_80xx": list(
                            (shadow_rebuild or {}).get(
                                "insert_skipped_live_80xx"
                            )
                            or []
                        ),
                    },
                    "insert_80xx": {
                        "inserted_leaves": int(
                            (shadow_rebuild or {}).get("inserted_leaves") or 0
                        ),
                        "inserted_message_ids": list(
                            (shadow_rebuild or {}).get("inserted_message_ids")
                            or []
                        ),
                        "skipped_reason": str(
                            (shadow_rebuild or {}).get("insert_skipped_reason")
                            or ""
                        ),
                        "live_80xx": list(
                            (shadow_rebuild or {}).get(
                                "insert_skipped_live_80xx"
                            )
                            or []
                        ),
                        "live_message_ids": list(
                            (live or {}).get("message_ids") or []
                        ),
                        "output_message_ids": list(
                            (output or {}).get("message_ids") or []
                        ),
                    },
                    "ordinals": {
                        "decision_after_match": state["decision"],
                        "target_09": state["target_09"],
                        "game_target_09": game_state["target_09"],
                        "report_index": detail.get("report_index"),
                        "previous_leaf_sequence": previous_leaf_sequence,
                        "leaf_sequence_start": (
                            live_sequences[0] if live_sequences else None
                        ),
                        "leaf_sequence_end": (
                            live_sequences[-1] if live_sequences else None
                        ),
                    },
                    "cursor": {
                        "before": detail.get("cursor_before"),
                        "selected_pool_idx": detail.get("pool_idx"),
                        "after": detail.get("cursor_after"),
                        "pool_total": detail.get("pool_total", 0),
                    },
                    "recorded_template": template,
                    "live_input": live,
                    "shadow_candidate": shadow,
                    "final_output": output,
                    "checks": checks,
                    "validation_errors": detail.get("validation_errors", []),
                    "online_decode": detail.get("online_decode"),
                    "shadow_rebuild": shadow_rebuild,
                }
                learning = cls._analysis_01_learning
                if learning is not None:
                    try:
                        event["learning"] = learning.observe(event)
                    except (OSError, TypeError, ValueError):
                        event["learning"] = {"observed": 0, "alerts": 0, "error": True}
                cls._write_tfp_called_events(
                    run_dir=run_dir,
                    event=event,
                    leaf_results=leaf_results,
                )
                cls._write_unknown_leaf_samples(
                    run_dir=run_dir,
                    event=event,
                    leaf_results=leaf_results,
                    live_snapshot=live,
                )
                detailed = bool(app_config.get("detail_01_log", False))
                if detailed:
                    stored_event = event
                else:
                    stored_event = {
                        **event,
                        "recorded_template": cls._compact_packet_snapshot(template),
                        "live_input": cls._compact_packet_snapshot(live),
                        "shadow_candidate": cls._compact_packet_snapshot(shadow),
                        "final_output": cls._compact_packet_snapshot(output),
                        "online_decode": cls._compact_online_decode(
                            event.get("online_decode")
                        ),
                        "shadow_rebuild": cls._compact_shadow_rebuild(
                            shadow_rebuild
                        ),
                    }
                events_path = os.path.join(run_dir, "01_replace_events.jsonl")
                with open(events_path, "a", encoding="utf-8") as f:
                    f.write(
                        json.dumps(
                            stored_event,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )

                suspect_leaves = [
                    leaf
                    for leaf in (shadow_rebuild or {}).get("leaf_results", [])
                    if leaf.get("suspect_watch") or leaf.get("suspect_flags")
                ]
                if suspect_leaves:
                    suspect_event = {
                        "schema": "dfm-01-suspect-diff-v1",
                        "event_id": event["event_id"],
                        "time": event["time"],
                        "user": username,
                        "game_id": event["game_id"],
                        "cross_account": event.get("cross_account"),
                        "connection": event["connection"],
                        "ordinals": event["ordinals"],
                        "decision": decision,
                        "reason": event["reason"],
                        "network_output_equals_live": checks["final_equals_live"],
                        "shadow_only": True,
                        "live_frames_hex": (
                            [bytes(frame).hex().upper() for frame in live_frames]
                            if detailed else []
                        ),
                        "live_type9_plaintext_hex": (
                            (shadow_rebuild or {}).get(
                                "suspect_live_plaintext_hex", ""
                            ) if detailed else ""
                        ),
                        "suspect_leaves": (
                            suspect_leaves
                            if detailed
                            else [
                                cls._compact_leaf_result(leaf)
                                for leaf in suspect_leaves
                            ]
                        ),
                    }
                    with open(
                        os.path.join(run_dir, "01_suspect_diffs.jsonl"),
                        "a",
                        encoding="utf-8",
                    ) as f:
                        f.write(
                            json.dumps(
                                suspect_event,
                                ensure_ascii=False,
                                separators=(",", ":"),
                            )
                            + "\n"
                        )

                summary_path = os.path.join(run_dir, "01_replace_summary.csv")
                new_summary = not os.path.exists(summary_path)
                with open(summary_path, "a", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f)
                    if new_summary:
                        writer.writerow([
                            "event_id", "time", "decision", "reason", "report_index",
                            "target_09_ordinal", "game_target_09", "cursor_before", "pool_idx", "cursor_after",
                            "pool_total", "live_len", "template_len", "output_len",
                            "live_crc", "template_crc", "output_crc", "calculated_crc",
                            "crc_ok", "game_id", "leaf_sequence_start", "leaf_sequence_end",
                            "leaf_continuity", "shadow_status", "shadow_matched", "shadow_total",
                            "shadow_coverage", "shadow_semantic_leaves", "shadow_unmapped_leaves",
                            "shadow_ready", "shadow_mechanical_ready", "shadow_crc_ok", "shadow_decode_ok",
                            "final_equals_live", "final_equals_shadow", "replacement_changed",
                            "replacement_level", "shadow_send_ready", "changed_leaves",
                            "pruned_leaves", "unmatched_pass_live_leaves",
                            "unmapped_pass_live_leaves",
                            "live_context_pass_live_leaves",
                            "device_context_pass_live_leaves",
                            "cross_record_replaced_leaves",
                            "tfp_called_detected_leaves",
                            "tfp_called_template_replaced_leaves",
                            "tfp_called_structured_removed_leaves",
                            "tfp_called_zeroed_leaves",
                            "tfp_called_residual_leaves",
                            "tfp_called_rule_ids",
                            "special_handled_leaves", "special_changed_leaves",
                            "special_dropped_leaves", "special_emptied_leaves",
                            "variable_length_replaced_leaves",
                            "full_live_inherited_leaves",
                            "clean_changed_leaves", "aggressive_changed_leaves",
                            "aggressive_blocked_leaves",
                            "suspect_leaf_count",
                            "cross_account", "live_game_id", "donor_game_id",
                            "identity_rewrite_count", "identity_blocked_leaves",
                            "final_identity_check",
                            "template_mode", "player_template_leaves",
                            "official_template_leaves", "official_batch_ids",
                            "inserted_leaves", "inserted_message_ids",
                            "insert_skipped_reason", "insert_skipped_live_80xx",
                            "live_message_ids", "output_message_ids",
                        ])
                    writer.writerow([
                        event["event_id"], event["time"], decision, event["reason"],
                        event["ordinals"]["report_index"], state["target_09"],
                        game_state["target_09"],
                        event["cursor"]["before"], event["cursor"]["selected_pool_idx"],
                        event["cursor"]["after"], event["cursor"]["pool_total"],
                        (live or {}).get("total_length"), (template or {}).get("total_length"),
                        (output or {}).get("total_length"), (live or {}).get("outer_crc32"),
                        (template or {}).get("outer_crc32"), (output or {}).get("outer_crc32"),
                        (output or {}).get("calculated_crc32"), checks["output_crc_ok"],
                        event["game_id"], event["ordinals"]["leaf_sequence_start"],
                        event["ordinals"]["leaf_sequence_end"], leaf_continuity,
                        (shadow_rebuild or {}).get("status"),
                        (shadow_rebuild or {}).get("matched_leaves"),
                        (shadow_rebuild or {}).get("total_leaves"),
                        (shadow_rebuild or {}).get("coverage"),
                        (shadow_rebuild or {}).get("semantic_ready_leaves"),
                        (shadow_rebuild or {}).get("semantic_unmapped_leaves"),
                        (shadow_rebuild or {}).get("ready"),
                        (shadow_rebuild or {}).get("mechanical_ready"),
                        shadow_checks.get("outer_crc_ok"),
                        shadow_checks.get("decode_ok"),
                        checks.get("final_equals_live"),
                        checks.get("final_equals_shadow"),
                        checks.get("replacement_changed"),
                        event.get("replacement_level"),
                        checks.get("shadow_send_ready"),
                        (shadow_rebuild or {}).get("changed_leaves"),
                        (shadow_rebuild or {}).get("pruned_leaves", 0),
                        (shadow_rebuild or {}).get(
                            "unmatched_pass_live_leaves", 0
                        ),
                        (shadow_rebuild or {}).get(
                            "unmapped_pass_live_leaves", 0
                        ),
                        (shadow_rebuild or {}).get(
                            "live_context_pass_live_leaves", 0
                        ),
                        (shadow_rebuild or {}).get(
                            "device_context_pass_live_leaves", 0
                        ),
                        (shadow_rebuild or {}).get(
                            "cross_record_replaced_leaves", 0
                        ),
                        (shadow_rebuild or {}).get(
                            "tfp_called_detected_leaves", 0
                        ),
                        (shadow_rebuild or {}).get(
                            "tfp_called_template_replaced_leaves", 0
                        ),
                        (shadow_rebuild or {}).get(
                            "tfp_called_structured_removed_leaves", 0
                        ),
                        (shadow_rebuild or {}).get(
                            "tfp_called_zeroed_leaves", 0
                        ),
                        (shadow_rebuild or {}).get(
                            "tfp_called_residual_leaves", 0
                        ),
                        "|".join(
                            (shadow_rebuild or {}).get(
                                "tfp_called_rule_ids", []
                            )
                            or []
                        ),
                        (shadow_rebuild or {}).get("special_handled_leaves", 0),
                        (shadow_rebuild or {}).get("special_changed_leaves", 0),
                        (shadow_rebuild or {}).get("special_dropped_leaves", 0),
                        (shadow_rebuild or {}).get("special_emptied_leaves", 0),
                        (shadow_rebuild or {}).get(
                            "variable_length_replaced_leaves", 0
                        ),
                        (shadow_rebuild or {}).get(
                            "full_live_inherited_leaves", 0
                        ),
                        (shadow_rebuild or {}).get("clean_changed_leaves"),
                        (shadow_rebuild or {}).get("aggressive_changed_leaves"),
                        (shadow_rebuild or {}).get("aggressive_blocked_leaves"),
                        (shadow_rebuild or {}).get("suspect_leaf_count"),
                        bool(detail.get("cross_account")),
                        detail.get("live_game_id", ""),
                        detail.get("donor_game_id", ""),
                        (shadow_rebuild or {}).get("identity_rewrite_count", 0),
                        (shadow_rebuild or {}).get("identity_blocked_leaves", 0),
                        detail.get("final_identity_check"),
                        template_mode,
                        player_template_leaves,
                        official_template_leaves,
                        "|".join(official_batch_ids),
                        (shadow_rebuild or {}).get("inserted_leaves", 0),
                        "|".join(
                            (shadow_rebuild or {}).get("inserted_message_ids")
                            or []
                        ),
                        (shadow_rebuild or {}).get("insert_skipped_reason", ""),
                        "|".join(
                            (shadow_rebuild or {}).get(
                                "insert_skipped_live_80xx"
                            )
                            or []
                        ),
                        "|".join((live or {}).get("message_ids") or []),
                        "|".join((output or {}).get("message_ids") or []),
                    ])
                if decision == "PASS_LIVE":
                    required_checks = [
                        checks["final_equals_live"],
                        checks["output_crc_ok"],
                        checks["output_validation_ok"],
                    ]
                elif decision == "PASS_NON_TARGET":
                    required_checks = [
                        checks["final_equals_live"],
                        checks["output_crc_ok"],
                        checks["output_validation_ok"],
                    ]
                elif decision == "REPLACE":
                    required_checks = [
                        checks["report_inherited"],
                        checks["blue_06_09_inherited"],
                        checks["blue_12_25_inherited"],
                        checks["blue_2f_inherited"],
                        checks["final_equals_shadow"],
                        checks["replacement_changed"],
                        checks["output_crc_ok"],
                        checks["output_validation_ok"],
                        checks["shadow_candidate_ready"],
                        checks["shadow_mechanical_ready"],
                        checks["shadow_send_ready"],
                        checks["shadow_outer_crc_ok"],
                        checks["shadow_decode_ok"],
                        checks["shadow_signature_equal_live"],
                        checks["shadow_sequences_equal_live"],
                    ]
                else:
                    required_checks = [
                        value for value in checks.values() if value is not None
                    ]
                has_check_error = decision == "DROP" or any(
                    value is False for value in required_checks
                )
                if has_check_error:
                    with open(
                        os.path.join(run_dir, "01_replace_errors.jsonl"),
                        "a",
                        encoding="utf-8",
                    ) as f:
                        f.write(
                            json.dumps(
                                stored_event,
                                ensure_ascii=False,
                                separators=(",", ":"),
                            )
                            + "\n"
                        )
                return events_path
            except (OSError, TypeError, ValueError):
                return None

    @classmethod
    def log_persistent_01_record_packet(
        cls,
        *,
        direction: str,
        client_ip: str,
        conn_id: str,
        uid: str,
        data: bytes,
        username: str,
    ) -> str | None:
        """把 test 用户录制端切割完成的完整 01 物理帧写入持久日志。"""
        if cls.ai_machine_enabled():
            if not data or not cls._ai_allow(username):
                return None
            try:
                return ai_log_v128.write_record_frame(
                    data_dir=DATA_DIR,
                    config=app_config,
                    direction=direction,
                    client_ip=client_ip,
                    conn_id=conn_id,
                    uid=uid,
                    data=data,
                    username=username,
                )
            except (OSError, TypeError, ValueError):
                return None
        if (username or "").strip().lower() != "test" or not data:
            return None
        with cls._persistent_01_lock:
            try:
                if not cls._persistent_01_path:
                    folder = os.path.join(DATA_DIR, "01RecordPackets")
                    os.makedirs(folder, exist_ok=True)
                    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                    cls._persistent_01_path = os.path.join(
                        folder, f"test_01_sliced_{stamp}.log"
                    )
                path = cls._persistent_01_path
                is_new = not os.path.exists(path)
                ts = datetime.now().isoformat(timespec="milliseconds")
                uid_tag = uid if uid else "-"
                header = (
                    f"{ts}  user=test  dir={direction or '-'}  "
                    f"ip={client_ip or '-'}  conn={conn_id or '-'}  "
                    f"uid={uid_tag}  LEN={len(data)}\n"
                )
                detailed = bool(app_config.get("detail_01_log", False))
                body = (
                    cls._wrap_hex(data.hex().upper())
                    if detailed
                    else (
                        f"SHA256={hashlib.sha256(data).hexdigest()}  "
                        f"HEAD={data[:32].hex().upper()}"
                    )
                )
                with open(path, "a", encoding="utf-8") as f:
                    if is_new:
                        f.write(
                            "DFMProxy test 用户 01 录制物理帧\n"
                            "每条记录均来自 TCP 重组和 01 长度切割；普通模式记录摘要，详细模式记录完整帧。\n\n"
                        )
                    f.write(header)
                    f.write(body)
                    f.write("\n\n")
                return path
            except OSError:
                return None

    @classmethod
    def log_persistent_01_message_item(
        cls,
        *,
        client_ip: str,
        session: dict,
        item: dict,
    ) -> str | None:
        """始终记录已解密Type9叶子，供两份录制直接做消息ID/字段差分。

        该JSONL不依赖detail_01_log；每个逻辑01报告只写一行，保留叶子原始Hex，
        后续比较脚本无需再次处理TCP分片或物理帧摘要模式。
        """
        if cls.ai_machine_enabled():
            username = str(session.get("owner_username") or "")
            if not cls._ai_allow(username):
                return None
            try:
                return ai_log_v128.write_record_report(
                    data_dir=DATA_DIR,
                    config=app_config,
                    client_ip=client_ip,
                    session=session,
                    item=item,
                )
            except (OSError, TypeError, ValueError, IndexError, KeyError):
                return None
        with cls._persistent_01_lock:
            try:
                if not cls._persistent_01_message_leaf_path:
                    folder = os.path.join(DATA_DIR, "01RecordPackets")
                    os.makedirs(folder, exist_ok=True)
                    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                    cls._persistent_01_message_leaf_path = os.path.join(
                        folder, f"test_01_message_leaves_{stamp}.jsonl"
                    )
                raw_packet = bytes(item.get("raw_packet") or b"")
                if not raw_packet:
                    return None
                from core.type9_shadow import decode_material

                decoded = decode_material(raw_packet)
                if not decoded.get("ok") or not decoded.get("leaves"):
                    return None
                cls._persistent_01_message_leaf_event_id += 1
                event = {
                    "schema": "dfm-01-message-leaves-v1",
                    "event_id": cls._persistent_01_message_leaf_event_id,
                    "time": datetime.now().isoformat(timespec="milliseconds"),
                    "client_ip": str(client_ip or ""),
                    "sid": str(session.get("sid") or ""),
                    "game_id": str(session.get("game_id") or item.get("account_id") or ""),
                    "proxy_username": str(session.get("owner_username") or ""),
                    "report_index": item.get("report_index"),
                    "top_record_code": (
                        f"0x{int((decoded.get('root') or {}).get('record_code') or 0):08X}"
                    ),
                    "leaf_count": len(decoded.get("leaves") or []),
                    "leaves": [
                        {
                            "path": list(leaf.get("path") or []),
                            "record_code": f"0x{int(leaf.get('record_code') or 0):08X}",
                            "message_id": (
                                f"0x{int(leaf.get('message_id')):04X}"
                                if isinstance(leaf.get("message_id"), int)
                                else None
                            ),
                            "length": int(leaf.get("actual_length") or 0),
                            "sequence": int(leaf.get("record_sequence") or 0),
                            "raw_hex": bytes(leaf.get("raw") or b"").hex().upper(),
                        }
                        for leaf in decoded.get("leaves") or []
                    ],
                }
                path = cls._persistent_01_message_leaf_path
                with open(path, "a", encoding="utf-8") as stream:
                    stream.write(
                        json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                        + "\n"
                    )
                return path
            except (OSError, TypeError, ValueError, IndexError, KeyError):
                return None

    @classmethod
    def log_01_downlink_packet(
        cls,
        *,
        mode: str,
        client_ip: str,
        conn_id: str,
        uid: str,
        data: bytes,
        username: str,
        disposition: str = "FORWARD",
        reason: str = "",
    ) -> str | None:
        """分别向录制、重放专属目录写入完整 01 下行物理帧。"""
        if cls.ai_machine_enabled():
            if not data or not cls._ai_allow(username):
                return None
            mode_tag = str(mode or "").strip().lower()
            if mode_tag not in {"record", "replay"}:
                return None
            try:
                return ai_log_v128.write_downlink(
                    data_dir=DATA_DIR,
                    config=app_config,
                    mode=mode_tag,
                    client_ip=client_ip,
                    conn_id=conn_id,
                    uid=uid,
                    data=data,
                    username=username,
                    disposition=disposition,
                    reason=reason,
                )
            except (OSError, TypeError, ValueError):
                return None
        if (username or "").strip().lower() != "test" or not data:
            return None
        mode_tag = str(mode or "").strip().lower()
        if mode_tag not in {"record", "replay"}:
            return None

        lock = cls._persistent_01_lock if mode_tag == "record" else cls._analysis_01_lock
        if mode_tag == "record" and not cls._persistent_01_downlink_path:
            cls.begin_persistent_01_record_run()
        elif mode_tag == "replay" and not cls._analysis_01_dir:
            cls.begin_01_replay_analysis_run()

        with lock:
            try:
                if mode_tag == "record":
                    path = cls._persistent_01_downlink_path
                    if not path:
                        return None
                    cls._persistent_01_downlink_event_id += 1
                    event_id = cls._persistent_01_downlink_event_id
                else:
                    if not cls._analysis_01_dir:
                        return None
                    path = os.path.join(cls._analysis_01_dir, "01_downlink_events.jsonl")
                    cls._analysis_01_downlink_event_id += 1
                    event_id = cls._analysis_01_downlink_event_id

                snapshot = cls._analysis_packet_snapshot([bytes(data)])
                if not app_config.get("detail_01_log", False):
                    snapshot = cls._compact_packet_snapshot(snapshot)
                event = {
                    "schema": "dfm-01-downlink-v1",
                    "event_id": event_id,
                    "time": datetime.now().isoformat(timespec="milliseconds"),
                    "mode": mode_tag.upper(),
                    "direction": "DOWN",
                    "disposition": str(disposition or "FORWARD"),
                    "reason": str(reason or ""),
                    "user": username,
                    "game_id": uid or (snapshot or {}).get("game_id", ""),
                    "connection": {"client_ip": client_ip, "conn_id": conn_id},
                    "packet": snapshot,
                }
                with open(path, "a", encoding="utf-8") as stream:
                    stream.write(
                        json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                        + "\n"
                    )
                return path
            except (OSError, TypeError, ValueError):
                return None

    @classmethod
    def ensure_log_dir_ready(cls) -> str | None:
        """代理启动时预创建详单目录，确保用户登录等流量到达时能立即写入。"""
        if cls.ai_machine_enabled():
            try:
                return ai_log_v128.ensure_run(DATA_DIR, app_config)
            except OSError:
                return None
        return cls._ensure_dir()

    @classmethod
    def reset_ai_connection_state(cls, conn_id: str) -> None:
        if cls.ai_machine_enabled():
            ai_log_v128.reset_connection(str(conn_id or ""))

    @classmethod
    def min_len(cls) -> int:
        try:
            return max(0, int(app_config.get("traffic_log_min_len", 10)))
        except (TypeError, ValueError):
            return 10

    @classmethod
    def _ensure_dir(cls) -> str | None:
        if not cls.enabled():
            return None
        if cls._dir and os.path.isdir(cls._dir):
            return cls._dir
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.getcwd()
        cls._dir = os.path.join(base, f"PyProxyTrafficLogs_{stamp}")
        os.makedirs(cls._dir, exist_ok=True)
        readme = os.path.join(cls._dir, "README.txt")
        try:
            with open(readme, "w", encoding="utf-8") as f:
                f.write(
                    "本目录为 DFMProxy 三角洲专版自动生成的流量详单。\n"
                    "- tcp_raw.log                    : 经过代理的 TCP 原始分片（上下行，长度>=配置阈值）\n"
                    "- 01_sliced.log                  : 01 通道切片（录制收到 / 3366明文提取 / 重放实际发出）\n"
                    "- 01_replace.log                 : 01 重放替换（原始封包、替换后封包、verify 输出、UID）\n"
                    "- 33_uplink.log                  : 33 上行帧（原始密文、解密明文、ASCII 可读显示）\n"
                    "- 33_replace.log                 : 33 重放替换（原始密文/明文 → 替换明文 → 重加密密文）\n"
                    "- 33_downlink.log                : 33 下行帧（前64B密文 + 明文可打印字符串，对照 tcp_raw.log）\n"
                    "- 3366_record_reason.log         : 33 未入池原因（Key未取、解密失败、明文无01切片等）\n"
                    "- 3366_raw_high_entropy_drop.log : 3366 含 01_0A_00_09/23 的丢包记录\n"
                )
        except OSError:
            pass
        return cls._dir

    @classmethod
    def _append(cls, filename: str, text: str) -> None:
        if not cls.enabled():
            return
        with cls._lock:
            d = cls._ensure_dir()
            if not d:
                return
            path = os.path.join(d, filename)
            try:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(text)
            except OSError:
                pass

    # ── 格式化工具 ──────────────────────────────────────────────────

    @classmethod
    def _wrap_hex(cls, hex_str: str, chars_per_line: int = 64) -> str:
        """将长 hex 按行换行，避免单行过长难以阅读"""
        if len(hex_str) <= chars_per_line:
            return hex_str
        lines = []
        for i in range(0, len(hex_str), chars_per_line):
            lines.append(hex_str[i: i + chars_per_line])
        return "\n".join(lines)

    @classmethod
    def _hexdump(cls, data: bytes, bytes_per_line: int = 16) -> str:
        """hexdump 风格：偏移 + 空格分隔 hex + ASCII 列（不可打印用 '.'）"""
        lines = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i: i + bytes_per_line]
            hex_col = " ".join(f"{b:02X}" for b in chunk)
            asc_col = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            lines.append(f"  {i:04X}  {hex_col:<{bytes_per_line * 3}}  {asc_col}")
        return "\n".join(lines)

    @classmethod
    def _extract_printable(cls, data: bytes, min_run: int = 4) -> str:
        """
        从 bytes 中提取连续可打印 ASCII 字符串（长度 >= min_run），
        用 ' | ' 分隔，供 33 下行日志快速识别内容。
        """
        result: list[str] = []
        run: list[str] = []
        for b in data:
            if 0x20 <= b < 0x7F:
                run.append(chr(b))
            else:
                if len(run) >= min_run:
                    result.append("".join(run))
                run = []
        if len(run) >= min_run:
            result.append("".join(run))
        return " | ".join(result) if result else "(无可打印字符串)"

    @classmethod
    def _decode_utf8_text(cls, data: bytes) -> str:
        """尝试 UTF-8 解码，不可解码字节用 · 替代，控制字符用 · 替代"""
        text = data.decode("utf-8", errors="replace")
        out = []
        for ch in text:
            if ch == "\ufffd" or (ord(ch) < 0x20 and ch not in "\n\r\t"):
                out.append("·")
            else:
                out.append(ch)
        return "".join(out)

    # ── Protobuf 命令名提取 & 收集 ──────────────────────────────────

    _cmd_re = re.compile(rb"CS[A-Z][A-Za-z0-9]{4,60}(?:Req|Res|Ntf)")
    _seen_cmds: set[str] = set()
    _cmd_lock = threading.Lock()

    @classmethod
    def _extract_pb_cmd(cls, plain: bytes) -> str | None:
        """从 protobuf 明文中提取 CS*Req / CS*Res / CS*Ntf 命令名"""
        m = cls._cmd_re.search(plain)
        return m.group(0).decode("ascii") if m else None

    @classmethod
    def _collect_cmd(cls, cmd: str, direction: str, client_ip: str):
        """将命令名去重后追加到 33_commands.log"""
        key = f"{direction}|{cmd}"
        with cls._cmd_lock:
            is_new = key not in cls._seen_cmds
            if is_new:
                cls._seen_cmds.add(key)
        if is_new:
            ts = datetime.now().isoformat(timespec="milliseconds")
            d_tag = "UP" if "UP" in direction else "DN"
            cls._append("33_commands.log", f"{ts}  {d_tag}  {cmd}  ({client_ip})\n")

    # ── 日志函数 ────────────────────────────────────────────────────

    @classmethod
    def log_tcp_raw(
        cls,
        *,
        conn_id: str,
        direction: str,
        dst: str,
        mode: str,
        label: str,
        data: bytes,
        username: str = "",
    ) -> None:
        """tcp_raw.log — 经过代理的 TCP 原始分片（上下行，全量记录）"""
        if cls.ai_machine_enabled():
            if not data or not cls._ai_allow(username):
                return
            try:
                ai_log_v128.write_raw_tcp_request(
                    data_dir=DATA_DIR,
                    config=app_config,
                    conn_id=conn_id,
                    direction=direction,
                    dst=dst,
                    mode=mode,
                    label=label,
                    data=data,
                    username=username,
                )
            except (OSError, TypeError, ValueError):
                pass
            return
        if not cls._allow(username):
            return
        if not data:
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        hx = data.hex().upper()
        meta = f"{ts}\t{label}\t{mode}\t{conn_id}\t{direction}\t{dst}\t{len(data)}"
        if len(hx) <= 64:
            line = f"{meta}\t{hx}\n"
        else:
            line = f"{meta}\n{cls._wrap_hex(hx)}\n"
        cls._append("tcp_raw.log", line)

    @classmethod
    def log_01_sliced(
        cls,
        *,
        kind: str,
        direction: str = "",
        uid: str = "",
        data: bytes,
        username: str = "",
    ) -> None:
        """
        01_sliced.log — 01 00 协议 TCP 原始帧记录（完整帧，不做子段提取）。
          kind="recv"   录制/重放端从网络收到的完整 01 00 帧
          kind="sent"   重放端替换后实际发出的完整 01 00 帧
        上下行（direction=↑UP/↓DOWN）、UID 均记录，数据为连续大写 hex。
        """
        if cls.ai_machine_enabled():
            if not data or not cls._ai_allow(username):
                return
            try:
                ai_log_v128.write_stream_frame(
                    data_dir=DATA_DIR,
                    config=app_config,
                    kind=kind,
                    direction=direction,
                    uid=uid,
                    data=data,
                    username=username,
                )
            except (OSError, TypeError, ValueError):
                pass
            return
        if not cls._allow(username):
            return
        if not data:
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        dir_tag = direction if direction else "-"
        uid_tag = uid if uid else "-"
        hx = data.hex().upper()
        header = f"{ts}  kind={kind}  dir={dir_tag}  uid={uid_tag}  LEN={len(data)}\n"
        if len(hx) <= 128:
            body = f"  {hx}\n"
        else:
            body = f"  {cls._wrap_hex(hx)}\n"
        cls._append("01_sliced.log", header + body + "\n")

    @classmethod
    def log_01_replace(
        cls,
        *,
        orig_packet: bytes,
        new_packet: bytes,
        pool_idx: int,
        uid: str = "",
        username: str = "",
    ) -> None:
        """
        01_replace.log — 01 重放替换详情（无条数上限，由用户过滤控制）。
        记录：原始封包 hexdump、替换后封包 hexdump、双份 verify 输出、UID。
        """
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        uid_tag = uid if uid else "-"
        blk = [
            f"\n{'=' * 64}\n",
            f"{ts}  01 REPLACE  uid={uid_tag}  pool_idx={pool_idx}\n",
            "----- 原始封包 HEX+ASCII -----\n",
            cls._hexdump(orig_packet),
            "\n",
            format_01_packet_verify_report(orig_packet),
            "\n----- 替换后封包 HEX+ASCII（实际发出） -----\n",
            cls._hexdump(new_packet),
            "\n",
            format_01_packet_verify_report(new_packet),
            "\n",
        ]
        cls._append("01_replace.log", "".join(blk))

    @classmethod
    def log_33_uplink(
        cls,
        *,
        conn_id: str,
        client_ip: str,
        uid: str = "",
        mode: str = "",
        cipher_bytes: bytes,
        plain_bytes: bytes | None,
        username: str = "",
    ) -> None:
        """
        33_uplink.log — 33 上行帧（录制 / 重放两侧均记录）。
        记录：原始密文 hex、解密明文 hex、明文 ASCII 显示。
        """
        if cls.ai_machine_enabled():
            if cls._ai_allow(username):
                try:
                    ai_log_v128.write_3366_frame(
                        data_dir=DATA_DIR,
                        config=app_config,
                        conn_id=conn_id,
                        direction="↑UP",
                        client_ip=client_ip,
                        uid=uid,
                        mode=mode,
                        frame=cipher_bytes,
                        plaintext=plain_bytes,
                        username=username,
                    )
                except (OSError, TypeError, ValueError):
                    pass
            if not cls.enabled():
                return
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        uid_tag = uid if uid else "-"
        plain_len = len(plain_bytes) if plain_bytes else 0
        header = (
            f"{ts}  ↑UP  {conn_id}  {client_ip}  uid={uid_tag}  mode={mode or '-'}  "
            f"CIPHER={len(cipher_bytes)}B  PLAIN={plain_len}B\n"
        )
        parts = [header]
        parts.append(f"  CIPHER({len(cipher_bytes)}B):\n{cls._hexdump(cipher_bytes)}\n")
        if plain_bytes:
            printable = cls._extract_printable(plain_bytes)
            parts.append(f"  PLAIN_PRINTABLE: {printable}\n")
            parts.append(f"  PLAIN_FULL({plain_len}B):\n{cls._hexdump(plain_bytes)}\n")
            parts.append(f"  PLAIN_TEXT:\n  {cls._decode_utf8_text(plain_bytes)}\n")
            cmd = cls._extract_pb_cmd(plain_bytes)
            if cmd:
                cls._collect_cmd(cmd, "UP", client_ip)
        else:
            parts.append("  PLAIN: (未解密)\n")
        cls._append("33_uplink.log", "".join(parts) + "\n")

    @classmethod
    def log_33_replace(
        cls,
        *,
        conn_id: str,
        client_ip: str,
        uid: str = "",
        orig_frame: bytes,
        new_frame: bytes,
        orig_cipher: bytes,
        orig_plain: bytes,
        new_plain: bytes,
        new_cipher: bytes,
        seq: int | None = None,
        username: str = "",
    ) -> None:
        """
        33_replace.log — 33 重放替换详情（无条数上限，由用户过滤控制）。
        记录：原始密文、原始明文（+ASCII）、替换后明文（+ASCII）、重加密密文。
        """
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        uid_tag = uid if uid else "-"
        seq_str = f"  seq={seq}" if seq is not None else ""
        orig_plain_asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in orig_plain)
        new_plain_asc  = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in new_plain)
        blk = [
            f"\n{'=' * 64}\n",
            f"{ts}  33 REPLACE  uid={uid_tag}  conn={conn_id}  ip={client_ip}"
            f"  frame={len(orig_frame)}B  cipher={len(orig_cipher)}B  plain={len(orig_plain)}B{seq_str}\n",
            "----- 原始密文 HEX -----\n",
            cls._wrap_hex(orig_cipher.hex().upper()),
            "\n----- 原始明文 HEX -----\n",
            cls._wrap_hex(orig_plain.hex().upper()),
            f"\n  ASCII: {orig_plain_asc}\n",
            "----- 替换后明文 HEX -----\n",
            cls._wrap_hex(new_plain.hex().upper()),
            f"\n  ASCII: {new_plain_asc}\n",
            "----- 重加密密文 HEX（实际发出） -----\n",
            cls._wrap_hex(new_cipher.hex().upper()),
            "\n",
        ]
        cls._append("33_replace.log", "".join(blk))

    @classmethod
    def log_33_downlink(
        cls,
        *,
        conn_id: str,
        client_ip: str,
        cipher_bytes: bytes,
        plain_bytes: bytes | None,
        username: str = "",
        uid: str = "",
        mode: str = "",
    ) -> None:
        """
        33_downlink.log — 33 下行帧（所有帧均记录，无论能否解密）。
        记录前 64B 原始密文 hex（便于在 tcp_raw.log 中定位）+ 明文中的可打印字符串。
        """
        if cls.ai_machine_enabled():
            if cls._ai_allow(username):
                try:
                    ai_log_v128.write_3366_frame(
                        data_dir=DATA_DIR,
                        config=app_config,
                        conn_id=conn_id,
                        direction="↓DOWN",
                        client_ip=client_ip,
                        uid=uid,
                        mode=mode,
                        frame=cipher_bytes,
                        plaintext=plain_bytes,
                        username=username,
                    )
                except (OSError, TypeError, ValueError):
                    pass
            if not cls.enabled():
                return
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        cipher_head = cipher_bytes[:64]
        plain_len = len(plain_bytes) if plain_bytes else 0
        header = (
            f"{ts}  ↓DOWN  {conn_id}  {client_ip}  "
            f"CIPHER={len(cipher_bytes)}B  PLAIN={plain_len}B\n"
        )
        parts = [header]
        parts.append(f"  CIPHER({len(cipher_bytes)}B):\n{cls._hexdump(cipher_bytes)}\n")
        if plain_bytes:
            printable = cls._extract_printable(plain_bytes)
            parts.append(f"  PLAIN_PRINTABLE: {printable}\n")
            parts.append(f"  PLAIN_FULL({plain_len}B):\n{cls._hexdump(plain_bytes)}\n")
            parts.append(f"  PLAIN_TEXT:\n  {cls._decode_utf8_text(plain_bytes)}\n")
            cmd = cls._extract_pb_cmd(plain_bytes)
            if cmd:
                cls._collect_cmd(cmd, "DOWN", client_ip)
        else:
            parts.append("  PLAIN: (未解密)\n")
        parts.append("\n")
        cls._append("33_downlink.log", "".join(parts))

    @classmethod
    def log_3366_record_reason(
        cls,
        *,
        client_ip: str,
        conn_id: str,
        reason: str,
        detail: str = "",
        username: str = "",
        uid: str = "",
    ) -> None:
        """3366_record_reason.log — 33 未入池时写入原因，便于排查"""
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        uid_tag = f"\tUID={uid}" if uid else ""
        line = f"{ts}\t{client_ip}\t{conn_id}{uid_tag}\t{reason}"
        if detail:
            line += f"\t{detail}"
        line += "\n"
        cls._append("3366_record_reason.log", line)

    @classmethod
    def log_3366_raw_high_entropy_drop(
        cls,
        *,
        conn_id: str,
        client_ip: str,
        direction: str,
        msg_hex: str,
        frame_len: int,
        frame_full_hex: str | None = None,
        username: str = "",
    ) -> None:
        """3366_raw_high_entropy_drop.log — 3366 含 01 0A 00 09 或 01 0A 00 23 丢包记录"""
        if not cls._allow(username):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        line = (
            f"\n{ts}\t{conn_id}\t{client_ip}\t{direction}\tmsg={msg_hex}\t"
            f"frame_len={frame_len}B\n"
        )
        if frame_full_hex:
            line += "----- 原始请求完整 HEX -----\n"
            line += cls._wrap_hex(frame_full_hex)
            line += "\n\n"
        cls._append("3366_raw_high_entropy_drop.log", line)

    # ── 旧接口兼容层（转发到新函数，调用点逐步迁移后可移除） ─────────

    @classmethod
    def log_tcp_chunk(cls, *, conn_id, direction, dst, mode, label, data, username=""):
        cls.log_tcp_raw(conn_id=conn_id, direction=direction, dst=dst,
                        mode=mode, label=label, data=data, username=username)

    @classmethod
    def log_sliced_01_0a_line(cls, source: str, data: bytes, username: str = "") -> None:
        pass  # 已由 log_01_sliced 替代，此接口废弃

    @classmethod
    def log_3366_trace(cls, **kwargs) -> None:
        pass  # 已拆分到 33_uplink.log / 33_downlink.log

    @classmethod
    def log_3366_user_detail(cls, **kwargs) -> None:
        pass  # 已合并到 33_uplink.log

    @classmethod
    def log_3366_replay_replace(cls, *, conn_id, client_ip, orig_frame, new_frame,
                                 orig_cipher, orig_plain, new_plain, new_cipher,
                                 seq=None, username=""):
        cls.log_33_replace(conn_id=conn_id, client_ip=client_ip,
                           orig_frame=orig_frame, new_frame=new_frame,
                           orig_cipher=orig_cipher, orig_plain=orig_plain,
                           new_plain=new_plain, new_cipher=new_cipher,
                           seq=seq, username=username)

    @classmethod
    def log_3366_replay_uplink_frame(cls, *, conn_id, client_ip, msg_hex,
                                      frame, plain_hex=None, skip_reason, username=""):
        plain_bytes = bytes.fromhex(plain_hex) if plain_hex else None
        cls.log_33_uplink(conn_id=conn_id, client_ip=client_ip, mode="replay",
                          cipher_bytes=frame, plain_bytes=plain_bytes, username=username)

    @classmethod
    def log_3366_replay_downlink_trace(cls, *, conn_id, client_ip, msg_hex,
                                        frame, plain_bytes, username=""):
        cls.log_33_downlink(conn_id=conn_id, client_ip=client_ip,
                            cipher_bytes=frame, plain_bytes=plain_bytes, username=username)

    @classmethod
    def log_01_replay_replace_pair(cls, *, orig_packet, new_packet, pool_idx, username=""):
        cls.log_01_replace(orig_packet=orig_packet, new_packet=new_packet,
                           pool_idx=pool_idx, username=username)


traffic_file_logger = TrafficSessionLog
