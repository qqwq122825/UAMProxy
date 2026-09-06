import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

import core.traffic_session_log as traffic_module
from core.ai_log_v128 import AI_LOG_DIR_NAME, V128AiLog, ai_log_v128
from core.config import app_config
from core.crypto import _ace_01_reassemble_frames, _ace_try_replay_template
from core.traffic_session_log import TrafficSessionLog
from tests.test_type9_hot_rules import frame, leaf
from tools.package_01_learning_bundle import package


class V128AiLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_data_dir = traffic_module.DATA_DIR
        self.old_values = {
            key: app_config.get(key)
            for key in (
                "ai_log_enabled",
                "ai_log_machine_only",
                "ai_log_user_filter",
                "legacy_text_log_enabled",
                "replenish_01_mode",
                "detail_01_log",
                "detail_01_log_users",
                "ai_log_periodic_full_every",
                "ai_log_retention_days",
                "ai_log_max_gb",
            )
        }
        traffic_module.DATA_DIR = self.temp.name
        app_config.set("ai_log_enabled", True)
        app_config.set("ai_log_machine_only", True)
        app_config.set("ai_log_user_filter", "")
        app_config.set("legacy_text_log_enabled", False)
        app_config.set("replenish_01_mode", True)
        app_config.set("detail_01_log", True)
        app_config.set("detail_01_log_users", "test")
        app_config.set("ai_log_periodic_full_every", 0)
        app_config.set("ai_log_retention_days", 7)
        app_config.set("ai_log_max_gb", 10.0)
        ai_log_v128.reset()
        TrafficSessionLog._analysis_01_dir = None
        TrafficSessionLog._persistent_01_path = None

    def tearDown(self):
        traffic_module.DATA_DIR = self.old_data_dir
        for key, value in self.old_values.items():
            app_config.set(key, value)
        ai_log_v128.reset()
        self.temp.cleanup()

    @staticmethod
    def read_jsonl(path):
        with open(path, encoding="utf-8") as stream:
            return [json.loads(line) for line in stream]

    def test_run_is_under_config_ai_log_and_record_frame_is_jsonl(self):
        path = TrafficSessionLog.begin_persistent_01_record_run()
        self.assertEqual(os.path.basename(path), "record_frames.jsonl")
        run_dir = os.path.dirname(path)
        self.assertEqual(os.path.basename(os.path.dirname(run_dir)), AI_LOG_DIR_NAME)
        with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as stream:
            manifest = json.load(stream)
        self.assertEqual(manifest["schema"], "dfm-ai-log-manifest-v1")
        self.assertEqual(manifest["app_version"], "v1.131.0")
        self.assertEqual(manifest["record_format"], "jsonl-one-object-per-line")
        self.assertIn("v128_model_revision", manifest)
        self.assertEqual(
            manifest["v131_builtin_800d"],
            {
                "message_id": "0x800D",
                "seed_revision": "v131-history-328-zero-deviation-r1",
                "anchor_slots": [60, 660],
                "period": 600,
                "policy": "LIVE_THEN_RECORDED_DONOR_THEN_BUILTIN",
            },
        )
        self.assertEqual(
            manifest["control_audit_revision"],
            "v129-operation-state-audit-r1",
        )
        self.assertEqual(
            manifest["files"]["control_events"],
            "control_events.jsonl",
        )
        self.assertEqual(
            manifest["files"]["raw_tcp_requests"],
            "raw_tcp_requests.jsonl",
        )
        self.assertEqual(
            manifest["files"]["record_01_slices"],
            "record_01_slices.jsonl",
        )

        control_path = ai_log_v128.write_control_event(
            source="test",
            actor="operator",
            action="config_flags_changed",
            details={
                "changed": {
                    "replenish_01_mode": {"before": False, "after": True}
                }
            },
            state={
                "engine": {"running": True},
                "hot_rules": {
                    "generation": 2,
                    "rule_changed_counts": {
                        "1105-clean-module-enumeration": 59
                    },
                },
            },
        )
        self.assertEqual(os.path.basename(control_path), "control_events.jsonl")
        control = [
            row for row in self.read_jsonl(control_path)
            if row.get("action") == "config_flags_changed"
        ][-1]
        self.assertEqual(control["schema"], "dfm-ai-control-event-v129-v1")
        self.assertEqual(control["action"], "config_flags_changed")
        self.assertTrue(control["state"]["engine"]["running"])
        self.assertEqual(
            control["state"]["hot_rules"]["rule_changed_counts"][
                "1105-clean-module-enumeration"
            ],
            59,
        )

        source = frame(
            leaf(1, fill=0x11, message_id=0x1004, length=44),
            account_id="GAME-AI",
            report_index=1,
        )
        written = TrafficSessionLog.log_persistent_01_record_packet(
            direction="↑UP",
            client_ip="127.0.0.1",
            conn_id="conn-ai",
            uid="GAME-AI",
            data=source,
            username="any-user",
        )
        self.assertEqual(written, path)
        row = self.read_jsonl(path)[0]
        self.assertEqual(row["schema"], "dfm-ai-01-record-frame-v1")
        self.assertEqual(row["packet"]["frames_hex"], [source.hex().upper()])
        self.assertTrue(row["packet"]["frame_validation_ok"])
        self.assertFalse(os.path.exists(os.path.join(self.temp.name, "01RecordPackets")))

        slices_path = os.path.join(run_dir, "record_01_slices.jsonl")
        physical_slice = self.read_jsonl(slices_path)[0]
        self.assertEqual(
            physical_slice["schema"], "dfm-ai-01-physical-slice-v1"
        )
        self.assertEqual(physical_slice["source_event_id"], row["event_id"])
        self.assertEqual(physical_slice["raw_01_hex"], source.hex().upper())
        self.assertEqual(physical_slice["slice_length"], len(source))

        TrafficSessionLog.log_tcp_raw(
            conn_id="conn-ai",
            direction="↑UP",
            dst="TARGET:PORT",
            mode="record",
            label="test-server",
            data=b"\x01\x00RAW-TCP-CHUNK",
            username="test",
        )
        raw_request = self.read_jsonl(
            os.path.join(run_dir, "raw_tcp_requests.jsonl")
        )[0]
        self.assertEqual(raw_request["schema"], "dfm-ai-raw-tcp-request-v1")
        self.assertEqual(raw_request["raw_tcp_hex"], b"\x01\x00RAW-TCP-CHUNK".hex().upper())
        self.assertEqual(raw_request["capture_stage"], "socket_read_pre_protocol_split")
        app_config.set("detail_01_log", False)
        TrafficSessionLog.log_tcp_raw(
            conn_id="conn-ai",
            direction="↑UP",
            dst="TARGET:PORT",
            mode="record",
            label="test-server",
            data=b"NOT-STORED-WHEN-DETAIL-OFF",
            username="test",
        )
        self.assertEqual(
            len(self.read_jsonl(os.path.join(run_dir, "raw_tcp_requests.jsonl"))),
            1,
        )
        app_config.set("detail_01_log", True)

        assembled = _ace_01_reassemble_frames([source])
        self.assertIsNotNone(assembled)
        report_path = TrafficSessionLog.log_persistent_01_message_item(
            client_ip="127.0.0.1",
            session={
                "sid": "session-ai",
                "game_id": "GAME-AI",
                "owner_username": "any-user",
            },
            item={"raw_packet": assembled[1], "report_index": 1},
        )
        self.assertEqual(os.path.basename(report_path), "record_reports.jsonl")
        report = self.read_jsonl(report_path)[0]
        record_leaf = self.read_jsonl(
            os.path.join(run_dir, "record_leaves.jsonl")
        )[0]
        self.assertEqual(report["leaf_count"], 1)
        self.assertEqual(record_leaf["message_id"], 0x1004)
        self.assertEqual(record_leaf["raw_hex"], leaf(
            1, fill=0x11, message_id=0x1004, length=44
        ).hex().upper())

        session_path = TrafficSessionLog.log_record_session_event(
            action="START",
            session={
                "sid": "session-ai",
                "owner_username": "any-user",
                "game_id": "GAME-AI",
                "pool_items": [{"source": "01"}],
            },
            client_ip="127.0.0.1",
        )
        self.assertEqual(os.path.basename(session_path), "record_sessions.jsonl")
        self.assertEqual(self.read_jsonl(session_path)[0]["counts"]["01"], 1)

        selection_path = TrafficSessionLog.log_01_replay_template_selection(
            username="any-user",
            client_ip="127.0.0.1",
            conn_id="conn-ai",
            live_game_id="GAME-AI",
            selected={
                "personal_01_count": 3,
                "official_01_count": 2,
                "official_sources": ["official-v7"],
            },
        )
        selection = self.read_jsonl(selection_path)[0]
        self.assertEqual(selection["schema"], "dfm-ai-01-template-selection-v1")
        self.assertEqual(selection["template_mode"], "player_primary_with_official_fallback")
        self.assertEqual(selection["time_unix_ms"].__class__, int)

        reconnect_path = TrafficSessionLog.log_01_reconnect_event(
            phase="BIND_DECISION",
            username="any-user",
            client_ip="127.0.0.1",
            conn_id="conn-ai-2",
            game_id="GAME-AI",
            details={
                "decision": "PENDING_LIVE_REPORT",
                "session_token_u32": 0x9ABF276F,
                "unix_time_u32": 0x6A8C48F4,
            },
        )
        self.assertEqual(os.path.basename(reconnect_path), "reconnect_events.jsonl")
        reconnect = self.read_jsonl(reconnect_path)[0]
        self.assertEqual(reconnect["schema"], "dfm-ai-01-reconnect-v130-v1")
        self.assertEqual(reconnect["phase"], "BIND_DECISION")
        self.assertEqual(
            reconnect["details"]["session_token_u32"], 0x9ABF276F
        )

        downlink_path = TrafficSessionLog.log_01_downlink_packet(
            mode="record",
            client_ip="127.0.0.1",
            conn_id="conn-ai",
            uid="GAME-AI",
            data=source,
            username="any-user",
        )
        downlink = self.read_jsonl(downlink_path)[0]
        self.assertEqual(downlink["schema"], "dfm-ai-01-downlink-v1")
        self.assertEqual(downlink["packet"]["frames_hex"], [source.hex().upper()])

        TrafficSessionLog.log_01_sliced(
            kind="recv",
            direction="↑UP",
            uid="GAME-AI",
            data=b"\x01\x00\x00\x00\x05",
            username="any-user",
        )
        stream_row = self.read_jsonl(
            os.path.join(run_dir, "stream_frames.jsonl")
        )[0]
        self.assertEqual(stream_row["schema"], "dfm-ai-01-stream-frame-v1")
        self.assertEqual(stream_row["packet"]["frames_hex"], ["0100000005"])

        archive_path = package(run_dir)
        self.assertTrue(os.path.isfile(archive_path))
        with zipfile.ZipFile(archive_path) as archive:
            names = set(archive.namelist())
        self.assertIn("manifest.json", names)
        self.assertIn("record_frames.jsonl", names)
        self.assertIn("raw_tcp_requests.jsonl", names)
        self.assertIn("record_01_slices.jsonl", names)
        self.assertIn("record_leaves.jsonl", names)
        self.assertIn("control_events.jsonl", names)

    def test_log_cleanup_applies_age_and_capacity_limits(self):
        root = os.path.join(self.temp.name, AI_LOG_DIR_NAME)
        os.makedirs(root, exist_ok=True)
        old = os.path.join(root, "run_20200101_old")
        first = os.path.join(root, "run_20260824_first")
        second = os.path.join(root, "run_20260824_second")
        for path in (old, first, second):
            os.makedirs(path)
            with open(os.path.join(path, "sample.bin"), "wb") as stream:
                stream.write(b"X" * 1024)
        now = time.time()
        os.utime(old, (now - 10 * 86400, now - 10 * 86400))
        os.utime(first, (now - 20, now - 20))
        os.utime(second, (now - 10, now - 10))

        logger = V128AiLog()
        result = logger.cleanup_runs(
            self.temp.name,
            {
                "ai_log_retention_days": 7,
                "ai_log_max_gb": 0.0000015,
            },
        )
        self.assertFalse(os.path.exists(old))
        self.assertFalse(os.path.exists(first))
        self.assertTrue(os.path.isdir(second))
        self.assertEqual(
            set(result["removed_runs"]),
            {"run_20200101_old", "run_20260824_first"},
        )

    def test_clear_all_logs_rotates_to_fresh_run_when_active(self):
        logger = V128AiLog()
        first_run = logger.start_run(
            self.temp.name,
            app_config,
            force_new=True,
        )
        logger.append("markers", {"schema": "before-clear"})
        loose = os.path.join(self.temp.name, AI_LOG_DIR_NAME, "loose.tmp")
        with open(loose, "wb") as stream:
            stream.write(b"X" * 128)

        result = logger.clear_all_logs(
            self.temp.name,
            app_config,
            start_fresh_run=True,
        )

        self.assertFalse(os.path.exists(first_run))
        self.assertTrue(result["fresh_run_started"])
        self.assertNotEqual(result["new_run_dir"], first_run)
        self.assertTrue(
            os.path.isfile(os.path.join(result["new_run_dir"], "manifest.json"))
        )
        self.assertGreaterEqual(result["removed_count"], 2)
        logger.append("markers", {"schema": "after-clear"})
        self.assertTrue(os.path.isfile(logger.path("markers")))

    def test_clear_all_logs_while_stopped_leaves_empty_root(self):
        logger = V128AiLog()
        logger.start_run(self.temp.name, app_config, force_new=True)
        result = logger.clear_all_logs(
            self.temp.name,
            app_config,
            start_fresh_run=False,
        )
        root = os.path.join(self.temp.name, AI_LOG_DIR_NAME)
        self.assertEqual(os.listdir(root), [])
        self.assertFalse(result["fresh_run_started"])
        self.assertIsNone(logger.run_dir)

    def test_v128_multi_group_output_is_normalized_and_script_validates(self):
        TrafficSessionLog.begin_persistent_01_record_run()
        run_dir = TrafficSessionLog.begin_01_replay_analysis_run()
        cursor = [0, 0, {}]

        details = []
        live_21 = frame(
            leaf(75, fill=0x22, message_id=0x1004, length=44),
            account_id="GAME-AI",
            report_index=21,
        )
        output_21, changed = _ace_try_replay_template(
            [live_21],
            [],
            cursor,
            expected_game_id="GAME-AI",
            on_log=details.append,
            session_elapsed_seconds=31.0,
        )
        self.assertTrue(changed)
        self.assertEqual(len(output_21), 2)
        path = TrafficSessionLog.log_01_replay_analysis_event(
            detail=details[-1],
            username="any-user",
            client_ip="127.0.0.1",
            conn_id="conn-ai",
        )
        self.assertEqual(path, os.path.join(run_dir, "replay_events.jsonl"))

        details = []
        live_22 = frame(
            leaf(76, fill=0x33, message_id=0x1004, length=44),
            account_id="GAME-AI",
            report_index=22,
        )
        _ace_try_replay_template(
            [live_22],
            [],
            cursor,
            expected_game_id="GAME-AI",
            on_log=details.append,
            session_elapsed_seconds=32.0,
        )
        TrafficSessionLog.log_01_replay_analysis_event(
            detail=details[-1],
            username="any-user",
            client_ip="127.0.0.1",
            conn_id="conn-ai",
        )

        events = self.read_jsonl(os.path.join(run_dir, "replay_events.jsonl"))
        groups = self.read_jsonl(os.path.join(run_dir, "replay_groups.jsonl"))
        leaves = self.read_jsonl(os.path.join(run_dir, "replay_leaves.jsonl"))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["group_counts"]["output"], 2)
        self.assertEqual(events[0]["v128"]["injected_report_count"], 1)
        self.assertEqual(events[0]["v128"]["injected_leaf_count"], 16)
        self.assertEqual(events[0]["v128"]["offsets_after"]["leaf_offset"], 16)

        output_groups = [row for row in groups if row["phase"] == "output"]
        self.assertEqual(
            [row["source"] for row in output_groups],
            ["native", "v128_central9", "native"],
        )
        self.assertEqual(
            [row["packet"]["report_index"] for row in output_groups],
            [21, 22, 23],
        )
        output_leaves = [row for row in leaves if row["phase"] == "output"]
        self.assertEqual(
            [row["record_sequence"] for row in output_leaves],
            list(range(75, 93)),
        )
        injected = [row for row in output_leaves if row["source"] == "v128_central9"]
        self.assertEqual(len(injected), 16)
        self.assertTrue(all(row["raw_hex"] for row in injected))

        completed = subprocess.run(
            [sys.executable, "tools/analyze_ai_logs.py", run_dir],
            cwd=os.path.dirname(os.path.dirname(__file__)),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        summary = json.loads(completed.stdout)
        self.assertTrue(summary["pass"])
        self.assertEqual(summary["counts"]["output_source_v128_central9"], 1)

    def test_two_tier_profiles_keep_all_users_and_promote_anomalies(self):
        app_config.set("ai_log_user_filter", "test")  # v128.2旧白名单不再丢其他用户
        path = TrafficSessionLog.begin_persistent_01_record_run()
        normal = frame(
            leaf(1, fill=0x11, message_id=0x1004, length=44),
            account_id="GAME-PROFILE",
            report_index=1,
        )

        TrafficSessionLog.log_persistent_01_record_packet(
            direction="↑UP", client_ip="1.1.1.1", conn_id="test-1",
            uid="GAME-PROFILE", data=normal, username="test",
        )
        TrafficSessionLog.log_persistent_01_record_packet(
            direction="↑UP", client_ip="2.2.2.2", conn_id="other-1",
            uid="GAME-PROFILE", data=normal, username="other",
        )
        TrafficSessionLog.log_persistent_01_record_packet(
            direction="↑UP", client_ip="2.2.2.2", conn_id="other-1",
            uid="GAME-PROFILE", data=normal, username="other",
        )

        rows = self.read_jsonl(path)
        self.assertEqual([row["log_profile"] for row in rows], ["full", "compact", "compact"])
        self.assertTrue(rows[0]["packet"]["frames_hex"])
        self.assertTrue(rows[1]["packet"]["frames_hex"])  # 该用户首份新结构自动升级
        self.assertIsNone(rows[2]["packet"]["frames_hex"])
        self.assertTrue(rows[2]["packet"]["frames_sha256"])
        self.assertEqual(rows[2]["packet"]["message_ids"], [0x1004])

        app_config.set("detail_01_log", False)
        TrafficSessionLog.log_persistent_01_record_packet(
            direction="↑UP", client_ip="1.1.1.1", conn_id="test-1",
            uid="GAME-PROFILE", data=normal, username="test",
        )
        rows = self.read_jsonl(path)
        self.assertEqual(rows[-1]["log_profile"], "compact")
        self.assertIsNone(rows[-1]["packet"]["frames_hex"])

        hot = frame(
            leaf(2, fill=0x22, message_id=0x0207, length=116),
            account_id="GAME-PROFILE",
            report_index=2,
        )
        TrafficSessionLog.log_persistent_01_record_packet(
            direction="↑UP", client_ip="2.2.2.2", conn_id="other-1",
            uid="GAME-PROFILE", data=hot, username="other",
        )
        rows = self.read_jsonl(path)
        self.assertTrue(rows[-1]["packet"]["frames_hex"])
        self.assertIn("hot_message:0x0207", rows[-1]["full_capture_reasons"])
        anomalies = self.read_jsonl(
            os.path.join(os.path.dirname(path), "anomaly_full.jsonl")
        )
        self.assertTrue(any(
            "hot_message:0x0207" in row.get("reasons", [])
            for row in anomalies
        ))

        user_bundle = package(os.path.dirname(path), user="other")
        with zipfile.ZipFile(user_bundle) as archive:
            filtered = [
                json.loads(line)
                for line in archive.read("record_frames.jsonl").decode("utf-8").splitlines()
            ]
        self.assertTrue(filtered)
        self.assertEqual(
            {row.get("proxy_username") for row in filtered}, {"other"}
        )


if __name__ == "__main__":
    unittest.main()
