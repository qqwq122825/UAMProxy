import json
import hashlib
import os
import tempfile
import unittest
import zlib

import core.traffic_session_log as traffic_module
from core.type9_crypto import KEYS, type9_transform


def _analysis_frame(marker_type: int = 0x52) -> bytes:
    account = b"UID-ANALYSIS"
    logical = (
        b"\x00" * 5
        + b"\x01\x0A\x00\x23"
        + (16).to_bytes(4, "big")
        + b"\x00" * 10
        + bytes([len(account)])
        + account
        + b"\x00"
        + b"\x01\x0A\x00"
        + bytes([marker_type])
        + b"\x00" * 20
    )
    frame = bytearray(55)
    frame[0:3] = b"\x01\x00\x00"
    frame[6:10] = b"\x01\x02\x03\x04"
    frame[18:38] = bytes(range(20))
    frame[38:40] = (1).to_bytes(2, "big")
    frame[40:44] = (zlib.crc32(logical) & 0xFFFFFFFF).to_bytes(4, "big")
    frame[44] = 1
    frame[45:47] = (9).to_bytes(2, "big")
    frame[47] = 0x70
    frame[49:51] = (1).to_bytes(2, "big")
    frame[51:55] = len(logical).to_bytes(4, "big")
    frame += logical
    frame[3:5] = len(frame).to_bytes(2, "big")
    return bytes(frame)


def _type9_leaf_payload(message_id: int = 0x0207) -> bytes:
    leaf = bytearray(116)
    leaf[0:4] = (1).to_bytes(4, "big")
    leaf[4:6] = len(leaf).to_bytes(2, "big")
    leaf[6:10] = (0x0102000A).to_bytes(4, "big")
    leaf[10:14] = (7).to_bytes(4, "big")
    leaf[0x16:0x18] = message_id.to_bytes(2, "big")
    selector, key_index = 0, 2
    cipher = type9_transform(bytes(leaf), selector, KEYS[key_index], direction=1)
    record = (
        bytes([selector, key_index])
        + (zlib.crc32(leaf) & 0xFFFFFFFF).to_bytes(4, "big")
        + len(cipher).to_bytes(2, "big")
        + cipher
    )
    return b"\x01\x0A\x00\x09" + b"\x00" * 10 + record


class Persistent01RecordLogTests(unittest.TestCase):
    def setUp(self):
        self.old_data_dir = traffic_module.DATA_DIR
        self.old_path = traffic_module.TrafficSessionLog._persistent_01_path
        self.old_downlink_path = (
            traffic_module.TrafficSessionLog._persistent_01_downlink_path
        )
        self.old_message_leaf_path = (
            traffic_module.TrafficSessionLog._persistent_01_message_leaf_path
        )
        self.old_downlink_id = (
            traffic_module.TrafficSessionLog._persistent_01_downlink_event_id
        )
        self.old_message_leaf_id = (
            traffic_module.TrafficSessionLog._persistent_01_message_leaf_event_id
        )
        self.old_record_session_id = (
            traffic_module.TrafficSessionLog._persistent_record_session_event_id
        )
        self.old_analysis_dir = traffic_module.TrafficSessionLog._analysis_01_dir
        self.old_analysis_id = traffic_module.TrafficSessionLog._analysis_01_event_id
        self.old_analysis_downlink_id = (
            traffic_module.TrafficSessionLog._analysis_01_downlink_event_id
        )
        self.old_analysis_selection_id = (
            traffic_module.TrafficSessionLog._analysis_01_selection_event_id
        )
        self.old_analysis_usage_id = (
            traffic_module.TrafficSessionLog._analysis_01_usage_event_id
        )
        self.old_analysis_state = traffic_module.TrafficSessionLog._analysis_01_conn_state
        self.old_analysis_game_state = (
            traffic_module.TrafficSessionLog._analysis_01_game_state
        )
        self.old_unknown_leaf_stats = (
            traffic_module.TrafficSessionLog._analysis_01_unknown_leaf_stats
        )
        self.old_tfp_called_stats = (
            traffic_module.TrafficSessionLog._analysis_01_tfp_called_stats
        )
        self.old_analysis_learning = (
            traffic_module.TrafficSessionLog._analysis_01_learning
        )
        self.old_detail_01_log = traffic_module.app_config.get("detail_01_log")
        self.old_ai_log_machine_only = traffic_module.app_config.get(
            "ai_log_machine_only"
        )
        self.temp_dir = tempfile.TemporaryDirectory()
        traffic_module.DATA_DIR = self.temp_dir.name
        traffic_module.TrafficSessionLog._persistent_01_path = None
        traffic_module.TrafficSessionLog._persistent_01_downlink_path = None
        traffic_module.TrafficSessionLog._persistent_01_message_leaf_path = None
        traffic_module.TrafficSessionLog._persistent_01_downlink_event_id = 0
        traffic_module.TrafficSessionLog._persistent_01_message_leaf_event_id = 0
        traffic_module.TrafficSessionLog._persistent_record_session_event_id = 0
        traffic_module.TrafficSessionLog._analysis_01_dir = None
        traffic_module.TrafficSessionLog._analysis_01_event_id = 0
        traffic_module.TrafficSessionLog._analysis_01_downlink_event_id = 0
        traffic_module.TrafficSessionLog._analysis_01_selection_event_id = 0
        traffic_module.TrafficSessionLog._analysis_01_usage_event_id = 0
        traffic_module.TrafficSessionLog._analysis_01_conn_state = {}
        traffic_module.TrafficSessionLog._analysis_01_game_state = {}
        traffic_module.TrafficSessionLog._analysis_01_unknown_leaf_stats = {}
        traffic_module.TrafficSessionLog._analysis_01_tfp_called_stats = {}
        traffic_module.TrafficSessionLog._analysis_01_learning = None
        traffic_module.app_config.set("detail_01_log", False)
        # 本组保留v6兼容读写回归；v128机器日志由
        # test_ai_log_v128.py独立覆盖。
        traffic_module.app_config.set("ai_log_machine_only", False)

    def tearDown(self):
        traffic_module.DATA_DIR = self.old_data_dir
        traffic_module.TrafficSessionLog._persistent_01_path = self.old_path
        traffic_module.TrafficSessionLog._persistent_01_downlink_path = self.old_downlink_path
        traffic_module.TrafficSessionLog._persistent_01_message_leaf_path = (
            self.old_message_leaf_path
        )
        traffic_module.TrafficSessionLog._persistent_01_downlink_event_id = self.old_downlink_id
        traffic_module.TrafficSessionLog._persistent_01_message_leaf_event_id = (
            self.old_message_leaf_id
        )
        traffic_module.TrafficSessionLog._persistent_record_session_event_id = (
            self.old_record_session_id
        )
        traffic_module.TrafficSessionLog._analysis_01_dir = self.old_analysis_dir
        traffic_module.TrafficSessionLog._analysis_01_event_id = self.old_analysis_id
        traffic_module.TrafficSessionLog._analysis_01_downlink_event_id = (
            self.old_analysis_downlink_id
        )
        traffic_module.TrafficSessionLog._analysis_01_selection_event_id = (
            self.old_analysis_selection_id
        )
        traffic_module.TrafficSessionLog._analysis_01_usage_event_id = (
            self.old_analysis_usage_id
        )
        traffic_module.TrafficSessionLog._analysis_01_conn_state = self.old_analysis_state
        traffic_module.TrafficSessionLog._analysis_01_game_state = (
            self.old_analysis_game_state
        )
        traffic_module.TrafficSessionLog._analysis_01_unknown_leaf_stats = (
            self.old_unknown_leaf_stats
        )
        traffic_module.TrafficSessionLog._analysis_01_tfp_called_stats = (
            self.old_tfp_called_stats
        )
        traffic_module.TrafficSessionLog._analysis_01_learning = (
            self.old_analysis_learning
        )
        traffic_module.app_config.set("detail_01_log", self.old_detail_01_log)
        traffic_module.app_config.set(
            "ai_log_machine_only", self.old_ai_log_machine_only
        )
        self.temp_dir.cleanup()

    def test_test_record_frames_are_kept_in_separate_timestamped_runs(self):
        first_path = traffic_module.TrafficSessionLog.begin_persistent_01_record_run()
        self.assertIsNotNone(first_path)
        self.assertEqual(
            os.path.basename(os.path.dirname(first_path)),
            "01RecordPackets",
        )

        ignored = traffic_module.TrafficSessionLog.log_persistent_01_record_packet(
            direction="↑UP",
            client_ip="127.0.0.1",
            conn_id="127.0.0.1:1000",
            uid="UID-1",
            data=b"\x01\x00\x00\x00\x05",
            username="other",
        )
        self.assertIsNone(ignored)
        self.assertFalse(os.path.exists(first_path))

        written = traffic_module.TrafficSessionLog.log_persistent_01_record_packet(
            direction="↑UP",
            client_ip="127.0.0.1",
            conn_id="127.0.0.1:1000",
            uid="UID-1",
            data=b"\x01\x00\x00\x00\x05",
            username="test",
        )
        self.assertEqual(written, first_path)
        self.assertTrue(os.path.isfile(first_path))
        with open(first_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("user=test", content)
        self.assertIn("dir=↑UP", content)
        self.assertIn("uid=UID-1", content)
        self.assertIn("LEN=5", content)
        self.assertIn("0100000005", content)
        self.assertIn("SHA256=", content)

        second_path = traffic_module.TrafficSessionLog.begin_persistent_01_record_run()
        self.assertIsNotNone(second_path)
        self.assertNotEqual(second_path, first_path)
        traffic_module.TrafficSessionLog.log_persistent_01_record_packet(
            direction="↓DOWN",
            client_ip="127.0.0.1",
            conn_id="127.0.0.1:1001",
            uid="UID-1",
            data=b"\x01\x00\x00\x00\x05",
            username="test",
        )
        self.assertTrue(os.path.isfile(first_path))
        self.assertTrue(os.path.isfile(second_path))

    def test_record_and_replay_downlink_have_dedicated_jsonl(self):
        traffic_module.TrafficSessionLog.begin_persistent_01_record_run()
        frame = _analysis_frame(0x52)
        record_path = traffic_module.TrafficSessionLog.log_01_downlink_packet(
            mode="record",
            client_ip="127.0.0.1",
            conn_id="record-conn",
            uid="UID-ANALYSIS",
            data=frame,
            username="test",
            disposition="FORWARD",
            reason="RECORD_SERVER_DOWNLINK",
        )
        self.assertIn("test_01_downlink_", os.path.basename(record_path))
        with open(record_path, "r", encoding="utf-8") as f:
            recorded = json.loads(f.readline())
        self.assertEqual(recorded["mode"], "RECORD")
        self.assertEqual(recorded["direction"], "DOWN")
        self.assertNotIn("frames_hex", recorded["packet"])
        self.assertEqual(
            recorded["packet"]["sha256"], hashlib.sha256(frame).hexdigest()
        )

        run_dir = traffic_module.TrafficSessionLog.begin_01_replay_analysis_run()
        replay_path = traffic_module.TrafficSessionLog.log_01_downlink_packet(
            mode="replay",
            client_ip="127.0.0.1",
            conn_id="replay-conn",
            uid="UID-ANALYSIS",
            data=frame,
            username="test",
            disposition="DROP_THRESHOLD",
            reason="LEN_2000_GT_1000",
        )
        self.assertEqual(
            replay_path, os.path.join(run_dir, "01_downlink_events.jsonl")
        )
        with open(replay_path, "r", encoding="utf-8") as f:
            replayed = json.loads(f.readline())
        self.assertEqual(replayed["mode"], "REPLAY")
        self.assertEqual(replayed["disposition"], "DROP_THRESHOLD")
        self.assertEqual(replayed["reason"], "LEN_2000_GT_1000")
        self.assertTrue(replayed["packet"]["crc_ok"])

    def test_decoded_message_leaf_log_is_written_without_detail_frame_log(self):
        traffic_module.TrafficSessionLog.begin_persistent_01_record_run()
        path = traffic_module.TrafficSessionLog.log_persistent_01_message_item(
            client_ip="127.0.0.1",
            session={"sid": "SID-1", "game_id": "GAME-1", "owner_username": "test"},
            item={"raw_packet": _type9_leaf_payload(), "report_index": 9},
        )

        self.assertIsNotNone(path)
        self.assertIn("test_01_message_leaves_", os.path.basename(path))
        with open(path, "r", encoding="utf-8") as stream:
            event = json.loads(stream.readline())
        self.assertEqual(event["schema"], "dfm-01-message-leaves-v1")
        self.assertEqual(event["game_id"], "GAME-1")
        self.assertEqual(event["report_index"], 9)
        self.assertEqual(event["top_record_code"], "0x0102000A")
        self.assertEqual(event["leaf_count"], 1)
        self.assertEqual(event["leaves"][0]["message_id"], "0x0207")
        self.assertEqual(event["leaves"][0]["length"], 116)

    def test_experiment_marker_is_written_into_current_analysis_run(self):
        run_dir = traffic_module.TrafficSessionLog.begin_01_replay_analysis_run()

        path = traffic_module.TrafficSessionLog.write_experiment_marker(
            "REPLAY_3366_BLOCK",
            enabled=True,
            details={
                "closed_connections": 2,
                "independent_01": "continue",
            },
        )

        self.assertEqual(path, os.path.join(run_dir, "experiment_markers.jsonl"))
        with open(path, "r", encoding="utf-8") as stream:
            marker = json.loads(stream.readline())
        self.assertEqual(marker["schema"], "dfm-experiment-marker-v1")
        self.assertEqual(marker["marker"], "REPLAY_3366_BLOCK")
        self.assertTrue(marker["enabled"])
        self.assertEqual(marker["details"]["closed_connections"], 2)
        self.assertEqual(marker["details"]["independent_01"], "continue")

    def test_record_session_lifecycle_log_is_persistent_and_tagged(self):
        path = traffic_module.TrafficSessionLog.log_record_session_event(
            action="STOP",
            client_ip="10.0.0.8",
            reason="ALL_RECORD_CONNECTIONS_CLOSED",
            session={
                "sid": "10.0.0.8#1",
                "owner_username": "official-proxy",
                "game_id": "DONOR-8",
                "pool_scope": "official",
                "batch_id": "official-8",
                "batch_name": "weekly",
                "client_version": "1.117",
                "published": True,
                "pool_items": [
                    {"source": "01"},
                    {"source": "3366_09"},
                ],
            },
        )
        self.assertEqual(
            path,
            os.path.join(
                self.temp_dir.name,
                "01RecordPackets",
                "01_record_sessions.jsonl",
            ),
        )
        with open(path, "r", encoding="utf-8") as stream:
            event = json.loads(stream.readline())
        self.assertEqual(event["proxy_username"], "official-proxy")
        self.assertEqual(event["record_role"], "official")
        self.assertEqual(event["batch_id"], "official-8")
        self.assertEqual(event["counts"], {"01": 1, "33": 1, "total": 2})

    def test_template_selection_and_usage_cover_non_test_player(self):
        run_dir = traffic_module.TrafficSessionLog.begin_01_replay_analysis_run()
        selection_path = (
            traffic_module.TrafficSessionLog.log_01_replay_template_selection(
                username="player-proxy",
                client_ip="10.0.0.9",
                conn_id="player-conn",
                live_game_id="PLAYER-9",
                selected={
                    "personal_01_count": 0,
                    "official_01_count": 95,
                    "client_version": "1.117",
                    "official_sources": [{
                        "batch_id": "official-9",
                        "batch_name": "weekly",
                        "client_version": "1.117",
                        "donor_game_id": "DONOR-9",
                        "owner_username": "official-proxy",
                    }],
                },
            )
        )
        with open(selection_path, "r", encoding="utf-8") as stream:
            selected = json.loads(stream.readline())
        self.assertEqual(selected["template_mode"], "official_fallback")
        self.assertEqual(selected["proxy_username"], "player-proxy")
        self.assertEqual(selected["official_01_count"], 95)

        result = traffic_module.TrafficSessionLog.log_01_replay_analysis_event(
            detail={
                "decision": "REPLACE",
                "reason": "SEMANTIC_READY_FULL_CLEAN_REPLACE",
                "account_id": "PLAYER-9",
                "live_game_id": "PLAYER-9",
                "shadow_rebuild": {
                    "replacement_level": "KNOWN_CLEAN",
                    "pruned_leaves": 0,
                    "leaf_results": [{
                        "template_scope": "official",
                        "template_batch_id": "official-9",
                        "donor_game_id": "DONOR-9",
                    }],
                },
            },
            username="player-proxy",
            client_ip="10.0.0.9",
            conn_id="player-conn",
        )
        self.assertIsNone(result)
        usage_path = os.path.join(run_dir, "template_usage_events.jsonl")
        with open(usage_path, "r", encoding="utf-8") as stream:
            usage = json.loads(stream.readline())
        self.assertEqual(usage["template_mode"], "official_fallback")
        self.assertEqual(usage["official_template_leaves"], 1)
        self.assertEqual(usage["official_batch_ids"], ["official-9"])

    def test_v124_tfp_called_writes_rule_and_replacement_statistics(self):
        run_dir = traffic_module.TrafficSessionLog.begin_01_replay_analysis_run()
        traffic_module.TrafficSessionLog.log_01_replay_analysis_event(
            detail={
                "decision": "REPLACE",
                "reason": "TFP_CALLED_NO_TEMPLATE_STRUCTURED_REMOVE",
                "replacement_level": "TFP_CALLED_STRUCTURED_REMOVE",
                "account_id": "PLAYER-TFP",
                "live_game_id": "PLAYER-TFP",
                "report_index": 9,
                "shadow_rebuild": {
                    "replacement_level": "TFP_CALLED_STRUCTURED_REMOVE",
                    "tfp_called_detected_leaves": 1,
                    "tfp_called_template_replaced_leaves": 0,
                    "tfp_called_structured_removed_leaves": 1,
                    "tfp_called_zeroed_leaves": 0,
                    "tfp_called_residual_leaves": 0,
                    "tfp_called_rule_ids": [
                        "v124-tfp-called-no-template-structured-remove"
                    ],
                    "special_handled_leaves": 1,
                    "leaf_results": [{
                        "path": [2],
                        "record_code": 0x01122358,
                        "message_id": None,
                        "length": 225,
                        "candidate_length": 205,
                        "live_sequence": 23,
                        "replacement_level": "TFP_CALLED_STRUCTURED_REMOVE",
                        "tfp_called_detected": True,
                        "tfp_called_rule_id": (
                            "v124-tfp-called-no-template-structured-remove"
                        ),
                        "tfp_called_action": "STRUCTURED_FIELD_REMOVE",
                        "tfp_called_replacement": {
                            "detected": True,
                            "rule_id": (
                                "v124-tfp-called-no-template-structured-remove"
                            ),
                            "action": "STRUCTURED_FIELD_REMOVE",
                            "live_marker_offsets": [151],
                            "candidate_marker_present": False,
                            "live_length": 225,
                            "candidate_length": 205,
                            "live_sha256": "LIVE-SHA",
                            "candidate_sha256": "CANDIDATE-SHA",
                        },
                    }],
                },
            },
            username="test",
            client_ip="127.0.0.1",
            conn_id="conn-tfp",
        )

        events_path = os.path.join(run_dir, "01_tfp_called_events.jsonl")
        stats_path = os.path.join(run_dir, "01_tfp_called_stats.json")
        with open(events_path, "r", encoding="utf-8") as stream:
            event = json.loads(stream.readline())
        with open(stats_path, "r", encoding="utf-8") as stream:
            stats = json.load(stream)
        self.assertEqual(event["record_code"], "0x01122358")
        self.assertEqual(
            event["rule_id"],
            "v124-tfp-called-no-template-structured-remove",
        )
        self.assertEqual(event["action"], "STRUCTURED_FIELD_REMOVE")
        self.assertFalse(event["replacement"]["candidate_marker_present"])
        self.assertEqual(stats["detected_leaves"], 1)
        self.assertEqual(stats["structured_removed_leaves"], 1)
        self.assertEqual(stats["residual_leaves"], 0)
        self.assertEqual(stats["record_codes"]["0x01122358"], 1)

    def test_replay_analysis_records_pass_and_drop_events(self):
        run_dir = traffic_module.TrafficSessionLog.begin_01_replay_analysis_run()
        self.assertIsNotNone(run_dir)
        with open(os.path.join(run_dir, "manifest.json"), "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest["schema"], "dfm-01-replay-v6")
        self.assertEqual(manifest["learning_mode"], "118-tiered-pass-live")
        self.assertIn(
            "mechanically verified", manifest["source_map"]["network_output"]
        )
        frame = _analysis_frame(0x52)
        base = {
            "account_id": "UID-ANALYSIS",
            "report_index": 16,
            "pool_total": 50,
            "cursor_before": 15,
            "cursor_after": 15,
            "pool_idx": None,
            "live_frames": [frame],
            "template_frames": [],
            "output_frames": [frame],
            "validation_errors": [],
        }
        path = traffic_module.TrafficSessionLog.log_01_replay_analysis_event(
            detail={
                **base,
                "decision": "PASS_NON_TARGET",
                "reason": "NO_01_0A_00_09",
            },
            username="test",
            client_ip="127.0.0.1",
            conn_id="conn-1",
        )
        self.assertTrue(os.path.isfile(path))
        with open(path, "r", encoding="utf-8") as f:
            passed = json.loads(f.readline())
        self.assertEqual(passed["decision"], "PASS_NON_TARGET")
        self.assertEqual(passed["ordinals"]["target_09"], 0)
        self.assertEqual(passed["cursor"]["before"], passed["cursor"]["after"])
        self.assertEqual(passed["live_input"]["marker_types"], ["23", "52"])
        self.assertTrue(passed["checks"]["output_crc_ok"])
        self.assertNotIn("frames_hex", passed["final_output"])

        traffic_module.TrafficSessionLog.log_01_replay_analysis_event(
            detail={
                **base,
                "decision": "PASS_LIVE",
                "reason": "BATCH_SHAPE_MISMATCH",
                "template_frames": [frame],
                "cursor_after": 16,
                "pool_idx": 15,
                "online_decode": {
                    "live": {"child_count": 10},
                    "template": {"child_count": 1},
                    "facts": {"batch_shape_match": False},
                },
            },
            username="test",
            client_ip="127.0.0.1",
            conn_id="conn-1",
        )
        with open(path, "r", encoding="utf-8") as f:
            events = [json.loads(line) for line in f if line.strip()]
        observed = events[-1]
        self.assertEqual(observed["decision"], "PASS_LIVE")
        self.assertEqual(observed["ordinals"]["target_09"], 1)
        self.assertTrue(observed["checks"]["final_equals_live"])
        self.assertEqual(observed["online_decode"]["live"]["child_count"], 10)

        traffic_module.TrafficSessionLog.log_01_replay_analysis_event(
            detail={
                **base,
                "decision": "DROP",
                "reason": "FINAL_VALIDATION_FAILED",
                "output_frames": [],
                "validation_errors": ["CRC不符"],
            },
            username="test",
            client_ip="127.0.0.1",
            conn_id="conn-1",
        )
        errors_path = os.path.join(run_dir, "01_replace_errors.jsonl")
        self.assertTrue(os.path.isfile(errors_path))
        with open(errors_path, "r", encoding="utf-8") as f:
            dropped = json.loads(f.readline())
        self.assertEqual(dropped["decision"], "DROP")
        self.assertEqual(dropped["ordinals"]["target_09"], 2)

    def test_replay_analysis_records_verified_semantic_replace(self):
        run_dir = traffic_module.TrafficSessionLog.begin_01_replay_analysis_run()
        live = _analysis_frame(0x09)
        shadow = bytearray(live)
        shadow[-1] ^= 0x5A
        shadow[40:44] = (
            zlib.crc32(shadow[55:]) & 0xFFFFFFFF
        ).to_bytes(4, "big")
        shadow = bytes(shadow)
        shadow_checks = {
            "generated": True,
            "outer_crc_ok": True,
            "frame_validation_ok": True,
            "decode_ok": True,
            "signature_equal_live": True,
            "sequences_equal_live": True,
            "roundtrip_ok": True,
        }

        path = traffic_module.TrafficSessionLog.log_01_replay_analysis_event(
            detail={
                "decision": "REPLACE",
                "reason": "SEMANTIC_READY_FULL_CLEAN_REPLACE",
                "replacement_level": "KNOWN_CLEAN",
                "account_id": "UID-ANALYSIS",
                "report_index": 16,
                "pool_total": 1,
                "cursor_before": 0,
                "cursor_after": 1,
                "pool_idx": 0,
                "live_frames": [live],
                "template_frames": [live],
                "shadow_frames": [shadow],
                "output_frames": [shadow],
                "validation_errors": [],
                "online_decode": {"live": {"leaf_sequences": [1]}},
                "shadow_rebuild": {
                    "status": "SEMANTIC_READY_FULL",
                    "ready": True,
                    "send_ready": True,
                    "mechanical_ready": True,
                    "semantic_ready": True,
                    "checks": shadow_checks,
                    "leaf_results": [],
                },
            },
            username="test",
            client_ip="127.0.0.1",
            conn_id="replace-conn",
        )

        with open(path, "r", encoding="utf-8") as stream:
            event = json.loads(stream.readline())
        self.assertEqual(event["decision"], "REPLACE")
        self.assertEqual(event["schema"], "dfm-01-replay-v6")
        self.assertEqual(event["replacement_level"], "KNOWN_CLEAN")
        self.assertFalse(event["checks"]["final_equals_live"])
        self.assertTrue(event["checks"]["final_equals_shadow"])
        self.assertTrue(event["checks"]["replacement_changed"])
        self.assertTrue(event["checks"]["shadow_send_ready"])
        self.assertTrue(event["checks"]["output_crc_ok"])
        self.assertFalse(
            os.path.exists(os.path.join(run_dir, "01_replace_errors.jsonl"))
        )

    def test_replay_analysis_records_cross_account_identity_fields(self):
        run_dir = traffic_module.TrafficSessionLog.begin_01_replay_analysis_run()
        live = _analysis_frame(0x09)
        path = traffic_module.TrafficSessionLog.log_01_replay_analysis_event(
            detail={
                "decision": "PASS_LIVE",
                "reason": "NO_RECORDED_BODY_CHANGE_PASS_LIVE",
                "account_id": "LIVE-UID",
                "live_game_id": "LIVE-UID",
                "donor_game_id": "DONOR-UID",
                "cross_account": True,
                "final_identity_check": True,
                "report_index": 20,
                "pool_total": 1,
                "cursor_before": 0,
                "cursor_after": 1,
                "pool_idx": 0,
                "live_frames": [live],
                "template_frames": [live],
                "shadow_frames": [live],
                "output_frames": [live],
                "validation_errors": [],
                "online_decode": {"live": {"leaf_sequences": [500]}},
                "shadow_rebuild": {
                    "status": "SEMANTIC_READY_FULL",
                    "ready": True,
                    "send_ready": True,
                    "mechanical_ready": True,
                    "semantic_ready": True,
                    "identity_rewrite_count": 2,
                    "identity_blocked_leaves": 1,
                    "checks": {
                        "outer_crc_ok": True,
                        "decode_ok": True,
                        "signature_equal_live": True,
                        "sequences_equal_live": True,
                    },
                    "leaf_results": [],
                },
            },
            username="test",
            client_ip="127.0.0.1",
            conn_id="cross-account-conn",
        )

        with open(path, "r", encoding="utf-8") as stream:
            event = json.loads(stream.readline())
        self.assertTrue(event["cross_account"]["enabled"])
        self.assertEqual(event["cross_account"]["live_game_id"], "LIVE-UID")
        self.assertEqual(event["cross_account"]["donor_game_id"], "DONOR-UID")
        self.assertEqual(event["cross_account"]["identity_rewrite_count"], 2)
        self.assertEqual(event["cross_account"]["identity_blocked_leaves"], 1)
        self.assertTrue(event["cross_account"]["final_identity_check"])

        summary_path = os.path.join(run_dir, "01_replace_summary.csv")
        with open(summary_path, "r", encoding="utf-8-sig") as stream:
            header = stream.readline()
        self.assertIn("donor_game_id", header)
        self.assertIn("final_identity_check", header)

        shadow = bytearray(live)
        shadow[-1] ^= 0x5A
        shadow[40:44] = (
            zlib.crc32(shadow[55:]) & 0xFFFFFFFF
        ).to_bytes(4, "big")
        shadow = bytes(shadow)
        shadow_checks = {
            "generated": True,
            "outer_crc_ok": True,
            "frame_validation_ok": True,
            "decode_ok": True,
            "signature_equal_live": True,
            "sequences_equal_live": True,
            "roundtrip_ok": True,
        }
        traffic_module.TrafficSessionLog.log_01_replay_analysis_event(
            detail={
                "decision": "REPLACE",
                "reason": "AGGRESSIVE_UNKNOWN_REPLACE",
                "replacement_level": "AGGRESSIVE_UNKNOWN",
                "account_id": "UID-ANALYSIS",
                "report_index": 17,
                "pool_total": 1,
                "cursor_before": 0,
                "cursor_after": 1,
                "pool_idx": 0,
                "live_frames": [live],
                "template_frames": [live],
                "shadow_frames": [shadow],
                "output_frames": [shadow],
                "validation_errors": [],
                "online_decode": {"live": {"leaf_sequences": [2]}},
                "shadow_rebuild": {
                    "status": "AGGRESSIVE_UNKNOWN_READY",
                    "replacement_level": "AGGRESSIVE_UNKNOWN",
                    "ready": True,
                    "send_ready": True,
                    "mechanical_ready": True,
                    "semantic_ready": False,
                    "aggressive_changed_leaves": 1,
                    "checks": shadow_checks,
                    "leaf_results": [],
                },
            },
            username="test",
            client_ip="127.0.0.1",
            conn_id="replace-conn",
        )
        with open(path, "r", encoding="utf-8") as stream:
            aggressive = [json.loads(line) for line in stream][-1]
        self.assertEqual(
            aggressive["replacement_level"], "AGGRESSIVE_UNKNOWN"
        )
        self.assertFalse(aggressive["checks"]["shadow_semantic_ready"])
        self.assertTrue(aggressive["checks"]["shadow_send_ready"])
        self.assertFalse(
            os.path.exists(os.path.join(run_dir, "01_replace_errors.jsonl"))
        )

    def test_replay_analysis_writes_suspect_shadow_sidecar(self):
        traffic_module.app_config.set("detail_01_log", True)
        run_dir = traffic_module.TrafficSessionLog.begin_01_replay_analysis_run()
        live = _analysis_frame(0x09)
        leaf = {
            "path": [0],
            "record_code": 0x01122388,
            "message_id": None,
            "length": 337,
            "live_sequence": 435,
            "matched": True,
            "replacement_level": "NONE",
            "block_reason": "AGGRESSIVE_BLOCK_DYNAMIC",
            "suspect_watch": True,
            "suspect_flags": ["DYNAMIC_GUARD", "BODY_DIFF"],
            "available_template_lengths": [337],
            "live_hex": "AA",
            "template_hex": "BB",
            "candidate_hex": "AA",
            "shadow_only_candidate_hex": "BB",
            "shadow_only_diff_offsets": [14],
            "shadow_only_diff_ranges": [
                {"start": 14, "end": 14, "length": 1}
            ],
        }

        traffic_module.TrafficSessionLog.log_01_replay_analysis_event(
            detail={
                "decision": "PASS_LIVE",
                "reason": "AGGRESSIVE_BLOCK_DYNAMIC",
                "replacement_level": "NONE",
                "account_id": "UID-ANALYSIS",
                "report_index": 18,
                "pool_total": 1,
                "cursor_before": 0,
                "cursor_after": 1,
                "pool_idx": 0,
                "live_frames": [live],
                "template_frames": [live],
                "shadow_frames": [live],
                "output_frames": [live],
                "validation_errors": [],
                "online_decode": {"live": {"leaf_sequences": [435]}},
                "shadow_rebuild": {
                    "status": "SEMANTIC_READY_FULL",
                    "ready": True,
                    "send_ready": True,
                    "mechanical_ready": True,
                    "semantic_ready": True,
                    "suspect_leaf_count": 1,
                    "suspect_live_plaintext_hex": "01020304",
                    "checks": {
                        "generated": True,
                        "outer_crc_ok": True,
                        "frame_validation_ok": True,
                        "decode_ok": True,
                        "signature_equal_live": True,
                        "sequences_equal_live": True,
                        "roundtrip_ok": True,
                    },
                    "leaf_results": [leaf],
                },
            },
            username="test",
            client_ip="127.0.0.1",
            conn_id="suspect-conn",
        )

        path = os.path.join(run_dir, "01_suspect_diffs.jsonl")
        self.assertTrue(os.path.isfile(path))
        with open(path, "r", encoding="utf-8") as stream:
            event = json.loads(stream.readline())
        self.assertEqual(event["schema"], "dfm-01-suspect-diff-v1")
        self.assertTrue(event["shadow_only"])
        self.assertTrue(event["network_output_equals_live"])
        self.assertEqual(event["live_type9_plaintext_hex"], "01020304")
        self.assertEqual(
            event["suspect_leaves"][0]["shadow_only_candidate_hex"], "BB"
        )

    def test_normal_log_keeps_three_raw_unknown_leaf_samples(self):
        run_dir = traffic_module.TrafficSessionLog.begin_01_replay_analysis_run()
        live = _analysis_frame(0x09)
        leaf = {
            "path": [1],
            "record_code": 0x01122388,
            "message_id": 0x8024,
            "length": 16,
            "live_sequence": 51,
            "structural_match": False,
            "matched": False,
            "replacement_level": "UNMATCHED_LEAF_PASS_LIVE",
            "available_template_lengths": [],
            "live_hex": "0102030405060708090A0B0C0D0E0F10",
            "template_hex": "",
            "candidate_hex": "",
        }
        detail = {
            "decision": "PASS_LIVE",
            "reason": "SEMANTIC_UNMAPPED_PASS_LIVE",
            "replacement_level": "NONE",
            "account_id": "UID-ANALYSIS",
            "report_index": 51,
            "pool_total": 1,
            "cursor_before": 0,
            "cursor_after": 0,
            "pool_idx": None,
            "live_frames": [live],
            "template_frames": [],
            "shadow_frames": [],
            "output_frames": [live],
            "validation_errors": [],
            "online_decode": {"live": {"leaf_sequences": [51]}},
            "shadow_rebuild": {
                "status": "SEMANTIC_UNMAPPED",
                "ready": False,
                "send_ready": False,
                "mechanical_ready": True,
                "semantic_ready": False,
                "pruned_leaves": 0,
                "unmatched_pass_live_leaves": 1,
                "suspect_live_plaintext_hex": "01020304",
                "leaf_results": [leaf],
                "checks": {"outer_crc_ok": True, "decode_ok": True},
            },
        }
        for _ in range(4):
            traffic_module.TrafficSessionLog.log_01_replay_analysis_event(
                detail=detail,
                username="test",
                client_ip="127.0.0.1",
                conn_id="unknown-conn",
            )

        samples_path = os.path.join(run_dir, "01_unknown_leaf_samples.jsonl")
        with open(samples_path, "r", encoding="utf-8") as stream:
            samples = [json.loads(line) for line in stream if line.strip()]
        self.assertEqual(len(samples), 3)
        self.assertEqual(samples[0]["raw_leaf_hex"], leaf["live_hex"])
        self.assertEqual(samples[0]["context_event_id"], samples[0]["event_id"])
        self.assertEqual(samples[-1]["sample_index"], 3)

        context_path = os.path.join(
            run_dir, "01_unknown_context_samples.jsonl"
        )
        with open(context_path, "r", encoding="utf-8") as stream:
            contexts = [json.loads(line) for line in stream if line.strip()]
        self.assertEqual(len(contexts), 3)
        self.assertEqual(contexts[0]["event_id"], samples[0]["context_event_id"])
        self.assertEqual(contexts[0]["raw_frames_hex"], [live.hex().upper()])
        self.assertEqual(contexts[0]["raw_type9_plaintext_hex"], "01020304")
        self.assertEqual(
            contexts[0]["raw_type9_plaintext_sha256"],
            hashlib.sha256(bytes.fromhex("01020304")).hexdigest(),
        )

        with open(
            os.path.join(run_dir, "01_unknown_leaf_stats.json"),
            "r",
            encoding="utf-8",
        ) as stream:
            stats = json.load(stream)
        row = stats["schemas"]["01122388:8024:16"]
        self.assertEqual(row["occurrences"], 4)
        self.assertEqual(row["samples_written"], 3)

        with open(
            os.path.join(run_dir, "01_replace_events.jsonl"),
            "r",
            encoding="utf-8",
        ) as stream:
            compact = json.loads(stream.readline())
        self.assertNotIn("frames_hex", compact["live_input"])
        compact_leaf = compact["shadow_rebuild"]["leaf_results"][0]
        self.assertNotIn("live_hex", compact_leaf)


if __name__ == "__main__":
    unittest.main()
