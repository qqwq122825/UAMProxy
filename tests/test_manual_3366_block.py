from __future__ import annotations

import unittest

try:
    from core.server import ProxyEngine, Socks5Server
except ImportError:  # 核心精简环境未安装PySide6时跳过，Windows构建会执行。
    ProxyEngine = None
    Socks5Server = None


class _Writer:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


@unittest.skipIf(Socks5Server is None, "PySide6 is not installed")
class Manual3366BlockTests(unittest.TestCase):
    def test_detected_3366_detaches_only_its_01_matching_state(self):
        server = Socks5Server(1080, mode="replay", label="重放")
        for conn_id in ("c3366", "c01"):
            server._replay_index[conn_id] = [7, 7]
            server._replay_index_33[conn_id] = {"09": [3, 3]}
            server._replay_pools[conn_id] = {"pool_01": [conn_id]}
            server._replay_all_pools[conn_id] = {"uid": conn_id}
            server._replay_gid_checked[conn_id] = True
            server._replay_await_join.add(conn_id)
            server._conn_live_gid[conn_id] = "UID"

        server.detach_3366_from_01_replay("c3366")

        self.assertNotIn("c3366", server._replay_index)
        self.assertNotIn("c3366", server._replay_pools)
        self.assertNotIn("c3366", server._replay_gid_checked)
        self.assertNotIn("c3366", server._replay_await_join)
        self.assertNotIn("c3366", server._conn_live_gid)
        self.assertEqual(server._replay_index["c01"], [7, 7])
        self.assertEqual(server._replay_pools["c01"], {"pool_01": ["c01"]})
        self.assertTrue(server._replay_gid_checked["c01"])
        self.assertIn("c01", server._replay_await_join)
        self.assertEqual(server._conn_live_gid["c01"], "UID")

    def test_switch_closes_only_3366_connections_on_replay(self):
        server = Socks5Server(1080, mode="replay", label="重放")
        port_3366 = _Writer()
        detected_3366 = _Writer()
        channel_01 = _Writer()
        server._conn_client_writers = {
            "c3366": port_3366,
            "cdetected": detected_3366,
            "c01": channel_01,
        }
        server._conn_target_ports = {
            "c3366": 3366,
            "cdetected": 443,
            "c01": 9000,
        }
        server._conn_carries_3366.add("cdetected")

        closed = server.set_manual_3366_block(True)

        self.assertEqual(closed, 2)
        self.assertTrue(port_3366.closed)
        self.assertTrue(detected_3366.closed)
        self.assertFalse(channel_01.closed)
        self.assertTrue(server.should_reject_manual_3366(3366, "replay"))
        self.assertFalse(server.should_reject_manual_3366(9000, "replay"))

    def test_switch_also_closes_and_rejects_3366_on_record(self):
        record_server = Socks5Server(1081, mode="record", label="录制")
        port_3366 = _Writer()
        detected_3366 = _Writer()
        channel_01 = _Writer()
        record_server._conn_client_writers = {
            "c3366": port_3366,
            "cdetected": detected_3366,
            "c01": channel_01,
        }
        record_server._conn_target_ports = {
            "c3366": 3366,
            "cdetected": 443,
            "c01": 443,
        }
        record_server._conn_carries_3366.add("cdetected")

        closed = record_server.set_manual_3366_block(True)

        self.assertEqual(closed, 2)
        self.assertTrue(port_3366.closed)
        self.assertTrue(detected_3366.closed)
        self.assertFalse(channel_01.closed)
        self.assertTrue(record_server.should_reject_manual_3366(3366, "record"))
        self.assertFalse(record_server.should_reject_manual_3366(443, "record"))

    def test_disabling_switch_allows_new_3366_connection(self):
        server = Socks5Server(1080, mode="replay", label="重放")
        server.set_manual_3366_block(True)
        server.set_manual_3366_block(False)

        self.assertFalse(server.should_reject_manual_3366(3366, "replay"))

    def test_engine_switch_updates_record_and_replay_servers(self):
        engine = ProxyEngine()
        engine.server_1080 = Socks5Server(1080, mode="replay", label="重放")
        engine.server_1081 = Socks5Server(1081, mode="record", label="录制")

        engine.set_3366_block(True)

        self.assertTrue(engine.manual_3366_block_enabled)
        self.assertTrue(engine.replay_3366_block_enabled)
        self.assertTrue(engine.server_1080._manual_3366_block_enabled)
        self.assertTrue(engine.server_1081._manual_3366_block_enabled)

        engine.set_replay_3366_block(False)

        self.assertFalse(engine.server_1080._manual_3366_block_enabled)
        self.assertFalse(engine.server_1081._manual_3366_block_enabled)

    def test_01_threshold_blocks_3366_and_keeps_01(self):
        from core.config import app_config
        from core.server import engine

        previous_1080 = engine.server_1080
        previous_1081 = engine.server_1081
        self.addCleanup(setattr, engine, "server_1080", previous_1080)
        self.addCleanup(setattr, engine, "server_1081", previous_1081)
        self.addCleanup(app_config.set, "replenish_01_mode", False)
        self.addCleanup(app_config.set, "auto_disconnect_01_threshold", 100)
        self.addCleanup(app_config.set, "auto_disconnect_01_policy", "count")
        engine.server_1080 = Socks5Server(1080, mode="replay", label="重放")
        engine.server_1081 = Socks5Server(1081, mode="record", label="录制")
        record = engine.server_1081
        port_3366 = _Writer()
        channel_01 = _Writer()
        record._conn_client_writers = {"c3366": port_3366, "c01": channel_01}
        record._conn_target_ports = {"c3366": 3366, "c01": 443}
        record._user_active_conns = {
            "test": {"1.2.3.4": {"c3366", "c01"}}
        }
        app_config.set("replenish_01_mode", False)
        app_config.set("auto_disconnect_01_policy", "count")
        app_config.set("auto_disconnect_01_threshold", 150)
        self.assertFalse(record.maybe_block_3366_after_01_threshold("1.2.3.4", n01=149))
        self.assertFalse(port_3366.closed)
        self.assertFalse(channel_01.closed)

        self.assertTrue(record.maybe_block_3366_after_01_threshold("1.2.3.4", n01=150))
        self.assertTrue(port_3366.closed)
        self.assertFalse(channel_01.closed)
        self.assertTrue(
            record.should_reject_manual_3366(3366, "record", "1.2.3.4")
        )
        self.assertFalse(
            record.should_reject_manual_3366(3366, "record", "9.9.9.9")
        )
        self.assertFalse(record._manual_3366_block_enabled)
        self.assertFalse(engine.server_1080.should_reject_manual_3366(3366, "replay"))
        self.assertFalse(engine.manual_3366_block_enabled)
        self.assertFalse(
            record.maybe_block_3366_after_01_threshold("1.2.3.4", n01=151)
        )

        # 同一 IP 的全部连接退出后，阈值阻断状态清掉；不会残留成全局开关。
        record._auto_disconnect_blocked.discard("1.2.3.4")
        self.assertFalse(
            record.should_reject_manual_3366(3366, "record", "1.2.3.4")
        )

    def test_message_coverage_goal_blocks_only_same_ip_3366(self):
        from unittest.mock import patch
        from core.config import app_config

        record = Socks5Server(1081, mode="record", label="录制")
        same_ip_3366 = _Writer()
        same_ip_01 = _Writer()
        other_ip_3366 = _Writer()
        record._conn_client_writers = {
            "same33": same_ip_3366,
            "same01": same_ip_01,
            "other33": other_ip_3366,
        }
        record._conn_target_ports = {
            "same33": 3366,
            "same01": 443,
            "other33": 3366,
        }
        record._user_active_conns = {
            "test": {
                "1.2.3.4": {"same33", "same01"},
                "9.9.9.9": {"other33"},
            }
        }
        self.addCleanup(app_config.set, "auto_disconnect_01_policy", "count")
        self.addCleanup(
            app_config.set, "auto_disconnect_message_coverage_threshold", 100
        )
        app_config.set("auto_disconnect_01_policy", "coverage")
        app_config.set("auto_disconnect_message_coverage_threshold", 100)

        with patch(
            "core.server.recording_pool.get_active_message_coverage",
            return_value={
                "priority_coverage_percent": 100.0,
                "recording_completion_percent": 100.0,
                "seen_priority_count": 21,
                "priority_total": 21,
                "subtype_8004_seen_count": 9,
                "subtype_8004_total": 9,
                "periodic_ready_count": 3,
                "periodic_total": 3,
            },
        ):
            triggered = record.maybe_block_3366_after_recording_goal(
                "1.2.3.4", n01=1
            )

        self.assertTrue(triggered)
        self.assertTrue(same_ip_3366.closed)
        self.assertFalse(same_ip_01.closed)
        self.assertFalse(other_ip_3366.closed)

    def test_id_coverage_alone_does_not_finish_before_periodic_readiness(self):
        from unittest.mock import patch
        from core.config import app_config

        record = Socks5Server(1081, mode="record", label="录制")
        self.addCleanup(app_config.set, "auto_disconnect_01_policy", "count")
        self.addCleanup(
            app_config.set, "auto_disconnect_message_coverage_threshold", 100
        )
        app_config.set("auto_disconnect_01_policy", "coverage")
        app_config.set("auto_disconnect_message_coverage_threshold", 100)

        with patch(
            "core.server.recording_pool.get_active_message_coverage",
            return_value={
                "priority_coverage_percent": 100.0,
                "recording_completion_percent": 96.875,
                "seen_priority_count": 21,
                "priority_total": 21,
                "subtype_8004_seen_count": 9,
                "subtype_8004_total": 9,
                "periodic_ready_count": 2,
                "periodic_total": 3,
            },
        ):
            triggered = record.maybe_block_3366_after_recording_goal(
                "1.2.3.4", n01=999
            )

        self.assertFalse(triggered)
        self.assertNotIn("1.2.3.4", record._auto_disconnect_blocked)

    def test_coverage_periodic_goal_requires_both_conditions(self):
        from unittest.mock import patch
        from core.config import app_config

        record = Socks5Server(1081, mode="record", label="录制")
        self.addCleanup(app_config.set, "auto_disconnect_01_policy", "count")
        self.addCleanup(
            app_config.set, "auto_disconnect_message_coverage_threshold", 100
        )
        app_config.set(
            "auto_disconnect_01_policy", "coverage_periodic"
        )
        app_config.set("auto_disconnect_message_coverage_threshold", 90)

        incomplete = {
            "priority_coverage_percent": 100.0,
            "recording_completion_percent": 95.0,
            "seen_priority_count": 21,
            "priority_total": 21,
            "subtype_8004_seen_count": 9,
            "subtype_8004_total": 9,
            "periodic_ready_count": 6,
            "periodic_total": 7,
        }
        with patch(
            "core.server.recording_pool.get_active_message_coverage",
            return_value=incomplete,
        ):
            self.assertFalse(
                record.maybe_block_3366_after_recording_goal(
                    "1.2.3.4", n01=999
                )
            )

        complete = dict(incomplete, periodic_ready_count=7)
        with patch(
            "core.server.recording_pool.get_active_message_coverage",
            return_value=complete,
        ):
            self.assertTrue(
                record.maybe_block_3366_after_recording_goal(
                    "1.2.3.4", n01=999
                )
            )

    def test_hold_01_only_after_threshold_on_record_uplink(self):
        from core.config import app_config

        record = Socks5Server(1081, mode="record", label="录制")
        replay = Socks5Server(1080, mode="replay", label="重放")
        self.addCleanup(app_config.set, "hold_01_after_threshold", False)
        app_config.set("hold_01_after_threshold", True)

        self.assertFalse(record.should_hold_record_01("1.2.3.4", "↑UP"))
        record._auto_disconnect_blocked.add("1.2.3.4")
        self.assertTrue(record.should_hold_record_01("1.2.3.4", "↑UP"))
        self.assertFalse(record.should_hold_record_01("1.2.3.4", "↓DOWN"))
        self.assertFalse(record.should_hold_record_01("9.9.9.9", "↑UP"))
        self.assertFalse(replay.should_hold_record_01("1.2.3.4", "↑UP"))

        app_config.set("hold_01_after_threshold", False)
        self.assertFalse(record.should_hold_record_01("1.2.3.4", "↑UP"))


if __name__ == "__main__":
    unittest.main()
