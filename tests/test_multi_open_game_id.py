from __future__ import annotations

import unittest
from unittest.mock import patch

try:
    from core.server import Socks5Server, engine
except ImportError:
    Socks5Server = None
    engine = None


class _Writer:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _register(server: Socks5Server, username: str, ip: str, conn_id: str, writer: _Writer):
    ip_map = server._user_active_conns.setdefault(username, {})
    ip_map.setdefault(ip, set()).add(conn_id)
    server._conn_client_writers[conn_id] = writer


@unittest.skipIf(Socks5Server is None, "PySide6 is not installed")
class MultiOpenByGameIdTests(unittest.TestCase):
    def setUp(self):
        self.record = Socks5Server(1081, mode="record", label="录制")
        self.replay = Socks5Server(1080, mode="replay", label="重放")
        self._old_1080 = engine.server_1080
        self._old_1081 = engine.server_1081
        engine.server_1080 = self.replay
        engine.server_1081 = self.record

    def tearDown(self):
        engine.server_1080 = self._old_1080
        engine.server_1081 = self._old_1081

    @patch("core.server.user_manager.get_allow_multi", return_value=False)
    def test_same_game_id_record_and_replay_not_kicked(self, _allow):
        rec_w = _Writer()
        rep_w = _Writer()
        _register(self.record, "u1", "1.1.1.1", "rec01", rec_w)
        _register(self.replay, "u1", "2.2.2.2", "rep01", rep_w)

        self.record._remember_conn_game_id("u1", "rec01", "1.1.1.1", "GID-A")
        self.replay._remember_conn_game_id("u1", "rep01", "2.2.2.2", "GID-A")

        self.assertFalse(rec_w.closed)
        self.assertFalse(rep_w.closed)
        self.assertIn("rec01", self.record._user_active_conns["u1"]["1.1.1.1"])
        self.assertIn("rep01", self.replay._user_active_conns["u1"]["2.2.2.2"])

    @patch("core.server.user_manager.get_allow_multi", return_value=False)
    def test_same_game_id_two_ips_on_replay_not_kicked(self, _allow):
        w1 = _Writer()
        w2 = _Writer()
        _register(self.replay, "u1", "1.1.1.1", "c1", w1)
        _register(self.replay, "u1", "2.2.2.2", "c2", w2)

        self.replay._remember_conn_game_id("u1", "c1", "1.1.1.1", "GID-A")
        self.replay._remember_conn_game_id("u1", "c2", "2.2.2.2", "GID-A")

        self.assertFalse(w1.closed)
        self.assertFalse(w2.closed)

    @patch("core.server.user_manager.get_allow_multi", return_value=False)
    def test_different_game_id_kicks_old(self, _allow):
        old_w = _Writer()
        new_w = _Writer()
        _register(self.record, "u1", "1.1.1.1", "old", old_w)
        _register(self.replay, "u1", "2.2.2.2", "new", new_w)

        self.record._remember_conn_game_id("u1", "old", "1.1.1.1", "GID-A")
        self.replay._remember_conn_game_id("u1", "new", "2.2.2.2", "GID-B")

        self.assertTrue(old_w.closed)
        self.assertFalse(new_w.closed)
        self.assertNotIn("1.1.1.1", self.record._user_active_conns.get("u1", {}))

    @patch("core.server.user_manager.get_allow_multi", return_value=True)
    def test_allow_multi_keeps_different_game_ids(self, _allow):
        old_w = _Writer()
        new_w = _Writer()
        _register(self.record, "u1", "1.1.1.1", "old", old_w)
        _register(self.replay, "u1", "2.2.2.2", "new", new_w)

        self.record._remember_conn_game_id("u1", "old", "1.1.1.1", "GID-A")
        self.replay._remember_conn_game_id("u1", "new", "2.2.2.2", "GID-B")

        self.assertFalse(old_w.closed)
        self.assertFalse(new_w.closed)

    @patch("core.server.user_manager.get_allow_multi", return_value=False)
    def test_unidentified_connection_not_kicked(self, _allow):
        unknown_w = _Writer()
        known_w = _Writer()
        _register(self.record, "u1", "1.1.1.1", "unknown", unknown_w)
        _register(self.replay, "u1", "2.2.2.2", "known", known_w)

        self.replay._remember_conn_game_id("u1", "known", "2.2.2.2", "GID-A")

        self.assertFalse(unknown_w.closed)
        self.assertFalse(known_w.closed)


if __name__ == "__main__":
    unittest.main()
