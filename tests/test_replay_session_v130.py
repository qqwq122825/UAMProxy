import unittest

from core.replay_session_v130 import (
    ReplaySessionRegistry,
    join_frame_fields,
    live_leaf_sequence_decision,
    replay_phase_label,
    resumed_replay_context,
    REPLAY_PHASE_CONTINUE,
    REPLAY_PHASE_FIRST,
)


def join_frame(token: int, unix_time: int) -> bytes:
    frame = bytearray(42)
    frame[:5] = b"\x01\x00\x00\x00\x2A"
    frame[10:14] = int(token & 0xFFFFFFFF).to_bytes(4, "big")
    frame[14:18] = (0x0A92).to_bytes(4, "big")
    frame[38:42] = int(unix_time & 0xFFFFFFFF).to_bytes(4, "big")
    return bytes(frame)


class ReplaySessionV130Tests(unittest.TestCase):
    def test_reads_session_token_and_full_unix_time(self):
        fields = join_frame_fields(join_frame(0x9ABF276F, 0x6A8C48F4))
        self.assertEqual(fields["session_token_u32"], 0x9ABF276F)
        self.assertEqual(fields["unix_time_u32"], 0x6A8C48F4)
        self.assertIsNone(join_frame_fields(b"\x00" * 42))

    def test_live_leaf_sequence_confirms_reconnect(self):
        decision, detail = live_leaf_sequence_decision(2196, 2197)
        self.assertEqual(decision, "CONFIRMED_CONTINUATION")
        self.assertEqual(detail["forward_delta"], 1)
        retransmit, _ = live_leaf_sequence_decision(2196, 2196)
        self.assertEqual(retransmit, "CONFIRMED_RETRANSMIT")

    def test_live_leaf_reset_rejects_candidate(self):
        decision, detail = live_leaf_sequence_decision(2196, 10)
        self.assertEqual(decision, "REJECTED_NEW_SESSION")
        self.assertGreater(detail["forward_delta"], 0xFFFF)

    def test_resume_keeps_semantics_pending_and_resets_transport(self):
        source = {
            "live_device_context": {"device_idfv": "DEVICE-1"},
            "v128_replenish": {
                "emitted": ["0x8007:30"],
                "last_native_live_leaf_sequence": 2196,
                "report_offset": 4,
                "leaf_offset": 27,
                "frame_offset": 4,
                "group_offset": 4,
                "last_output_leaf_sequence": 2200,
                "injected_report_count": 4,
                "injected_leaf_count": 27,
            },
        }
        resumed = resumed_replay_context(
            source,
            previous_last_live_leaf_sequence=2196,
            fresh_started_monotonic=300.0,
        )
        state = resumed["v128_replenish"]
        self.assertEqual(state["emitted"], ["0x8007:30"])
        self.assertEqual(
            resumed["v130_pending_reconnect"][
                "previous_last_live_leaf_sequence"
            ],
            2196,
        )
        for key in (
            "report_offset", "frame_offset", "group_offset",
        ):
            self.assertEqual(state[key], 0)
        self.assertEqual(state["leaf_offset"], 27)
        self.assertEqual(state["last_output_leaf_sequence"], 2200)
        self.assertEqual(state["injected_report_count"], 4)
        self.assertEqual(state["injected_leaf_count"], 27)
        self.assertNotIn("ui_replay_phase", resumed)

    def _old_session(self) -> ReplaySessionRegistry:
        registry = ReplaySessionRegistry()
        registry.observe_join(
            "old", "proxy", join_frame(0x9ABF276F, 1000), now=100.0
        )
        context, _, _ = registry.bind(
            "old", "proxy", "GAME-1", {},
            fresh_started_monotonic=100.0, now=100.1,
        )
        context["v128_replenish"] = {
            "emitted": ["0x8004:30"],
            "last_native_live_leaf_sequence": 2196,
        }
        registry.attach_context("old", context)
        registry.disconnect("old", now=150.0)
        return registry

    def test_same_token_creates_candidate_not_immediate_resume(self):
        registry = self._old_session()
        registry.observe_join(
            "new", "proxy", join_frame(0x9ABF276F, 1050), now=151.0
        )
        context, started, detail = registry.bind(
            "new", "proxy", "GAME-1", {},
            fresh_started_monotonic=151.0, now=151.1,
        )
        self.assertTrue(detail["candidate"])
        self.assertFalse(detail["continued"])
        self.assertEqual(detail["classification"], "RECONNECT_CANDIDATE")
        self.assertEqual(started, 100.0)
        self.assertIn("v130_pending_reconnect", context)
        self.assertEqual(
            context["v128_replenish"]["emitted"], ["0x8004:30"]
        )

    def test_changed_token_starts_fresh_session(self):
        registry = self._old_session()
        registry.observe_join(
            "new", "proxy", join_frame(0xE22BF85B, 1050), now=151.0
        )
        context, started, detail = registry.bind(
            "new", "proxy", "GAME-1", {"fresh": True},
            fresh_started_monotonic=151.0, now=151.1,
        )
        self.assertFalse(detail["candidate"])
        self.assertEqual(detail["classification"], "GAME_REOPEN_OR_NEW_SESSION")
        self.assertEqual(started, 151.0)
        self.assertEqual(context, {"fresh": True})

    def test_superseded_socket_does_not_disconnect_new_session(self):
        registry = ReplaySessionRegistry()
        registry.observe_join(
            "old", "proxy", join_frame(0x11111111, 1000), now=100.0
        )
        old_context, _, _ = registry.bind(
            "old", "proxy", "GAME-1", {},
            fresh_started_monotonic=100.0, now=100.1,
        )
        old_context["v128_replenish"] = {
            "last_native_live_leaf_sequence": 10
        }
        registry.attach_context("old", old_context)
        registry.observe_join(
            "new", "proxy", join_frame(0x11111111, 1002), now=102.0
        )
        new_context, _, detail = registry.bind(
            "new", "proxy", "GAME-1", {},
            fresh_started_monotonic=102.0, now=102.1,
        )
        self.assertTrue(detail["active_connection_overlap"])
        registry.attach_context("old", {"stale": True})
        stale = registry.disconnect("old", now=103.0)
        self.assertTrue(stale["stale_connection_ignored"])
        session = registry.sessions[("proxy", "GAME-1")]
        self.assertIs(session.replay_context, new_context)
        self.assertIsNone(session.disconnected_monotonic)

    def test_disconnected_session_expires(self):
        registry = ReplaySessionRegistry(disconnected_ttl_seconds=10)
        registry.observe_join(
            "old", "proxy", join_frame(0x11111111, 1000), now=100.0
        )
        registry.bind(
            "old", "proxy", "GAME-1", {},
            fresh_started_monotonic=100.0, now=100.1,
        )
        registry.disconnect("old", now=101.0)
        registry.observe_join(
            "new", "proxy", join_frame(0x11111111, 1011), now=111.0
        )
        _, _, detail = registry.bind(
            "new", "proxy", "GAME-1", {},
            fresh_started_monotonic=111.0, now=111.1,
        )
        self.assertEqual(detail["classification"], "FIRST_JOIN")

    def test_replay_phase_label_is_only_first_or_continue(self):
        self.assertEqual(replay_phase_label(continued=False), REPLAY_PHASE_FIRST)
        self.assertEqual(replay_phase_label(continued=True), REPLAY_PHASE_CONTINUE)


if __name__ == "__main__":
    unittest.main()
