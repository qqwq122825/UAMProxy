import os
import tempfile
import time
import unittest

import core.type9_special_rules as special_rules
from core.config import app_config
from core.crypto import (
    _ace_01_reassemble_frames,
    _ace_01_report_index,
    _ace_try_extract_frames,
    _ace_try_replay_template,
)
from core.type9_shadow import decode_material, merge_device_context
from core.type9_special_rules import HOT_RULE_SCHEMA, Type9HotRuleStore
from core.type9_v128_replenish import (
    BUILTIN_MODEL,
    BUILTIN_MESSAGE_IDS,
    STRONG_PROFILE_MODEL,
    WALL_SECONDS_PER_LOGICAL_SLOT,
    collect_due_groups,
    collect_due_strong_profile_groups,
    ensure_v128_state,
    evaluate_800a_period,
    evaluate_scan_wave_template,
    player_event_emit_key,
    player_leaf_identity,
    plan_same_device_player_groups,
    rebuild_player_supplement_leaf,
    stamp_strong_profile_leaf,
    strict_device_gate,
)
from tests.test_type9_hot_rules import batch_children, frame, leaf


def empty_rule_document():
    return {"schema": HOT_RULE_SCHEMA, "revision": "v128-test-empty", "rules": []}


def drop_9000_document():
    return {
        "schema": HOT_RULE_SCHEMA,
        "revision": "v128-test-sequence-safe-drop",
        "rules": [
            {
                "id": "test-drop-9000",
                "enabled": True,
                "match": {
                    "record_code": "0x0102000A",
                    "message_id": "0x9000",
                    "length": "*",
                },
                "action": "drop_leaf",
            }
        ],
    }


class V128ReplenishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Type9HotRuleStore(
            os.path.join(self.tmp.name, "type9_hot_rules.json"),
            auto_reload_interval=0,
        )
        self.store.replace_document(empty_rule_document())
        self.previous_store = special_rules.type9_hot_rule_store
        special_rules.type9_hot_rule_store = self.store
        self.previous_mode = app_config.get("replenish_01_mode")
        self.previous_full_rebuild_mode = app_config.get(
            "full_rebuild_01_mode"
        )
        self.previous_match_events = app_config.get("rebuild_match_events")
        self.previous_scan_waves = app_config.get("rebuild_scan_waves")
        self.previous_rebuild_controls_v2 = app_config.get(
            "rebuild_controls_v2"
        )
        self.previous_rebuild_controls_v3 = app_config.get(
            "rebuild_controls_v3"
        )
        self.previous_rebuild_central9 = app_config.get(
            "rebuild_central9_enabled"
        )
        self.previous_rebuild_player_base = app_config.get(
            "rebuild_player_base_enabled"
        )
        self.previous_rebuild_match_enabled = app_config.get(
            "rebuild_match_events_enabled"
        )
        self.previous_rebuild_scan_enabled = app_config.get(
            "rebuild_scan_waves_enabled"
        )
        self.previous_rebuild_player_ids = {
            message_id: app_config.get(f"rebuild_player_{message_id}_enabled")
            for message_id in ("8007", "800A", "800C", "800D", "800F", "8023", "8024", "802C")
        }
        self.previous_rebuild_strong = app_config.get(
            "rebuild_strong_profile"
        )
        app_config.set("replenish_01_mode", True)
        app_config.set("full_rebuild_01_mode", False)
        app_config.set("rebuild_controls_v2", False)
        app_config.set("rebuild_controls_v3", False)
        for message_id in self.previous_rebuild_player_ids:
            app_config.set(f"rebuild_player_{message_id}_enabled", False)
        app_config.set("rebuild_match_events", "off")
        app_config.set("rebuild_scan_waves", "off")

    def tearDown(self):
        app_config.set("replenish_01_mode", self.previous_mode)
        app_config.set(
            "full_rebuild_01_mode", self.previous_full_rebuild_mode
        )
        app_config.set("rebuild_match_events", self.previous_match_events)
        app_config.set("rebuild_scan_waves", self.previous_scan_waves)
        app_config.set(
            "rebuild_controls_v2", self.previous_rebuild_controls_v2
        )
        app_config.set(
            "rebuild_controls_v3", self.previous_rebuild_controls_v3
        )
        for message_id, value in self.previous_rebuild_player_ids.items():
            app_config.set(f"rebuild_player_{message_id}_enabled", value)
        app_config.set(
            "rebuild_central9_enabled", self.previous_rebuild_central9
        )
        app_config.set(
            "rebuild_player_base_enabled", self.previous_rebuild_player_base
        )
        app_config.set(
            "rebuild_match_events_enabled", self.previous_rebuild_match_enabled
        )
        app_config.set(
            "rebuild_scan_waves_enabled", self.previous_rebuild_scan_enabled
        )
        app_config.set(
            "rebuild_strong_profile", self.previous_rebuild_strong
        )
        special_rules.type9_hot_rule_store = self.previous_store
        self.tmp.cleanup()

    @staticmethod
    def decode_frame(source: bytes) -> tuple[int, dict]:
        assembled = _ace_01_reassemble_frames([source])
        assert assembled
        return _ace_01_report_index(assembled[1]), decode_material(assembled[1])

    @staticmethod
    def builtin_leaf(message_id: int, index: int, sequence: int) -> bytes:
        raw = bytearray(BUILTIN_MODEL[message_id]["templates"][index])
        raw[10:14] = int(sequence).to_bytes(4, "big")
        return bytes(raw)

    @staticmethod
    def device_context_leaf(
        sequence: int,
        *,
        model: str = "iPad13,4",
        system_version: str = "14.6",
        device_idfv: str = "TEST-IDFV-00000001",
    ) -> bytes:
        body = (
            f"model:{model};ver:{system_version};"
            f"iDevHwModel:{model};iDevSysVer:{system_version};"
            f"iDevIDFV:{device_idfv};"
            "inc_id:1;obf_id:1"
        ).encode("ascii") + b"\x00"
        raw = bytearray(14 + len(body))
        raw[0:4] = (1).to_bytes(4, "big")
        raw[4:6] = len(raw).to_bytes(2, "big")
        raw[6:10] = (0x01122340).to_bytes(4, "big")
        raw[10:14] = int(sequence).to_bytes(4, "big")
        raw[14:] = body
        return bytes(raw)

    @staticmethod
    def player_leaf(sequence: int, message_id: int, *, slot: int = 30) -> bytes:
        raw = bytearray(leaf(sequence, fill=0, message_id=message_id, length=56))
        raw[0x1C:0x1E] = int(slot).to_bytes(2, "big")
        raw[0x1E:] = bytes((index * 7) & 0xFF for index in range(len(raw) - 0x1E))
        return bytes(raw)

    @staticmethod
    def strong_module_leaf(sequence: int, file_name: str) -> bytes:
        body = file_name.encode("ascii") + b"\x00"
        raw = bytearray(14 + len(body))
        raw[0:4] = (1).to_bytes(4, "big")
        raw[4:6] = len(raw).to_bytes(2, "big")
        raw[6:10] = (0x0112232E).to_bytes(4, "big")
        raw[10:14] = int(sequence).to_bytes(4, "big")
        raw[14:] = body
        return bytes(raw)

    def player_pool_item(
        self,
        *,
        message_id: int = 0x8023,
        slot: int = 30,
        report_index: int = 20,
        recorded_elapsed_seconds: float | None = None,
        recorded_at: float | None = None,
        model: str = "iPad13,4",
        system_version: str = "14.6",
        device_idfv: str = "TEST-IDFV-00000001",
        account_id: str = "GAME-42",
        sequence: int = 2,
        u20: int | None = None,
        pool_idx: int | None = None,
    ) -> dict:
        leaf_raw = bytearray(self.player_leaf(sequence, message_id, slot=slot))
        if u20 is not None:
            leaf_raw[0x20:0x24] = int(u20).to_bytes(4, "big")
            leaf_raw[0x24:0x28] = int(sequence).to_bytes(4, "big")
        recorded = frame(
            batch_children(
                0,
                self.device_context_leaf(
                    1,
                    model=model,
                    system_version=system_version,
                    device_idfv=device_idfv,
                ),
                bytes(leaf_raw),
            ),
            account_id=account_id,
            report_index=2,
        )
        item = _ace_try_extract_frames([recorded])
        assert item is not None
        # Historical same-device captures place these leaves at recording
        # report 20/21 and replay report 22.  Scheduling must therefore use
        # protocol slot 30 instead of trying to match report ordinals.
        item["report_index"] = report_index
        item["recorded_elapsed_seconds"] = recorded_elapsed_seconds
        item["recorded_at"] = recorded_at
        item["template_scope"] = "player"
        item["template_session_id"] = "player-same-device"
        if pool_idx is not None:
            item["pool_idx"] = pool_idx
        return item

    def test_v13013_individual_player_toggles_and_cross_account_gate(self):
        app_config.set("rebuild_controls_v3", True)
        for message_id in (0x8007, 0x800A, 0x800C, 0x800D, 0x800F, 0x8023, 0x8024, 0x802C):
            app_config.set(f"rebuild_player_{message_id:04X}_enabled", True)
        rows = [
            dict(
                next(
                    item for item in self.player_pool_item(
                        message_id=message_id,
                        slot=30,
                        report_index=index + 20,
                        account_id="DONOR",
                        pool_idx=index,
                    )["_type9_shadow_leaf_cache"]["rows"]
                    if item["key"][1] == message_id
                ),
                donor_game_id="DONOR",
                report_index=index + 20,
                pool_idx=index,
                recorded_elapsed_seconds=30.0,
                recorded_at=1_000.0,
                template_scope="player",
                template_session_id="player-same-device",
            )
            for index, message_id in enumerate(
                (0x8007, 0x800A, 0x800C, 0x800D, 0x800F, 0x8023, 0x8024, 0x802C),
                1,
            )
        ]
        for row in rows:
            row["device_cross_account_candidate"] = True
            row["device_context"] = {
                "model": "iPad13,4",
                "system_version": "14.6",
                "device_idfv": "TEST-IDFV-00000001",
            }
        groups, info = plan_same_device_player_groups(
            {},
            template_rows=rows,
            elapsed_seconds=100.0,
            unix_now=2_000.0,
            live_leaves=[],
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.6",
                "device_idfv": "TEST-IDFV-00000001",
            },
            live_game_id="GAME-42",
            allow_cross_account_device=True,
        )
        emitted = {
            int(row["message_id"])
            for group in groups
            for row in group.get("rows") or []
        }
        self.assertEqual(emitted, {0x8024, 0x802C, 0x800D})
        self.assertEqual(info["cross_account_device"], True)
        self.assertIn("0x800C", info["cross_account_blocked_message_ids"])
        self.assertNotIn("0x800D", info.get("cross_account_blocked_message_ids") or [])
        self.assertNotIn("0x8027", info.get("cross_account_blocked_message_ids") or [])
        self.assertNotIn("0x8029", info.get("cross_account_blocked_message_ids") or [])

    def test_v13015_scan_and_match_not_in_cross_account_block_list(self):
        from core.type9_v128_replenish import PLAYER_CROSS_ACCOUNT_BLOCKED_MESSAGE_IDS

        # 8027/8029 扫设备环境；802A/802B 对局；800D 纯轮次：均可跨账号。
        for message_id in (0x8027, 0x8029, 0x802A, 0x802B, 0x800D):
            self.assertNotIn(message_id, PLAYER_CROSS_ACCOUNT_BLOCKED_MESSAGE_IDS)
        self.assertIn(0x8007, PLAYER_CROSS_ACCOUNT_BLOCKED_MESSAGE_IDS)

    def test_v13015_800d_allowed_on_cross_device_same_account(self):
        app_config.set("rebuild_controls_v3", True)
        app_config.set("rebuild_player_800D_enabled", True)
        app_config.set("rebuild_player_8023_enabled", True)
        rows = []
        for index, message_id in enumerate((0x800D, 0x8023), 1):
            row = next(
                item for item in self.player_pool_item(
                    message_id=message_id,
                    slot=60 if message_id == 0x800D else 30,
                    report_index=20 + index,
                    account_id="GAME-42",
                    pool_idx=index,
                )["_type9_shadow_leaf_cache"]["rows"]
                if item["key"][1] == message_id
            )
            rows.append(
                dict(
                    row,
                    donor_game_id="GAME-42",
                    report_index=20 + index,
                    pool_idx=index,
                    recorded_elapsed_seconds=30.0,
                    recorded_at=1_000.0,
                    template_scope="player",
                    template_session_id="player-cross-device",
                    device_context={
                        "model": "iPad13,4",
                        "system_version": "14.6",
                        "device_idfv": "RECORDED-IDFV-AAAA",
                    },
                )
            )
        # 两档 800D 才能外推；这里先验证跨设备至少能拿到录制档。
        second = dict(rows[0])
        second_raw = bytearray(second["raw"])
        second_raw[0x1C:0x1E] = (660).to_bytes(2, "big")
        second["raw"] = bytes(second_raw)
        second["pool_idx"] = 3
        second["report_index"] = 30
        second["recorded_elapsed_seconds"] = 600.0
        rows.append(second)

        groups, info = plan_same_device_player_groups(
            {},
            template_rows=rows,
            elapsed_seconds=100.0,
            unix_now=2_000.0,
            live_leaves=[],
            live_device_context={
                "model": "iPhone15,3",
                "system_version": "26.3",
                "device_idfv": "LIVE-IDFV-BBBB",
            },
            live_game_id="GAME-42",
        )
        emitted = {
            int(row["message_id"])
            for group in groups
            for row in group.get("rows") or []
        }
        self.assertEqual(info["gate"], "CROSS_DEVICE_800D")
        self.assertTrue(info.get("cross_device_counter_only"))
        self.assertEqual(emitted, {0x800D})
        self.assertNotIn(0x8023, emitted)

    def test_v13015_800d_from_any_donor_when_cross_device_cross_account(self):
        """跨设备+跨账号：只要勾选 800D，任意 donor 的 800D 叶仍可调度。"""
        app_config.set("rebuild_controls_v3", True)
        app_config.set("rebuild_player_800D_enabled", True)
        row = next(
            item for item in self.player_pool_item(
                message_id=0x800D,
                slot=60,
                report_index=20,
                account_id="DONOR-OTHER",
                pool_idx=1,
            )["_type9_shadow_leaf_cache"]["rows"]
            if item["key"][1] == 0x800D
        )
        row = dict(
            row,
            donor_game_id="DONOR-OTHER",
            report_index=20,
            pool_idx=1,
            recorded_elapsed_seconds=30.0,
            recorded_at=1_000.0,
            template_scope="player",
            template_session_id="player-foreign",
            device_context={
                "model": "iPad13,4",
                "system_version": "14.6",
                "device_idfv": "RECORDED-IDFV-AAAA",
            },
        )
        # 无 device_cross_account_candidate，也无同账号。
        groups, info = plan_same_device_player_groups(
            {},
            template_rows=[row],
            elapsed_seconds=100.0,
            unix_now=2_000.0,
            live_leaves=[],
            live_device_context={
                "model": "iPhone15,3",
                "system_version": "26.3",
                "device_idfv": "LIVE-IDFV-BBBB",
            },
            live_game_id="GAME-42",
            allow_cross_account_device=False,
        )
        emitted = {
            int(item["message_id"])
            for group in groups
            for item in group.get("rows") or []
        }
        self.assertEqual(info["gate"], "CROSS_DEVICE_800D")
        self.assertEqual(emitted, {0x800D})
        self.assertTrue(info.get("cross_account_device"))
        self.assertFalse(info["builtin_800d_fallback"])
        self.assertEqual(info["800d_source"], "cross_device_donor")

    def test_v131_builtin_800d_emits_without_recording_or_device_context(self):
        app_config.set("rebuild_controls_v3", True)
        app_config.set("rebuild_player_800D_enabled", True)
        groups, info = plan_same_device_player_groups(
            {},
            template_rows=[],
            elapsed_seconds=(60.5 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT,
            unix_now=2_000.0,
            live_leaves=[],
            live_device_context={},
            live_game_id="GAME-42",
        )
        rows = [row for group in groups for row in group.get("rows") or []]
        self.assertEqual(info["gate"], "BUILTIN_800D")
        self.assertTrue(info["builtin_800d_fallback"])
        self.assertEqual(info["800d_source"], "builtin")
        self.assertIn("0x800D", info["recorded_missing_message_ids"])
        self.assertEqual(len(rows), 1)
        raw = bytes(rows[0]["raw"])
        self.assertEqual(len(raw), 64)
        self.assertEqual(int.from_bytes(raw[0x16:0x18], "big"), 0x800D)
        self.assertEqual(int.from_bytes(raw[0x1C:0x1E], "big"), 60)
        self.assertEqual(int.from_bytes(raw[0x20:0x24], "big"), 1)

    def test_v131_builtin_800d_keeps_fixed_600_slot_schedule(self):
        app_config.set("rebuild_controls_v3", True)
        app_config.set("rebuild_player_800D_enabled", True)
        state = {}

        def plan_at(slot):
            groups, info = plan_same_device_player_groups(
                state,
                template_rows=[],
                elapsed_seconds=(slot + 0.5 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT,
                unix_now=2_000.0 + slot,
                live_leaves=[],
                live_device_context={},
                live_game_id="GAME-42",
            )
            rows = [row for group in groups for row in group.get("rows") or []]
            self.assertEqual(info["800d_source"], "builtin")
            return [bytes(row["raw"]) for row in rows]

        emitted = plan_at(60) + plan_at(660) + plan_at(1260)
        self.assertEqual(
            [int.from_bytes(raw[0x1C:0x1E], "big") for raw in emitted],
            [60, 660, 1260],
        )
        self.assertEqual(
            [int.from_bytes(raw[0x20:0x24], "big") for raw in emitted],
            [1, 21, 41],
        )

    def test_v131_live_800d_suppresses_builtin_same_slot(self):
        app_config.set("rebuild_controls_v3", True)
        app_config.set("rebuild_player_800D_enabled", True)
        live_800d = self.player_leaf(11, 0x800D, slot=60)
        groups, info = plan_same_device_player_groups(
            {},
            template_rows=[],
            elapsed_seconds=(60.5 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT,
            unix_now=2_000.0,
            live_leaves=[{"raw": live_800d}],
            live_device_context={},
            live_game_id="GAME-42",
        )
        self.assertEqual(groups, [])
        self.assertTrue(info["builtin_800d_fallback"])
        self.assertEqual(info["suppressed_by_live"], ["0x800D"])

    def test_v131_disabled_800d_keeps_no_recording_behavior(self):
        app_config.set("rebuild_controls_v3", True)
        app_config.set("rebuild_player_800D_enabled", False)
        groups, info = plan_same_device_player_groups(
            {},
            template_rows=[],
            elapsed_seconds=(60.5 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT,
            unix_now=2_000.0,
            live_leaves=[],
            live_device_context={},
            live_game_id="GAME-42",
        )
        self.assertEqual(groups, [])
        self.assertEqual(info["gate"], "NO_PLAYER_RECORDING")
        self.assertFalse(info["builtin_800d_fallback"])

    def test_v131_replay_pipeline_injects_builtin_800d_without_pool(self):
        app_config.set("rebuild_controls_v3", True)
        app_config.set("rebuild_central9_enabled", False)
        app_config.set("rebuild_player_800D_enabled", True)
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=(60.5 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT,
            session_unix_time=2_000.0,
        )
        self.assertTrue(changed)
        inserted = []
        for source in output[1:]:
            _, material = self.decode_frame(source)
            inserted.extend(material["leaves"])
        leaf_800d = next(row for row in inserted if row["message_id"] == 0x800D)
        raw = bytes(leaf_800d["raw"])
        self.assertEqual(int.from_bytes(raw[0x1C:0x1E], "big"), 60)
        self.assertEqual(int.from_bytes(raw[0x20:0x24], "big"), 1)
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(supplement["gate"], "BUILTIN_800D")
        self.assertEqual(supplement["800d_source"], "builtin")

    def test_v13013_same_account_can_select_800c_without_extension(self):
        app_config.set("rebuild_controls_v3", True)
        app_config.set("rebuild_player_800C_enabled", True)
        row = next(
            item for item in self.player_pool_item(
                message_id=0x800C,
                slot=30,
                report_index=20,
                account_id="GAME-42",
                pool_idx=1,
            )["_type9_shadow_leaf_cache"]["rows"]
            if item["key"][1] == 0x800C
        )
        row = dict(
            row,
            donor_game_id="GAME-42",
            report_index=20,
            pool_idx=1,
            recorded_elapsed_seconds=30.0,
            recorded_at=1_000.0,
            template_scope="player",
            template_session_id="player-same-device",
        )
        row["device_context"] = {
            "model": "iPad13,4",
            "system_version": "14.6",
            "device_idfv": "TEST-IDFV-00000001",
        }
        groups, _ = plan_same_device_player_groups(
            {},
            template_rows=[row],
            elapsed_seconds=100.0,
            unix_now=2_000.0,
            live_leaves=[],
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.6",
                "device_idfv": "TEST-IDFV-00000001",
            },
            live_game_id="GAME-42",
        )
        self.assertEqual(
            [int(item["message_id"]) for group in groups for item in group["rows"]],
            [0x800C],
        )
        self.assertFalse(any(item.get("periodic_extension") for group in groups for item in group["rows"]))

    def test_v1285_same_device_player_recording_adds_recorded_only_leaf(self):
        app_config.set("full_rebuild_01_mode", True)
        live = frame(
            self.device_context_leaf(
                10, model="iPhone15,3", system_version="26.30"
            ),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [
                self.player_pool_item(
                    message_id=0x800F,
                    model="iPhone15,3",
                    system_version="26.3",
                ),
                self.player_pool_item(
                    message_id=0x8023,
                    model="iPhone15,3",
                    system_version="26.3",
                ),
            ],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=31.0,
        )
        self.assertTrue(changed)
        inserted_ids = []
        for source in output[1:]:
            _, inserted = self.decode_frame(source)
            inserted_ids.extend(
                row["message_id"] for row in inserted["leaves"]
            )
        self.assertIn(0x800F, inserted_ids)
        self.assertIn(0x8023, inserted_ids)
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(supplement["gate"], "MATCH")
        self.assertEqual(
            supplement["due_message_ids"], ["0x800F", "0x8023"]
        )
        self.assertEqual(logs[0]["reason"], "V128_7_SAME_DEVICE_REPORT_INJECT")

    def test_v129_clean_recording_replays_for_other_account_on_same_device(self):
        app_config.set("full_rebuild_01_mode", True)
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-99",
            report_index=2,
        )
        item = self.player_pool_item(
            message_id=0x8023,
            account_id="GAME-42",
        )
        item.update(
            {
                "donor_game_id": "GAME-42",
                "device_cross_account_candidate": True,
            }
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [item],
            [0, 0, {}],
            expected_game_id="GAME-99",
            allow_cross_account=True,
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=31.0,
        )
        self.assertTrue(changed)
        inserted_ids = []
        for source in output[1:]:
            _, inserted = self.decode_frame(source)
            inserted_ids.extend(row["message_id"] for row in inserted["leaves"])
        self.assertIn(0x8023, inserted_ids)
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(supplement["gate"], "MATCH")
        self.assertTrue(supplement["cross_account_device"])
        self.assertEqual(supplement["donor_game_id"], "GAME-42")

    def test_v129_cross_account_recording_is_held_on_device_mismatch(self):
        app_config.set("full_rebuild_01_mode", True)
        live = frame(
            self.device_context_leaf(10, model="iPhone15,3", device_idfv="LIVE-IDFV-IPHONE"),
            account_id="GAME-99",
            report_index=2,
        )
        item = self.player_pool_item(
            message_id=0x8023,
            account_id="GAME-42",
            model="iPad13,4",
        )
        item.update(
            {
                "donor_game_id": "GAME-42",
                "device_cross_account_candidate": True,
            }
        )
        logs = []
        output, _ = _ace_try_replay_template(
            [live],
            [item],
            [0, 0, {}],
            expected_game_id="GAME-99",
            allow_cross_account=True,
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=31.0,
        )
        inserted_ids = []
        for source in output[1:]:
            _, inserted = self.decode_frame(source)
            inserted_ids.extend(row["message_id"] for row in inserted["leaves"])
        self.assertNotIn(0x8023, inserted_ids)
        self.assertEqual(
            logs[0]["shadow_rebuild"]["v129_device_gate"],
            "PENDING_OR_MISMATCH",
        )

    def test_v129_same_device_donor_wins_over_exact_account_wrong_device(self):
        app_config.set("full_rebuild_01_mode", True)
        live = frame(
            self.device_context_leaf(10, model="iPad13,4"),
            account_id="GAME-99",
            report_index=2,
        )
        exact_wrong = self.player_pool_item(
            message_id=0x800F,
            account_id="GAME-99",
            model="iPhone15,3",
            device_idfv="WRONG-IDFV-IPHONE",
        )
        exact_wrong.update(
            {
                "donor_game_id": "GAME-99",
                "template_session_id": "exact-account-wrong-device",
                "device_cross_account_candidate": False,
            }
        )
        same_device = self.player_pool_item(
            message_id=0x8023,
            account_id="GAME-42",
            model="iPad13,4",
        )
        same_device.update(
            {
                "donor_game_id": "GAME-42",
                "template_session_id": "same-device-clean-recording",
                "device_cross_account_candidate": True,
            }
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [exact_wrong, same_device],
            [0, 0, {}],
            expected_game_id="GAME-99",
            allow_cross_account=True,
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=31.0,
        )
        self.assertTrue(changed)
        inserted_ids = []
        for source in output[1:]:
            _, inserted = self.decode_frame(source)
            inserted_ids.extend(row["message_id"] for row in inserted["leaves"])
        self.assertIn(0x8023, inserted_ids)
        self.assertNotIn(0x800F, inserted_ids)
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(
            supplement["selected_session_id"],
            "same-device-clean-recording",
        )

    def test_v130_first_live_report_confirms_pending_reconnect(self):
        state = ensure_v128_state({})
        state["emitted"] = ["8004@30#0"]
        state["last_native_live_leaf_sequence"] = 9
        state["leaf_offset"] = 27
        state["last_output_leaf_sequence"] = 36
        context = {
            "v128_replenish": state,
            "v130_pending_reconnect": {
                "previous_last_live_leaf_sequence": 9,
                "fresh_started_monotonic": time.monotonic(),
            },
        }
        logs = []
        _ace_try_replay_template(
            [frame(
                self.device_context_leaf(10),
                account_id="GAME-42",
                report_index=2,
            )],
            [],
            [0, 0, context],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=1.0,
        )
        result = context["v130_reconnect_result"]
        self.assertTrue(result["continued"])
        self.assertEqual(result["decision"], "CONFIRMED_CONTINUATION")
        self.assertEqual(result["forward_delta"], 1)
        self.assertIn(
            "8004@30#0", context["v128_replenish"]["emitted"]
        )
        self.assertEqual(
            context["v128_replenish"]["last_native_live_leaf_sequence"], 10
        )
        self.assertEqual(context["v128_replenish"]["leaf_offset"], 27)
        self.assertEqual(context["v128_replenish"]["last_output_leaf_sequence"], 37)
        self.assertEqual(
            logs[0]["v130_reconnect_resolution"]["classification"],
            "NETWORK_RECONNECT",
        )

    def test_v130_reset_live_report_discards_old_semantic_state(self):
        state = ensure_v128_state({})
        state["emitted"] = ["8004@30#0"]
        state["last_native_live_leaf_sequence"] = 2196
        context = {
            "live_device_context": {"device_idfv": "OLD-DEVICE"},
            "v128_replenish": state,
            "v130_pending_reconnect": {
                "previous_last_live_leaf_sequence": 2196,
                "fresh_started_monotonic": time.monotonic() - 1.0,
            },
        }
        logs = []
        _ace_try_replay_template(
            [frame(
                self.device_context_leaf(10),
                account_id="GAME-42",
                report_index=2,
            )],
            [],
            [0, 0, context],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=600.0,
        )
        result = context["v130_reconnect_result"]
        self.assertFalse(result["continued"])
        self.assertEqual(result["decision"], "REJECTED_NEW_SESSION")
        self.assertNotEqual(
            context["live_device_context"].get("device_idfv"), "OLD-DEVICE"
        )
        self.assertEqual(context["v128_replenish"]["emitted"], [])
        self.assertEqual(
            context["v128_replenish"]["last_native_live_leaf_sequence"], 10
        )
        self.assertLess(logs[0]["v128_replenish"]["elapsed_ms"], 5000)

    def test_full_rebuild_off_uses_central9_for_matching_device(self):
        app_config.set("full_rebuild_01_mode", False)
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [self.player_pool_item(message_id=0x8023)],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=31.0,
        )
        self.assertTrue(changed)
        inserted_ids = []
        for source in output[1:]:
            _, inserted = self.decode_frame(source)
            inserted_ids.extend(
                row["message_id"] for row in inserted["leaves"]
            )
        self.assertIn(0x8000, inserted_ids)
        self.assertNotIn(0x8023, inserted_ids)
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertFalse(supplement["enabled"])
        self.assertEqual(supplement["gate"], "DISABLED")

    def test_v1285_device_mismatch_keeps_central9_only(self):
        app_config.set("full_rebuild_01_mode", True)
        live = frame(
            self.device_context_leaf(
                10,
                model="iPhone15,3",
                system_version="26.3",
                device_idfv="LIVE-IDFV-IPHONE",
            ),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [self.player_pool_item()],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=31.0,
        )
        self.assertTrue(changed)
        inserted_ids = []
        for source in output[1:]:
            _, inserted = self.decode_frame(source)
            inserted_ids.extend(
                row["message_id"] for row in inserted["leaves"]
            )
        self.assertIn(0x8000, inserted_ids)
        self.assertNotIn(0x8023, inserted_ids)
        self.assertEqual(
            logs[0]["v128_replenish"]["same_device_player"]["gate"],
            "CROSS_DEVICE_800D",
        )

    def test_v1285_same_model_different_idfv_is_cross_device(self):
        app_config.set("full_rebuild_01_mode", True)
        live = frame(
            self.device_context_leaf(
                10,
                model="iPhone15,3",
                system_version="26.3",
                device_idfv="LIVE-IDFV-00000001",
            ),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [self.player_pool_item(
                model="iPhone15,3", system_version="26.3"
            )],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=2.0,
        )
        self.assertFalse(changed)
        self.assertEqual(len(output), 1)
        gate = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(gate["gate"], "CROSS_DEVICE_800D")
        self.assertIn("device_idfv", gate["gate_fields"])

    def test_v13018_idfv_match_ignores_ver_vs_idevsysver(self):
        self.assertEqual(
            strict_device_gate(
                {
                    "model": "iPhone15,3",
                    "system_version": "16.30",
                    "device_idfv": "0FFFC5A3-AEA4-48F6-B133-D426E5573F09",
                },
                {
                    "model": "iPhone15,3",
                    "system_version": "16.3.1",
                    "device_idfv": "0FFFC5A3-AEA4-48F6-B133-D426E5573F09",
                },
            ),
            ("MATCH", []),
        )

    def test_v13018_same_idfv_unlocks_player_layer_despite_version_encoding(self):
        app_config.set("rebuild_controls_v3", True)
        for message_id in (0x800D, 0x8024, 0x802C):
            app_config.set(f"rebuild_player_{message_id:04X}_enabled", True)
        rows = []
        for index, message_id in enumerate((0x800D, 0x8024, 0x802C), 1):
            row = next(
                item for item in self.player_pool_item(
                    message_id=message_id,
                    slot=60 if message_id == 0x800D else 30,
                    report_index=20 + index,
                    account_id="GAME-42",
                    pool_idx=index,
                )["_type9_shadow_leaf_cache"]["rows"]
                if item["key"][1] == message_id
            )
            rows.append(
                dict(
                    row,
                    donor_game_id="GAME-42",
                    report_index=20 + index,
                    pool_idx=index,
                    recorded_elapsed_seconds=30.0,
                    recorded_at=1_000.0,
                    template_scope="player",
                    template_session_id="player-same-idfv",
                    device_context={
                        "model": "iPhone15,3",
                        "system_version": "16.3.1",
                        "device_idfv": "0FFFC5A3-AEA4-48F6-B133-D426E5573F09",
                    },
                )
            )
        groups, info = plan_same_device_player_groups(
            {},
            template_rows=rows,
            elapsed_seconds=100.0,
            unix_now=2_000.0,
            live_leaves=[],
            live_device_context={
                "model": "iPhone15,3",
                "system_version": "16.30",
                "device_idfv": "0FFFC5A3-AEA4-48F6-B133-D426E5573F09",
            },
            live_game_id="GAME-42",
        )
        emitted = {
            int(item["message_id"])
            for group in groups
            for item in group.get("rows") or []
        }
        self.assertEqual(info["gate"], "MATCH")
        self.assertFalse(info.get("cross_device_counter_only"))
        self.assertEqual(emitted, {0x800D, 0x8024, 0x802C})

    def test_v13018_missing_live_idfv_stays_pending(self):
        app_config.set("rebuild_controls_v3", True)
        app_config.set("rebuild_player_800D_enabled", True)
        row = next(
            item for item in self.player_pool_item(
                message_id=0x800D,
                slot=60,
                report_index=21,
                account_id="GAME-42",
                pool_idx=1,
            )["_type9_shadow_leaf_cache"]["rows"]
            if item["key"][1] == 0x800D
        )
        row = dict(
            row,
            donor_game_id="GAME-42",
            report_index=21,
            pool_idx=1,
            recorded_elapsed_seconds=30.0,
            recorded_at=1_000.0,
            template_scope="player",
            template_session_id="player-waiting-idfv",
            device_context={
                "model": "iPhone15,3",
                "system_version": "16.3.1",
                "device_idfv": "0FFFC5A3-AEA4-48F6-B133-D426E5573F09",
            },
        )
        groups, info = plan_same_device_player_groups(
            {},
            template_rows=[row],
            elapsed_seconds=100.0,
            unix_now=2_000.0,
            live_leaves=[],
            live_device_context={
                "model": "iPhone15,3",
                "system_version": "16.30",
            },
            live_game_id="GAME-42",
        )
        self.assertEqual(groups, [])
        self.assertEqual(info["gate"], "PENDING_CONTEXT")
        self.assertIn("live.device_idfv", info["gate_fields"])
        self.assertFalse(info.get("cross_device_counter_only"))

    def test_v13018_merge_keeps_idevsysver_over_ver_header(self):
        merged = merge_device_context(
            {"system_version": "16.30", "model": "iPhone15,3"},
            {
                "system_version": "16.3.1",
                "device_idfv": "0FFFC5A3-AEA4-48F6-B133-D426E5573F09",
            },
            {"system_version": "16.30", "model": "iPhone15,3"},
        )
        self.assertEqual(merged["system_version"], "16.3.1")
        self.assertEqual(
            merged["device_idfv"], "0FFFC5A3-AEA4-48F6-B133-D426E5573F09"
        )

    def test_v1285_8027_8029_are_recorded_and_wait_for_event_time(self):
        app_config.set("full_rebuild_01_mode", True)
        for message_id in (0x8027, 0x8029):
            logs = []
            live = frame(
                self.device_context_leaf(10),
                account_id="GAME-42",
                report_index=2,
            )
            output, changed = _ace_try_replay_template(
                [live],
                [self.player_pool_item(message_id=message_id)],
                [0, 0, {}],
                expected_game_id="GAME-42",
                special_rule_store=self.store,
                on_log=logs.append,
                session_elapsed_seconds=2.0,
            )
            self.assertFalse(changed)
            self.assertEqual(len(output), 1)
            supplement = logs[0]["v128_replenish"]["same_device_player"]
            self.assertEqual(supplement["gate"], "MATCH")
            self.assertIn(
                f"0x{message_id:04X}", supplement["eligible_message_ids"]
            )
            self.assertIn(
                f"0x{message_id:04X}",
                supplement["recorded_dynamic_ready_message_ids"],
            )
            self.assertEqual(supplement["due_message_ids"], [])

    def test_v1285_missing_player_id_live_leak_uses_secondary_pass_live(self):
        app_config.set("full_rebuild_01_mode", True)
        live = frame(
            batch_children(
                0,
                self.device_context_leaf(10),
                self.player_leaf(11, 0x8027),
            ),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [self.player_pool_item(message_id=0x8023)],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=2.0,
        )
        self.assertFalse(changed)
        self.assertEqual(output, [live])
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(supplement["gate"], "MATCH")
        self.assertIn("0x8027", supplement["recorded_missing_message_ids"])
        self.assertEqual(
            supplement["live_secondary_fallback_message_ids"], ["0x8027"]
        )
        self.assertEqual(
            supplement["secondary_fallback_scope"],
            "ALL_PLAYER_SUPPLEMENT_IDS",
        )
        self.assertIn(
            "HOT_RULE_MISS_PASS_LIVE",
            supplement["secondary_fallback_policy"],
        )

    def test_v1285_no_player_recording_live_leak_still_uses_secondary(self):
        app_config.set("full_rebuild_01_mode", True)
        live = frame(
            self.player_leaf(11, 0x8029),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=2.0,
        )
        self.assertFalse(changed)
        self.assertEqual(output, [live])
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(supplement["gate"], "NO_PLAYER_RECORDING")
        self.assertIn("0x8029", supplement["recorded_missing_message_ids"])
        self.assertEqual(
            supplement["live_secondary_fallback_message_ids"], ["0x8029"]
        )

    def test_v1285_missing_player_id_live_leak_uses_matching_hot_rule(self):
        app_config.set("full_rebuild_01_mode", True)
        self.store.replace_document(
            {
                "schema": HOT_RULE_SCHEMA,
                "revision": "v128-test-secondary-800d",
                "rules": [
                    {
                        "id": "secondary-patch-800d",
                        "enabled": True,
                        "match": {
                            "record_code": "0x0102000A",
                            "message_id": "0x800D",
                            "length": 56,
                        },
                        "action": "patch_live",
                        "patches": [{"offset": 30, "hex": "AABB"}],
                    }
                ],
            }
        )
        live = frame(
            batch_children(
                0,
                self.device_context_leaf(10),
                self.player_leaf(11, 0x800D),
            ),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [self.player_pool_item(message_id=0x8023)],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=2.0,
        )
        self.assertTrue(changed)
        _, material = self.decode_frame(output[0])
        patched = next(
            row for row in material["leaves"] if row["message_id"] == 0x800D
        )
        self.assertEqual(bytes(patched["raw"])[30:32], b"\xAA\xBB")
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertIn("0x800D", supplement["recorded_missing_message_ids"])
        self.assertEqual(
            supplement["live_secondary_fallback_message_ids"], ["0x800D"]
        )

    def test_v1285_dynamic_player_leaf_waits_for_recorded_slot(self):
        app_config.set("full_rebuild_01_mode", True)
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [self.player_pool_item(message_id=0x8024)],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=2.0,
        )
        self.assertFalse(changed)
        self.assertEqual(len(output), 1)
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(supplement["gate"], "MATCH")
        self.assertIn("0x8024", supplement["eligible_message_ids"])
        self.assertIn("0x8024", supplement["dynamic_ready_message_ids"])
        self.assertEqual(supplement["due_message_ids"], [])

    def test_v1285_all_dynamic_player_families_emit_on_recorded_timeline(self):
        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_scan_waves", "repeat_first")
        specifications = [
            (0x8007, 60, 29, None),
            (0x800A, 30, 20, None),
            (0x800C, 13, 3, None),
            (0x800D, 60, 29, None),
            (0x8024, 30, 21, None),
            (0x8027, 0x3456, 26, 38.5),
            (0x8029, 0x3456, 24, 28.0),
            (0x802C, 30, 21, None),
        ]
        pool = [
            self.player_pool_item(
                message_id=message_id,
                slot=slot,
                report_index=report_index,
                recorded_elapsed_seconds=recorded_elapsed,
            )
            for message_id, slot, report_index, recorded_elapsed in specifications
        ]
        live = frame(
            batch_children(
                0,
                self.device_context_leaf(10),
                self.player_leaf(10, 0x8028, slot=0x3456),
            ),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            pool,
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=90.0,
        )
        self.assertTrue(changed)
        output_ids = set()
        for source in output[1:]:
            _, material = self.decode_frame(source)
            output_ids.update(
                row["message_id"] for row in material["leaves"]
            )
        expected_ids = {row[0] for row in specifications}
        self.assertTrue(expected_ids.issubset(output_ids))
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(supplement["gate"], "MATCH")
        self.assertEqual(supplement["dynamic_pending_message_ids"], [])
        self.assertEqual(
            set(supplement["due_message_ids"]),
            {f"0x{value:04X}" for value in expected_ids},
        )

    def test_v130_event_identity_dedup_skips_near_duplicate_8029(self):
        """同一8029语义指纹只外发一次，即使录制池有多行近重复。"""
        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_scan_waves", "repeat_first")
        base = bytearray(self.player_leaf(2, 0x8029, slot=0x3456))
        # 模拟录制近重复：正文主体相同，仅瞬时字段 body[2:6]（叶+0x20）不同。
        twin = bytearray(base)
        twin[0x20:0x24] = (0x01020304).to_bytes(4, "big")
        base[0x20:0x24] = (0x0A0B0C0D).to_bytes(4, "big")
        from core.type9_v128_replenish import player_leaf_identity

        self.assertEqual(
            player_leaf_identity(base),
            player_leaf_identity(twin),
        )

        def pool_row(raw: bytes, report_index: int, pool_idx: int) -> dict:
            recorded = frame(
                batch_children(
                    0,
                    self.device_context_leaf(1),
                    bytes(raw),
                ),
                account_id="GAME-42",
                report_index=2,
            )
            item = _ace_try_extract_frames([recorded])
            assert item is not None
            item["report_index"] = report_index
            item["recorded_elapsed_seconds"] = 28.0
            item["template_scope"] = "player"
            item["template_session_id"] = "player-same-device"
            item["pool_idx"] = pool_idx
            return item

        pool = [
            pool_row(bytes(base), 59, 100),
            pool_row(bytes(twin), 61, 101),
        ]
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            pool,
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=90.0,
        )
        self.assertTrue(changed)
        count_8029 = 0
        identities = []
        for source in output[1:]:
            _, material = self.decode_frame(source)
            for row in material["leaves"]:
                if row.get("message_id") == 0x8029:
                    count_8029 += 1
                    identities.append(player_leaf_identity(row["raw"]))
        self.assertEqual(count_8029, 1, identities)
        self.assertEqual(len(set(identities)), 1)
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(supplement["due_message_ids"], ["0x8029"])

    def test_v1307_8029_keeps_same_wave_leaves_at_different_elapsed(self):
        """同波、elapsed 不同的 8029 同进程多片要都发（backboardd×7）。"""
        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_scan_waves", "repeat_first")
        base = bytearray(self.player_leaf(2, 0x8029, slot=0x3456))
        twin = bytearray(base)
        twin[0x20:0x24] = (0x01020304).to_bytes(4, "big")
        base[0x20:0x24] = (0x0A0B0C0D).to_bytes(4, "big")
        self.assertEqual(player_leaf_identity(base), player_leaf_identity(twin))
        self.assertNotEqual(
            player_event_emit_key(base, recorded_elapsed_seconds=28.0),
            player_event_emit_key(twin, recorded_elapsed_seconds=33.5),
        )

        def pool_row(raw: bytes, elapsed: float, pool_idx: int) -> dict:
            recorded = frame(
                batch_children(
                    0,
                    self.device_context_leaf(1),
                    bytes(raw),
                ),
                account_id="GAME-42",
                report_index=2,
            )
            item = _ace_try_extract_frames([recorded])
            assert item is not None
            item["report_index"] = 24
            item["recorded_elapsed_seconds"] = elapsed
            item["template_scope"] = "player"
            item["template_session_id"] = "player-same-device"
            item["pool_idx"] = pool_idx
            return item

        pool = [
            pool_row(bytes(base), 28.0, 100),
            pool_row(bytes(twin), 33.5, 101),
        ]
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        output, changed = _ace_try_replay_template(
            [live],
            pool,
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=90.0,
        )
        self.assertTrue(changed)
        count_8029 = 0
        for source in output[1:]:
            _, material = self.decode_frame(source)
            count_8029 += sum(
                1 for row in material["leaves"] if row.get("message_id") == 0x8029
            )
        self.assertEqual(count_8029, 2)

    def test_v130_8027_replays_recorded_scan_wave_ten_minutes_later(self):
        """129绿色：同名8027约12分钟后再扫一轮，identity 不能整场只发一次。"""
        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_scan_waves", "repeat_first")
        source = self.player_leaf(2, 0x8027, slot=0x3456)
        self.assertEqual(
            player_event_emit_key(source, recorded_elapsed_seconds=43.1),
            f"{player_leaf_identity(source)}@W0",
        )
        self.assertEqual(
            player_event_emit_key(source, recorded_elapsed_seconds=787.8),
            f"{player_leaf_identity(source)}@W1",
        )

        def pool_row(report_index: int, elapsed: float, pool_idx: int) -> dict:
            recorded = frame(
                batch_children(
                    0,
                    self.device_context_leaf(1),
                    source,
                ),
                account_id="GAME-42",
                report_index=2,
            )
            item = _ace_try_extract_frames([recorded])
            assert item is not None
            item["report_index"] = report_index
            item["recorded_elapsed_seconds"] = elapsed
            item["template_scope"] = "player"
            item["template_session_id"] = "player-same-device"
            item["pool_idx"] = pool_idx
            return item

        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        state = [0, 0, {}]
        pool = [pool_row(31, 43.1, 100), pool_row(189, 787.8, 101)]

        def count_8027(frames: list[bytes]) -> int:
            total = 0
            for frame_bytes in frames[1:]:
                _, material = self.decode_frame(frame_bytes)
                total += sum(
                    1
                    for row in material["leaves"]
                    if row.get("message_id") == 0x8027
                )
            return total

        first_out, first_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=90.0,
        )
        self.assertTrue(first_changed)
        self.assertEqual(count_8027(first_out), 1)

        second_out, second_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=800.0,
        )
        self.assertTrue(second_changed)
        self.assertEqual(count_8027(second_out), 1)

    def _scan_wave_pool(self):
        return [
            self.player_pool_item(
                message_id=0x8029,
                slot=0x3456,
                report_index=20,
                recorded_elapsed_seconds=35.0,
                sequence=2,
                u20=200,
                pool_idx=20,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                report_index=25,
                recorded_elapsed_seconds=40.0,
                sequence=3,
                u20=268,
                pool_idx=25,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                report_index=50,
                recorded_elapsed_seconds=50.0,
                sequence=4,
                u20=59,
                pool_idx=50,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                report_index=168,
                recorded_elapsed_seconds=784.0,
                sequence=5,
                u20=268,
                pool_idx=168,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                report_index=170,
                recorded_elapsed_seconds=800.0,
                sequence=6,
                u20=180,
                pool_idx=170,
            ),
        ]

    def _count_scan_leaves(self, frames: list[bytes], message_id: int) -> list[int]:
        values = []
        for frame_bytes in frames[1:]:
            _, material = self.decode_frame(frame_bytes)
            for row in material["leaves"]:
                if row.get("message_id") != message_id:
                    continue
                raw = bytes(row.get("raw") or b"")
                values.append(int.from_bytes(raw[0x20:0x24], "big"))
        return values

    def test_v1306_repeats_first_complete_8027_wave_after_second_open(self):
        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_scan_waves", "repeat_first")
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        state = [0, 0, {}]
        pool = self._scan_wave_pool()
        first_out, first_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=90.0,
        )
        self.assertTrue(first_changed)
        self.assertEqual(self._count_scan_leaves(first_out, 0x8027), [268, 59])
        self.assertEqual(self._count_scan_leaves(first_out, 0x8029), [200])
        scan = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(scan["rebuild_scan_waves"], "repeat_first")
        self.assertAlmostEqual(scan["scan_wave_period_seconds"], 744.0)
        self.assertAlmostEqual(scan["scan_wave_origin_elapsed"], 40.0)

        second_out, second_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=800.0,
        )
        self.assertTrue(second_changed)
        self.assertEqual(self._count_scan_leaves(second_out, 0x8027), [268, 59])
        self.assertEqual(self._count_scan_leaves(second_out, 0x8029), [200])

    def test_v1306_scan_wave_off_does_not_inject(self):
        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_scan_waves", "off")
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        state = [0, 0, {}]
        pool = self._scan_wave_pool()
        first_out, _first_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=90.0,
        )
        self.assertEqual(self._count_scan_leaves(first_out, 0x8027), [])
        self.assertEqual(self._count_scan_leaves(first_out, 0x8029), [])
        self.assertEqual(
            logs[0]["v128_replenish"]["same_device_player"]["rebuild_scan_waves"],
            "off",
        )
        second_out, _changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=800.0,
        )
        self.assertEqual(self._count_scan_leaves(second_out, 0x8027), [])
        self.assertEqual(self._count_scan_leaves(second_out, 0x8029), [])

    def test_v1306_does_not_repeat_incomplete_first_8027_wave(self):
        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_scan_waves", "repeat_first")
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        pool = [
            self.player_pool_item(
                message_id=0x8029,
                slot=0x3456,
                recorded_elapsed_seconds=35.0,
                sequence=2,
                u20=200,
                pool_idx=20,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                recorded_elapsed_seconds=40.0,
                sequence=3,
                u20=268,
                pool_idx=25,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                recorded_elapsed_seconds=784.0,
                sequence=5,
                u20=268,
                pool_idx=168,
            ),
        ]
        logs = []
        state = [0, 0, {}]
        first_out, first_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=90.0,
        )
        self.assertTrue(first_changed)
        self.assertEqual(self._count_scan_leaves(first_out, 0x8027), [268])
        scan = logs[0]["v128_replenish"]["same_device_player"]
        self.assertIsNone(scan["scan_wave_period_seconds"])
        second_out, second_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=800.0,
        )
        self.assertTrue(second_changed)
        self.assertEqual(self._count_scan_leaves(second_out, 0x8027), [268])

    def test_v1285_rebuilds_confirmed_player_counters(self):
        round_leaf = bytearray(self.player_leaf(2, 0x800D, slot=660))
        round_leaf[0x20:0x24] = (999).to_bytes(4, "big")
        rebuilt_round, round_fields = rebuild_player_supplement_leaf(
            round_leaf,
            target_slot=660,
            unix_now=200.0,
            recorded_at=100.0,
        )
        self.assertEqual(int.from_bytes(rebuilt_round[0x20:0x24], "big"), 21)
        self.assertEqual(round_fields, ["round_counter@0x20"])

        elapsed_leaf = bytearray(self.player_leaf(2, 0x802C, slot=30))
        elapsed_leaf[0x20:0x24] = (1000).to_bytes(4, "big")
        rebuilt_elapsed, elapsed_fields = rebuild_player_supplement_leaf(
            elapsed_leaf,
            target_slot=30,
            unix_now=160.0,
            recorded_at=100.0,
        )
        self.assertEqual(
            int.from_bytes(rebuilt_elapsed[0x20:0x24], "big"), 1060
        )
        self.assertEqual(elapsed_fields, ["elapsed_counter@0x20"])

        zero_recorded_at, zero_fields = rebuild_player_supplement_leaf(
            elapsed_leaf,
            target_slot=30,
            unix_now=60.0,
            recorded_at=0.0,
        )
        self.assertEqual(
            int.from_bytes(zero_recorded_at[0x20:0x24], "big"), 1060
        )
        self.assertEqual(zero_fields, ["elapsed_counter@0x20"])

        chained_elapsed = bytearray(self.player_leaf(3, 0x802C, slot=30))
        chained_elapsed[0x20:0x24] = (1000).to_bytes(4, "big")
        chained_elapsed[0x24:0x28] = (12).to_bytes(4, "big")
        chained_elapsed[0x28:0x2C] = (16).to_bytes(4, "big")
        rebuilt_chained, chained_fields = rebuild_player_supplement_leaf(
            chained_elapsed,
            target_slot=30,
            unix_now=160.0,
            recorded_at=100.0,
            previous_802c_counter=16,
        )
        self.assertEqual(
            int.from_bytes(rebuilt_chained[0x20:0x24], "big"), 1060
        )
        self.assertEqual(
            int.from_bytes(rebuilt_chained[0x24:0x28], "big"), 16
        )
        self.assertEqual(
            int.from_bytes(rebuilt_chained[0x28:0x2C], "big"), 20
        )
        self.assertEqual(
            chained_fields,
            [
                "elapsed_counter@0x20",
                "link_previous@0x24",
                "link_counter@0x28",
            ],
        )

        epoch_leaf = bytearray(self.player_leaf(4, 0x8024, slot=30))
        epoch_leaf[0x20:0x24] = (500_000).to_bytes(4, "big")
        epoch_leaf[0x24:0x28] = (500_008).to_bytes(4, "big")
        rebuilt_epoch, epoch_fields = rebuild_player_supplement_leaf(
            epoch_leaf,
            target_slot=30,
            unix_now=160.0,
            recorded_at=100.0,
        )
        self.assertEqual(
            int.from_bytes(rebuilt_epoch[0x20:0x24], "big"), 500_000
        )
        self.assertEqual(
            int.from_bytes(rebuilt_epoch[0x24:0x28], "big"), 500_008
        )
        self.assertEqual(epoch_fields, [])

        later_elapsed, _ = rebuild_player_supplement_leaf(
            elapsed_leaf,
            target_slot=30,
            unix_now=280.0,
            recorded_at=100.0,
        )
        self.assertEqual(
            int.from_bytes(later_elapsed[0x20:0x24], "big"), 1180
        )

    def test_v1306_802a_off_does_not_inject_even_with_trigger(self):
        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_match_events", "off")
        pool = [
            self.player_pool_item(
                message_id=message_id,
                slot=0x3456,
                report_index=41,
                recorded_elapsed_seconds=40.0,
            )
            for message_id in (0x802A, 0x802B)
        ]
        logs = []
        output, changed = _ace_try_replay_template(
            [
                frame(
                    batch_children(
                        0,
                        self.device_context_leaf(10),
                        self.player_leaf(11, 0x8029, slot=0x3456),
                    ),
                    account_id="GAME-42",
                    report_index=2,
                )
            ],
            pool,
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=2000.0,
        )
        ids = []
        for source in output[1:]:
            _, material = self.decode_frame(source)
            ids.extend(row["message_id"] for row in material["leaves"])
        self.assertNotIn(0x802A, ids)
        self.assertNotIn(0x802B, ids)
        self.assertEqual(
            logs[0]["v128_replenish"]["same_device_player"]["rebuild_match_events"],
            "off",
        )

    def test_v1306_802a_random_emits_pair_without_gameplay_gate(self):
        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_match_events", "random")
        pool = [
            self.player_pool_item(
                message_id=message_id,
                slot=0x3456,
                report_index=41,
                recorded_elapsed_seconds=40.0,
            )
            for message_id in (0x802A, 0x802B)
        ]
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        state = [0, 0, {}]
        first_out, first_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=90.0,
        )
        first_ids = []
        for source in first_out[1:]:
            _, material = self.decode_frame(source)
            first_ids.extend(row["message_id"] for row in material["leaves"])
        self.assertNotIn(0x802A, first_ids)
        self.assertNotIn(0x802B, first_ids)

        second_out, second_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=2000.0,
        )
        self.assertTrue(second_changed)
        second_ids = []
        for source in second_out[1:]:
            _, material = self.decode_frame(source)
            second_ids.extend(row["message_id"] for row in material["leaves"])
        self.assertIn(0x802A, second_ids)
        self.assertIn(0x802B, second_ids)

    def test_v1304_802a_802b_wait_for_gameplay_gate(self):
        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_match_events", "off")
        pool = [
            self.player_pool_item(
                message_id=message_id,
                slot=0x3456,
                report_index=41,
                recorded_elapsed_seconds=40.0,
            )
            for message_id in (0x802A, 0x802B)
        ]

        def replay(live_children):
            logs = []
            output, changed = _ace_try_replay_template(
                [
                    frame(
                        batch_children(
                            0,
                            self.device_context_leaf(10),
                            *live_children,
                        ),
                        account_id="GAME-42",
                        report_index=2,
                    )
                ],
                pool,
                [0, 0, {}],
                expected_game_id="GAME-42",
                special_rule_store=self.store,
                on_log=logs.append,
                session_elapsed_seconds=90.0,
            )
            ids = []
            for source in output[1:]:
                _, material = self.decode_frame(source)
                ids.extend(row["message_id"] for row in material["leaves"])
            return changed, ids, logs[0]["v128_replenish"][
                "same_device_player"
            ]

        changed, ids, info = replay([])
        self.assertNotIn(0x802A, ids)
        self.assertNotIn(0x802B, ids)
        self.assertEqual(info["rebuild_match_events"], "off")
        self.assertEqual(info["due_message_ids"], [])

        trigger = self.player_leaf(11, 0x8029, slot=0x3456)
        changed, ids, info = replay([trigger])
        self.assertNotIn(0x802A, ids)
        self.assertNotIn(0x802B, ids)

    def test_v1286_extends_verified_player_periods_after_recording_tail(self):
        app_config.set("full_rebuild_01_mode", True)
        pool = []
        specifications = {
            0x8007: (60, 660, 1260),
            0x800D: (60, 660, 1260),
            0x802C: (630, 1230),
        }
        pool_idx = 0
        for message_id, slots in specifications.items():
            for slot in slots:
                pool_idx += 1
                pool.append(
                    self.player_pool_item(
                        message_id=message_id,
                        slot=slot,
                        report_index=pool_idx + 10,
                        recorded_elapsed_seconds=(
                            max(0, slot - 13) * WALL_SECONDS_PER_LOGICAL_SLOT
                        ),
                        recorded_at=1_000.0 + slot,
                    )
                )

        cursor = [0, 0, {}]

        def replay_at(logical_slot: float, report_index: int):
            live = frame(
                self.device_context_leaf(report_index + 10),
                account_id="GAME-42",
                report_index=report_index,
            )
            logs = []
            output, changed = _ace_try_replay_template(
                [live],
                pool,
                cursor,
                expected_game_id="GAME-42",
                special_rule_store=self.store,
                on_log=logs.append,
                session_elapsed_seconds=(
                    (logical_slot - 13) * WALL_SECONDS_PER_LOGICAL_SLOT
                ),
                session_unix_time=4_000.0 + logical_slot,
            )
            self.assertTrue(changed)
            leaves = []
            for source in output[1:]:
                _, material = self.decode_frame(source)
                leaves.extend(material["leaves"])
            return leaves, logs[0]["v128_replenish"]["same_device_player"]

        # 先走完整个源录制时间线，使最后两个相差600 slot的观测成立。
        replay_at(1260.5, 2)

        first_extension, first_info = replay_at(1860.5, 3)
        first_slots = {
            (
                row["message_id"],
                int.from_bytes(bytes(row["raw"])[0x1C:0x1E], "big"),
            )
            for row in first_extension
            if row.get("message_id") in specifications
        }
        self.assertEqual(
            first_slots,
            {(0x8007, 1860), (0x800D, 1860), (0x802C, 1830)},
        )
        self.assertEqual(
            set(first_info["periodic_extension_due_message_ids"]),
            {"0x8007", "0x800D", "0x802C"},
        )
        self.assertEqual(
            first_info["periodic_extension_slots"],
            {
                "0x8007": [1860],
                "0x800D": [1860],
                "0x802C": [1830],
            },
        )

        second_extension, second_info = replay_at(2460.5, 4)
        second_slots = {
            (
                row["message_id"],
                int.from_bytes(bytes(row["raw"])[0x1C:0x1E], "big"),
            )
            for row in second_extension
            if row.get("message_id") in specifications
        }
        self.assertEqual(
            second_slots,
            {(0x8007, 2460), (0x800D, 2460), (0x802C, 2430)},
        )
        self.assertEqual(
            set(second_info["periodic_extension_due_message_ids"]),
            {"0x8007", "0x800D", "0x802C"},
        )

    def test_v1286_does_not_extend_single_unverified_period_sample(self):
        app_config.set("full_rebuild_01_mode", True)
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [self.player_pool_item(message_id=0x800D, slot=1260)],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=(
                (1860.5 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT
            ),
        )
        # 单条旧样本已过期，同时不满足周期确认条件，因此没有玩家周期补入。
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(supplement["periodic_extension_due_message_ids"], [])
        self.assertEqual(supplement["periodic_extension_slots"], {})
        self.assertNotIn("0x800D", supplement["due_message_ids"])

    def test_v1307_extends_800a_800f_after_two_900_slot_samples(self):
        app_config.set("full_rebuild_01_mode", True)
        pool = []
        pool_idx = 0
        for message_id in (0x800A, 0x800F):
            for slot in (30, 930):
                pool_idx += 1
                pool.append(
                    self.player_pool_item(
                        message_id=message_id,
                        slot=slot,
                        report_index=pool_idx + 10,
                        recorded_elapsed_seconds=(
                            max(0, slot - 13) * WALL_SECONDS_PER_LOGICAL_SLOT
                        ),
                    )
                )
        live = frame(
            self.device_context_leaf(40),
            account_id="GAME-42",
            report_index=40,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            pool,
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=(
                (1830.5 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT
            ),
        )
        self.assertTrue(changed)
        slots = {
            (
                row["message_id"],
                int.from_bytes(bytes(row["raw"])[0x1C:0x1E], "big"),
            )
            for source in output[1:]
            for row in self.decode_frame(source)[1]["leaves"]
            if row.get("message_id") in {0x800A, 0x800F}
        }
        self.assertEqual(slots, {(0x800A, 1830), (0x800F, 1830)})
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(
            set(supplement["periodic_extension_due_message_ids"]),
            {"0x800A", "0x800F"},
        )
        self.assertEqual(
            supplement["periodic_extension_slots"],
            {"0x800A": [1830], "0x800F": [1830]},
        )

    def test_v1307_does_not_extend_single_sample_800a(self):
        app_config.set("full_rebuild_01_mode", True)
        logs = []
        output, changed = _ace_try_replay_template(
            [
                frame(
                    self.device_context_leaf(40),
                    account_id="GAME-42",
                    report_index=40,
                )
            ],
            [self.player_pool_item(message_id=0x800A, slot=30)],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=(
                (1830.5 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT
            ),
        )
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(supplement["periodic_extension_due_message_ids"], [])
        self.assertEqual(supplement["periodic_extension_slots"], {})
        self.assertNotIn("0x800A", supplement["due_message_ids"])

    def test_v1308_800a_two_30_slot_clusters_do_not_extend(self):
        judged = evaluate_800a_period(
            list(range(60, 511, 30)) + list(range(1380, 1591, 30))
        )
        self.assertFalse(judged["ready"])
        self.assertEqual(judged["morphology"], "cluster_30")
        self.assertEqual(judged["cluster_count"], 2)
        self.assertEqual(judged["status"], "等待第3簇 (2/3)")

        app_config.set("full_rebuild_01_mode", True)
        pool = [
            self.player_pool_item(
                message_id=0x800A,
                slot=slot,
                report_index=20 + index,
                recorded_elapsed_seconds=(
                    max(0, slot - 13) * WALL_SECONDS_PER_LOGICAL_SLOT
                ),
            )
            for index, slot in enumerate((60, 90, 1380, 1410))
        ]
        logs = []
        _ace_try_replay_template(
            [
                frame(
                    self.device_context_leaf(40),
                    account_id="GAME-42",
                    report_index=40,
                )
            ],
            pool,
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=(
                (2700.5 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT
            ),
        )
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertNotIn("0x800A", supplement["periodic_extension_due_message_ids"])
        self.assertEqual(supplement["periodic_extension_slots"], {})

    def test_v1308_800a_three_clusters_extend_by_cluster_interval(self):
        judged = evaluate_800a_period((60, 90, 1380, 1410, 2700, 2730))
        self.assertTrue(judged["ready"])
        self.assertEqual(judged["period"], 1320)
        self.assertEqual(judged["morphology"], "cluster_30")

        app_config.set("full_rebuild_01_mode", True)
        pool = [
            self.player_pool_item(
                message_id=0x800A,
                slot=slot,
                report_index=20 + index,
                recorded_elapsed_seconds=(
                    max(0, slot - 13) * WALL_SECONDS_PER_LOGICAL_SLOT
                ),
            )
            for index, slot in enumerate((60, 90, 1380, 1410, 2700, 2730))
        ]
        logs = []
        output, changed = _ace_try_replay_template(
            [
                frame(
                    self.device_context_leaf(40),
                    account_id="GAME-42",
                    report_index=40,
                )
            ],
            pool,
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=(
                (4050.5 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT
            ),
        )
        self.assertTrue(changed)
        slots = {
            int.from_bytes(bytes(row["raw"])[0x1C:0x1E], "big")
            for source in output[1:]
            for row in self.decode_frame(source)[1]["leaves"]
            if row.get("message_id") == 0x800A
        }
        self.assertIn(4020, slots)
        self.assertIn(4050, slots)
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertIn("0x800A", supplement["periodic_extension_due_message_ids"])
        self.assertEqual(
            set(supplement["periodic_extension_slots"]["0x800A"]),
            {4020, 4050},
        )

    def test_v1308_long_8027_wave_repeats_after_second_open(self):
        def scan_row(message_id, elapsed, u20):
            raw = bytearray(0x24)
            raw[0x20:0x24] = int(u20).to_bytes(4, "big")
            return {
                "message_id": message_id,
                "recorded_elapsed_seconds": elapsed,
                "raw": bytes(raw),
            }

        waiting = evaluate_scan_wave_template([
            scan_row(0x8029, 32.679, 70283),
            scan_row(0x8027, 39.338, 70283),
            scan_row(0x8027, 150.000, 52810),
        ])
        self.assertFalse(waiting["ready"])
        self.assertEqual(waiting["status"], "waiting_wave2")
        self.assertEqual(waiting["wave1_shape"], "long_gap")

        judged = evaluate_scan_wave_template([
            scan_row(0x8029, 32.679, 70283),
            scan_row(0x8027, 39.338, 70283),
            scan_row(0x8027, 150.000, 52810),
            scan_row(0x8027, 962.688, 70296),
        ])
        self.assertTrue(judged["ready"])
        self.assertEqual(judged["wave1_shape"], "long_gap")
        self.assertAlmostEqual(judged["scan_wave_period_seconds"], 923.35, places=2)

        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_scan_waves", "repeat_first")
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        pool = [
            self.player_pool_item(
                message_id=0x8029,
                slot=0x3456,
                recorded_elapsed_seconds=32.679,
                sequence=2,
                u20=70283,
                pool_idx=20,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                recorded_elapsed_seconds=39.338,
                sequence=3,
                u20=70283,
                pool_idx=25,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                recorded_elapsed_seconds=150.000,
                sequence=4,
                u20=52810,
                pool_idx=50,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                recorded_elapsed_seconds=962.688,
                sequence=5,
                u20=70296,
                pool_idx=168,
            ),
        ]
        logs = []
        state = [0, 0, {}]
        first_out, first_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=90.0,
        )
        self.assertTrue(first_changed)
        self.assertEqual(self._count_scan_leaves(first_out, 0x8027), [70283])
        scan = logs[0]["v128_replenish"]["same_device_player"]
        self.assertAlmostEqual(scan["scan_wave_period_seconds"], 923.35, places=2)
        later_out, later_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=39.338 + 923.35 + 5.0,
        )
        self.assertTrue(later_changed)
        self.assertEqual(
            self._count_scan_leaves(later_out, 0x8027),
            [70283],
        )

    def test_v1308_non_monotonic_8027_wave_is_not_complete(self):
        def scan_row(message_id, elapsed, u20):
            raw = bytearray(0x24)
            raw[0x20:0x24] = int(u20).to_bytes(4, "big")
            return {
                "message_id": message_id,
                "recorded_elapsed_seconds": elapsed,
                "raw": bytes(raw),
            }

        judged = evaluate_scan_wave_template([
            scan_row(0x8029, 32.679, 70283),
            scan_row(0x8027, 39.338, 70283),
            scan_row(0x8027, 80.0, 50000),
            scan_row(0x8027, 120.0, 65000),
            scan_row(0x8027, 150.0, 52810),
            scan_row(0x8027, 962.688, 70296),
        ])
        self.assertFalse(judged["ready"])
        self.assertEqual(judged["status"], "waiting_wave1")
        self.assertIsNone(judged["wave1_shape"])
        self.assertIsNone(judged["scan_wave_period_seconds"])

        app_config.set("full_rebuild_01_mode", True)
        app_config.set("rebuild_scan_waves", "repeat_first")
        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        pool = [
            self.player_pool_item(
                message_id=0x8029,
                slot=0x3456,
                recorded_elapsed_seconds=32.679,
                sequence=2,
                u20=70283,
                pool_idx=20,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                recorded_elapsed_seconds=39.338,
                sequence=3,
                u20=70283,
                pool_idx=25,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                recorded_elapsed_seconds=80.0,
                sequence=4,
                u20=50000,
                pool_idx=40,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                recorded_elapsed_seconds=120.0,
                sequence=5,
                u20=65000,
                pool_idx=45,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                recorded_elapsed_seconds=150.0,
                sequence=6,
                u20=52810,
                pool_idx=50,
            ),
            self.player_pool_item(
                message_id=0x8027,
                slot=0x3456,
                recorded_elapsed_seconds=962.688,
                sequence=7,
                u20=70296,
                pool_idx=168,
            ),
        ]
        logs = []
        state = [0, 0, {}]
        first_out, first_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=90.0,
        )
        self.assertTrue(first_changed)
        scan = logs[0]["v128_replenish"]["same_device_player"]
        self.assertIsNone(scan["scan_wave_period_seconds"])
        second_out, second_changed = _ace_try_replay_template(
            [live],
            pool,
            state,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=39.338 + 923.35 + 5.0,
        )
        self.assertTrue(second_changed)
        self.assertEqual(self._count_scan_leaves(second_out, 0x8027), [70296])

    def test_v1305_keeps_recorded_8024_and_advances_802c_by_wall_clock(self):
        app_config.set("full_rebuild_01_mode", True)
        epoch_row = self.player_pool_item(
            message_id=0x8024,
            slot=30,
            report_index=20,
            recorded_elapsed_seconds=0.0,
            recorded_at=1_000.0,
        )
        epoch_raw = bytearray(epoch_row["_type9_shadow_leaf_cache"]["rows"][1]["raw"])
        epoch_raw[0x20:0x24] = (500_000).to_bytes(4, "big")
        epoch_raw[0x24:0x28] = (500_008).to_bytes(4, "big")
        epoch_row["_type9_shadow_leaf_cache"]["rows"][1]["raw"] = bytes(epoch_raw)

        counter_row = self.player_pool_item(
            message_id=0x802C,
            slot=30,
            report_index=21,
            recorded_elapsed_seconds=0.0,
            recorded_at=1_000.0,
        )
        counter_raw = bytearray(counter_row["_type9_shadow_leaf_cache"]["rows"][1]["raw"])
        counter_raw[0x20:0x24] = (100).to_bytes(4, "big")
        counter_raw[0x24:0x28] = (0).to_bytes(4, "big")
        counter_raw[0x28:0x2C] = (4).to_bytes(4, "big")
        counter_row["_type9_shadow_leaf_cache"]["rows"][1]["raw"] = bytes(counter_raw)

        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )

        def replay(*, elapsed: float, unix_now: float):
            logs = []
            output, changed = _ace_try_replay_template(
                [live],
                [epoch_row, counter_row],
                [0, 0, {}],
                expected_game_id="GAME-42",
                special_rule_store=self.store,
                on_log=logs.append,
                session_elapsed_seconds=elapsed,
                session_unix_time=unix_now,
            )
            self.assertTrue(changed)
            leaves = []
            for source in output[1:]:
                _, material = self.decode_frame(source)
                leaves.extend(material["leaves"])
            by_id = {row["message_id"]: bytes(row["raw"]) for row in leaves}
            return by_id, logs[0]["v128_replenish"]["same_device_player"]

        first_by_id, first_info = replay(elapsed=60.0, unix_now=1_060.0)
        self.assertEqual(
            int.from_bytes(first_by_id[0x8024][0x20:0x24], "big"), 500_000
        )
        self.assertEqual(
            int.from_bytes(first_by_id[0x8024][0x24:0x28], "big"), 500_008
        )
        self.assertEqual(
            int.from_bytes(first_by_id[0x802C][0x20:0x24], "big"), 160
        )
        self.assertNotIn("0x8024:virtual_epoch@0x20", first_info["rebuilt_fields"])
        self.assertIn("0x802C:elapsed_counter@0x20", first_info["rebuilt_fields"])

        # 新连接 elapsed 变小，墙钟继续走：802C 必须跟 recorded_at 而不是连接秒。
        second_by_id, _ = replay(elapsed=20.0, unix_now=2_000.0)
        self.assertEqual(
            int.from_bytes(second_by_id[0x8024][0x20:0x24], "big"), 500_000
        )
        self.assertEqual(
            int.from_bytes(second_by_id[0x802C][0x20:0x24], "big"), 1_100
        )

    def test_v1306_reports_missing_clock_metadata_without_freezing_chain(self):
        app_config.set("full_rebuild_01_mode", True)
        counter_row = self.player_pool_item(
            message_id=0x802C,
            slot=30,
            report_index=21,
            recorded_elapsed_seconds=None,
            recorded_at=None,
        )
        counter_raw = bytearray(
            counter_row["_type9_shadow_leaf_cache"]["rows"][1]["raw"]
        )
        counter_raw[0x20:0x24] = (100).to_bytes(4, "big")
        counter_raw[0x24:0x28] = (0).to_bytes(4, "big")
        counter_raw[0x28:0x2C] = (4).to_bytes(4, "big")
        counter_row["_type9_shadow_leaf_cache"]["rows"][1]["raw"] = bytes(
            counter_raw
        )

        live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [counter_row],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=60.0,
            session_unix_time=1_060.0,
        )
        self.assertTrue(changed)
        leaves = []
        for source in output[1:]:
            _, material = self.decode_frame(source)
            leaves.extend(material["leaves"])
        counter = next(row for row in leaves if row["message_id"] == 0x802C)
        self.assertEqual(
            int.from_bytes(bytes(counter["raw"])[0x20:0x24], "big"), 100
        )
        info = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(info["clock_metadata_status"], "CLOCK_METADATA_MISSING")
        self.assertEqual(info["clock_metadata_missing_message_ids"], ["0x802C"])

    def test_v1285_partial_hook_live_leaf_suppresses_player_duplicate(self):
        app_config.set("full_rebuild_01_mode", True)
        live = frame(
            batch_children(
                0,
                self.device_context_leaf(10),
                self.player_leaf(11, 0x8023),
            ),
            account_id="GAME-42",
            report_index=2,
        )
        logs = []
        output, _ = _ace_try_replay_template(
            [live],
            [self.player_pool_item()],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=31.0,
        )
        output_ids = []
        for source in output:
            _, material = self.decode_frame(source)
            output_ids.extend(row["message_id"] for row in material["leaves"])
        self.assertEqual(output_ids.count(0x8023), 1)
        supplement = logs[0]["v128_replenish"]["same_device_player"]
        self.assertEqual(supplement["due_message_ids"], [])
        self.assertEqual(supplement["suppressed_by_live"], ["0x8023"])

    def test_v1285_late_player_live_duplicate_becomes_empty_2000(self):
        app_config.set("full_rebuild_01_mode", True)
        cursor = [0, 0, {}]
        pool = [self.player_pool_item(message_id=0x8023)]
        first_live = frame(
            self.device_context_leaf(10),
            account_id="GAME-42",
            report_index=2,
        )
        first, changed = _ace_try_replay_template(
            [first_live],
            pool,
            cursor,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=31.0,
        )
        self.assertTrue(changed)
        self.assertGreaterEqual(len(first), 2)

        late_live = frame(
            self.player_leaf(20, 0x8023),
            account_id="GAME-42",
            report_index=3,
        )
        logs = []
        second, changed = _ace_try_replay_template(
            [late_live],
            pool,
            cursor,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=32.0,
        )
        self.assertTrue(changed)
        _, material = self.decode_frame(second[0])
        self.assertEqual(
            [row["message_id"] for row in material["leaves"]], [0x2000]
        )
        late = logs[0]["v128_replenish"]["late_live_duplicates"]
        self.assertTrue(late["changed"])
        self.assertTrue(any("PLAYER:8023@30" in key for key in late["keys"]))

    def test_slot30_injects_independent_report_and_shifts_next_live(self):
        cursor = [0, 0, {}]
        live_21 = frame(
            leaf(75, fill=0x22, message_id=0x1004, length=44),
            account_id="GAME-42",
            report_index=21,
        )
        first, changed = _ace_try_replay_template(
            [live_21],
            [],
            cursor,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=31.0,
        )
        self.assertTrue(changed)
        self.assertEqual(len(first), 2)
        report_21, native = self.decode_frame(first[0])
        report_22, inserted = self.decode_frame(first[1])
        self.assertEqual(report_21, 21)
        self.assertEqual(report_22, 22)
        self.assertTrue(native["ok"])
        self.assertTrue(inserted["ok"])
        self.assertEqual(
            [leaf_row["record_sequence"] for leaf_row in native["leaves"]],
            [75],
        )
        self.assertEqual(
            [leaf_row["record_sequence"] for leaf_row in inserted["leaves"]],
            list(range(76, 92)),
        )
        inserted_ids = [leaf_row["message_id"] for leaf_row in inserted["leaves"]]
        self.assertEqual(len(inserted_ids), 16)
        self.assertEqual(inserted_ids.count(0x8004), 9)
        self.assertEqual(int.from_bytes(first[0][8:10], "big"), 21)
        self.assertEqual(int.from_bytes(first[1][8:10], "big"), 22)
        self.assertEqual(int.from_bytes(first[0][36:38], "big"), 21)
        self.assertEqual(int.from_bytes(first[1][36:38], "big"), 22)

        live_22 = frame(
            leaf(76, fill=0x33, message_id=0x1004, length=44),
            account_id="GAME-42",
            report_index=22,
        )
        second_logs = []
        second, changed_second = _ace_try_replay_template(
            [live_22],
            [],
            cursor,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=second_logs.append,
            session_elapsed_seconds=32.0,
        )
        self.assertTrue(changed_second)
        self.assertEqual(len(second), 1)
        report_23, shifted = self.decode_frame(second[0])
        self.assertEqual(report_23, 23)
        self.assertEqual(
            [leaf_row["record_sequence"] for leaf_row in shifted["leaves"]],
            [92],
        )
        self.assertEqual(int.from_bytes(second[0][8:10], "big"), 23)
        self.assertEqual(int.from_bytes(second[0][36:38], "big"), 23)
        self.assertEqual(second_logs[0]["decision"], "REPLACE")
        self.assertEqual(second_logs[0]["reason"], "V128_SEQUENCE_OFFSET_SHIFT")
        self.assertEqual(
            second_logs[0]["replacement_level"], "V128_SEQUENCE_OFFSET"
        )
        self.assertEqual(
            second_logs[0]["replace_mode"], "type9_v128_sequence_offset"
        )
        self.assertFalse(second_logs[0]["final_equals_live"])
        state = cursor[2]["v128_replenish"]
        self.assertEqual(state["report_offset"], 1)
        self.assertEqual(state["leaf_offset"], 16)
        self.assertEqual(state["frame_offset"], 1)
        self.assertEqual(state["group_offset"], 1)

    def test_partial_live_8004_fills_only_missing_subtypes(self):
        dirty_8004 = bytearray(self.builtin_leaf(0x8004, 0, 1))
        dirty_8004[0x24:0x28] = b"\xAA\xBB\xCC\xDD"
        live = frame(
            batch_children(
                0,
                bytes(dirty_8004),
                leaf(2, fill=0, message_id=0x1004, length=44),
            ),
            account_id="GAME-42",
            report_index=1,
        )
        output, _ = _ace_try_replay_template(
            [live],
            [],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=31.0,
        )
        self.assertEqual(len(output), 2)
        _, native = self.decode_frame(output[0])
        native_8004 = next(
            row for row in native["leaves"] if row["message_id"] == 0x8004
        )
        self.assertEqual(
            native_8004["raw"],
            self.builtin_leaf(0x8004, 0, 1),
        )
        _, inserted = self.decode_frame(output[1])
        ids = [leaf_row["message_id"] for leaf_row in inserted["leaves"]]
        self.assertEqual(ids.count(0x8004), 8)
        self.assertEqual(len(ids), 15)

    def test_live_builtin_body_is_replaced_by_authoritative_template(self):
        dirty = bytearray(self.builtin_leaf(0x8000, 0, 1))
        dirty[0x20:] = b"\xA5" * (len(dirty) - 0x20)
        output, changed = _ace_try_replay_template(
            [
                frame(
                    bytes(dirty),
                    account_id="GAME-42",
                    report_index=1,
                )
            ],
            [],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=31.0,
        )
        self.assertTrue(changed)
        self.assertEqual(len(output), 2)
        _, native = self.decode_frame(output[0])
        self.assertEqual(
            [row["message_id"] for row in native["leaves"]],
            [0x8000],
        )
        self.assertEqual(
            native["leaves"][0]["raw"],
            self.builtin_leaf(0x8000, 0, 1),
        )
        _, inserted = self.decode_frame(output[1])
        self.assertNotIn(
            0x8000,
            [row["message_id"] for row in inserted["leaves"]],
        )

    def test_unexpected_live_builtin_slot_is_emptied_and_due_slot_is_injected(self):
        unexpected = bytearray(self.builtin_leaf(0x8000, 0, 1))
        unexpected[0x1C:0x1E] = (31).to_bytes(2, "big")
        output, changed = _ace_try_replay_template(
            [
                frame(
                    bytes(unexpected),
                    account_id="GAME-42",
                    report_index=1,
                )
            ],
            [],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=31.0,
        )
        self.assertTrue(changed)
        self.assertEqual(len(output), 2)
        _, native = self.decode_frame(output[0])
        self.assertEqual(
            [row["message_id"] for row in native["leaves"]],
            [0x2000],
        )
        _, inserted = self.decode_frame(output[1])
        self.assertIn(
            0x8000,
            [row["message_id"] for row in inserted["leaves"]],
        )

    def test_full_live_8004_suppresses_all_nine_subtypes_for_slot(self):
        children = [
            self.builtin_leaf(0x8004, index, index + 1)
            for index in range(9)
        ]
        live = frame(
            batch_children(0, *children),
            account_id="GAME-42",
            report_index=1,
        )
        output, _ = _ace_try_replay_template(
            [live],
            [],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=31.0,
        )
        self.assertEqual(len(output), 2)
        _, inserted = self.decode_frame(output[1])
        ids = [leaf_row["message_id"] for leaf_row in inserted["leaves"]]
        self.assertNotIn(0x8004, ids)
        self.assertEqual(len(ids), 7)

    def test_live_slot_does_not_disable_next_periodic_slot(self):
        state = ensure_v128_state({})
        first = collect_due_groups(
            state,
            elapsed_seconds=31.0,
            live_leaves=[{"raw": self.builtin_leaf(0x8000, 0, 1)}],
        )
        self.assertFalse(
            any(
                row["message_id"] == 0x8000
                for group in first
                for row in group["rows"]
            )
        )
        second = collect_due_groups(
            state,
            elapsed_seconds=631.0 * WALL_SECONDS_PER_LOGICAL_SLOT,
        )
        self.assertTrue(
            any(
                row["message_id"] == 0x8000 and row["slot"] == 630
                for group in second
                for row in group["rows"]
            )
        )

    def test_late_live_duplicate_becomes_sequence_preserving_2000(self):
        cursor = [0, 0, {}]
        first_live = frame(
            leaf(75, fill=0x22, message_id=0x1004, length=44),
            account_id="GAME-42",
            report_index=21,
        )
        first, _ = _ace_try_replay_template(
            [first_live],
            [],
            cursor,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=31.0,
        )
        self.assertEqual(len(first), 2)

        late_live = frame(
            self.builtin_leaf(0x8000, 0, 76),
            account_id="GAME-42",
            report_index=22,
        )
        second, changed = _ace_try_replay_template(
            [late_live],
            [],
            cursor,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=32.0,
        )
        self.assertTrue(changed)
        self.assertEqual(len(second), 1)
        _, decoded = self.decode_frame(second[0])
        self.assertEqual(
            [row["message_id"] for row in decoded["leaves"]],
            [0x2000],
        )
        self.assertEqual(
            [row["record_sequence"] for row in decoded["leaves"]],
            [92],
        )
        state = cursor[2]["v128_replenish"]
        self.assertIn("8000@30#single", state["late_live_keys"])

    def test_scheduler_skips_old_slots_after_long_idle(self):
        state = ensure_v128_state({})
        groups = collect_due_groups(state, elapsed_seconds=500.0)
        self.assertEqual(groups, [])
        self.assertTrue(state["skipped_stale"])

    def test_builtin_model_has_nine_families(self):
        self.assertEqual(
            BUILTIN_MESSAGE_IDS,
            {
                0x8000,
                0x8002,
                0x8003,
                0x8004,
                0x800B,
                0x8020,
                0x8021,
                0x8025,
                0x8028,
            },
        )

    def test_strong_profile_file_pairs_arm_only_their_confirmed_ids(self):
        state = ensure_v128_state({})
        groups, info = collect_due_strong_profile_groups(
            state,
            elapsed_seconds=0.0,
            trigger_leaves=[b"mrpcs_i_vv.data", b"mrpcs_i_v_tl.data"],
        )
        self.assertEqual(groups, [])
        self.assertEqual(info["armed_message_ids"], ["0x9100"])
        self.assertNotIn("0x8C03", info["armed_message_ids"])

        state = ensure_v128_state({})
        _, info = collect_due_strong_profile_groups(
            state,
            elapsed_seconds=0.0,
            trigger_leaves=[b"mrpcs_i_j.data", b"mrpcs_i_f.data"],
        )
        self.assertEqual(info["armed_message_ids"], ["0x8C03"])

    def test_v_ic_is_recorded_but_does_not_arm_strong_profile(self):
        state = ensure_v128_state({})
        groups, info = collect_due_strong_profile_groups(
            state,
            elapsed_seconds=0.0,
            trigger_leaves=[b"mrpcs_i_v_ic.data"],
        )
        self.assertEqual(groups, [])
        self.assertEqual(info["armed_message_ids"], [])
        self.assertEqual(info["seen_files"], ["mrpcs_i_v_ic.data"])
        self.assertEqual(info["unmapped_seen_files"], ["mrpcs_i_v_ic.data"])

        state = ensure_v128_state({})
        _, info = collect_due_strong_profile_groups(
            state,
            elapsed_seconds=0.0,
            trigger_leaves=[
                b"mrpcs_i_j.data",
                b"mrpcs_i_f.data",
                b"mrpcs_i_v_ic.data",
            ],
        )
        self.assertEqual(info["armed_message_ids"], ["0x8C03"])
        self.assertIn("mrpcs_i_v_ic.data", info["seen_files"])
        self.assertEqual(info["unmapped_seen_files"], ["mrpcs_i_v_ic.data"])

    def test_strong_8c03_uses_120_slot_cycle_and_rebuilds_counter(self):
        state = ensure_v128_state({})
        collect_due_strong_profile_groups(
            state,
            elapsed_seconds=0.0,
            trigger_leaves=[b"mrpcs_i_j.data", b"mrpcs_i_f.data"],
        )
        elapsed = (150 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT
        groups, info = collect_due_strong_profile_groups(
            state,
            elapsed_seconds=elapsed,
        )
        self.assertEqual(info["due_message_ids"], ["0x8C03"])
        row = groups[0]["rows"][0]
        self.assertEqual(groups[0]["layer"], "central_strong")
        self.assertEqual(int.from_bytes(row["raw"][0x1A:0x1E], "big"), 150)
        self.assertEqual(int.from_bytes(row["raw"][0x24:0x28], "big"), 4)

        groups, _ = collect_due_strong_profile_groups(
            state,
            elapsed_seconds=(270 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT,
        )
        row = groups[0]["rows"][0]
        self.assertEqual(row["slot"], 270)
        self.assertEqual(int.from_bytes(row["raw"][0x24:0x28], "big"), 8)

    def test_strong_9100_is_conditional_and_repeats_every_600_slots(self):
        state = ensure_v128_state({})
        collect_due_strong_profile_groups(
            state,
            elapsed_seconds=0.0,
            trigger_leaves=[b"mrpcs_i_vv.data", b"mrpcs_i_v_tl.data"],
        )
        groups, _ = collect_due_strong_profile_groups(
            state,
            elapsed_seconds=(600 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT,
        )
        self.assertEqual([row["message_id"] for row in groups[0]["rows"]], [0x9100])
        raw = groups[0]["rows"][0]["raw"]
        self.assertEqual(len(raw), 36)
        self.assertEqual(int.from_bytes(raw[0x1A:0x1E], "big"), 600)

    def test_native_strong_leaf_suppresses_matching_central_slot(self):
        state = ensure_v128_state({})
        collect_due_strong_profile_groups(
            state,
            elapsed_seconds=0.0,
            trigger_leaves=[b"mrpcs_i_j.data", b"mrpcs_i_f.data"],
        )
        live = bytearray(STRONG_PROFILE_MODEL[0x8C03]["templates"][0])
        live[0x1A:0x1E] = (150).to_bytes(4, "big")
        groups, _ = collect_due_strong_profile_groups(
            state,
            elapsed_seconds=(150 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT,
            live_leaves=[bytes(live)],
        )
        self.assertEqual(groups, [])

    def test_strong_profile_stamper_preserves_body_and_sets_sequence(self):
        source = STRONG_PROFILE_MODEL[0x9100]["templates"][0]
        stamped = stamp_strong_profile_leaf(source, sequence=77, version=1)
        self.assertEqual(int.from_bytes(stamped[10:14], "big"), 77)
        self.assertEqual(stamped[0x1E:], source[0x1E:])

    def test_replay_detects_strong_files_and_injects_8c03(self):
        live = frame(
            batch_children(
                0,
                self.strong_module_leaf(1, "mrpcs_i_j.data"),
                self.strong_module_leaf(2, "mrpcs_i_f.data"),
            ),
            account_id="GAME-42",
            report_index=1,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=(150 - 13) * WALL_SECONDS_PER_LOGICAL_SLOT,
        )
        self.assertTrue(changed)
        self.assertEqual(len(output), 2)
        _, injected = self.decode_frame(output[1])
        self.assertEqual(
            [row["message_id"] for row in injected["leaves"]],
            [0x8C03],
        )
        self.assertEqual(
            logs[0]["v128_replenish"]["groups"][0]["layer"],
            "central_strong",
        )

    def test_v13012_only_strong_selected_emits_9100_without_central9(self):
        app_config.set("rebuild_controls_v2", True)
        app_config.set("rebuild_central9_enabled", False)
        app_config.set("rebuild_strong_profile", True)
        app_config.set("rebuild_player_base_enabled", False)
        app_config.set("rebuild_match_events_enabled", False)
        app_config.set("rebuild_scan_waves_enabled", False)
        live = frame(
            batch_children(
                0,
                self.strong_module_leaf(1, "mrpcs_i_vv.data"),
                self.strong_module_leaf(2, "mrpcs_i_v_tl.data"),
            ),
            account_id="GAME-42",
            report_index=1,
        )
        logs = []
        output, changed = _ace_try_replay_template(
            [live],
            [],
            [0, 0, {}],
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=logs.append,
            session_elapsed_seconds=(600 - 13)
            * WALL_SECONDS_PER_LOGICAL_SLOT,
        )
        self.assertTrue(changed)
        injected_ids = []
        for source in output[1:]:
            _, injected = self.decode_frame(source)
            injected_ids.extend(
                row["message_id"] for row in injected["leaves"]
            )
        self.assertEqual(injected_ids, [0x9100])
        options = logs[0]["v128_replenish"]["rebuild_options"]
        self.assertFalse(options["central9"])
        self.assertTrue(options["strong_profile"])
        self.assertFalse(options["player_base"])
        self.assertFalse(options["match_events"])
        self.assertFalse(options["scan_waves"])

    def test_drop_leaf_compacts_current_batch_and_shifts_later_live_leaf(self):
        self.store.replace_document(drop_9000_document())
        cursor = [0, 0, {}]
        first_live = frame(
            batch_children(
                99,
                leaf(100, fill=0x11, message_id=0x1004, length=44),
                leaf(101, fill=0x77, message_id=0x9000, length=80),
                leaf(102, fill=0x22, message_id=0x1004, length=44),
            ),
            account_id="GAME-42",
            report_index=10,
        )
        first_logs = []
        first, changed = _ace_try_replay_template(
            [first_live],
            [],
            cursor,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=first_logs.append,
            session_elapsed_seconds=1.0,
        )
        self.assertTrue(changed)
        self.assertEqual(len(first), 1)
        _, first_decoded = self.decode_frame(first[0])
        self.assertEqual(
            [row["message_id"] for row in first_decoded["leaves"]],
            [0x1004, 0x1004],
        )
        self.assertEqual(
            [row["record_sequence"] for row in first_decoded["leaves"]],
            [100, 101],
        )
        self.assertEqual(
            first_logs[0]["drop_leaf_sequence_compaction"]["leaf_delta"],
            -1,
        )
        self.assertTrue(
            first_logs[0]["drop_leaf_sequence_compaction"]["applied"]
        )
        self.assertEqual(cursor[2]["v128_replenish"]["leaf_offset"], -1)

        second_live = frame(
            leaf(103, fill=0x33, message_id=0x1004, length=44),
            account_id="GAME-42",
            report_index=11,
        )
        second, changed_second = _ace_try_replay_template(
            [second_live],
            [],
            cursor,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            session_elapsed_seconds=2.0,
        )
        self.assertTrue(changed_second)
        _, second_decoded = self.decode_frame(second[0])
        self.assertEqual(
            [row["record_sequence"] for row in second_decoded["leaves"]],
            [102],
        )

    def test_drop_leaf_sequence_safety_also_runs_without_replenish_mode(self):
        app_config.set("replenish_01_mode", False)
        self.store.replace_document(drop_9000_document())
        cursor = [0, 0]
        first_live = frame(
            batch_children(
                9,
                leaf(10, fill=0x11, message_id=0x1004, length=44),
                leaf(11, fill=0x77, message_id=0x9000, length=80),
                leaf(12, fill=0x22, message_id=0x1004, length=44),
            ),
            account_id="GAME-42",
            report_index=1,
        )
        first, _ = _ace_try_replay_template(
            [first_live],
            [],
            cursor,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
        )
        _, first_decoded = self.decode_frame(first[0])
        self.assertEqual(
            [row["record_sequence"] for row in first_decoded["leaves"]],
            [10, 11],
        )
        self.assertEqual(cursor[2]["sequence_safe_drop"]["leaf_offset"], -1)

        second_logs = []
        second_live = frame(
            leaf(13, fill=0x33, message_id=0x1004, length=44),
            account_id="GAME-42",
            report_index=2,
        )
        second, changed = _ace_try_replay_template(
            [second_live],
            [],
            cursor,
            expected_game_id="GAME-42",
            special_rule_store=self.store,
            on_log=second_logs.append,
        )
        self.assertTrue(changed)
        _, second_decoded = self.decode_frame(second[0])
        self.assertEqual(
            [row["record_sequence"] for row in second_decoded["leaves"]],
            [12],
        )
        self.assertEqual(
            second_logs[0]["replacement_level"],
            "DROP_LEAF_SEQUENCE_OFFSET",
        )


if __name__ == "__main__":
    unittest.main()
