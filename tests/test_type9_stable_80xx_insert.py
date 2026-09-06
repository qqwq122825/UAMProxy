import os
import tempfile
import unittest

import core.type9_special_rules as special_rules
from core.config import app_config
from core.crypto import (
    _ace_01_reassemble_frames,
    _ace_try_extract_frames,
    _ace_try_replay_template,
)
from core.type9_online import BATCH_CODE, BINARY_CODE
from core.type9_shadow import build_shadow_logical, decode_material, template_leaf_rows
from core.type9_special_rules import HOT_RULE_SCHEMA, Type9HotRuleStore
from core.type9_stable_80xx_insert import (
    STABLE_INSERT_MESSAGE_IDS,
    build_insert_schedule,
    plan_inserts,
    sanitize_insert_leaf,
)
from tests.test_type9_hot_rules import (
    batch,
    batch_children,
    frame,
    leaf,
    type9_payload,
)


def empty_rule_document():
    return {"schema": HOT_RULE_SCHEMA, "revision": "test-insert-empty", "rules": []}


def leaf_8028(sequence: int, write_counter: int = 74107) -> bytes:
    data = bytearray(leaf(sequence, fill=0, message_id=0x8028, length=40))
    data[0x20:0x24] = (7).to_bytes(4, "big")
    data[0x24:0x28] = int(write_counter).to_bytes(4, "big")
    return bytes(data)


def leaf_8002(sequence: int, status_word: int = 3) -> bytes:
    data = bytearray(leaf(sequence, fill=0, message_id=0x8002, length=56))
    data[0x2C:0x30] = int(status_word).to_bytes(4, "big")
    return bytes(data)


def rows_from(*raws, report_index: int, session: str = "rec-1"):
    payload = (
        type9_payload(raws[0])
        if len(raws) == 1
        else type9_payload(batch_children(1, *raws))
    )
    rows = template_leaf_rows(payload, pool_idx=0)["rows"]
    for row in rows:
        row["report_index"] = report_index
        row["template_session_id"] = session
    return rows


class Type9Stable80xxInsertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "type9_hot_rules.json")
        self.store = Type9HotRuleStore(self.path, auto_reload_interval=0)
        self.store.replace_document(empty_rule_document())
        self.previous_store = special_rules.type9_hot_rule_store
        special_rules.type9_hot_rule_store = self.store

    def tearDown(self):
        special_rules.type9_hot_rule_store = self.previous_store
        self.tmp.cleanup()

    def test_no_template_does_not_forge(self):
        insert_state = {}
        rebuilt = build_shadow_logical(
            type9_payload(leaf(10, fill=0x11, message_id=0x1004, length=44)),
            [],
            special_rule_store=self.store,
            live_report_index=22,
            insert_state=insert_state,
        )
        self.assertEqual(rebuilt["inserted_leaves"], 0)
        self.assertEqual(insert_state.get("schedule"), [])

    def test_inserts_8028_at_matching_report_and_zeros_counter(self):
        rows = rows_from(leaf_8028(70, write_counter=74107), report_index=22)
        insert_state = {}
        rebuilt = build_shadow_logical(
            type9_payload(leaf(10, fill=0x22, message_id=0x1004, length=44)),
            rows,
            special_rule_store=self.store,
            live_report_index=22,
            insert_state=insert_state,
        )
        self.assertTrue(rebuilt["generated"])
        self.assertTrue(rebuilt["roundtrip_ok"])
        self.assertEqual(rebuilt["inserted_leaves"], 1)
        self.assertEqual(rebuilt["inserted_message_ids"], ["0x8028"])
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        ids = [item["message_id"] for item in decoded["leaves"]]
        self.assertEqual(ids, [0x1004, 0x8028])
        out = next(item["raw"] for item in decoded["leaves"] if item["message_id"] == 0x8028)
        self.assertEqual(int.from_bytes(out[0x20:0x24], "big"), 7)
        self.assertEqual(out[0x24:0x28], b"\x00" * 4)
        self.assertEqual(
            {item["replacement_level"] for item in rebuilt["leaf_results"] if item.get("changed")},
            {"SPECIAL_INSERT_LEAF"},
        )
        self.assertTrue(all(not item.get("special_rule_id") for item in rebuilt["leaf_results"] if item.get("replacement_level") == "SPECIAL_INSERT_LEAF"))
        self.assertTrue(insert_state.get("consumed"))

    def test_live_already_has_8028_skips_insert(self):
        rows = rows_from(leaf_8028(70), report_index=22)
        live_8028 = leaf_8028(10, write_counter=1)
        insert_state = {}
        rebuilt = build_shadow_logical(
            type9_payload(batch_children(1, leaf(9, fill=0x22, message_id=0x1004, length=44), live_8028)),
            rows,
            special_rule_store=self.store,
            live_report_index=22,
            insert_state=insert_state,
        )
        self.assertEqual(rebuilt["inserted_leaves"], 0)
        self.assertEqual(rebuilt["insert_skipped_reason"], "LIVE_HAS_STABLE_80XX")
        self.assertEqual(rebuilt["insert_skipped_live_80xx"], ["0x8028"])
        self.assertTrue(insert_state.get("disabled"))
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertEqual(
            [item["message_id"] for item in decoded["leaves"]].count(0x8028),
            1,
        )

    def test_live_80xx_family_blocks_other_stable_insert(self):
        rows = rows_from(leaf_8002(71), report_index=22)
        rebuilt = build_shadow_logical(
            type9_payload(
                batch_children(
                    1,
                    leaf(9, fill=0x22, message_id=0x1004, length=44),
                    leaf_8028(10),
                )
            ),
            rows,
            special_rule_store=self.store,
            live_report_index=22,
            insert_state={},
        )
        self.assertEqual(rebuilt["inserted_leaves"], 0)
        self.assertEqual(rebuilt["insert_skipped_reason"], "LIVE_HAS_STABLE_80XX")
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertNotIn(0x8002, [item["message_id"] for item in decoded["leaves"]])

    def test_live_80xx_disables_insert_for_rest_of_connection(self):
        rows = rows_from(leaf_8028(70), report_index=23, session="rec-1") + rows_from(
            leaf_8028(71), report_index=22, session="rec-1"
        )
        insert_state = {}
        first = build_shadow_logical(
            type9_payload(
                batch_children(
                    1,
                    leaf(9, fill=0x22, message_id=0x1004, length=44),
                    leaf_8028(10),
                )
            ),
            rows,
            special_rule_store=self.store,
            live_report_index=22,
            insert_state=insert_state,
        )
        self.assertEqual(first["inserted_leaves"], 0)
        self.assertTrue(insert_state.get("disabled"))

        later = build_shadow_logical(
            type9_payload(leaf(11, fill=0x33, message_id=0x1004, length=44)),
            rows,
            special_rule_store=self.store,
            live_report_index=23,
            insert_state=insert_state,
        )
        self.assertEqual(later["inserted_leaves"], 0)
        self.assertEqual(later["insert_skipped_reason"], "LIVE_HAS_STABLE_80XX")
        self.assertEqual(later["insert_skipped_live_80xx"], ["0x8028"])
        decoded = decode_material(later["candidate_logical"])
        self.assertNotIn(0x8028, [item["message_id"] for item in decoded["leaves"]])

    def test_replenish_refresh_picks_up_later_recording_slot(self):
        early = rows_from(leaf_8028(70), report_index=22, session="rec-1")
        insert_state = {}
        first = build_shadow_logical(
            type9_payload(leaf(10, fill=0x22, message_id=0x1004, length=44)),
            early,
            special_rule_store=self.store,
            live_report_index=23,
            insert_state=insert_state,
            refresh_insert_schedule=True,
        )
        self.assertEqual(first["inserted_leaves"], 0)
        self.assertEqual(first["insert_skipped_reason"], "NO_RECORDING_SLOT")

        later_rows = early + rows_from(leaf_8028(80), report_index=23, session="rec-1")
        second = build_shadow_logical(
            type9_payload(leaf(11, fill=0x33, message_id=0x1004, length=44)),
            later_rows,
            special_rule_store=self.store,
            live_report_index=23,
            insert_state=insert_state,
            refresh_insert_schedule=True,
        )
        self.assertEqual(second["inserted_leaves"], 1)
        self.assertEqual(second["inserted_message_ids"], ["0x8028"])

    def test_wrong_report_index_does_not_insert(self):
        rows = rows_from(leaf_8028(70), report_index=22)
        rebuilt = build_shadow_logical(
            type9_payload(leaf(10, fill=0x22, message_id=0x1004, length=44)),
            rows,
            special_rule_store=self.store,
            live_report_index=21,
            insert_state={},
        )
        self.assertEqual(rebuilt["inserted_leaves"], 0)

    def test_dirty_8002_template_is_sent_with_zero_status(self):
        rows = rows_from(leaf_8002(71, status_word=9), report_index=22)
        rebuilt = build_shadow_logical(
            type9_payload(leaf(10, fill=0x22, message_id=0x1004, length=44)),
            rows,
            special_rule_store=self.store,
            live_report_index=22,
            insert_state={},
        )
        self.assertEqual(rebuilt["inserted_leaves"], 1)
        out = next(
            item["raw"]
            for item in decode_material(rebuilt["candidate_logical"])["leaves"]
            if item["message_id"] == 0x8002
        )
        self.assertEqual(out[0x2C:0x30], b"\x00" * 4)

    def test_8004_cluster_inserts_together(self):
        hashes = [
            leaf(80 + index, fill=0x30 + index, message_id=0x8004, length=40)
            for index in range(9)
        ]
        rows = rows_from(*hashes, report_index=22)
        rebuilt = build_shadow_logical(
            type9_payload(leaf(10, fill=0x22, message_id=0x1004, length=44)),
            rows,
            special_rule_store=self.store,
            live_report_index=22,
            insert_state={},
        )
        self.assertEqual(rebuilt["inserted_leaves"], 9)
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertEqual(
            [item["message_id"] for item in decoded["leaves"]].count(0x8004),
            9,
        )

    def test_root_leaf_is_promoted_to_batch_before_insert(self):
        rows = rows_from(leaf_8028(70), report_index=22)
        live_root = leaf(10, fill=0x22, message_id=0x1004, length=44)
        rebuilt = build_shadow_logical(
            type9_payload(live_root),
            rows,
            special_rule_store=self.store,
            live_report_index=22,
            insert_state={},
        )
        self.assertTrue(rebuilt["generated"])
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertEqual(decoded["root"]["record_code"], BATCH_CODE)
        self.assertEqual(
            [item["message_id"] for item in decoded["leaves"]],
            [0x1004, 0x8028],
        )
        self.assertEqual(decoded["root"]["raw"][0x14], 2)

    def test_sanitize_rejects_unknown_message(self):
        dirty = leaf(1, fill=0, message_id=0x8024, length=44)
        self.assertEqual(sanitize_insert_leaf(dirty), b"")
        self.assertTrue(0x8028 in STABLE_INSERT_MESSAGE_IDS)
        self.assertFalse(0x8024 in STABLE_INSERT_MESSAGE_IDS)

    def test_schedule_picks_session_with_more_coverage(self):
        thin = rows_from(leaf_8028(1), report_index=22, session="thin")
        rich = rows_from(
            leaf_8028(2),
            leaf_8002(3),
            report_index=22,
            session="rich",
        )
        schedule = build_insert_schedule(thin + rich)
        self.assertTrue(schedule)
        self.assertEqual({item["template_session_id"] for item in schedule}, {"rich"})
        planned = plan_inserts(
            schedule,
            live_report_index=22,
            live_message_ids=[],
        )
        self.assertEqual({item["message_id"] for item in planned}, {0x8028, 0x8002})

    def test_online_replay_without_replenish_follows_existing_rules(self):
        recorded_frames = [
            frame(batch(70, leaf_8028(70, write_counter=74107)), account_id="GAME-42", report_index=22)
        ]
        live_frames = [
            frame(
                batch(10, leaf(10, fill=0x22, message_id=0x1004, length=44)),
                account_id="GAME-42",
                report_index=22,
            )
        ]
        previous = app_config.get("replenish_01_mode")
        app_config.set("replenish_01_mode", False)
        self.addCleanup(app_config.set, "replenish_01_mode", previous)
        logs = []
        output, changed = _ace_try_replay_template(
            live_frames,
            [_ace_try_extract_frames(recorded_frames)],
            [0, 0, {}],
            expected_game_id="GAME-42",
            on_log=logs.append,
        )
        rebuilt = decode_material(_ace_01_reassemble_frames(output)[1])
        self.assertNotIn(0x8028, [item["message_id"] for item in rebuilt["leaves"]])
        if logs:
            self.assertNotEqual(logs[0].get("reason"), "STABLE_80XX_INSERT_LEAF")
            self.assertEqual(logs[0].get("shadow_rebuild", {}).get("inserted_leaves", 0), 0)

    def test_online_replay_inserts_8028_without_hot_rule_count(self):
        recorded_frames = [
            frame(batch(70, leaf_8028(70, write_counter=74107)), account_id="GAME-42", report_index=22)
        ]
        live_frames = [
            frame(
                batch(10, leaf(10, fill=0x22, message_id=0x1004, length=44)),
                account_id="GAME-42",
                report_index=22,
            )
        ]
        previous = app_config.get("replenish_01_mode")
        app_config.set("replenish_01_mode", True)
        self.addCleanup(app_config.set, "replenish_01_mode", previous)
        logs = []
        output, changed = _ace_try_replay_template(
            live_frames,
            [_ace_try_extract_frames(recorded_frames)],
            [0, 0, {}],
            expected_game_id="GAME-42",
            on_log=logs.append,
        )
        self.assertTrue(changed)
        self.assertEqual(logs[0]["decision"], "REPLACE")
        self.assertEqual(logs[0]["reason"], "STABLE_80XX_INSERT_LEAF")
        self.assertEqual(logs[0]["shadow_rebuild"]["inserted_leaves"], 1)
        self.assertEqual(logs[0]["shadow_rebuild"]["inserted_message_ids"], ["0x8028"])
        self.assertEqual(logs[0]["shadow_rebuild"]["insert_skipped_reason"], "")
        rebuilt = decode_material(_ace_01_reassemble_frames(output)[1])
        out = next(item["raw"] for item in rebuilt["leaves"] if item["message_id"] == 0x8028)
        self.assertEqual(out[0x24:0x28], b"\x00" * 4)
        self.assertEqual(self.store.snapshot(check_reload=False)["rule_changed_counts"], {})


if __name__ == "__main__":
    unittest.main()
