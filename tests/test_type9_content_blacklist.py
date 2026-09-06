import os
import tempfile
import unittest

import core.type9_special_rules as special_rules
from core.crypto import (
    _ace_01_reassemble_frames,
    _ace_try_extract_frames,
    _ace_try_replay_template,
)
from core.type9_content_blacklist import (
    CONTENT_BLACKLIST_RULE_ID,
    scan_type9_content_blacklist,
    xor_b6,
)
from core.type9_shadow import (
    BATCH_CODE,
    build_shadow_logical,
    decode_material,
    template_leaf_rows,
)
from core.type9_special_rules import Type9HotRuleStore
from tests.test_type9_hot_rules import (
    batch,
    batch_children,
    frame,
    leaf,
    nearest_document,
    type9_payload,
)


def leaf_with_body_text(
    sequence: int,
    *,
    message_id: int,
    text: str,
    xor_encode: bool = True,
    length: int = 160,
    fill: int = 0x00,
) -> bytes:
    data = bytearray(leaf(sequence, fill=fill, message_id=message_id, length=length))
    payload = text.encode("utf-8")
    if xor_encode:
        payload = xor_b6(payload)
    data[0x20:0x20 + len(payload)] = payload
    return bytes(data)


class Type9ContentBlacklistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "type9_hot_rules.json")
        self.store = Type9HotRuleStore(self.path, auto_reload_interval=0)

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan_hits_xor_b6_and_plain_and_chinese(self):
        xor_hit = scan_type9_content_blacklist(xor_b6(b"mtxdfm"))
        self.assertEqual(xor_hit["token"], "mtxdfm")
        self.assertEqual(xor_hit["encoding"], "xor_b6")

        bundle_hit = scan_type9_content_blacklist(b"xxcom.mtx.mtxdfmxx")
        self.assertEqual(bundle_hit["token"], "com.mtx.mtxdfm")
        self.assertEqual(bundle_hit["encoding"], "plain")

        chinese_hit = scan_type9_content_blacklist(xor_b6("多巴胺".encode("utf-8")))
        self.assertEqual(chinese_hit["token"], "多巴胺")
        self.assertIsNone(scan_type9_content_blacklist(b"SpringBoard"))

    def test_drop_8027_mtxdfm_leaf_keeps_clean_sibling(self):
        self.store.replace_document(nearest_document(0x8027))
        clean_template = leaf(100, fill=0x11, message_id=0x8027, length=110)
        clean_live = leaf(900, fill=0x22, message_id=0x8027, length=110)
        dirty_live = leaf_with_body_text(
            901, message_id=0x8027, text="mtxdfm", xor_encode=True, length=160
        )
        rows = template_leaf_rows(
            type9_payload(batch(99, clean_template)), pool_idx=0
        )["rows"]

        rebuilt = build_shadow_logical(
            type9_payload(batch_children(899, clean_live, dirty_live)),
            rows,
            special_rule_store=self.store,
        )

        self.assertTrue(rebuilt["generated"])
        self.assertTrue(rebuilt["roundtrip_ok"])
        self.assertEqual(rebuilt["pruned_leaves"], 0)
        self.assertEqual(rebuilt["content_blacklist_dropped_leaves"], 0)
        self.assertEqual(rebuilt["content_blacklist_emptied_leaves"], 1)
        self.assertEqual(rebuilt["special_emptied_leaves"], 1)
        self.assertEqual(rebuilt["content_blacklist_tokens"], ["mtxdfm"])
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertEqual(decoded["root"]["record_code"], 0x010A001B)
        self.assertEqual(
            [row["message_id"] for row in decoded["leaves"]],
            [0x8027, 0x2000],
        )
        self.assertEqual(
            [row["record_sequence"] for row in decoded["leaves"]],
            [900, 901],
        )
        self.assertNotIn(b"mtxdfm", xor_b6(decoded["leaves"][0]["raw"]))
        drop_result = next(
            row for row in rebuilt["leaf_results"] if row["content_blacklist_hit"]
        )
        self.assertEqual(drop_result["message_id"], 0x8027)
        self.assertEqual(drop_result["special_rule_id"], CONTENT_BLACKLIST_RULE_ID)
        self.assertEqual(
            drop_result["special_rule_action"], "REPLACE_CLEAN_2000"
        )
        self.assertEqual(drop_result["replacement_level"], "SPECIAL_EMPTY_2000")
        self.assertEqual(drop_result["content_blacklist_token"], "mtxdfm")
        self.assertEqual(drop_result["content_blacklist_encoding"], "xor_b6")

    def test_blacklist_beats_8027_template_replace(self):
        self.store.replace_document(nearest_document(0x8027))
        clean_template = leaf(100, fill=0x11, message_id=0x8027, length=160)
        dirty_live = leaf_with_body_text(
            901, message_id=0x8027, text="com.mtx.mtxdfm", xor_encode=True, length=160
        )
        rows = template_leaf_rows(
            type9_payload(batch(99, clean_template)), pool_idx=0
        )["rows"]

        rebuilt = build_shadow_logical(
            type9_payload(batch(899, dirty_live)),
            rows,
            special_rule_store=self.store,
        )

        self.assertEqual(rebuilt["content_blacklist_dropped_leaves"], 0)
        self.assertEqual(rebuilt["content_blacklist_emptied_leaves"], 1)
        self.assertEqual(rebuilt["pruned_leaves"], 0)
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertEqual(decoded["root"]["record_code"], 0x010A001B)
        self.assertEqual([row["message_id"] for row in decoded["leaves"]], [0x2000])
        self.assertEqual(decoded["leaves"][0]["record_sequence"], 901)

    def test_root_leaf_blacklist_becomes_clean_2000(self):
        dirty_root = leaf_with_body_text(
            901,
            message_id=0x8027,
            text="Dopamine",
            xor_encode=False,
            length=120,
        )
        clean_template = leaf(100, fill=0x11, message_id=0x8027, length=110)
        rows = template_leaf_rows(
            type9_payload(batch(99, clean_template)), pool_idx=0
        )["rows"]

        rebuilt = build_shadow_logical(
            type9_payload(dirty_root),
            rows,
            special_rule_store=self.store,
        )

        self.assertFalse(rebuilt["drop_entire_report"])
        self.assertTrue(rebuilt["generated"])
        self.assertTrue(rebuilt["roundtrip_ok"])
        self.assertEqual(rebuilt["content_blacklist_dropped_leaves"], 0)
        self.assertEqual(rebuilt["content_blacklist_emptied_leaves"], 1)
        self.assertEqual(rebuilt["content_blacklist_tokens"], ["dopamine"])
        self.assertEqual(
            rebuilt["leaf_results"][0]["block_reason"],
            "SPECIAL_EMPTY_2000_KEEP_SEQUENCE",
        )
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        self.assertEqual(decoded["root"]["record_code"], 0x0102000A)
        self.assertEqual(decoded["root"]["message_id"], 0x2000)
        self.assertEqual(decoded["root"]["actual_length"], 44)
        self.assertEqual(decoded["root"]["record_sequence"], 901)
        self.assertEqual(len(decoded["leaves"]), 1)
        self.assertEqual(decoded["leaves"][0]["message_id"], 0x2000)
        self.assertIsNone(
            scan_type9_content_blacklist(decoded["root"]["raw"])
        )

    def test_online_replay_drops_filza_and_rebuilds_container(self):
        self.store.replace_document(nearest_document(0x8027))
        clean_sibling = leaf(100, fill=0x11, message_id=0x8027, length=110)
        live_sibling = leaf(900, fill=0x11, message_id=0x8027, length=110)
        dirty = leaf_with_body_text(
            901, message_id=0x8029, text="Filza", xor_encode=True, length=140
        )
        recorded_frames = [
            frame(batch(99, clean_sibling), account_id="GAME-42", report_index=1)
        ]
        live_frames = [
            frame(
                batch_children(899, live_sibling, dirty),
                account_id="GAME-42",
                report_index=18,
            )
        ]
        item = _ace_try_extract_frames(recorded_frames)
        logs = []
        previous_store = special_rules.type9_hot_rule_store
        special_rules.type9_hot_rule_store = self.store
        try:
            output, changed = _ace_try_replay_template(
                live_frames,
                [item],
                [0, 0],
                expected_game_id="GAME-42",
                on_log=logs.append,
            )
        finally:
            special_rules.type9_hot_rule_store = previous_store

        self.assertTrue(changed)
        self.assertEqual(logs[0]["decision"], "REPLACE")
        self.assertEqual(logs[0]["replacement_level"], "SPECIAL_EMPTY_2000")
        self.assertTrue(logs[0]["validation_ok"])
        self.assertEqual(
            logs[0]["shadow_rebuild"]["content_blacklist_tokens"],
            ["filza"],
        )
        decoded = decode_material(_ace_01_reassemble_frames(output)[1])
        self.assertEqual(
            [row["message_id"] for row in decoded["leaves"]],
            [0x8027, 0x2000],
        )
        self.assertEqual(
            [row["record_sequence"] for row in decoded["leaves"]],
            [900, 901],
        )
        self.assertEqual(
            self.store.snapshot()["rule_changed_counts"].get(
                CONTENT_BLACKLIST_RULE_ID, 0
            ),
            1,
        )

    def test_chinese_troll_token_drops_9000_style_leaf(self):
        dirty = leaf_with_body_text(
            901, message_id=0x9000, text="巨魔", xor_encode=True, length=96
        )
        clean_sibling = leaf(900, fill=0x11, message_id=0x8027, length=110)
        rows = template_leaf_rows(
            type9_payload(batch(99, clean_sibling)), pool_idx=0
        )["rows"]

        rebuilt = build_shadow_logical(
            type9_payload(batch_children(899, clean_sibling, dirty)),
            rows,
            special_rule_store=self.store,
        )

        self.assertEqual(rebuilt["content_blacklist_tokens"], ["巨魔"])
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertEqual(
            [row["message_id"] for row in decoded["leaves"]],
            [0x8027, 0x2000],
        )
        self.assertEqual(
            [row["record_sequence"] for row in decoded["leaves"]],
            [900, 901],
        )


if __name__ == "__main__":
    unittest.main()
