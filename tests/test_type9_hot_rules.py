import json
import os
import tempfile
import time
import unittest
import zlib

import core.type9_special_rules as special_rules
from core.crypto import (
    _ace_01_reassemble_frames,
    _ace_01_report_index,
    _ace_try_extract_frames,
    _ace_try_replay_template,
)
from core.type9_crypto import KEYS, type9_transform
from core.type9_online import BATCH_CODE, BINARY_CODE
from core.type9_shadow import build_shadow_logical, decode_material, template_leaf_rows
from core.type9_special_rules import (
    DEFAULT_HOT_RULE_DOCUMENT,
    HOT_RULE_SCHEMA,
    LEGACY_V122_DEFAULT_HOT_RULE_DOCUMENT,
    LEGACY_V123_COMPLETE_TEST_7_DOCUMENT,
    V123_SAFE_REPLAY_1_DOCUMENT,
    V123_SAFE_REPLAY_2_DOCUMENT,
    V123_SAFE_REPLAY_3_DOCUMENT,
    V1231_COMPLETE_TELEMETRY_CLEAN_DOCUMENT,
    V1232_DEVICE_AWARE_SLOT_CLEAN_1_DOCUMENT,
    V1255_8028_8002_ZERO_1_DOCUMENT,
    V1256_0207_DROP_100C_TEMPLATE_1_DOCUMENT,
    V1264_DROP_PATCH_ONLY_1_DOCUMENT,
    V1264_RESTORE_1105_TEMPLATE_1_DOCUMENT,
    V1264_100B_CROSS_DEVICE_TEMPLATE_1_DOCUMENT,
    V1264_MINIMAL_7_1_DOCUMENT,
    V1265_8027_8029_NEAREST_1_DOCUMENT,
    V1265_2000_NEAREST_DROP_1_DOCUMENT,
    V1267_0207_PATCH_LIVE_1_DOCUMENT,
    V1268_SEQUENCE_SAFE_EMPTY_2000_1_DOCUMENT,
    HotRuleValidationError,
    Type9HotRuleStore,
    apply_special_unknown_leaf,
    validate_hot_rule_document,
)


def leaf(sequence: int, *, fill: int, message_id: int = 0x0207, length: int = 116) -> bytes:
    data = bytearray([fill] * length)
    data[0:4] = (1).to_bytes(4, "big")
    data[4:6] = length.to_bytes(2, "big")
    data[6:10] = BINARY_CODE.to_bytes(4, "big")
    data[10:14] = sequence.to_bytes(4, "big")
    data[0x16:0x18] = message_id.to_bytes(2, "big")
    return bytes(data)


def batch(sequence: int, child: bytes) -> bytes:
    data = bytearray(21)
    data[0:4] = (1).to_bytes(4, "big")
    data[6:10] = BATCH_CODE.to_bytes(4, "big")
    data[10:14] = sequence.to_bytes(4, "big")
    data[0x14] = 1
    data += len(child).to_bytes(4, "big") + child
    data[4:6] = len(data).to_bytes(2, "big")
    return bytes(data)


def batch_children(sequence: int, *children: bytes) -> bytes:
    data = bytearray(21)
    data[0:4] = (1).to_bytes(4, "big")
    data[6:10] = BATCH_CODE.to_bytes(4, "big")
    data[10:14] = sequence.to_bytes(4, "big")
    data[0x14] = len(children)
    for child in children:
        data += len(child).to_bytes(4, "big") + child
    data[4:6] = len(data).to_bytes(2, "big")
    return bytes(data)


def type9_payload(plaintext: bytes, selector: int = 1, key_index: int = 3) -> bytes:
    cipher = type9_transform(plaintext, selector, KEYS[key_index], direction=1)
    return (
        b"\x01\x0A\x00\x09"
        + b"\x00" * 10
        + bytes([selector, key_index])
        + (zlib.crc32(plaintext) & 0xFFFFFFFF).to_bytes(4, "big")
        + len(cipher).to_bytes(2, "big")
        + cipher
    )


def frame(plaintext: bytes, *, account_id: str, report_index: int) -> bytes:
    account = account_id.encode("ascii")
    logical = (
        b"\x00" * 5
        + b"\x01\x0A\x00\x23"
        + report_index.to_bytes(4, "big")
        + b"\x00" * 10
        + bytes([len(account)])
        + account
        + b"\x00"
        + type9_payload(plaintext)
    )
    data = bytearray(55)
    data[0:3] = b"\x01\x00\x00"
    data[8:10] = report_index.to_bytes(2, "big")
    data[36:38] = report_index.to_bytes(2, "big")
    data[38:40] = (1).to_bytes(2, "big")
    data[40:44] = (zlib.crc32(logical) & 0xFFFFFFFF).to_bytes(4, "big")
    data[44] = 1
    data[45:47] = (9).to_bytes(2, "big")
    data[47] = 0x2B
    data[49:51] = (1).to_bytes(2, "big")
    data[51:55] = len(logical).to_bytes(4, "big")
    data += logical
    data[3:5] = len(data).to_bytes(2, "big")
    return bytes(data)


def document(action="patch_live", *, patches=None):
    rule = {
        "id": f"test-{action}",
        "enabled": True,
        "match": {
            "record_code": "0x0102000A",
            "message_id": "0x0207",
            "length": 116,
        },
        "action": action,
    }
    if patches is not None:
        rule["patches"] = patches
    return {"schema": HOT_RULE_SCHEMA, "revision": "test-1", "rules": [rule]}


def nearest_document(message_id=0x8027):
    return {
        "schema": HOT_RULE_SCHEMA,
        "revision": "test-nearest-1",
        "rules": [
            {
                "id": f"test-nearest-{message_id:04x}",
                "enabled": True,
                "match": {
                    "record_code": "0x0102000A",
                    "message_id": f"0x{message_id:04X}",
                    "length": "*",
                },
                "action": "replace_template_nearest",
            }
        ],
    }


def drop_9000_document():
    return {
        "schema": HOT_RULE_SCHEMA,
        "revision": "test-drop-9000-1",
        "rules": [
            {
                "id": "test-drop-hit-only-9000",
                "description": "删除命中型9000叶子",
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


class Type9HotRuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "type9_hot_rules.json")
        self.store = Type9HotRuleStore(
            self.path,
            auto_reload_interval=0,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_validation_normalizes_hex_and_rejects_overlap(self):
        source = document(
            patches=[{"offset": "0x48", "hex": "00 00 00 00"}]
        )
        source["rules"][0]["description"] = "测试中文说明"
        normalized, compiled = validate_hot_rule_document(
            source
        )
        self.assertEqual(normalized["rules"][0]["match"]["record_code"], "0x0102000A")
        self.assertEqual(normalized["rules"][0]["patches"][0]["offset"], 0x48)
        self.assertEqual(
            normalized["rules"][0]["description"], "测试中文说明"
        )
        self.assertEqual(compiled[0]["patches"][0]["value"], b"\x00" * 4)

        with self.assertRaises(HotRuleValidationError):
            validate_hot_rule_document(
                document(
                    patches=[
                        {"offset": 0x48, "hex": "00000000"},
                        {"offset": 0x4A, "hex": "00000000"},
                    ]
                )
            )

    def test_atomic_replace_and_bad_reload_keep_last_good_snapshot(self):
        status = self.store.replace_document(
            document(patches=[{"offset": 0x48, "hex": "00000000"}])
        )
        self.assertTrue(status["ok"])
        self.assertEqual(status["active_rule_count"], 1)
        first_generation = status["generation"]

        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("{broken")
        status = self.store.reload(force=True)
        self.assertFalse(status["ok"])
        self.assertEqual(status["active_rule_count"], 1)
        self.assertEqual(status["generation"], first_generation)
        self.assertIsNotNone(self.store.get_rule((BINARY_CODE, 0x0207, 116)))

    def test_nearest_template_rule_uses_wildcard_length(self):
        status = self.store.replace_document(nearest_document())
        self.assertTrue(status["ok"])
        self.assertEqual(
            status["document"]["rules"][0]["match"]["length"], "*"
        )
        rule = self.store.get_rule((BINARY_CODE, 0x8027, 137))
        self.assertEqual(rule["action"], "replace_template_nearest")

        invalid = nearest_document()
        invalid["rules"][0]["action"] = "patch_live"
        with self.assertRaises(HotRuleValidationError):
            validate_hot_rule_document(invalid)

    def test_drop_leaf_rule_accepts_wildcard_and_rejects_patches(self):
        normalized, compiled = validate_hot_rule_document(drop_9000_document())
        self.assertEqual(normalized["rules"][0]["match"]["length"], "*")
        self.assertEqual(compiled[0]["action"], "drop_leaf")

        invalid = drop_9000_document()
        invalid["rules"][0]["patches"] = [{"offset": 0, "hex": "00"}]
        with self.assertRaises(HotRuleValidationError):
            validate_hot_rule_document(invalid)

    def test_full_template_rule_keeps_live_device_and_runtime_context(self):
        self.store.replace_document(nearest_document(message_id=0x8027))
        recorded = bytearray(
            leaf(10, fill=0, message_id=0x8027, length=144)
        )
        live = bytearray(
            leaf(11, fill=0, message_id=0x8027, length=144)
        )
        recorded_context = (
            b"model:iPhone18,2;ver:26.50;inc_id:25;obf_id:25"
        )
        live_context = b"model:iPad13,4;ver:14.60;inc_id:67;obf_id:67"
        recorded[36:36 + len(recorded_context)] = recorded_context
        live[36:36 + len(live_context)] = live_context
        rows = template_leaf_rows(type9_payload(bytes(recorded)), pool_idx=0)[
            "rows"
        ]

        shadow = build_shadow_logical(
            type9_payload(bytes(live)),
            rows,
            special_rule_store=self.store,
        )

        self.assertTrue(shadow["generated"])
        self.assertTrue(shadow["roundtrip_ok"])
        self.assertEqual(shadow["changed_leaves"], 0)
        self.assertEqual(shadow["device_context_pass_live_leaves"], 1)
        result = shadow["leaf_results"][0]
        self.assertEqual(result["replacement_level"], "DEVICE_CONTEXT_PASS_LIVE")
        self.assertEqual(result["block_reason"], "DEVICE_CONTEXT_MISMATCH_PASS_LIVE")
        self.assertEqual(
            result["special_rule_error"], "DEVICE_CONTEXT_MISMATCH_PASS_LIVE"
        )
        rebuilt = decode_material(shadow["candidate_logical"])["leaves"][0][
            "raw"
        ]
        self.assertEqual(rebuilt, bytes(live))
        self.assertEqual(
            self.store.snapshot()["rule_changed_counts"]["test-nearest-8027"],
            0,
        )

    def test_v123_default_rules_only_show_effective_special_set(self):
        status = self.store.replace_document(DEFAULT_HOT_RULE_DOCUMENT)
        self.assertTrue(status["ok"])
        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(
            [rule["id"] for rule in status["document"]["rules"]],
            [
                "0207-zero-anomaly-counters",
                "2001-zero-behavior-vector",
                "8028-zero-write-counter",
                "8002-zero-status-word",
                "100B-clean-uikit-view-tree",
                "2000-clean-module-report",
                "1105-clean-module-enumeration",
                "8027-clean-process-profile",
                "8029-clean-process-location-profile",
                "9000-clean-installed-target-profile",
            ],
        )
        self.assertTrue(all(
            rule["description"] for rule in status["document"]["rules"]
        ))
        for message_id in (0x100B, 0x2000, 0x1105, 0x8027, 0x8029, 0x9000):
            self.assertIsNotNone(
                self.store.get_rule((BINARY_CODE, message_id, 80))
            )
        self.assertEqual(
            self.store.get_rule((BINARY_CODE, 0x0207, 116))["action"],
            "patch_live",
        )
        rule_0207 = self.store.get_rule((BINARY_CODE, 0x0207, 116))
        self.assertEqual(
            [(patch["offset"], patch["value"]) for patch in rule_0207["patches"]],
            [(0x48, b"\x00" * 4), (0x50, b"\x00" * 4)],
        )
        self.assertIsNone(
            self.store.get_rule((BINARY_CODE, 0x100C, 84))
        )
        self.assertEqual(
            self.store.get_rule((BINARY_CODE, 0x2001, 56))["action"],
            "patch_live",
        )
        self.assertEqual(
            self.store.get_rule((BINARY_CODE, 0x8028, 40))["action"],
            "patch_live",
        )
        self.assertEqual(
            self.store.get_rule((BINARY_CODE, 0x8002, 56))["action"],
            "patch_live",
        )
        self.assertEqual(
            self.store.get_rule((BINARY_CODE, 0x9000, 80))["id"],
            "9000-clean-installed-target-profile",
        )
        self.assertEqual(
            self.store.get_rule((BINARY_CODE, 0x9000, 80))["action"],
            "empty_2000",
        )
        self.assertEqual(
            self.store.get_rule((BINARY_CODE, 0x2000, 80))["no_template"],
            "empty_2000",
        )
        for message_id in (0x1007, 0x1008, 0x1009, 0x100C, 0x100F):
            self.assertIsNone(
                self.store.get_rule((BINARY_CODE, message_id, 80))
            )
        rule_100b = self.store.get_rule((BINARY_CODE, 0x100B, 80))
        self.assertEqual(rule_100b["action"], "replace_template_nearest")
        self.assertEqual(rule_100b["inherit_live_header"], 14)
        self.assertTrue(rule_100b.get("allow_cross_device"))
        self.assertFalse(rule_100b.get("require_same_device"))
        rule_1105 = self.store.get_rule((BINARY_CODE, 0x1105, 80))
        self.assertEqual(rule_1105["action"], "replace_template_nearest")
        self.assertEqual(rule_1105["inherit_live_header"], 36)
        rule_2000 = self.store.get_rule((BINARY_CODE, 0x2000, 80))
        self.assertEqual(rule_2000["action"], "replace_template_nearest")
        self.assertEqual(rule_2000["inherit_live_header"], 14)
        self.assertEqual(rule_2000.get("no_template"), "empty_2000")
        for message_id in (0x8027, 0x8029):
            rule = self.store.get_rule((BINARY_CODE, message_id, 80))
            self.assertEqual(rule["action"], "replace_template_nearest")
            self.assertEqual(rule["inherit_live_header"], 14)
            self.assertTrue(rule.get("allow_cross_device"))
            self.assertFalse(rule.get("require_same_device"))

    def test_bootstrap_upgrades_untouched_v1231_default_to_device_aware(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1231_COMPLETE_TELEMETRY_CLEAN_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(
                V1231_COMPLETE_TELEMETRY_CLEAN_DOCUMENT,
            ),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(status["active_rule_count"], 10)
        self.assertIsNone(store.get_rule((BINARY_CODE, 0x100C, 84)))
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x100B, 123))["action"],
            "replace_template_nearest",
        )
        self.assertTrue(
            store.get_rule((BINARY_CODE, 0x100B, 123)).get("allow_cross_device")
        )

    def test_bootstrap_upgrades_untouched_first_v1255_default(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1255_8028_8002_ZERO_1_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(V1255_8028_8002_ZERO_1_DOCUMENT,),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x0207, 116))["action"],
            "patch_live",
        )
        self.assertIsNone(store.get_rule((BINARY_CODE, 0x100C, 84)))

    def test_bootstrap_upgrades_untouched_v1256_to_drop_patch_only(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1256_0207_DROP_100C_TEMPLATE_1_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(
                V1256_0207_DROP_100C_TEMPLATE_1_DOCUMENT,
            ),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x0207, 116))["action"],
            "patch_live",
        )
        self.assertIsNone(store.get_rule((BINARY_CODE, 0x100C, 84)))
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x2001, 56))["action"],
            "patch_live",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x1105, 80))["action"],
            "replace_template_nearest",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x1105, 80))["inherit_live_header"],
            36,
        )

    def test_bootstrap_upgrades_untouched_v1264_pass_live_1105_back_to_template(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1264_DROP_PATCH_ONLY_1_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(V1264_DROP_PATCH_ONLY_1_DOCUMENT,),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x1105, 80))["action"],
            "replace_template_nearest",
        )
        self.assertIsNone(store.get_rule((BINARY_CODE, 0x100C, 84)))

    def test_bootstrap_upgrades_untouched_v1264_1105_to_cross_device_100b(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1264_RESTORE_1105_TEMPLATE_1_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(
                V1264_RESTORE_1105_TEMPLATE_1_DOCUMENT,
            ),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x100B, 80))["action"],
            "replace_template_nearest",
        )
        self.assertTrue(
            store.get_rule((BINARY_CODE, 0x100B, 80)).get("allow_cross_device")
        )

    def test_bootstrap_upgrades_untouched_12_rule_default_to_minimal_7(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1264_100B_CROSS_DEVICE_TEMPLATE_1_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(
                V1264_100B_CROSS_DEVICE_TEMPLATE_1_DOCUMENT,
            ),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(status["active_rule_count"], 10)
        self.assertIsNone(store.get_rule((BINARY_CODE, 0x100C, 84)))
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x2000, 80))["action"],
            "replace_template_nearest",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x2000, 80)).get("no_template"),
            "empty_2000",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x100B, 80))["action"],
            "replace_template_nearest",
        )
        for message_id in (0x8027, 0x8029):
            rule = store.get_rule((BINARY_CODE, message_id, 80))
            self.assertEqual(rule["action"], "replace_template_nearest")
            self.assertTrue(rule.get("allow_cross_device"))

    def test_bootstrap_upgrades_untouched_minimal_7_to_8027_8029_nearest(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1264_MINIMAL_7_1_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(V1264_MINIMAL_7_1_DOCUMENT,),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(status["active_rule_count"], 10)
        self.assertIsNone(store.get_rule((BINARY_CODE, 0x100C, 84)))
        for message_id in (0x8027, 0x8029):
            rule = store.get_rule((BINARY_CODE, message_id, 80))
            self.assertEqual(rule["action"], "replace_template_nearest")
            self.assertEqual(rule["inherit_live_header"], 14)
            self.assertTrue(rule.get("allow_cross_device"))

    def test_bootstrap_upgrades_untouched_8027_8029_set_to_2000_nearest(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1265_8027_8029_NEAREST_1_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(V1265_8027_8029_NEAREST_1_DOCUMENT,),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(status["active_rule_count"], 10)
        rule = store.get_rule((BINARY_CODE, 0x2000, 80))
        self.assertEqual(rule["action"], "replace_template_nearest")
        self.assertEqual(rule.get("no_template"), "empty_2000")

    def test_bootstrap_upgrades_untouched_v1265_0207_drop_to_patch_live(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1265_2000_NEAREST_DROP_1_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(V1265_2000_NEAREST_DROP_1_DOCUMENT,),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        rule = store.get_rule((BINARY_CODE, 0x0207, 116))
        self.assertEqual(rule["action"], "patch_live")
        self.assertEqual(
            [(patch["offset"], patch["value"]) for patch in rule["patches"]],
            [(0x48, b"\x00" * 4), (0x50, b"\x00" * 4)],
        )

    def test_bootstrap_upgrades_untouched_v1267_drop_rules_to_empty_2000(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1267_0207_PATCH_LIVE_1_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(V1267_0207_PATCH_LIVE_1_DOCUMENT,),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x9000, 80))["action"],
            "empty_2000",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x2000, 80))["no_template"],
            "empty_2000",
        )

    def test_bootstrap_upgrades_untouched_v1268_candidate_to_v127(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1268_SEQUENCE_SAFE_EMPTY_2000_1_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(
                V1268_SEQUENCE_SAFE_EMPTY_2000_1_DOCUMENT,
            ),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x9000, 80))["action"],
            "empty_2000",
        )

    def test_runtime_policy_forces_persisted_0207_drop_back_to_patch_live(self):
        persisted = json.loads(json.dumps(DEFAULT_HOT_RULE_DOCUMENT))
        persisted["revision"] = "user-persisted-old-drop"
        rule_0207 = next(
            rule
            for rule in persisted["rules"]
            if rule["id"] == "0207-zero-anomaly-counters"
        )
        rule_0207["id"] = "custom-drop-same-0207-key"
        rule_0207["action"] = "drop_leaf"
        rule_0207.pop("patches", None)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(persisted, handle, ensure_ascii=False)
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            auto_reload_interval=0,
            force_builtin_0207_patch_live=True,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        compiled = store.get_rule((BINARY_CODE, 0x0207, 116))
        self.assertEqual(compiled["action"], "patch_live")
        self.assertEqual(
            [(patch["offset"], patch["value"]) for patch in compiled["patches"]],
            [(0x48, b"\x00" * 4), (0x50, b"\x00" * 4)],
        )

    def test_explicit_1105_rule_keeps_live_counter_during_variable_replacement(self):
        explicit = nearest_document(message_id=0x1105)
        explicit["rules"][0]["inherit_live_header"] = 36
        self.store.replace_document(explicit)
        template = bytearray(leaf(100, fill=0, message_id=0x1105, length=93))
        live = bytearray(leaf(900, fill=0x77, message_id=0x1105, length=125))
        template[32:36] = (3).to_bytes(4, "big")
        template[36:] = b"\x00" * (len(template) - 36)
        live[32:36] = (57).to_bytes(4, "big")
        rows = template_leaf_rows(type9_payload(bytes(template)), pool_idx=7)["rows"]

        for wrap in (lambda value: value, lambda value: batch(899, value)):
            rebuilt = build_shadow_logical(
                type9_payload(wrap(bytes(live))),
                rows,
                special_rule_store=self.store,
            )
            self.assertTrue(rebuilt["generated"])
            decoded = decode_material(rebuilt["candidate_logical"])
            self.assertTrue(decoded["ok"])
            out = decoded["leaves"][0]["raw"]
            self.assertEqual(len(out), 93)
            self.assertEqual(int.from_bytes(out[4:6], "big"), 93)
            self.assertEqual(out[:4], live[:4])
            self.assertEqual(out[6:36], live[6:36])
            self.assertEqual(out[36:], template[36:])
            result = rebuilt["leaf_results"][0]
            self.assertEqual(
                result["replacement_level"],
                "SPECIAL_REPLACE_TEMPLATE_NEAREST",
            )
            self.assertEqual(result["candidate_length"], 93)

    def test_bootstrap_upgrades_only_untouched_v122_builtin_document(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                LEGACY_V122_DEFAULT_HOT_RULE_DOCUMENT,
                handle,
                ensure_ascii=False,
                indent=2,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(
                LEGACY_V122_DEFAULT_HOT_RULE_DOCUMENT,
                V123_SAFE_REPLAY_1_DOCUMENT,
                V123_SAFE_REPLAY_2_DOCUMENT,
                V123_SAFE_REPLAY_3_DOCUMENT,
            ),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(status["active_rule_count"], 10)

    def test_bootstrap_adds_9000_to_untouched_v123_revision_1(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(V123_SAFE_REPLAY_1_DOCUMENT, handle, ensure_ascii=False)
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(V123_SAFE_REPLAY_1_DOCUMENT,),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertIsNotNone(store.get_rule((BINARY_CODE, 0x9000, 80)))

    def test_bootstrap_changes_untouched_v123_revision_2_9000_to_drop_leaf(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(V123_SAFE_REPLAY_2_DOCUMENT, handle, ensure_ascii=False)
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(V123_SAFE_REPLAY_2_DOCUMENT,),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(
            store.get_rule((BINARY_CODE, 0x9000, 80))["action"],
            "empty_2000",
        )

    def test_bootstrap_upgrades_untouched_v123_revision_3_to_complete_set(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(V123_SAFE_REPLAY_3_DOCUMENT, handle, ensure_ascii=False)
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(V123_SAFE_REPLAY_3_DOCUMENT,),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(status["active_rule_count"], 10)
        self.assertIsNone(store.get_rule((BINARY_CODE, 0x1008, 180)))
        self.assertIsNone(store.get_rule((BINARY_CODE, 0x1009, 80)))
        self.assertIsNotNone(store.get_rule((BINARY_CODE, 0x100B, 90)))
        self.assertIsNone(store.get_rule((BINARY_CODE, 0x100F, 44)))

    def test_bootstrap_upgrades_untouched_seven_rule_test_document(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                LEGACY_V123_COMPLETE_TEST_7_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(
                LEGACY_V123_COMPLETE_TEST_7_DOCUMENT,
            ),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(status["active_rule_count"], 10)
        self.assertIsNone(store.get_rule((BINARY_CODE, 0x1008, 180)))

    def test_bootstrap_upgrades_untouched_old_thirteen_rule_default(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(
                V1232_DEVICE_AWARE_SLOT_CLEAN_1_DOCUMENT,
                handle,
                ensure_ascii=False,
            )
        store = Type9HotRuleStore(
            self.path,
            default_document=DEFAULT_HOT_RULE_DOCUMENT,
            managed_previous_defaults=(
                V1232_DEVICE_AWARE_SLOT_CLEAN_1_DOCUMENT,
            ),
            auto_reload_interval=0,
        )

        status = store.bootstrap()

        self.assertEqual(
            status["document"]["revision"],
            "v128.2-0207-4850-compact-ai-log-1",
        )
        self.assertEqual(status["active_rule_count"], 10)
        for message_id in (0x1007, 0x1008, 0x1009):
            self.assertIsNone(store.get_rule((BINARY_CODE, message_id, 80)))
        self.assertIsNone(store.get_rule((BINARY_CODE, 0x100C, 84)))

    def test_exact_length_rule_precedes_nearest_wildcard(self):
        rules = nearest_document()["rules"]
        rules.append(
            {
                "id": "8027-exact-pass",
                "enabled": True,
                "match": {
                    "record_code": "0x0102000A",
                    "message_id": "0x8027",
                    "length": 137,
                },
                "action": "pass_live",
            }
        )
        self.store.replace_document(
            {
                "schema": HOT_RULE_SCHEMA,
                "revision": "exact-wins",
                "rules": rules,
            }
        )
        self.assertEqual(
            self.store.get_rule((BINARY_CODE, 0x8027, 137))["id"],
            "8027-exact-pass",
        )
        self.assertEqual(
            self.store.get_rule((BINARY_CODE, 0x8027, 138))["id"],
            "test-nearest-8027",
        )

    def test_rule_changed_count_only_tracks_real_byte_changes(self):
        self.store.replace_document(
            document(patches=[{"offset": 0x48, "hex": "00000000"}])
        )
        raw = leaf(900, fill=0x77)
        parsed_leaf = {
            "raw": raw,
            "record_code": BINARY_CODE,
            "message_id": 0x0207,
            "actual_length": len(raw),
        }
        self.assertEqual(
            self.store.snapshot()["rule_changed_counts"]["test-patch_live"], 0
        )
        apply_special_unknown_leaf(parsed_leaf, rule_store=self.store)
        self.assertEqual(
            self.store.snapshot()["rule_changed_counts"]["test-patch_live"], 1
        )

        already_zero = bytearray(raw)
        already_zero[0x48:0x4C] = b"\x00" * 4
        parsed_leaf["raw"] = bytes(already_zero)
        apply_special_unknown_leaf(parsed_leaf, rule_store=self.store)
        self.assertEqual(
            self.store.snapshot()["rule_changed_counts"]["test-patch_live"], 1
        )

        status = self.store.reload(force=True)
        self.assertEqual(status["rule_changed_counts"]["test-patch_live"], 0)

    def test_clear_changed_counts_resets_all_rules_without_reloading(self):
        self.store.replace_document(
            document(patches=[{"offset": 0x48, "hex": "00000000"}])
        )
        generation = self.store.snapshot()["generation"]
        self.store.record_changed("test-patch_live")
        self.store.record_changed("test-patch_live")

        status = self.store.clear_changed_counts()

        self.assertEqual(status["generation"], generation)
        self.assertEqual(status["rule_changed_counts"]["test-patch_live"], 0)
        self.assertIsNotNone(self.store.get_rule((BINARY_CODE, 0x0207, 116)))

    def test_patch_live_overrides_template_for_root_and_container(self):
        self.store.replace_document(
            document(
                patches=[
                    {"offset": "0x48", "hex": "00000000"},
                    {"offset": "0x50", "hex": "00000000"},
                ]
            )
        )
        live = bytearray(leaf(900, fill=0x77))
        live[0x48:0x4C] = (573).to_bytes(4, "big")
        live[0x50:0x54] = (6).to_bytes(4, "big")
        live[0x40:0x44] = bytes.fromhex("A1B2C3D4")
        template = leaf(100, fill=0x11)

        for wrap in (lambda value: value, lambda value: batch(899, value)):
            rows = template_leaf_rows(type9_payload(wrap(template)), pool_idx=0)["rows"]
            rebuilt = build_shadow_logical(
                type9_payload(wrap(bytes(live))),
                rows,
                special_rule_store=self.store,
            )
            self.assertTrue(rebuilt["generated"])
            decoded = decode_material(rebuilt["candidate_logical"])
            out = decoded["leaves"][0]["raw"]
            self.assertEqual(int.from_bytes(out[10:14], "big"), 900)
            self.assertEqual(out[0x40:0x44], bytes.fromhex("A1B2C3D4"))
            self.assertEqual(out[0x48:0x4C], b"\x00" * 4)
            self.assertEqual(out[0x50:0x54], b"\x00" * 4)
            result = rebuilt["leaf_results"][0]
            self.assertEqual(result["replacement_level"], "SPECIAL_PATCH_LIVE")
            self.assertEqual(result["special_rule_id"], "test-patch_live")
            self.assertEqual(result["template_sequence"], 100)

    def test_default_8028_8002_zero_only_jumped_fields(self):
        self.store.replace_document(DEFAULT_HOT_RULE_DOCUMENT)
        live_8028 = bytearray(leaf(10, fill=0, message_id=0x8028, length=40))
        live_8028[0x20:0x24] = (7).to_bytes(4, "big")
        live_8028[0x24:0x28] = (74107).to_bytes(4, "big")
        live_8002 = bytearray(leaf(11, fill=0, message_id=0x8002, length=56))
        live_8002[0x2C:0x30] = (3).to_bytes(4, "big")
        live_8002[0x30:0x34] = (4).to_bytes(4, "big")
        live_8002[0x34:0x38] = (3).to_bytes(4, "big")

        rebuilt = build_shadow_logical(
            type9_payload(batch_children(1, bytes(live_8028), bytes(live_8002))),
            [],
            special_rule_store=self.store,
        )
        self.assertTrue(rebuilt["generated"])
        out_leaves = decode_material(rebuilt["candidate_logical"])["leaves"]
        out_8028 = next(item["raw"] for item in out_leaves if item["message_id"] == 0x8028)
        out_8002 = next(item["raw"] for item in out_leaves if item["message_id"] == 0x8002)
        self.assertEqual(int.from_bytes(out_8028[0x20:0x24], "big"), 7)
        self.assertEqual(out_8028[0x24:0x28], b"\x00" * 4)
        self.assertEqual(out_8002[0x2C:0x30], b"\x00" * 4)
        self.assertEqual(int.from_bytes(out_8002[0x30:0x34], "big"), 4)
        self.assertEqual(int.from_bytes(out_8002[0x34:0x38], "big"), 3)
        rule_ids = {item["special_rule_id"] for item in rebuilt["leaf_results"]}
        self.assertEqual(
            rule_ids,
            {"8028-zero-write-counter", "8002-zero-status-word"},
        )

    def test_default_100b_replaces_across_devices(self):
        self.store.replace_document(DEFAULT_HOT_RULE_DOCUMENT)
        recorded = leaf(10, fill=0x11, message_id=0x100B, length=90)
        live = leaf(91, fill=0xA5, message_id=0x100B, length=123)
        rows = template_leaf_rows(type9_payload(recorded), pool_idx=0)["rows"]
        for row in rows:
            row["device_context"] = {
                "model": "iPhone18,2",
                "system_version": "26.5.1",
            }

        rebuilt = build_shadow_logical(
            type9_payload(live),
            rows,
            special_rule_store=self.store,
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.6",
            },
        )

        self.assertTrue(rebuilt["generated"])
        out = decode_material(rebuilt["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(out[:4], live[:4])
        self.assertEqual(int.from_bytes(out[4:6], "big"), 90)
        self.assertEqual(out[6:14], live[6:14])
        self.assertEqual(out[14:], recorded[14:])
        self.assertEqual(len(out), 90)
        result = rebuilt["leaf_results"][0]
        self.assertEqual(
            result["replacement_level"],
            "SPECIAL_REPLACE_TEMPLATE_NEAREST",
        )
        self.assertFalse(result.get("device_context_mismatch"))

    def test_default_8027_replaces_from_template_across_devices(self):
        self.store.replace_document(DEFAULT_HOT_RULE_DOCUMENT)
        recorded = leaf(10, fill=0x11, message_id=0x8027, length=102)
        live = leaf(91, fill=0xA5, message_id=0x8027, length=113)
        rows = template_leaf_rows(type9_payload(recorded), pool_idx=0)["rows"]
        for row in rows:
            row["device_context"] = {
                "model": "iPhone18,2",
                "system_version": "26.5.1",
            }

        rebuilt = build_shadow_logical(
            type9_payload(live),
            rows,
            special_rule_store=self.store,
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.6",
            },
        )

        self.assertTrue(rebuilt["generated"])
        out = decode_material(rebuilt["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(out[:4], live[:4])
        self.assertEqual(int.from_bytes(out[4:6], "big"), 102)
        self.assertEqual(out[6:14], live[6:14])
        self.assertEqual(out[14:], recorded[14:])
        result = rebuilt["leaf_results"][0]
        self.assertEqual(
            result["replacement_level"],
            "SPECIAL_REPLACE_TEMPLATE_NEAREST",
        )
        self.assertFalse(result.get("device_context_mismatch"))

    def test_cross_device_template_inherits_live_ipad_identity(self):
        self.store.replace_document(DEFAULT_HOT_RULE_DOCUMENT)
        recorded = bytearray(
            leaf(10, fill=0, message_id=0x8027, length=512)
        )
        live = bytearray(
            leaf(91, fill=0, message_id=0x8027, length=512)
        )
        recorded_identity = (
            b"model:iPhone18,2;ver:26.5.1;iDevHwModel:D84AP;"
            b"iDevSysVer:26.5.1;iDevSysName:iPhone OS;"
            b"iDevIDFV:11111111-1111-1111-1111-111111111111;"
            b"iDevRes:1179x2556;iAppVersion:1.2.3;"
            b"iAppMachUUID:AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA;"
            b"inc_id:25;obf_id:25"
        )
        live_identity = (
            b"model:iPad13,4;ver:14.6;iDevHwModel:J517AP;"
            b"iDevSysVer:14.6;iDevSysName:iPadOS;"
            b"iDevIDFV:22222222-2222-2222-2222-222222222222;"
            b"iDevRes:1640x2360;iAppVersion:9.8.7;"
            b"iAppMachUUID:BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB;"
            b"inc_id:67;obf_id:67"
        )
        recorded[36:36 + len(recorded_identity)] = recorded_identity
        live[36:36 + len(live_identity)] = live_identity
        rows = template_leaf_rows(
            type9_payload(bytes(recorded)), pool_idx=0
        )["rows"]
        for row in rows:
            row["device_context"] = {
                "model": "iPhone18,2",
                "system_version": "26.5.1",
            }

        rebuilt = build_shadow_logical(
            type9_payload(bytes(live)),
            rows,
            special_rule_store=self.store,
            device_mode="inherit_live",
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.6",
            },
        )

        self.assertTrue(rebuilt["generated"])
        self.assertTrue(rebuilt["roundtrip_ok"])
        out = decode_material(rebuilt["candidate_logical"])["leaves"][0]["raw"]
        self.assertIn(b"model:iPad13,4;ver:14.6", out)
        self.assertIn(b"iDevHwModel:J517AP", out)
        self.assertIn(b"iDevSysVer:14.6;iDevSysName:iPadOS", out)
        self.assertIn(b"iDevIDFV:22222222-2222-2222-2222-222222222222", out)
        self.assertIn(b"iDevRes:1640x2360;iAppVersion:9.8.7", out)
        self.assertIn(
            b"iAppMachUUID:BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB",
            out,
        )
        self.assertIn(b"inc_id:67;obf_id:67", out)
        self.assertNotIn(b"iPhone18,2", out)
        result = rebuilt["leaf_results"][0]
        self.assertFalse(result.get("device_context_mismatch"))
        self.assertEqual(
            {item["field"] for item in result["device_field_rewrites"]},
            {
                "model",
                "hardware_model",
                "system_version",
                "system_name",
                "device_idfv",
                "device_resolution",
                "app_version",
                "app_mach_uuid",
            },
        )
        self.assertEqual(
            {item["field"] for item in result["runtime_field_rewrites"]},
            {"inc_id", "obf_id"},
        )

    def test_default_8027_passes_live_without_template(self):
        self.store.replace_document(DEFAULT_HOT_RULE_DOCUMENT)
        live = leaf(91, fill=0xA5, message_id=0x8027, length=113)

        rebuilt = build_shadow_logical(
            type9_payload(live),
            [],
            special_rule_store=self.store,
        )

        self.assertTrue(rebuilt["generated"])
        out = decode_material(rebuilt["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(out, live)
        result = rebuilt["leaf_results"][0]
        self.assertEqual(result["replacement_level"], "SPECIAL_PASS_LIVE")
        self.assertEqual(result["special_rule_id"], "8027-clean-process-profile")
        self.assertEqual(result["special_rule_error"], "HOT_RULE_TEMPLATE_REQUIRED")

    def test_default_2000_replaces_from_template(self):
        self.store.replace_document(DEFAULT_HOT_RULE_DOCUMENT)
        recorded = leaf(10, fill=0x11, message_id=0x2000, length=44)
        live = leaf(91, fill=0xA5, message_id=0x2000, length=80)
        rows = template_leaf_rows(type9_payload(recorded), pool_idx=0)["rows"]

        rebuilt = build_shadow_logical(
            type9_payload(live),
            rows,
            special_rule_store=self.store,
        )

        self.assertTrue(rebuilt["generated"])
        out = decode_material(rebuilt["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(out[:4], live[:4])
        self.assertEqual(int.from_bytes(out[4:6], "big"), 44)
        self.assertEqual(out[6:14], live[6:14])
        self.assertEqual(out[14:], recorded[14:])
        result = rebuilt["leaf_results"][0]
        self.assertEqual(
            result["replacement_level"],
            "SPECIAL_REPLACE_TEMPLATE_NEAREST",
        )
        self.assertEqual(result["special_rule_id"], "2000-clean-module-report")

    def test_default_2000_becomes_empty_without_template(self):
        self.store.replace_document(DEFAULT_HOT_RULE_DOCUMENT)
        sibling = leaf(90, fill=0x11, message_id=0x100C, length=84)
        live_2000 = leaf(91, fill=0xA5, message_id=0x2000, length=80)

        rebuilt = build_shadow_logical(
            type9_payload(batch_children(899, sibling, live_2000)),
            [],
            special_rule_store=self.store,
        )

        self.assertTrue(rebuilt["generated"])
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertEqual(
            [row["message_id"] for row in decoded["leaves"]],
            [0x100C, 0x2000],
        )
        emptied = [
            row for row in rebuilt["leaf_results"] if row["message_id"] == 0x2000
        ]
        self.assertEqual(len(emptied), 1)
        self.assertEqual(emptied[0]["replacement_level"], "SPECIAL_EMPTY_2000")
        self.assertEqual(emptied[0]["special_rule_id"], "2000-clean-module-report")
        self.assertEqual(
            emptied[0]["special_rule_error"],
            "HOT_RULE_TEMPLATE_REQUIRED_EMPTY_2000",
        )
        out = decoded["leaves"][1]["raw"]
        self.assertEqual(len(out), 44)
        self.assertEqual(out[10:14], live_2000[10:14])
        self.assertEqual(rebuilt["special_emptied_leaves"], 1)
        self.assertEqual(rebuilt["special_dropped_leaves"], 0)

    def test_default_9000_becomes_empty_and_keeps_sequence_continuous(self):
        self.store.replace_document(DEFAULT_HOT_RULE_DOCUMENT)
        before = leaf(3324, fill=0x11, message_id=0x100C, length=84)
        hit_9000 = leaf(3325, fill=0x77, message_id=0x9000, length=84)
        after = leaf(3326, fill=0x22, message_id=0x100C, length=84)

        rebuilt = build_shadow_logical(
            type9_payload(batch_children(3319, before, hit_9000, after)),
            [],
            special_rule_store=self.store,
        )

        self.assertTrue(rebuilt["generated"])
        self.assertTrue(rebuilt["roundtrip_ok"])
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertEqual(
            [row["message_id"] for row in decoded["leaves"]],
            [0x100C, 0x2000, 0x100C],
        )
        self.assertEqual(
            [row["record_sequence"] for row in decoded["leaves"]],
            [3324, 3325, 3326],
        )
        empty = decoded["leaves"][1]["raw"]
        self.assertEqual(len(empty), 44)
        self.assertEqual(empty[10:14], (3325).to_bytes(4, "big"))
        self.assertEqual(rebuilt["special_emptied_leaves"], 1)
        self.assertEqual(rebuilt["special_dropped_leaves"], 0)
        result = rebuilt["leaf_results"][1]
        self.assertEqual(result["replacement_level"], "SPECIAL_EMPTY_2000")
        self.assertEqual(result["special_rule_action"], "REPLACE_CLEAN_2000")

    def test_default_patches_0207_and_keeps_100c_live(self):
        self.store.replace_document(DEFAULT_HOT_RULE_DOCUMENT)
        clean_100c = leaf(100, fill=0x11, message_id=0x100C, length=84)
        live_100c = leaf(901, fill=0x77, message_id=0x100C, length=84)
        live_0207 = bytearray(
            leaf(900, fill=0x55, message_id=0x0207, length=116)
        )
        live_0207[0x44:0x48] = (13).to_bytes(4, "big")
        live_0207[0x48:0x4C] = (7).to_bytes(4, "big")
        live_0207[0x4C:0x50] = (1).to_bytes(4, "big")
        live_0207[0x50:0x54] = (2).to_bytes(4, "big")
        live_0207 = bytes(live_0207)
        rows = template_leaf_rows(
            type9_payload(clean_100c), pool_idx=7
        )["rows"]

        rebuilt = build_shadow_logical(
            type9_payload(batch_children(899, live_0207, live_100c)),
            rows,
            special_rule_store=self.store,
        )

        self.assertTrue(rebuilt["generated"])
        self.assertTrue(rebuilt["roundtrip_ok"])
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertEqual(
            [row["message_id"] for row in decoded["leaves"]],
            [0x0207, 0x100C],
        )
        out_0207 = decoded["leaves"][0]["raw"]
        out_100c = decoded["leaves"][1]["raw"]
        self.assertEqual(out_0207[:0x44], live_0207[:0x44])
        self.assertEqual(out_0207[0x44:0x48], live_0207[0x44:0x48])
        self.assertEqual(out_0207[0x48:0x4C], b"\x00" * 4)
        self.assertEqual(out_0207[0x4C:0x50], live_0207[0x4C:0x50])
        self.assertEqual(out_0207[0x50:0x54], b"\x00" * 4)
        self.assertEqual(out_0207[0x54:], live_0207[0x54:])
        self.assertEqual(out_100c, live_100c)
        result_0207 = next(
            row for row in rebuilt["leaf_results"]
            if row["message_id"] == 0x0207
        )
        result_100c = next(
            row for row in rebuilt["leaf_results"]
            if row["message_id"] == 0x100C
        )
        self.assertEqual(result_0207["replacement_level"], "SPECIAL_PATCH_LIVE")
        self.assertEqual(rebuilt["special_dropped_leaves"], 0)
        self.assertEqual(result_100c["replacement_level"], "UNMAPPED_BODY_PASS_LIVE")
        self.assertEqual(result_100c.get("special_rule_id") or "", "")

    def test_default_0207_keeps_container_and_root_shape(self):
        self.store.replace_document(DEFAULT_HOT_RULE_DOCUMENT)
        live_0207 = bytearray(
            leaf(901, fill=0x55, message_id=0x0207, length=116)
        )
        live_0207[0x44:0x48] = (28).to_bytes(4, "big")
        live_0207[0x48:0x4C] = (9).to_bytes(4, "big")
        live_0207[0x4C:0x50] = (1).to_bytes(4, "big")
        live_0207[0x50:0x54] = (3).to_bytes(4, "big")
        live_0207 = bytes(live_0207)

        for live_plain in (batch(899, live_0207), live_0207):
            rebuilt = build_shadow_logical(
                type9_payload(live_plain),
                [],
                special_rule_store=self.store,
            )

            self.assertTrue(rebuilt["generated"])
            self.assertTrue(rebuilt["roundtrip_ok"])
            self.assertEqual(rebuilt["special_dropped_leaves"], 0)
            decoded = decode_material(rebuilt["candidate_logical"])
            self.assertTrue(decoded["ok"])
            self.assertEqual(
                [row["message_id"] for row in decoded["leaves"]],
                [0x0207],
            )
            out = decoded["leaves"][0]["raw"]
            self.assertEqual(out[0x44:0x48], live_0207[0x44:0x48])
            self.assertEqual(out[0x48:0x4C], b"\x00" * 4)
            self.assertEqual(out[0x4C:0x50], live_0207[0x4C:0x50])
            self.assertEqual(out[0x50:0x54], b"\x00" * 4)
            self.assertEqual(out[10:14], (901).to_bytes(4, "big"))

    def test_patch_live_does_not_require_leaf_template(self):
        self.store.replace_document(
            document(patches=[{"offset": "0x48", "hex": "00000000"}])
        )
        live = bytearray(leaf(900, fill=0x77))
        live[0x48:0x4C] = (573).to_bytes(4, "big")
        rebuilt = build_shadow_logical(
            type9_payload(bytes(live)),
            [],
            special_rule_store=self.store,
        )
        self.assertTrue(rebuilt["generated"])
        self.assertEqual(rebuilt["matched_leaves"], 0)
        self.assertEqual(rebuilt["special_handled_leaves"], 1)
        out = decode_material(rebuilt["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(out[0x48:0x4C], b"\x00" * 4)
        self.assertEqual(out[:0x48], bytes(live[:0x48]))

    def test_online_replay_sends_patch_without_matching_leaf_template(self):
        self.store.replace_document(
            document(patches=[{"offset": "0x48", "hex": "00000000"}])
        )
        unrelated_template = leaf(100, fill=0x11, message_id=0x9001)
        recorded_frames = [
            frame(batch(99, unrelated_template), account_id="GAME-42", report_index=1)
        ]
        live_leaf = bytearray(leaf(900, fill=0x77))
        live_leaf[0x48:0x4C] = (573).to_bytes(4, "big")
        live_frames = [
            frame(batch(899, bytes(live_leaf)), account_id="GAME-42", report_index=18)
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
        result = logs[0]["shadow_rebuild"]["leaf_results"][0]
        self.assertFalse(result["matched"])
        self.assertEqual(result["replacement_level"], "SPECIAL_PATCH_LIVE")
        rebuilt = decode_material(_ace_01_reassemble_frames(output)[1])["leaves"][0]["raw"]
        self.assertEqual(rebuilt[0x48:0x4C], b"\x00" * 4)

    def test_drop_9000_leaf_rebuilds_container_without_clean_9000_template(self):
        self.store.replace_document(drop_9000_document())
        clean_sibling = leaf(100, fill=0x11, message_id=0x8027, length=110)
        live_sibling = leaf(900, fill=0x11, message_id=0x8027, length=110)
        hit_9000 = leaf(901, fill=0x77, message_id=0x9000, length=96)
        rows = template_leaf_rows(
            type9_payload(batch(99, clean_sibling)), pool_idx=0
        )["rows"]

        rebuilt = build_shadow_logical(
            type9_payload(batch_children(899, live_sibling, hit_9000)),
            rows,
            special_rule_store=self.store,
        )

        self.assertTrue(rebuilt["generated"])
        self.assertTrue(rebuilt["roundtrip_ok"])
        self.assertEqual(rebuilt["pruned_leaves"], 1)
        self.assertEqual(rebuilt["special_dropped_leaves"], 1)
        self.assertEqual(rebuilt["special_changed_leaves"], 1)
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        self.assertEqual(decoded["root"]["record_code"], BINARY_CODE)
        self.assertEqual(decoded["root"]["message_id"], 0x8027)
        self.assertEqual(decoded["leaves"][0].get("path"), [])
        self.assertEqual([row["message_id"] for row in decoded["leaves"]], [0x8027])
        drop_result = next(
            row for row in rebuilt["leaf_results"] if row["message_id"] == 0x9000
        )
        self.assertEqual(drop_result["replacement_level"], "SPECIAL_DROP_LEAF")
        self.assertEqual(drop_result["special_rule_action"], "DROP_LEAF")
        self.assertEqual(
            self.store.snapshot()["rule_changed_counts"]["test-drop-hit-only-9000"],
            1,
        )

    def test_online_replay_drops_live_9000_when_recording_has_no_9000(self):
        self.store.replace_document(drop_9000_document())
        clean_sibling = leaf(100, fill=0x11, message_id=0x8027, length=110)
        live_sibling = leaf(900, fill=0x11, message_id=0x8027, length=110)
        hit_9000 = leaf(901, fill=0x77, message_id=0x9000, length=96)
        recorded_frames = [
            frame(batch(99, clean_sibling), account_id="GAME-42", report_index=1)
        ]
        live_frames = [
            frame(
                batch_children(899, live_sibling, hit_9000),
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
        self.assertEqual(logs[0]["replacement_level"], "SPECIAL_DROP_LEAF")
        self.assertEqual(logs[0]["reason"], "SPECIAL_DROP_LEAF_REPLACE")
        self.assertTrue(logs[0]["validation_ok"])
        self.assertTrue(logs[0]["shadow_rebuild"]["checks"]["outer_crc_ok"])
        self.assertTrue(logs[0]["shadow_rebuild"]["checks"]["decode_ok"])
        decoded = decode_material(_ace_01_reassemble_frames(output)[1])
        self.assertEqual([row["message_id"] for row in decoded["leaves"]], [0x8027])

    def test_online_replay_keeps_report_index_when_9000_is_root_leaf(self):
        self.store.replace_document(drop_9000_document())
        unrelated = leaf(100, fill=0x11, message_id=0x8027, length=110)
        root_9000 = leaf(901, fill=0x77, message_id=0x9000, length=83)
        recorded_frames = [
            frame(batch(99, unrelated), account_id="GAME-42", report_index=1)
        ]
        live_frames = [
            frame(root_9000, account_id="GAME-42", report_index=18)
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
        self.assertTrue(output)
        self.assertEqual(logs[0]["decision"], "REPLACE")
        self.assertEqual(
            logs[0]["reason"], "SPECIAL_DROP_ROOT_TO_CLEAN_2000_REPLACE"
        )
        self.assertTrue(logs[0]["validation_ok"])
        self.assertFalse(logs[0]["shadow_rebuild"]["drop_entire_report"])
        assembled = _ace_01_reassemble_frames(output)
        self.assertIsNotNone(assembled)
        self.assertEqual(_ace_01_report_index(assembled[1]), 18)
        decoded = decode_material(assembled[1])
        self.assertTrue(decoded["ok"])
        self.assertEqual(decoded["root"]["record_code"], BINARY_CODE)
        self.assertEqual(decoded["root"]["message_id"], 0x2000)
        self.assertEqual(decoded["root"]["actual_length"], 44)
        self.assertEqual(decoded["root"]["record_sequence"], 901)
        self.assertEqual([row["message_id"] for row in decoded["leaves"]], [0x2000])

    def test_replace_template_and_pass_live_actions(self):
        live = leaf(900, fill=0x77)
        template = leaf(100, fill=0x11)
        rows = template_leaf_rows(type9_payload(template), pool_idx=0)["rows"]

        self.store.replace_document(document(action="replace_template"))
        rebuilt = build_shadow_logical(
            type9_payload(live), rows, special_rule_store=self.store
        )
        out = decode_material(rebuilt["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(out[:14], live[:14])
        self.assertEqual(out[14:], template[14:])
        self.assertEqual(
            rebuilt["leaf_results"][0]["replacement_level"],
            "SPECIAL_REPLACE_TEMPLATE",
        )

        self.store.replace_document(document(action="pass_live"))
        rebuilt = build_shadow_logical(
            type9_payload(live), rows, special_rule_store=self.store
        )
        out = decode_material(rebuilt["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(out, live)
        self.assertEqual(
            rebuilt["leaf_results"][0]["replacement_level"],
            "SPECIAL_PASS_LIVE",
        )
        self.assertEqual(
            self.store.snapshot()["rule_changed_counts"]["test-pass_live"], 0
        )

    def test_nearest_template_rule_rebuilds_root_and_container_lengths(self):
        self.store.replace_document(nearest_document(message_id=0x2000))
        template = leaf(100, fill=0x11, message_id=0x2000, length=110)
        live = leaf(900, fill=0x77, message_id=0x2000, length=137)
        rows = template_leaf_rows(type9_payload(template), pool_idx=4)["rows"]

        for wrap in (lambda value: value, lambda value: batch(899, value)):
            rebuilt = build_shadow_logical(
                type9_payload(wrap(live)),
                rows,
                special_rule_store=self.store,
            )
            self.assertTrue(rebuilt["generated"])
            self.assertEqual(rebuilt["variable_length_replaced_leaves"], 1)
            decoded = decode_material(rebuilt["candidate_logical"])
            self.assertTrue(decoded["ok"])
            out = decoded["leaves"][0]["raw"]
            self.assertEqual(len(out), 110)
            self.assertEqual(int.from_bytes(out[4:6], "big"), 110)
            self.assertEqual(int.from_bytes(out[10:14], "big"), 900)
            self.assertEqual(out[14:], template[14:])
            result = rebuilt["leaf_results"][0]
            self.assertEqual(
                result["replacement_level"],
                "SPECIAL_REPLACE_TEMPLATE_NEAREST",
            )
            self.assertEqual(result["length"], 137)
            self.assertEqual(result["candidate_length"], 110)
            self.assertEqual(result["template_length"], 110)
            self.assertEqual(result["template_pool_idx"], 4)
        self.assertEqual(
            self.store.snapshot()["rule_changed_counts"]["test-nearest-2000"],
            2,
        )

    def test_online_replay_refragments_nearest_clean_process_template(self):
        self.store.replace_document(nearest_document(message_id=0x2000))
        clean_leaf = leaf(100, fill=0x11, message_id=0x2000, length=110)
        live_leaf = leaf(900, fill=0x77, message_id=0x2000, length=137)
        recorded_frames = [
            frame(batch(99, clean_leaf), account_id="GAME-42", report_index=1)
        ]
        live_frames = [
            frame(batch(899, live_leaf), account_id="GAME-42", report_index=18)
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
        self.assertEqual(
            logs[0]["replacement_level"],
            "SPECIAL_REPLACE_TEMPLATE_NEAREST",
        )
        self.assertEqual(
            logs[0]["reason"], "PROCESS_SCAN_CLEAN_TEMPLATE_REPLACE"
        )
        rebuilt = _ace_01_reassemble_frames(output)
        self.assertIsNotNone(rebuilt)
        out = decode_material(rebuilt[1])["leaves"][0]["raw"]
        self.assertEqual(len(out), 110)
        self.assertEqual(int.from_bytes(out[10:14], "big"), 900)
        self.assertEqual(out[14:], clean_leaf[14:])

    def test_expect_mismatch_keeps_live_and_logs_error(self):
        self.store.replace_document(
            document(
                patches=[
                    {
                        "offset": 0x48,
                        "expect_hex": "01000000",
                        "hex": "00000000",
                    }
                ]
            )
        )
        live = leaf(900, fill=0x77)
        template = leaf(100, fill=0x11)
        rows = template_leaf_rows(type9_payload(template), pool_idx=0)["rows"]
        rebuilt = build_shadow_logical(
            type9_payload(live), rows, special_rule_store=self.store
        )
        result = rebuilt["leaf_results"][0]
        self.assertEqual(result["replacement_level"], "SPECIAL_PASS_LIVE")
        self.assertEqual(result["special_rule_error"], "HOT_RULE_EXPECT_MISMATCH@0x48")
        out = decode_material(rebuilt["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(out, live)


if __name__ == "__main__":
    unittest.main()
