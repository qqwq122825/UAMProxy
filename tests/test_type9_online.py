import unittest
import zlib

from core.config import app_config
from core.crypto import (
    _ace_01_reassemble_frames,
    _ace_try_extract_frames,
    _ace_try_replay_template,
)
from core.type9_crypto import KEYS, type9_transform
from core.type9_online import (
    BATCH_CODE,
    BINARY_CODE,
    decode_type9_payload,
    decide_observe_only,
)
from core.type9_shadow import (
    build_shadow_logical,
    decode_material,
    template_leaf_rows,
)
from core.type9_special_rules import type9_hot_rule_store


class _NoHotRules:
    def get_rule(self, _key):
        return None

    def record_changed(self, _rule_id):
        pass


NO_HOT_RULES = _NoHotRules()


class _OneHotRule:
    def __init__(self, message_id: int):
        self.message_id = message_id

    def get_rule(self, key):
        if key[0] != BINARY_CODE or key[1] != self.message_id:
            return None
        return {
            "id": f"test-{self.message_id:04X}-same-device",
            "action": "replace_template_nearest",
            "inherit_live_header": 14,
            "require_same_device": True,
            "patches": [],
        }

    def record_changed(self, _rule_id):
        pass


def _leaf(sequence: int, message_id: int) -> bytes:
    data = bytearray(24)
    data[0:4] = (1).to_bytes(4, "big")
    data[6:10] = BINARY_CODE.to_bytes(4, "big")
    data[10:14] = sequence.to_bytes(4, "big")
    data[0x16:0x18] = message_id.to_bytes(2, "big")
    data[4:6] = len(data).to_bytes(2, "big")
    return bytes(data)


def _leaf_with_body(
    sequence: int, message_id: int, fill: int, *, length: int = 40
) -> bytes:
    data = bytearray([fill] * length)
    data[0:4] = (1).to_bytes(4, "big")
    data[6:10] = BINARY_CODE.to_bytes(4, "big")
    data[10:14] = sequence.to_bytes(4, "big")
    data[0x16:0x18] = message_id.to_bytes(2, "big")
    data[4:6] = len(data).to_bytes(2, "big")
    return bytes(data)


def _leaf_with_clean_value(
    sequence: int, message_id: int, value: int
) -> bytes:
    data = bytearray(_leaf_with_body(sequence, message_id, 0))
    data[24:32] = bytes.fromhex("200F000234560001")
    data[32:36] = value.to_bytes(4, "big")
    return bytes(data)


def _batch(sequence: int, children: list[bytes]) -> bytes:
    data = bytearray(21)
    data[0:4] = (1).to_bytes(4, "big")
    data[6:10] = BATCH_CODE.to_bytes(4, "big")
    data[10:14] = sequence.to_bytes(4, "big")
    data[0x14] = len(children)
    for child in children:
        data += len(child).to_bytes(4, "big") + child
    data[4:6] = len(data).to_bytes(2, "big")
    return bytes(data)


def _telemetry_leaf(sequence: int, record_code: int, text: str) -> bytes:
    body = text.encode("ascii") + b"\x00"
    data = bytearray(14 + len(body))
    data[0:4] = (1).to_bytes(4, "big")
    data[6:10] = record_code.to_bytes(4, "big")
    data[10:14] = sequence.to_bytes(4, "big")
    data[14:] = body
    data[4:6] = len(data).to_bytes(2, "big")
    return bytes(data)


def _type9_payload(plaintext: bytes, selector: int, key_index: int) -> bytes:
    cipher = type9_transform(
        plaintext, selector, KEYS[key_index], direction=1
    )
    record = (
        bytes([selector, key_index])
        + (zlib.crc32(plaintext) & 0xFFFFFFFF).to_bytes(4, "big")
        + len(cipher).to_bytes(2, "big")
        + cipher
    )
    return b"\x01\x0A\x00\x09" + b"\x00" * 10 + record


def _frame(
    plaintext: bytes,
    *,
    selector: int,
    key_index: int,
    account_id: str,
    report_index: int,
) -> bytes:
    account = account_id.encode("ascii")
    logical = (
        b"\x00" * 5
        + b"\x01\x0A\x00\x23"
        + report_index.to_bytes(4, "big")
        + b"\x00" * 10
        + bytes([len(account)])
        + account
        + b"\x00"
        + _type9_payload(plaintext, selector, key_index)
    )
    frame = bytearray(55)
    frame[0:3] = b"\x01\x00\x00"
    frame[8:10] = report_index.to_bytes(2, "big")
    frame[36:38] = report_index.to_bytes(2, "big")
    frame[38:40] = (1).to_bytes(2, "big")
    frame[40:44] = (zlib.crc32(logical) & 0xFFFFFFFF).to_bytes(4, "big")
    frame[44] = 1
    frame[45:47] = (9).to_bytes(2, "big")
    frame[47] = 0x2B
    frame[49:51] = (1).to_bytes(2, "big")
    frame[51:55] = len(logical).to_bytes(4, "big")
    frame += logical
    frame[3:5] = len(frame).to_bytes(2, "big")
    return bytes(frame)


class Type9OnlineTests(unittest.TestCase):
    def test_v1232_device_sensitive_template_blocks_cross_device_mix(self):
        recorded_leaf = _leaf_with_body(10, 0x1008, 0x11, length=64)
        live_leaf = _leaf_with_body(91, 0x1008, 0xA5, length=64)
        rows = template_leaf_rows(
            _type9_payload(recorded_leaf, selector=0, key_index=2),
            pool_idx=0,
        )["rows"]
        for row in rows:
            row["device_context"] = {
                "model": "iPhone18,2",
                "system_version": "26.5.1",
            }

        rebuilt = build_shadow_logical(
            _type9_payload(live_leaf, selector=1, key_index=3),
            rows,
            special_rule_store=_OneHotRule(0x1008),
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.6",
            },
        )

        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        self.assertEqual(decoded["leaves"][0]["raw"], live_leaf)
        self.assertEqual(rebuilt["device_context_pass_live_leaves"], 1)
        result = rebuilt["leaf_results"][0]
        self.assertTrue(result["device_context_mismatch"])
        self.assertEqual(
            result["replacement_level"], "DEVICE_CONTEXT_PASS_LIVE"
        )

    def test_v1232_device_sensitive_template_allows_same_device(self):
        recorded_leaf = _leaf_with_body(10, 0x1008, 0x11, length=64)
        live_leaf = _leaf_with_body(91, 0x1008, 0xA5, length=64)
        rows = template_leaf_rows(
            _type9_payload(recorded_leaf, selector=0, key_index=2),
            pool_idx=0,
        )["rows"]
        for row in rows:
            row["device_context"] = {
                "model": "iPad13,4",
                "system_version": "14.6",
            }

        rebuilt = build_shadow_logical(
            _type9_payload(live_leaf, selector=1, key_index=3),
            rows,
            special_rule_store=_OneHotRule(0x1008),
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.6",
            },
        )

        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        out = decoded["leaves"][0]["raw"]
        self.assertEqual(out[:14], live_leaf[:14])
        self.assertEqual(out[14:], recorded_leaf[14:])
        self.assertEqual(
            rebuilt["leaf_results"][0]["replacement_level"],
            "SPECIAL_REPLACE_TEMPLATE_NEAREST",
        )

    def test_v1232_device_sensitive_template_without_context_passes_live(self):
        recorded_leaf = _leaf_with_body(10, 0x100B, 0x11, length=64)
        live_leaf = _leaf_with_body(91, 0x100B, 0xA5, length=64)
        rows = template_leaf_rows(
            _type9_payload(recorded_leaf, selector=0, key_index=2),
            pool_idx=0,
        )["rows"]

        rebuilt = build_shadow_logical(
            _type9_payload(live_leaf, selector=1, key_index=3),
            rows,
            special_rule_store=_OneHotRule(0x100B),
        )

        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        self.assertEqual(decoded["leaves"][0]["raw"], live_leaf)
        self.assertEqual(rebuilt["device_context_pass_live_leaves"], 1)

    def test_v1232_recorded_device_mode_rewrites_identity_and_device_reports(self):
        recorded_identity = _telemetry_leaf(
            10,
            0x01122329,
            "model:iPhone18,2;ver:26.5.1;iDevHwModel:iPhone18,2;"
            "iDevSysVer:26.5.1;iDevIDFV:PHONE-IDFV;"
            "iDevRes:1320X2868;iAppVersion:1.2.3;"
            "iAppMachUUID:PHONE-MACH-UUID;inc_id:13;obf_id:13",
        )
        live_identity = _telemetry_leaf(
            90,
            0x01122329,
            "model:iPad13,4;ver:14.6;iDevHwModel:iPad13,4;"
            "iDevSysVer:14.6;iDevIDFV:IPAD-IDFV;"
            "iDevRes:1668X2388;iAppVersion:1.2.3;"
            "iAppMachUUID:PHONE-MACH-UUID;inc_id:13;obf_id:13",
        )
        recorded_100b = _leaf_with_body(11, 0x100B, 0x11, length=90)
        live_100b = _leaf_with_body(91, 0x100B, 0xA5, length=123)
        rows = template_leaf_rows(
            _type9_payload(
                _batch(9, [recorded_identity, recorded_100b]),
                selector=0,
                key_index=2,
            ),
            pool_idx=0,
        )["rows"]
        recorded_context = {
            "model": "iPhone18,2",
            "hardware_model": "iPhone18,2",
            "system_version": "26.5.1",
            "device_idfv": "PHONE-IDFV",
            "device_resolution": "1320X2868",
            "app_version": "1.2.3",
            "app_mach_uuid": "PHONE-MACH-UUID",
        }
        for row in rows:
            row["device_context"] = dict(recorded_context)
            row["template_session_id"] = "phone-session"

        rebuilt = build_shadow_logical(
            _type9_payload(
                _batch(89, [live_identity, live_100b]),
                selector=1,
                key_index=3,
            ),
            rows,
            special_rule_store=NO_HOT_RULES,
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.6",
            },
            device_mode="replace_recorded",
            recorded_device_context=recorded_context,
            recorded_template_session_id="phone-session",
        )

        self.assertTrue(rebuilt["generated"])
        self.assertEqual(rebuilt["device_mode"], "replace_recorded")
        self.assertGreaterEqual(
            rebuilt["recorded_device_profile_rewritten_leaves"], 1
        )
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        identity = decoded["leaves"][0]["raw"]
        self.assertIn(b"model:iPhone18,2", identity)
        self.assertIn(b"iDevHwModel:iPhone18,2", identity)
        self.assertIn(b"iDevSysVer:26.5.1", identity)
        self.assertIn(b"iDevIDFV:PHONE-IDFV", identity)
        self.assertIn(b"iDevRes:1320X2868", identity)
        self.assertNotIn(b"iPad13,4", identity)
        self.assertIn(b"inc_id:13;obf_id:13", identity)
        kept_100b = decoded["leaves"][1]["raw"]
        self.assertEqual(kept_100b, live_100b)
        self.assertEqual(
            rebuilt["leaf_results"][1]["replacement_level"],
            "UNMATCHED_LEAF_PASS_LIVE",
        )

    def test_v1232_recorded_device_mode_is_pinned_for_connection(self):
        recorded = [
            _frame(
                _batch(
                    9,
                    [
                        _telemetry_leaf(
                            10,
                            0x01122329,
                            "model:iPhone18,2;ver:26.5.1;"
                            "iDevHwModel:iPhone18,2;iDevSysVer:26.5.1;"
                            "inc_id:13;obf_id:13",
                        ),
                        _leaf_with_body(11, 0x100B, 0x11, length=90),
                    ],
                ),
                selector=0,
                key_index=2,
                account_id="GAME-42",
                report_index=1,
            )
        ]
        live = [
            _frame(
                _batch(
                    89,
                    [
                        _telemetry_leaf(
                            90,
                            0x01122329,
                            "model:iPad13,4;ver:14.6;"
                            "iDevHwModel:iPad13,4;iDevSysVer:14.6;"
                            "inc_id:13;obf_id:13",
                        ),
                        _leaf_with_body(91, 0x100B, 0xA5, length=123),
                    ],
                ),
                selector=1,
                key_index=3,
                account_id="GAME-42",
                report_index=2,
            )
        ]
        item = _ace_try_extract_frames(recorded)
        item["template_scope"] = "player"
        item["template_session_id"] = "phone-session"
        cursor = [0, 0]
        logs = []

        output, changed = _ace_try_replay_template(
            live,
            [item],
            cursor,
            expected_game_id="GAME-42",
            device_mode="replace_recorded",
            on_log=logs.append,
        )

        self.assertTrue(changed)
        self.assertNotEqual(output, live)
        self.assertEqual(cursor[2]["device_mode"], "replace_recorded")
        self.assertEqual(
            cursor[2]["recorded_template_session_id"], "phone-session"
        )
        self.assertEqual(
            logs[0]["shadow_rebuild"]["device_mode"], "replace_recorded"
        )
        self.assertEqual(
            logs[0]["shadow_rebuild"]["recorded_device_context"]["model"],
            "iPhone18,2",
        )

        # 同一连接后续即使外部配置切换，也保持首次锁定的设备模式。
        logs.clear()
        _ace_try_replay_template(
            live,
            [item],
            cursor,
            expected_game_id="GAME-42",
            device_mode="inherit_live",
            on_log=logs.append,
        )
        self.assertEqual(
            logs[0]["shadow_rebuild"]["device_mode"], "replace_recorded"
        )

    def test_v1232_recorded_device_mode_keeps_one_session_with_multi_device_pool(self):
        def recorded_item(
            session_id: str,
            model: str,
            system_version: str,
            body_fill: int,
            report_index: int,
        ):
            frames = [
                _frame(
                    _batch(
                        report_index,
                        [
                            _telemetry_leaf(
                                report_index + 1,
                                0x01122329,
                                f"model:{model};ver:{system_version};"
                                f"iDevHwModel:{model};"
                                f"iDevSysVer:{system_version};"
                                "inc_id:13;obf_id:13",
                            ),
                            _leaf_with_body(
                                report_index + 2,
                                0x100B,
                                body_fill,
                                length=90,
                            ),
                        ],
                    ),
                    selector=0,
                    key_index=2,
                    account_id="GAME-42",
                    report_index=report_index,
                )
            ]
            item = _ace_try_extract_frames(frames)
            item["template_scope"] = "player"
            item["template_session_id"] = session_id
            return item

        first = recorded_item(
            "phone-newest", "iPhone18,2", "26.5.1", 0x11, 1
        )
        second = recorded_item(
            "phone-older", "iPhone15,2", "18.6", 0x22, 2
        )
        live = [
            _frame(
                _batch(
                    89,
                    [
                        _telemetry_leaf(
                            90,
                            0x01122329,
                            "model:iPad13,4;ver:14.6;"
                            "iDevHwModel:iPad13,4;iDevSysVer:14.6;"
                            "inc_id:13;obf_id:13",
                        ),
                        _leaf_with_body(91, 0x100B, 0xA5, length=123),
                    ],
                ),
                selector=1,
                key_index=3,
                account_id="GAME-42",
                report_index=3,
            )
        ]
        cursor = [0, 0]
        logs = []

        output, changed = _ace_try_replay_template(
            live,
            [first, second],
            cursor,
            expected_game_id="GAME-42",
            device_mode="replace_recorded",
            special_rule_store=NO_HOT_RULES,
            on_log=logs.append,
        )

        self.assertTrue(changed)
        self.assertEqual(
            cursor[2]["recorded_template_session_id"], "phone-newest"
        )
        assembled = _ace_01_reassemble_frames(output)
        decoded = decode_material(assembled[1])
        self.assertTrue(decoded["ok"])
        joined = b"\n".join(row["raw"] for row in decoded["leaves"])
        self.assertIn(b"iPhone18,2", joined)
        self.assertNotIn(b"iPhone15,2", joined)
        kept_100b = decoded["leaves"][1]["raw"]
        live_100b = _leaf_with_body(91, 0x100B, 0xA5, length=123)
        self.assertEqual(kept_100b[14:], live_100b[14:])
        self.assertEqual(len(kept_100b), 123)
        self.assertEqual(
            logs[0]["shadow_rebuild"]["recorded_device_context"]["model"],
            "iPhone18,2",
        )

    def test_v1232_tfp_called_uses_clean_semantic_slot_and_live_device(self):
        recorded_leaf = _telemetry_leaf(
            13,
            0x01122329,
            "model:iPhone18,2;ver:26.50;inc_id:13;obf_id:13",
        )
        live_leaf = _telemetry_leaf(
            913,
            0x0112233B,
            "model:iPad13,4;ver:14.60;inc_id:13;obf_id:13;tfp_called",
        )
        rows = template_leaf_rows(
            _type9_payload(
                _batch(10, [recorded_leaf]), selector=0, key_index=2
            ),
            pool_idx=0,
        )["rows"]

        rebuilt = build_shadow_logical(
            _type9_payload(
                _batch(900, [live_leaf]), selector=1, key_index=3
            ),
            rows,
            special_rule_store=NO_HOT_RULES,
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.60",
            },
        )

        self.assertTrue(rebuilt["generated"])
        self.assertEqual(rebuilt["cross_record_replaced_leaves"], 1)
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        self.assertEqual(decoded["root"]["child_count_declared"], 1)
        out = decoded["leaves"][0]
        self.assertEqual(out["record_code"], 0x01122329)
        self.assertEqual(out["record_sequence"], 913)
        self.assertIn(b"model:iPad13,4;ver:14.60", out["raw"])
        self.assertNotIn(b"iPhone18,2", out["raw"])
        self.assertNotIn(b"tfp_called", out["raw"])
        self.assertEqual(
            rebuilt["leaf_results"][0]["replacement_level"],
            "CROSS_RECORD_SLOT_REPLACE",
        )

    def test_v1232_tfp_called_on_1122329_uses_nearest_clean_slot(self):
        recorded_leaf = _telemetry_leaf(
            21,
            0x01122329,
            "model:iPhone18,2;ver:26.50;inc_id:13;obf_id:13",
        )
        live_leaf = _telemetry_leaf(
            924,
            0x01122329,
            "model:iPad13,4;ver:14.60;inc_id:14;obf_id:14;tfp_called",
        )
        rows = template_leaf_rows(
            _type9_payload(
                _batch(10, [recorded_leaf]), selector=0, key_index=2
            ),
            pool_idx=0,
        )["rows"]

        rebuilt = build_shadow_logical(
            _type9_payload(
                _batch(900, [live_leaf]), selector=1, key_index=3
            ),
            rows,
            special_rule_store=NO_HOT_RULES,
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.60",
            },
        )

        self.assertTrue(rebuilt["generated"])
        self.assertEqual(rebuilt["cross_record_replaced_leaves"], 1)
        self.assertTrue(rebuilt["roundtrip_ok"])
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        out = decoded["leaves"][0]
        self.assertEqual(out["record_code"], 0x01122329)
        self.assertEqual(out["record_sequence"], 924)
        self.assertIn(
            b"model:iPad13,4;ver:14.60;inc_id:14;obf_id:14",
            out["raw"],
        )
        self.assertNotIn(b"iPhone18,2", out["raw"])
        self.assertNotIn(b"tfp_called", out["raw"])
        result = rebuilt["leaf_results"][0]
        self.assertEqual(
            result["replacement_level"], "CROSS_RECORD_SLOT_REPLACE"
        )
        self.assertEqual(
            result["cross_slot_match_mode"],
            "nearest_clean_runtime_slot",
        )
        self.assertEqual(
            {row["field"] for row in result["runtime_field_rewrites"]},
            {"inc_id", "obf_id"},
        )

    def test_v1233_tfp_called_without_template_uses_structured_remove(self):
        body = (
            b"model:iPad13,4;ver:14.60;inc_id:14;obf_id:14\x00"
            + bytes.fromhex("0000000001000000000B")
            + b"tfp_called"
            + b"\x00" * 32
        )
        encoded_leaf = bytearray(14 + len(body))
        encoded_leaf[0:4] = (1).to_bytes(4, "big")
        encoded_leaf[6:10] = (0x01122329).to_bytes(4, "big")
        encoded_leaf[10:14] = (924).to_bytes(4, "big")
        encoded_leaf[14:] = body
        encoded_leaf[4:6] = len(encoded_leaf).to_bytes(2, "big")
        live_leaf = bytes(encoded_leaf)

        rebuilt = build_shadow_logical(
            _type9_payload(
                _batch(900, [live_leaf]), selector=1, key_index=3
            ),
            [],
            special_rule_store=NO_HOT_RULES,
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.60",
            },
        )

        self.assertTrue(rebuilt["generated"])
        self.assertTrue(rebuilt["roundtrip_ok"])
        self.assertEqual(
            rebuilt["tfp_called_structured_removed_leaves"], 1
        )
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        out = decoded["leaves"][0]
        self.assertEqual(out["record_code"], 0x01122329)
        self.assertEqual(out["record_sequence"], 924)
        self.assertEqual(len(out["raw"]), len(live_leaf) - 20)
        self.assertIn(
            b"model:iPad13,4;ver:14.60;inc_id:14;obf_id:14",
            out["raw"],
        )
        self.assertNotIn(b"tfp_called", out["raw"])
        result = rebuilt["leaf_results"][0]
        self.assertEqual(
            result["replacement_level"],
            "TFP_CALLED_STRUCTURED_REMOVE",
        )
        self.assertEqual(
            result["cross_slot_match_mode"],
            "structured_remove_fallback",
        )
        self.assertEqual(
            result["tfp_called_remove_info"]["removed_length"], 20
        )

    def test_v124_confirmed_1122358_uses_clean_template(self):
        recorded_leaf = _telemetry_leaf(
            23,
            0x01122358,
            "model:iPad13,4;ver:14.60;inc_id:13;obf_id:13",
        )
        live_leaf = _telemetry_leaf(
            923,
            0x01122358,
            "model:iPad13,4;ver:14.60;inc_id:13;obf_id:13;tfp_called",
        )
        rows = template_leaf_rows(
            _type9_payload(
                _batch(10, [recorded_leaf]), selector=0, key_index=2
            ),
            pool_idx=0,
        )["rows"]

        rebuilt = build_shadow_logical(
            _type9_payload(
                _batch(900, [live_leaf]), selector=1, key_index=3
            ),
            rows,
            special_rule_store=NO_HOT_RULES,
            live_device_context={
                "model": "iPad13,4",
                "system_version": "14.60",
            },
        )

        self.assertTrue(rebuilt["generated"])
        self.assertEqual(rebuilt["tfp_called_detected_leaves"], 1)
        self.assertEqual(rebuilt["tfp_called_template_replaced_leaves"], 1)
        self.assertEqual(rebuilt["tfp_called_residual_leaves"], 0)
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        out = decoded["leaves"][0]
        self.assertEqual(out["record_code"], 0x01122358)
        self.assertEqual(out["record_sequence"], 923)
        self.assertNotIn(b"tfp_called", out["raw"])
        result = rebuilt["leaf_results"][0]
        self.assertEqual(
            result["tfp_called_rule_id"],
            "1122358-tfp-called-clean-slot",
        )
        self.assertEqual(
            result["tfp_called_action"], "CLEAN_TEMPLATE_REPLACE"
        )
        self.assertFalse(
            result["tfp_called_replacement"]["candidate_marker_present"]
        )

    def test_v124_unseen_record_code_uses_generic_clean_template(self):
        recorded_leaf = _telemetry_leaf(
            23,
            0x01122399,
            "model:iPad13,4;ver:14.60;inc_id:13;obf_id:13",
        )
        live_leaf = _telemetry_leaf(
            923,
            0x01122399,
            "model:iPad13,4;ver:14.60;inc_id:13;obf_id:13;tfp_called",
        )
        rows = template_leaf_rows(
            _type9_payload(
                _batch(10, [recorded_leaf]), selector=0, key_index=2
            ),
            pool_idx=0,
        )["rows"]

        rebuilt = build_shadow_logical(
            _type9_payload(
                _batch(900, [live_leaf]), selector=1, key_index=3
            ),
            rows,
            special_rule_store=NO_HOT_RULES,
        )

        self.assertTrue(rebuilt["generated"])
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        self.assertNotIn(b"tfp_called", decoded["leaves"][0]["raw"])
        self.assertEqual(
            rebuilt["leaf_results"][0]["tfp_called_rule_id"],
            "v124-tfp-called-any-record-clean-slot",
        )

    def test_v124_tfp_called_on_new_record_without_template_removes_field(self):
        body = (
            b"model:iPad13,4;ver:14.60;inc_id:13;obf_id:13\x00"
            + bytes.fromhex("0000000001000000000B")
            + b"tfp_called"
            + b"\x00" * 32
        )
        encoded_leaf = bytearray(14 + len(body))
        encoded_leaf[0:4] = (1).to_bytes(4, "big")
        encoded_leaf[6:10] = (0x01122358).to_bytes(4, "big")
        encoded_leaf[10:14] = (923).to_bytes(4, "big")
        encoded_leaf[14:] = body
        encoded_leaf[4:6] = len(encoded_leaf).to_bytes(2, "big")
        live_leaf = bytes(encoded_leaf)

        rebuilt = build_shadow_logical(
            _type9_payload(
                _batch(900, [live_leaf]), selector=1, key_index=3
            ),
            [],
            special_rule_store=NO_HOT_RULES,
        )

        self.assertTrue(rebuilt["generated"])
        self.assertEqual(rebuilt["tfp_called_detected_leaves"], 1)
        self.assertEqual(rebuilt["tfp_called_structured_removed_leaves"], 1)
        self.assertEqual(rebuilt["tfp_called_residual_leaves"], 0)
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        out = decoded["leaves"][0]
        self.assertEqual(out["record_code"], 0x01122358)
        self.assertEqual(len(out["raw"]), len(live_leaf) - 20)
        self.assertNotIn(b"tfp_called", out["raw"])
        result = rebuilt["leaf_results"][0]
        self.assertEqual(
            result["tfp_called_rule_id"],
            "v124-tfp-called-no-template-structured-remove",
        )
        self.assertEqual(
            result["tfp_called_action"], "STRUCTURED_FIELD_REMOVE"
        )

    def test_v124_tfp_called_unknown_layout_uses_zero_marker_fallback(self):
        live_leaf = _telemetry_leaf(
            923,
            0x01122399,
            "model:iPad13,4;ver:14.60;inc_id:13;obf_id:13;tfp_called",
        )

        rebuilt = build_shadow_logical(
            _type9_payload(
                _batch(900, [live_leaf]), selector=1, key_index=3
            ),
            [],
            special_rule_store=NO_HOT_RULES,
        )

        self.assertTrue(rebuilt["generated"])
        self.assertEqual(rebuilt["tfp_called_detected_leaves"], 1)
        self.assertEqual(rebuilt["tfp_called_zeroed_leaves"], 1)
        self.assertEqual(rebuilt["tfp_called_residual_leaves"], 0)
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        out = decoded["leaves"][0]
        self.assertEqual(len(out["raw"]), len(live_leaf))
        self.assertNotIn(b"tfp_called", out["raw"])
        result = rebuilt["leaf_results"][0]
        self.assertEqual(
            result["replacement_level"], "TFP_CALLED_ZERO_MARKER"
        )
        self.assertEqual(
            result["tfp_called_rule_id"],
            "v124-tfp-called-unknown-layout-zero-marker",
        )
        self.assertEqual(result["tfp_called_action"], "ZERO_MARKER")

    def test_v1233_tfp_structured_remove_passes_full_01_crc_gate(self):
        type9_hot_rule_store.clear_changed_counts()
        body = (
            b"model:iPad13,4;ver:14.60;inc_id:14;obf_id:14\x00"
            + bytes.fromhex("0000000001000000000B")
            + b"tfp_called"
            + b"\x00" * 32
        )
        encoded_leaf = bytearray(14 + len(body))
        encoded_leaf[0:4] = (1).to_bytes(4, "big")
        encoded_leaf[6:10] = (0x01122329).to_bytes(4, "big")
        encoded_leaf[10:14] = (924).to_bytes(4, "big")
        encoded_leaf[14:] = body
        encoded_leaf[4:6] = len(encoded_leaf).to_bytes(2, "big")
        live = [
            _frame(
                _batch(900, [bytes(encoded_leaf)]),
                selector=1,
                key_index=3,
                account_id="GAME-42",
                report_index=900,
            )
        ]
        recorded = [
            _frame(
                _batch(
                    10,
                    [
                        _telemetry_leaf(
                            11,
                            0x01122342,
                            "model:iPhone18,2;ver:26.50;"
                            "inc_id:13;obf_id:13",
                        )
                    ],
                ),
                selector=0,
                key_index=2,
                account_id="GAME-42",
                report_index=10,
            )
        ]
        item = _ace_try_extract_frames(recorded)
        logs = []

        output, changed = _ace_try_replay_template(
            live,
            [item],
            [0, 0],
            expected_game_id="GAME-42",
            device_mode="inherit_live",
            on_log=logs.append,
        )

        self.assertTrue(changed)
        self.assertEqual(logs[0]["decision"], "REPLACE")
        self.assertEqual(
            logs[0]["replacement_level"],
            "TFP_CALLED_STRUCTURED_REMOVE",
        )
        self.assertEqual(
            logs[0]["reason"],
            "TFP_CALLED_NO_TEMPLATE_STRUCTURED_REMOVE",
        )
        self.assertTrue(logs[0]["validation_ok"])
        self.assertTrue(logs[0]["shadow_rebuild"]["checks"]["outer_crc_ok"])
        assembled = _ace_01_reassemble_frames(output)
        self.assertIsNotNone(assembled)
        decoded = decode_material(assembled[1])
        self.assertTrue(decoded["ok"])
        self.assertNotIn(b"tfp_called", decoded["leaves"][0]["raw"])
        counts = type9_hot_rule_store.snapshot()["rule_changed_counts"]
        self.assertEqual(
            counts.get("v124-tfp-called-no-template-structured-remove"), 1
        )
        type9_hot_rule_store.clear_changed_counts()

    def test_v118_retains_opt_in_prune_experiment_implementation(self):
        clean_plain = _batch(10, [_leaf(11, 0x8023)])
        live_plain = _batch(90, [_leaf(91, 0x8023), _leaf(92, 0x8024)])
        rows = template_leaf_rows(
            _type9_payload(clean_plain, selector=0, key_index=2),
            pool_idx=0,
        )
        self.assertTrue(rows["ok"])

        rebuilt = build_shadow_logical(
            _type9_payload(live_plain, selector=1, key_index=3),
            rows["rows"],
            prune_unmatched=True,
        )

        self.assertTrue(rebuilt["generated"])
        self.assertEqual(rebuilt["pruned_leaves"], 1)
        self.assertEqual(rebuilt["candidate_plaintext"], _leaf(91, 0x8023))
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        self.assertEqual(decoded["root"]["record_code"], BINARY_CODE)
        self.assertEqual(decoded["root"]["message_id"], 0x8023)
        self.assertEqual(decoded["leaves"][0].get("path"), [])
        self.assertEqual(
            [leaf["message_id"] for leaf in decoded["leaves"]],
            [0x8023],
        )

    def test_v118_special_unknown_handler_is_exact_and_same_length(self):
        live_leaf = _leaf_with_body(91, 0x9001, 0x77)

        def replace_last_byte(raw, _leaf_meta):
            return raw[:-1] + b"\x33"

        rebuilt = build_shadow_logical(
            _type9_payload(
                _batch(90, [live_leaf]), selector=1, key_index=3
            ),
            [],
            special_handlers={
                (BINARY_CODE, 0x9001, len(live_leaf)): (
                    "test-9001",
                    replace_last_byte,
                )
            },
        )

        self.assertTrue(rebuilt["generated"])
        self.assertEqual(rebuilt["pruned_leaves"], 0)
        self.assertEqual(rebuilt["unmatched_pass_live_leaves"], 0)
        self.assertEqual(rebuilt["special_handled_leaves"], 1)
        self.assertEqual(rebuilt["special_changed_leaves"], 1)
        decoded = decode_material(rebuilt["candidate_logical"])
        self.assertTrue(decoded["ok"])
        self.assertEqual(decoded["leaves"][0]["raw"][-1], 0x33)
        self.assertEqual(
            rebuilt["leaf_results"][0]["special_rule_id"], "test-9001"
        )

    def test_cross_account_replay_uses_donor_clean_leaf_and_live_account(self):
        donor_id = "DONOR-01"
        live_id = "LIVE---1"
        clean = [
            _frame(
                _batch(10, [_leaf_with_clean_value(11, 0x1002, 0x11223344)]),
                selector=0,
                key_index=2,
                account_id=donor_id,
                report_index=1,
            )
        ]
        live = [
            _frame(
                _batch(90, [_leaf_with_clean_value(91, 0x1002, 0xAABBCCDD)]),
                selector=2,
                key_index=8,
                account_id=live_id,
                report_index=9,
            )
        ]
        item = _ace_try_extract_frames(clean)
        self.assertIsNotNone(item)
        logs = []

        output, changed = _ace_try_replay_template(
            live,
            [item],
            [0, 0],
            expected_game_id=live_id,
            allow_cross_account=True,
            donor_game_id=donor_id,
            on_log=logs.append,
        )

        self.assertTrue(changed)
        self.assertEqual(logs[0]["decision"], "REPLACE")
        self.assertTrue(logs[0]["cross_account"])
        self.assertEqual(logs[0]["live_game_id"], live_id)
        self.assertEqual(logs[0]["donor_game_id"], donor_id)
        self.assertTrue(logs[0]["final_identity_check"])
        assembled = _ace_01_reassemble_frames(output)
        self.assertIsNotNone(assembled)
        decoded = decode_material(assembled[1])
        self.assertTrue(decoded["ok"])
        self.assertEqual(decoded["leaves"][0]["record_sequence"], 91)
        self.assertEqual(
            decoded["leaves"][0]["raw"][32:36],
            bytes.fromhex("11223344"),
        )

    def test_cross_account_leaf_rewrites_exact_donor_identity(self):
        donor_id = "DONOR001"
        live_id = "LIVE0001"
        clean_leaf = bytearray(_leaf_with_body(11, 0x8123, 0x31, length=56))
        live_leaf = bytearray(_leaf_with_body(91, 0x8123, 0xA1, length=56))
        clean_leaf[32:40] = donor_id.encode("ascii")
        live_leaf[32:40] = live_id.encode("ascii")
        rows = template_leaf_rows(
            _type9_payload(bytes(clean_leaf), selector=0, key_index=2),
            pool_idx=3,
        )
        self.assertTrue(rows["ok"])
        for row in rows["rows"]:
            row["donor_game_id"] = donor_id

        shadow = build_shadow_logical(
            _type9_payload(bytes(live_leaf), selector=2, key_index=8),
            rows["rows"],
            cross_account=True,
            live_game_id=live_id,
            donor_game_id=donor_id,
        )

        self.assertTrue(shadow["generated"])
        self.assertEqual(shadow["identity_rewrite_count"], 1)
        rebuilt = decode_material(shadow["candidate_logical"])
        self.assertTrue(rebuilt["ok"])
        candidate = rebuilt["leaves"][0]["raw"]
        self.assertIn(live_id.encode("ascii"), candidate)
        self.assertNotIn(donor_id.encode("ascii"), candidate)
        leaf_log = shadow["leaf_results"][0]
        self.assertEqual(leaf_log["identity_rewrite"]["status"], "REWRITTEN")
        self.assertEqual(len(leaf_log["identity_rewrite_ranges"]), 1)

    def test_cross_account_identity_context_mismatch_keeps_live_leaf(self):
        donor_id = "DONOR001"
        live_id = "LIVE0001"
        clean_leaf = bytearray(_leaf_with_body(11, 0x8123, 0x31, length=56))
        live_leaf = bytearray(_leaf_with_body(91, 0x8123, 0xA1, length=56))
        clean_leaf[32:40] = donor_id.encode("ascii")
        rows = template_leaf_rows(
            _type9_payload(bytes(clean_leaf), selector=0, key_index=2),
            pool_idx=3,
        )
        for row in rows["rows"]:
            row["donor_game_id"] = donor_id

        shadow = build_shadow_logical(
            _type9_payload(bytes(live_leaf), selector=2, key_index=8),
            rows["rows"],
            cross_account=True,
            live_game_id=live_id,
            donor_game_id=donor_id,
        )

        self.assertTrue(shadow["generated"])
        self.assertEqual(shadow["changed_leaves"], 0)
        self.assertEqual(shadow["identity_blocked_leaves"], 1)
        leaf_log = shadow["leaf_results"][0]
        self.assertEqual(leaf_log["block_reason"], "CROSS_ACCOUNT_IDENTITY_BLOCK")
        self.assertEqual(
            leaf_log["identity_rewrite"]["status"],
            "LIVE_ID_CONTEXT_MISMATCH",
        )

    def test_all_three_selectors_decrypt_and_validate_crc(self):
        plain = _batch(
            100,
            [_leaf(101, 0x8027), _leaf(102, 0x1005)],
        )
        for selector in (0, 1, 2):
            with self.subTest(selector=selector):
                decoded = decode_type9_payload(
                    _type9_payload(plain, selector, key_index=3)
                )
                self.assertTrue(decoded["parse_ok"])
                self.assertTrue(decoded["plain_crc_ok"])
                self.assertEqual(decoded["selector"], selector)
                self.assertEqual(decoded["top_record_code"], BATCH_CODE)
                self.assertEqual(decoded["child_count"], 2)
                self.assertEqual(decoded["leaf_sequences"], [101, 102])
                self.assertEqual(
                    [row["message_id"] for row in decoded["leaves"]],
                    [0x8027, 0x1005],
                )

    def test_batch_shape_mismatch_is_pass_live(self):
        live = decode_type9_payload(
            _type9_payload(
                _batch(200, [_leaf(201, 0x8027), _leaf(202, 0x1005)]),
                2,
                3,
            )
        )
        template = decode_type9_payload(
            _type9_payload(_leaf(100, 0x8027), 2, 3)
        )
        reason, facts = decide_observe_only(
            live, template, live_length=956, template_length=277
        )
        self.assertEqual(reason, "BATCH_SHAPE_MISMATCH")
        self.assertFalse(facts["batch_shape_match"])

    def test_v118_ignores_legacy_prune_config_and_keeps_unknown_live(self):
        template = [
            _frame(
                _leaf(262, 0x8027),
                selector=2,
                key_index=3,
                account_id="GAME-42",
                report_index=84,
            )
        ]
        live = [
            _frame(
                _batch(
                    270,
                    [_leaf(271, 0x8027), _leaf(272, 0x1005)],
                ),
                selector=2,
                key_index=3,
                account_id="GAME-42",
                report_index=84,
            )
        ]
        item = _ace_try_extract_frames(template)
        self.assertIsNotNone(item)
        cursor = [0, 0]
        logs = []

        old_values = {
            key: app_config.get(key)
            for key in (
                "v117_unmatched_leaf_policy",
                "v117_leaf_prune_experiment_enabled",
                "v118_unknown_leaf_policy",
                "v118_leaf_prune_experiment_enabled",
            )
        }
        try:
            app_config.set("v117_unmatched_leaf_policy", "prune")
            app_config.set("v117_leaf_prune_experiment_enabled", True)
            app_config.set("v118_unknown_leaf_policy", "pass_live")
            app_config.set("v118_leaf_prune_experiment_enabled", False)
            output, changed = _ace_try_replay_template(
                live,
                [item],
                cursor,
                expected_game_id="GAME-42",
                special_rule_store=_OneHotRule(0x8027),
                on_log=logs.append,
            )
        finally:
            for key, value in old_values.items():
                app_config.set(key, value)

        self.assertFalse(changed)
        self.assertEqual(output, live)
        self.assertEqual(cursor[0], 1)
        self.assertEqual(logs[0]["decision"], "PASS_LIVE")
        self.assertEqual(
            logs[0]["reason"], "DEVICE_CONTEXT_MISMATCH_PASS_LIVE"
        )
        self.assertTrue(logs[0]["final_equals_live"])
        self.assertEqual(logs[0]["shadow_rebuild"]["pruned_leaves"], 0)
        self.assertEqual(
            logs[0]["shadow_rebuild"]["device_context_pass_live_leaves"], 1
        )
        self.assertEqual(
            logs[0]["online_decode"]["live"]["leaf_sequences"],
            [271, 272],
        )

    def test_leaf_shadow_rebuild_keeps_unmapped_bodies_and_live_sequences(self):
        clean_plain = _batch(
            10,
            [
                _leaf_with_body(11, 0x8027, 0x31),
                _leaf_with_body(12, 0x1005, 0x32),
            ],
        )
        live_plain = _batch(
            99,
            [
                _leaf_with_body(100, 0x8027, 0xA1),
                _leaf_with_body(101, 0x1005, 0xA2),
            ],
        )
        rows = template_leaf_rows(
            _type9_payload(clean_plain, selector=0, key_index=2), pool_idx=7
        )
        self.assertTrue(rows["ok"])

        shadow = build_shadow_logical(
            _type9_payload(live_plain, selector=2, key_index=8),
            rows["rows"],
            special_rule_store=NO_HOT_RULES,
        )

        self.assertTrue(shadow["generated"])
        self.assertTrue(shadow["roundtrip_ok"])
        self.assertEqual(shadow["matched_leaves"], 2)
        self.assertEqual(shadow["coverage"], 1.0)
        rebuilt = decode_material(shadow["candidate_logical"])
        self.assertTrue(rebuilt["ok"])
        self.assertEqual(
            [leaf["record_sequence"] for leaf in rebuilt["leaves"]],
            [100, 101],
        )
        self.assertEqual(rebuilt["leaves"][0]["raw"][14:22], bytes([0xA1]) * 8)
        self.assertEqual(rebuilt["leaves"][1]["raw"][14:22], bytes([0xA2]) * 8)
        self.assertEqual(shadow["changed_leaves"], 0)
        self.assertEqual(shadow["unmapped_pass_live_leaves"], 2)
        self.assertEqual(
            [row["template_pool_idx"] for row in shadow["leaf_results"]],
            [7, 7],
        )

    def test_replay_sends_verified_semantic_shadow_candidate(self):
        clean = [
            _frame(
                _batch(10, [_leaf_with_clean_value(11, 0x1002, 0x11223344)]),
                selector=0,
                key_index=2,
                account_id="GAME-42",
                report_index=1,
            )
        ]
        live = [
            _frame(
                _batch(300, [_leaf_with_clean_value(301, 0x1002, 0xAABBCCDD)]),
                selector=2,
                key_index=8,
                account_id="GAME-42",
                report_index=99,
            )
        ]
        item = _ace_try_extract_frames(clean)
        self.assertIsNotNone(item)
        logs = []

        output, changed = _ace_try_replay_template(
            live,
            [item],
            [0, 0],
            expected_game_id="GAME-42",
            on_log=logs.append,
        )

        self.assertTrue(changed)
        self.assertNotEqual(output, live)
        detail = logs[0]
        self.assertEqual(detail["decision"], "REPLACE")
        self.assertEqual(output, detail["shadow_frames"])
        self.assertFalse(detail["final_equals_live"])
        self.assertEqual(
            detail["shadow_rebuild"]["status"], "SEMANTIC_READY_FULL"
        )
        self.assertTrue(detail["shadow_rebuild"]["ready"])
        self.assertTrue(detail["shadow_rebuild"]["mechanical_ready"])
        self.assertNotEqual(detail["shadow_frames"], live)
        self.assertTrue(all(detail["shadow_rebuild"]["checks"].values()))
        shadow_decoded = detail["shadow_rebuild"]["decoded"]
        self.assertEqual(shadow_decoded["leaf_sequences"], [301])
        self.assertEqual(
            shadow_decoded["signature"],
            detail["online_decode"]["live"]["signature"],
        )
        output_decoded = decode_material(
            _ace_01_reassemble_frames(output)[1]
        )
        self.assertEqual(
            int.from_bytes(output_decoded["leaves"][0]["raw"][32:36], "big"),
            0x11223344,
        )

    def test_replay_sends_semantic_partial_and_keeps_unmatched_leaf_live(self):
        clean_leaf = _leaf_with_clean_value(11, 0x1002, 0x11223344)
        live_clean_leaf = _leaf_with_clean_value(301, 0x1002, 0xAABBCCDD)
        unmatched_leaf = _leaf_with_body(302, 0x9001, 0x77)
        clean = [
            _frame(
                _batch(10, [clean_leaf]),
                selector=0,
                key_index=2,
                account_id="GAME-42",
                report_index=1,
            )
        ]
        live = [
            _frame(
                _batch(300, [live_clean_leaf, unmatched_leaf]),
                selector=2,
                key_index=8,
                account_id="GAME-42",
                report_index=99,
            )
        ]
        item = _ace_try_extract_frames(clean)
        logs = []

        output, changed = _ace_try_replay_template(
            live,
            [item],
            [0, 0],
            expected_game_id="GAME-42",
            on_log=logs.append,
        )

        self.assertTrue(changed)
        self.assertEqual(logs[0]["decision"], "REPLACE")
        self.assertEqual(
            logs[0]["shadow_rebuild"]["status"],
            "SEMANTIC_READY_PARTIAL",
        )
        leaves = decode_material(
            _ace_01_reassemble_frames(output)[1]
        )["leaves"]
        self.assertEqual(int.from_bytes(leaves[0]["raw"][32:36], "big"), 0x11223344)
        self.assertEqual(len(leaves), 2)
        self.assertEqual(leaves[1]["raw"], unmatched_leaf)
        self.assertEqual(logs[0]["shadow_rebuild"]["pruned_leaves"], 0)
        self.assertEqual(
            logs[0]["shadow_rebuild"]["unmatched_pass_live_leaves"], 1
        )

    def test_semantic_counter_fields_are_inherited_from_live(self):
        clean_leaf = bytearray(
            _leaf_with_body(65, 0x100A, 0, length=68)
        )
        live_leaf = bytearray(
            _leaf_with_body(62, 0x100A, 0, length=68)
        )
        for offset, clean_value, live_value in (
            (32, 4, 1),
            (40, 4, 1),
            (44, 4, 1),
            (48, 3, 0),
            (64, 0x6A6CCB38, 0x6A6CCEC4),
        ):
            clean_leaf[offset:offset + 4] = clean_value.to_bytes(4, "big")
            live_leaf[offset:offset + 4] = live_value.to_bytes(4, "big")
        rows = template_leaf_rows(
            _type9_payload(bytes(clean_leaf), selector=0, key_index=2),
            pool_idx=4,
        )["rows"]

        shadow = build_shadow_logical(
            _type9_payload(bytes(live_leaf), selector=2, key_index=8), rows
        )

        self.assertTrue(shadow["generated"])
        self.assertEqual(shadow["semantic_unmapped_leaves"], 0)
        self.assertEqual(shadow["semantic_ready_leaves"], 1)
        rebuilt = decode_material(shadow["candidate_logical"])["leaves"][0]["raw"]
        for offset in (32, 40, 44, 48, 64):
            self.assertEqual(rebuilt[offset:offset + 4], live_leaf[offset:offset + 4])

    def test_semantic_subtype_selects_matching_clean_leaf(self):
        def typed_leaf(sequence: int, subtype: int, value: int) -> bytes:
            data = bytearray(
                _leaf_with_body(sequence, 0xFFF9, 0, length=41)
            )
            data[35] = subtype
            data[37:41] = value.to_bytes(4, "big")
            return bytes(data)

        rows = []
        for pool_idx, leaf in enumerate(
            [typed_leaf(10, 0x81, 0x11111111), typed_leaf(20, 0x89, 0x22222222)]
        ):
            rows.extend(
                template_leaf_rows(
                    _type9_payload(leaf, selector=0, key_index=2),
                    pool_idx=pool_idx,
                )["rows"]
            )
        live = typed_leaf(21, 0x89, 0xAAAAAAAA)

        shadow = build_shadow_logical(
            _type9_payload(live, selector=2, key_index=8), rows
        )

        leaf_result = shadow["leaf_results"][0]
        self.assertEqual(leaf_result["template_pool_idx"], 1)
        self.assertTrue(leaf_result["semantic_ready"])
        rebuilt = decode_material(shadow["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(rebuilt[35], 0x89)
        self.assertEqual(int.from_bytes(rebuilt[37:41], "big"), 0x22222222)

    def test_semantic_selection_uses_nearest_record_sequence(self):
        rows = []
        for pool_idx, leaf in enumerate(
            [
                _leaf_with_clean_value(10, 0x1002, 0x11111111),
                _leaf_with_clean_value(100, 0x1002, 0x22222222),
            ]
        ):
            rows.extend(
                template_leaf_rows(
                    _type9_payload(leaf, selector=0, key_index=2),
                    pool_idx=pool_idx,
                )["rows"]
            )

        shadow = build_shadow_logical(
            _type9_payload(
                _leaf_with_clean_value(90, 0x1002, 0xAAAAAAAA),
                selector=2,
                key_index=8,
            ),
            rows,
        )

        leaf_result = shadow["leaf_results"][0]
        self.assertEqual(leaf_result["template_sequence"], 100)
        self.assertEqual(leaf_result["sequence_distance"], 10)
        self.assertEqual(
            leaf_result["clean_field_values"][0]["template_hex"],
            "22222222",
        )

    def test_unmapped_body_difference_is_safely_kept_live(self):
        rows = template_leaf_rows(
            _type9_payload(
                _leaf_with_body(10, 0x9001, 0x11), selector=0, key_index=2
            ),
            pool_idx=0,
        )["rows"]

        shadow = build_shadow_logical(
            _type9_payload(
                _leaf_with_body(11, 0x9001, 0x22), selector=2, key_index=8
            ),
            rows,
        )

        self.assertTrue(shadow["generated"])
        self.assertEqual(shadow["semantic_ready_leaves"], 1)
        self.assertEqual(shadow["semantic_unmapped_leaves"], 0)
        self.assertEqual(shadow["unmapped_pass_live_leaves"], 1)
        result = shadow["leaf_results"][0]
        self.assertTrue(result["unknown_diff_offsets"])
        self.assertEqual(result["replacement_level"], "UNMAPPED_BODY_PASS_LIVE")
        self.assertEqual(result["block_reason"], "UNMAPPED_BODY_PASS_LIVE")
        self.assertEqual(result["candidate_hex"], result["live_hex"])
        self.assertNotEqual(
            result["shadow_only_candidate_hex"], result["candidate_hex"]
        )

    def test_unmapped_template_never_changes_live_device_identity(self):
        recorded_leaf = bytearray(
            _leaf_with_body(10, 0x0000, 0, length=128)
        )
        live_leaf = bytearray(
            _leaf_with_body(11, 0x0000, 0, length=128)
        )
        record_code = 0x01122342
        recorded_leaf[6:10] = record_code.to_bytes(4, "big")
        live_leaf[6:10] = record_code.to_bytes(4, "big")
        recorded_identity = b"model:iPhone18,2;ver:26.50;inc_id:25;obf_id:25"
        live_identity = b"model:iPad13,4;ver:14.60;inc_id:67;obf_id:67"
        recorded_leaf[32:32 + len(recorded_identity)] = recorded_identity
        live_leaf[32:32 + len(live_identity)] = live_identity
        rows = template_leaf_rows(
            _type9_payload(bytes(recorded_leaf), selector=0, key_index=2),
            pool_idx=0,
        )["rows"]

        shadow = build_shadow_logical(
            _type9_payload(bytes(live_leaf), selector=2, key_index=8),
            rows,
            special_rule_store=NO_HOT_RULES,
        )

        self.assertTrue(shadow["generated"])
        self.assertTrue(shadow["roundtrip_ok"])
        self.assertEqual(shadow["changed_leaves"], 0)
        self.assertEqual(shadow["unmapped_pass_live_leaves"], 1)
        rebuilt = decode_material(shadow["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(rebuilt, bytes(live_leaf))
        self.assertIn(b"model:iPad13,4", rebuilt)
        self.assertNotIn(b"model:iPhone18,2", rebuilt)

    def test_replay_keeps_unmapped_unknown_body_live(self):
        recorded_leaf = _leaf_with_body(10, 0x9001, 0x11, length=44)
        live_leaf = _leaf_with_body(91, 0x9001, 0xA5, length=44)
        recorded = [
            _frame(
                _batch(9, [recorded_leaf]),
                selector=0,
                key_index=2,
                account_id="GAME-42",
                report_index=1,
            )
        ]
        live = [
            _frame(
                _batch(90, [live_leaf]),
                selector=2,
                key_index=8,
                account_id="GAME-42",
                report_index=18,
            )
        ]
        item = _ace_try_extract_frames(recorded)
        logs = []

        output, changed = _ace_try_replay_template(
            live,
            [item],
            [0, 0],
            expected_game_id="GAME-42",
            on_log=logs.append,
        )

        self.assertFalse(changed)
        self.assertEqual(output, live)
        detail = logs[0]
        self.assertEqual(detail["decision"], "PASS_LIVE")
        self.assertEqual(detail["reason"], "UNMAPPED_BODY_PASS_LIVE")
        self.assertEqual(detail["replacement_level"], "NONE")
        self.assertEqual(
            detail["shadow_rebuild"]["status"],
            "SEMANTIC_READY_FULL",
        )
        self.assertTrue(detail["shadow_rebuild"]["send_ready"])
        self.assertTrue(detail["shadow_rebuild"]["semantic_ready"])
        self.assertEqual(
            detail["shadow_rebuild"]["unmapped_pass_live_leaves"], 1
        )
        leaf_result = detail["shadow_rebuild"]["leaf_results"][0]
        self.assertEqual(
            leaf_result["replacement_level"], "UNMAPPED_BODY_PASS_LIVE"
        )
        self.assertTrue(leaf_result["live_hex"])
        self.assertTrue(leaf_result["template_hex"])
        self.assertTrue(leaf_result["candidate_hex"])
        self.assertEqual(leaf_result["candidate_hex"], leaf_result["live_hex"])
        self.assertNotEqual(
            leaf_result["shadow_only_candidate_hex"],
            leaf_result["candidate_hex"],
        )

    def test_dynamic_record_code_keeps_live_body(self):
        recorded_leaf = bytearray(
            _leaf_with_body(417, 0x0000, 0x11, length=120)
        )
        live_leaf = bytearray(
            _leaf_with_body(263, 0x0000, 0x22, length=120)
        )
        recorded_leaf[6:10] = (0x01122388).to_bytes(4, "big")
        live_leaf[6:10] = (0x01122388).to_bytes(4, "big")
        recorded_leaf[40:50] = b"1785526532"
        live_leaf[40:50] = b"1785527394"
        rows = template_leaf_rows(
            _type9_payload(bytes(recorded_leaf), selector=0, key_index=2),
            pool_idx=125,
        )["rows"]

        shadow = build_shadow_logical(
            _type9_payload(bytes(live_leaf), selector=2, key_index=8), rows
        )

        self.assertTrue(shadow["generated"])
        self.assertEqual(shadow["changed_leaves"], 0)
        self.assertEqual(shadow["aggressive_changed_leaves"], 0)
        self.assertEqual(shadow["aggressive_blocked_leaves"], 0)
        self.assertEqual(shadow["full_live_inherited_leaves"], 1)
        result = shadow["leaf_results"][0]
        self.assertEqual(result["block_reason"], "FULL_LIVE_INHERIT")
        self.assertEqual(result["replacement_level"], "FULL_LIVE_INHERIT")
        self.assertIsNone(result["dynamic_guard"])
        self.assertTrue(result["suspect_watch"])
        self.assertIn("FULL_LIVE_INHERIT", result["suspect_flags"])
        self.assertTrue(result["shadow_only_candidate_hex"])
        self.assertTrue(result["shadow_only_diff_ranges"])
        self.assertNotEqual(
            result["shadow_only_candidate_hex"], result["candidate_hex"]
        )
        self.assertTrue(shadow["suspect_live_plaintext_hex"])
        rebuilt = decode_material(shadow["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(rebuilt, bytes(live_leaf))

    def test_confirmed_dynamic_fff_message_ids_keep_live_body(self):
        for message_id in (0xFFF2, 0xFFF3):
            with self.subTest(message_id=f"0x{message_id:04X}"):
                recorded_leaf = _leaf_with_body(10, message_id, 0x11, length=44)
                live_leaf = _leaf_with_body(11, message_id, 0xA5, length=44)
                rows = template_leaf_rows(
                    _type9_payload(recorded_leaf, selector=0, key_index=2),
                    pool_idx=0,
                )["rows"]

                shadow = build_shadow_logical(
                    _type9_payload(live_leaf, selector=2, key_index=8), rows
                )

                self.assertEqual(shadow["changed_leaves"], 0)
                self.assertEqual(shadow["aggressive_blocked_leaves"], 0)
                self.assertEqual(shadow["full_live_inherited_leaves"], 1)
                result = shadow["leaf_results"][0]
                self.assertEqual(
                    result["block_reason"], "FULL_LIVE_INHERIT"
                )

    def test_1105_uses_exact_message_template_and_inherits_live_prefix(self):
        recorded = bytearray(
            _leaf_with_body(10, 0x1105, 0x31, length=236)
        )
        live = bytearray(
            _leaf_with_body(1404, 0x1105, 0xA7, length=236)
        )
        decoy = bytearray(
            _leaf_with_body(1403, 0x1005, 0x55, length=236)
        )
        recorded[32:36] = (3).to_bytes(4, "big")
        live[32:36] = (57).to_bytes(4, "big")
        rows = []
        rows.extend(
            template_leaf_rows(
                _type9_payload(bytes(recorded), selector=0, key_index=2),
                pool_idx=1,
            )["rows"]
        )
        rows.extend(
            template_leaf_rows(
                _type9_payload(bytes(decoy), selector=0, key_index=2),
                pool_idx=2,
            )["rows"]
        )

        shadow = build_shadow_logical(
            _type9_payload(bytes(live), selector=2, key_index=8),
            rows,
            special_rule_store=NO_HOT_RULES,
        )

        self.assertTrue(shadow["generated"])
        self.assertEqual(shadow["changed_leaves"], 1)
        self.assertEqual(shadow["clean_changed_leaves"], 1)
        self.assertEqual(shadow["aggressive_blocked_leaves"], 0)
        result = shadow["leaf_results"][0]
        self.assertEqual(result["message_id"], 0x1105)
        self.assertEqual(result["template_sequence"], 10)
        self.assertEqual(result["sequence_distance"], 1394)
        self.assertEqual(result["replacement_level"], "KNOWN_CLEAN")
        self.assertEqual(result["unknown_diff_offsets"], [])
        rebuilt = decode_material(shadow["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(rebuilt[:0x24], bytes(live[:0x24]))
        self.assertEqual(rebuilt[0x24:], bytes(recorded[0x24:]))
        self.assertEqual(int.from_bytes(rebuilt[10:14], "big"), 1404)
        self.assertEqual(int.from_bytes(rebuilt[32:36], "big"), 57)

    def test_batch_keeps_01122388_live_while_replacing_1105_sibling(self):
        recorded_counter = bytearray(
            _leaf_with_body(100, 0, 0x11, length=120)
        )
        live_counter = bytearray(
            _leaf_with_body(854, 0, 0x22, length=120)
        )
        recorded_counter[6:10] = (0x01122388).to_bytes(4, "big")
        live_counter[6:10] = (0x01122388).to_bytes(4, "big")
        live_counter[40:83] = (
            b"inc_id:67;obf_id:67;r:1/9/853/863/759/23/23"
        )
        recorded_1105 = bytearray(
            _leaf_with_body(101, 0x1105, 0x33, length=93)
        )
        live_1105 = bytearray(
            _leaf_with_body(855, 0x1105, 0x99, length=93)
        )
        live_1105[32:36] = (23).to_bytes(4, "big")
        rows = template_leaf_rows(
            _type9_payload(
                _batch(0, [bytes(recorded_counter), bytes(recorded_1105)]),
                selector=0,
                key_index=2,
            ),
            pool_idx=0,
        )["rows"]

        shadow = build_shadow_logical(
            _type9_payload(
                _batch(0, [bytes(live_counter), bytes(live_1105)]),
                selector=2,
                key_index=8,
            ),
            rows,
            special_rule_store=NO_HOT_RULES,
        )

        self.assertTrue(shadow["generated"])
        self.assertEqual(shadow["full_live_inherited_leaves"], 1)
        rebuilt = decode_material(shadow["candidate_logical"])["leaves"]
        self.assertEqual([row["record_sequence"] for row in rebuilt], [854, 855])
        self.assertEqual(rebuilt[0]["record_code"], 0x01122388)
        self.assertIsNone(rebuilt[0]["message_id"])
        self.assertEqual(rebuilt[0]["raw"], bytes(live_counter))
        self.assertEqual(rebuilt[1]["message_id"], 0x1105)
        self.assertEqual(rebuilt[1]["raw"][:0x24], bytes(live_1105[:0x24]))
        self.assertEqual(rebuilt[1]["raw"][0x24:], bytes(recorded_1105[0x24:]))

    def test_watched_8024_is_profiled_and_kept_live(self):
        recorded_leaf = _leaf_with_body(10, 0x8024, 0x11, length=44)
        live_leaf = _leaf_with_body(11, 0x8024, 0xA5, length=44)
        rows = template_leaf_rows(
            _type9_payload(recorded_leaf, selector=0, key_index=2),
            pool_idx=0,
        )["rows"]

        shadow = build_shadow_logical(
            _type9_payload(live_leaf, selector=2, key_index=8), rows
        )

        self.assertEqual(shadow["changed_leaves"], 0)
        self.assertEqual(shadow["unmapped_pass_live_leaves"], 1)
        self.assertEqual(shadow["aggressive_blocked_leaves"], 0)
        result = shadow["leaf_results"][0]
        self.assertTrue(result["suspect_watch"])
        self.assertEqual(result["candidate_hex"], result["live_hex"])
        self.assertNotEqual(
            result["shadow_only_candidate_hex"], result["candidate_hex"]
        )

    def test_watched_new_length_records_full_live_plaintext(self):
        recorded_leaf = bytearray(
            _leaf_with_body(10, 0x0000, 0x11, length=120)
        )
        live_leaf = bytearray(
            _leaf_with_body(11, 0x0000, 0x22, length=121)
        )
        recorded_leaf[6:10] = (0x01122388).to_bytes(4, "big")
        live_leaf[6:10] = (0x01122388).to_bytes(4, "big")
        rows = template_leaf_rows(
            _type9_payload(bytes(recorded_leaf), selector=0, key_index=2),
            pool_idx=0,
        )["rows"]

        shadow = build_shadow_logical(
            _type9_payload(bytes(live_leaf), selector=2, key_index=8), rows
        )

        result = shadow["leaf_results"][0]
        self.assertFalse(result["matched"])
        self.assertTrue(result["suspect_watch"])
        self.assertIn("NEW_LENGTH", result["suspect_flags"])
        self.assertEqual(result["available_template_lengths"], [120])
        self.assertTrue(result["live_hex"])
        self.assertFalse(result["shadow_only_candidate_hex"])
        self.assertEqual(shadow["suspect_leaf_count"], 1)
        self.assertTrue(shadow["suspect_live_plaintext_hex"])

    def test_distant_unknown_sequence_is_kept_live(self):
        recorded_leaf = _leaf_with_body(10, 0x9001, 0x11, length=44)
        live_leaf = _leaf_with_body(200, 0x9001, 0xA5, length=44)
        rows = template_leaf_rows(
            _type9_payload(recorded_leaf, selector=0, key_index=2), pool_idx=0
        )["rows"]

        shadow = build_shadow_logical(
            _type9_payload(live_leaf, selector=2, key_index=8), rows
        )

        result = shadow["leaf_results"][0]
        self.assertEqual(result["block_reason"], "UNMAPPED_BODY_PASS_LIVE")
        self.assertEqual(
            result["replacement_level"], "UNMAPPED_BODY_PASS_LIVE"
        )
        self.assertTrue(result["dynamic_guard"]["blocked"])
        self.assertIn("UNMAPPED_BODY", result["dynamic_guard"]["reasons"])
        self.assertIsNone(result["dynamic_guard"]["sequence_limit"])
        self.assertFalse(result["dynamic_guard"]["sequence_limit_enabled"])
        self.assertEqual(result["dynamic_guard"]["sequence_distance"], 190)
        self.assertEqual(shadow["changed_leaves"], 0)
        self.assertEqual(shadow["unmapped_pass_live_leaves"], 1)
        candidate = bytes.fromhex(result["candidate_hex"])
        self.assertEqual(candidate, live_leaf)
        shadow_only = bytes.fromhex(result["shadow_only_candidate_hex"])
        self.assertEqual(shadow_only[0:14], live_leaf[0:14])
        self.assertEqual(shadow_only[14:], recorded_leaf[14:])

    def test_stale_unknown_timestamp_is_kept_live(self):
        recorded_leaf = bytearray(
            _leaf_with_body(10, 0x9001, 0x11, length=80)
        )
        live_leaf = bytearray(
            _leaf_with_body(11, 0x9001, 0xA5, length=80)
        )
        recorded_leaf[40:50] = b"1785526532"
        live_leaf[40:50] = b"1785527394"
        rows = template_leaf_rows(
            _type9_payload(bytes(recorded_leaf), selector=0, key_index=2),
            pool_idx=0,
        )["rows"]

        shadow = build_shadow_logical(
            _type9_payload(bytes(live_leaf), selector=2, key_index=8), rows
        )

        result = shadow["leaf_results"][0]
        self.assertEqual(result["block_reason"], "UNMAPPED_BODY_PASS_LIVE")
        self.assertIn("UNMAPPED_BODY", result["dynamic_guard"]["reasons"])
        self.assertIn(
            "TIMESTAMP_DELTA_EXCEEDED", result["dynamic_guard"]["reasons"]
        )
        self.assertEqual(shadow["changed_leaves"], 0)

    def test_replay_logs_dynamic_block_and_passes_live(self):
        recorded_leaf = _leaf_with_body(10, 0xFFF3, 0x11, length=44)
        live_leaf = _leaf_with_body(11, 0xFFF3, 0xA5, length=44)
        recorded = [
            _frame(
                _batch(9, [recorded_leaf]),
                selector=0,
                key_index=2,
                account_id="GAME-42",
                report_index=1,
            )
        ]
        live = [
            _frame(
                _batch(10, [live_leaf]),
                selector=2,
                key_index=8,
                account_id="GAME-42",
                report_index=18,
            )
        ]
        logs = []

        output, changed = _ace_try_replay_template(
            live,
            [_ace_try_extract_frames(recorded)],
            [0, 0],
            expected_game_id="GAME-42",
            on_log=logs.append,
        )

        self.assertFalse(changed)
        self.assertEqual(output, live)
        self.assertEqual(logs[0]["decision"], "PASS_LIVE")
        self.assertEqual(logs[0]["reason"], "NO_RECORDED_BODY_CHANGE_PASS_LIVE")
        self.assertEqual(
            logs[0]["shadow_rebuild"]["full_live_inherited_leaves"], 1
        )

    def test_8004_inherits_group_and_matches_subindex(self):
        def grouped_leaf(sequence: int, group_id: int, sub_index: int) -> bytes:
            data = bytearray(
                _leaf_with_body(sequence, 0x8004, 0, length=40)
            )
            data[28:30] = group_id.to_bytes(2, "big")
            data[30:32] = (1).to_bytes(2, "big")
            data[32:36] = sub_index.to_bytes(4, "big")
            data[36:40] = bytes.fromhex("14CBFFC2")
            return bytes(data)

        rows = template_leaf_rows(
            _type9_payload(
                grouped_leaf(70, 0x001E, 3), selector=0, key_index=2
            ),
            pool_idx=0,
        )["rows"]
        live = grouped_leaf(560, 0x0276, 3)

        shadow = build_shadow_logical(
            _type9_payload(live, selector=2, key_index=8), rows
        )

        self.assertEqual(shadow["matched_leaves"], 1)
        self.assertEqual(shadow["subtype_miss_leaves"], 0)
        self.assertEqual(shadow["semantic_ready_leaves"], 1)
        rebuilt = decode_material(shadow["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(rebuilt[28:30], bytes.fromhex("0276"))
        self.assertEqual(rebuilt[32:36], (3).to_bytes(4, "big"))

    def test_fffe_clean_vector_includes_final_byte(self):
        clean = bytearray(_leaf_with_body(10, 0xFFFE, 0, length=49))
        live = bytearray(_leaf_with_body(11, 0xFFFE, 0, length=49))
        clean[38:49] = bytes.fromhex("0102030405060708090A0B")
        live[38:49] = bytes.fromhex("A1A2A3A4A5A6A7A8A9AAAB")
        rows = template_leaf_rows(
            _type9_payload(bytes(clean), selector=0, key_index=2),
            pool_idx=0,
        )["rows"]

        shadow = build_shadow_logical(
            _type9_payload(bytes(live), selector=2, key_index=8), rows
        )

        self.assertEqual(shadow["semantic_unmapped_leaves"], 0)
        self.assertEqual(shadow["semantic_ready_leaves"], 1)
        rebuilt = decode_material(shadow["candidate_logical"])["leaves"][0]["raw"]
        self.assertEqual(rebuilt[38:49], clean[38:49])


if __name__ == "__main__":
    unittest.main()
