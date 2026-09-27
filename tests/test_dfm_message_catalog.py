from __future__ import annotations

import unittest
import zlib

from core.type9_crypto import KEYS, type9_transform

from core.uam_message_catalog import (
    UAM_KNOWN_80XX_MESSAGE_IDS,
    UAM_KNOWN_MESSAGE_ID_CATALOG,
    UAM_KNOWN_MESSAGE_IDS,
    UAM_REPLAY_80XX_MESSAGE_IDS,
    format_recording_period_status,
    summarize_pool_items,
)


def cached_item(*rows, source="01"):
    cached_rows = []
    for row in rows:
        message_id, length = row[:2]
        raw = bytearray(max(int(length), 0x1E))
        if len(row) >= 3 and row[2] is not None:
            raw[0x1C:0x1E] = int(row[2]).to_bytes(2, "big")
        if len(row) >= 4 and row[3] is not None:
            raw[0x20:0x24] = int(row[3]).to_bytes(4, "big")
        cached_rows.append({
            "key": (0x0102000A, message_id, length),
            "raw": bytes(raw),
        })
    return {
        "source": source,
        "_type9_shadow_leaf_cache": {
            "ok": True,
            "rows": cached_rows,
        },
    }


class UamMessageCatalogTests(unittest.TestCase):
    def test_catalog_matches_uam_v1312_sample_set(self):
        self.assertEqual(len(UAM_KNOWN_MESSAGE_IDS), 48)
        for message_id in (0x8023, 0x80CC, 0x810B, 0xFFF3, 0xFFFE):
            self.assertIn(message_id, UAM_KNOWN_MESSAGE_IDS)
        self.assertEqual(UAM_REPLAY_80XX_MESSAGE_IDS, UAM_KNOWN_MESSAGE_IDS)
        self.assertNotIn(0x8024, UAM_KNOWN_MESSAGE_IDS)
        self.assertNotIn(0x800F, UAM_KNOWN_MESSAGE_IDS)

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_coverage_counts_known_missing_and_unknown_ids(self):
        summary = summarize_pool_items([
            cached_item((0x1001, 80), (0x1001, 80), (0x9000, 84)),
            cached_item((0xDEAD, 48)),
            cached_item((0x1002, 60), source="3366_09"),
        ])

        self.assertEqual(summary["seen_known_count"], 2)
        self.assertEqual(summary["message_counts"][0x1001], 2)
        self.assertEqual(summary["message_lengths"][0x1001], [80])
        self.assertEqual(summary["unknown_ids"], [0xDEAD])
        self.assertIn(0x1002, summary["missing_ids"])
        self.assertAlmostEqual(summary["coverage_percent"], 2 / 58 * 100)
        self.assertEqual(summary["priority_coverage_percent"], 0.0)
        self.assertFalse(summary["complete"])

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_normalized_pool_record_without_outer_marker_is_decoded(self):
        leaf = bytearray(40)
        leaf[0:4] = (1).to_bytes(4, "big")
        leaf[4:6] = len(leaf).to_bytes(2, "big")
        leaf[6:10] = (0x0102000A).to_bytes(4, "big")
        leaf[10:14] = (1).to_bytes(4, "big")
        leaf[0x16:0x18] = (0x8007).to_bytes(2, "big")
        leaf[0x1C:0x1E] = (60).to_bytes(2, "big")
        cipher = type9_transform(bytes(leaf), 0, KEYS[8], direction=1)
        normalized_record = (
            bytes([0, 8])
            + (zlib.crc32(leaf) & 0xFFFFFFFF).to_bytes(4, "big")
            + len(cipher).to_bytes(2, "big")
            + cipher
        )

        summary = summarize_pool_items([{
            "source": "01",
            "payload": normalized_record,
        }])

        self.assertEqual(summary["decoded_reports"], 1)
        self.assertEqual(summary["decode_failures"], 0)
        self.assertEqual(summary["seen_priority_ids"], [0x8007])
        self.assertEqual(summary["message_slots"][0x8007], [60])

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_primary_coverage_only_counts_replay_80xx(self):
        summary = summarize_pool_items([
            cached_item((0x8000, 48), (0x8029, 96), (0x1001, 80)),
        ])

        self.assertEqual(summary["seen_priority_count"], 2)
        self.assertEqual(summary["priority_total"], 21)
        self.assertAlmostEqual(
            summary["priority_coverage_percent"], 2 / 21 * 100
        )
        self.assertIn(0x8021, summary["missing_priority_ids"])

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_periodic_readiness_requires_two_consecutive_600_slots(self):
        summary = summarize_pool_items([
            cached_item(
                (0x8007, 48, 30),
                (0x800D, 56, 30),
                (0x802C, 52, 30),
            ),
            cached_item(
                (0x8007, 48, 630),
                (0x800D, 56, 631),
                (0x802C, 52, 630),
            ),
        ])

        self.assertEqual(summary["periodic_total"], 7)
        self.assertEqual(summary["periodic_ready_count"], 2)
        self.assertEqual(summary["periodic_ready_ids"], [0x8007, 0x802C])
        rows = {
            row["message_id"]: row for row in summary["periodic_rows"]
        }
        self.assertTrue(rows[0x8007]["ready"])
        self.assertEqual(rows[0x8007]["last_interval"], 600)
        self.assertFalse(rows[0x800D]["ready"])
        self.assertEqual(rows[0x800D]["last_interval"], 601)
        self.assertFalse(rows[0x800A]["ready"])
        self.assertFalse(rows[0x800F]["ready"])
        self.assertFalse(rows[0x8027]["ready"])
        self.assertFalse(rows[0x8029]["ready"])
        self.assertEqual(rows[0x8027]["kind"], "scan_wave")
        self.assertEqual(rows[0x8027]["status"], "waiting_wave1")
        self.assertAlmostEqual(summary["periodic_coverage_percent"], 200 / 7)
        self.assertEqual(summary["recording_completion_count"], 5)
        self.assertEqual(summary["recording_completion_total"], 36)

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_scan_wave_readiness_requires_complete_first_wave_and_second_open(self):
        def scan_item(message_id, length, slot, u20, elapsed):
            item = cached_item((message_id, length, slot, u20))
            item["recorded_elapsed_seconds"] = elapsed
            return item

        incomplete = summarize_pool_items([
            scan_item(0x8029, 80, 0x3456, 200, 35.0),
            scan_item(0x8027, 110, 0x3456, 268, 40.0),
            scan_item(0x8027, 114, 0x3456, 59, 50.0),
        ])
        self.assertEqual(incomplete["periodic_total"], 7)
        self.assertEqual(incomplete["scan_wave_status"], "waiting_wave2")
        self.assertFalse(incomplete["scan_wave_ready"])
        self.assertNotIn(0x8027, incomplete["periodic_ready_ids"])
        self.assertNotIn(0x8029, incomplete["periodic_ready_ids"])

        ready = summarize_pool_items([
            scan_item(0x8029, 80, 0x3456, 200, 35.0),
            scan_item(0x8027, 110, 0x3456, 268, 40.0),
            scan_item(0x8027, 114, 0x3456, 59, 50.0),
            scan_item(0x8027, 110, 0x3456, 268, 784.0),
        ])
        self.assertTrue(ready["scan_wave_ready"])
        self.assertEqual(ready["scan_wave_status"], "ready")
        self.assertAlmostEqual(ready["scan_wave_period_seconds"], 744.0)
        self.assertEqual(ready["periodic_ready_ids"], [0x8027, 0x8029])
        self.assertEqual(ready["periodic_ready_count"], 2)
        rows = {row["message_id"]: row for row in ready["periodic_rows"]}
        self.assertTrue(rows[0x8027]["ready"])
        self.assertTrue(rows[0x8029]["ready"])

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_800a_two_30_slot_clusters_are_not_ready(self):
        slots = list(range(60, 511, 30)) + list(range(1380, 1591, 30))
        summary = summarize_pool_items([
            cached_item(*[(0x800A, 80, slot) for slot in slots]),
        ])
        rows = {
            row["message_id"]: row for row in summary["periodic_rows"]
        }
        self.assertEqual(summary["periodic_total"], 7)
        self.assertFalse(rows[0x800A]["ready"])
        self.assertEqual(rows[0x800A]["morphology"], "cluster_30")
        self.assertEqual(rows[0x800A]["cluster_count"], 2)
        self.assertEqual(rows[0x800A]["status"], "等待第3簇 (2/3)")
        self.assertNotIn(0x800A, summary["periodic_ready_ids"])

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_800a_three_consistent_clusters_are_ready(self):
        slots = (
            list(range(60, 511, 30))
            + list(range(1380, 1591, 30))
            + list(range(2700, 2911, 30))
        )
        summary = summarize_pool_items([
            cached_item(*[(0x800A, 80, slot) for slot in slots]),
        ])
        rows = {
            row["message_id"]: row for row in summary["periodic_rows"]
        }
        self.assertTrue(rows[0x800A]["ready"])
        self.assertEqual(rows[0x800A]["morphology"], "cluster_30")
        self.assertEqual(rows[0x800A]["period"], 1320)
        self.assertIn(0x800A, summary["periodic_ready_ids"])

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_800a_sparse_900_still_ready(self):
        summary = summarize_pool_items([
            cached_item((0x800A, 80, 30), (0x800A, 80, 930)),
        ])
        rows = {
            row["message_id"]: row for row in summary["periodic_rows"]
        }
        self.assertTrue(rows[0x800A]["ready"])
        self.assertEqual(rows[0x800A]["morphology"], "sparse_900")
        self.assertEqual(rows[0x800A]["period"], 900)

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_long_8027_wave_ready_after_second_open(self):
        def scan_item(message_id, length, slot, u20, elapsed):
            item = cached_item((message_id, length, slot, u20))
            item["recorded_elapsed_seconds"] = elapsed
            return item

        waiting = summarize_pool_items([
            scan_item(0x8029, 80, 0x3456, 70283, 32.679),
            scan_item(0x8027, 110, 0x3456, 70283, 39.338),
            scan_item(0x8027, 110, 0x3456, 52810, 150.000),
        ])
        self.assertEqual(waiting["scan_wave_status"], "waiting_wave2")
        self.assertFalse(waiting["scan_wave_ready"])

        ready = summarize_pool_items([
            scan_item(0x8029, 80, 0x3456, 70283, 32.679),
            scan_item(0x8027, 110, 0x3456, 70283, 39.338),
            scan_item(0x8027, 110, 0x3456, 52810, 150.000),
            scan_item(0x8027, 110, 0x3456, 70296, 962.688),
        ])
        self.assertTrue(ready["scan_wave_ready"])
        self.assertEqual(ready["scan_wave_status"], "ready")
        self.assertAlmostEqual(ready["scan_wave_period_seconds"], 923.35, places=2)
        rows = {row["message_id"]: row for row in ready["periodic_rows"]}
        self.assertEqual(rows[0x8027]["wave1_shape"], "long_gap")
        self.assertIn(0x8027, ready["periodic_ready_ids"])
        self.assertIn(0x8029, ready["periodic_ready_ids"])

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_non_monotonic_8027_wave_is_not_ready(self):
        def scan_item(message_id, length, slot, u20, elapsed):
            item = cached_item((message_id, length, slot, u20))
            item["recorded_elapsed_seconds"] = elapsed
            return item

        summary = summarize_pool_items([
            scan_item(0x8029, 80, 0x3456, 70283, 32.679),
            scan_item(0x8027, 110, 0x3456, 70283, 39.338),
            scan_item(0x8027, 110, 0x3456, 50000, 80.0),
            scan_item(0x8027, 110, 0x3456, 65000, 120.0),
            scan_item(0x8027, 110, 0x3456, 52810, 150.0),
            scan_item(0x8027, 110, 0x3456, 70296, 962.688),
        ])
        self.assertFalse(summary["scan_wave_ready"])
        self.assertEqual(summary["scan_wave_status"], "waiting_wave1")
        self.assertNotIn(0x8027, summary["periodic_ready_ids"])
        self.assertNotIn(0x8029, summary["periodic_ready_ids"])

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_8004_requires_all_nine_subtypes_for_structural_readiness(self):
        expected = [0, 1, 2, 3, 4, 5, 6, 7, 0x10]
        summary = summarize_pool_items([
            cached_item(*[
                (0x8004, 40, 30, subtype) for subtype in expected
            ])
        ])

        self.assertEqual(summary["subtype_8004_seen_count"], 9)
        self.assertEqual(summary["subtype_8004_total"], 9)
        self.assertTrue(summary["subtype_8004_ready"])
        self.assertEqual(summary["subtype_8004_missing"], [])

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_recording_pool_aggregates_coverage_by_game_id(self):
        try:
            from core.pool import RecordingPool
        except ImportError:
            self.skipTest("PySide6 is not installed")

        pool = RecordingPool()
        pool._sessions = {
            "1.2.3.4": [{
                "sid": "1.2.3.4#1",
                "game_id": "PLAYER",
                "active": True,
                "_ghost": False,
                "pool_items": [
                    cached_item((0x1001, 80)),
                    cached_item((0x1002, 60)),
                    cached_item((0x9000, 84), source="3366_09"),
                ],
                "pkts": [],
            }]
        }

        summary = pool.get_message_coverage_for_game_id("PLAYER")
        rows = pool.get_all_sessions()

        self.assertEqual(summary["seen_known_count"], 2)
        self.assertEqual(set(summary["seen_known_ids"]), {0x1001, 0x1002})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["message_coverage"]["seen_known_count"], 2)

    @unittest.skip("UAM 样本目录：不适用旧版 80xx/slot/扫描波周期就绪测试")
    def test_recording_pool_exposes_stable_device_identity_for_ui(self):
        try:
            from core.pool import RecordingPool
        except ImportError:
            self.skipTest("PySide6 is not installed")

        raw = (
            b"model:iPad13,4;ver:14.6;iDevHwModel:J517AP;"
            b"iDevSysVer:14.6;"
            b"iDevIDFV:12345678-1234-1234-1234-123456789ABC;"
            b"iAppVersion:1.2.3;"
        )
        item = {
            "source": "01",
            "_type9_shadow_leaf_cache": {
                "ok": True,
                "rows": [{"raw": raw}],
            },
        }
        pool = RecordingPool()
        pool._sessions = {
            "1.2.3.4": [{
                "sid": "1.2.3.4#1",
                "game_id": "PLAYER",
                "active": True,
                "_ghost": False,
                "pool_items": [item],
                "pkts": [],
            }]
        }

        identity = pool.get_device_identity_for_game_id("PLAYER")
        rows = pool.get_all_sessions()

        self.assertEqual(identity["status"], "complete")
        self.assertTrue(identity["reuse_ready"])
        self.assertEqual(identity["context"]["model"], "iPad13,4")
        self.assertEqual(identity["context"]["hardware_model"], "J517AP")
        self.assertEqual(identity["context"]["system_version"], "14.6")
        self.assertEqual(
            identity["context"]["device_idfv"],
            "12345678-1234-1234-1234-123456789ABC",
        )
        self.assertEqual(len(identity["fingerprint_sha256"]), 64)
        self.assertEqual(len(identity["fingerprint_short"]), 12)
        self.assertEqual(
            rows[0]["device_identity"]["fingerprint_sha256"],
            identity["fingerprint_sha256"],
        )

        pool._sessions["5.6.7.8"] = [{
            "sid": "5.6.7.8#1",
            "game_id": "PLAYER",
            "active": False,
            "_ghost": False,
            "pool_items": [{
                "source": "01",
                "_type9_shadow_leaf_cache": {
                    "ok": True,
                    "rows": [{
                        "raw": raw.replace(
                            b"12345678-1234-1234-1234-123456789ABC",
                            b"87654321-4321-4321-4321-CBA987654321",
                        )
                    }],
                },
            }],
            "pkts": [],
        }]
        mixed = pool.get_device_identity_for_game_id("PLAYER")
        self.assertEqual(mixed["status"], "multiple")
        self.assertFalse(mixed["reuse_ready"])
        self.assertEqual(mixed["device_count"], 2)
        self.assertEqual(mixed["fingerprint_sha256"], "")

    def test_recording_period_status_uses_uam_sample_labels(self):
        empty = summarize_pool_items([])
        self.assertEqual(
            format_recording_period_status(0x8023, coverage=empty),
            "约 120 秒（UAM 样本）",
        )
        self.assertEqual(
            format_recording_period_status(0x8101, coverage=empty),
            "见本次录制",
        )
        self.assertEqual(format_recording_period_status(0x8024, coverage=empty), "—")
        self.assertEqual(format_recording_period_status(0x1001, coverage=empty), "—")
        for message_id in UAM_KNOWN_80XX_MESSAGE_IDS:
            text = format_recording_period_status(
                message_id,
                coverage=empty,
                match_event_mode="off",
            )
            self.assertTrue(text)
            self.assertNotEqual(text, "—")


if __name__ == "__main__":
    unittest.main()
