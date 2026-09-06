import json
from pathlib import Path
import tempfile
import unittest
import zlib

from core.type9_crypto import KEYS, type9_transform
from tools.compare_01_message_ids import (
    Dataset,
    LeafSample,
    compare_datasets,
    discover_pair,
    load_dataset,
)


def _sample(message_id: int, sequence: int, value_28: int, value_30: int) -> LeafSample:
    raw = bytearray(116)
    raw[0:4] = (1).to_bytes(4, "big")
    raw[4:6] = len(raw).to_bytes(2, "big")
    raw[6:10] = (0x0102000A).to_bytes(4, "big")
    raw[10:14] = sequence.to_bytes(4, "big")
    raw[0x16:0x18] = message_id.to_bytes(2, "big")
    raw[0x48:0x4C] = value_28.to_bytes(4, "big")
    raw[0x50:0x54] = value_30.to_bytes(4, "big")
    return LeafSample(
        record_code=0x0102000A,
        message_id=message_id,
        length=len(raw),
        sequence=sequence,
        raw=bytes(raw),
        packet_id=f"packet-{sequence}",
    )


def _physical_frame(sample: LeafSample, report_index: int) -> bytes:
    selector, key_index = 0, 2
    cipher = type9_transform(sample.raw, selector, KEYS[key_index], direction=1)
    type9 = (
        b"\x01\x0A\x00\x09"
        + b"\x00" * 10
        + bytes([selector, key_index])
        + (zlib.crc32(sample.raw) & 0xFFFFFFFF).to_bytes(4, "big")
        + len(cipher).to_bytes(2, "big")
        + cipher
    )
    account = b"RAW-ARRAY"
    logical = (
        b"\x00" * 5
        + b"\x01\x0A\x00\x23"
        + report_index.to_bytes(4, "big")
        + b"\x00" * 10
        + bytes([len(account)])
        + account
        + b"\x00"
        + type9
    )
    frame = bytearray(55)
    frame[0:3] = b"\x01\x00\x00"
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


class Compare01MessageIdsTests(unittest.TestCase):
    def test_marks_0207_zero_to_nonzero_fields_at_payload_offsets(self):
        baseline = Dataset(label="clean", input_path="A")
        observed = Dataset(label="test", input_path="B")
        baseline.samples = [
            _sample(0x0207, 1, 0, 0),
            _sample(0x0207, 2, 0, 0),
            _sample(0x0207, 3, 0, 0),
        ]
        observed.samples = [
            _sample(0x0207, 11, 13, 1),
            _sample(0x0207, 12, 13, 1),
            _sample(0x0207, 13, 28, 1),
        ]
        baseline.packets = {row.packet_id for row in baseline.samples}
        observed.packets = {row.packet_id for row in observed.samples}

        result = compare_datasets(
            baseline,
            observed,
            only_message_ids={0x0207},
        )

        count = result["message_ids"][0]
        self.assertEqual(count["message_id"], "0x0207")
        self.assertEqual((count["count_a"], count["count_b"]), (3, 3))
        fields = {
            (row["leaf_offset"], row["width"], row["category"])
            for row in result["field_anomalies"]
        }
        self.assertIn((0x48, 4, "ZERO_TO_NONZERO"), fields)
        self.assertIn((0x50, 4, "ZERO_TO_NONZERO"), fields)

    def test_small_all_unique_baseline_is_not_called_stable(self):
        baseline = Dataset(label="clean", input_path="A")
        observed = Dataset(label="test", input_path="B")
        baseline.samples = [
            _sample(0x0207, 1, 1, 0),
            _sample(0x0207, 2, 2, 0),
            _sample(0x0207, 3, 3, 0),
        ]
        observed.samples = [
            _sample(0x0207, 11, 100, 0),
            _sample(0x0207, 12, 101, 0),
            _sample(0x0207, 13, 102, 0),
        ]
        baseline.packets = {row.packet_id for row in baseline.samples}
        observed.packets = {row.packet_id for row in observed.samples}

        result = compare_datasets(baseline, observed)

        self.assertFalse(
            any(
                row["leaf_offset"] == 0x48
                and row["category"] == "NEW_VALUE_OUTSIDE_BASELINE"
                for row in result["field_anomalies"]
            )
        )

    def test_auto_pair_and_message_leaf_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            for name, value in (("A_clean", 0), ("B_test", 13)):
                record_dir = parent / name / "01RecordPackets"
                record_dir.mkdir(parents=True)
                sample = _sample(0x0207, 1, value, int(value != 0))
                event = {
                    "schema": "dfm-01-message-leaves-v1",
                    "event_id": 1,
                    "time": "2026-08-04T12:00:00.000",
                    "leaves": [
                        {
                            "record_code": "0x0102000A",
                            "message_id": "0x0207",
                            "sequence": 1,
                            "path": [0],
                            "raw_hex": sample.raw.hex(),
                        }
                    ],
                }
                (record_dir / "test_01_message_leaves_run.jsonl").write_text(
                    json.dumps(event) + "\n", encoding="utf-8"
                )

            pair = discover_pair(parent)
            self.assertEqual([path.name for path in pair], ["A_clean", "B_test"])
            loaded = load_dataset(pair[1], "test", direction="up", view="live")
            self.assertEqual(len(loaded.packets), 1)
            self.assertEqual(len(loaded.samples), 1)
            self.assertEqual(loaded.samples[0].message_id, 0x0207)
            self.assertEqual(
                int.from_bytes(loaded.samples[0].raw[0x48:0x4C], "big"), 13
            )

    def test_generic_data1_data2_python_arrays_decrypt_full_01_frames(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            clean_frames = [
                _physical_frame(_sample(0x0207, index, 0, 0), index)
                for index in (1, 2, 3)
            ]
            test_frames = [
                _physical_frame(_sample(0x0207, 10 + index, value, 1), 10 + index)
                for index, value in enumerate((13, 13, 28), 1)
            ]
            (parent / "数据1.py").write_text(
                "数据1 = " + repr([list(frame) for frame in clean_frames]) + "\n",
                encoding="utf-8",
            )
            # 验证用户所说的无外层变量、逗号分隔 ``[],[],[]`` 写法。
            (parent / "数据2.py").write_text(
                ",\n".join(
                    repr([byte if byte < 128 else byte - 256 for byte in frame])
                    for frame in test_frames
                )
                + "\n",
                encoding="utf-8",
            )

            pair = discover_pair(parent)
            baseline = load_dataset(pair[0], "数据1", direction="up", view="live")
            observed = load_dataset(pair[1], "数据2", direction="up", view="live")
            result = compare_datasets(baseline, observed)

            self.assertEqual((len(baseline.packets), len(observed.packets)), (3, 3))
            self.assertEqual(result["message_ids"][0]["message_id"], "0x0207")
            self.assertEqual(
                (result["message_ids"][0]["count_a"], result["message_ids"][0]["count_b"]),
                (3, 3),
            )
            fields = {
                (row["leaf_offset"], row["width"], row["category"])
                for row in result["field_anomalies"]
            }
            self.assertIn((0x48, 4, "ZERO_TO_NONZERO"), fields)
            self.assertIn((0x50, 4, "ZERO_TO_NONZERO"), fields)


class FieldWhitelistTests(unittest.TestCase):
    def test_splits_confirmed_clock_but_keeps_100c_and_2001_write_counter(self):
        from tools.compare_01_field_whitelist import group_by_message, split_anomalies

        kept, ignored = split_anomalies(
            [
                {
                    "shape": "0x2001/56",
                    "message_id": "0x2001",
                    "leaf_offset": 0x20,
                    "leaf_offset_hex": "0x20",
                    "payload_offset_hex": "+0x00",
                    "width": 4,
                    "category": "ZERO_TO_NONZERO",
                    "outlier_ratio_b": 0.3,
                    "values_a": [],
                    "values_b": [],
                },
                {
                    "shape": "0x2001/56",
                    "message_id": "0x2001",
                    "leaf_offset": 0x24,
                    "leaf_offset_hex": "0x24",
                    "payload_offset_hex": "+0x04",
                    "width": 4,
                    "category": "ZERO_TO_NONZERO",
                    "outlier_ratio_b": 1.0,
                    "values_a": [],
                    "values_b": [],
                },
                {
                    "shape": "0x100C/84",
                    "message_id": "0x100C",
                    "leaf_offset": 0x50,
                    "leaf_offset_hex": "0x50",
                    "payload_offset_hex": "+0x30",
                    "width": 4,
                    "category": "STABLE_BASELINE_CHANGED",
                    "outlier_ratio_b": 0.4,
                    "values_a": [],
                    "values_b": [],
                },
                {
                    "shape": "0x8024/40",
                    "message_id": "0x8024",
                    "leaf_offset": 0x24,
                    "leaf_offset_hex": "0x24",
                    "payload_offset_hex": "+0x04",
                    "width": 4,
                    "category": "STABLE_BASELINE_CHANGED",
                    "outlier_ratio_b": 1.0,
                    "values_a": [],
                    "values_b": [],
                },
            ]
        )
        self.assertEqual(
            [row["shape"] for row in kept],
            ["0x2001/56", "0x100C/84"],
        )
        self.assertEqual(kept[0]["leaf_offset_hex"], "0x24")
        self.assertEqual({row["shape"] for row in ignored}, {"0x2001/56", "0x8024/40"})
        grouped = group_by_message(kept)
        self.assertEqual(set(grouped), {"0x100C", "0x2001"})


class QuickCompareWatchTests(unittest.TestCase):
    def test_index_keeps_100c_even_when_score_rank_is_low(self):
        from tools.quick_compare_01_suite import DEFAULT_WATCH_IDS, watched_anomalies

        anomalies = [
            {
                "shape": "0x1005/60",
                "message_id": "0x1005",
                "category": "ZERO_TO_NONZERO",
                "leaf_offset_hex": "0x2A",
                "payload_offset_hex": "+0x0A",
                "width": 2,
                "outlier_ratio_b": 1.0,
                "values_a": [{"hex": "0000", "count": 4}],
                "values_b": [{"hex": "4000", "count": 10}],
            },
            {
                "shape": "0x100C/84",
                "message_id": "0x100C",
                "category": "STABLE_BASELINE_CHANGED",
                "leaf_offset_hex": "0x50",
                "payload_offset_hex": "+0x30",
                "width": 4,
                "outlier_ratio_b": 0.4,
                "values_a": [{"hex": "00000302", "count": 4}],
                "values_b": [
                    {"hex": "00000302", "count": 6},
                    {"hex": "00000303", "count": 4},
                ],
            },
        ]
        watched = watched_anomalies(anomalies, set(DEFAULT_WATCH_IDS))
        self.assertEqual([row["shape"] for row in watched], ["0x100C/84"])
        self.assertEqual(watched[0]["offset"], "0x50")


if __name__ == "__main__":
    unittest.main()
