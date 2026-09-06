from __future__ import annotations

import unittest
import zlib

from core.crypto import (
    ace_corrupt_01_downlink_zip_frames,
    ace_mutate_01_downlink_mrpcs_frames,
    _ace_01_frame_meta,
    _ace_01_verify_frames,
)
from core.type9_crypto import KEYS, find_records, type9_transform


def _frame() -> bytes:
    zip_payload = b"PK\x03\x04" + b"\x00" * 22 + (5).to_bytes(2, "little") + b"\x00\x00" + b"x.dat" + b"BODY"
    plaintext = b"HEADER" + zip_payload
    selector, key_index = 2, 2
    ciphertext = type9_transform(
        plaintext, selector, KEYS[key_index], direction=1
    )
    record = (
        bytes([selector, key_index])
        + (zlib.crc32(plaintext) & 0xFFFFFFFF).to_bytes(4, "big")
        + len(ciphertext).to_bytes(2, "big")
        + ciphertext
    )
    payload = b"\x00\x00\x00\x01" + (len(record) + 20).to_bytes(2, "big") + b"\x01\x0A\x00\x08" + b"\x00" * 10 + record
    frame = bytearray(55)
    frame[0:3] = b"\x01\x00\x00"
    frame[8:10] = (7).to_bytes(2, "big")
    frame[36:38] = (19).to_bytes(2, "big")
    frame[38:40] = (1).to_bytes(2, "big")
    frame[40:44] = (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "big")
    frame[44] = 1
    frame[49:51] = (1).to_bytes(2, "big")
    frame[51:55] = len(payload).to_bytes(4, "big")
    frame += payload
    frame[3:5] = len(frame).to_bytes(2, "big")
    return bytes(frame)


def _type9_frame(
    plaintext: bytes,
    *,
    marker: bytes = b"\x01\x0A\x00\x09",
) -> bytes:
    selector, key_index = 1, 3
    ciphertext = type9_transform(
        plaintext, selector, KEYS[key_index], direction=1
    )
    record = (
        bytes([selector, key_index])
        + (zlib.crc32(plaintext) & 0xFFFFFFFF).to_bytes(4, "big")
        + len(ciphertext).to_bytes(2, "big")
        + ciphertext
    )
    payload = (
        b"\x00\x00\x00\x01"
        + (len(record) + 20).to_bytes(2, "big")
        + marker
        + b"\x00" * 10
        + record
    )
    frame = bytearray(55)
    frame[0:3] = b"\x01\x00\x00"
    frame[8:10] = (8).to_bytes(2, "big")
    frame[36:38] = (20).to_bytes(2, "big")
    frame[38:40] = (1).to_bytes(2, "big")
    frame[40:44] = (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "big")
    frame[44] = 1
    frame[49:51] = (1).to_bytes(2, "big")
    frame[51:55] = len(payload).to_bytes(4, "big")
    frame += payload
    frame[3:5] = len(frame).to_bytes(2, "big")
    return bytes(frame)


class Downlink01CorruptTests(unittest.TestCase):
    def test_decrypts_and_corrupts_zip_then_rebuilds_valid_outer_frame(self):
        source = _frame()
        frames, detail = ace_corrupt_01_downlink_zip_frames([source])
        output = frames[0]

        self.assertTrue(detail["changed"])
        self.assertEqual(len(output), len(source))
        self.assertEqual(detail["filename"], "x.dat")
        self.assertEqual(detail["before"], ord("K"))
        self.assertEqual(detail["after"], ord("Z"))
        self.assertIsNotNone(_ace_01_frame_meta(output))
        self.assertNotEqual(output[40:44], source[40:44])

        logical = _ace_01_frame_meta(output)["data"]
        record = logical[20:]
        selector, key_index = record[0], record[1]
        stored_crc = int.from_bytes(record[2:6], "big")
        cipher_len = int.from_bytes(record[6:8], "big")
        plaintext = type9_transform(
            record[8:8 + cipher_len],
            selector,
            KEYS[key_index],
            direction=0,
        )
        self.assertEqual(zlib.crc32(plaintext) & 0xFFFFFFFF, stored_crc)
        self.assertIn(b"PZ\x03\x04", plaintext)
        self.assertNotIn(b"PK\x03\x04", plaintext)

    def test_invalid_or_empty_frame_is_left_unchanged(self):
        source = b"\x01\x00\x00\x00\x05"
        output, detail = ace_corrupt_01_downlink_zip_frames([source])
        self.assertEqual(output, [source])
        self.assertFalse(detail["changed"])

    def test_mrpcs_data_names_are_mutated_and_crc_stays_valid(self):
        source = _type9_frame(
            b"HEAD mrpcs_i_c.data MID MRPCS_I_V.data TAIL config2.dat"
        )
        frames, detail = ace_mutate_01_downlink_mrpcs_frames([source])
        output = frames[0]

        self.assertTrue(detail["changed"])
        self.assertEqual(detail["match_count"], 2)
        self.assertEqual(len(output), len(source))
        self.assertNotEqual(output[40:44], source[40:44])
        self.assertIsNotNone(_ace_01_frame_meta(output))
        verification = _ace_01_verify_frames([output])
        self.assertTrue(verification["ok"], verification["errors"])
        self.assertEqual(
            verification["crc_hex"], verification["calculated_crc_hex"]
        )
        self.assertTrue(detail["validation_ok"])
        self.assertTrue(detail["inner_crc_ok"])
        self.assertEqual(detail["outer_crc32"], detail["calculated_outer_crc32"])

        logical = _ace_01_frame_meta(output)["data"]
        record = next(iter(find_records(logical)))
        plaintext = type9_transform(
            record["ciphertext"],
            record["selector"],
            KEYS[record["key_index"]],
            direction=0,
        )
        self.assertEqual(
            zlib.crc32(plaintext) & 0xFFFFFFFF,
            record["stored_crc32"],
        )
        self.assertIn(b"mrpcs_i_c1data", plaintext)
        self.assertIn(b"MRPCS_I_V1data", plaintext)
        self.assertIn(b"config2.dat", plaintext)
        self.assertNotIn(b"mrpcs_i_c.data", plaintext)

    def test_mrpcs_rule_leaves_nonmatching_type9_unchanged(self):
        source = _type9_frame(b"HEAD config2.dat comm.zip TAIL")
        frames, detail = ace_mutate_01_downlink_mrpcs_frames([source])
        self.assertEqual(frames, [source])
        self.assertFalse(detail["changed"])
        self.assertEqual(detail["error"], "MRPCS_DATA_NOT_FOUND")

    def test_mrpcs_rule_also_mutates_type8_downlink_records(self):
        source = _type9_frame(
            b"HEAD mrpcs_i_v_tl.data unzipmrpcs.data TAIL",
            marker=b"\x01\x0A\x00\x08",
        )
        frames, detail = ace_mutate_01_downlink_mrpcs_frames([source])
        output = frames[0]

        self.assertTrue(detail["changed"])
        self.assertEqual(detail["match_count"], 2)
        self.assertEqual(detail["record_types"], ["08"])
        verification = _ace_01_verify_frames([output])
        self.assertTrue(verification["ok"], verification["errors"])

        logical = _ace_01_frame_meta(output)["data"]
        marker_offset = logical.index(b"\x01\x0A\x00\x08")
        record_offset = marker_offset + 14
        selector = logical[record_offset]
        key_index = logical[record_offset + 1]
        stored_crc = int.from_bytes(
            logical[record_offset + 2:record_offset + 6], "big"
        )
        cipher_len = int.from_bytes(
            logical[record_offset + 6:record_offset + 8], "big"
        )
        cipher_start = record_offset + 8
        plaintext = type9_transform(
            logical[cipher_start:cipher_start + cipher_len],
            selector,
            KEYS[key_index],
            direction=0,
        )
        self.assertEqual(zlib.crc32(plaintext) & 0xFFFFFFFF, stored_crc)
        self.assertIn(b"mrpcs_i_v_tl1data", plaintext)
        self.assertIn(b"unzipmrpcs1data", plaintext)


if __name__ == "__main__":
    unittest.main()
