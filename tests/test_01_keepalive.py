import unittest
import zlib

from core.crypto import (
    ace_bump_01_keepalive_frame,
    ace_is_01_keepalive_template,
    ace_next_01_outer_ids,
    ace_read_01_outer_ids,
    ace_restamp_01_frame,
)


KEEPALIVE_105 = bytes.fromhex(
    "0100000069010000001262FD104D00000A92BC64816A805904000081CB83E3A6B38B"
    "0000000E0001009845C4010009A300000100000032000000010032010A0008"
    "000000000000000000000201B118064300161308173894453B88D60E42C323"
    "E526A1FB9244B85DC4"
)


class Ace01KeepaliveTests(unittest.TestCase):
    def test_sample_105_is_keepalive_template(self):
        self.assertEqual(len(KEEPALIVE_105), 105)
        self.assertTrue(ace_is_01_keepalive_template(KEEPALIVE_105))
        self.assertEqual(KEEPALIVE_105[40:44], b"\x00\x98\x45\xC4")
        self.assertEqual(
            zlib.crc32(KEEPALIVE_105[55:]) & 0xFFFFFFFF,
            0x009845C4,
        )

    def test_bump_advances_sequence_group_and_crc(self):
        bumped = ace_bump_01_keepalive_frame(KEEPALIVE_105)
        self.assertEqual(len(bumped), 105)
        self.assertEqual(int.from_bytes(bumped[6:10], "big"), 19)
        self.assertEqual(int.from_bytes(bumped[36:38], "big"), 15)
        self.assertEqual(
            bumped[40:44],
            (zlib.crc32(bumped[55:]) & 0xFFFFFFFF).to_bytes(4, "big"),
        )
        self.assertEqual(bumped[55:], KEEPALIVE_105[55:])
        self.assertEqual(bumped[18:34], KEEPALIVE_105[18:34])

    def test_rejects_zip_sized_downlink(self):
        huge = bytearray(KEEPALIVE_105)
        huge[3:5] = (400).to_bytes(2, "big")
        huge.extend(b"\x00" * 295)
        self.assertFalse(ace_is_01_keepalive_template(bytes(huge)))
        self.assertEqual(ace_bump_01_keepalive_frame(bytes(huge)), b"")

    def test_restamp_real_after_fake_does_not_overlap(self):
        fake = ace_bump_01_keepalive_frame(KEEPALIVE_105)
        self.assertEqual(ace_read_01_outer_ids(fake), (19, 15))
        ace_again = KEEPALIVE_105
        seq, group = ace_next_01_outer_ids(19, 15, bump_group=True)
        sent = ace_restamp_01_frame(ace_again, seq=seq, group=group)
        self.assertEqual(ace_read_01_outer_ids(sent), (20, 16))
        self.assertNotEqual(ace_read_01_outer_ids(sent), ace_read_01_outer_ids(fake))
        self.assertEqual(sent[55:], ace_again[55:])

    def test_same_ace_group_keeps_client_group(self):
        seq, group = ace_next_01_outer_ids(20, 16, bump_group=False)
        self.assertEqual((seq, group), (21, 16))

    def test_explicit_seq_on_keepalive_bump(self):
        bumped = ace_bump_01_keepalive_frame(KEEPALIVE_105, seq=100, group=7)
        self.assertEqual(ace_read_01_outer_ids(bumped), (100, 7))
        self.assertEqual(bumped[55:], KEEPALIVE_105[55:])


if __name__ == "__main__":
    unittest.main()
