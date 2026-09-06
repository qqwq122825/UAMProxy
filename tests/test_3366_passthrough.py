from __future__ import annotations

import unittest

from core.protocol_3366 import Conn3366State, feed_3366_stream


def _frame(msg: bytes, payload: bytes) -> bytes:
    return (
        b"\x33\x66\x00\x0B\x00\x0C"
        + msg
        + b"\x00" * 8
        + payload
    )


class Dfm3366PassthroughTests(unittest.TestCase):
    def test_detection_framing_does_not_extract_key_or_product(self):
        state = Conn3366State()
        first = _frame(b"\x10\x02", bytes(range(64)))
        second = _frame(b"\x40\x13", b"payload")

        detected = feed_3366_stream(state, first + second)

        self.assertEqual(detected, [first])
        self.assertIsNone(state.key)
        self.assertIsNone(state.iv)
        self.assertIsNone(state.product_name)
        self.assertIsNone(state.product_hex)


if __name__ == "__main__":
    unittest.main()
