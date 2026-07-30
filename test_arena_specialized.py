import json
import os
import tempfile
import unittest
import zlib
import sys
import types

try:
    import PySide6.QtCore  # type: ignore
except ModuleNotFoundError:
    class _Signal:
        def __init__(self, *args):
            pass

        def emit(self, *args):
            pass

        def connect(self, *args):
            pass

    class _QObject:
        pass

    pyside = types.ModuleType("PySide6")
    qtcore = types.ModuleType("PySide6.QtCore")
    qtcore.QObject = _QObject
    qtcore.Signal = _Signal
    pyside.QtCore = qtcore
    sys.modules["PySide6"] = pyside
    sys.modules["PySide6.QtCore"] = qtcore

from core.crypto import (
    ACE_FIRST_HEADER_LEN,
    ACE_NEXT_HEADER_LEN,
    MARKER_01_0A_00_09,
    AceReplayAssembler,
    _ace_try_extract,
    parse_ace_fragment,
    try_replace_3366_4013_plain,
)
from core.pool import RecordingPool
from core.protocol_3366 import merge_3366_product_registry
from core.managers import UserManager
from core.special_capture import SpecialCaptureManager


def make_record(selector: int, key_index: int, fill: int, size: int) -> bytes:
    cipher = bytes([fill]) * size
    return (
        bytes([selector, key_index])
        + (0x10203040 + fill).to_bytes(4, "big")
        + len(cipher).to_bytes(2, "big")
        + cipher
    )


def make_payload(record: bytes, *, tail: bytes = b"TAIL", pad_to: int = 0) -> bytes:
    identity = b"1234"
    payload = bytearray(50)
    payload[23] = len(identity)
    payload[24:28] = identity
    payload[36:40] = b"\x01\x0A\x00\x09"
    payload[40:50] = b"\x00" * 10
    payload.extend(record)
    payload.extend(tail)
    if len(payload) < pad_to:
        payload.extend(b"Z" * (pad_to - len(payload)))
    payload[4:6] = len(payload).to_bytes(2, "big")
    inner_len = len(payload) - 30
    payload[28:30] = inner_len.to_bytes(2, "big")
    payload[34:36] = inner_len.to_bytes(2, "big")
    return bytes(payload)


def make_frames(payload: bytes, *, group: int = 7, tag: int = 0xA7) -> list[bytes]:
    chunks = [payload[i:i + 4096] for i in range(0, len(payload), 4096)] or [b""]
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    frames = []
    for index, chunk in enumerate(chunks, 1):
        header_len = ACE_FIRST_HEADER_LEN if index == 1 else ACE_NEXT_HEADER_LEN
        header = bytearray(header_len)
        header[:3] = b"\x01\x00\x00"
        header[8:10] = (100 + index).to_bytes(2, "big")
        header[0x24:0x26] = group.to_bytes(2, "big")
        header[0x26:0x28] = len(chunks).to_bytes(2, "big")
        header[0x28:0x2C] = crc.to_bytes(4, "big")
        if index == 1:
            header[0x2C] = 1
            header[0x2D:0x2F] = (9).to_bytes(2, "big")
            header[0x2F] = tag
            header[0x31:0x33] = index.to_bytes(2, "big")
            header[0x33:0x37] = len(chunk).to_bytes(4, "big")
        else:
            header[0x2C] = 0
            header[0x2D:0x2F] = index.to_bytes(2, "big")
            header[0x2F:0x33] = len(chunk).to_bytes(4, "big")
        header[3:5] = (len(header) + len(chunk)).to_bytes(2, "big")
        frames.append(bytes(header) + chunk)
    return frames


def split_frames(stream: bytes) -> list[bytes]:
    out = []
    pos = 0
    while pos + 5 <= len(stream):
        length = int.from_bytes(stream[pos + 3:pos + 5], "big")
        out.append(stream[pos:pos + length])
        pos += length
    return out


class ArenaReplayTests(unittest.TestCase):
    def test_dual_capture_keeps_raw_chunks_streams_and_frames(self):
        def frame_3366(msg: bytes, payload: bytes) -> bytes:
            header = bytearray(16)
            header[:8] = b"\x33\x66\x00\x0B\x00\x0C" + msg
            header[9:13] = (1).to_bytes(4, "big")
            return bytes(header) + payload

        with tempfile.TemporaryDirectory() as temp_dir:
            capture = SpecialCaptureManager()
            root = capture.start("test", temp_dir)
            self.assertFalse(
                capture.open_connection(
                    "ignored",
                    username="other",
                    client_endpoint="127.0.0.2:1000",
                    remote_endpoint="TARGET:PORT",
                )
            )
            self.assertTrue(
                capture.open_connection(
                    "proxy-01",
                    username="test",
                    client_endpoint="127.0.0.1:1001",
                    remote_endpoint="TARGET:10001",
                    hostname="TARGET",
                )
            )
            frame01 = b"\x01\x00\x00\x00\x0BABCDEF"
            capture.record_chunk("proxy-01", "↑UP", frame01[:4])
            capture.record_chunk("proxy-01", "↑UP", frame01[4:])
            capture.close_connection("proxy-01")

            self.assertTrue(
                capture.open_connection(
                    "proxy-3366",
                    username="test",
                    client_endpoint="127.0.0.1:1002",
                    remote_endpoint="TARGET:3366",
                    hostname="TARGET",
                )
            )
            first3366 = frame_3366(b"\x10\x01", b"HELLO")
            second3366 = frame_3366(b"\x20\x01", b"WORLD")
            capture.record_chunk(
                "proxy-3366", "↑UP", first3366 + second3366
            )
            capture.close_connection("proxy-3366")
            self.assertEqual(capture.stop(), root)

            root_path = os.path.abspath(root)
            conn01 = os.path.join(
                root_path, "flows", "protocol-01", "conn-0001"
            )
            conn3366 = os.path.join(
                root_path, "flows", "protocol-3366", "conn-0002"
            )
            self.assertTrue(os.path.isdir(conn01))
            self.assertTrue(os.path.isdir(conn3366))
            with open(
                os.path.join(conn01, "chunks.jsonl"), encoding="utf-8"
            ) as f:
                chunks = [json.loads(line) for line in f if line.strip()]
            self.assertEqual([row["streamOffset"] for row in chunks], [0, 4])
            self.assertTrue(all(row["modified"] is False for row in chunks))
            with open(os.path.join(conn01, "c2s.raw.bin"), "rb") as f:
                self.assertEqual(f.read(), frame01)
            with open(
                os.path.join(conn01, "frames.jsonl"), encoding="utf-8"
            ) as f:
                frames01 = [json.loads(line) for line in f if line.strip()]
            self.assertEqual(len(frames01), 1)
            self.assertEqual(frames01[0]["sourceChunkIds"], [1, 2])
            with open(
                os.path.join(conn01, frames01[0]["rawFile"]), "rb"
            ) as f:
                self.assertEqual(f.read(), frame01)
            with open(
                os.path.join(conn3366, "frames.jsonl"), encoding="utf-8"
            ) as f:
                frames3366 = [json.loads(line) for line in f if line.strip()]
            self.assertEqual(frames3366[0]["messageTypeHex"], "1001")
            self.assertEqual(frames3366[0]["parseStatus"], "complete")
            self.assertTrue(os.path.isfile(os.path.join(root_path, "checksums.sha256")))
            with open(
                os.path.join(root_path, "integrity-report.json"), encoding="utf-8"
            ) as f:
                report = json.load(f)
            self.assertEqual(report["status"], "pass")
            self.assertTrue(report["rawForwardHashesMatch"])
            self.assertFalse(
                any(name.startswith("PyProxyTrafficLogs_") for name in os.listdir(temp_dir))
            )

    def test_user_manager_batch_delete(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = UserManager(os.path.join(temp_dir, "users.json"))
            manager._users = [
                {"username": "a", "password": "1"},
                {"username": "b", "password": "2"},
                {"username": "c", "password": "3"},
            ]
            manager.save()
            self.assertEqual(manager.remove_many(["a", "c", "missing"]), 2)
            self.assertEqual(
                [user["username"] for user in manager.all()],
                ["b"],
            )

    def test_product_registry_is_arena_only(self):
        registry = merge_3366_product_registry({
            "0000094E": {"name": "暗区专项"},
            "DEADBEEF": {"name": "其它产品", "decrypt": "other"},
        })
        self.assertEqual(set(registry), {"0000094E"})
        self.assertEqual(registry["0000094E"]["name"], "暗区专项")

    def test_type9_record_is_bounded(self):
        record = make_record(1, 4, 0x22, 32)
        frame = make_frames(make_payload(record, tail=b"AFTER_RECORD"))[0]
        item = _ace_try_extract(frame)
        self.assertIsNotNone(item)
        self.assertEqual(item["schema"], "tersafe-type9-clean-record-v2")
        self.assertEqual(item["payload"], record)
        self.assertNotIn(b"AFTER_RECORD", item["payload"])

    def test_crc_and_dynamic_header_are_rebuilt(self):
        live_record = make_record(0, 2, 0x11, 16)
        clean_record = make_record(2, 8, 0x33, 48)
        live_frames = make_frames(make_payload(live_record), tag=0xA7)
        pool = [{
            "payload": clean_record,
            "schema": "tersafe-type9-clean-record-v2",
            "account_id": "1234",
        }]
        index = [0, 0]
        output, replaced = AceReplayAssembler().feed(live_frames[0], pool, index)
        self.assertTrue(replaced)
        rebuilt_frames = split_frames(output)
        infos = [parse_ace_fragment(frame) for frame in rebuilt_frames]
        rebuilt_payload = b"".join(info["data"] for info in infos)
        self.assertEqual(infos[0]["transport_tag"], 0xA7)
        self.assertEqual(infos[0]["crc32"], zlib.crc32(rebuilt_payload) & 0xFFFFFFFF)
        self.assertIn(clean_record, rebuilt_payload)
        self.assertIn(b"TAIL", rebuilt_payload)
        self.assertEqual(index[0], 1)

    def test_multifragment_waits_then_rebuilds(self):
        live_record = make_record(0, 1, 0x44, 16)
        clean_record = make_record(1, 5, 0x55, 32)
        frames = make_frames(make_payload(live_record, pad_to=5000))
        assembler = AceReplayAssembler()
        pool = [{"payload": clean_record, "schema": "tersafe-type9-clean-record-v2"}]
        index = [0, 0]
        first_out, first_replaced = assembler.feed(frames[0], pool, index)
        self.assertEqual(first_out, b"")
        self.assertFalse(first_replaced)
        output, replaced = assembler.feed(frames[1], pool, index)
        self.assertTrue(replaced)
        rebuilt = split_frames(output)
        infos = [parse_ace_fragment(frame) for frame in rebuilt]
        payload = b"".join(info["data"] for info in infos)
        self.assertTrue(all(info["crc32"] == zlib.crc32(payload) & 0xFFFFFFFF for info in infos))
        self.assertEqual([info["fragment_number"] for info in infos], list(range(1, len(infos) + 1)))

    def test_multifragment_capture_creates_one_bounded_template(self):
        record = make_record(2, 7, 0x31, 64)
        frames = make_frames(make_payload(record, tail=b"TRAILER", pad_to=5000))
        pool = RecordingPool()
        pool.new_session("127.0.0.2")
        pool.append("127.0.0.2", frames[0])
        self.assertEqual(pool._sessions["127.0.0.2"][0]["pool_items"], [])
        pool.append("127.0.0.2", frames[1])
        items = pool._sessions["127.0.0.2"][0]["pool_items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["payload"], record)
        self.assertEqual(items[0]["fragment_count"], 2)

    def test_pool_cycles_in_recorded_order(self):
        live = make_frames(make_payload(make_record(0, 1, 0x66, 16)))[0]
        clean_first = make_record(0, 2, 0x77, 16)
        clean_second = make_record(1, 3, 0x88, 16)
        pool = [
            {"payload": clean_first, "schema": "tersafe-type9-clean-record-v2"},
            {"payload": clean_second, "schema": "tersafe-type9-clean-record-v2"},
        ]
        index = [0, 0]
        assembler = AceReplayAssembler()
        outputs = [assembler.feed(live, pool, index) for _ in range(3)]
        self.assertTrue(all(replaced for _output, replaced in outputs))
        rebuilt_payloads = []
        for output, _replaced in outputs:
            rebuilt_payloads.append(
                b"".join(
                    parse_ace_fragment(frame)["data"]
                    for frame in split_frames(output)
                )
            )
        self.assertIn(clean_first, rebuilt_payloads[0])
        self.assertIn(clean_second, rebuilt_payloads[1])
        self.assertIn(clean_first, rebuilt_payloads[2])
        self.assertEqual(index[0], 3)

    def test_3366_pool_cycles_in_recorded_order(self):
        plain = b"HEADER" + MARKER_01_0A_00_09 + (b"\x00" * 10) + b"LIVE"
        pool_33 = [
            {"payload": b"AAAA", "source": "3366_09"},
            {"payload": b"BBBB", "source": "3366_09"},
        ]
        index_09 = [0, 0]
        index_21 = [0, 0]
        index_01 = [0, 0]
        outputs = []
        for _ in range(3):
            output, replaced = try_replace_3366_4013_plain(
                plain,
                pool_33,
                [],
                index_09,
                index_21,
                index_01,
            )
            self.assertTrue(replaced)
            outputs.append(output)
        self.assertTrue(outputs[0].endswith(b"AAAA"))
        self.assertTrue(outputs[1].endswith(b"BBBB"))
        self.assertTrue(outputs[2].endswith(b"AAAA"))
        self.assertEqual(index_09, [3, 3])

    def test_new_recording_lifecycle_clears_old_pool(self):
        pool = RecordingPool()
        pool.new_session("127.0.0.1")
        frame = make_frames(make_payload(make_record(0, 1, 0x12, 16)))[0]
        pool.append("127.0.0.1", frame)
        pool._sessions["127.0.0.1"][0]["_ghost"] = False
        pool._sessions["127.0.0.1"][0]["game_id"] = "1234"
        pool.stop("127.0.0.1", force=True)
        self.assertTrue(pool._sessions["127.0.0.1"][0]["pool_items"])
        pool.new_session("127.0.0.1")
        self.assertEqual(len(pool._sessions["127.0.0.1"]), 1)
        self.assertEqual(pool._sessions["127.0.0.1"][0]["pool_items"], [])

    def test_new_join_packet_clears_pool_even_with_lingering_connection(self):
        pool = RecordingPool()
        pool.new_session("127.0.0.3")
        pool.note_join_packet("127.0.0.3", "old-conn")
        frame = make_frames(make_payload(make_record(0, 1, 0x18, 16)))[0]
        pool.append("127.0.0.3", frame)
        self.assertEqual(len(pool._sessions["127.0.0.3"][0]["pool_items"]), 1)
        changed = pool.note_join_packet("127.0.0.3", "new-conn")
        self.assertTrue(changed)
        self.assertEqual(pool._sessions["127.0.0.3"][0]["pool_items"], [])
        self.assertEqual(pool._sessions["127.0.0.3"][0]["_join_conn_id"], "new-conn")


if __name__ == "__main__":
    unittest.main()
