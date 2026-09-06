import importlib
import json
import os
import sys
import tempfile
import types
import unittest
import zlib

from core.crypto import (
    _ace_01_verify_frames,
    _ace_01_frame_meta,
    _ace_01_reassemble_frames,
    _ace_try_extract,
    _ace_try_extract_frames,
    _ace_try_replay_template,
    _ace_try_replace,
    _ace_try_replace_frames,
)


def _record(selector: int, key_index: int, plain_crc: bytes, cipher: bytes) -> bytes:
    return (
        bytes([selector, key_index])
        + plain_crc
        + len(cipher).to_bytes(2, "big")
        + cipher
    )


def _frame(record: bytes, *, message_id: int, suffix: bytes = b"") -> bytes:
    logical = bytearray(70)
    logical += b"\x01\x0A\x00\x09"
    logical += b"\x00" * 10
    logical += record
    logical += suffix

    frame = bytearray(55)
    frame[0:3] = b"\x01\x00\x00"
    frame[38:40] = (1).to_bytes(2, "big")
    frame[44] = 1
    frame[45:47] = (9).to_bytes(2, "big")
    frame[47] = message_id
    frame[49:51] = (1).to_bytes(2, "big")
    frame += logical
    frame[3:5] = len(frame).to_bytes(2, "big")
    frame[51:55] = len(logical).to_bytes(4, "big")
    frame[40:44] = (zlib.crc32(logical) & 0xFFFFFFFF).to_bytes(4, "big")
    return bytes(frame)


def _frames(record: bytes, *, message_id: int, suffix: bytes = b"") -> list[bytes]:
    logical = bytearray(70)
    logical += b"\x01\x0A\x00\x09"
    logical += b"\x00" * 10
    logical += record
    logical += suffix
    crc = (zlib.crc32(logical) & 0xFFFFFFFF).to_bytes(4, "big")
    chunks = [logical[i:i + 4096] for i in range(0, len(logical), 4096)]
    out = []
    for idx, chunk in enumerate(chunks):
        if idx == 0:
            header = bytearray(55)
            header[44] = 1
            header[45:47] = (9).to_bytes(2, "big")
            header[47] = message_id
            header[49:51] = (1).to_bytes(2, "big")
            header[51:55] = len(chunk).to_bytes(4, "big")
        else:
            header = bytearray(51)
            header[44] = 0
            header[45:47] = (idx + 1).to_bytes(2, "big")
            header[47:51] = len(chunk).to_bytes(4, "big")
        header[0:3] = b"\x01\x00\x00"
        header[8:10] = (100 + idx).to_bytes(2, "big")
        header[36:38] = (7).to_bytes(2, "big")
        header[38:40] = len(chunks).to_bytes(2, "big")
        header[40:44] = crc
        frame = header + chunk
        frame[3:5] = len(frame).to_bytes(2, "big")
        out.append(bytes(frame))
    return out


def _template_frames(
    *,
    account_id: str,
    report_index: int,
    sequence: int,
    group: int,
    session_byte: int,
    message_id: int,
    cipher_byte: bytes,
    cipher_len: int = 128,
    fragment_size: int = 4096,
) -> list[bytes]:
    account = account_id.encode("ascii")
    record = _record(1, 4, b"\x11\x22\x33\x44", cipher_byte * cipher_len)
    logical = (
        b"\x00" * 5
        + b"\x01\x0A\x00\x23"
        + report_index.to_bytes(4, "big")
        + b"\x00" * 10
        + bytes([len(account)])
        + account
        + b"\x00"
        + b"\x01\x0A\x00\x09"
        + b"\x00" * 10
        + record
    )
    crc = (zlib.crc32(logical) & 0xFFFFFFFF).to_bytes(4, "big")
    chunks = [
        logical[i:i + fragment_size]
        for i in range(0, len(logical), fragment_size)
    ]
    out = []
    for idx, chunk in enumerate(chunks):
        if idx == 0:
            header = bytearray(55)
            header[44] = 1
            header[45:47] = (9).to_bytes(2, "big")
            header[47] = message_id
            header[49:51] = (1).to_bytes(2, "big")
            header[51:55] = len(chunk).to_bytes(4, "big")
        else:
            header = bytearray(51)
            header[44] = 0
            header[45:47] = (idx + 1).to_bytes(2, "big")
            header[47:51] = len(chunk).to_bytes(4, "big")
        header[0:3] = b"\x01\x00\x00"
        header[5:36] = bytes([session_byte]) * 31
        header[8:10] = ((sequence + idx) & 0xFFFF).to_bytes(2, "big")
        header[36:38] = group.to_bytes(2, "big")
        header[38:40] = len(chunks).to_bytes(2, "big")
        header[40:44] = crc
        frame = header + chunk
        frame[3:5] = len(frame).to_bytes(2, "big")
        out.append(bytes(frame))
    return out


class Ace01ReplayTests(unittest.TestCase):
    def test_extract_uses_ciphertext_length_not_frame_tail(self):
        encrypted = _record(1, 4, b"\x11\x22\x33\x44", b"C" * 32)
        packet = _frame(encrypted, message_id=0x70, suffix=b"TAIL-RECORD")

        item = _ace_try_extract(packet)

        self.assertIsNotNone(item)
        self.assertEqual(item["payload"], encrypted)
        self.assertEqual(item["encrypted_record"], encrypted)
        self.assertFalse(item["raw_packet"].endswith(b"TAIL-RECORD"))

    def test_replace_preserves_tail_recomputes_crc_and_uses_recorded_message_id(self):
        current = _record(0, 2, b"\xAA\xBB\xCC\xDD", b"A" * 20)
        clean = _record(2, 8, b"\x10\x20\x30\x40", b"B" * 28)
        suffix = b"ANOTHER-LIVE-RECORD"
        live_packet = _frame(current, message_id=0x2B, suffix=suffix)
        clean_packet = _frame(clean, message_id=0x88)
        clean_item = _ace_try_extract(clean_packet)
        self.assertIsNotNone(clean_item)

        details = []
        rebuilt, changed = _ace_try_replace(
            live_packet, [clean_item], [0, 0], on_log=details.append
        )

        self.assertTrue(changed)
        self.assertTrue(rebuilt.endswith(suffix))
        self.assertEqual(rebuilt[47], 0x88)
        self.assertEqual(int.from_bytes(rebuilt[3:5], "big"), len(rebuilt))
        self.assertEqual(int.from_bytes(rebuilt[51:55], "big"), len(rebuilt) - 55)
        expected_crc = zlib.crc32(rebuilt[55:]) & 0xFFFFFFFF
        self.assertEqual(int.from_bytes(rebuilt[40:44], "big"), expected_crc)
        self.assertNotEqual(rebuilt[40:44], clean_packet[40:44])
        self.assertEqual(details[0]["crc_hex"], f"{expected_crc:08X}")

    def test_multifragment_reassembles_replaces_and_recalculates_crc(self):
        current = _record(0, 1, b"\x01\x02\x03\x04", b"A" * 4300)
        clean = _record(2, 9, b"\x10\x20\x30\x40", b"B" * 4500)
        suffix = b"LIVE-TAIL-AFTER-TARGET"
        live_frames = _frames(current, message_id=0x2B, suffix=suffix)
        clean_frames = _frames(clean, message_id=0x70)
        clean_item = _ace_try_extract_frames(clean_frames)
        self.assertIsNotNone(clean_item)

        rebuilt, changed = _ace_try_replace_frames(
            live_frames, [clean_item], [0, 0]
        )

        self.assertTrue(changed)
        assembled = _ace_01_reassemble_frames(rebuilt)
        self.assertIsNotNone(assembled)
        ordered, logical = assembled
        self.assertTrue(logical.endswith(suffix))
        expected_crc = (zlib.crc32(logical) & 0xFFFFFFFF).to_bytes(4, "big")
        self.assertTrue(all(frame[40:44] == expected_crc for frame in ordered))
        self.assertEqual(ordered[0][47], 0x70)
        self.assertEqual(
            [(_ace_01_frame_meta(frame) or {})["fragment_number"] for frame in ordered],
            list(range(1, len(ordered) + 1)),
        )


class Ace01FullTemplateReplayTests(unittest.TestCase):
    def test_non_09_packet_is_forwarded_without_cursor_or_replace(self):
        clean = _template_frames(
            account_id="7792540774520990667",
            report_index=1,
            sequence=100,
            group=1,
            session_byte=0x15,
            message_id=0x70,
            cipher_byte=b"C",
        )
        item = _ace_try_extract_frames(clean)
        self.assertIsNotNone(item)
        for marker_type in (0x1D, 0x52):
            with self.subTest(marker_type=f"{marker_type:02X}"):
                live = bytearray(
                    _template_frames(
                        account_id="7792540774520990667",
                        report_index=0,
                        sequence=200,
                        group=1,
                        session_byte=0xA1,
                        message_id=0xD1,
                        cipher_byte=b"L",
                    )[0]
                )
                marker = live.find(b"\x01\x0A\x00\x09", 55)
                self.assertGreaterEqual(marker, 0)
                live[marker + 3] = marker_type
                live[40:44] = (
                    zlib.crc32(live[55:]) & 0xFFFFFFFF
                ).to_bytes(4, "big")
                live_frame = bytes(live)
                cursor = [0, 0]
                logs = []

                output, changed = _ace_try_replay_template(
                    [live_frame],
                    [item],
                    cursor,
                    expected_game_id="7792540774520990667",
                    on_log=logs.append,
                )

                self.assertFalse(changed)
                self.assertEqual(output, [live_frame])
                self.assertEqual(cursor, [0, 0])
                self.assertEqual(len(logs), 1)
                self.assertEqual(logs[0]["decision"], "PASS_NON_TARGET")
                self.assertEqual(logs[0]["reason"], "NO_01_0A_00_09")
                self.assertEqual(
                    logs[0]["marker_types"], sorted([f"{marker_type:02X}", "23"])
                )
                self.assertEqual(logs[0]["cursor_before"], 0)
                self.assertEqual(logs[0]["cursor_after"], 0)
                self.assertEqual(logs[0]["output_frames"], [live_frame])

    def test_type9_observe_cursor_never_changes_live_output(self):
        clean_a = _template_frames(
            account_id="933579391",
            report_index=4,
            sequence=100,
            group=5,
            session_byte=0x15,
            message_id=0x70,
            cipher_byte=b"A",
        )
        clean_b = _template_frames(
            account_id="933579391",
            report_index=5,
            sequence=101,
            group=6,
            session_byte=0x16,
            message_id=0x70,
            cipher_byte=b"B",
        )
        live = _template_frames(
            account_id="933579391",
            report_index=99,
            sequence=700,
            group=88,
            session_byte=0xA1,
            message_id=0x2B,
            cipher_byte=b"X",
        )
        pool = [
            _ace_try_extract_frames(clean_a),
            _ace_try_extract_frames(clean_b),
        ]
        self.assertTrue(all(pool))
        cursor = [0, 0]
        logs = []

        first, changed = _ace_try_replay_template(
            live,
            pool,
            cursor,
            expected_game_id="933579391",
            on_log=logs.append,
        )
        second, changed_2 = _ace_try_replay_template(
            live,
            pool,
            cursor,
            expected_game_id="933579391",
            on_log=logs.append,
        )
        wrapped, changed_3 = _ace_try_replay_template(
            live,
            pool,
            cursor,
            expected_game_id="933579391",
            on_log=logs.append,
        )

        self.assertFalse(changed or changed_2 or changed_3)
        self.assertEqual(first, live)
        self.assertEqual(second, live)
        self.assertEqual(wrapped, live)
        self.assertEqual([row["decision"] for row in logs], ["PASS_LIVE"] * 3)
        self.assertTrue(all(row["final_equals_live"] for row in logs))
        self.assertEqual([row["pool_idx"] for row in logs], [0, 1, 0])
        checked = _ace_01_verify_frames(
            first, expected_game_id="933579391"
        )
        self.assertTrue(checked["ok"])
        self.assertEqual(checked["report_index"], 99)

    def test_multifragment_live_is_forwarded_byte_for_byte(self):
        clean = _template_frames(
            account_id="GAME-42",
            report_index=6,
            sequence=100,
            group=7,
            session_byte=0x15,
            message_id=0x70,
            cipher_byte=b"C",
            cipher_len=600,
            fragment_size=160,
        )
        live = _template_frames(
            account_id="GAME-42",
            report_index=9,
            sequence=65534,
            group=12,
            session_byte=0xA1,
            message_id=0x2B,
            cipher_byte=b"L",
            cipher_len=180,
            fragment_size=4096,
        )
        item = _ace_try_extract_frames(clean)
        self.assertIsNotNone(item)

        output, changed = _ace_try_replay_template(
            live,
            [item],
            [0, 0],
            expected_game_id="GAME-42",
        )

        self.assertFalse(changed)
        self.assertEqual(output, live)
        checked = _ace_01_verify_frames(output, expected_game_id="GAME-42")
        self.assertTrue(checked["ok"])
        self.assertEqual(checked["report_index"], 9)

    def test_wrong_game_id_and_corrupt_template_still_pass_live(self):
        clean = _template_frames(
            account_id="RIGHT",
            report_index=4,
            sequence=100,
            group=5,
            session_byte=0x15,
            message_id=0x70,
            cipher_byte=b"C",
        )
        live = _template_frames(
            account_id="OTHER",
            report_index=4,
            sequence=200,
            group=8,
            session_byte=0xA1,
            message_id=0x2B,
            cipher_byte=b"L",
        )
        item = _ace_try_extract_frames(clean)
        self.assertIsNotNone(item)
        logs = []

        output, changed = _ace_try_replay_template(
            live,
            [item],
            [0, 0],
            expected_game_id="RIGHT",
            on_log=logs.append,
        )
        self.assertFalse(changed)
        self.assertEqual(output, live)
        self.assertEqual(logs[-1]["decision"], "PASS_LIVE")
        self.assertEqual(logs[-1]["reason"], "GAME_ID_MISMATCH_PASS_LIVE")

        corrupt = dict(item)
        bad_frame = bytearray(clean[0])
        bad_frame[-1] ^= 0xFF
        corrupt["template_frames"] = [bytes(bad_frame)]
        logs.clear()
        output, changed = _ace_try_replay_template(
            clean,
            [corrupt],
            [0, 0],
            expected_game_id="RIGHT",
            on_log=logs.append,
        )
        self.assertFalse(changed)
        self.assertEqual(output, clean)
        self.assertEqual(logs[-1]["decision"], "PASS_LIVE")
        self.assertEqual(logs[-1]["reason"], "NO_VALID_TEMPLATE_PASS_LIVE")
        self.assertIn("有效完整01模板", logs[-1]["validation_errors"][0])


class RecordingPoolJoinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # core.events depends on PySide6 in the desktop build. Pool behavior itself
        # only needs these signal-shaped methods, so tests provide small stubs.
        events = types.ModuleType("core.events")

        class Signal:
            def emit(self, *args, **kwargs):
                pass

        events.log_bus = types.SimpleNamespace(
            record_updated=Signal(),
            record_count=Signal(),
            conn_game_id_update=Signal(),
            conn_ace_channels_updated=Signal(),
            conn_3366_product=Signal(),
        )
        events._event = lambda *args, **kwargs: None
        sys.modules["core.events"] = events

        traffic = types.ModuleType("core.traffic_session_log")
        traffic.traffic_file_logger = types.SimpleNamespace()
        sys.modules["core.traffic_session_log"] = traffic

        sys.modules.pop("core.pool", None)
        cls.pool_module = importlib.import_module("core.pool")

    def test_42_join_clears_01_in_place_and_keeps_3366(self):
        pool = self.pool_module.RecordingPool()
        self.assertTrue(pool.new_session("127.0.0.1"))
        session = pool._active_session("127.0.0.1")
        old_01 = {"source": "01", "payload": b"old"}
        old_33 = {"source": "3366_09", "payload": b"keep"}
        session["pool_items"].extend([old_01, old_33])
        session["pool_01_items"].append(old_01)
        session["pool_33_items"].append(old_33)
        session["pkts"].append(b"old-raw")
        session["game_id"] = "OLD_UID"
        session["game_id_source"] = "01"
        session["ace_user_01"] = "OLD_UID"
        pool_ref = session["pool_01_items"]

        removed = pool.begin_01_join("127.0.0.1")

        self.assertEqual(removed, 1)
        self.assertIs(pool_ref, session["pool_01_items"])
        self.assertEqual(pool_ref, [])
        self.assertEqual(session["pool_items"], [old_33])
        self.assertEqual(session["pool_33_items"], [old_33])
        self.assertEqual(session["pkts"], [])
        self.assertEqual(session["ace_user_01"], "")
        self.assertEqual(session["game_id"], "")

    def test_new_session_uid_replaces_old_01_pool_instead_of_merging(self):
        pool = self.pool_module.RecordingPool()
        pool.new_session("10.0.0.1")
        old_session = pool._active_session("10.0.0.1")
        old_item = {"source": "01", "payload": b"old"}
        old_session["pool_items"].append(old_item)
        old_session["pool_01_items"].append(old_item)
        old_session["game_id"] = "USER42"
        old_session["game_id_source"] = "01"
        old_session["_ghost"] = False
        old_ref = old_session["pool_01_items"]
        pool.stop("10.0.0.1", force=True)

        pool.new_session("10.0.0.2")
        new_record = _record(1, 2, b"\x11\x22\x33\x44", b"N" * 32)
        packet = bytearray(_frame(new_record, message_id=0x66))
        packet[70:74] = b"\x0A\x00\x23\x00"
        packet[78] = len("USER42")
        packet[79:85] = b"USER42"
        packet[40:44] = (
            zlib.crc32(packet[55:]) & 0xFFFFFFFF
        ).to_bytes(4, "big")

        pool.append("10.0.0.2", bytes(packet))

        self.assertEqual(old_ref, [])
        replacement = pool.find_pool_by_game_id("USER42")
        self.assertIsNotNone(replacement)
        self.assertEqual(len(replacement["pool_01"]), 1)
        self.assertNotEqual(replacement["pool_01"][0]["payload"], b"old")
        self.assertEqual(
            replacement["pool_01"][0]["template_frames"],
            [bytes(packet)],
        )

    def test_recording_pool_reassembles_and_stores_multiframe_template(self):
        pool = self.pool_module.RecordingPool()
        pool.new_session("10.0.0.4")
        frames = _template_frames(
            account_id="MULTI-42",
            report_index=6,
            sequence=100,
            group=7,
            session_byte=0x15,
            message_id=0x70,
            cipher_byte=b"M",
            cipher_len=600,
            fragment_size=160,
        )

        for frame in frames:
            pool.append("10.0.0.4", frame)

        replacement = pool.find_pool_by_game_id("MULTI-42")
        self.assertIsNotNone(replacement)
        self.assertEqual(len(replacement["pool_01"]), 1)
        self.assertEqual(
            replacement["pool_01"][0]["template_frames"],
            frames,
        )

    def test_cross_account_pool_selects_latest_donor_and_excludes_33(self):
        pool = self.pool_module.RecordingPool()
        for ip, game_id, created_at in (
            ("10.0.0.10", "DONOR-OLD", 100.0),
            ("10.0.0.11", "DONOR-NEW", 200.0),
            ("10.0.0.12", "LIVE-USER", 300.0),
        ):
            pool.new_session(ip)
            session = pool._active_session(ip)
            item_01 = {"source": "01", "payload": game_id.encode("ascii")}
            item_33 = {"source": "3366_09", "payload": b"33"}
            session["game_id"] = game_id
            session["created_at"] = created_at
            session["_ghost"] = False
            session["pool_items"].extend([item_01, item_33])
            session["pool_01_items"].append(item_01)
            session["pool_33_items"].append(item_33)

        selected = pool.find_cross_account_01_pool("LIVE-USER")

        self.assertIsNotNone(selected)
        self.assertTrue(selected["cross_account"])
        self.assertEqual(selected["donor_game_id"], "DONOR-NEW")
        self.assertEqual(len(selected["pool_01"]), 1)
        self.assertEqual(selected["pool_33"], [])

    def test_player_only_pool_excludes_legacy_official_rows(self):
        pool = self.pool_module.RecordingPool()
        pool.new_session("10.0.0.20", "player-proxy", "player")
        personal_session = pool._active_session("10.0.0.20")
        personal_item = {"source": "01", "payload": b"personal"}
        personal_session.update({"game_id": "LIVE", "_ghost": False})
        personal_session["pool_items"].append(personal_item)
        personal_session["pool_01_items"].append(personal_item)

        pool.new_session("10.0.0.21", "legacy-proxy", "player")
        legacy_session = pool._active_session("10.0.0.21")
        legacy_item = {"source": "01", "payload": b"legacy-official"}
        legacy_session.update({
            "game_id": "DONOR",
            "_ghost": False,
            "pool_scope": "official",
            "published": True,
        })
        legacy_session["pool_items"].append(legacy_item)
        legacy_session["pool_01_items"].append(legacy_item)

        selected = pool.find_v129_01_pool("LIVE", client_version="1.117")

        self.assertIsNotNone(selected)
        self.assertEqual(selected["personal_01_count"], 1)
        self.assertEqual(selected["official_01_count"], 0)
        self.assertEqual(
            [item["template_scope"] for item in selected["pool_01"]],
            ["player"],
        )

    def test_v129_pool_exposes_cross_account_players_as_device_candidates(self):
        pool = self.pool_module.RecordingPool()
        for ip, game_id, created_at in (
            ("10.0.0.31", "CLEAN-ACCOUNT-A", 100.0),
            ("10.0.0.32", "CLEAN-ACCOUNT-B", 200.0),
        ):
            pool.new_session(ip, "proxy", "player")
            session = pool._active_session(ip)
            item_01 = {"source": "01", "payload": game_id.encode("ascii")}
            item_33 = {"source": "3366_09", "payload": b"private"}
            session.update(
                {
                    "game_id": game_id,
                    "created_at": created_at,
                    "_ghost": False,
                }
            )
            session["pool_items"].extend([item_01, item_33])
            session["pool_01_items"].append(item_01)
            session["pool_33_items"].append(item_33)

        selected = pool.find_v129_01_pool("NEW-ACCOUNT-SAME-DEVICE")

        self.assertIsNotNone(selected)
        self.assertTrue(selected["device_cross_account"])
        self.assertEqual(selected["pool_33"], [])
        self.assertEqual(len(selected["pool_01"]), 2)
        self.assertTrue(
            all(
                item.get("device_cross_account_candidate")
                for item in selected["pool_01"]
            )
        )
        self.assertEqual(
            {item["donor_game_id"] for item in selected["pool_01"]},
            {"CLEAN-ACCOUNT-A", "CLEAN-ACCOUNT-B"},
        )

    def test_default_pool_exposes_device_candidates_and_keeps_exact_33(self):
        pool = self.pool_module.RecordingPool()
        for ip, game_id in (
            ("10.0.0.41", "LIVE-ACCOUNT"),
            ("10.0.0.42", "OTHER-ACCOUNT"),
        ):
            pool.new_session(ip, "proxy", "player")
            session = pool._active_session(ip)
            item_01 = {"source": "01", "payload": game_id.encode("ascii")}
            item_33 = {"source": "3366_09", "payload": game_id.encode("ascii")}
            session.update({"game_id": game_id, "_ghost": False})
            session["pool_items"].extend([item_01, item_33])
            session["pool_01_items"].append(item_01)
            session["pool_33_items"].append(item_33)

        selected = pool.find_v129_01_pool("LIVE-ACCOUNT")

        self.assertIsNotNone(selected)
        self.assertTrue(selected.get("device_cross_account", False))
        self.assertTrue(selected["pool_33"])
        self.assertEqual(
            {item.get("donor_game_id") for item in selected["pool_01"]},
            {"LIVE-ACCOUNT", "OTHER-ACCOUNT"},
        )
        self.assertEqual(
            selected["pool_33"][0]["payload"], b"LIVE-ACCOUNT"
        )

    def test_player_recording_is_persisted_and_restored_automatically(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = self.pool_module.RecordingPool()
            pool._snapshot_path = os.path.join(temp_dir, "players.json")
            pool.new_session("10.0.0.30", "normal-player", "player")
            session = pool._active_session("10.0.0.30")
            player_item = {"source": "01", "payload": b"clean-player"}
            session.update({"game_id": "PLAYER-DONOR", "_ghost": False})
            session["pool_items"].append(player_item)
            session["pool_01_items"].append(player_item)

            pool.stop("10.0.0.30", force=True)
            self.assertTrue(os.path.isfile(pool._snapshot_path))

            restored = self.pool_module.RecordingPool()
            restored._snapshot_path = pool._snapshot_path
            ok, _ = restored.load_snapshot()
            self.assertTrue(ok)
            selected = restored.find_v129_01_pool("PLAYER-DONOR")
            self.assertIsNotNone(selected)
            self.assertEqual(selected["official_01_count"], 0)
            self.assertEqual(
                selected["pool_01"][0]["payload"], b"clean-player"
            )
            self.assertEqual(
                selected["pool_01"][0]["template_scope"], "player"
            )

    def test_v5_export_import_keeps_full_template_frames(self):
        pool = self.pool_module.RecordingPool()
        pool.new_session("10.0.0.3")
        session = pool._active_session("10.0.0.3")
        frames = _template_frames(
            account_id="EXPORT-42",
            report_index=8,
            sequence=100,
            group=7,
            session_byte=0x15,
            message_id=0x70,
            cipher_byte=b"E",
            cipher_len=500,
            fragment_size=160,
        )
        item = _ace_try_extract_frames(frames)
        self.assertIsNotNone(item)
        session["game_id"] = "EXPORT-42"
        session["game_id_source"] = "01"
        session["_ghost"] = False
        session["pool_items"].append(item)
        session["pool_01_items"].append(item)

        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "recording.json")
            ok, _ = pool.export_to_file(path)
            self.assertTrue(ok)
            restored = self.pool_module.RecordingPool()
            ok, _ = restored.import_from_file(path)
            self.assertTrue(ok)

        replay_pool = restored.find_pool_by_game_id("EXPORT-42")
        self.assertIsNotNone(replay_pool)
        self.assertEqual(
            replay_pool["pool_01"][0]["template_frames"],
            frames,
        )

    def test_old_official_package_is_not_loaded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            legacy_path = os.path.join(temp_dir, "official", "templates.json")
            os.makedirs(os.path.dirname(legacy_path), exist_ok=True)
            with open(legacy_path, "w", encoding="utf-8") as stream:
                stream.write('{"sessions": {"10.0.0.11": []}}')

            restored = self.pool_module.RecordingPool()
            restored._snapshot_path = os.path.join(temp_dir, "players.json")
            ok, msg = restored.load_snapshot()
            self.assertTrue(ok)
            self.assertIn("尚未创建", msg)
            self.assertIsNone(restored.find_v129_01_pool("NEW-PLAYER"))


if __name__ == "__main__":
    unittest.main()
