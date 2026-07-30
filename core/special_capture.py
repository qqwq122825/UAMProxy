"""01/3366 双协议只读采集器。

采集点位于代理 ``reader.read`` 后、任何解析和改写之前。每次读取保存为独立
chunk，同时维护连接方向字节流，并由独立状态机切出完整 01/3366 帧。该模块
不参与转发数据的构造，采集失败也不会改变网络流量。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from core.crypto import parse_ace_fragment
from core.protocol_3366 import (
    MSG_DATA,
    MSG_SERVER_KEY,
    TAES_FIXED_IV,
    _find_valid_magic,
    find_embedded_product_id,
    parse_3366_header,
    try_decrypt_4013_frame,
    try_extract_key_iv_from_first_downlink,
)


MARKERS = (
    b"\x01\x0A\x00\x09",
    b"\x01\x0A\x00\x21",
    b"\x01\x0A\x00\x23",
    b"\x08\x10\x00\x03",
)
MAX_UNCLASSIFIED_PARSE_BYTES = 1024 * 1024


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now_pair() -> tuple[int, int]:
    return time.time_ns(), time.monotonic_ns()


def _json_dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.replace(tmp, path)


def _append_jsonl(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")


@dataclass
class _Connection:
    proxy_id: str
    connection_id: str
    username: str
    client_endpoint: str
    remote_endpoint: str
    hostname: str
    base_dir: Path
    connect_unix_ns: int
    connect_mono_ns: int
    classification: str = "unknown"
    classification_reason: str = "waiting for protocol magic"
    sequence: int = 0
    bytes_by_dir: dict[str, int] = field(
        default_factory=lambda: {"c2s": 0, "s2c": 0}
    )
    chunks_by_dir: dict[str, list[dict]] = field(
        default_factory=lambda: {"c2s": [], "s2c": []}
    )
    parse_buf: dict[str, bytearray] = field(
        default_factory=lambda: {"c2s": bytearray(), "s2c": bytearray()}
    )
    parse_base: dict[str, int] = field(
        default_factory=lambda: {"c2s": 0, "s2c": 0}
    )
    frame_count: dict[str, int] = field(
        default_factory=lambda: {"c2s": 0, "s2c": 0}
    )
    logical_count: int = 0
    logical_groups: dict[tuple, dict] = field(default_factory=dict)
    key: bytes | None = None
    iv: bytes | None = None
    key_source: dict | None = None
    seen_complete_downlink_1002: bool = False
    closed: bool = False


class SpecialCaptureManager:
    """进程级专项采集会话。所有公开方法均可由双向转发协程并发调用。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._root: Path | None = None
        self._target_user = "test"
        self._session_id = ""
        self._start_unix_ns = 0
        self._start_mono_ns = 0
        self._next_connection = 0
        self._connections: dict[str, _Connection] = {}
        self._totals = {
            "connections": 0,
            "chunks": 0,
            "frames01": 0,
            "frames3366": 0,
            "logicalMessages": 0,
            "rawBytes": 0,
            "c2sBytes": 0,
            "s2cBytes": 0,
        }

    @property
    def root_path(self) -> str | None:
        with self._lock:
            return str(self._root) if self._root else None

    def start(self, target_user: str, base_dir: str | None = None) -> str:
        with self._lock:
            if self._root:
                return str(self._root)
            unix_ns, mono_ns = _now_pair()
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            self._session_id = f"clean-{stamp}"
            self._target_user = target_user.strip() or "test"
            self._start_unix_ns = unix_ns
            self._start_mono_ns = mono_ns
            self._next_connection = 0
            self._connections.clear()
            for key in self._totals:
                self._totals[key] = 0

            root_base = Path(base_dir or os.getcwd())
            self._root = root_base / f"capture-{self._session_id}"
            (self._root / "flows" / "pending").mkdir(parents=True, exist_ok=True)
            (self._root / "flows" / "protocol-01").mkdir(parents=True, exist_ok=True)
            (self._root / "flows" / "protocol-3366").mkdir(parents=True, exist_ok=True)
            (self._root / "unclassified").mkdir(parents=True, exist_ok=True)
            (self._root / "network").mkdir(parents=True, exist_ok=True)

            _json_dump(
                self._root / "session.json",
                {
                    "schemaVersion": 1,
                    "sessionId": self._session_id,
                    "captureStartUnixNs": unix_ns,
                    "captureStartMonotonicNs": mono_ns,
                    "captureEndUnixNs": None,
                    "captureEndMonotonicNs": None,
                    "timezone": "Asia/Shanghai",
                    "deviceAlias": "DEVICE_A",
                    "accountAlias": "ACCOUNT_A",
                    "accountStateBefore": "normal",
                    "gameVersion": "GAME_VERSION",
                    "bundleId": "BUNDLE_ID",
                    "networkMode": "socks5-proxy",
                    "captureDirections": ["c2s", "s2c"],
                    "proxyVersion": "UAMProxy",
                    "trafficModified": False,
                    "replacementEnabled": False,
                    "lldbAttached": False,
                    "rawTap": "before_parse_and_forward",
                    "captureProtocols": ["01", "3366"],
                    "samples": {
                        "tersafeUUID": "F3C6779D-9098-3F23-ABB7-CF16682B7793",
                        "UAGameUUID": "A7BACCFE-E360-3859-BCAA-CB7C500B5D6A",
                        "GCloudUUID": "CBEE50AB-686C-380B-B764-16FCD7DBEE2F",
                    },
                    "pcapngAvailable": False,
                    "pcapngNote": "SOCKS5 application proxy has no TCP sequence/UDP packet tap",
                    "scenario": [
                        "cold_start",
                        "login",
                        "lobby",
                        "matchmaking",
                        "loading",
                        "in_match",
                        "settlement",
                        "return_lobby",
                    ],
                    "notes": "完整保存代理可见的原始chunk、方向字节流和协议帧。",
                },
            )
            self._append_timeline_locked("phase", "capture_start", "专项采集启动")
            (self._root / "dns.jsonl").touch()
            (self._root / "anomalies.jsonl").touch()
            (self._root / "capture.log").write_text(
                f"{datetime.now().isoformat()} capture started accountAlias=ACCOUNT_A\n",
                encoding="utf-8",
            )
            return str(self._root)

    def mark_timeline(self, phase: str, note: str = "") -> bool:
        with self._lock:
            if not self._root:
                return False
            event = "action" if phase in {
                "first_move", "first_shot", "first_hit", "first_kill"
            } else "phase"
            self._append_timeline_locked(event, phase, note)
            return True

    def _append_timeline_locked(self, event: str, value: str, note: str) -> None:
        if not self._root:
            return
        unix_ns, mono_ns = _now_pair()
        row = {
            "event": event,
            event: value,
            "timestampUnixNs": unix_ns,
            "timestampMonotonicNs": mono_ns,
            "note": note,
        }
        _append_jsonl(self._root / "timeline.jsonl", row)

    def open_connection(
        self,
        proxy_conn_id: str,
        *,
        username: str,
        client_endpoint: str,
        remote_endpoint: str,
        hostname: str = "",
    ) -> bool:
        with self._lock:
            if not self._root or username != self._target_user:
                return False
            if proxy_conn_id in self._connections:
                return True
            self._next_connection += 1
            connection_id = f"conn-{self._next_connection:04d}"
            base = self._root / "flows" / "pending" / connection_id
            for name in ("chunks", "frames", "logical-messages"):
                (base / name).mkdir(parents=True, exist_ok=True)
            for name in (
                "chunks.jsonl",
                "frames.jsonl",
                "c2s.raw.bin",
                "s2c.raw.bin",
            ):
                (base / name).touch()
            unix_ns, mono_ns = _now_pair()
            state = _Connection(
                proxy_id=proxy_conn_id,
                connection_id=connection_id,
                username=username,
                client_endpoint=client_endpoint,
                remote_endpoint=remote_endpoint,
                hostname=hostname,
                base_dir=base,
                connect_unix_ns=unix_ns,
                connect_mono_ns=mono_ns,
            )
            self._connections[proxy_conn_id] = state
            self._totals["connections"] += 1
            self._write_connection_locked(state)
            self._log_locked(
                f"open {connection_id} {client_endpoint} -> {remote_endpoint}"
            )
            return True

    def has_connection(self, proxy_conn_id: str) -> bool:
        with self._lock:
            state = self._connections.get(proxy_conn_id)
            return bool(state and not state.closed)

    def record_chunk(self, proxy_conn_id: str, direction: str, data: bytes) -> None:
        """RAW_TAP：保存每次非空 socket read，随后把副本交给独立解析器。"""
        if not data:
            return
        canonical_dir = "c2s" if direction in ("↑UP", "c2s") else "s2c"
        with self._lock:
            state = self._connections.get(proxy_conn_id)
            if not state or state.closed:
                return
            unix_ns, mono_ns = _now_pair()
            state.sequence += 1
            chunk_id = state.sequence
            offset = state.bytes_by_dir[canonical_dir]
            payload = bytes(data)
            digest = _sha256(payload)
            rel_file = (
                f"chunks/chunk-{chunk_id:06d}.{canonical_dir}.bin"
            )
            (state.base_dir / rel_file).write_bytes(payload)
            with (state.base_dir / f"{canonical_dir}.raw.bin").open("ab") as f:
                f.write(payload)
            row = {
                "schemaVersion": 1,
                "chunkId": chunk_id,
                "sequence": chunk_id,
                "timestampUnixNs": unix_ns,
                "timestampMonotonicNs": mono_ns,
                "connectionId": state.connection_id,
                "direction": canonical_dir,
                "transport": "tcp",
                "streamOffset": offset,
                "payloadLength": len(payload),
                "payloadSha256": digest,
                "rawFile": rel_file,
                "previewHex": payload[:32].hex(),
                "scenarioPhase": "unknown",
                "source": "proxy_recv",
                "forwardedLength": len(payload),
                "forwardedSha256": digest,
                "modified": False,
            }
            _append_jsonl(state.base_dir / "chunks.jsonl", row)
            state.chunks_by_dir[canonical_dir].append(
                {
                    "start": offset,
                    "end": offset + len(payload),
                    "chunkId": chunk_id,
                    "unixNs": unix_ns,
                    "monoNs": mono_ns,
                }
            )
            state.bytes_by_dir[canonical_dir] += len(payload)
            state.parse_buf[canonical_dir].extend(payload)
            self._totals["chunks"] += 1
            self._totals["rawBytes"] += len(payload)
            self._totals[f"{canonical_dir}Bytes"] += len(payload)

            if state.classification == "unknown":
                self._try_classify_locked(state)
            if state.classification != "unknown":
                self._parse_available_locked(state, canonical_dir)
            elif len(state.parse_buf[canonical_dir]) > MAX_UNCLASSIFIED_PARSE_BYTES:
                trim = len(state.parse_buf[canonical_dir]) - MAX_UNCLASSIFIED_PARSE_BYTES
                del state.parse_buf[canonical_dir][:trim]
                state.parse_base[canonical_dir] += trim

    def _try_classify_locked(self, state: _Connection) -> None:
        candidates: list[tuple[int, str, str]] = []
        for direction in ("c2s", "s2c"):
            buf = state.parse_buf[direction]
            fp3366 = _find_valid_magic(buf, 0)
            if 0 <= fp3366 <= 64:
                candidates.append(
                    (fp3366, "protocol-3366", "stream starts with valid 3366 header")
                )
            fp01 = bytes(buf).find(b"\x01\x00")
            if 0 <= fp01 <= 64 and len(buf) >= fp01 + 5:
                declared = int.from_bytes(buf[fp01 + 3:fp01 + 5], "big")
                if 5 <= declared <= 65535:
                    candidates.append(
                        (fp01, "protocol-01", "stream starts with 01 frame header")
                    )
        if not candidates:
            return
        _, classification, reason = sorted(candidates, key=lambda x: x[0])[0]
        self._classify_locked(state, classification, reason)
        for direction in ("c2s", "s2c"):
            self._parse_available_locked(state, direction)

    def _classify_locked(
        self, state: _Connection, classification: str, reason: str
    ) -> None:
        if not self._root or state.classification != "unknown":
            return
        destination = self._root / "flows" / classification / state.connection_id
        destination.parent.mkdir(parents=True, exist_ok=True)
        if state.base_dir != destination:
            if destination.exists():
                shutil.rmtree(destination)
            shutil.move(str(state.base_dir), str(destination))
            state.base_dir = destination
        state.classification = classification
        state.classification_reason = reason
        self._write_connection_locked(state)
        self._log_locked(f"classify {state.connection_id} -> {classification}")

    def _parse_available_locked(self, state: _Connection, direction: str) -> None:
        if state.classification == "protocol-01":
            self._parse_01_locked(state, direction)
        elif state.classification == "protocol-3366":
            self._parse_3366_locked(state, direction)

    def _parse_01_locked(self, state: _Connection, direction: str) -> None:
        buf = state.parse_buf[direction]
        while True:
            marker = bytes(buf).find(b"\x01\x00")
            if marker < 0:
                if len(buf) > 1:
                    drop = len(buf) - 1
                    del buf[:drop]
                    state.parse_base[direction] += drop
                return
            if marker:
                del buf[:marker]
                state.parse_base[direction] += marker
            if len(buf) < 5:
                return
            frame_len = int.from_bytes(buf[3:5], "big")
            if frame_len < 5 or frame_len > 65535:
                del buf[:1]
                state.parse_base[direction] += 1
                continue
            if len(buf) < frame_len:
                return
            offset = state.parse_base[direction]
            frame = bytes(buf[:frame_len])
            del buf[:frame_len]
            state.parse_base[direction] += frame_len
            self._write_frame_locked(
                state, direction, offset, frame, "complete", "01"
            )

    def _parse_3366_locked(self, state: _Connection, direction: str) -> None:
        buf = state.parse_buf[direction]
        while True:
            marker = _find_valid_magic(buf, 0)
            if marker < 0:
                if len(buf) > 7:
                    drop = len(buf) - 7
                    del buf[:drop]
                    state.parse_base[direction] += drop
                return
            if marker:
                del buf[:marker]
                state.parse_base[direction] += marker
            if len(buf) < 16:
                return
            nxt = _find_valid_magic(buf, 2)
            if nxt < 0:
                return
            offset = state.parse_base[direction]
            frame = bytes(buf[:nxt])
            del buf[:nxt]
            state.parse_base[direction] += nxt
            self._write_frame_locked(
                state, direction, offset, frame, "complete", "3366"
            )

    def _source_chunks(
        self, state: _Connection, direction: str, offset: int, length: int
    ) -> tuple[list[int], int, int]:
        end = offset + length
        hits = [
            item for item in state.chunks_by_dir[direction]
            if item["start"] < end and item["end"] > offset
        ]
        if not hits:
            unix_ns, mono_ns = _now_pair()
            return [], unix_ns, mono_ns
        return (
            [item["chunkId"] for item in hits],
            hits[0]["unixNs"],
            hits[0]["monoNs"],
        )

    def _write_frame_locked(
        self,
        state: _Connection,
        direction: str,
        offset: int,
        frame: bytes,
        parse_status: str,
        protocol: str,
    ) -> None:
        state.frame_count[direction] += 1
        frame_index = sum(state.frame_count.values())
        frame_id = (
            f"{'01' if protocol == '01' else '3366'}-"
            f"{state.connection_id[-4:]}-F{frame_index:06d}"
        )
        rel_raw = f"frames/frame-{frame_index:06d}.raw.bin"
        (state.base_dir / rel_raw).write_bytes(frame)
        source_ids, first_unix, first_mono = self._source_chunks(
            state, direction, offset, len(frame)
        )
        last_mono = first_mono
        if source_ids:
            by_id = {
                item["chunkId"]: item
                for item in state.chunks_by_dir[direction]
            }
            last_mono = by_id[source_ids[-1]]["monoNs"]
        base = {
            "schemaVersion": 1,
            "frameId": frame_id,
            "connectionId": state.connection_id,
            "frameIndex": frame_index,
            "direction": direction,
            "firstTimestampUnixNs": first_unix,
            "firstTimestampMonotonicNs": first_mono,
            "lastTimestampMonotonicNs": last_mono,
            "streamOffset": offset,
            "frameLength": len(frame),
            "sourceChunkIds": source_ids,
            "rawFile": rel_raw,
            "rawSha256": _sha256(frame),
            "protocol": protocol,
            "parseStatus": parse_status,
            "scenarioPhase": "unknown",
            "markers": [m.hex() for m in MARKERS if m in frame],
        }
        if protocol == "01":
            self._totals["frames01"] += 1
            self._decorate_01_locked(state, frame_id, frame, base)
        else:
            self._totals["frames3366"] += 1
            self._decorate_3366_locked(state, direction, frame_id, frame, base)
        _append_jsonl(state.base_dir / "frames.jsonl", base)

    def _decorate_01_locked(
        self, state: _Connection, frame_id: str, frame: bytes, row: dict
    ) -> None:
        fragment = parse_ace_fragment(frame)
        payload_offset = fragment["header_len"] if fragment else 5
        payload = frame[payload_offset:]
        row.update(
            {
                "magicHex": frame[:3].hex() if len(frame) >= 3 else frame.hex(),
                "outerType": frame[2] if len(frame) > 2 else None,
                "declaredLength": (
                    int.from_bytes(frame[3:5], "big") if len(frame) >= 5 else None
                ),
                "sequenceNumber": (
                    int.from_bytes(frame[8:10], "big") if len(frame) >= 10 else None
                ),
                "containerType": fragment["payload_type"] if fragment else None,
                "fragmentIndex": fragment["fragment_number"] if fragment else None,
                "fragmentCount": fragment["fragment_count"] if fragment else None,
                "payloadOffset": payload_offset,
                "payloadLength": len(payload),
                "payloadSha256": _sha256(payload),
                "decryptStatus": "not_attempted",
                "plaintextFile": None,
                "plaintextSha256": None,
            }
        )
        if not fragment:
            return
        key = (
            row["direction"],
            fragment["packet_group"],
            fragment["fragment_count"],
            fragment["crc32"],
        )
        group = state.logical_groups.setdefault(
            key,
            {
                "expected": fragment["fragment_count"],
                "fragments": {},
                "frameIds": {},
                "payloadType": fragment["payload_type"],
            },
        )
        if fragment["payload_type"] is not None:
            group["payloadType"] = fragment["payload_type"]
        n = fragment["fragment_number"]
        group["fragments"][n] = fragment["data"]
        group["frameIds"][n] = frame_id
        if len(group["fragments"]) != group["expected"]:
            return
        ordered_numbers = range(1, group["expected"] + 1)
        if any(n not in group["fragments"] for n in ordered_numbers):
            return
        logical = b"".join(group["fragments"][n] for n in ordered_numbers)
        state.logical_count += 1
        idx = state.logical_count
        rel = f"logical-messages/message-{idx:06d}.bin"
        (state.base_dir / rel).write_bytes(logical)
        _append_jsonl(
            state.base_dir / "logical-messages.jsonl",
            {
                "schemaVersion": 1,
                "messageId": f"{state.connection_id}-M{idx:06d}",
                "connectionId": state.connection_id,
                "direction": row["direction"],
                "frameIds": [group["frameIds"][n] for n in ordered_numbers],
                "packetGroup": fragment["packet_group"],
                "fragmentCount": group["expected"],
                "payloadType": group["payloadType"],
                "length": len(logical),
                "sha256": _sha256(logical),
                "rawFile": rel,
                "markers": [m.hex() for m in MARKERS if m in logical],
                "parseStatus": "complete",
            },
        )
        self._totals["logicalMessages"] += 1
        state.logical_groups.pop(key, None)

    def _decorate_3366_locked(
        self,
        state: _Connection,
        direction: str,
        frame_id: str,
        frame: bytes,
        row: dict,
    ) -> None:
        info = parse_3366_header(frame)
        msg = info["msg"] if info else b""
        if (
            direction == "s2c"
            and msg == MSG_SERVER_KEY
            and row["parseStatus"] == "complete"
        ):
            state.seen_complete_downlink_1002 = True
        product = find_embedded_product_id(frame)
        row.update(
            {
                "magicHex": frame[:2].hex(),
                "messageTypeHex": msg.hex() if msg else None,
                "productIdHex": product[0].hex() if product else None,
                "declaredLength": None,
                "framing": "next_valid_magic",
                "sessionId": None,
                "sequenceNumber": info["seq"] if info else None,
                "encrypted": msg == MSG_DATA,
                "ciphertextOffset": None,
                "ciphertextLength": None,
                "ciphertextFile": None,
                "ciphertextSha256": None,
                "decryptStatus": "not_encrypted" if msg != MSG_DATA else "key_unavailable",
                "plaintextFile": None,
                "plaintextSha256": None,
            }
        )
        if (
            direction == "s2c"
            and msg == MSG_SERVER_KEY
            and state.key is None
        ):
            pair = try_extract_key_iv_from_first_downlink(frame)
            if pair:
                state.key, state.iv = pair
                state.key_source = {
                    "frameId": frame_id,
                    "direction": direction,
                    "messageTypeHex": "1002",
                    "payloadOffset": 7,
                    "frameOffset": 23,
                    "length": 16,
                }
                self._write_crypto_locked(state)

        if msg != MSG_DATA or len(frame) < 25:
            return
        enc_len = int.from_bytes(frame[19:21], "big")
        if enc_len <= 0 or enc_len % 16 or 25 + enc_len > len(frame):
            row["decryptStatus"] = "ciphertext_layout_invalid"
            return
        ciphertext = frame[25:25 + enc_len]
        frame_index = row["frameIndex"]
        rel_cipher = f"frames/frame-{frame_index:06d}.ciphertext.bin"
        (state.base_dir / rel_cipher).write_bytes(ciphertext)
        row.update(
            {
                "ciphertextOffset": 25,
                "ciphertextLength": len(ciphertext),
                "ciphertextFile": rel_cipher,
                "ciphertextSha256": _sha256(ciphertext),
            }
        )
        if not state.key or not state.iv:
            return
        plaintext = try_decrypt_4013_frame(frame, state.key, state.iv)
        if plaintext is None:
            row["decryptStatus"] = "failed"
            return
        rel_plain = f"frames/frame-{frame_index:06d}.plaintext.bin"
        (state.base_dir / rel_plain).write_bytes(plaintext)
        row.update(
            {
                "decryptStatus": "success",
                "plaintextFile": rel_plain,
                "plaintextSha256": _sha256(plaintext),
                "markers": sorted(
                    set(row["markers"])
                    | {m.hex() for m in MARKERS if m in plaintext}
                ),
            }
        )

    def _write_crypto_locked(self, state: _Connection) -> None:
        if not state.key or not state.iv:
            return
        _json_dump(
            state.base_dir / "crypto.json",
            {
                "schemaVersion": 1,
                "connectionId": state.connection_id,
                "algorithm": "AES-128-CBC",
                "keySource": state.key_source,
                "keyHex": state.key.hex(),
                "ivSource": (
                    "fixed"
                    if state.iv == TAES_FIXED_IV
                    else "session"
                ),
                "ivHex": state.iv.hex(),
                "validatedByRoundTrip": False,
            },
        )

    def _write_connection_locked(
        self,
        state: _Connection,
        *,
        close_reason: str | None = None,
        close_unix_ns: int | None = None,
        close_mono_ns: int | None = None,
    ) -> None:
        _json_dump(
            state.base_dir / "connection.json",
            {
                "schemaVersion": 1,
                "connectionId": state.connection_id,
                "classification": state.classification,
                "classificationReason": state.classification_reason,
                "transport": "tcp",
                "ipVersion": 6 if ":" in state.client_endpoint.rsplit(":", 1)[0] else 4,
                "localEndpoint": state.client_endpoint,
                "remoteEndpoint": state.remote_endpoint,
                "hostname": state.hostname,
                "connectUnixNs": state.connect_unix_ns,
                "connectMonotonicNs": state.connect_mono_ns,
                "disconnectUnixNs": close_unix_ns,
                "disconnectMonotonicNs": close_mono_ns,
                "closeReason": close_reason,
                "c2sBytes": state.bytes_by_dir["c2s"],
                "s2cBytes": state.bytes_by_dir["s2c"],
                "firstScenarioPhase": "unknown",
                "lastScenarioPhase": "unknown",
                "accountAlias": "ACCOUNT_A",
            },
        )

    def close_connection(self, proxy_conn_id: str, reason: str = "fin") -> None:
        with self._lock:
            state = self._connections.get(proxy_conn_id)
            if not state or state.closed:
                return
            for direction in ("c2s", "s2c"):
                self._finalize_partial_locked(state, direction)
            self._finalize_logical_groups_locked(state)
            self._write_connection_anomalies_locked(state)
            unix_ns, mono_ns = _now_pair()
            state.closed = True
            if state.classification == "unknown" and self._root:
                destination = self._root / "unclassified" / state.connection_id
                if destination.exists():
                    shutil.rmtree(destination)
                shutil.move(str(state.base_dir), str(destination))
                state.base_dir = destination
                state.classification_reason = "no 01/3366 protocol magic observed"
                _append_jsonl(
                    self._root / "unclassified" / "flows.jsonl",
                    {
                        "connectionId": state.connection_id,
                        "remoteEndpoint": state.remote_endpoint,
                        "c2sBytes": state.bytes_by_dir["c2s"],
                        "s2cBytes": state.bytes_by_dir["s2c"],
                        "reason": state.classification_reason,
                    },
                )
            self._write_connection_locked(
                state,
                close_reason=reason,
                close_unix_ns=unix_ns,
                close_mono_ns=mono_ns,
            )
            self._log_locked(f"close {state.connection_id} reason={reason}")

    def _write_connection_anomalies_locked(self, state: _Connection) -> None:
        if not self._root:
            return
        missing_dirs = [
            direction for direction in ("c2s", "s2c")
            if state.bytes_by_dir[direction] == 0
        ]
        if missing_dirs:
            _append_jsonl(
                self._root / "anomalies.jsonl",
                {
                    "schemaVersion": 1,
                    "type": "ONE_DIRECTION_MISSING",
                    "connectionId": state.connection_id,
                    "classification": state.classification,
                    "missingDirections": missing_dirs,
                    "c2sBytes": state.bytes_by_dir["c2s"],
                    "s2cBytes": state.bytes_by_dir["s2c"],
                    "timestampUnixNs": time.time_ns(),
                    "timestampMonotonicNs": time.monotonic_ns(),
                },
            )
        if (
            state.classification == "protocol-3366"
            and not state.seen_complete_downlink_1002
        ):
            _append_jsonl(
                self._root / "anomalies.jsonl",
                {
                    "schemaVersion": 1,
                    "type": "MISSING_COMPLETE_DOWNLINK_1002",
                    "connectionId": state.connection_id,
                    "classification": state.classification,
                    "timestampUnixNs": time.time_ns(),
                    "timestampMonotonicNs": time.monotonic_ns(),
                },
            )

    def _finalize_logical_groups_locked(self, state: _Connection) -> None:
        for key, group in list(state.logical_groups.items()):
            numbers = sorted(group["fragments"])
            if not numbers:
                continue
            logical = b"".join(group["fragments"][n] for n in numbers)
            state.logical_count += 1
            idx = state.logical_count
            rel = f"logical-messages/message-{idx:06d}.bin"
            (state.base_dir / rel).write_bytes(logical)
            _append_jsonl(
                state.base_dir / "logical-messages.jsonl",
                {
                    "schemaVersion": 1,
                    "messageId": f"{state.connection_id}-M{idx:06d}",
                    "connectionId": state.connection_id,
                    "direction": key[0],
                    "frameIds": [group["frameIds"][n] for n in numbers],
                    "packetGroup": key[1],
                    "fragmentCount": group["expected"],
                    "presentFragmentIndexes": numbers,
                    "missingFragmentIndexes": [
                        n for n in range(1, group["expected"] + 1)
                        if n not in group["fragments"]
                    ],
                    "payloadType": group["payloadType"],
                    "length": len(logical),
                    "sha256": _sha256(logical),
                    "rawFile": rel,
                    "markers": [m.hex() for m in MARKERS if m in logical],
                    "parseStatus": "partial_at_capture_end",
                },
            )
            self._totals["logicalMessages"] += 1
        state.logical_groups.clear()

    def _finalize_partial_locked(self, state: _Connection, direction: str) -> None:
        buf = state.parse_buf[direction]
        if not buf or state.classification == "unknown":
            return
        protocol = "01" if state.classification == "protocol-01" else "3366"
        marker_ok = (
            bytes(buf).startswith(b"\x01\x00")
            if protocol == "01"
            else _find_valid_magic(buf, 0) == 0
        )
        if marker_ok:
            self._write_frame_locked(
                state,
                direction,
                state.parse_base[direction],
                bytes(buf),
                "partial_at_capture_end",
                protocol,
            )
        state.parse_base[direction] += len(buf)
        buf.clear()

    def stop(self) -> str | None:
        with self._lock:
            if not self._root:
                return None
            for proxy_id in list(self._connections):
                self.close_connection(proxy_id, "capture_end")
            self._append_timeline_locked("phase", "capture_end", "专项采集停止")
            end_unix, end_mono = _now_pair()
            session_path = self._root / "session.json"
            session = json.loads(session_path.read_text(encoding="utf-8"))
            session["captureEndUnixNs"] = end_unix
            session["captureEndMonotonicNs"] = end_mono
            session["totals"] = dict(self._totals)
            _json_dump(session_path, session)

            self._log_locked(
                "capture stopped "
                + " ".join(f"{k}={v}" for k, v in self._totals.items())
            )
            report = self._build_integrity_report_locked()
            _json_dump(self._root / "integrity-report.json", report)
            self._write_checksums_locked()
            result = str(self._root)
            self._root = None
            self._connections.clear()
            return result

    def _build_integrity_report_locked(self) -> dict:
        assert self._root is not None
        missing: list[str] = []
        invalid_jsonl: list[str] = []
        stream_range_errors: list[str] = []
        chunk_hash_errors: list[str] = []
        forward_hash_mismatches: list[str] = []
        for path in self._root.rglob("*.jsonl"):
            line_no = 0
            try:
                for line_no, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), 1
                ):
                    if line.strip():
                        json.loads(line)
            except Exception as ex:
                invalid_jsonl.append(f"{path.relative_to(self._root)}:{line_no}:{ex}")
        for path in self._root.rglob("frames.jsonl"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                for field_name in ("rawFile", "ciphertextFile", "plaintextFile"):
                    rel = row.get(field_name)
                    if rel and not (path.parent / rel).is_file():
                        missing.append(
                            f"{path.parent.relative_to(self._root)}/{rel}"
                        )
        for path in self._root.rglob("chunks.jsonl"):
            conn_dir = path.parent
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                direction = row.get("direction")
                raw_stream = conn_dir / f"{direction}.raw.bin"
                end = int(row.get("streamOffset", 0)) + int(
                    row.get("payloadLength", 0)
                )
                if not raw_stream.is_file() or end > raw_stream.stat().st_size:
                    stream_range_errors.append(
                        f"{conn_dir.relative_to(self._root)}:"
                        f"chunk={row.get('chunkId')} end={end}"
                    )
                raw_file = conn_dir / str(row.get("rawFile", ""))
                if not raw_file.is_file():
                    missing.append(str(raw_file.relative_to(self._root)))
                elif _sha256(raw_file.read_bytes()) != row.get("payloadSha256"):
                    chunk_hash_errors.append(str(raw_file.relative_to(self._root)))
                if (
                    row.get("modified") is not False
                    or row.get("payloadLength") != row.get("forwardedLength")
                    or row.get("payloadSha256") != row.get("forwardedSha256")
                ):
                    forward_hash_mismatches.append(
                        f"{conn_dir.relative_to(self._root)}:"
                        f"chunk={row.get('chunkId')}"
                    )
        session = json.loads((self._root / "session.json").read_text(encoding="utf-8"))
        capture_directions_valid = session.get("captureDirections") == ["c2s", "s2c"]
        connection_rows = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in self._root.rglob("connection.json")
        ]
        both_direction_count = sum(
            1 for row in connection_rows
            if row.get("c2sBytes", 0) > 0 and row.get("s2cBytes", 0) > 0
        )
        anomalies = [
            json.loads(line)
            for line in (self._root / "anomalies.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]
        hard_failures = (
            invalid_jsonl
            or missing
            or stream_range_errors
            or chunk_hash_errors
            or forward_hash_mismatches
            or not capture_directions_valid
        )
        return {
            "schemaVersion": 1,
            "generatedUnixNs": time.time_ns(),
            "trafficModified": False,
            "replacementEnabled": False,
            "captureDirections": session.get("captureDirections"),
            "captureDirectionsValid": capture_directions_valid,
            "rawForwardHashesMatch": not forward_hash_mismatches,
            "totals": dict(self._totals),
            "connectionsWithBothDirections": both_direction_count,
            "connectionCount": len(connection_rows),
            "anomalyCount": len(anomalies),
            "anomalyTypes": sorted({row.get("type") for row in anomalies}),
            "invalidJsonl": invalid_jsonl,
            "missingReferencedFiles": missing,
            "streamRangeErrors": stream_range_errors,
            "chunkHashErrors": chunk_hash_errors,
            "forwardHashMismatches": forward_hash_mismatches,
            "pcapngAvailable": False,
            "dnsCaptured": False,
            "status": "failed" if hard_failures else (
                "pass_with_anomalies" if anomalies else "pass"
            ),
        }

    def _write_checksums_locked(self) -> None:
        assert self._root is not None
        output = self._root / "checksums.sha256"
        rows = []
        for path in sorted(self._root.rglob("*")):
            if not path.is_file() or path == output:
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            rows.append(f"{digest}  {path.relative_to(self._root).as_posix()}")
        output.write_text("\n".join(rows) + "\n", encoding="utf-8")

    def _log_locked(self, message: str) -> None:
        if not self._root:
            return
        with (self._root / "capture.log").open("a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} {message}\n")


special_capture_manager = SpecialCaptureManager()
