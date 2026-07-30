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
import zipfile
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _now_pair() -> tuple[int, int]:
    return time.time_ns(), time.monotonic_ns()


def _json_dump(path: Path, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
    _write_bytes_verified(path, payload)


def _append_jsonl(path: Path, value: dict) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    _append_bytes_verified(path, payload)


def _write_all(f, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        n = f.write(view[written:])
        if not n:
            raise OSError(f"short write: {written}/{len(view)}")
        written += n


def _write_bytes_verified(path: Path, payload: bytes) -> None:
    """临时文件完整写入、fsync、读回校验后原子替换。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(
        f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}"
    )
    try:
        with temp.open("wb") as f:
            _write_all(f, payload)
            f.flush()
            os.fsync(f.fileno())
        if temp.stat().st_size != len(payload):
            raise OSError(
                f"length mismatch for {path}: {temp.stat().st_size}!={len(payload)}"
            )
        readback = temp.read_bytes()
        if _sha256(readback) != _sha256(payload):
            raise OSError(f"readback hash mismatch for {path}")
        os.replace(temp, path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _append_bytes_verified(
    path: Path, payload: bytes, expected_offset: int | None = None
) -> int:
    """串行追加并立即读回刚写入的范围，返回写入前偏移。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as f:
        f.seek(0, os.SEEK_END)
        offset = f.tell()
        if expected_offset is not None and offset != expected_offset:
            raise OSError(
                f"stream offset mismatch for {path}: {offset}!={expected_offset}"
            )
        _write_all(f, payload)
        f.flush()
        os.fsync(f.fileno())
        if f.tell() != offset + len(payload):
            raise OSError(f"append length mismatch for {path}")
        f.seek(offset)
        readback = f.read(len(payload))
    if _sha256(readback) != _sha256(payload):
        raise OSError(f"append readback hash mismatch for {path} at {offset}")
    return offset


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
        self._writer_errors: list[str] = []
        self._last_archive: str | None = None
        self._last_status: str | None = None
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

    @property
    def last_archive_path(self) -> str | None:
        with self._lock:
            return self._last_archive

    @property
    def last_status(self) -> str | None:
        with self._lock:
            return self._last_status

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
            self._writer_errors.clear()
            self._last_archive = None
            self._last_status = "recording"
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
                    "sessionStatus": "recording",
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
            _write_bytes_verified(self._root / "dns.jsonl", b"")
            _write_bytes_verified(self._root / "anomalies.jsonl", b"")
            _write_bytes_verified(
                self._root / "capture.log",
                (
                    f"{datetime.now().isoformat()} "
                    "capture started accountAlias=ACCOUNT_A\n"
                ).encode("utf-8"),
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
                _write_bytes_verified(base / name, b"")
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
        """故障隔离入口：写盘异常记入会话，但不改变代理转发。"""
        try:
            self._record_chunk_impl(proxy_conn_id, direction, data)
        except Exception as ex:
            self._record_writer_error(
                f"RAW_TAP {proxy_conn_id} {direction}: {type(ex).__name__}: {ex}"
            )

    def _record_chunk_impl(
        self, proxy_conn_id: str, direction: str, data: bytes
    ) -> None:
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
            _write_bytes_verified(state.base_dir / rel_file, payload)
            _append_bytes_verified(
                state.base_dir / f"{canonical_dir}.raw.bin",
                payload,
                expected_offset=offset,
            )
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

    def _record_writer_error(self, message: str) -> None:
        with self._lock:
            self._writer_errors.append(message)
            if not self._root:
                return
            try:
                _append_bytes_verified(
                    self._root / "capture.log",
                    (
                        f"{datetime.now().isoformat()} WRITER_ERROR {message}\n"
                    ).encode("utf-8"),
                )
                _append_jsonl(
                    self._root / "anomalies.jsonl",
                    {
                        "schemaVersion": 1,
                        "type": "WRITER_ERROR",
                        "message": message,
                        "timestampUnixNs": time.time_ns(),
                        "timestampMonotonicNs": time.monotonic_ns(),
                    },
                )
            except Exception:
                pass

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
        _write_bytes_verified(state.base_dir / rel_raw, bytes(frame))
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
        _write_bytes_verified(state.base_dir / rel, bytes(logical))
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
        _write_bytes_verified(state.base_dir / rel_cipher, bytes(ciphertext))
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
        _write_bytes_verified(state.base_dir / rel_plain, bytes(plaintext))
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
        try:
            self._close_connection_impl(proxy_conn_id, reason)
        except Exception as ex:
            self._record_writer_error(
                f"CLOSE {proxy_conn_id}: {type(ex).__name__}: {ex}"
            )

    def _close_connection_impl(
        self, proxy_conn_id: str, reason: str = "fin"
    ) -> None:
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
            self._write_checkpoint_locked()

    def _write_checkpoint_locked(self) -> None:
        """连接关闭即落一份未结束快照，避免目录被提前复制时没有任何状态说明。"""
        if not self._root:
            return
        unix_ns, mono_ns = _now_pair()
        session_path = self._root / "session.json"
        session = json.loads(session_path.read_text(encoding="utf-8"))
        session["sessionStatus"] = "recording"
        session["lastCheckpointUnixNs"] = unix_ns
        session["lastCheckpointMonotonicNs"] = mono_ns
        session["checkpointTotals"] = dict(self._totals)
        _json_dump(session_path, session)
        _json_dump(
            self._root / "checkpoint-integrity.json",
            {
                "schemaVersion": 1,
                "generatedUnixNs": unix_ns,
                "sessionStatus": "recording",
                "finalized": False,
                "writerErrors": list(self._writer_errors),
                "note": "请点击停止代理，等待最终完整性报告、checksums和ZIP生成。",
            },
        )
        self._write_checksum_file_locked("checkpoint-checksums.sha256")

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
            _write_bytes_verified(state.base_dir / rel, bytes(logical))
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
            session["sessionStatus"] = "finalizing"
            _json_dump(session_path, session)

            self._log_locked(
                "capture stopped "
                + " ".join(f"{k}={v}" for k, v in self._totals.items())
            )
            report = self._build_integrity_report_locked()
            if self._append_integrity_anomalies_locked(report):
                report = self._build_integrity_report_locked()
            session_status = "invalid" if report["status"] == "failed" else "valid"
            self._last_status = session_status
            session["sessionStatus"] = session_status
            _json_dump(session_path, session)
            report["sessionStatus"] = session_status
            _json_dump(self._root / "integrity-report.json", report)
            self._write_checksums_locked()
            result = str(self._root)
            self._last_archive = self._create_archive_locked()
            self._root = None
            self._connections.clear()
            return result

    def _append_integrity_anomalies_locked(self, report: dict) -> bool:
        assert self._root is not None
        checks = (
            ("invalidJsonl", "JSON_PARSE_FAILED"),
            ("textNulFiles", "JSONL_HAS_NUL"),
            ("sparseOutputFiles", "SPARSE_OUTPUT_FILE"),
            ("chunkHashErrors", "READBACK_HASH_MISMATCH"),
            ("frameHashErrors", "READBACK_HASH_MISMATCH"),
            ("streamContentMismatches", "READBACK_HASH_MISMATCH"),
            ("frameStreamMismatches", "READBACK_HASH_MISMATCH"),
            ("chunkCountMismatches", "CHUNK_COUNT_MISMATCH"),
            ("frameCountMismatches", "FRAME_COUNT_MISMATCH"),
        )
        grouped: dict[str, list[str]] = {}
        for field_name, anomaly_type in checks:
            values = report.get(field_name) or []
            if values:
                grouped.setdefault(anomaly_type, []).extend(map(str, values))
        for error in report.get("writerErrors") or []:
            grouped.setdefault("WRITER_ERROR", []).append(str(error))
        if not grouped:
            return False
        for anomaly_type, details in grouped.items():
            _append_jsonl(
                self._root / "anomalies.jsonl",
                {
                    "schemaVersion": 1,
                    "type": anomaly_type,
                    "count": len(details),
                    "examples": details[:20],
                    "timestampUnixNs": time.time_ns(),
                    "timestampMonotonicNs": time.monotonic_ns(),
                },
            )
        return True

    def _build_integrity_report_locked(self) -> dict:
        assert self._root is not None
        missing: list[str] = []
        invalid_jsonl: list[str] = []
        stream_range_errors: list[str] = []
        chunk_hash_errors: list[str] = []
        forward_hash_mismatches: list[str] = []
        stream_content_mismatches: list[str] = []
        frame_hash_errors: list[str] = []
        frame_stream_mismatches: list[str] = []
        text_nul_files: list[str] = []
        sparse_output_files: list[str] = []
        chunk_count_mismatches: list[str] = []
        frame_count_mismatches: list[str] = []
        invalid_jsonl_paths: set[str] = set()
        for path in self._root.rglob("*"):
            if not path.is_file():
                continue
            stat = path.stat()
            blocks = getattr(stat, "st_blocks", None)
            if stat.st_size > 0 and blocks == 0:
                sparse_output_files.append(str(path.relative_to(self._root)))
            if path.suffix in (".json", ".jsonl", ".log", ".sha256"):
                if b"\x00" in path.read_bytes():
                    text_nul_files.append(str(path.relative_to(self._root)))
        for path in self._root.rglob("*.jsonl"):
            line_no = 0
            try:
                for line_no, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), 1
                ):
                    if line.strip():
                        json.loads(line)
            except Exception as ex:
                rel = str(path.relative_to(self._root))
                invalid_jsonl_paths.add(rel)
                invalid_jsonl.append(f"{rel}:{line_no}:{ex}")
        for path in self._root.rglob("frames.jsonl"):
            if str(path.relative_to(self._root)) in invalid_jsonl_paths:
                continue
            frame_rows = [
                line for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            raw_frame_files = list((path.parent / "frames").glob("frame-*.raw.bin"))
            if len(frame_rows) != len(raw_frame_files):
                frame_count_mismatches.append(
                    f"{path.parent.relative_to(self._root)}:"
                    f"rows={len(frame_rows)} files={len(raw_frame_files)}"
                )
            for line in frame_rows:
                row = json.loads(line)
                for field_name in ("rawFile", "ciphertextFile", "plaintextFile"):
                    rel = row.get(field_name)
                    if rel and not (path.parent / rel).is_file():
                        missing.append(
                            f"{path.parent.relative_to(self._root)}/{rel}"
                        )
                raw_rel = row.get("rawFile")
                raw_path = path.parent / str(raw_rel or "")
                if raw_rel and raw_path.is_file():
                    raw_bytes = raw_path.read_bytes()
                    if (
                        len(raw_bytes) != row.get("frameLength")
                        or _sha256(raw_bytes) != row.get("rawSha256")
                    ):
                        frame_hash_errors.append(
                            str(raw_path.relative_to(self._root))
                        )
                    direction = row.get("direction")
                    stream_path = path.parent / f"{direction}.raw.bin"
                    offset = int(row.get("streamOffset", 0))
                    if stream_path.is_file():
                        with stream_path.open("rb") as stream:
                            stream.seek(offset)
                            stream_slice = stream.read(len(raw_bytes))
                        if stream_slice != raw_bytes:
                            frame_stream_mismatches.append(
                                str(raw_path.relative_to(self._root))
                            )
        for path in self._root.rglob("chunks.jsonl"):
            if str(path.relative_to(self._root)) in invalid_jsonl_paths:
                continue
            conn_dir = path.parent
            chunk_rows = [
                line for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            chunk_files = list((conn_dir / "chunks").glob("chunk-*.bin"))
            if len(chunk_rows) != len(chunk_files):
                chunk_count_mismatches.append(
                    f"{conn_dir.relative_to(self._root)}:"
                    f"rows={len(chunk_rows)} files={len(chunk_files)}"
                )
            rows_by_direction: dict[str, list[tuple[int, bytes]]] = {
                "c2s": [],
                "s2c": [],
            }
            for line in chunk_rows:
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
                else:
                    chunk_bytes = raw_file.read_bytes()
                    if _sha256(chunk_bytes) != row.get("payloadSha256"):
                        chunk_hash_errors.append(str(raw_file.relative_to(self._root)))
                    if direction in rows_by_direction:
                        rows_by_direction[direction].append(
                            (int(row.get("streamOffset", 0)), chunk_bytes)
                        )
                if (
                    row.get("modified") is not False
                    or row.get("payloadLength") != row.get("forwardedLength")
                    or row.get("payloadSha256") != row.get("forwardedSha256")
                ):
                    forward_hash_mismatches.append(
                        f"{conn_dir.relative_to(self._root)}:"
                        f"chunk={row.get('chunkId')}"
                    )
            for direction, pieces in rows_by_direction.items():
                pieces.sort(key=lambda item: item[0])
                stream_path = conn_dir / f"{direction}.raw.bin"
                if stream_path.is_file():
                    digest = hashlib.sha256()
                    expected_offset = 0
                    for offset, piece in pieces:
                        if offset != expected_offset:
                            stream_content_mismatches.append(
                                str(stream_path.relative_to(self._root))
                            )
                            break
                        digest.update(piece)
                        expected_offset += len(piece)
                    else:
                        if (
                            expected_offset != stream_path.stat().st_size
                            or digest.hexdigest() != _sha256_file(stream_path)
                        ):
                            stream_content_mismatches.append(
                                str(stream_path.relative_to(self._root))
                            )
        try:
            session = json.loads(
                (self._root / "session.json").read_text(encoding="utf-8")
            )
        except Exception as ex:
            session = {}
            invalid_jsonl.append(f"session.json:0:{ex}")
        capture_directions_valid = session.get("captureDirections") == ["c2s", "s2c"]
        connection_rows = []
        for path in self._root.rglob("connection.json"):
            try:
                connection_rows.append(
                    json.loads(path.read_text(encoding="utf-8"))
                )
            except Exception as ex:
                invalid_jsonl.append(
                    f"{path.relative_to(self._root)}:0:{ex}"
                )
        both_direction_count = sum(
            1 for row in connection_rows
            if row.get("c2sBytes", 0) > 0 and row.get("s2cBytes", 0) > 0
        )
        anomalies = []
        try:
            anomalies = [
                json.loads(line)
                for line in (self._root / "anomalies.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
                if line.strip()
            ]
        except Exception as ex:
            invalid_jsonl.append(f"anomalies.jsonl:0:{ex}")
        critical_anomaly_types = {
            "ONE_DIRECTION_MISSING",
            "MISSING_COMPLETE_DOWNLINK_1002",
            "WRITER_ERROR",
        }
        has_critical_anomaly = any(
            row.get("type") in critical_anomaly_types for row in anomalies
        )
        hard_failures = (
            invalid_jsonl
            or missing
            or stream_range_errors
            or chunk_hash_errors
            or forward_hash_mismatches
            or stream_content_mismatches
            or frame_hash_errors
            or frame_stream_mismatches
            or text_nul_files
            or sparse_output_files
            or chunk_count_mismatches
            or frame_count_mismatches
            or not capture_directions_valid
            or self._writer_errors
            or has_critical_anomaly
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
            "criticalAnomaly": has_critical_anomaly,
            "invalidJsonl": invalid_jsonl,
            "missingReferencedFiles": missing,
            "streamRangeErrors": stream_range_errors,
            "chunkHashErrors": chunk_hash_errors,
            "forwardHashMismatches": forward_hash_mismatches,
            "streamContentMismatches": stream_content_mismatches,
            "frameHashErrors": frame_hash_errors,
            "frameStreamMismatches": frame_stream_mismatches,
            "textNulFiles": text_nul_files,
            "sparseOutputFiles": sparse_output_files,
            "chunkCountMismatches": chunk_count_mismatches,
            "frameCountMismatches": frame_count_mismatches,
            "writerErrors": list(self._writer_errors),
            "pcapngAvailable": False,
            "dnsCaptured": False,
            "status": "failed" if hard_failures else (
                "pass_with_anomalies" if anomalies else "pass"
            ),
        }

    def _write_checksums_locked(self) -> None:
        self._write_checksum_file_locked("checksums.sha256")

    def _write_checksum_file_locked(self, filename: str) -> None:
        assert self._root is not None
        output = self._root / filename
        rows = []
        for path in sorted(self._root.rglob("*")):
            if (
                not path.is_file()
                or path == output
                or path.name in {"checksums.sha256", "checkpoint-checksums.sha256"}
            ):
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            rows.append(f"{digest}  {path.relative_to(self._root).as_posix()}")
        _write_bytes_verified(
            output, ("\n".join(rows) + "\n").encode("utf-8")
        )

    def _create_archive_locked(self) -> str:
        """停止后生成单一 ZIP，避免远程桌面逐文件复制破坏大量小文件。"""
        assert self._root is not None
        archive = self._root.with_suffix(".zip")
        temp = archive.with_suffix(".zip.tmp")
        try:
            with zipfile.ZipFile(
                temp, "w", compression=zipfile.ZIP_STORED, allowZip64=True
            ) as zf:
                for path in sorted(self._root.rglob("*")):
                    if path.is_file():
                        zf.write(
                            path,
                            arcname=(
                                f"{self._root.name}/"
                                f"{path.relative_to(self._root).as_posix()}"
                            ),
                        )
            with temp.open("r+b") as f:
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, archive)
            digest = _sha256_file(archive)
            _write_bytes_verified(
                archive.with_suffix(".zip.sha256"),
                f"{digest}  {archive.name}\n".encode("ascii"),
            )
            return str(archive)
        finally:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass

    def _log_locked(self, message: str) -> None:
        if not self._root:
            return
        _append_bytes_verified(
            self._root / "capture.log",
            f"{datetime.now().isoformat()} {message}\n".encode("utf-8"),
        )


special_capture_manager = SpecialCaptureManager()
