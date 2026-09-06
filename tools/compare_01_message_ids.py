#!/usr/bin/env python3
"""比较两份 DFMProxy 01 数据中的消息ID、频率和字段异常。

推荐把第一份作为基线/正常数据，第二份作为待检查数据。输入支持：

* ``01RecordPackets`` 目录或 ``test_01_sliced_*.log``；
* v1.121 的 ``test_01_message_leaves_*.jsonl``；
* ``01_replace_events.jsonl``；
* ``v117_recording_pools.json``；
* 通用 ``数据1.py`` / ``数据2.py`` 原始01字节数组；
* 一个只包含两份上述数据的父目录（自动配对）。

原始数组文件既可以写完整列表，也可以直接写逗号分隔的多个列表：
``数据1 = [[1, 0, ...], [1, 0, ...]]`` 或 ``[1, 0, ...], [1, 0, ...]``。
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import csv
from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path
import re
import sys
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.crypto import (  # noqa: E402
    _ace_01_frame_meta,
    _ace_01_reassemble_frames,
    _ace_split_packets,
)
from core.type9_shadow import decode_material  # noqa: E402


HEADER_RE = re.compile(
    r"^(?P<time>\S+)\s+user=(?P<user>\S+)\s+dir=(?P<direction>\S+)\s+"
    r"ip=(?P<ip>\S+)\s+conn=(?P<conn>\S+)\s+uid=(?P<uid>\S+)\s+LEN=(?P<len>\d+)"
)
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
RAW_ARRAY_SUFFIXES = {"", ".json", ".txt", ".py", ".data", ".raw"}
PAIR_NAME_A = {"数据1", "数据一", "data1", "dataset1", "capture1", "sample1"}
PAIR_NAME_B = {"数据2", "数据二", "data2", "dataset2", "capture2", "sample2"}


@dataclass
class LeafSample:
    record_code: int
    message_id: int | None
    length: int
    sequence: int
    raw: bytes
    packet_id: str
    time: str = ""
    report_index: int | None = None
    path: tuple[int, ...] = ()
    source_file: str = ""

    @property
    def identity(self) -> tuple[int, int | None]:
        return self.record_code, self.message_id

    @property
    def shape(self) -> tuple[int, int | None, int]:
        return self.record_code, self.message_id, self.length


@dataclass
class Dataset:
    label: str
    input_path: str
    view: str = "live"
    samples: list[LeafSample] = field(default_factory=list)
    packets: set[str] = field(default_factory=set)
    source_files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_int(value: str | int | None) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    return int(text, 16 if text.startswith("0x") else 10)


def identity_text(key: tuple[int, int | None]) -> str:
    record_code, message_id = key
    if message_id is not None:
        return f"0x{message_id:04X}"
    return f"code=0x{record_code:08X}"


def shape_text(key: tuple[int, int | None, int]) -> str:
    return f"{identity_text((key[0], key[1]))}/{key[2]}"


def _append_decoded(
    dataset: Dataset,
    logical: bytes,
    *,
    packet_id: str,
    time_text: str = "",
    report_index: int | None = None,
    source_file: str = "",
) -> None:
    decoded = decode_material(logical)
    if not decoded.get("ok"):
        return
    leaves = decoded.get("leaves") or []
    if not leaves:
        return
    dataset.packets.add(packet_id)
    for leaf in leaves:
        raw = bytes(leaf.get("raw") or b"")
        if not raw:
            continue
        dataset.samples.append(
            LeafSample(
                record_code=int(leaf.get("record_code") or 0),
                message_id=leaf.get("message_id"),
                length=len(raw),
                sequence=int(leaf.get("record_sequence") or 0),
                raw=raw,
                packet_id=packet_id,
                time=time_text,
                report_index=report_index,
                path=tuple(leaf.get("path") or []),
                source_file=source_file,
            )
        )


def _physical_entries(path: Path) -> Iterable[dict]:
    current: dict | None = None
    hex_lines: list[str] = []

    def finish():
        nonlocal current, hex_lines
        if current is None:
            return None
        text = "".join(hex_lines)
        result = dict(current)
        result["hex"] = text
        current = None
        hex_lines = []
        return result

    with path.open("r", encoding="utf-8-sig", errors="replace") as stream:
        for line in stream:
            stripped = line.strip()
            match = HEADER_RE.match(stripped)
            if match:
                old = finish()
                if old is not None:
                    yield old
                current = match.groupdict()
                current["len"] = int(current["len"])
                continue
            if current is not None and stripped and HEX_RE.fullmatch(stripped):
                hex_lines.append(stripped)
        old = finish()
        if old is not None:
            yield old


def load_physical_logs(paths: list[Path], dataset: Dataset, *, direction: str) -> None:
    groups: dict[tuple, dict[int, tuple[bytes, dict, str]]] = defaultdict(dict)
    no_full_hex = 0
    invalid_frames = 0
    selected_directions = {
        "up": {"↑UP", "UP"},
        "down": {"↓DOWN", "DOWN"},
        "both": {"↑UP", "UP", "↓DOWN", "DOWN"},
    }[direction]
    ordinal = 0
    for path in paths:
        dataset.source_files.append(str(path))
        for entry in _physical_entries(path):
            if entry.get("direction") not in selected_directions:
                continue
            raw_hex = entry.get("hex") or ""
            if len(raw_hex) != int(entry["len"]) * 2:
                no_full_hex += 1
                continue
            try:
                frame = bytes.fromhex(raw_hex)
            except ValueError:
                invalid_frames += 1
                continue
            meta = _ace_01_frame_meta(frame)
            if not meta:
                continue
            ordinal += 1
            key = (
                entry.get("conn"),
                meta["group"],
                meta["fragment_count"],
                meta["crc"],
            )
            groups[key][meta["fragment_number"]] = (frame, entry, str(path))
            if len(groups[key]) != meta["fragment_count"]:
                continue
            slots = groups.pop(key)
            frames = [slots[index][0] for index in sorted(slots)]
            rebuilt = _ace_01_reassemble_frames(frames)
            if not rebuilt:
                invalid_frames += 1
                continue
            first_entry = slots[min(slots)][1]
            packet_id = f"physical:{path}:{ordinal}:{meta['group']}:{meta['crc'].hex()}"
            _append_decoded(
                dataset,
                rebuilt[1],
                packet_id=packet_id,
                time_text=str(first_entry.get("time") or ""),
                source_file=str(path),
            )
    if no_full_hex:
        dataset.warnings.append(
            f"{no_full_hex}条物理帧只有摘要/HEAD，需打开详细01日志后才能解密比较"
        )
    if invalid_frames:
        dataset.warnings.append(f"{invalid_frames}条物理帧或分片组校验失败")
    if groups:
        dataset.warnings.append(f"{len(groups)}个物理分片组未收齐")


def load_message_leaf_jsonl(paths: list[Path], dataset: Dataset) -> None:
    for path in paths:
        dataset.source_files.append(str(path))
        with path.open("r", encoding="utf-8-sig") as stream:
            for line_no, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                packet_id = f"leaf-json:{path}:{row.get('event_id', line_no)}"
                leaves = row.get("leaves") or []
                if leaves:
                    dataset.packets.add(packet_id)
                for leaf in leaves:
                    raw_hex = str(leaf.get("raw_hex") or "")
                    try:
                        raw = bytes.fromhex(raw_hex)
                    except ValueError:
                        continue
                    if not raw:
                        continue
                    dataset.samples.append(
                        LeafSample(
                            record_code=int(parse_int(leaf.get("record_code")) or 0),
                            message_id=parse_int(leaf.get("message_id")),
                            length=len(raw),
                            sequence=int(parse_int(leaf.get("sequence")) or 0),
                            raw=raw,
                            packet_id=packet_id,
                            time=str(row.get("time") or ""),
                            report_index=parse_int(row.get("report_index")),
                            path=tuple(leaf.get("path") or []),
                            source_file=str(path),
                        )
                    )


def load_replay_jsonl(path: Path, dataset: Dataset, *, view: str) -> None:
    dataset.source_files.append(str(path))
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            event = json.loads(line)
            packet_id = f"replay:{path}:{event.get('event_id', line_no)}"
            report_index = (event.get("ordinals") or {}).get("report_index")
            leaf_results = (event.get("shadow_rebuild") or {}).get("leaf_results") or []
            hex_key = {
                "live": "live_hex",
                "candidate": "candidate_hex",
                "template": "template_hex",
            }.get(view)
            if hex_key:
                present = False
                for leaf in leaf_results:
                    raw_hex = str(leaf.get(hex_key) or "")
                    if not raw_hex:
                        continue
                    try:
                        raw = bytes.fromhex(raw_hex)
                    except ValueError:
                        continue
                    present = True
                    dataset.samples.append(
                        LeafSample(
                            record_code=int(leaf.get("record_code") or 0),
                            message_id=leaf.get("message_id"),
                            length=len(raw),
                            sequence=int.from_bytes(raw[10:14], "big") if len(raw) >= 14 else 0,
                            raw=raw,
                            packet_id=packet_id,
                            time=str(event.get("time") or ""),
                            report_index=report_index,
                            path=tuple(leaf.get("path") or []),
                            source_file=str(path),
                        )
                    )
                if present:
                    dataset.packets.add(packet_id)
                continue
            snapshot = event.get("final_output") if view == "final" else event.get("live_input")
            frames_hex = (snapshot or {}).get("frames_hex") or []
            if not frames_hex:
                continue
            rebuilt = _ace_01_reassemble_frames([bytes.fromhex(value) for value in frames_hex])
            if rebuilt:
                _append_decoded(
                    dataset,
                    rebuilt[1],
                    packet_id=packet_id,
                    time_text=str(event.get("time") or ""),
                    report_index=report_index,
                    source_file=str(path),
                )


def load_recording_pool(path: Path, dataset: Dataset) -> None:
    dataset.source_files.append(str(path))
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    ordinal = 0
    sessions = payload.get("sessions") or {}
    for _ip, rows in sessions.items():
        for session in rows or []:
            for item in session.get("pool_items") or []:
                raw_hex = item.get("raw_packet") or ""
                if not raw_hex:
                    continue
                ordinal += 1
                _append_decoded(
                    dataset,
                    bytes.fromhex(raw_hex),
                    packet_id=f"pool:{path}:{ordinal}",
                    report_index=parse_int(item.get("report_index")),
                    source_file=str(path),
                )


def _array_document_value(path: Path):
    """读取JSON/Python字面量；支持 ``数据1 = [...]`` 和 ``[],[],[]``。"""
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        raise ValueError(f"原始数组文件为空: {path}")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        module = ast.parse(text, filename=str(path), mode="exec")
        assignments = [
            node for node in module.body
            if isinstance(node, (ast.Assign, ast.AnnAssign))
        ]
        if assignments:
            node = assignments[-1]
            return ast.literal_eval(node.value)
        if len(module.body) == 1 and isinstance(module.body[0], ast.Expr):
            return ast.literal_eval(module.body[0].value)
        if module.body and all(isinstance(node, ast.Expr) for node in module.body):
            return [ast.literal_eval(node.value) for node in module.body]
    except (SyntaxError, ValueError) as exc:
        raise ValueError(f"原始数组语法错误: {path}: {exc}") from exc
    raise ValueError(f"原始数组中没有可读取的数据: {path}")


def _hex_string_bytes(value: str) -> bytes:
    text = value.strip()
    if not text:
        return b""
    text = re.sub(r"0x", "", text, flags=re.IGNORECASE)
    text = re.sub(r"[\s,:;|_\-]", "", text)
    if len(text) % 2 or not HEX_RE.fullmatch(text):
        raise ValueError("字符串既不是偶数字节Hex，也不是字节数组")
    return bytes.fromhex(text)


def _collect_raw_blobs(value, *, location: str = "root") -> list[bytes]:
    """把多种通用写法归一化为一组原始01字节串。"""
    if isinstance(value, (bytes, bytearray)):
        return [bytes(value)]
    if isinstance(value, str):
        return [_hex_string_bytes(value)]
    if isinstance(value, dict):
        for key in (
            "frames", "packets", "records", "items", "data",
            "数据", "数据1", "数据2", "raw", "raw_hex", "hex",
        ):
            if key in value:
                return _collect_raw_blobs(value[key], location=f"{location}.{key}")
        raise ValueError(f"{location}对象缺少frames/packets/data/raw/hex字段")
    if isinstance(value, (list, tuple)):
        if not value:
            return []
        if all(isinstance(item, int) and not isinstance(item, bool) for item in value):
            bad = [item for item in value if item < -128 or item > 255]
            if bad:
                raise ValueError(f"{location}包含超出-128..255的字节值: {bad[0]}")
            return [bytes(item & 0xFF for item in value)]
        blobs: list[bytes] = []
        for index, item in enumerate(value):
            blobs.extend(_collect_raw_blobs(item, location=f"{location}[{index}]"))
        return blobs
    raise ValueError(f"{location}包含不支持的值类型: {type(value).__name__}")


def load_raw_array(path: Path, dataset: Dataset) -> None:
    """解密通用原始数组中的单帧、多帧、TCP合并帧或Type9片段。"""
    dataset.source_files.append(str(path))
    blobs = _collect_raw_blobs(_array_document_value(path))
    groups: dict[tuple, dict[int, bytes]] = {}
    decoded_before = len(dataset.packets)
    invalid = 0
    ordinal = 0

    def append_logical(logical: bytes, packet_suffix: str) -> None:
        nonlocal ordinal
        ordinal += 1
        _append_decoded(
            dataset,
            logical,
            packet_id=f"raw-array:{path}:{ordinal}:{packet_suffix}",
            source_file=str(path),
        )

    for blob_index, blob in enumerate(blobs, 1):
        if not blob:
            continue
        split = _ace_split_packets(blob)
        physical = []
        for frame in split:
            meta = _ace_01_frame_meta(frame)
            if meta:
                physical.append((frame, meta))
        if not physical:
            before = len(dataset.packets)
            append_logical(blob, f"blob-{blob_index}")
            if len(dataset.packets) == before:
                invalid += 1
            continue
        for frame, meta in physical:
            if meta["fragment_count"] == 1:
                rebuilt = _ace_01_reassemble_frames([frame])
                if rebuilt:
                    append_logical(rebuilt[1], f"blob-{blob_index}-single")
                else:
                    invalid += 1
                continue
            key = (meta["group"], meta["fragment_count"], meta["crc"])
            slots = groups.setdefault(key, {})
            if meta["fragment_number"] == 1 and slots:
                invalid += 1
                slots = {}
                groups[key] = slots
            slots[meta["fragment_number"]] = frame
            if len(slots) == meta["fragment_count"]:
                ordered = [slots[index] for index in sorted(slots)]
                rebuilt = _ace_01_reassemble_frames(ordered)
                groups.pop(key, None)
                if rebuilt:
                    append_logical(
                        rebuilt[1],
                        f"group-{meta['group']}-{meta['crc'].hex()}",
                    )
                else:
                    invalid += 1
    if groups:
        dataset.warnings.append(f"{len(groups)}个原始数组分片组未收齐")
    if invalid:
        dataset.warnings.append(f"{invalid}个原始数组条目未解出Type9消息")
    if len(dataset.packets) == decoded_before:
        dataset.warnings.append("原始数组中没有成功解密的Type9报告")


def _looks_like_raw_array(path: Path) -> bool:
    if path.suffix.lower() in RAW_ARRAY_SUFFIXES and path.suffix.lower() != ".log":
        return True
    try:
        head = path.read_text(encoding="utf-8-sig", errors="replace")[:512].lstrip()
    except OSError:
        return False
    return head.startswith(("[", "(", "{", "数据", "data", "DATA"))


def resolve_source(path: Path) -> tuple[str, list[Path]]:
    path = path.expanduser().resolve()
    if path.is_file():
        name = path.name
        if name.startswith("test_01_message_leaves_") and name.endswith(".jsonl"):
            return "message_jsonl", [path]
        if name == "01_replace_events.jsonl":
            return "replay", [path]
        if name == "v117_recording_pools.json":
            return "pool", [path]
        if name.endswith(".log"):
            if _looks_like_raw_array(path):
                return "raw_array", [path]
            return "physical", [path]
        if _looks_like_raw_array(path):
            return "raw_array", [path]
        raise ValueError(f"不支持的输入文件: {path}")
    if not path.is_dir():
        raise ValueError(f"路径不存在: {path}")

    leaf_json = sorted(path.glob("test_01_message_leaves_*.jsonl"))
    if leaf_json:
        return "message_jsonl", leaf_json
    physical = sorted(path.glob("test_01_sliced_*.log"))
    if physical:
        return "physical", physical
    record_dir = path / "01RecordPackets"
    if record_dir.is_dir():
        return resolve_source(record_dir)
    replay = sorted(path.glob("01ReplayAnalysis/run_*/01_replace_events.jsonl"))
    if replay:
        return "replay", [replay[-1]]
    direct_replay = path / "01_replace_events.jsonl"
    if direct_replay.is_file():
        return "replay", [direct_replay]
    pool = path / "v117_recording_pools.json"
    if pool.is_file():
        return "pool", [pool]
    raise ValueError(f"目录中没有可识别的01数据: {path}")


def discover_pair(parent: Path) -> list[Path]:
    named_a: list[Path] = []
    named_b: list[Path] = []
    for child in sorted(parent.iterdir()):
        if not child.is_file():
            continue
        normalized = re.sub(r"[\s_\-]", "", child.stem).lower()
        if normalized in PAIR_NAME_A:
            named_a.append(child)
        elif normalized in PAIR_NAME_B:
            named_b.append(child)
    if len(named_a) == 1 and len(named_b) == 1:
        return [named_a[0], named_b[0]]

    candidates: list[Path] = []
    for child in sorted(parent.iterdir()):
        if not child.is_dir():
            continue
        try:
            resolve_source(child)
        except ValueError:
            continue
        candidates.append(child)
    if len(candidates) != 2:
        names = ", ".join(str(value) for value in candidates) or "无"
        raise ValueError(
            f"单目录自动配对需要正好2份子数据，当前识别到{len(candidates)}份: {names}"
        )
    return candidates


def load_dataset(path: Path, label: str, *, direction: str, view: str) -> Dataset:
    kind, paths = resolve_source(path)
    dataset = Dataset(label=label, input_path=str(path.resolve()), view=view)
    if kind == "physical":
        load_physical_logs(paths, dataset, direction=direction)
    elif kind == "message_jsonl":
        load_message_leaf_jsonl(paths, dataset)
    elif kind == "replay":
        load_replay_jsonl(paths[0], dataset, view=view)
    elif kind == "pool":
        load_recording_pool(paths[0], dataset)
    elif kind == "raw_array":
        load_raw_array(paths[0], dataset)
    if not dataset.samples:
        raise ValueError(
            f"{path}没有解出Type9叶子。若输入物理日志，请启用detail_01_log后重新录制，"
            "或使用v1.121 message_leaves JSONL。"
        )
    return dataset


def _top_values(counter: Counter[bytes], limit: int = 8) -> list[dict]:
    return [
        {
            "hex": value.hex().upper(),
            "be_uint": int.from_bytes(value, "big"),
            "count": count,
        }
        for value, count in counter.most_common(limit)
    ]


def compare_datasets(
    baseline: Dataset,
    observed: Dataset,
    *,
    widths: tuple[int, ...] = (4, 2, 1),
    min_baseline_samples: int = 2,
    only_message_ids: set[int] | None = None,
) -> dict:
    a_identity = Counter(sample.identity for sample in baseline.samples)
    b_identity = Counter(sample.identity for sample in observed.samples)
    a_shapes: dict[tuple, list[LeafSample]] = defaultdict(list)
    b_shapes: dict[tuple, list[LeafSample]] = defaultdict(list)
    for sample in baseline.samples:
        a_shapes[sample.shape].append(sample)
    for sample in observed.samples:
        b_shapes[sample.shape].append(sample)

    if only_message_ids:
        a_identity = Counter({k: v for k, v in a_identity.items() if k[1] in only_message_ids})
        b_identity = Counter({k: v for k, v in b_identity.items() if k[1] in only_message_ids})
        a_shapes = defaultdict(list, {k: v for k, v in a_shapes.items() if k[1] in only_message_ids})
        b_shapes = defaultdict(list, {k: v for k, v in b_shapes.items() if k[1] in only_message_ids})

    all_ids = sorted(set(a_identity) | set(b_identity), key=lambda x: (x[1] is None, x[1] or x[0], x[0]))
    packet_a = max(1, len(baseline.packets))
    packet_b = max(1, len(observed.packets))
    id_rows = []
    for key in all_ids:
        count_a, count_b = a_identity[key], b_identity[key]
        rate_a, rate_b = count_a / packet_a * 100, count_b / packet_b * 100
        status = "COMMON"
        if count_a == 0:
            status = "NEW_IN_B"
        elif count_b == 0:
            status = "MISSING_IN_B"
        elif rate_a and (rate_b / rate_a >= 2 or rate_b / rate_a <= 0.5):
            status = "FREQUENCY_SHIFT"
        lengths_a = sorted({key2[2] for key2 in a_shapes if key2[:2] == key})
        lengths_b = sorted({key2[2] for key2 in b_shapes if key2[:2] == key})
        id_rows.append(
            {
                "identity": identity_text(key),
                "record_code": f"0x{key[0]:08X}",
                "message_id": f"0x{key[1]:04X}" if key[1] is not None else None,
                "status": status,
                "count_a": count_a,
                "count_b": count_b,
                "per_100_packets_a": round(rate_a, 3),
                "per_100_packets_b": round(rate_b, 3),
                "rate_ratio_b_over_a": round(rate_b / rate_a, 3) if rate_a else None,
                "lengths_a": lengths_a,
                "lengths_b": lengths_b,
                "new_lengths_b": sorted(set(lengths_b) - set(lengths_a)),
            }
        )

    candidates = []
    for shape in sorted(set(a_shapes) & set(b_shapes)):
        rows_a, rows_b = a_shapes[shape], b_shapes[shape]
        if len(rows_a) < min_baseline_samples or not rows_b:
            continue
        length = min(shape[2], *(len(row.raw) for row in rows_a + rows_b))
        payload_start = 0x20 if shape[1] is not None and length >= 0x20 else 0x0E
        for width in sorted(set(widths), reverse=True):
            if width <= 0 or width > length - payload_start:
                continue
            for offset in range(payload_start, length - width + 1):
                if width > 1 and offset % width:
                    continue
                values_a = Counter(row.raw[offset:offset + width] for row in rows_a)
                values_b = Counter(row.raw[offset:offset + width] for row in rows_b)
                baseline_set = set(values_a)
                zero = b"\x00" * width
                outlier_count = sum(count for value, count in values_b.items() if value not in baseline_set)
                outlier_ratio = outlier_count / len(rows_b)
                b_nonzero_count = sum(count for value, count in values_b.items() if value != zero)
                a_all_zero = len(values_a) == 1 and zero in values_a
                category = ""
                score = 0.0
                if a_all_zero and b_nonzero_count:
                    category = "ZERO_TO_NONZERO"
                    score = 100 + outlier_ratio * 20 + min(len(rows_a), 20) / 10
                elif len(values_a) == 1 and outlier_count:
                    # 单字节很容易把浮点数、时间戳中的偶然稳定字节误标为字段。
                    # 小样本时仅保留至少半数B样本变化的单字节候选。
                    if width == 1 and (len(rows_a) < 5 or outlier_ratio < 0.5):
                        continue
                    category = "STABLE_BASELINE_CHANGED"
                    score = 80 + outlier_ratio * 20 + min(len(rows_a), 20) / 10
                elif (
                    len(rows_a) >= 5
                    and len(values_a) / len(rows_a) <= 0.5
                    and outlier_ratio >= 0.25
                ):
                    category = "NEW_VALUE_OUTSIDE_BASELINE"
                    score = 55 + outlier_ratio * 20
                else:
                    continue
                if width == 4:
                    score += 2
                examples = []
                for row in rows_b:
                    value = row.raw[offset:offset + width]
                    if value in baseline_set:
                        continue
                    examples.append(
                        {
                            "hex": value.hex().upper(),
                            "be_uint": int.from_bytes(value, "big"),
                            "time": row.time,
                            "report_index": row.report_index,
                            "sequence": row.sequence,
                            "path": list(row.path),
                        }
                    )
                    if len(examples) >= 5:
                        break
                candidates.append(
                    {
                        "shape": shape_text(shape),
                        "record_code": f"0x{shape[0]:08X}",
                        "message_id": f"0x{shape[1]:04X}" if shape[1] is not None else None,
                        "length": shape[2],
                        "category": category,
                        "score": round(score, 3),
                        "leaf_offset": offset,
                        "leaf_offset_hex": f"0x{offset:02X}",
                        "payload_offset": offset - payload_start,
                        "payload_offset_hex": f"+0x{offset - payload_start:02X}",
                        "width": width,
                        "samples_a": len(rows_a),
                        "samples_b": len(rows_b),
                        "unique_a": len(values_a),
                        "unique_b": len(values_b),
                        "outlier_count_b": outlier_count,
                        "outlier_ratio_b": round(outlier_ratio, 6),
                        "nonzero_count_b": b_nonzero_count,
                        "values_a": _top_values(values_a),
                        "values_b": _top_values(values_b),
                        "outlier_examples_b": examples,
                    }
                )

    candidates.sort(key=lambda row: (-row["score"], -row["width"], row["shape"], row["leaf_offset"]))
    visible = []
    for candidate in candidates:
        start = candidate["leaf_offset"]
        end = start + candidate["width"]
        covered = any(
            previous["shape"] == candidate["shape"]
            and previous["category"] == candidate["category"]
            and previous["leaf_offset"] <= start
            and previous["leaf_offset"] + previous["width"] >= end
            for previous in visible
        )
        if not covered:
            visible.append(candidate)

    return {
        "schema": "dfm-01-message-diff-v1",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "baseline": {
            "label": baseline.label,
            "input": baseline.input_path,
            "view": baseline.view,
            "packets": len(baseline.packets),
            "leaves": len(baseline.samples),
            "source_files": baseline.source_files,
            "warnings": baseline.warnings,
        },
        "observed": {
            "label": observed.label,
            "input": observed.input_path,
            "view": observed.view,
            "packets": len(observed.packets),
            "leaves": len(observed.samples),
            "source_files": observed.source_files,
            "warnings": observed.warnings,
        },
        "message_ids": id_rows,
        "new_ids_b": [row for row in id_rows if row["status"] == "NEW_IN_B"],
        "missing_ids_b": [row for row in id_rows if row["status"] == "MISSING_IN_B"],
        "frequency_shifts": [row for row in id_rows if row["status"] == "FREQUENCY_SHIFT"],
        "field_anomalies": visible,
    }


def write_outputs(result: dict, output_dir: Path, *, top: int) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "message_diff.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    with (output_dir / "message_id_counts.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        fields = [
            "identity", "record_code", "message_id", "status", "count_a", "count_b",
            "per_100_packets_a", "per_100_packets_b", "rate_ratio_b_over_a",
            "lengths_a", "lengths_b", "new_lengths_b",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in result["message_ids"]:
            writer.writerow({key: row.get(key) for key in fields})
    with (output_dir / "field_anomalies.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        fields = [
            "shape", "record_code", "message_id", "length", "category", "score",
            "leaf_offset_hex", "payload_offset_hex", "width", "samples_a", "samples_b",
            "unique_a", "unique_b", "outlier_count_b", "outlier_ratio_b", "nonzero_count_b",
            "values_a", "values_b",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in result["field_anomalies"]:
            item = {key: row.get(key) for key in fields}
            item["values_a"] = json.dumps(row["values_a"], ensure_ascii=False)
            item["values_b"] = json.dumps(row["values_b"], ensure_ascii=False)
            writer.writerow(item)

    lines = [
        "# 01消息ID与字段差异报告",
        "",
        f"- 基线A：`{result['baseline']['label']}`，{result['baseline']['packets']}包 / {result['baseline']['leaves']}叶子",
        f"- 检查B：`{result['observed']['label']}`，{result['observed']['packets']}包 / {result['observed']['leaves']}叶子",
        f"- A输入：`{result['baseline']['input']}`；视图：`{result['baseline']['view']}`",
        f"- B输入：`{result['observed']['input']}`；视图：`{result['observed']['view']}`",
        "",
    ]
    warnings = result["baseline"]["warnings"] + result["observed"]["warnings"]
    if warnings:
        lines += ["## 读取警告", ""] + [f"- {value}" for value in warnings] + [""]
    lines += ["## 消息ID计数", "", "| ID | 状态 | A次数 | B次数 | A/100包 | B/100包 | 长度A → B |", "|---|---|---:|---:|---:|---:|---|"]
    priority = {"NEW_IN_B": 0, "MISSING_IN_B": 1, "FREQUENCY_SHIFT": 2, "COMMON": 3}
    for row in sorted(result["message_ids"], key=lambda x: (priority[x["status"]], x["identity"])):
        lines.append(
            f"| `{row['identity']}` | {row['status']} | {row['count_a']} | {row['count_b']} | "
            f"{row['per_100_packets_a']:.2f} | {row['per_100_packets_b']:.2f} | "
            f"{row['lengths_a']} → {row['lengths_b']} |"
        )
    lines += ["", "## 字段异常候选", "", "| 排名 | 消息 | 类型 | 完整叶子偏移 | 载荷偏移 | 宽度 | A值 | B值 | B异常占比 |", "|---:|---|---|---|---|---:|---|---|---:|"]
    for index, row in enumerate(result["field_anomalies"][:top], 1):
        values_a = ", ".join(f"{v['hex']}({v['count']})" for v in row["values_a"][:4])
        values_b = ", ".join(f"{v['hex']}({v['count']})" for v in row["values_b"][:4])
        lines.append(
            f"| {index} | `{row['shape']}` | {row['category']} | `{row['leaf_offset_hex']}` | "
            f"`{row['payload_offset_hex']}` | {row['width']} | `{values_a}` | `{values_b}` | "
            f"{row['outlier_ratio_b']:.1%} |"
        )
    if not result["field_anomalies"]:
        lines.append("| - | - | 未发现满足当前阈值的稳定字段异常 | - | - | - | - | - | - |")
    lines += [
        "",
        "## 判定说明",
        "",
        "- `ZERO_TO_NONZERO`：A中该字段始终为0，B中出现非0，优先级最高。",
        "- `STABLE_BASELINE_CHANGED`：A中字段固定，B出现基线未见值。",
        "- `NEW_VALUE_OUTSIDE_BASELINE`：A只有少量取值，B出现较多新值。",
        "- 频率按每100个已解密Type9包归一化，减少录制时长差异影响。",
        "- 默认从二进制消息完整叶子0x20开始分析，报告同时给出完整叶子偏移与载荷相对偏移。",
        "",
    ]
    (output_dir / "message_diff.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="比较两份01录制中的消息ID次数、长度和稳定字段异常"
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help="两个输入路径；一个含两份数据的目录；留空则在当前目录找数据1/数据2",
    )
    parser.add_argument("--label-a", default="基线A")
    parser.add_argument("--label-b", default="检查B")
    parser.add_argument("--direction", choices=("up", "down", "both"), default="up")
    parser.add_argument(
        "--view",
        choices=("live", "candidate", "template", "final"),
        default="live",
        help="输入01_replace_events.jsonl时选择哪一侧，默认live",
    )
    parser.add_argument(
        "--view-a",
        choices=("live", "candidate", "template", "final"),
        help="单独指定A视图；省略时沿用--view",
    )
    parser.add_argument(
        "--view-b",
        choices=("live", "candidate", "template", "final"),
        help="单独指定B视图；省略时沿用--view",
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--top", type=int, default=80)
    parser.add_argument("--min-baseline-samples", type=int, default=2)
    parser.add_argument(
        "--message-id",
        action="append",
        default=[],
        help="只分析指定ID，可重复，例如 --message-id 0x0207",
    )
    args = parser.parse_args()
    try:
        inputs = [Path(value) for value in args.inputs]
        if not inputs:
            inputs = discover_pair(Path.cwd())
        if len(inputs) == 1:
            inputs = discover_pair(inputs[0].expanduser().resolve())
        if len(inputs) != 2:
            raise ValueError("需要两个输入路径，或一个可自动识别出两份数据的父目录")
        only_ids = {int(value, 0) for value in args.message_id} or None
        view_a = args.view_a or args.view
        view_b = args.view_b or args.view
        baseline = load_dataset(
            inputs[0], args.label_a, direction=args.direction, view=view_a
        )
        observed = load_dataset(
            inputs[1], args.label_b, direction=args.direction, view=view_b
        )
        result = compare_datasets(
            baseline,
            observed,
            min_baseline_samples=max(1, args.min_baseline_samples),
            only_message_ids=only_ids,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    output_dir = args.output_dir or Path.cwd() / (
        f"01MessageDiff_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    write_outputs(result, output_dir, top=max(1, args.top))
    print(f"A: {baseline.label} packets={len(baseline.packets)} leaves={len(baseline.samples)}")
    print(f"B: {observed.label} packets={len(observed.packets)} leaves={len(observed.samples)}")
    print(f"新增ID: {len(result['new_ids_b'])}")
    print(f"缺失ID: {len(result['missing_ids_b'])}")
    print(f"频率变化: {len(result['frequency_shifts'])}")
    print(f"字段异常候选: {len(result['field_anomalies'])}")
    print(f"输出: {output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
