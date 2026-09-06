#!/usr/bin/env python3
"""DFMProxy Type9 加解密核心：支持在线解析和离线复核三种算法。

当前构建已确认：
  marker + 10字节前导 + selector:u8 + key_index:u8
  + plaintext_crc32:u32be + ciphertext_length:u16be + ciphertext

selector:
  0 = tersafe 自定义可逆 S-box/XOR 流变换
  1 = MARS
  2 = RC6
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import struct
import zlib

from core.type9_crypto_constants import MARS_SBOX


MARKER = b"\x01\x0A\x00\x09"
ALGORITHM_NAMES = {
    0: "tersafe-custom-sbox-xor",
    1: "MARS",
    2: "RC6",
}
KEYS = (
    b"CHAGQX",
    b"Q_VA[\\R",
    b"SYSZZ",
    b"]P@XQA",
    b"CE]AQ",
    b"[TK",
    b"QDF\\",
    b"D^GP\\",
    b"CA@Z@P",
    b"WIX_83qpt",
)
KEY_XOR = bytes((0x8A, 0xE6, 0x9B, 0xF3, 0xC1, 0x7D, 0x40, 0x25))
TAIL_TABLE = bytes.fromhex("37924468a53dcc7fbb0fd988ee9ae95a")
MASK32 = 0xFFFFFFFF


def rol32(value: int, count: int) -> int:
    count &= 31
    value &= MASK32
    if not count:
        return value
    return ((value << count) | (value >> (32 - count))) & MASK32


def ror32(value: int, count: int) -> int:
    count &= 31
    value &= MASK32
    if not count:
        return value
    return ((value >> count) | (value << (32 - count))) & MASK32


def add32(*values: int) -> int:
    return sum(values) & MASK32


def sub32(left: int, right: int) -> int:
    return (left - right) & MASK32


def parse_hex(text: str) -> bytes:
    pairs = re.findall(r"(?i)(?:0x)?([0-9a-f]{2})(?![0-9a-f])", text)
    if pairs:
        return bytes(int(x, 16) for x in pairs)
    compact = re.sub(r"(?i)0x|[^0-9a-f]", "", text)
    if len(compact) % 2:
        raise ValueError("HEX字符数量为奇数")
    return bytes.fromhex(compact)


def load_input(path: pathlib.Path, force_hex: bool) -> bytes:
    raw = path.read_bytes()
    if force_hex or path.suffix.lower() in {".txt", ".md", ".log", ".hex"}:
        return parse_hex(raw.decode("utf-8", errors="ignore"))
    return raw


def custom_sbox(key: bytes, decrypt: bool) -> tuple[bytes, list[int]]:
    key8 = (key + b"\0" * 8)[:8]
    derived = bytes(a ^ b for a, b in zip(key8, KEY_XOR))
    table = list(range(256))
    state = (
        derived[3] | (derived[2] << 8) | (derived[1] << 16)
    ) ^ (
        derived[7] | (derived[6] << 8) | (derived[5] << 16)
    )
    for index in range(256):
        state = (state * 0x343FD + 0x269EC3) & 0xFFFFFFFFFFFFFFFF
        other = (state >> 16) & 0xFF
        table[index], table[other] = table[other], table[index]
    if decrypt:
        inverse = [0] * 256
        for index, value in enumerate(table):
            inverse[value] = index
        table = inverse
    return derived, table


def custom_transform(data: bytes, key: bytes, direction: int) -> bytes:
    """逐字节复刻 sub_C0E10 + sub_C0FC4；direction 1加密、0解密。"""
    derived, table = custom_sbox(key, decrypt=direction == 0)
    output = bytearray(len(data))
    for index, value in enumerate(data):
        index_byte = index & 0xFF
        if direction:
            value ^= index_byte
            extra = 0
        else:
            extra = index_byte
        key_byte = derived[index & 7]
        output[index] = key_byte ^ extra ^ table[(value ^ key_byte) & 0xFF]
    return bytes(output)


def tail_transform(data: bytes, key: bytes, direction: int) -> bytes:
    """复刻 sub_C380C：MARS/RC6 非16字节对齐尾部的可逆变换。"""
    key8 = (key + b"\0" * 8)[:8]
    output = bytearray(len(data))
    for index, value in enumerate(data):
        table_byte = TAIL_TABLE[index & 15]
        key_byte = key8[index & 7]
        adjustment = table_byte if direction else -table_byte
        mixed = ((table_byte ^ value ^ key_byte) + adjustment) & 0xFF
        output[index] = mixed ^ table_byte ^ key_byte
    return bytes(output)


def rc6_schedule(key: bytes) -> list[int]:
    """复刻 sub_C2BB0；8个密钥字节分别作为8个32位L字。"""
    key8 = (key + b"\0" * 8)[:8]
    schedule = [0] * 44
    schedule[0] = 0xB7E15163
    for index in range(1, 44):
        schedule[index] = add32(schedule[index - 1], 0x9E3779B9)
    words = list(key8)
    left = right = 0
    for iteration in range(132):
        si = iteration % 44
        li = iteration & 7
        left = schedule[si] = rol32(add32(schedule[si], left, right), 3)
        right = words[li] = rol32(
            add32(words[li], left, right), add32(left, right)
        )
    return schedule


def rc6_encrypt_block(block: bytes, schedule: list[int]) -> bytes:
    a, b, c, d = struct.unpack("<4I", block)
    b = add32(b, schedule[0])
    d = add32(d, schedule[1])
    for round_index in range(1, 21):
        t = rol32((b * add32(2 * b, 1)) & MASK32, 5)
        u = rol32((d * add32(2 * d, 1)) & MASK32, 5)
        a = add32(rol32(a ^ t, u), schedule[2 * round_index])
        c = add32(rol32(c ^ u, t), schedule[2 * round_index + 1])
        a, b, c, d = b, c, d, a
    a = add32(a, schedule[42])
    c = add32(c, schedule[43])
    return struct.pack("<4I", a, b, c, d)


def rc6_decrypt_block(block: bytes, schedule: list[int]) -> bytes:
    a, b, c, d = struct.unpack("<4I", block)
    c = sub32(c, schedule[43])
    a = sub32(a, schedule[42])
    for round_index in range(20, 0, -1):
        a, b, c, d = d, a, b, c
        u = rol32((d * add32(2 * d, 1)) & MASK32, 5)
        t = rol32((b * add32(2 * b, 1)) & MASK32, 5)
        c = ror32(sub32(c, schedule[2 * round_index + 1]), t) ^ u
        a = ror32(sub32(a, schedule[2 * round_index]), u) ^ t
    d = sub32(d, schedule[1])
    b = sub32(b, schedule[0])
    return struct.pack("<4I", a, b, c, d)


def rc6_transform(data: bytes, key: bytes, direction: int) -> bytes:
    schedule = rc6_schedule(key)
    aligned = len(data) & ~15
    block_fn = rc6_encrypt_block if direction else rc6_decrypt_block
    output = bytearray()
    for offset in range(0, aligned, 16):
        output.extend(block_fn(data[offset : offset + 16], schedule))
    output.extend(tail_transform(data[aligned:], key, direction))
    return bytes(output)


def mars_gen_mask(value: int) -> int:
    mask = (~value ^ (value >> 1)) & 0x7FFFFFFF
    mask &= (mask >> 1) & (mask >> 2)
    mask &= (mask >> 3) & (mask >> 6)
    if not mask:
        return 0
    mask <<= 1
    mask |= mask << 1
    mask |= mask << 2
    mask |= mask << 4
    mask |= (mask << 1) & (~value) & 0x80000000
    return mask & 0xFFFFFFFC


def mars_schedule(key: bytes) -> list[int]:
    """复刻 sub_C10A0 的128位 MARS 密钥扩展。"""
    key16 = (key + b"\0" * 16)[:16]
    temp = list(struct.unpack("<4I", key16)) + [0] * 11
    temp[4] = 4
    schedule = [0] * 40
    for outer in range(4):
        for index in range(15):
            temp[index] = (
                temp[index]
                ^ rol32(temp[(index + 8) % 15] ^ temp[(index + 13) % 15], 3)
                ^ (4 * index + outer)
            ) & MASK32
        for _ in range(4):
            for index in range(15):
                temp[index] = rol32(
                    add32(temp[index], MARS_SBOX[temp[(index + 14) % 15] & 0x1FF]),
                    9,
                )
        for index in range(10):
            schedule[10 * outer + index] = temp[(4 * index) % 15]
    for index in range(5, 37, 2):
        word = schedule[index] | 3
        mask = mars_gen_mask(word)
        if mask:
            word ^= rol32(MARS_SBOX[265 + (schedule[index] & 3)], schedule[index - 1]) & mask
        schedule[index] = word & MASK32
    return schedule


def mars_forward_mix(a: int, b: int, c: int, d: int):
    rotate = ror32(a, 8)
    b = (b ^ MARS_SBOX[a & 0xFF]) & MASK32
    b = add32(b, MARS_SBOX[(rotate & 0xFF) + 256])
    rotate = ror32(a, 16)
    a = ror32(a, 24)
    c = add32(c, MARS_SBOX[rotate & 0xFF])
    d = (d ^ MARS_SBOX[(a & 0xFF) + 256]) & MASK32
    return a, b, c, d


def mars_backward_mix(a: int, b: int, c: int, d: int):
    rotate = rol32(a, 8)
    b = (b ^ MARS_SBOX[(a & 0xFF) + 256]) & MASK32
    c = sub32(c, MARS_SBOX[rotate & 0xFF])
    rotate = rol32(a, 16)
    a = rol32(a, 24)
    d = sub32(d, MARS_SBOX[(rotate & 0xFF) + 256])
    d = (d ^ MARS_SBOX[a & 0xFF]) & MASK32
    return a, b, c, d


def mars_forward_round(a: int, b: int, c: int, d: int, index: int, schedule):
    middle = add32(a, schedule[index])
    a = rol32(a, 13)
    right = (a * schedule[index + 1]) & MASK32
    left = MARS_SBOX[middle & 0x1FF]
    right = rol32(right, 5)
    left ^= right
    c = add32(c, rol32(middle, right))
    right = rol32(right, 5)
    left ^= right
    d = (d ^ right) & MASK32
    b = add32(b, rol32(left, right))
    return a, b, c, d


def mars_reverse_round(a: int, b: int, c: int, d: int, index: int, schedule):
    right = (a * schedule[index + 1]) & MASK32
    a = ror32(a, 13)
    middle = add32(a, schedule[index])
    left = MARS_SBOX[middle & 0x1FF]
    right = rol32(right, 5)
    left ^= right
    c = sub32(c, rol32(middle, right))
    right = rol32(right, 5)
    left ^= right
    d = (d ^ right) & MASK32
    b = sub32(b, rol32(left, right))
    return a, b, c, d


def mars_apply_round(words, order, index, schedule, reverse=False):
    fn = mars_reverse_round if reverse else mars_forward_round
    selected = fn(*(words[position] for position in order), index, schedule)
    for position, value in zip(order, selected):
        words[position] = value


def mars_encrypt_block(block: bytes, schedule: list[int]) -> bytes:
    a, b, c, d = struct.unpack("<4I", block)
    a, b, c, d = (add32(a, schedule[0]), add32(b, schedule[1]),
                  add32(c, schedule[2]), add32(d, schedule[3]))
    for _ in range(2):
        a, b, c, d = mars_forward_mix(a, b, c, d); a = add32(a, d)
        b, c, d, a = mars_forward_mix(b, c, d, a); b = add32(b, c)
        c, d, a, b = mars_forward_mix(c, d, a, b)
        d, a, b, c = mars_forward_mix(d, a, b, c)
    words = [a, b, c, d]
    first = ((0,1,2,3),(1,2,3,0),(2,3,0,1),(3,0,1,2)) * 2
    second = ((0,3,2,1),(1,0,3,2),(2,1,0,3),(3,2,1,0)) * 2
    for round_index, order in enumerate(first + second):
        mars_apply_round(words, order, 4 + 2 * round_index, schedule)
    a, b, c, d = words
    for _ in range(2):
        a, b, c, d = mars_backward_mix(a, b, c, d)
        b, c, d, a = mars_backward_mix(b, c, d, a); c = sub32(c, b)
        c, d, a, b = mars_backward_mix(c, d, a, b); d = sub32(d, a)
        d, a, b, c = mars_backward_mix(d, a, b, c)
    return struct.pack("<4I", sub32(a,schedule[36]), sub32(b,schedule[37]),
                       sub32(c,schedule[38]), sub32(d,schedule[39]))


def mars_decrypt_block(block: bytes, schedule: list[int]) -> bytes:
    d, c, b, a = struct.unpack("<4I", block)
    d, c, b, a = (add32(d, schedule[36]), add32(c, schedule[37]),
                  add32(b, schedule[38]), add32(a, schedule[39]))
    for _ in range(2):
        a, b, c, d = mars_forward_mix(a, b, c, d); a = add32(a, d)
        b, c, d, a = mars_forward_mix(b, c, d, a); b = add32(b, c)
        c, d, a, b = mars_forward_mix(c, d, a, b)
        d, a, b, c = mars_forward_mix(d, a, b, c)
    words = [a, b, c, d]
    first = ((0,1,2,3),(1,2,3,0),(2,3,0,1),(3,0,1,2)) * 2
    second = ((0,3,2,1),(1,0,3,2),(2,1,0,3),(3,2,1,0)) * 2
    reverse_indices = list(range(34, 18, -2)) + list(range(18, 2, -2))
    for order, key_index in zip(first + second, reverse_indices):
        mars_apply_round(words, order, key_index, schedule, reverse=True)
    a, b, c, d = words
    for _ in range(2):
        a, b, c, d = mars_backward_mix(a, b, c, d)
        b, c, d, a = mars_backward_mix(b, c, d, a); c = sub32(c, b)
        c, d, a, b = mars_backward_mix(c, d, a, b); d = sub32(d, a)
        d, a, b, c = mars_backward_mix(d, a, b, c)
    d, c, b, a = (sub32(d,schedule[0]), sub32(c,schedule[1]),
                  sub32(b,schedule[2]), sub32(a,schedule[3]))
    return struct.pack("<4I", d, c, b, a)


def mars_transform(data: bytes, key: bytes, direction: int) -> bytes:
    schedule = mars_schedule(key)
    aligned = len(data) & ~15
    block_fn = mars_encrypt_block if direction else mars_decrypt_block
    output = bytearray()
    for offset in range(0, aligned, 16):
        output.extend(block_fn(data[offset : offset + 16], schedule))
    output.extend(tail_transform(data[aligned:], key, direction))
    return bytes(output)


def type9_transform(data: bytes, selector: int, key: bytes, direction: int) -> bytes:
    if selector == 0:
        return custom_transform(data, key, direction)
    if selector == 1:
        return mars_transform(data, key, direction)
    if selector == 2:
        return rc6_transform(data, key, direction)
    raise ValueError(f"未知算法选择器: {selector}")


def find_records(data: bytes):
    cursor = 0
    while True:
        marker = data.find(MARKER, cursor)
        if marker < 0:
            return
        header = marker + 14
        if header + 8 <= len(data):
            selector = data[header]
            key_index = data[header + 1]
            stored_crc = int.from_bytes(data[header + 2 : header + 6], "big")
            length = int.from_bytes(data[header + 6 : header + 8], "big")
            start = header + 8
            end = start + length
            if selector <= 2 and key_index <= 9 and end <= len(data):
                yield {
                    "marker_offset": marker,
                    "selector": selector,
                    "key_index": key_index,
                    "stored_crc32": stored_crc,
                    "ciphertext_offset": start,
                    "ciphertext_length": length,
                    "ciphertext": data[start:end],
                }
        cursor = marker + 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path)
    parser.add_argument("--hex", action="store_true", help="按HEX文本读取")
    parser.add_argument("--output-dir", type=pathlib.Path)
    args = parser.parse_args()

    data = load_input(args.input, args.hex)
    out = args.output_dir or args.input.with_name(args.input.stem + "-decoded")
    out.mkdir(parents=True, exist_ok=True)
    report = []
    for index, record in enumerate(find_records(data), 1):
        selector = record["selector"]
        key_index = record["key_index"]
        item = {
            key: value
            for key, value in record.items()
            if key != "ciphertext"
        }
        item["algorithm"] = ALGORITHM_NAMES[selector]
        item["key_ascii"] = KEYS[key_index].decode("ascii")
        cipher_path = out / f"record-{index:03d}-ciphertext.bin"
        cipher_path.write_bytes(record["ciphertext"])
        item["ciphertext_file"] = str(cipher_path)
        plaintext = type9_transform(
            record["ciphertext"], selector, KEYS[key_index], direction=0
        )
        calculated = zlib.crc32(plaintext) & 0xFFFFFFFF
        plain_path = out / f"record-{index:03d}-plaintext.bin"
        plain_path.write_bytes(plaintext)
        item.update(
            {
                "plaintext_file": str(plain_path),
                "calculated_crc32": calculated,
                "crc32_matches": calculated == record["stored_crc32"],
                "plaintext_head_hex": plaintext[:64].hex(),
                "decrypt_status": "离线解密完成",
            }
        )
        report.append(item)

    report_path = out / "report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"识别记录={len(report)} 报告={report_path}")
    for item in report:
        status = item.get("crc32_matches", "-")
        print(
            "offset=0x%x selector=%d(%s) key=%d crc=0x%08x match=%s"
            % (
                item["marker_offset"],
                item["selector"],
                item["algorithm"],
                item["key_index"],
                item["stored_crc32"],
                status,
            )
        )


if __name__ == "__main__":
    main()
