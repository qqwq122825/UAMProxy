#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
只用 1002 和固定客户端密钥（DH_priv）推导 AES key。
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
from pathlib import Path

P_HEX = (
    "97981E0AADE0DE72E29CD2789193562547BAD2591FB7E59C"
    "523923DDDECEBCCAE49BDCD4B8EC39022B0BD95D4AF8FD3C"
    "D600919393255C1084C2FD5ABB2FEDE3"
)
DH_PUB_OFF = 0x18
DH_PUB_LEN = 64


def parse_hex(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace("\n", "").replace("0x", "")
    if len(s) % 2:
        raise ValueError("hex 长度必须为偶数")
    return binascii.unhexlify(s)


def read_client_key() -> str:
    return (
        Path(__file__).with_name("client_dh_priv.txt").read_text(encoding="utf-8").strip()
    )


def extract_server_pub_from_1002(frame: bytes, pub_off: int) -> bytes:
    if frame[0:2] != b"\x33\x66":
        raise ValueError("不是 33 66 帧")
    if frame[6:8] != b"\x10\x02":
        raise ValueError(f"不是 1002 帧，实际 f3={frame[6:8].hex()}")
    end = pub_off + DH_PUB_LEN
    if len(frame) < end:
        raise ValueError(f"1002 帧太短，无法取 server_pub: len={len(frame)}")
    return frame[pub_off:end]


def derive_aes_key(client_priv_hex: str, server_pub: bytes) -> tuple[bytes, bytes]:
    p = int(P_HEX, 16)
    client_priv = int(client_priv_hex, 16)
    server_pub_int = int.from_bytes(server_pub, "big")
    shared = pow(server_pub_int, client_priv, p)
    shared_bytes = shared.to_bytes((p.bit_length() + 7) // 8, "big")
    aes_key = hashlib.md5(shared_bytes).digest()
    return shared_bytes, aes_key


def main() -> int:
    parser = argparse.ArgumentParser(description="只用 1002 + 固定客户端密钥 推导 AES key")
    parser.add_argument("--frame-1002-hex", help="完整 1002 帧 hex")
    parser.add_argument("--server-pub-hex", help="1002 里的服务端公钥 64B hex")
    parser.add_argument(
        "--dh-pub-offset",
        type=lambda s: int(s, 0),
        default=DH_PUB_OFF,
        help=f"1002 帧内 server_pub 偏移，默认 {DH_PUB_OFF:#x}",
    )
    args = parser.parse_args()

    if not args.frame_1002_hex and not args.server_pub_hex:
        parser.error("需要 --frame-1002-hex 或 --server-pub-hex")
    if args.frame_1002_hex and args.server_pub_hex:
        parser.error("--frame-1002-hex 和 --server-pub-hex 二选一")

    client_key = read_client_key()
    if args.frame_1002_hex:
        frame = parse_hex(args.frame_1002_hex)
        server_pub = extract_server_pub_from_1002(frame, args.dh_pub_offset)
    else:
        server_pub = parse_hex(args.server_pub_hex)
        if len(server_pub) != DH_PUB_LEN:
            raise ValueError(f"server_pub 长度必须是 {DH_PUB_LEN} 字节")

    shared, aes_key = derive_aes_key(client_key, server_pub)
    print(f"client_key={client_key}")
    print(f"server_pub={server_pub.hex()}")
    print(f"shared_secret={shared.hex()}")
    print(f"aes_key={aes_key.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
