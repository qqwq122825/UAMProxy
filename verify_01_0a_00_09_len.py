#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
01 0A 00 09 长度字段验证脚本
依据 3366协议01_0A_00_09长度字段分析.md 校验明文中的 LEN 与实际块长度是否一致。

用法：
  python verify_01_0a_00_09_len.py                    # 使用内置示例
  python verify_01_0a_00_09_len.py <hex>              # 传入 hex 字符串
  python verify_01_0a_00_09_len.py -f plain.hex      # 从文件读取
"""
from __future__ import annotations

import sys

# 块结构：00 00 00 01 | LEN(2B BE) | 01 0A 00 XX | 8B填充 | 序号 | 类型 | 高熵区
PREFIX_00000001 = b"\x00\x00\x00\x01"
MARKER_01_0A_00_09 = b"\x01\x0A\x00\x09"
MARKER_01_0A_00_21 = b"\x01\x0A\x00\x21"
HEADER_LEN = 44
ABAB = b"\xAB\xAB"


def hex_to_bytes(hex_str: str) -> bytes:
    """去除空格/换行后转 bytes"""
    s = hex_str.replace(" ", "").replace("\n", "").replace("\r", "")
    return bytes.fromhex(s)


def verify_plaintext(plain: bytes) -> list[dict]:
    """
    验证 40 13 明文中的 01 0A 00 09/21 块长度字段。
    返回每块校验结果列表。
    """
    if len(plain) < HEADER_LEN or plain[42:44] != ABAB:
        return [{"ok": False, "err": "非有效 40 13 明文（需 44 字节头且 [42:44]=ABAB）"}]

    payload = plain[HEADER_LEN:]
    proto_len = int.from_bytes(plain[4:8], "big") if len(plain) >= 8 else 0
    actual_payload_len = len(payload)

    results = []
    # 1. PROTO_LEN 校验（可选：单块时 PROTO_LEN ≈ payload 长度）
    results.append({
        "name": "PROTO_LEN",
        "offset": "plain[4:8]",
        "declared": proto_len,
        "actual": actual_payload_len,
        "ok": proto_len == actual_payload_len,
        "note": "ABAB 后 PAYLOAD 总长度",
    })

    # 2. 遍历所有 01 0A 00 09/21 块，校验块内 LEN
    for marker, xx in ((MARKER_01_0A_00_09, "09"), (MARKER_01_0A_00_21, "21")):
        pos = 0
        while True:
            i = payload.find(marker, pos)
            if i < 0:
                break
            if i < 6:
                pos = i + 1
                continue
            if payload[i - 6 : i - 2] != PREFIX_00000001:
                pos = i + 1
                continue

            blen_pos = i - 2
            declared_len = int.from_bytes(payload[blen_pos : blen_pos + 2], "big")
            block_start = i - 6
            block_end_ex = block_start + declared_len
            actual_len = block_end_ex - block_start if block_end_ex <= len(payload) else None

            if actual_len is None:
                ok = False
                note = f"块尾 {block_end_ex} 超出 payload 长度 {len(payload)}"
            else:
                ok = declared_len == actual_len
                note = "LEN = 从 00000001 到块尾的字节数" if ok else f"声明 {declared_len} != 实际 {actual_len}"

            results.append({
                "name": f"块 LEN (01 0A 00 {xx})",
                "offset": f"payload[{blen_pos}:{blen_pos+2}]",
                "declared": declared_len,
                "actual": actual_len,
                "ok": ok,
                "note": note,
                "block_start": block_start,
                "block_end_ex": block_end_ex,
                "high_entropy_start": i + 14,  # 01 0A 00 XX 后 10 字节
                "high_entropy_len": (block_end_ex - (i + 14)) if block_end_ex <= len(payload) else None,
            })
            pos = i + 4

    return results


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "-f" and len(sys.argv) > 2:
            with open(sys.argv[2], "r", encoding="utf-8") as f:
                hex_input = f.read()
        else:
            hex_input = " ".join(sys.argv[1:])
    else:
        hex_input = """
00000067000002190810000300000000000000000000000000000000005D0000
00000000000000000044ABAB000000010219010A000900000000000000000000
02079DAEA6C501FD4E67337953CC607C53F0AB947F1A86A85CC4BAA727AF9274
BDC6F678C70DC0F77CF275F85D550262199550CB4416FC2F106B0C0A7E7DC1CF
3501EF2F3344C157C787599A962FA01EB7041C08D6271A0ECF8B42E25895BDB9
476DD6B3D2BD9178A7935690F98AD4E486262322BF9B432F816F595200CDEC59
00770B6DEDB50D56B4A480CF5C2D1F03786D893D083771601B0216498C4BF9E6
C91E82EB2B1A02418F3CD8190F218D72BEBD91B4757B8186773E3EFBF23EB97A
7DAA25A7C52DC6530359496278125FCC429AA7C2BC58BB3FB90D7CC619A2C0BC
D025B93211D7408C776387347DDE8032E51F3317EF26F03AAD3D1D64BF4CE382
5282E9A4BFA10903116C1788647451207D069432F4629E12ADF52D595D5F682B
FA269F90D0C6F07C106B0C0A7E7DC1CF3501EF2F3344C157C787599A962FA01E
B7041C08D6271A0ECF8B42E25895BDB9476DD6B3D2BD917812BCFFF8A9D0F320
D3147EE3F99A992A81AC677E38E3437595CEBAB6E76C7FB9B4A480CF5C2D1F03
786D893D083771607ED2DBEA0A84A5C0C144F6FB3A76CCBA8F3CD8190F218D72
BEBD91B4757B8186773E3EFBF23EB97A7DAA25A7C52DC6530359496278125FCC
429AA7C2BC58BB3F9378D079370684AEA495F35DC34BE125B41DBF15BAD9C0BA
7CBAFE8D52D11FF50305E6292083459F559F0B85EC271464041B9C99675108D7
BDB44AFB33
"""

    try:
        plain = hex_to_bytes(hex_input)
    except ValueError as e:
        print(f"HEX 解析失败: {e}")
        return 1

    print(f"明文长度: {len(plain)} 字节")
    print("=" * 60)

    results = verify_plaintext(plain)
    all_ok = True
    for r in results:
        if "err" in r:
            print(f"错误: {r['err']}")
            all_ok = False
            continue
        status = "[OK]" if r["ok"] else "[FAIL]"
        if not r["ok"]:
            all_ok = False
        print(f"{status} {r['name']}")
        print(f"   偏移: {r['offset']}  声明值: {r['declared']}  实际: {r['actual']}")
        print(f"   说明: {r['note']}")
        if "high_entropy_len" in r and r.get("high_entropy_len") is not None:
            print(f"   高熵区: 起点+{r['high_entropy_start']} 长度 {r['high_entropy_len']} 字节")
        print()

    print("=" * 60)
    print("全部通过" if all_ok else "存在校验失败")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
