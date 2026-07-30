# ─────────────────────────────────────────
# ACE 0x01 包结构校验（与仓库根目录 verify_01_packet.py 算法一致，供日志/自动化调用）
# ─────────────────────────────────────────
from __future__ import annotations


def _lines_verify_ace_01_packet(packet: bytes) -> list[str]:
    out: list[str] = []
    out.append(f"实际包总长度: {len(packet)} 字节 (0x{len(packet):04X})")

    if len(packet) < 5:
        out.append("[ERROR] 封包长度小于 5 字节，不是有效的 01 包")
        return out

    if packet[0] != 0x01:
        out.append(f"[ERROR] 封包未以 01 开头，首字节为 {packet[0]:02X}")
        return out
    out.append("[OK] 包头验证通过 (01)")

    header_length = (packet[3] << 8) | packet[4]
    out.append(f"[*] 包头标称长度 (a[3..4]): {header_length} 字节 (0x{header_length:04X})")
    if header_length == len(packet):
        out.append("[OK] 封包总长度校验通过")
    else:
        out.append(
            f"[ERROR] 标称长度 {header_length} 与实际长度 {len(packet)} 不一致！"
        )

    if len(packet) > 55:
        seg_a_len = len(packet) - 55
        if len(packet) > 54:
            read_seg_a_1 = (packet[53] << 8) | packet[54]
            out.append(
                f"[*] 段A标称长度1 (a[53..54]): {read_seg_a_1} (0x{read_seg_a_1:04X}) | 期望: {seg_a_len}"
            )
            if read_seg_a_1 == seg_a_len:
                out.append("[OK] 段A长度1 校验通过")
            else:
                out.append(f"[ERROR] 段A长度1 {read_seg_a_1} 与期望值 {seg_a_len} 不符！")
        if len(packet) > 60:
            read_seg_a_2 = (packet[59] << 8) | packet[60]
            out.append(
                f"[*] 段A标称长度2 (a[59..60]): {read_seg_a_2} (0x{read_seg_a_2:04X}) | 期望: {seg_a_len}"
            )
            if read_seg_a_2 == seg_a_len:
                out.append("[OK] 段A长度2 校验通过")
            else:
                out.append(f"[ERROR] 段A长度2 {read_seg_a_2} 与期望值 {seg_a_len} 不符！")
    else:
        out.append("[-] 封包长度<=55，跳过段A验证")

    if len(packet) > 78:
        id_len = packet[78]
        out.append(f"[*] 账号 ID 长度 (a[78]): {id_len} 字节")
        if 0 < id_len <= 64:
            account_id_bytes = packet[79 : 79 + id_len]
            try:
                account_id = account_id_bytes.decode("ascii")
                out.append(f"[*] 账号 ID 解析为: {account_id}")
            except Exception:
                out.append(f"[*] 账号 ID Hex: {account_id_bytes.hex().upper()}")
            seg_b_start = 78 + id_len + 3
            if seg_b_start < len(packet):
                expected_seg_b_len = len(packet) - seg_b_start
                out.append(
                    f"[*] 段B起始偏移: {seg_b_start}，期望长度: {expected_seg_b_len}"
                )
                pos1 = 78 + id_len + 1
                pos2 = 78 + id_len + 7
                if pos1 + 1 < len(packet):
                    read_seg_b_1 = (packet[pos1] << 8) | packet[pos1 + 1]
                    out.append(
                        f"[*] 段B标称长度1: {read_seg_b_1} (0x{read_seg_b_1:04X}) | 期望: {expected_seg_b_len}"
                    )
                    if read_seg_b_1 == expected_seg_b_len:
                        out.append("[OK] 段B长度1 校验通过")
                    else:
                        out.append(
                            f"[ERROR] 段B长度1 {read_seg_b_1} 与期望值 {expected_seg_b_len} 不符！"
                        )
                if pos2 + 1 < len(packet):
                    read_seg_b_2 = (packet[pos2] << 8) | packet[pos2 + 1]
                    out.append(
                        f"[*] 段B标称长度2: {read_seg_b_2} (0x{read_seg_b_2:04X}) | 期望: {expected_seg_b_len}"
                    )
                    if read_seg_b_2 == expected_seg_b_len:
                        out.append("[OK] 段B长度2 校验通过")
                    else:
                        out.append(
                            f"[ERROR] 段B长度2 {read_seg_b_2} 与期望值 {expected_seg_b_len} 不符！"
                        )
            else:
                out.append("[-] 封包长度不足以包含完整的段B信息，跳过验证")
        else:
            out.append("[-] ID长度不合法或为0，跳过段B验证")
    else:
        out.append("[-] 封包长度<=78，跳过账号和段B验证")

    return out


def get_01_packet_verify_summary(packet: bytes) -> str:
    """
    返回单行校验摘要，供连接详情日志使用。与 verify_01_packet.py 算法一致。
    """
    if len(packet) < 5 or packet[0] != 0x01:
        return "验证: 非有效01包"
    errs: list[str] = []
    header_len = (packet[3] << 8) | packet[4]
    if header_len != len(packet):
        errs.append("总长度")
    if len(packet) > 55:
        seg_a = len(packet) - 55
        if len(packet) > 54 and ((packet[53] << 8) | packet[54]) != seg_a:
            errs.append("段A")
        if len(packet) > 60 and ((packet[59] << 8) | packet[60]) != seg_a:
            errs.append("段A2")
    if len(packet) > 78:
        id_len = packet[78]
        if 0 < id_len <= 64:
            seg_b_start = 78 + id_len + 3
            if seg_b_start < len(packet):
                exp = len(packet) - seg_b_start
                pos1 = 78 + id_len + 1
                pos2 = 78 + id_len + 7
                if pos1 + 1 < len(packet) and ((packet[pos1] << 8) | packet[pos1 + 1]) != exp:
                    errs.append("段B")
                if pos2 + 1 < len(packet) and ((packet[pos2] << 8) | packet[pos2 + 1]) != exp:
                    errs.append("段B2")
    if errs:
        return f"验证: 不符({','.join(errs)})"
    return "验证: 通过"


def format_01_packet_verify_report(data: bytes | str) -> str:
    """
    返回多行文本报告。data 为完整 01 子包 bytes，或连续 hex 字符串（可含空格换行）。
    """
    try:
        if isinstance(data, bytes):
            packet = data
        else:
            hex_data = "".join(data.split())
            packet = bytes.fromhex(hex_data)
    except ValueError as e:
        return f"[ERROR] 无法解析 Hex 数据: {e}"

    lines = ["======== 0x01 包结构验证 ========", *_lines_verify_ace_01_packet(packet), "======== 结束 ========"]
    return "\n".join(lines)
