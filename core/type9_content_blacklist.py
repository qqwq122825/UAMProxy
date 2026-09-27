"""Type9 内容黑名单：进程/包名命中后改写为合法替换叶。

三角洲：任意叶命中后改成 44 字节 0x2000 空结果叶。
暗区 UAM：仅 0x8418 进程上报叶，命中后改成 44 字节 0x8306 固定叶（保留 Live 序号）。
"""

from __future__ import annotations

from core.edition import (
    type9_legacy_builtin_intercepts_enabled,
    type9_uam_content_blacklist_enabled,
)


XOR_B6 = 0xB6
CONTENT_BLACKLIST_RULE_ID = "v1268-content-blacklist-empty-2000"
UAM_CONTENT_BLACKLIST_RULE_ID = "uam-8418-process-blacklist-replace-8306"
UAM_PROCESS_REPORT_MESSAGE_ID = 0x8418
UAM_CLEAN_8306_LENGTH = 44
# 样本 run_20260927：40 条 0x8306 仅 recordSequence 不同，正文结构一致。
UAM_CLEAN_8306_TEMPLATE = bytes.fromhex(
    "00000001002C0102000A00000010000000000000001683062167000234560001000000000000000000000000"
)

CONTENT_BLACKLIST_TOKENS: tuple[str, ...] = tuple(
    sorted(
        {
            "com.mtx.mtxdfm",
            "mtxdfm",
            "dfm_cn_yy",
            "dopamine",
            "多巴胺",
            "trollstore",
            "巨魔",
            "filza",
            "文件管理器",
            "sileo",
            "roothide",
            "zebra",
            "appstoreplus",
        },
        key=lambda token: (-len(token.encode("utf-8")), token.lower()),
    )
)

UAM_CONTENT_BLACKLIST_TOKENS: tuple[str, ...] = tuple(
    sorted(
        {
            "com.mtx.mtxuam",
            "mtxuam",
            "dopamine",
            "多巴胺",
            "trollstore",
            "巨魔",
            "filza",
            "文件管理器",
            "sileo",
            "roothide",
            "zebra",
            "appstoreplus",
        },
        key=lambda token: (-len(token.encode("utf-8")), token.lower()),
    )
)

_DFM_CONTENT_BLACKLIST_RULE_ROW = {
    "id": CONTENT_BLACKLIST_RULE_ID,
    "description": (
        "任意叶子命中多巴胺/巨魔/文件管理器/mtxdfm 等黑名单后改成"
        "真实44字节0x2000空结果叶，保留Live序号"
    ),
    "record_code": "*",
    "action": "empty_2000",
}

_UAM_CONTENT_BLACKLIST_RULE_ROW = {
    "id": UAM_CONTENT_BLACKLIST_RULE_ID,
    "description": (
        "0x8418进程上报命中mtxuam/巨魔/文件管理器等黑名单后改成"
        "真实44字节0x8306叶，保留Live序号"
    ),
    "record_code": "*",
    "message_id": "0x8418",
    "action": "replace_8306",
}

if type9_legacy_builtin_intercepts_enabled():
    CONTENT_BLACKLIST_RULE_ROWS = (_DFM_CONTENT_BLACKLIST_RULE_ROW,)
elif type9_uam_content_blacklist_enabled():
    CONTENT_BLACKLIST_RULE_ROWS = (_UAM_CONTENT_BLACKLIST_RULE_ROW,)
else:
    CONTENT_BLACKLIST_RULE_ROWS = ()


def xor_b6(data: bytes) -> bytes:
    return bytes(byte ^ XOR_B6 for byte in data)


def uam_clean_8306_leaf(sequence: int, *, version: int = 1) -> bytes:
    """根叶形态 0x8306 44B，对齐 UAM 样本固定正文。"""
    data = bytearray(UAM_CLEAN_8306_TEMPLATE)
    data[0:4] = int(version).to_bytes(4, "big")
    data[4:6] = UAM_CLEAN_8306_LENGTH.to_bytes(2, "big")
    data[10:14] = int(sequence).to_bytes(4, "big")
    return bytes(data)


def _scan_tokens(
    raw: bytes,
    tokens: tuple[str, ...],
    *,
    replace_kind: str,
    rule_id: str,
) -> dict | None:
    if not raw:
        return None
    haystacks = (
        ("plain", bytes(raw).lower()),
        ("xor_b6", xor_b6(bytes(raw)).lower()),
    )
    for token in tokens:
        needle = token.encode("utf-8").lower()
        for encoding, haystack in haystacks:
            offset = haystack.find(needle)
            if offset >= 0:
                return {
                    "token": token,
                    "encoding": encoding,
                    "offset": offset,
                    "replace_kind": replace_kind,
                    "rule_id": rule_id,
                }
    return None


def scan_type9_content_blacklist(
    raw: bytes,
    *,
    message_id: int | None = None,
) -> dict | None:
    """在明文和 XOR-B6 正文中查找黑名单；未命中返回 None。"""
    if type9_legacy_builtin_intercepts_enabled():
        return _scan_tokens(
            raw,
            CONTENT_BLACKLIST_TOKENS,
            replace_kind="dfm_empty_2000",
            rule_id=CONTENT_BLACKLIST_RULE_ID,
        )
    if type9_uam_content_blacklist_enabled():
        if int(message_id or 0) != UAM_PROCESS_REPORT_MESSAGE_ID:
            return None
        return _scan_tokens(
            raw,
            UAM_CONTENT_BLACKLIST_TOKENS,
            replace_kind="uam_8306",
            rule_id=UAM_CONTENT_BLACKLIST_RULE_ID,
        )
    return None
