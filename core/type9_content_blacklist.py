"""Type9 内容黑名单：命中进程名、包名或中文显示名后写入合法空结果叶。

8027/8029/9000 等叶子通常一条只带一个进程或一个探测包名，字符串多为
XOR 0xB6。插件路径也可能以明文出现在 0x1105、0x2000、0x011223xx。
扫描明文和 XOR-B6 两套正文；命中后由 Type9 基座改成真实0x2000空结果叶，
保留Live recordSequence，避免整叶删除形成序号空洞。
"""

from __future__ import annotations


XOR_B6 = 0xB6
CONTENT_BLACKLIST_RULE_ID = "v1268-content-blacklist-empty-2000"

# 长词优先，避免 com.mtx.mtxdfm 只报成 mtxdfm。
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

CONTENT_BLACKLIST_RULE_ROWS = (
    {
        "id": CONTENT_BLACKLIST_RULE_ID,
        "description": (
            "任意叶子命中多巴胺/巨魔/文件管理器/mtxdfm 等黑名单后改成"
            "真实44字节0x2000空结果叶，保留Live序号"
        ),
        "record_code": "*",
        "action": "empty_2000",
    },
)


def xor_b6(data: bytes) -> bytes:
    return bytes(byte ^ XOR_B6 for byte in data)


def scan_type9_content_blacklist(raw: bytes) -> dict | None:
    """在明文和 XOR-B6 正文中查找黑名单；未命中返回 None。"""
    if not raw:
        return None
    haystacks = (
        ("plain", bytes(raw).lower()),
        ("xor_b6", xor_b6(bytes(raw)).lower()),
    )
    for token in CONTENT_BLACKLIST_TOKENS:
        needle = token.encode("utf-8").lower()
        for encoding, haystack in haystacks:
            offset = haystack.find(needle)
            if offset >= 0:
                return {
                    "token": token,
                    "encoding": encoding,
                    "offset": offset,
                }
    return None
