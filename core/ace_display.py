# ─────────────────────────────────────────
# 连接表「账户 / 游戏」列：将 ACE 解析出的标识映射为游戏显示名
# ─────────────────────────────────────────
from __future__ import annotations

_BUILTIN_IDENTIFIER_NAMES: dict[str, str] = {}


def _norm_hex8_key(s: str) -> str | None:
    t = "".join((s or "").split()).upper()
    if len(t) == 8 and all("0" <= c <= "9" or "A" <= c <= "F" for c in t):
        return t
    return None


def _strip_key(s: str) -> str:
    return "".join((s or "").split()).upper()


def build_ace_identifier_lookup(app_config) -> dict[str, str]:
    """
    合并 3366_products 的 name（键为 8 位 hex）与 ace_identifier_display_map。
    app_config：带 .get(key) 的配置对象（如 core.config.app_config）。
    """
    out: dict[str, str] = dict(_BUILTIN_IDENTIFIER_NAMES)
    prods = app_config.get("3366_products") if app_config else None
    if isinstance(prods, dict):
        for k, v in prods.items():
            if not isinstance(v, dict):
                continue
            name = (v.get("name") or "").strip()
            if not name:
                continue
            h8 = _norm_hex8_key(str(k))
            if h8:
                out[h8] = name
            out[_strip_key(str(k))] = name
    extra = app_config.get("ace_identifier_display_map") if app_config else None
    if isinstance(extra, dict):
        for k, v in extra.items():
            if not isinstance(v, str) or not v.strip():
                continue
            name = v.strip()
            h8 = _norm_hex8_key(str(k))
            if h8:
                out[h8] = name
            out[_strip_key(str(k))] = name
    return out


def ace_identifier_display(raw: str, lookup: dict[str, str]) -> tuple[str, str]:
    """
    返回 (单元格文案, 悬停提示)。
    未匹配映射时单元格为「未知」，提示中仍带原始标识便于核对。
    """
    raw = (raw or "").strip()
    if not raw or raw == "—":
        return "—", ""

    k_strip = _strip_key(raw)
    if k_strip in lookup:
        return lookup[k_strip], f"原始标识: {raw}"

    h8 = _norm_hex8_key(raw)
    if h8 and h8 in lookup:
        return lookup[h8], f"原始标识: {raw}"

    return "未知", f"原始标识: {raw}（未在 config 中配置映射）"


def format_conn_table_id_pair(
    rec_id: str,
    rep_id: str,
    *,
    lookup: dict[str, str],
) -> tuple[str, str]:
    """录制与重放各有一份标识时的展示（含 tooltip）。"""
    tips: list[str] = []
    parts: list[str] = []
    if rec_id:
        dr, tr = ace_identifier_display(rec_id, lookup)
        parts.append(f"{dr}(录)")
        if tr:
            tips.append(tr)
    if rep_id:
        dp, tp = ace_identifier_display(rep_id, lookup)
        parts.append(f"{dp}(放)")
        if tp:
            tips.append(tp)
    if not parts:
        return "—", ""
    return " / ".join(parts), "\n".join(tips)
