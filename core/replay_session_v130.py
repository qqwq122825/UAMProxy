"""v1.128.10 logical game-session continuity for 01 reconnects.

The 42-byte join frame carries two different values:

* bytes ``+0x0A..+0x0D`` stay stable across the observed reconnects and are
  treated as a provisional ACE/game-process session token;
* the final four bytes are a Unix timestamp and are diagnostic only.

The token never completes a resume by itself. A candidate keeps the old
semantic snapshot pending until the first complete native Type9 report proves
that its leaf ``recordSequence`` continues the report state held in memory.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from threading import RLock
import time


JOIN_FRAME_LENGTH = 42
JOIN_SESSION_TOKEN_OFFSET = 0x0A
JOIN_UNIX_TIME_OFFSET = 0x26
DISCONNECTED_SESSION_TTL_SECONDS = 6 * 60 * 60
PENDING_JOIN_TTL_SECONDS = 5 * 60
MAX_LIVE_LEAF_FORWARD_GAP = 0xFFFF
REPLAY_PHASE_FIRST = "首次重放"
REPLAY_PHASE_CONTINUE = "续连重放"


def replay_phase_label(*, continued: bool) -> str:
    """Connection-table mode has only these two replay labels."""
    return REPLAY_PHASE_CONTINUE if continued else REPLAY_PHASE_FIRST


def join_frame_fields(frame: bytes | bytearray) -> dict | None:
    data = bytes(frame or b"")
    if len(data) != JOIN_FRAME_LENGTH or data[:5] != b"\x01\x00\x00\x00\x2A":
        return None
    return {
        "session_token_u32": int.from_bytes(
            data[JOIN_SESSION_TOKEN_OFFSET:JOIN_SESSION_TOKEN_OFFSET + 4],
            "big",
        ),
        "unix_time_u32": int.from_bytes(
            data[JOIN_UNIX_TIME_OFFSET:JOIN_UNIX_TIME_OFFSET + 4],
            "big",
        ),
    }


def live_leaf_sequence_decision(
    previous_last: int | None,
    current_first: int | None,
    *,
    max_forward_gap: int = MAX_LIVE_LEAF_FORWARD_GAP,
) -> tuple[str, dict]:
    """Classify the first native Type9 leaf after a reconnect candidate."""
    detail = {
        "previous_last_live_leaf_sequence": previous_last,
        "current_first_live_leaf_sequence": current_first,
        "forward_delta": None,
        "max_forward_gap": int(max_forward_gap),
    }
    if previous_last is None or current_first is None:
        return "PENDING", detail
    delta = (int(current_first) - int(previous_last)) & 0xFFFFFFFF
    detail["forward_delta"] = delta
    if delta == 0:
        return "CONFIRMED_RETRANSMIT", detail
    if 1 <= delta <= int(max_forward_gap):
        return "CONFIRMED_CONTINUATION", detail
    return "REJECTED_NEW_SESSION", detail


def resumed_replay_context(
    source: dict | None,
    *,
    previous_last_live_leaf_sequence: int,
    fresh_started_monotonic: float,
) -> dict:
    """Copy semantic state and mark it pending native-report confirmation."""
    old = deepcopy(source or {})
    v128 = deepcopy(old.get("v128_replenish") or {})
    for key in (
        "report_offset",
        "frame_offset",
        "group_offset",
    ):
        v128[key] = 0
    old["v128_replenish"] = v128
    old["v130_pending_reconnect"] = {
        "previous_last_live_leaf_sequence": int(
            previous_last_live_leaf_sequence
        ),
        "fresh_started_monotonic": float(fresh_started_monotonic),
    }
    old.pop("ui_replay_phase", None)
    old.pop("v130_reconnect_result", None)
    old["v130_resume_count"] = int(old.get("v130_resume_count") or 0) + 1
    return old


@dataclass
class LogicalGameSession:
    username: str
    game_id: str
    started_monotonic: float
    session_token_u32: int
    join_unix_time_u32: int
    join_seen_monotonic: float
    replay_context: dict
    last_connection_id: str = ""
    disconnected_monotonic: float | None = None


class ReplaySessionRegistry:
    """Process-local registry keyed by authenticated user and game account."""

    def __init__(
        self,
        *,
        disconnected_ttl_seconds: float = DISCONNECTED_SESSION_TTL_SECONDS,
        pending_join_ttl_seconds: float = PENDING_JOIN_TTL_SECONDS,
    ) -> None:
        self._lock = RLock()
        self.disconnected_ttl_seconds = max(1.0, float(disconnected_ttl_seconds))
        self.pending_join_ttl_seconds = max(1.0, float(pending_join_ttl_seconds))
        self.sessions: dict[tuple[str, str], LogicalGameSession] = {}
        self.pending_joins: dict[str, dict] = {}
        self.connection_keys: dict[str, tuple[str, str]] = {}

    def _cleanup(self, now: float) -> None:
        expired_sessions = [
            key
            for key, session in self.sessions.items()
            if session.disconnected_monotonic is not None
            and now - session.disconnected_monotonic
            > self.disconnected_ttl_seconds
        ]
        for key in expired_sessions:
            self.sessions.pop(key, None)
        expired_joins = [
            conn_id
            for conn_id, pending in self.pending_joins.items()
            if now - float(pending["seen_monotonic"])
            > self.pending_join_ttl_seconds
        ]
        for conn_id in expired_joins:
            self.pending_joins.pop(conn_id, None)

    def observe_join(
        self,
        conn_id: str,
        username: str,
        frame: bytes,
        *,
        now: float | None = None,
    ) -> dict | None:
        fields = join_frame_fields(frame)
        if fields is None:
            return None
        now_value = float(time.monotonic() if now is None else now)
        pending = {
            "username": str(username or ""),
            "seen_monotonic": now_value,
            **fields,
        }
        with self._lock:
            self._cleanup(now_value)
            self.pending_joins[str(conn_id)] = pending
        return dict(fields)

    def bind(
        self,
        conn_id: str,
        username: str,
        game_id: str,
        fresh_context: dict,
        *,
        fresh_started_monotonic: float,
        now: float | None = None,
    ) -> tuple[dict, float, dict]:
        now_value = float(time.monotonic() if now is None else now)
        key = (str(username or ""), str(game_id or ""))
        with self._lock:
            self._cleanup(now_value)
            pending = self.pending_joins.pop(str(conn_id), None)
            old = self.sessions.get(key)
            previous_connection_id = old.last_connection_id if old else ""
            disconnected_gap_seconds = (
                max(0.0, now_value - old.disconnected_monotonic)
                if old and old.disconnected_monotonic is not None
                else None
            )
            old_v128 = (
                old.replay_context.get("v128_replenish") or {}
                if old
                else {}
            )
            previous_last_live = old_v128.get("last_native_live_leaf_sequence")
            token_matches = bool(
                old
                and pending
                and pending.get("username") == key[0]
                and int(pending.get("session_token_u32") or 0) != 0
                and int(pending.get("session_token_u32") or 0)
                == int(old.session_token_u32)
            )
            candidate = bool(token_matches and previous_last_live is not None)
            if candidate and old:
                context = resumed_replay_context(
                    old.replay_context,
                    previous_last_live_leaf_sequence=int(previous_last_live),
                    fresh_started_monotonic=float(fresh_started_monotonic),
                )
                started = old.started_monotonic
                decision = "PENDING_LIVE_REPORT"
                classification = "RECONNECT_CANDIDATE"
            else:
                context = fresh_context
                started = float(fresh_started_monotonic)
                decision = "NEW_GAME_SESSION"
                classification = (
                    "GAME_REOPEN_OR_NEW_SESSION" if old else "FIRST_JOIN"
                )
            token = (
                int(pending.get("session_token_u32") or 0)
                if pending
                else 0
            )
            unix_time = (
                int(pending.get("unix_time_u32") or 0)
                if pending
                else 0
            )
            join_seen = (
                float(pending.get("seen_monotonic") or now_value)
                if pending
                else now_value
            )
            session = LogicalGameSession(
                username=key[0],
                game_id=key[1],
                started_monotonic=started,
                session_token_u32=token,
                join_unix_time_u32=unix_time,
                join_seen_monotonic=join_seen,
                replay_context=context,
                last_connection_id=str(conn_id),
            )
            self.sessions[key] = session
            self.connection_keys[str(conn_id)] = key
            return context, started, {
                "decision": decision,
                "continued": False,
                "candidate": candidate,
                "classification": classification,
                "had_previous_session": bool(old),
                "previous_connection_id": previous_connection_id,
                "disconnected_gap_seconds": disconnected_gap_seconds,
                "active_connection_overlap": bool(
                    old
                    and old.disconnected_monotonic is None
                    and old.last_connection_id != str(conn_id)
                ),
                "previous_session_token_u32": (
                    old.session_token_u32 if old else None
                ),
                "current_session_token_u32": token if pending else None,
                "session_token_matches": token_matches,
                "join_unix_time_u32": unix_time if pending else None,
                "previous_last_live_leaf_sequence": previous_last_live,
            }

    def finalize_live_report(
        self,
        conn_id: str,
        context: dict,
        *,
        started_monotonic: float,
    ) -> None:
        with self._lock:
            key = self.connection_keys.get(str(conn_id))
            if key in self.sessions:
                session = self.sessions[key]
                if session.last_connection_id == str(conn_id):
                    session.replay_context = context
                    session.started_monotonic = float(started_monotonic)

    def attach_context(self, conn_id: str, context: dict) -> None:
        with self._lock:
            key = self.connection_keys.get(str(conn_id))
            if key in self.sessions:
                session = self.sessions[key]
                if session.last_connection_id == str(conn_id):
                    session.replay_context = context

    def disconnect(self, conn_id: str, *, now: float | None = None) -> dict:
        now_value = float(time.monotonic() if now is None else now)
        with self._lock:
            key = self.connection_keys.pop(str(conn_id), None)
            detail = {
                "connection_id": str(conn_id),
                "username": key[0] if key else "",
                "game_id": key[1] if key else "",
                "session_token_u32": None,
                "join_unix_time_u32": None,
                "stale_connection_ignored": False,
            }
            if key in self.sessions:
                session = self.sessions[key]
                detail["session_token_u32"] = session.session_token_u32
                detail["join_unix_time_u32"] = session.join_unix_time_u32
                if session.last_connection_id == str(conn_id):
                    session.disconnected_monotonic = now_value
                    detail["logical_elapsed_seconds"] = max(
                        0.0,
                        session.disconnected_monotonic - session.started_monotonic,
                    )
                else:
                    detail["stale_connection_ignored"] = True
            self.pending_joins.pop(str(conn_id), None)
            self._cleanup(now_value)
            return detail
