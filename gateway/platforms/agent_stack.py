"""Private durable Agent Stack channel adapter.

The adapter implements ``agent_stack.channel.v1`` over an authenticated,
length-prefixed JSON stream on a Unix-domain socket. Command ingress and event
outbox writes share SQLite transactions so reconnects can replay accepted work
without executing it twice.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import struct
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from gateway.config import Platform, PlatformConfig
from gateway.platform_registry import PlatformEntry, platform_registry
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    ProcessingOutcome,
    SendResult,
)
from gateway.session import SessionSource, build_session_key

logger = logging.getLogger(__name__)

CONTRACT_VERSION = "agent_stack.channel.v1"
SCHEMA_VERSION = 1
MAX_FRAME_BYTES = 1_048_576
MAX_COMMAND_PAYLOAD_BYTES = 524_288
MAX_EVENT_BYTES = 262_144
MAX_EVENTS_PER_TURN = 10_000
MAX_IDENTIFIER_BYTES = 128
MAX_VISIBLE_TEXT_DELTA_BYTES = 65_536
MAX_VISIBLE_TEXT_CHECKPOINT_BYTES = 262_144
MAX_ATTACHMENT_DESCRIPTORS = 4
MAX_ACTIVE_TURNS = 64

COMMAND_KINDS = (
    "conversation.bind",
    "turn.submit",
    "turn.cancel",
    "event.ack",
)
EVENT_KINDS = (
    "conversation.bound",
    "turn.accepted",
    "turn.started",
    "turn.activity",
    "turn.text.delta",
    "turn.text.checkpoint",
    "turn.approval.required",
    "turn.resumed",
    "turn.cancel_requested",
    "conversation.advanced",
    "turn.delivery_error",
    "turn.completed",
    "turn.failed",
    "turn.cancelled",
)
TERMINAL_KINDS = {"turn.completed", "turn.failed", "turn.cancelled"}
FORBIDDEN_PRIVATE_FIELDS = {
    "raw_tool_output",
    "tool_arguments",
    "tool_result",
    "chain_of_thought",
    "reasoning_content",
    "system_prompt",
    "internal_exception",
    "stack_trace",
    "local_path",
    "private_context",
}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{7,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)

_ERROR_ROWS = (
    ("ack_out_of_range", False, "The acknowledgement exceeds the delivered event range.", False),
    ("approval_response_unsupported", False, "Approve this action from an authorized Hermes surface.", False),
    ("attachment_forbidden", False, "This device cannot access the attachment.", False),
    ("attachment_invalid", False, "The attachment descriptor is invalid.", False),
    ("attachment_unavailable", True, "The attachment is unavailable.", False),
    ("binding_conflict", True, "The conversation binding changed; reconnect and retry.", False),
    ("binding_revoked", False, "The conversation binding was revoked.", False),
    ("conversation_forbidden", False, "This device cannot access the conversation.", False),
    ("conversation_not_found", False, "The conversation is unavailable.", False),
    ("event_payload_conflict", False, "An event sequence was reused with different content.", False),
    ("event_too_large", False, "The channel event exceeds the allowed size.", True),
    ("execution_failed", False, "Hermes could not complete the turn.", True),
    ("execution_interrupted", True, "Hermes restarted before the turn finished.", True),
    ("execution_timed_out", True, "The turn exceeded its execution limit.", True),
    ("frame_too_large", False, "The channel frame exceeds the allowed size.", False),
    ("gateway_unavailable", True, "Hermes is temporarily unavailable.", False),
    ("internal_error", True, "The channel could not process the request.", False),
    ("invalid_envelope", False, "The channel message is invalid.", False),
    ("payload_digest_conflict", False, "This command identifier was reused with different content.", False),
    ("projection_failed", True, "The conversation view could not be updated.", False),
    ("rate_limited", True, "Too many requests; retry later.", False),
    ("sequence_gap", True, "Event replay paused until the missing event is available.", False),
    ("stale_gateway_generation", False, "The turn belongs to an earlier gateway generation.", False),
    ("transcript_flush_failed", True, "The transcript could not be saved.", True),
    ("turn_already_terminal", False, "The turn has already finished.", False),
    ("turn_not_found", False, "The turn is unavailable.", False),
    ("unsupported_schema_version", False, "The peer does not support this schema version.", False),
)
ERROR_SPECS = {
    code: {"code": code, "retryable": retryable, "safe_message": message, "terminal": terminal}
    for code, retryable, message, terminal in _ERROR_ROWS
}

CAPABILITY_DOCUMENT: dict[str, Any] = {
    "commands": list(COMMAND_KINDS),
    "contract_version": CONTRACT_VERSION,
    "dispatch": {"available": True, "degraded_reason": None},
    "document_type": "capabilities",
    "error_codes": list(ERROR_SPECS.values()),
    "events": list(EVENT_KINDS),
    "features": {
        "approval_observation": True,
        "approval_response": False,
        "attachment_references": True,
        "client_cursor_gateway_derivation": False,
        "compression_continuation": True,
        "cross_surface_observation": True,
        "durable_event_replay": True,
        "durable_ingress_dedupe": True,
        "outbound_artifacts": False,
        "safe_activity": True,
        "visible_text_streaming": True,
    },
    "fixture_schema_version": 1,
    "limits": {
        "max_active_turns_per_bridge": MAX_ACTIVE_TURNS,
        "max_attachment_descriptors": MAX_ATTACHMENT_DESCRIPTORS,
        "max_client_cursor_bytes": 256,
        "max_command_payload_bytes": MAX_COMMAND_PAYLOAD_BYTES,
        "max_error_safe_message_bytes": 512,
        "max_event_bytes": MAX_EVENT_BYTES,
        "max_events_per_turn": MAX_EVENTS_PER_TURN,
        "max_frame_bytes": MAX_FRAME_BYTES,
        "max_identifier_bytes": MAX_IDENTIFIER_BYTES,
        "max_safe_activity_title_bytes": 160,
        "max_visible_text_checkpoint_bytes": MAX_VISIBLE_TEXT_CHECKPOINT_BYTES,
        "max_visible_text_delta_bytes": MAX_VISIBLE_TEXT_DELTA_BYTES,
    },
    "platform": "agent_stack",
    "schema_versions": {"maximum": 1, "minimum": 1},
    "transport": {
        "acknowledgement": "highest_contiguous",
        "client_cursor_owner": "control_api",
        "delivery": "at_least_once",
        "framing": "utf8_json_message",
        "ordering": "per_gateway_turn",
        "privacy": "private_authenticated_runtime_link",
    },
}


class AgentStackProtocolError(ValueError):
    """A redaction-safe protocol rejection."""

    def __init__(self, code: str) -> None:
        spec = ERROR_SPECS.get(code) or {
            "retryable": True,
            "safe_message": "The channel could not process the request.",
            "terminal": False,
        }
        super().__init__(spec["safe_message"])
        self.code = code
        self.retryable = bool(spec["retryable"])
        self.safe_message = str(spec["safe_message"])
        self.terminal = bool(spec["terminal"])

    def as_frame(self, *, terminal: Optional[bool] = None) -> dict[str, Any]:
        """Return the payload-free transport error frame."""
        return {
            "kind": "protocol.error",
            "error_code": self.code,
            "retryable": self.retryable,
            "safe_message": self.safe_message,
            "terminal": self.terminal if terminal is None else terminal,
        }


def _reject_number(_value: str) -> Any:
    raise AgentStackProtocolError("invalid_envelope")


def _parse_int(value: str) -> int:
    parsed = int(value)
    if abs(parsed) > 9_007_199_254_740_991:
        raise AgentStackProtocolError("invalid_envelope")
    return parsed


def _pairs_to_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AgentStackProtocolError("invalid_envelope")
        result[key] = value
    return result


def decode_json_frame(raw: bytes) -> dict[str, Any]:
    """Decode one strict UTF-8 JSON object without ambiguous number forms."""
    if len(raw) > MAX_FRAME_BYTES:
        raise AgentStackProtocolError("frame_too_large")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise AgentStackProtocolError("invalid_envelope")
    try:
        text = raw.decode("utf-8", errors="strict")
        decoder = json.JSONDecoder(
            object_pairs_hook=_pairs_to_object,
            parse_float=_reject_number,
            parse_int=_parse_int,
            parse_constant=_reject_number,
        )
        stripped = text.lstrip()
        value, end = decoder.raw_decode(stripped)
        if stripped[end:].strip():
            raise AgentStackProtocolError("invalid_envelope")
    except AgentStackProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise AgentStackProtocolError("invalid_envelope") from exc
    if not isinstance(value, dict):
        raise AgentStackProtocolError("invalid_envelope")
    _validate_json_value(value)
    return value


def _validate_json_value(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9_007_199_254_740_991:
            raise AgentStackProtocolError("invalid_envelope")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AgentStackProtocolError("invalid_envelope")
            _validate_json_value(item)
        return
    raise AgentStackProtocolError("invalid_envelope")


def canonical_json_bytes(value: Any) -> bytes:
    """Encode a value using RFC 8785-compatible v1 canonical JSON limits."""
    _validate_json_value(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def payload_digest_for_command(envelope: dict[str, Any]) -> str:
    """Calculate the command digest over the frozen v1 member set."""
    return _digest(
        {
            "channel_binding_id": envelope.get("channel_binding_id"),
            "contract_version": envelope.get("contract_version"),
            "conversation_id": envelope.get("conversation_id"),
            "gateway_turn_id": envelope.get("gateway_turn_id"),
            "ingress_id": envelope.get("ingress_id"),
            "kind": envelope.get("kind"),
            "payload": envelope.get("payload"),
            "schema_version": envelope.get("schema_version"),
            "turn_id": envelope.get("turn_id"),
        }
    )


def _payload_digest_for_event(envelope: dict[str, Any]) -> str:
    return _digest({key: value for key, value in envelope.items() if key != "payload_digest"})


def _require_exact(value: dict[str, Any], keys: set[str]) -> None:
    if set(value) != keys:
        raise AgentStackProtocolError("invalid_envelope")


def _require_id(value: Any, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES or not ID_RE.fullmatch(value):
        raise AgentStackProtocolError("invalid_envelope")


def _require_time(value: Any) -> None:
    if not isinstance(value, str) or not RFC3339_RE.fullmatch(value):
        raise AgentStackProtocolError("invalid_envelope")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AgentStackProtocolError("invalid_envelope") from exc


def _reject_private_fields(value: Any) -> None:
    if isinstance(value, dict):
        if FORBIDDEN_PRIVATE_FIELDS.intersection(value):
            raise AgentStackProtocolError("invalid_envelope")
        for child in value.values():
            _reject_private_fields(child)
    elif isinstance(value, list):
        for child in value:
            _reject_private_fields(child)


def _validate_command_payload(kind: str, payload: dict[str, Any]) -> None:
    if kind == "conversation.bind":
        _require_exact(payload, {"account_id", "binding_version", "current_hermes_session_id", "platform", "routing_key"})
        _require_id(payload["account_id"])
        _require_id(payload["routing_key"])
        _require_id(payload["current_hermes_session_id"], nullable=True)
        if payload["platform"] != "agent_stack" or not isinstance(payload["binding_version"], int) or isinstance(payload["binding_version"], bool) or payload["binding_version"] < 1:
            raise AgentStackProtocolError("invalid_envelope")
    elif kind == "turn.submit":
        _require_exact(payload, {"attachments", "client_surface", "retry_of_turn_id", "user_message_id", "visible_text"})
        _require_id(payload["user_message_id"])
        _require_id(payload["retry_of_turn_id"], nullable=True)
        if payload["client_surface"] not in {"ios", "web"} or not isinstance(payload["visible_text"], str):
            raise AgentStackProtocolError("invalid_envelope")
        attachments = payload["attachments"]
        if not isinstance(attachments, list) or len(attachments) > MAX_ATTACHMENT_DESCRIPTORS:
            raise AgentStackProtocolError("attachment_invalid")
        for attachment in attachments:
            if not isinstance(attachment, dict):
                raise AgentStackProtocolError("attachment_invalid")
            _require_exact(attachment, {"attachment_id", "media_type", "read_capability", "sha256", "size_bytes"})
            _require_id(attachment["attachment_id"])
            _require_id(attachment["read_capability"])
            if (
                not isinstance(attachment["media_type"], str)
                or not isinstance(attachment["size_bytes"], int)
                or isinstance(attachment["size_bytes"], bool)
                or attachment["size_bytes"] < 0
                or not isinstance(attachment["sha256"], str)
                or not SHA256_RE.fullmatch(attachment["sha256"])
            ):
                raise AgentStackProtocolError("attachment_invalid")
    elif kind == "turn.cancel":
        _require_exact(payload, {"reason", "target_gateway_generation"})
        if payload["reason"] != "user_requested":
            raise AgentStackProtocolError("invalid_envelope")
        _require_id(payload["target_gateway_generation"])
    elif kind == "event.ack":
        _require_exact(payload, {"highest_contiguous_gateway_sequence"})
        highest = payload["highest_contiguous_gateway_sequence"]
        if not isinstance(highest, int) or isinstance(highest, bool) or highest < 1:
            raise AgentStackProtocolError("invalid_envelope")


def validate_command_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    """Validate and return a frozen v1 command envelope."""
    _require_exact(
        envelope,
        {
            "bridge_generation", "channel_binding_id", "contract_version", "conversation_id",
            "gateway_turn_id", "ingress_id", "kind", "payload", "payload_digest",
            "schema_version", "sent_at", "turn_id",
        },
    )
    if envelope["contract_version"] != CONTRACT_VERSION:
        raise AgentStackProtocolError("invalid_envelope")
    if envelope["schema_version"] != SCHEMA_VERSION:
        raise AgentStackProtocolError("unsupported_schema_version")
    if envelope["kind"] not in COMMAND_KINDS or not isinstance(envelope["payload"], dict):
        raise AgentStackProtocolError("invalid_envelope")
    for key in ("bridge_generation", "channel_binding_id", "conversation_id", "ingress_id"):
        _require_id(envelope[key])
    _require_id(envelope["gateway_turn_id"], nullable=True)
    _require_id(envelope["turn_id"], nullable=True)
    _require_time(envelope["sent_at"])
    _reject_private_fields(envelope["payload"])
    if len(canonical_json_bytes(envelope["payload"])) > MAX_COMMAND_PAYLOAD_BYTES:
        raise AgentStackProtocolError("invalid_envelope")
    _validate_command_payload(envelope["kind"], envelope["payload"])
    if not isinstance(envelope["payload_digest"], str) or not hmac.compare_digest(
        envelope["payload_digest"], payload_digest_for_command(envelope)
    ):
        raise AgentStackProtocolError("invalid_envelope")
    if envelope["kind"] == "conversation.bind":
        if envelope["gateway_turn_id"] is not None or envelope["turn_id"] is not None:
            raise AgentStackProtocolError("invalid_envelope")
    elif envelope["kind"] == "turn.submit":
        if envelope["gateway_turn_id"] is not None:
            raise AgentStackProtocolError("invalid_envelope")
        _require_id(envelope["turn_id"])
    else:
        _require_id(envelope["gateway_turn_id"])
        _require_id(envelope["turn_id"])
    return envelope


def validate_event_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    """Validate a fixture or generated receipt/event envelope."""
    if envelope.get("kind") == "conversation.bound":
        _require_exact(
            envelope,
            {"bridge_generation", "channel_binding_id", "contract_version", "conversation_id", "emitted_at",
             "hermes_session_id", "ingress_id", "kind", "payload", "payload_digest", "schema_version"},
        )
    else:
        _require_exact(
            envelope,
            {"channel_binding_id", "contract_version", "conversation_id", "emitted_at", "gateway_generation",
             "gateway_sequence", "gateway_turn_id", "hermes_session_id", "ingress_id", "kind", "payload",
             "payload_digest", "schema_version", "source_platform", "source_surface", "turn_id"},
        )
    if envelope.get("contract_version") != CONTRACT_VERSION or envelope.get("schema_version") != SCHEMA_VERSION:
        raise AgentStackProtocolError("invalid_envelope")
    if envelope.get("kind") not in EVENT_KINDS or not isinstance(envelope.get("payload"), dict):
        raise AgentStackProtocolError("invalid_envelope")
    _reject_private_fields(envelope["payload"])
    _require_time(envelope["emitted_at"])
    for key in ("channel_binding_id", "conversation_id", "hermes_session_id", "ingress_id"):
        _require_id(envelope[key])
    if envelope["kind"] == "conversation.bound":
        _require_id(envelope["bridge_generation"])
        _require_exact(envelope["payload"], {"binding_version", "created"})
    else:
        for key in ("gateway_generation", "gateway_turn_id", "turn_id"):
            _require_id(envelope[key])
        seq = envelope["gateway_sequence"]
        if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= MAX_EVENTS_PER_TURN:
            raise AgentStackProtocolError("invalid_envelope")
        if envelope["source_surface"] not in {"ios", "web", "telegram", "discord", "slack", "signal", "whatsapp", "local", "api", "unknown"}:
            raise AgentStackProtocolError("invalid_envelope")
        if not isinstance(envelope["source_platform"], str) or not envelope["source_platform"]:
            raise AgentStackProtocolError("invalid_envelope")
    if not isinstance(envelope.get("payload_digest"), str) or not hmac.compare_digest(
        envelope["payload_digest"], _payload_digest_for_event(envelope)
    ):
        raise AgentStackProtocolError("invalid_envelope")
    if len(canonical_json_bytes(envelope)) > MAX_EVENT_BYTES:
        raise AgentStackProtocolError("event_too_large")
    return envelope


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


@dataclass(frozen=True)
class TurnDispatch:
    """Data needed to dispatch one newly accepted turn."""

    gateway_turn_id: str
    hermes_session_id: str
    command: dict[str, Any]


@dataclass(frozen=True)
class StoreResult:
    """Transactional command result."""

    duplicate: bool
    envelopes: tuple[dict[str, Any], ...]
    dispatch: Optional[TurnDispatch] = None


class AgentStackStore:
    """SQLite-backed ingress ledger, bindings, turns, and event outbox."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), timeout=10, isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=10000")
        self._create_schema()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _create_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS bindings (
                channel_binding_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL UNIQUE,
                account_id TEXT NOT NULL,
                routing_key TEXT NOT NULL,
                hermes_session_id TEXT NOT NULL,
                binding_version INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ingress (
                channel_binding_id TEXT NOT NULL,
                ingress_id TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                kind TEXT NOT NULL,
                gateway_turn_id TEXT,
                response_json TEXT NOT NULL,
                accepted_at TEXT NOT NULL,
                PRIMARY KEY(channel_binding_id, ingress_id)
            );
            CREATE TABLE IF NOT EXISTS turns (
                gateway_turn_id TEXT PRIMARY KEY,
                channel_binding_id TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                ingress_id TEXT NOT NULL,
                turn_id TEXT NOT NULL,
                bridge_generation TEXT NOT NULL,
                gateway_generation TEXT NOT NULL,
                hermes_session_id TEXT NOT NULL,
                source_surface TEXT NOT NULL,
                source_platform TEXT NOT NULL,
                state TEXT NOT NULL,
                highest_sequence INTEGER NOT NULL,
                highest_ack INTEGER NOT NULL DEFAULT 0,
                assistant_message_id TEXT,
                content_length_utf8 INTEGER NOT NULL DEFAULT 0,
                UNIQUE(channel_binding_id, turn_id)
            );
            CREATE TABLE IF NOT EXISTS events (
                gateway_turn_id TEXT NOT NULL,
                gateway_sequence INTEGER NOT NULL,
                payload_digest TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(gateway_turn_id, gateway_sequence),
                FOREIGN KEY(gateway_turn_id) REFERENCES turns(gateway_turn_id)
            );
            CREATE INDEX IF NOT EXISTS events_pending_idx ON events(created_at, gateway_turn_id, gateway_sequence);
            """
        )

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def close(self) -> None:
        """Close the store after flushing WAL state."""
        with self._lock:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.close()

    @staticmethod
    def _loads_envelopes(raw: str) -> tuple[dict[str, Any], ...]:
        decoded = json.loads(raw)
        return tuple(decoded if isinstance(decoded, list) else [decoded])

    def _duplicate(self, command: dict[str, Any]) -> Optional[StoreResult]:
        row = self._conn.execute(
            """SELECT payload_digest, response_json, kind, gateway_turn_id
               FROM ingress WHERE channel_binding_id=? AND ingress_id=?""",
            (command["channel_binding_id"], command["ingress_id"]),
        ).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(row["payload_digest"], command["payload_digest"]):
            raise AgentStackProtocolError("payload_digest_conflict")
        if row["kind"] == "turn.submit" and row["gateway_turn_id"]:
            events = self._conn.execute(
                """SELECT e.envelope_json FROM events e
                   JOIN turns t ON t.gateway_turn_id=e.gateway_turn_id
                   WHERE e.gateway_turn_id=? AND e.gateway_sequence > t.highest_ack
                   ORDER BY e.gateway_sequence""",
                (row["gateway_turn_id"],),
            ).fetchall()
            return StoreResult(
                duplicate=True,
                envelopes=tuple(json.loads(event["envelope_json"]) for event in events),
            )
        return StoreResult(duplicate=True, envelopes=self._loads_envelopes(row["response_json"]))

    def _binding(self, command: dict[str, Any]) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT * FROM bindings WHERE channel_binding_id=? AND conversation_id=?",
            (command["channel_binding_id"], command["conversation_id"]),
        ).fetchone()
        if row is None:
            raise AgentStackProtocolError("conversation_not_found")
        if not row["active"]:
            raise AgentStackProtocolError("binding_revoked")
        return row

    def bind(self, command: dict[str, Any], *, hermes_session_id: str) -> StoreResult:
        """Create or confirm a conversation binding and durable receipt."""
        validate_command_envelope(command)
        with self._transaction():
            duplicate = self._duplicate(command)
            if duplicate is not None:
                return duplicate
            existing = self._conn.execute(
                "SELECT * FROM bindings WHERE channel_binding_id=? OR conversation_id=?",
                (command["channel_binding_id"], command["conversation_id"]),
            ).fetchone()
            payload = command["payload"]
            created = existing is None
            if existing is not None and (
                existing["channel_binding_id"] != command["channel_binding_id"]
                or existing["conversation_id"] != command["conversation_id"]
                or existing["account_id"] != payload["account_id"]
                or existing["routing_key"] != payload["routing_key"]
            ):
                raise AgentStackProtocolError("binding_conflict")
            if existing is not None and payload["binding_version"] < existing["binding_version"]:
                raise AgentStackProtocolError("binding_conflict")
            self._conn.execute(
                """INSERT INTO bindings(channel_binding_id, conversation_id, account_id, routing_key,
                   hermes_session_id, binding_version, active, updated_at)
                   VALUES(?,?,?,?,?,?,1,?)
                   ON CONFLICT(channel_binding_id) DO UPDATE SET hermes_session_id=excluded.hermes_session_id,
                   binding_version=excluded.binding_version, active=1, updated_at=excluded.updated_at""",
                (command["channel_binding_id"], command["conversation_id"], payload["account_id"],
                 payload["routing_key"], hermes_session_id, payload["binding_version"], _now()),
            )
            receipt = {
                "bridge_generation": command["bridge_generation"],
                "channel_binding_id": command["channel_binding_id"],
                "contract_version": CONTRACT_VERSION,
                "conversation_id": command["conversation_id"],
                "emitted_at": _now(),
                "hermes_session_id": hermes_session_id,
                "ingress_id": command["ingress_id"],
                "kind": "conversation.bound",
                "payload": {"binding_version": payload["binding_version"], "created": created},
                "schema_version": SCHEMA_VERSION,
            }
            receipt["payload_digest"] = _payload_digest_for_event(receipt)
            self._conn.execute(
                "INSERT INTO ingress VALUES(?,?,?,?,?,?,?)",
                (command["channel_binding_id"], command["ingress_id"], command["payload_digest"],
                 command["kind"], None, json.dumps([receipt], separators=(",", ":")), _now()),
            )
            return StoreResult(duplicate=False, envelopes=(receipt,))

    def submit(self, command: dict[str, Any], *, hermes_session_id: str, gateway_generation: str) -> StoreResult:
        """Atomically dedupe ingress, accept a turn, and append sequence one."""
        validate_command_envelope(command)
        with self._transaction():
            binding = self._binding(command)
            duplicate = self._duplicate(command)
            if duplicate is not None:
                return duplicate
            active = self._conn.execute(
                "SELECT COUNT(*) FROM turns WHERE state NOT IN ('completed','failed','cancelled')"
            ).fetchone()[0]
            if active >= MAX_ACTIVE_TURNS:
                raise AgentStackProtocolError("rate_limited")
            gateway_turn_id = _new_id("gatewayturn")
            event = self._new_event(
                command=command,
                gateway_turn_id=gateway_turn_id,
                gateway_generation=gateway_generation,
                hermes_session_id=hermes_session_id,
                sequence=1,
                kind="turn.accepted",
                payload={"queued_at": _now(), "state": "accepted"},
                source_surface=command["payload"]["client_surface"],
            )
            self._conn.execute(
                """INSERT INTO turns(gateway_turn_id,channel_binding_id,conversation_id,ingress_id,turn_id,
                   bridge_generation,gateway_generation,hermes_session_id,source_surface,source_platform,state,highest_sequence)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,1)""",
                (gateway_turn_id, command["channel_binding_id"], command["conversation_id"], command["ingress_id"],
                 command["turn_id"], command["bridge_generation"], gateway_generation, hermes_session_id,
                 command["payload"]["client_surface"], "agent_stack", "accepted"),
            )
            self._conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?)",
                (gateway_turn_id, 1, event["payload_digest"], json.dumps(event, separators=(",", ":")), _now()),
            )
            self._conn.execute(
                "INSERT INTO ingress VALUES(?,?,?,?,?,?,?)",
                (command["channel_binding_id"], command["ingress_id"], command["payload_digest"], command["kind"],
                 gateway_turn_id, json.dumps([event], separators=(",", ":")), _now()),
            )
            return StoreResult(
                duplicate=False,
                envelopes=(event,),
                dispatch=TurnDispatch(gateway_turn_id, binding["hermes_session_id"], command),
            )

    def _new_event(
        self,
        *,
        command: Optional[dict[str, Any]] = None,
        row: Optional[sqlite3.Row] = None,
        gateway_turn_id: str,
        gateway_generation: str,
        hermes_session_id: str,
        sequence: int,
        kind: str,
        payload: dict[str, Any],
        source_surface: str,
    ) -> dict[str, Any]:
        if row is None and command is None:
            raise ValueError("row or command is required")
        if row is not None:
            channel_binding_id = row["channel_binding_id"]
            conversation_id = row["conversation_id"]
            ingress_id = row["ingress_id"]
            source_platform = row["source_platform"]
            turn_id = row["turn_id"]
        else:
            assert command is not None
            channel_binding_id = command["channel_binding_id"]
            conversation_id = command["conversation_id"]
            ingress_id = command["ingress_id"]
            source_platform = "agent_stack"
            turn_id = command["turn_id"]
        event = {
            "channel_binding_id": channel_binding_id,
            "contract_version": CONTRACT_VERSION,
            "conversation_id": conversation_id,
            "emitted_at": _now(),
            "gateway_generation": gateway_generation,
            "gateway_sequence": sequence,
            "gateway_turn_id": gateway_turn_id,
            "hermes_session_id": hermes_session_id,
            "ingress_id": ingress_id,
            "kind": kind,
            "payload": payload,
            "schema_version": SCHEMA_VERSION,
            "source_platform": source_platform,
            "source_surface": source_surface,
            "turn_id": turn_id,
        }
        event["payload_digest"] = _payload_digest_for_event(event)
        if len(canonical_json_bytes(event)) > MAX_EVENT_BYTES:
            raise AgentStackProtocolError("event_too_large")
        return event

    def append_event(self, gateway_turn_id: str, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Append one event with a monotonic per-turn sequence."""
        if kind not in EVENT_KINDS or kind == "conversation.bound":
            raise AgentStackProtocolError("invalid_envelope")
        _reject_private_fields(payload)
        with self._transaction():
            row = self._conn.execute("SELECT * FROM turns WHERE gateway_turn_id=?", (gateway_turn_id,)).fetchone()
            if row is None:
                raise AgentStackProtocolError("turn_not_found")
            if row["state"] in {"completed", "failed", "cancelled"}:
                raise AgentStackProtocolError("turn_already_terminal")
            sequence = row["highest_sequence"] + 1
            if sequence > MAX_EVENTS_PER_TURN:
                raise AgentStackProtocolError("event_too_large")
            event = self._new_event(
                row=row, gateway_turn_id=gateway_turn_id, gateway_generation=row["gateway_generation"],
                hermes_session_id=row["hermes_session_id"], sequence=sequence, kind=kind, payload=payload,
                source_surface=row["source_surface"],
            )
            state = payload.get("state", row["state"])
            self._conn.execute(
                "UPDATE turns SET highest_sequence=?, state=? WHERE gateway_turn_id=?",
                (sequence, state, gateway_turn_id),
            )
            self._conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?)",
                (gateway_turn_id, sequence, event["payload_digest"], json.dumps(event, separators=(",", ":")), _now()),
            )
            return event

    def ack(self, command: dict[str, Any]) -> StoreResult:
        """Persist a highest-contiguous event acknowledgement."""
        validate_command_envelope(command)
        with self._transaction():
            self._binding(command)
            duplicate = self._duplicate(command)
            if duplicate is not None:
                return duplicate
            row = self._conn.execute("SELECT * FROM turns WHERE gateway_turn_id=?", (command["gateway_turn_id"],)).fetchone()
            if row is None or row["turn_id"] != command["turn_id"]:
                raise AgentStackProtocolError("turn_not_found")
            highest = command["payload"]["highest_contiguous_gateway_sequence"]
            if highest > row["highest_sequence"]:
                raise AgentStackProtocolError("ack_out_of_range")
            self._conn.execute(
                "UPDATE turns SET highest_ack=MAX(highest_ack, ?) WHERE gateway_turn_id=?",
                (highest, command["gateway_turn_id"]),
            )
            self._conn.execute(
                "INSERT INTO ingress VALUES(?,?,?,?,?,?,?)",
                (command["channel_binding_id"], command["ingress_id"], command["payload_digest"], command["kind"],
                 command["gateway_turn_id"], "[]", _now()),
            )
            return StoreResult(duplicate=False, envelopes=())

    def cancel(self, command: dict[str, Any]) -> StoreResult:
        """Linearize cancellation before the terminal transition."""
        validate_command_envelope(command)
        with self._transaction():
            self._binding(command)
            duplicate = self._duplicate(command)
            if duplicate is not None:
                return duplicate
            row = self._conn.execute("SELECT * FROM turns WHERE gateway_turn_id=?", (command["gateway_turn_id"],)).fetchone()
            if row is None or row["turn_id"] != command["turn_id"]:
                raise AgentStackProtocolError("turn_not_found")
            if row["gateway_generation"] != command["payload"]["target_gateway_generation"]:
                raise AgentStackProtocolError("stale_gateway_generation")
            if row["state"] in {"completed", "failed", "cancelled"}:
                raise AgentStackProtocolError("turn_already_terminal")
            sequence = row["highest_sequence"] + 1
            event = self._new_event(
                row=row, gateway_turn_id=row["gateway_turn_id"], gateway_generation=row["gateway_generation"],
                hermes_session_id=row["hermes_session_id"], sequence=sequence, kind="turn.cancel_requested",
                payload={"requested_at": _now(), "state": "cancel_requested"}, source_surface=row["source_surface"],
            )
            self._conn.execute(
                "UPDATE turns SET state='cancel_requested', highest_sequence=? WHERE gateway_turn_id=?",
                (sequence, row["gateway_turn_id"]),
            )
            self._conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?)",
                (row["gateway_turn_id"], sequence, event["payload_digest"], json.dumps(event, separators=(",", ":")), _now()),
            )
            self._conn.execute(
                "INSERT INTO ingress VALUES(?,?,?,?,?,?,?)",
                (command["channel_binding_id"], command["ingress_id"], command["payload_digest"], command["kind"],
                 row["gateway_turn_id"], json.dumps([event], separators=(",", ":")), _now()),
            )
            return StoreResult(duplicate=False, envelopes=(event,))

    def append_terminal(
        self,
        gateway_turn_id: str,
        *,
        outcome: str,
        content_length_utf8: Optional[int] = None,
    ) -> dict[str, Any]:
        """Append one terminal event; a committed cancel request wins the race."""
        with self._transaction():
            row = self._conn.execute(
                "SELECT * FROM turns WHERE gateway_turn_id=?", (gateway_turn_id,)
            ).fetchone()
            if row is None:
                raise AgentStackProtocolError("turn_not_found")
            if row["state"] in {"completed", "failed", "cancelled"}:
                raise AgentStackProtocolError("turn_already_terminal")
            length = row["content_length_utf8"] if content_length_utf8 is None else content_length_utf8
            if row["state"] == "cancel_requested" or outcome == "cancelled":
                kind = "turn.cancelled"
                terminal_state = "cancelled"
                payload = {
                    "completed_at": _now(), "content_length_utf8": length,
                    "finish_reason": "user_requested", "state": "cancelled",
                }
            elif outcome == "completed":
                kind = "turn.completed"
                terminal_state = "completed"
                payload = {
                    "assistant_message_id": row["assistant_message_id"] or _new_id("assistantmsg"),
                    "completed_at": _now(), "content_length_utf8": length,
                    "finish_reason": "completed", "state": "succeeded",
                }
            else:
                kind = "turn.failed"
                terminal_state = "failed"
                payload = {
                    "completed_at": _now(), "error_code": "execution_failed",
                    "finish_reason": "execution_failed", "retryable": False, "state": "failed",
                }
            sequence = row["highest_sequence"] + 1
            event = self._new_event(
                row=row,
                gateway_turn_id=gateway_turn_id,
                gateway_generation=row["gateway_generation"],
                hermes_session_id=row["hermes_session_id"],
                sequence=sequence,
                kind=kind,
                payload=payload,
                source_surface=row["source_surface"],
            )
            self._conn.execute(
                "UPDATE turns SET state=?, highest_sequence=? WHERE gateway_turn_id=?",
                (terminal_state, sequence, gateway_turn_id),
            )
            self._conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?)",
                (gateway_turn_id, sequence, event["payload_digest"],
                 json.dumps(event, separators=(",", ":")), _now()),
            )
            return event

    def recover_interrupted(self) -> tuple[dict[str, Any], ...]:
        """Terminalize accepted work from a previous process without rerunning it."""
        recovered: list[dict[str, Any]] = []
        with self._transaction():
            rows = self._conn.execute(
                "SELECT * FROM turns WHERE state NOT IN ('completed','failed','cancelled')"
            ).fetchall()
            for row in rows:
                sequence = row["highest_sequence"] + 1
                payload = {
                    "completed_at": _now(), "error_code": "execution_interrupted",
                    "finish_reason": "execution_interrupted", "retryable": True, "state": "failed",
                }
                event = self._new_event(
                    row=row, gateway_turn_id=row["gateway_turn_id"],
                    gateway_generation=row["gateway_generation"],
                    hermes_session_id=row["hermes_session_id"], sequence=sequence,
                    kind="turn.failed", payload=payload, source_surface=row["source_surface"],
                )
                self._conn.execute(
                    "UPDATE turns SET state='failed', highest_sequence=? WHERE gateway_turn_id=?",
                    (sequence, row["gateway_turn_id"]),
                )
                self._conn.execute(
                    "INSERT INTO events VALUES(?,?,?,?,?)",
                    (row["gateway_turn_id"], sequence, event["payload_digest"],
                     json.dumps(event, separators=(",", ":")), _now()),
                )
                recovered.append(event)
        return tuple(recovered)

    def record_assistant_message(self, gateway_turn_id: str, assistant_message_id: str, length: int) -> None:
        """Record final visible content metadata without retaining a second payload copy."""
        with self._transaction():
            self._conn.execute(
                "UPDATE turns SET assistant_message_id=?, content_length_utf8=? WHERE gateway_turn_id=?",
                (assistant_message_id, length, gateway_turn_id),
            )

    def pending_events(self) -> tuple[dict[str, Any], ...]:
        """Return all unacknowledged events in stable replay order."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT e.envelope_json FROM events e JOIN turns t ON t.gateway_turn_id=e.gateway_turn_id
                   WHERE e.gateway_sequence > t.highest_ack ORDER BY e.created_at,e.gateway_turn_id,e.gateway_sequence"""
            ).fetchall()
        return tuple(json.loads(row["envelope_json"]) for row in rows)

    def binding_session(self, command: dict[str, Any]) -> str:
        """Return the currently authorized Hermes session for a command."""
        with self._lock:
            return str(self._binding(command)["hermes_session_id"])

    def turn_conversation(self, gateway_turn_id: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute("SELECT conversation_id FROM turns WHERE gateway_turn_id=?", (gateway_turn_id,)).fetchone()
        return str(row["conversation_id"]) if row else None

    def health(self) -> dict[str, Any]:
        """Return counts and state only; never command or transcript payloads."""
        with self._lock:
            binding_count = self._conn.execute("SELECT COUNT(*) FROM bindings WHERE active=1").fetchone()[0]
            active_turn_count = self._conn.execute(
                "SELECT COUNT(*) FROM turns WHERE state NOT IN ('completed','failed','cancelled')"
            ).fetchone()[0]
            pending_event_count = self._conn.execute(
                """SELECT COUNT(*) FROM events e JOIN turns t ON t.gateway_turn_id=e.gateway_turn_id
                   WHERE e.gateway_sequence > t.highest_ack"""
            ).fetchone()[0]
        return {
            "binding_count": binding_count,
            "active_turn_count": active_turn_count,
            "pending_event_count": pending_event_count,
        }


async def read_transport_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
    """Read one four-byte-length-prefixed strict JSON frame."""
    header = await reader.readexactly(4)
    length = struct.unpack(">I", header)[0]
    if length > MAX_FRAME_BYTES:
        raise AgentStackProtocolError("frame_too_large")
    return decode_json_frame(await reader.readexactly(length))


async def write_transport_frame(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
    """Write one canonical length-prefixed JSON frame."""
    raw = canonical_json_bytes(value)
    if len(raw) > MAX_FRAME_BYTES:
        raise AgentStackProtocolError("frame_too_large")
    writer.write(struct.pack(">I", len(raw)) + raw)
    await writer.drain()


@dataclass(eq=False)
class _Peer:
    writer: asyncio.StreamWriter
    lock: asyncio.Lock


class AgentStackAdapter(BasePlatformAdapter):
    """Hermes gateway adapter for the private Agent Stack control plane."""

    MAX_MESSAGE_LENGTH = MAX_VISIBLE_TEXT_CHECKPOINT_BYTES

    def __init__(self, config: PlatformConfig) -> None:
        super().__init__(config, Platform.AGENT_STACK)
        home = Path(os.environ.get("HERMES_HOME", "~/.hermes")).expanduser()
        extra = config.extra or {}
        self.runtime_dir = Path(str(extra.get("runtime_dir") or home / "run" / "agent-stack")).expanduser()
        self.socket_path = Path(str(extra.get("socket_path") or self.runtime_dir / "channel.sock")).expanduser()
        self.secret_path = Path(str(extra.get("secret_path") or self.runtime_dir / "channel.secret")).expanduser()
        self.db_path = Path(str(extra.get("db_path") or home / "state" / "agent-stack-channel.db")).expanduser()
        self.gateway_generation = _new_id("gatewaygen")
        self._secret = ""
        self._server: Optional[asyncio.AbstractServer] = None
        self._store: Optional[AgentStackStore] = None
        self._peers: set[_Peer] = set()
        self._client_tasks: set[asyncio.Task[Any]] = set()
        self._active_turn_by_chat: dict[str, str] = {}
        self._event_by_turn: dict[str, MessageEvent] = {}
        self._activity_emitted: set[str] = set()

    @property
    def authorization_is_upstream(self) -> bool:
        """The private peer authenticates before any event reaches the gateway."""
        return True

    def _prepare_runtime(self) -> None:
        self.runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.runtime_dir.is_symlink():
            raise RuntimeError("agent_stack runtime_dir must not be a symlink")
        os.chmod(self.runtime_dir, 0o700)
        for path in (self.socket_path, self.secret_path):
            if path.exists() or path.is_symlink():
                st = path.lstat()
                if hasattr(os, "getuid") and st.st_uid != os.getuid():
                    raise RuntimeError("agent_stack runtime file is not owned by this process user")
                path.unlink()
        self._secret = secrets.token_urlsafe(48)
        fd = os.open(self.secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, (self._secret + "\n").encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(self.secret_path, 0o600)

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        """Start the private Unix server and rotate the boot-scoped secret."""
        if self._server is not None:
            return True
        self._prepare_runtime()
        self._store = AgentStackStore(self.db_path)
        recovered = self._store.recover_interrupted()
        if recovered:
            logger.warning("Agent Stack recovered %d interrupted turn(s)", len(recovered))
        self._server = await asyncio.start_unix_server(self._accept_peer, path=str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        logger.info("Agent Stack private channel ready (generation=%s)", self.gateway_generation)
        return True

    async def disconnect(self) -> None:
        """Stop intake, close peers, cancel owned work, and remove boot credentials."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for peer in tuple(self._peers):
            peer.writer.close()
        for peer in tuple(self._peers):
            try:
                await peer.writer.wait_closed()
            except OSError:
                pass
        self._peers.clear()
        current = asyncio.current_task()
        for task in tuple(self._client_tasks):
            if task is not current:
                task.cancel()
        await self.cancel_background_tasks()
        if self._store is not None:
            self._store.close()
            self._store = None
        for path in (self.socket_path, self.secret_path):
            try:
                if path.exists() or path.is_symlink():
                    path.unlink()
            except OSError:
                logger.warning("Unable to remove Agent Stack runtime file")
        self._secret = ""

    async def _accept_peer(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        peer: Optional[_Peer] = None
        try:
            try:
                auth = await read_transport_frame(reader)
            except AgentStackProtocolError as exc:
                await self._send_unlocked(writer, exc.as_frame(terminal=True))
                return
            if set(auth) != {"kind", "secret"} or auth.get("kind") != "authenticate" or not isinstance(auth.get("secret"), str) or not hmac.compare_digest(auth["secret"], self._secret):
                await self._send_unlocked(writer, {
                    "kind": "protocol.error", "error_code": "unauthorized", "retryable": False,
                    "safe_message": "Authentication failed.", "terminal": True,
                })
                return
            peer = _Peer(writer=writer, lock=asyncio.Lock())
            self._peers.add(peer)
            await self._send_peer(peer, CAPABILITY_DOCUMENT)
            if self._store is not None:
                for event in self._store.pending_events():
                    await self._send_peer(peer, event)
            while True:
                try:
                    command = await read_transport_frame(reader)
                    await self._process_command(peer, command)
                except asyncio.IncompleteReadError:
                    break
                except AgentStackProtocolError as exc:
                    await self._send_peer(peer, exc.as_frame())
                    if exc.code == "frame_too_large":
                        break
                except Exception:
                    logger.exception("Agent Stack channel command failed without payload logging")
                    await self._send_peer(peer, AgentStackProtocolError("internal_error").as_frame())
        finally:
            if peer is not None:
                self._peers.discard(peer)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            if task is not None:
                self._client_tasks.discard(task)

    @staticmethod
    async def _send_unlocked(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
        try:
            await write_transport_frame(writer, value)
        except (ConnectionError, OSError):
            pass

    async def _send_peer(self, peer: _Peer, value: dict[str, Any]) -> None:
        async with peer.lock:
            await write_transport_frame(peer.writer, value)

    async def _broadcast(self, envelope: dict[str, Any]) -> None:
        for peer in tuple(self._peers):
            try:
                await self._send_peer(peer, envelope)
            except (ConnectionError, OSError):
                self._peers.discard(peer)

    async def _session_for_bind(self, command: dict[str, Any]) -> str:
        requested = command["payload"]["current_hermes_session_id"]
        store = getattr(self, "_session_store", None)
        if store is None:
            return requested or _new_id("session")
        source = self._source(command["conversation_id"], command["payload"]["account_id"])
        entry = await asyncio.to_thread(store.get_or_create_session, source)
        if requested and requested != entry.session_id:
            switched = await asyncio.to_thread(store.switch_session, entry.session_key, requested)
            if switched is None:
                raise AgentStackProtocolError("conversation_not_found")
            entry = switched
        return str(entry.session_id)

    async def _process_command(self, peer: _Peer, command: dict[str, Any]) -> None:
        validate_command_envelope(command)
        if self._store is None:
            raise AgentStackProtocolError("gateway_unavailable")
        kind = command["kind"]
        if kind == "conversation.bind":
            session_id = await self._session_for_bind(command)
            result = self._store.bind(command, hermes_session_id=session_id)
        elif kind == "turn.submit":
            session_id = self._store.binding_session(command)
            result = self._store.submit(
                command, hermes_session_id=session_id, gateway_generation=self.gateway_generation
            )
        elif kind == "turn.cancel":
            result = self._store.cancel(command)
        else:
            result = self._store.ack(command)
        for envelope in result.envelopes:
            await self._send_peer(peer, envelope)
        if kind == "turn.cancel" and not result.duplicate:
            event = self._event_by_turn.get(command["gateway_turn_id"])
            if event is not None:
                source = event.source
                session_store = getattr(self, "_session_store", None)
                session_key = build_session_key(
                    source,
                    group_sessions_per_user=self.config.extra.get(
                        "group_sessions_per_user", True
                    ),
                    thread_sessions_per_user=self.config.extra.get(
                        "thread_sessions_per_user", False
                    ),
                    profile=(
                        session_store._resolve_profile_for_key(source)
                        if session_store is not None
                        else None
                    ),
                )
                await self.cancel_session_processing(session_key)
        if result.dispatch is not None:
            await self._dispatch_turn(result.dispatch)

    def _source(self, conversation_id: str, account_id: str = "agent_stack_owner") -> SessionSource:
        return SessionSource(
            platform=Platform.AGENT_STACK,
            user_id=account_id,
            chat_id=conversation_id,
            chat_type="dm",
            chat_name="Agent Stack",
            user_name="Agent Stack owner",
        )

    async def _dispatch_turn(self, dispatch: TurnDispatch) -> None:
        command = dispatch.command
        payload = command["payload"]
        event = MessageEvent(
            text=payload["visible_text"],
            message_type=MessageType.TEXT,
            source=self._source(command["conversation_id"]),
            message_id=payload["user_message_id"],
            raw_message=None,
            metadata={
                "gateway_turn_id": dispatch.gateway_turn_id,
                "turn_id": command["turn_id"],
                "client_surface": payload["client_surface"],
                # Opaque descriptors only: no device/server path crosses the
                # channel boundary.
                "agent_stack_attachments": payload["attachments"],
            },
        )
        self._event_by_turn[dispatch.gateway_turn_id] = event
        await self.handle_message(event)

    async def on_processing_start(self, event: MessageEvent) -> None:
        gateway_turn_id = str(event.metadata.get("gateway_turn_id") or "")
        if not gateway_turn_id or self._store is None:
            return
        self._active_turn_by_chat[str(event.source.chat_id)] = gateway_turn_id
        started = self._store.append_event(
            gateway_turn_id, "turn.started", {"started_at": _now(), "state": "running"}
        )
        await self._broadcast(started)

    async def on_processing_complete(self, event: MessageEvent, outcome: ProcessingOutcome) -> None:
        gateway_turn_id = str(event.metadata.get("gateway_turn_id") or "")
        if not gateway_turn_id or self._store is None:
            return
        try:
            if outcome == ProcessingOutcome.SUCCESS:
                terminal = self._store.append_terminal(gateway_turn_id, outcome="completed")
            elif outcome == ProcessingOutcome.CANCELLED:
                terminal = self._store.append_terminal(gateway_turn_id, outcome="cancelled")
            else:
                terminal = self._store.append_terminal(gateway_turn_id, outcome="failed")
            await self._broadcast(terminal)
        except AgentStackProtocolError as exc:
            if exc.code != "turn_already_terminal":
                raise
        finally:
            self._active_turn_by_chat.pop(str(event.source.chat_id), None)
            self._event_by_turn.pop(gateway_turn_id, None)
            self._activity_emitted.discard(gateway_turn_id)

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> SendResult:
        """Persist and emit visible assistant text only."""
        gateway_turn_id = self._active_turn_by_chat.get(str(chat_id))
        if not gateway_turn_id or self._store is None:
            return SendResult(success=True, message_id=_new_id("assistantmsg"))
        raw = content.encode("utf-8")
        assistant_message_id = _new_id("assistantmsg")
        offset = 0
        while offset < len(raw):
            end = min(len(raw), offset + MAX_VISIBLE_TEXT_DELTA_BYTES)
            text = ""
            while end > offset:
                try:
                    text = raw[offset:end].decode("utf-8")
                    break
                except UnicodeDecodeError:
                    end -= 1
            delta = self._store.append_event(
                gateway_turn_id,
                "turn.text.delta",
                {"assistant_message_id": assistant_message_id, "content_length_utf8": len(raw),
                 "content_offset_utf8": offset, "text": text},
            )
            await self._broadcast(delta)
            offset = end
        checkpoint = self._store.append_event(
            gateway_turn_id,
            "turn.text.checkpoint",
            {"assistant_message_id": assistant_message_id, "content_length_utf8": len(raw),
             "transcript_checkpointed": True, "visible_text": content},
        )
        self._store.record_assistant_message(gateway_turn_id, assistant_message_id, len(raw))
        await self._broadcast(checkpoint)
        return SendResult(success=True, message_id=assistant_message_id)

    async def send_typing(self, chat_id: str, metadata: Optional[dict[str, Any]] = None) -> None:
        """Emit at most one allowlisted, payload-free activity event per turn."""
        gateway_turn_id = self._active_turn_by_chat.get(str(chat_id))
        if not gateway_turn_id or gateway_turn_id in self._activity_emitted or self._store is None:
            return
        self._activity_emitted.add(gateway_turn_id)
        event = self._store.append_event(
            gateway_turn_id, "turn.activity", {"phase": "thinking", "title": "Thinking…"}
        )
        await self._broadcast(event)

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        """Return payload-free local chat metadata."""
        return {"id": chat_id, "name": "Agent Stack", "type": "dm"}

    def health(self) -> dict[str, Any]:
        """Return a payload-free adapter health report."""
        store_health = self._store.health() if self._store is not None else {
            "binding_count": 0, "active_turn_count": 0, "pending_event_count": 0,
        }
        return {
            "connected": self._server is not None,
            "authenticated_peer_count": len(self._peers),
            "gateway_generation": self.gateway_generation,
            **store_health,
        }


def register_agent_stack_adapter(*, force: bool = False) -> None:
    """Register the built-in Agent Stack adapter with the platform registry."""
    if platform_registry.get("agent_stack") is not None and not force:
        return
    platform_registry.register(
        PlatformEntry(
            name="agent_stack",
            label="Agent Stack",
            adapter_factory=AgentStackAdapter,
            check_fn=lambda: True,
            validate_config=lambda cfg: bool(getattr(cfg, "enabled", False)),
            is_connected=lambda cfg: bool(getattr(cfg, "enabled", False)),
            required_env=[],
            source="builtin",
            pii_safe=True,
            emoji="🔒",
            allow_update_command=False,
            platform_hint="Private Agent Stack control channel.",
        )
    )
