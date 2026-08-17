from __future__ import annotations

import asyncio
import copy
import json
import os
import stat
import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platform_registry import platform_registry
from gateway.run import GatewayRunner
from gateway.platforms.base import ProcessingOutcome
from gateway.platforms.agent_stack import (
    CAPABILITY_DOCUMENT,
    MAX_FRAME_BYTES,
    AgentStackAdapter,
    AgentStackProtocolError,
    AgentStackStore,
    canonical_json_bytes,
    decode_json_frame,
    payload_digest_for_command,
    read_transport_frame,
    register_agent_stack_adapter,
    validate_command_envelope,
    validate_event_envelope,
    write_transport_frame,
)


FIXTURES = Path(__file__).parents[1] / "fixtures" / "agent_stack_channel_v1"


def _fixture_document(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _command(name: str) -> dict:
    document = _fixture_document("envelopes.json")
    return copy.deepcopy(
        next(item["envelope"] for item in document["command_examples"] if item["name"] == name)
    )


def _with_digest(command: dict) -> dict:
    command["payload_digest"] = payload_digest_for_command(command)
    return command


async def _authenticate(socket_path: Path, secret_path: Path):
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    await write_transport_frame(
        writer,
        {
            "kind": "authenticate",
            "secret": secret_path.read_text(encoding="ascii").strip(),
        },
    )
    assert await read_transport_frame(reader) == CAPABILITY_DOCUMENT
    return reader, writer


def test_ioschan_00_fixtures_decode_exactly() -> None:
    capabilities = _fixture_document("capabilities.json")
    envelopes = _fixture_document("envelopes.json")

    assert CAPABILITY_DOCUMENT == capabilities
    for example in envelopes["command_examples"]:
        assert validate_command_envelope(example["envelope"])["kind"] == example["envelope"]["kind"]
    for example in envelopes["receipt_examples"]:
        assert validate_event_envelope(example["envelope"])["kind"] == "conversation.bound"
    for trace in envelopes["turn_traces"]:
        for event in trace["events"]:
            assert validate_event_envelope(event)["kind"] == event["kind"]


@pytest.mark.parametrize(
    "raw,error_code",
    [
        (b'{"kind":"event.ack","kind":"event.ack"}', "invalid_envelope"),
        (b'{"value":1.25}', "invalid_envelope"),
        (b'{"value":NaN}', "invalid_envelope"),
        (b'\xef\xbb\xbf{"value":1}', "invalid_envelope"),
        (b'{"value":9007199254740992}', "invalid_envelope"),
        (b'{"value":1}{"value":2}', "invalid_envelope"),
    ],
)
def test_strict_json_decoder_rejects_ambiguous_json(raw: bytes, error_code: str) -> None:
    with pytest.raises(AgentStackProtocolError) as exc_info:
        decode_json_frame(raw)
    assert exc_info.value.code == error_code


def test_command_rejects_unknown_schema_version_and_fields() -> None:
    command = _command("submit-visible-text")
    command["schema_version"] = 2
    _with_digest(command)
    with pytest.raises(AgentStackProtocolError) as exc_info:
        validate_command_envelope(command)
    assert exc_info.value.code == "unsupported_schema_version"

    command = _command("submit-visible-text")
    command["unexpected"] = "value"
    _with_digest(command)
    with pytest.raises(AgentStackProtocolError) as exc_info:
        validate_command_envelope(command)
    assert exc_info.value.code == "invalid_envelope"


def test_store_deduplicates_before_execution_and_rejects_digest_conflict(tmp_path: Path) -> None:
    store = AgentStackStore(tmp_path / "channel.db")
    bind = _command("bind-existing-conversation")
    receipt = store.bind(bind, hermes_session_id="session_12345678")
    assert receipt.duplicate is False
    assert receipt.envelopes[0]["kind"] == "conversation.bound"

    submit = _command("submit-visible-text")
    accepted = store.submit(
        submit,
        hermes_session_id="session_12345678",
        gateway_generation="gatewaygen_12345678",
    )
    replay = store.submit(
        submit,
        hermes_session_id="session_12345678",
        gateway_generation="gatewaygen_other123",
    )
    assert accepted.duplicate is False
    assert replay.duplicate is True
    assert replay.envelopes == accepted.envelopes
    assert replay.dispatch is None

    conflicting = copy.deepcopy(submit)
    conflicting["payload"]["visible_text"] = "Different text"
    _with_digest(conflicting)
    with pytest.raises(AgentStackProtocolError) as exc_info:
        store.submit(
            conflicting,
            hermes_session_id="session_12345678",
            gateway_generation="gatewaygen_12345678",
        )
    assert exc_info.value.code == "payload_digest_conflict"
    store.close()


def test_store_emits_the_frozen_lifecycle_payloads(tmp_path: Path) -> None:
    store = AgentStackStore(tmp_path / "channel.db")
    receipt = store.bind(
        _command("bind-existing-conversation"),
        hermes_session_id="session_12345678",
    ).envelopes[0]
    assert receipt["payload"] == {"binding_version": 1, "created": True}

    accepted = store.submit(
        _command("submit-visible-text"),
        hermes_session_id="session_12345678",
        gateway_generation="gatewaygen_12345678",
    ).envelopes[0]
    gateway_turn_id = accepted["gateway_turn_id"]
    activity = store.append_event(
        gateway_turn_id,
        "turn.activity",
        {"phase": "thinking", "title": "Thinking…"},
    )
    assert activity["payload"] == {"phase": "thinking", "title": "Thinking…"}
    completed = store.append_terminal(gateway_turn_id, outcome="completed")
    assert completed["payload"]["finish_reason"] == "completed"
    assert completed["payload"]["state"] == "succeeded"
    store.close()


def test_store_persists_outbox_ack_and_cancel_wins_race(tmp_path: Path) -> None:
    db_path = tmp_path / "channel.db"
    store = AgentStackStore(db_path)
    bind = _command("bind-existing-conversation")
    store.bind(bind, hermes_session_id="session_12345678")
    submit = _command("submit-visible-text")
    result = store.submit(
        submit,
        hermes_session_id="session_12345678",
        gateway_generation="gatewaygen_12345678",
    )
    gateway_turn_id = result.envelopes[0]["gateway_turn_id"]
    started = store.append_event(
        gateway_turn_id,
        "turn.started",
        {"started_at": "2026-01-01T00:00:01Z", "state": "running"},
    )
    assert started["gateway_sequence"] == 2
    store.close()

    store = AgentStackStore(db_path)
    assert [event["gateway_sequence"] for event in store.pending_events()] == [1, 2]
    ack = _command("ack-highest-contiguous-event")
    ack["gateway_turn_id"] = gateway_turn_id
    ack["payload"]["highest_contiguous_gateway_sequence"] = 2
    _with_digest(ack)
    store.ack(ack)
    assert store.pending_events() == ()

    cancel = _command("cancel-accepted-turn")
    cancel["gateway_turn_id"] = gateway_turn_id
    cancel["payload"]["target_gateway_generation"] = "gatewaygen_12345678"
    _with_digest(cancel)
    cancel_result = store.cancel(cancel)
    assert cancel_result.envelopes[0]["kind"] == "turn.cancel_requested"
    terminal = store.append_terminal(gateway_turn_id, outcome="completed", content_length_utf8=10)
    assert terminal["kind"] == "turn.cancelled"
    assert store.health()["active_turn_count"] == 0
    store.close()


def test_restart_replays_and_terminalizes_without_redispatch(tmp_path: Path) -> None:
    db_path = tmp_path / "channel.db"
    bind = _command("bind-existing-conversation")
    submit = _command("submit-visible-text")
    store = AgentStackStore(db_path)
    store.bind(bind, hermes_session_id="session_12345678")
    accepted = store.submit(
        submit,
        hermes_session_id="session_12345678",
        gateway_generation="gatewaygen_12345678",
    )
    gateway_turn_id = accepted.envelopes[0]["gateway_turn_id"]
    store.append_event(
        gateway_turn_id,
        "turn.started",
        {"started_at": "2026-01-01T00:00:01Z", "state": "running"},
    )
    store.close()

    restarted = AgentStackStore(db_path)
    recovered = restarted.recover_interrupted()
    assert [event["kind"] for event in recovered] == ["turn.failed"]
    assert recovered[0]["payload"]["error_code"] == "execution_interrupted"
    replay = restarted.submit(
        submit,
        hermes_session_id="session_12345678",
        gateway_generation="gatewaygen_new1234",
    )
    assert replay.duplicate is True
    assert replay.dispatch is None
    assert [event["kind"] for event in replay.envelopes] == [
        "turn.accepted",
        "turn.started",
        "turn.failed",
    ]
    restarted.close()


@pytest.mark.asyncio
async def test_bind_switches_the_canonical_session_by_routing_key(tmp_path: Path) -> None:
    class FakeSessionStore:
        def get_or_create_session(self, source):
            return SimpleNamespace(session_key="agent:main:agent_stack:dm:conversation", session_id="old_session")

        def switch_session(self, session_key, target_session_id):
            assert session_key == "agent:main:agent_stack:dm:conversation"
            assert target_session_id == "session_target123"
            return SimpleNamespace(session_id=target_session_id)

    adapter = AgentStackAdapter(
        PlatformConfig(
            enabled=True,
            extra={"runtime_dir": str(tmp_path / "run"), "db_path": str(tmp_path / "channel.db")},
        )
    )
    adapter._session_store = FakeSessionStore()
    command = _command("bind-existing-conversation")
    command["payload"]["current_hermes_session_id"] = "session_target123"
    _with_digest(command)

    assert await adapter._session_for_bind(command) == "session_target123"


@pytest.mark.asyncio
async def test_private_transport_auth_permissions_replay_limit_and_shutdown(tmp_path: Path) -> None:
    config = PlatformConfig(
        enabled=True,
        extra={"runtime_dir": str(tmp_path / "run"), "db_path": str(tmp_path / "channel.db")},
    )
    adapter = AgentStackAdapter(config)
    adapter.handle_message = AsyncMock()
    await adapter.connect()

    assert stat.S_IMODE(os.stat(adapter.socket_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(adapter.secret_path).st_mode) == 0o600
    health = adapter.health()
    assert health["connected"] is True
    assert "secret" not in json.dumps(health)

    reader, writer = await asyncio.open_unix_connection(str(adapter.socket_path))
    await write_transport_frame(writer, {"kind": "authenticate", "secret": "wrong-secret"})
    auth_error = await read_transport_frame(reader)
    assert auth_error == {
        "kind": "protocol.error",
        "error_code": "unauthorized",
        "retryable": False,
        "safe_message": "Authentication failed.",
        "terminal": True,
    }
    assert await reader.read() == b""
    writer.close()
    await writer.wait_closed()

    reader, writer = await _authenticate(adapter.socket_path, adapter.secret_path)
    bind = _command("bind-existing-conversation")
    await write_transport_frame(writer, bind)
    receipt = await read_transport_frame(reader)
    assert receipt["kind"] == "conversation.bound"

    submit = _command("submit-visible-text")
    submit["payload"]["attachments"] = []
    _with_digest(submit)
    await write_transport_frame(writer, submit)
    accepted = await read_transport_frame(reader)
    assert accepted["kind"] == "turn.accepted"
    await write_transport_frame(writer, submit)
    assert await read_transport_frame(reader) == accepted
    await asyncio.sleep(0)
    adapter.handle_message.assert_awaited_once()

    writer.close()
    await writer.wait_closed()
    replay_reader, replay_writer = await _authenticate(adapter.socket_path, adapter.secret_path)
    assert await read_transport_frame(replay_reader) == accepted

    replay_writer.write(struct.pack(">I", MAX_FRAME_BYTES + 1))
    await replay_writer.drain()
    limit_error = await read_transport_frame(replay_reader)
    assert limit_error["error_code"] == "frame_too_large"
    assert await replay_reader.read() == b""
    replay_writer.close()
    await replay_writer.wait_closed()

    socket_path = adapter.socket_path
    secret_path = adapter.secret_path
    await adapter.disconnect()
    assert not socket_path.exists()
    assert not secret_path.exists()


@pytest.mark.asyncio
async def test_adapter_emits_safe_model_lifecycle_over_transport(tmp_path: Path) -> None:
    adapter = AgentStackAdapter(
        PlatformConfig(
            enabled=True,
            extra={"runtime_dir": str(tmp_path / "run"), "db_path": str(tmp_path / "channel.db")},
        )
    )
    adapter.handle_message = AsyncMock()
    await adapter.connect()
    reader, writer = await _authenticate(adapter.socket_path, adapter.secret_path)
    await write_transport_frame(writer, _command("bind-existing-conversation"))
    await read_transport_frame(reader)
    submit = _command("submit-visible-text")
    submit["payload"]["attachments"] = []
    _with_digest(submit)
    await write_transport_frame(writer, submit)
    accepted = await read_transport_frame(reader)
    model_event = adapter._event_by_turn[accepted["gateway_turn_id"]]

    await adapter.on_processing_start(model_event)
    started = await read_transport_frame(reader)
    assert started["kind"] == "turn.started"
    await adapter.send(model_event.source.chat_id, "Fixture response.")
    delta = await read_transport_frame(reader)
    checkpoint = await read_transport_frame(reader)
    assert delta["payload"]["text"] == "Fixture response."
    assert checkpoint["payload"]["transcript_checkpointed"] is True
    await adapter.on_processing_complete(model_event, ProcessingOutcome.SUCCESS)
    completed = await read_transport_frame(reader)
    assert completed["payload"]["state"] == "succeeded"
    assert completed["payload"]["finish_reason"] == "completed"

    writer.close()
    await writer.wait_closed()
    await adapter.disconnect()


def test_agent_stack_registry_and_gateway_config_wiring(tmp_path: Path) -> None:
    register_agent_stack_adapter(force=True)
    entry = platform_registry.get("agent_stack")
    assert entry is not None

    config = GatewayConfig.from_dict(
        {
            "platforms": {
                "agent_stack": {
                    "enabled": True,
                    "extra": {
                        "runtime_dir": str(tmp_path / "run"),
                        "db_path": str(tmp_path / "channel.db"),
                    },
                }
            }
        }
    )
    assert Platform.AGENT_STACK in config.get_connected_platforms()
    adapter = platform_registry.create_adapter(
        Platform.AGENT_STACK.value,
        config.platforms[Platform.AGENT_STACK],
    )
    assert isinstance(adapter, AgentStackAdapter)
    assert adapter.authorization_is_upstream is True

    runner = object.__new__(GatewayRunner)
    runner.config = config
    constructed = runner._create_adapter(
        Platform.AGENT_STACK,
        config.platforms[Platform.AGENT_STACK],
    )
    assert isinstance(constructed, AgentStackAdapter)
