from __future__ import annotations

import os
import sys
import time
import types
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.kanban_worker_heartbeat import (
    KanbanWorkerHeartbeat,
    enforce_current_run_ownership,
    worker_heartbeat_keepalive,
)
from hermes_cli import kanban_db as kb


def _wait_until(predicate, *, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def test_keepalive_heartbeats_without_foreground_activity():
    calls = 0

    def heartbeat() -> bool:
        nonlocal calls
        calls += 1
        return True

    keepalive = KanbanWorkerHeartbeat(heartbeat, interval_seconds=0.01)
    keepalive.start()
    try:
        assert _wait_until(lambda: calls >= 3)
    finally:
        keepalive.stop()

    stopped_at = calls
    time.sleep(0.05)
    assert calls == stopped_at
    assert not keepalive.is_alive


def test_keepalive_stops_when_task_is_no_longer_running():
    results = iter((True, False))
    calls = 0

    def heartbeat() -> bool:
        nonlocal calls
        calls += 1
        return next(results)

    keepalive = KanbanWorkerHeartbeat(heartbeat, interval_seconds=0.01)
    keepalive.start()

    assert _wait_until(lambda: not keepalive.is_alive)
    assert calls == 2


def test_keepalive_stops_when_worker_scope_errors():
    keepalive = None

    with pytest.raises(RuntimeError, match="model failed"):
        with worker_heartbeat_keepalive(
            interval_seconds=0.01,
            heartbeat_fn=lambda: True,
        ) as active_keepalive:
            keepalive = active_keepalive
            assert keepalive is not None
            assert _wait_until(lambda: keepalive.is_alive)
            raise RuntimeError("model failed")

    assert keepalive is not None
    assert not keepalive.is_alive


def test_chat_process_wraps_agent_run_in_worker_keepalive(monkeypatch):
    from agent import kanban_worker_heartbeat as heartbeat_module
    from hermes_cli import main

    events = []

    @contextmanager
    def fake_keepalive():
        events.append("heartbeat-started")
        try:
            yield None
        finally:
            events.append("heartbeat-stopped")

    def fake_cli_main(**_kwargs):
        events.append("agent-run")

    monkeypatch.setattr(heartbeat_module, "worker_heartbeat_keepalive", fake_keepalive)
    monkeypatch.setattr(main, "_resolve_use_tui", lambda _args: False)
    monkeypatch.setattr(main, "_apply_safe_mode", lambda _args: None)
    monkeypatch.setattr(main, "_has_any_provider_configured", lambda: True)
    monkeypatch.setattr(main, "_termux_should_prefetch_update_check", lambda: False)
    monkeypatch.setattr(main, "_sync_bundled_skills_for_startup", lambda: None)
    monkeypatch.setattr(main, "_pin_kanban_board_env", lambda: None)
    monkeypatch.setitem(sys.modules, "cli", types.SimpleNamespace(main=fake_cli_main))

    args = SimpleNamespace(model=None, toolsets=None, query="work kanban task t_test")
    main.cmd_chat(args)

    assert events == ["heartbeat-started", "agent-run", "heartbeat-stopped"]


@pytest.fixture
def running_worker(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_BOARD", "default")
    db_path = kb.kanban_db_path(board="default")
    kb._INITIALIZED_PATHS.discard(str(db_path.resolve()))
    kb.init_db(board="default")

    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="long model turn", assignee="worker")
        assert kb.claim_task(conn, task_id, claimer=kb._claimer_id())
        task = kb.get_task(conn, task_id)
        assert task is not None
        kb._set_worker_pid(conn, task_id, os.getpid())

    monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(task.current_run_id))
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", str(task.claim_lock))
    return task_id


def test_real_keepalive_refreshes_claim_and_prevents_stale_reclaim(
    running_worker, monkeypatch
):
    task_id = running_worker
    old = int(time.time()) - (kb.DEFAULT_CLAIM_HEARTBEAT_MAX_STALE_SECONDS + 60)
    with kb.connect() as conn:
        conn.execute(
            "UPDATE tasks SET claim_expires = ?, last_heartbeat_at = ? WHERE id = ?",
            (int(time.time()) - 1, old, task_id),
        )
        conn.commit()

    with worker_heartbeat_keepalive(interval_seconds=0.01):

        def refreshed() -> bool:
            with kb.connect() as conn:
                task = kb.get_task(conn, task_id)
                return bool(
                    task and task.last_heartbeat_at and task.last_heartbeat_at > old
                )

        assert _wait_until(refreshed)
        with kb.connect() as conn:
            assert kb.release_stale_claims(conn) == 0
            task = kb.get_task(conn, task_id)
            assert task is not None
            assert task.status == "running"


def test_stale_direct_worker_is_signalled_before_another_tool(running_worker):
    task_id = running_worker
    current_signals: list[str] = []
    assert enforce_current_run_ownership(terminate_fn=current_signals.append) is None
    assert current_signals == []

    with kb.connect() as conn:
        original = kb.get_task(conn, task_id)
        assert original is not None
        old_run_id = original.current_run_id
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET status = 'ready', claim_lock = NULL, "
                "claim_expires = NULL, worker_pid = NULL WHERE id = ?",
                (task_id,),
            )
            kb._end_run(
                conn,
                task_id,
                outcome="reclaimed",
                status="reclaimed",
            )
        replacement = kb.claim_task(conn, task_id, claimer=kb._claimer_id())
        assert replacement is not None
        assert replacement.current_run_id != old_run_id
        kb._set_worker_pid(conn, task_id, os.getpid() + 1000)

    signals: list[str] = []
    reason = enforce_current_run_ownership(terminate_fn=signals.append)

    assert reason is not None
    assert "stale kanban run fenced" in reason
    assert f"expected_run={old_run_id}" in reason
    assert signals == [reason]


@pytest.mark.parametrize("final_status", ["blocked", "done"])
def test_real_keepalive_self_stops_after_task_finalization(
    running_worker, final_status
):
    task_id = running_worker
    with worker_heartbeat_keepalive(interval_seconds=0.01) as keepalive:
        assert keepalive is not None
        assert _wait_until(lambda: keepalive.is_alive)
        with kb.connect() as conn:
            conn.execute(
                "UPDATE tasks SET status = ? WHERE id = ?", (final_status, task_id)
            )
            conn.commit()
        assert _wait_until(lambda: not keepalive.is_alive)


def test_concurrent_inline_tool_is_fenced_before_mutating_session_state(monkeypatch):
    """Agent-loop tools must not bypass the stale-worker fence."""
    from agent import agent_runtime_helpers as runtime
    from tools.todo_tool import TodoStore

    monkeypatch.setattr(
        runtime,
        "enforce_current_run_ownership",
        lambda _tool_name: "stale kanban run fenced before todo",
        raising=False,
    )
    store = TodoStore()
    agent = SimpleNamespace(
        _todo_store=store,
        _memory_manager=None,
        session_id="",
        valid_tool_names={"todo"},
        _current_turn_id="",
        _current_api_request_id="",
    )

    result = runtime.invoke_tool(
        agent,
        "todo",
        {
            "todos": [
                {
                    "id": "stale-write",
                    "content": "must not execute",
                    "status": "pending",
                }
            ]
        },
        "t-stale",
        pre_tool_block_checked=True,
        skip_tool_request_middleware=True,
    )

    assert "STALE_WORKER" in result
    assert store.has_items() is False


def test_sequential_tool_is_fenced_before_request_middleware(monkeypatch):
    """No stale call may reach middleware, hooks, guardrails, or execution."""
    from agent import tool_executor

    monkeypatch.setattr(tool_executor, "_budget_for_agent", lambda _agent: None)
    monkeypatch.setattr(
        tool_executor,
        "enforce_current_run_ownership",
        lambda _tool_name: "stale kanban run fenced before todo",
        raising=False,
    )
    monkeypatch.setattr(
        tool_executor,
        "_apply_tool_request_middleware_for_agent",
        lambda *_args, **_kwargs: pytest.fail(
            "stale worker reached tool request middleware"
        ),
    )
    monkeypatch.setattr(
        tool_executor,
        "_flush_session_db_after_tool_progress",
        lambda *_args, **_kwargs: pytest.fail(
            "stale worker persisted a normal session checkpoint"
        ),
    )
    tool_call = SimpleNamespace(
        id="call-stale",
        function=SimpleNamespace(name="todo", arguments="{}"),
    )
    assistant_message = SimpleNamespace(tool_calls=[tool_call])
    messages = []
    agent = SimpleNamespace(_interrupt_requested=False)

    tool_executor.execute_tool_calls_sequential(
        agent,
        assistant_message,
        messages,
        "t-stale",
        finalize=False,
    )

    assert len(messages) == 1
    assert "STALE_WORKER" in messages[0]["content"]
