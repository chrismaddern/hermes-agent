"""Canonical revision/edit/cancel contracts for Kanban control surfaces."""

from __future__ import annotations

import argparse
import contextlib
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import types
from pathlib import Path

import pytest

from hermes_cli import kanban as kanban_cli
from hermes_cli import kanban_db as kb


@pytest.fixture
def board(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_KANBAN_DB", raising=False)
    monkeypatch.delenv("HERMES_KANBAN_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb._INITIALIZED_PATHS.clear()
    kb.init_db()
    with kb.connect() as conn:
        yield conn


def test_fresh_and_migrated_boards_have_monotonic_revision_trigger(board):
    task_id = kb.create_task(board, title="revision")
    first = kb.get_task(board, task_id)
    assert first is not None
    assert first.revision >= 1

    board.execute("UPDATE tasks SET title = ? WHERE id = ?", ("same second", task_id))
    second = kb.get_task(board, task_id)
    assert second is not None
    assert second.revision == first.revision + 1

    board.execute("PRAGMA recursive_triggers=ON")
    board.execute("UPDATE tasks SET priority = priority + 1 WHERE id = ?", (task_id,))
    third = kb.get_task(board, task_id)
    assert third is not None
    assert third.revision == second.revision + 1

    trigger_count = board.execute(
        "SELECT COUNT(*) FROM sqlite_master "
        "WHERE type='trigger' AND name='tasks_revision_after_update'"
    ).fetchone()[0]
    assert trigger_count == 1


def test_populated_pre_revision_board_migrates_without_losing_rows(tmp_path: Path):
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(kb.SCHEMA_SQL.replace(
        "    block_recurrences    INTEGER NOT NULL DEFAULT 0,\n"
        "    revision             INTEGER NOT NULL DEFAULT 1\n",
        "    block_recurrences    INTEGER NOT NULL DEFAULT 0\n",
    ))
    # Simulate the prior schema by rebuilding only the tasks table without revision.
    conn.execute(
        "INSERT INTO tasks (id, title, status, created_at) VALUES ('legacy', 'kept', 'ready', 1)"
    )
    conn.commit()
    conn.close()

    kb._INITIALIZED_PATHS.clear()
    with kb.connect(db_path) as migrated:
        row = migrated.execute("SELECT title, revision FROM tasks WHERE id='legacy'").fetchone()
        assert tuple(row) == ("kept", 1)
        migrated.execute("UPDATE tasks SET title='changed' WHERE id='legacy'")
        assert migrated.execute(
            "SELECT revision FROM tasks WHERE id='legacy'"
        ).fetchone()[0] == 2


def test_revision_column_and_trigger_migrate_in_one_transaction():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT, status TEXT, created_at INTEGER)"
    )
    conn.execute(
        "INSERT INTO tasks (id, title, status, created_at) VALUES ('legacy', 'kept', 'ready', 1)"
    )
    conn.commit()

    def deny_trigger(action, _arg1, _arg2, _db_name, _trigger_name):
        if action == sqlite3.SQLITE_CREATE_TRIGGER:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    conn.set_authorizer(deny_trigger)
    with pytest.raises(sqlite3.DatabaseError):
        kb._migrate_task_revision(conn)
    conn.set_authorizer(None)

    columns = {row["name"] for row in conn.execute("PRAGMA table_info(tasks)")}
    trigger_count = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master "
        "WHERE type='trigger' AND name='tasks_revision_after_update'"
    ).fetchone()[0]
    assert "revision" not in columns
    assert trigger_count == 0
    assert conn.in_transaction is False


def test_task_revision_is_in_canonical_cli_serialization(board):
    task_id = kb.create_task(board, title="serialized")
    task = kb.get_task(board, task_id)

    serialized = kanban_cli._task_to_dict(task)

    assert serialized["revision"] == task.revision


def test_touch_task_revision_invalidates_detail_without_double_trigger_bump(board):
    task_id = kb.create_task(board, title="detail")
    before = kb.task_revision(kb.get_task(board, task_id))
    assert kb.touch_task_revision(board, task_id) is True
    after = kb.task_revision(kb.get_task(board, task_id))
    assert after == before + 1
    assert kb.touch_task_revision(board, "missing") is False


def test_comment_detail_change_advances_revision_once(board):
    task_id = kb.create_task(board, title="comment detail")
    before = kb.get_task(board, task_id).revision

    kb.add_comment(board, task_id, author="operator", body="new evidence")

    assert kb.get_task(board, task_id).revision == before + 1
    assert kb.list_events(board, task_id)[-1].kind == "commented"


def test_attachment_detail_changes_advance_revision_once(board, tmp_path: Path):
    task_id = kb.create_task(board, title="attachment detail")
    before = kb.get_task(board, task_id).revision
    blob = tmp_path / "evidence.txt"
    blob.write_text("evidence", encoding="utf-8")

    attachment_id = kb.add_attachment(
        board,
        task_id,
        filename=blob.name,
        stored_path=str(blob),
        size=blob.stat().st_size,
    )
    after_add = kb.get_task(board, task_id).revision
    assert after_add == before + 1

    removed = kb.delete_attachment(board, attachment_id)
    assert removed is not None
    assert kb.get_task(board, task_id).revision == after_add + 1


def test_dependency_detail_changes_advance_revision_without_status_change(board):
    first_parent = kb.create_task(board, title="parent one")
    second_parent = kb.create_task(board, title="parent two")
    child = kb.create_task(board, title="waiting child")
    board.execute("UPDATE tasks SET status='todo' WHERE id=?", (child,))
    before = kb.get_task(board, child).revision

    kb.link_tasks(board, first_parent, child)
    after_first_link = kb.get_task(board, child)
    assert after_first_link.status == "todo"
    assert after_first_link.revision == before + 1

    kb.link_tasks(board, second_parent, child)
    after_second_link = kb.get_task(board, child)
    assert after_second_link.revision == after_first_link.revision + 1

    assert kb.unlink_tasks(board, first_parent, child) is True
    after_unlink = kb.get_task(board, child)
    assert after_unlink.status == "todo"
    assert after_unlink.revision == after_second_link.revision + 1


def test_edit_task_fields_is_atomic_and_event_contains_field_names_only(board):
    task_id = kb.create_task(board, title="before")
    board.execute("UPDATE tasks SET status='blocked' WHERE id=?", (task_id,))
    source_revision = kb.get_task(board, task_id).revision

    result = kb.edit_task_fields(
        board,
        task_id,
        title=" after ",
        body="private body",
        priority=23,
        project_id="project-safe",
        expected_revision=source_revision,
    )

    task = kb.get_task(board, task_id)
    assert result.applied is True
    assert result.changed_fields == ("title", "body", "priority", "project_id")
    assert result.revision == task.revision
    assert (task.title, task.body, task.priority, task.project_id) == (
        "after", "private body", 23, "project-safe"
    )
    event = kb.list_events(board, task_id)[-1]
    assert event.kind == "edited"
    assert event.payload == {"fields": ["title", "body", "priority", "project_id"]}
    assert "private body" not in str(event.payload)
    assert "project-safe" not in str(event.payload)


def test_edit_task_fields_noop_has_no_event_or_revision_bump(board):
    task_id = kb.create_task(board, title="same")
    board.execute("UPDATE tasks SET status='ready' WHERE id=?", (task_id,))
    before = kb.get_task(board, task_id)
    event_count = len(kb.list_events(board, task_id))

    result = kb.edit_task_fields(
        board, task_id, title="same", expected_revision=before.revision
    )

    assert result.applied is True
    assert result.changed_fields == ()
    assert result.revision == before.revision
    assert len(kb.list_events(board, task_id)) == event_count


def test_edit_task_fields_rejects_stale_revision_and_disallowed_state_atomically(board):
    task_id = kb.create_task(board, title="running")
    board.execute("UPDATE tasks SET status='running' WHERE id=?", (task_id,))
    before = kb.get_task(board, task_id)

    with pytest.raises(kb.TaskRevisionConflict) as stale:
        kb.edit_task_fields(
            board, task_id, priority=1, expected_revision=before.revision - 1
        )
    assert stale.value.actual_revision == before.revision

    with pytest.raises(kb.TaskCommandConflict) as state:
        kb.edit_task_fields(
            board,
            task_id,
            title="must not land",
            priority=7,
            expected_revision=before.revision,
        )
    assert state.value.code == "action_not_allowed"
    unchanged = kb.get_task(board, task_id)
    assert unchanged.title == "running"
    assert unchanged.priority == before.priority


def test_edit_task_fields_can_join_caller_owned_transaction(board):
    task_id = kb.create_task(board, title="before")
    board.execute("UPDATE tasks SET status='ready' WHERE id=?", (task_id,))
    revision = kb.get_task(board, task_id).revision

    board.execute("BEGIN IMMEDIATE")
    kb.edit_task_fields(
        board,
        task_id,
        title="inside",
        expected_revision=revision,
        transaction_owned=True,
    )
    board.execute("ROLLBACK")

    assert kb.get_task(board, task_id).title == "before"


def test_promote_rechecks_dependencies_inside_write_transaction(
    board, monkeypatch: pytest.MonkeyPatch
):
    parent = kb.create_task(board, title="open parent")
    child = kb.create_task(board, title="requeue")
    board.execute("UPDATE tasks SET status='todo' WHERE id=?", (child,))
    revision = kb.get_task(board, child).revision
    original_write_txn = kb.write_txn
    inserted = False

    @kb.contextlib.contextmanager
    def racing_write_txn(conn):
        nonlocal inserted
        if not inserted:
            inserted = True
            conn.execute(
                "INSERT INTO task_links (parent_id, child_id) VALUES (?, ?)",
                (parent, child),
            )
        with original_write_txn(conn):
            yield conn

    monkeypatch.setattr(kb, "write_txn", racing_write_txn)

    ok, error = kb.promote_task(
        board, child, actor="test", force=False, expected_revision=revision
    )

    assert ok is False
    assert error is not None and "unsatisfied parent dependencies" in error
    assert kb.get_task(board, child).status == "todo"


def test_expected_revision_cas_guards_canonical_lifecycle_helpers(board):
    # Assignment
    assigned = kb.create_task(board, title="assign")
    rev = kb.get_task(board, assigned).revision
    with pytest.raises(kb.TaskRevisionConflict):
        kb.assign_task(board, assigned, "reviewer", expected_revision=rev - 1)
    assert kb.get_task(board, assigned).assignee is None
    assert kb.assign_task(board, assigned, "reviewer", expected_revision=rev)

    # Block / unblock
    blocked = kb.create_task(board, title="block")
    rev = kb.get_task(board, blocked).revision
    with pytest.raises(kb.TaskRevisionConflict):
        kb.block_task(board, blocked, expected_revision=rev - 1)
    assert kb.get_task(board, blocked).status == "ready"
    assert kb.block_task(board, blocked, expected_revision=rev)
    rev = kb.get_task(board, blocked).revision
    with pytest.raises(kb.TaskRevisionConflict):
        kb.unblock_task(board, blocked, expected_revision=rev - 1)
    assert kb.unblock_task(board, blocked, expected_revision=rev)

    # Promote without force and archive preserve their existing return shapes.
    promoted = kb.create_task(board, title="promote")
    board.execute("UPDATE tasks SET status='todo' WHERE id=?", (promoted,))
    rev = kb.get_task(board, promoted).revision
    with pytest.raises(kb.TaskRevisionConflict):
        kb.promote_task(
            board, promoted, actor="test", expected_revision=rev - 1
        )
    assert kb.promote_task(
        board, promoted, actor="test", expected_revision=rev
    ) == (True, None)

    archived = kb.create_task(board, title="archive")
    board.execute("UPDATE tasks SET status='done' WHERE id=?", (archived,))
    rev = kb.get_task(board, archived).revision
    with pytest.raises(kb.TaskRevisionConflict):
        kb.archive_task(board, archived, expected_revision=rev - 1)
    assert kb.archive_task(board, archived, expected_revision=rev)


def test_revision_conflict_precedes_lifecycle_state_refusal(board):
    ready = kb.create_task(board, title="already ready")
    ready_revision = kb.get_task(board, ready).revision
    board.execute("UPDATE tasks SET priority = priority + 1 WHERE id=?", (ready,))
    with pytest.raises(kb.TaskRevisionConflict):
        kb.unblock_task(board, ready, expected_revision=ready_revision)

    archived = kb.create_task(board, title="already archived")
    archived_revision = kb.get_task(board, archived).revision
    assert kb.archive_task(board, archived, expected_revision=archived_revision)
    with pytest.raises(kb.TaskRevisionConflict):
        kb.archive_task(board, archived, expected_revision=archived_revision)


def test_default_lifecycle_helper_calls_remain_backward_compatible(board):
    task_id = kb.create_task(board, title="legacy cli")
    assert kb.assign_task(board, task_id, "reviewer")
    assert kb.block_task(board, task_id, reason="legacy")
    assert kb.unblock_task(board, task_id)


@pytest.mark.parametrize("command", ["assign", "block", "unblock", "promote", "archive"])
def test_lifecycle_command_and_caller_receipt_commit_or_rollback_together(board, command):
    task_id = kb.create_task(board, title=command)
    if command == "unblock":
        assert kb.block_task(board, task_id, reason="prepare")
        source_status, result_status = "blocked", "ready"
    elif command == "promote":
        board.execute("UPDATE tasks SET status='todo' WHERE id=?", (task_id,))
        source_status, result_status = "todo", "ready"
    elif command == "archive":
        board.execute("UPDATE tasks SET status='done' WHERE id=?", (task_id,))
        source_status, result_status = "done", "archived"
    else:
        source_status = "ready"
        result_status = "blocked" if command == "block" else "ready"

    board.execute("CREATE TABLE IF NOT EXISTS command_receipts (command TEXT UNIQUE)")

    def apply():
        if command == "assign":
            return kb.assign_task(board, task_id, "reviewer", transaction_owned=True)
        if command == "block":
            return kb.block_task(board, task_id, reason="wait", transaction_owned=True)
        if command == "unblock":
            return kb.unblock_task(board, task_id, transaction_owned=True)
        if command == "promote":
            return kb.promote_task(
                board, task_id, actor="control", transaction_owned=True
            )[0]
        return kb.archive_task(board, task_id, transaction_owned=True)

    board.execute("BEGIN IMMEDIATE")
    assert apply()
    board.execute("INSERT INTO command_receipts VALUES (?)", (command,))
    board.execute("ROLLBACK")
    rolled_back = kb.get_task(board, task_id)
    assert rolled_back.status == source_status
    assert rolled_back.assignee is None
    assert board.execute("SELECT 1 FROM command_receipts").fetchone() is None

    with kb.task_command_transaction(board):
        assert apply()
        board.execute("INSERT INTO command_receipts VALUES (?)", (command,))
    committed = kb.get_task(board, task_id)
    assert committed.status == result_status
    if command == "assign":
        assert committed.assignee == "reviewer"
    assert board.execute(
        "SELECT command FROM command_receipts WHERE command=?", (command,)
    ).fetchone()[0] == command


def _running_task(board, monkeypatch, *, pid=424242, claim_lock=None):
    if claim_lock is None:
        claim_lock = f"{kb._claimer_id().split(':', 1)[0]}:999"
    task_id = kb.create_task(board, title="cancel me")
    claimed = kb.claim_task(board, task_id, claimer=claim_lock)
    assert claimed is not None
    kb._set_worker_pid(board, task_id, pid)
    task = kb.get_task(board, task_id)
    return task_id, task


def test_cancel_running_task_stops_exact_local_run_and_blocks(board, monkeypatch):
    task_id, task = _running_task(board, monkeypatch)
    monkeypatch.setattr(kb, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: True)
    monkeypatch.setattr(
        kb,
        "_cancel_worker_identity_matches",
        lambda pid, tid, **_identity: pid == task.worker_pid and tid == task_id,
    )
    monkeypatch.setattr(kb, "_terminate_cancel_worker_group", lambda pid: "stopped")

    result = kb.cancel_running_task(
        board,
        task_id,
        expected_run_id=task.current_run_id,
        expected_revision=task.revision,
    )

    cancelled = kb.get_task(board, task_id)
    run = board.execute(
        "SELECT * FROM task_runs WHERE id=?", (task.current_run_id,)
    ).fetchone()
    event = kb.list_events(board, task_id)[-1]
    assert result.worker_effect == "stopped"
    assert result.run_id == task.current_run_id
    assert result.revision == cancelled.revision
    assert cancelled.status == "blocked"
    assert cancelled.block_kind == "needs_input"
    assert cancelled.current_run_id is None
    assert cancelled.claim_lock is None
    assert cancelled.worker_pid is None
    assert (run["status"], run["outcome"], run["ended_at"] is not None) == (
        "cancelled", "cancelled", True
    )
    assert event.kind == "cancelled_by_operator"
    assert event.run_id == task.current_run_id
    assert event.payload == {"worker_effect": "stopped"}


def test_cancel_running_task_finalizes_exact_already_stopped_worker(board, monkeypatch):
    task_id, task = _running_task(board, monkeypatch)
    monkeypatch.setattr(kb, "_pid_alive", lambda pid: False)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: False)

    result = kb.cancel_running_task(
        board,
        task_id,
        expected_run_id=task.current_run_id,
        expected_revision=task.revision,
    )

    assert result.worker_effect == "already_stopped"
    assert kb.get_task(board, task_id).status == "blocked"


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_cancel_fails_closed_when_dead_leader_has_live_descendants(board, monkeypatch):
    task_id, task = _running_task(board, monkeypatch)
    monkeypatch.setattr(kb, "_pid_alive", lambda pid: False)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: True)

    with pytest.raises(kb.TaskCommandConflict) as error:
        kb.cancel_running_task(
            board,
            task_id,
            expected_run_id=task.current_run_id,
            expected_revision=task.revision,
        )

    assert error.value.code == "worker_identity_mismatch"
    assert kb.get_task(board, task_id).status == "running"


def test_cancel_running_task_fails_closed_for_foreign_or_identity_mismatch(board, monkeypatch):
    foreign_id, foreign = _running_task(board, monkeypatch, claim_lock="other-host:999")
    monkeypatch.setattr(kb, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: True)
    with pytest.raises(kb.TaskCommandConflict) as foreign_error:
        kb.cancel_running_task(
            board,
            foreign_id,
            expected_run_id=foreign.current_run_id,
            expected_revision=foreign.revision,
        )
    assert foreign_error.value.code == "worker_foreign"
    assert kb.get_task(board, foreign_id).status == "running"

    local_id, local = _running_task(board, monkeypatch, pid=525252)
    monkeypatch.setattr(
        kb, "_cancel_worker_identity_matches", lambda pid, tid, **_identity: False
    )
    with pytest.raises(kb.TaskCommandConflict) as identity_error:
        kb.cancel_running_task(
            board,
            local_id,
            expected_run_id=local.current_run_id,
            expected_revision=local.revision,
        )
    assert identity_error.value.code == "worker_identity_mismatch"
    assert kb.get_task(board, local_id).status == "running"


def test_cancel_running_task_rolls_back_when_stop_is_unconfirmed(board, monkeypatch):
    task_id, task = _running_task(board, monkeypatch)
    monkeypatch.setattr(kb, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: True)
    monkeypatch.setattr(
        kb, "_cancel_worker_identity_matches", lambda pid, tid, **_identity: True
    )
    monkeypatch.setattr(kb, "_terminate_cancel_worker_group", lambda pid: None)

    with pytest.raises(kb.TaskCommandConflict) as error:
        kb.cancel_running_task(
            board,
            task_id,
            expected_run_id=task.current_run_id,
            expected_revision=task.revision,
        )
    assert error.value.code == "worker_stop_unconfirmed"
    unchanged = kb.get_task(board, task_id)
    run = board.execute(
        "SELECT status, outcome, ended_at FROM task_runs WHERE id=?",
        (task.current_run_id,),
    ).fetchone()
    assert unchanged.status == "running"
    assert unchanged.current_run_id == task.current_run_id
    assert tuple(run) == ("running", None, None)


def test_cancel_running_task_binds_revision_run_claim_and_pid(board, monkeypatch):
    task_id, task = _running_task(board, monkeypatch)
    monkeypatch.setattr(kb, "_pid_alive", lambda pid: False)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: False)

    with pytest.raises(kb.TaskRevisionConflict):
        kb.cancel_running_task(
            board,
            task_id,
            expected_run_id=task.current_run_id,
            expected_revision=task.revision - 1,
        )
    with pytest.raises(kb.TaskCommandConflict) as changed:
        kb.cancel_running_task(
            board,
            task_id,
            expected_run_id=task.current_run_id + 1,
            expected_revision=task.revision,
        )
    assert changed.value.code == "run_changed"
    assert kb.get_task(board, task_id).status == "running"


def test_cancel_running_task_owns_commit_and_persists_caller_receipt(board, monkeypatch):
    task_id, task = _running_task(board, monkeypatch)
    monkeypatch.setattr(kb, "_pid_alive", lambda pid: False)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: False)
    board.execute("CREATE TABLE receipts (task_id TEXT, revision INTEGER)")

    result = kb.cancel_running_task(
        board,
        task_id,
        expected_run_id=task.current_run_id,
        expected_revision=task.revision,
        success_receipt=lambda conn, applied: conn.execute(
            "INSERT INTO receipts VALUES (?, ?)", (task_id, applied.revision)
        ),
    )

    assert kb.get_task(board, task_id).status == "blocked"
    assert tuple(board.execute("SELECT * FROM receipts").fetchone()) == (
        task_id,
        result.revision,
    )


def test_cancel_commit_failure_recovers_durable_terminal_state_and_receipt(
    board, monkeypatch
):
    task_id, task = _running_task(board, monkeypatch)
    monkeypatch.setattr(kb, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: True)
    monkeypatch.setattr(kb, "_cancel_worker_identity_matches", lambda *a, **k: True)
    monkeypatch.setattr(kb, "_terminate_cancel_worker_group", lambda pid: "stopped")
    board.execute("CREATE TABLE receipts (task_id TEXT UNIQUE)")
    attempts = 0

    @contextlib.contextmanager
    def fail_first_commit(conn, commit_recovery=None):
        nonlocal attempts
        attempts += 1
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except Exception:
            conn.execute("ROLLBACK")
            raise
        if attempts == 1:
            conn.execute("ROLLBACK")
            assert commit_recovery is not None
            commit_recovery()
        else:
            conn.execute("COMMIT")

    monkeypatch.setattr(kb, "_bounded_cancel_transaction", fail_first_commit)

    result = kb.cancel_running_task(
        board,
        task_id,
        expected_run_id=task.current_run_id,
        expected_revision=task.revision,
        success_receipt=lambda conn, _result: conn.execute(
            "INSERT INTO receipts VALUES (?)", (task_id,)
        ),
    )

    assert attempts == 2
    assert result.worker_effect == "stopped"
    assert kb.get_task(board, task_id).status == "blocked"
    assert board.execute("SELECT task_id FROM receipts").fetchone()[0] == task_id


def test_cancel_receipt_failure_still_persists_stopped_terminal_state(board, monkeypatch):
    task_id, task = _running_task(board, monkeypatch)
    monkeypatch.setattr(kb, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: True)
    monkeypatch.setattr(kb, "_cancel_worker_identity_matches", lambda *a, **k: True)
    monkeypatch.setattr(kb, "_terminate_cancel_worker_group", lambda pid: "stopped")

    def reject_receipt(_conn, _result):
        raise sqlite3.OperationalError("receipt unavailable")

    with pytest.raises(sqlite3.OperationalError, match="receipt unavailable"):
        kb.cancel_running_task(
            board,
            task_id,
            expected_run_id=task.current_run_id,
            expected_revision=task.revision,
            success_receipt=reject_receipt,
        )

    cancelled = kb.get_task(board, task_id)
    run = board.execute(
        "SELECT status, outcome FROM task_runs WHERE id=?", (task.current_run_id,)
    ).fetchone()
    assert cancelled.status == "blocked"
    assert cancelled.current_run_id is None
    assert tuple(run) == ("cancelled", "cancelled")


def test_cancel_standalone_transaction_does_not_retry_busy_window(board, monkeypatch):
    task_id, task = _running_task(board, monkeypatch)
    monkeypatch.setattr(kb, "_pid_alive", lambda pid: False)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: False)
    monkeypatch.setattr(
        kb,
        "_execute_boundary_with_retry",
        lambda conn, sql: (_ for _ in ()).throw(
            AssertionError("cancel must use one bounded SQLite busy window")
        ),
    )

    result = kb.cancel_running_task(
        board,
        task_id,
        expected_run_id=task.current_run_id,
        expected_revision=task.revision,
    )

    assert result.worker_effect == "already_stopped"
    assert kb.get_task(board, task_id).status == "blocked"


def test_cancel_cli_uses_canonical_cancel_not_reclaim(board, monkeypatch, capsys):
    task_id, task = _running_task(board, monkeypatch)
    monkeypatch.setattr(kb, "_pid_alive", lambda pid: False)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: False)

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    kanban_cli.build_parser(subparsers)
    args = parser.parse_args([
        "kanban", "cancel", task_id,
        "--run-id", str(task.current_run_id),
        "--revision", str(task.revision),
    ])

    assert kanban_cli.kanban_command(args) == 0
    output = capsys.readouterr().out
    assert "blocked" in output.lower()
    assert "already stopped" in output.lower()
    assert kb.get_task(board, task_id).status == "blocked"


def test_process_group_probe_fails_closed_when_proc_cannot_be_scanned(monkeypatch):
    def unreadable(_self):
        raise OSError("proc unavailable")

    monkeypatch.setattr(Path, "iterdir", unreadable)
    monkeypatch.setattr(kb.os, "killpg", lambda pgid, sig: None)

    assert kb._process_group_alive(424242) is True


def test_process_group_probe_uses_kernel_when_proc_entries_are_unreadable(monkeypatch):
    class UnreadableStat:
        def read_text(self, **_kwargs):
            raise PermissionError("hidden proc entry")

    class ProcEntry:
        name = "123"

        def __truediv__(self, _name):
            return UnreadableStat()

    probes = []
    monkeypatch.setattr(Path, "iterdir", lambda _self: iter([ProcEntry()]))
    monkeypatch.setattr(kb.os, "killpg", lambda pgid, sig: probes.append((pgid, sig)))

    assert kb._process_group_alive(424242) is True
    assert probes == [(424242, 0)]


@pytest.mark.parametrize(
    ("worker_run_id", "worker_claim_lock"),
    [("9002", "local:expected"), ("9001", "local:wrong")],
)
def test_cancel_identity_binds_task_run_and_claim(
    monkeypatch, worker_run_id, worker_claim_lock
):
    class Process:
        def __init__(self, _pid):
            pass

        def environ(self):
            return {
                "HERMES_KANBAN_TASK": "t_same",
                "HERMES_KANBAN_RUN_ID": worker_run_id,
                "HERMES_KANBAN_CLAIM_LOCK": worker_claim_lock,
            }

        def cmdline(self):
            return ["hermes", "work", "kanban", "task", "t_same"]

    fake_psutil = types.SimpleNamespace(Process=Process, Error=RuntimeError)
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil)
    monkeypatch.setattr(kb.os, "getpgid", lambda pid: pid)

    assert not kb._cancel_worker_identity_matches(
        424242,
        "t_same",
        expected_run_id=9001,
        expected_claim_lock="local:expected",
        expected_db_path="/boards/canonical.db",
        expected_board="canonical",
    )


def test_cancel_identity_rejects_same_task_run_claim_on_foreign_board(monkeypatch):
    class Process:
        def __init__(self, _pid):
            pass

        def environ(self):
            return {
                "HERMES_KANBAN_TASK": "t_same",
                "HERMES_KANBAN_RUN_ID": "9001",
                "HERMES_KANBAN_CLAIM_LOCK": "local:expected",
                "HERMES_KANBAN_DB": "/boards/foreign/../foreign.db",
                "HERMES_KANBAN_BOARD": "foreign",
            }

        def cmdline(self):
            return ["hermes", "work", "kanban", "task", "t_same"]

    fake_psutil = types.SimpleNamespace(Process=Process, Error=RuntimeError)
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil)
    monkeypatch.setattr(kb.os, "getpgid", lambda pid: pid)

    assert not kb._cancel_worker_identity_matches(
        424242,
        "t_same",
        expected_run_id=9001,
        expected_claim_lock="local:expected",
        expected_db_path="/boards/canonical.db",
        expected_board="canonical",
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_cancel_uses_bounded_sigkill_after_term_grace(monkeypatch):
    clock = [0.0]
    sent = []

    monkeypatch.setattr(kb, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: True)
    monkeypatch.setattr(kb.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(kb.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(kb.os, "killpg", lambda pgid, sig: sent.append(sig))
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: len(sent) < 2)

    effect = kb._terminate_cancel_worker_group(424242)

    assert effect == "stopped"
    assert sent == [signal.SIGTERM, signal.SIGKILL]
    assert clock[0] <= 5.0


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_cancel_terminator_tracks_group_after_leader_exits(monkeypatch):
    sent = []
    probes = iter([True, True, False])

    monkeypatch.setattr(kb, "_pid_alive", lambda pid: False)
    monkeypatch.setattr(kb, "_process_group_alive", lambda pgid: next(probes))
    monkeypatch.setattr(kb.os, "killpg", lambda pgid, sig: sent.append(sig))

    assert kb._terminate_cancel_worker_group(424242) == "stopped"
    assert sent == [signal.SIGTERM]


def test_natural_completion_racing_cancel_has_one_terminal_winner(
    board, monkeypatch: pytest.MonkeyPatch
):
    task_id, task = _running_task(board, monkeypatch)
    db_path = Path(board.execute("PRAGMA database_list").fetchone()[2])
    stop_window_entered = threading.Event()
    release_stop_window = threading.Event()
    completion_started = threading.Event()
    results = {}

    def worker_is_already_stopped(_pid):
        stop_window_entered.set()
        assert release_stop_window.wait(timeout=2)
        return False

    monkeypatch.setattr(kb, "_pid_alive", worker_is_already_stopped)

    def cancel():
        with kb.connect(db_path) as conn:
            results["cancel"] = kb.cancel_running_task(
                conn,
                task_id,
                expected_run_id=task.current_run_id,
                expected_revision=task.revision,
            )

    def complete():
        assert stop_window_entered.wait(timeout=2)
        completion_started.set()
        with kb.connect(db_path) as conn:
            results["complete"] = kb.complete_task(
                conn,
                task_id,
                summary="natural completion",
                expected_run_id=task.current_run_id,
            )

    cancel_thread = threading.Thread(target=cancel)
    complete_thread = threading.Thread(target=complete)
    cancel_thread.start()
    assert stop_window_entered.wait(timeout=2)
    complete_thread.start()
    assert completion_started.wait(timeout=2)
    release_stop_window.set()
    cancel_thread.join(timeout=5)
    complete_thread.join(timeout=5)

    assert not cancel_thread.is_alive()
    assert not complete_thread.is_alive()
    assert results["cancel"].worker_effect == "already_stopped"
    assert results["complete"] is False
    assert kb.get_task(board, task_id).status == "blocked"
    run = board.execute(
        "SELECT status, outcome FROM task_runs WHERE id=?",
        (task.current_run_id,),
    ).fetchone()
    assert tuple(run) == ("cancelled", "cancelled")


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_cancel_identity_and_process_group_termination_against_real_worker(board):
    task_id = kb.create_task(board, title="real worker")
    claim_lock = f"{kb._claimer_id().split(':', 1)[0]}:999"
    claimed = kb.claim_task(board, task_id, claimer=claim_lock)
    assert claimed is not None
    env = dict(os.environ)
    env["HERMES_KANBAN_TASK"] = task_id
    env["HERMES_KANBAN_RUN_ID"] = str(claimed.current_run_id)
    env["HERMES_KANBAN_CLAIM_LOCK"] = claim_lock
    env["HERMES_KANBAN_DB"] = str(
        Path(board.execute("PRAGMA database_list").fetchone()[2]).resolve()
    )
    env["HERMES_KANBAN_BOARD"] = "default"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(60)",
            "work kanban task",
            task_id,
        ],
        env=env,
        start_new_session=True,
    )
    try:
        kb._set_worker_pid(board, task_id, proc.pid)
        task = kb.get_task(board, task_id)
        assert kb._cancel_worker_identity_matches(
            proc.pid,
            task_id,
            expected_run_id=task.current_run_id,
            expected_claim_lock=claim_lock,
            expected_db_path=env["HERMES_KANBAN_DB"],
            expected_board="default",
        )
        result = kb.cancel_running_task(
            board,
            task_id,
            expected_run_id=task.current_run_id,
            expected_revision=task.revision,
        )
        assert result.worker_effect == "stopped"
        proc.wait(timeout=2)
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, 9)
            proc.wait(timeout=2)
