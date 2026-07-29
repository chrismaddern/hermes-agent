"""Regression coverage for fenced Kanban worker handoff.

A replacement run must never become claimable while the prior worker's
process group can still mutate shared state.  The scenarios here mirror the
stale-run overlap observed on tasks t_c79227ad and t_2576e886.
"""

from __future__ import annotations

import os
import signal
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def _local_lock(suffix: str = "worker") -> str:
    host = kb._claimer_id().split(":", 1)[0]
    return f"{host}:{suffix}"


def _termination(*, terminated: bool) -> dict:
    return {
        "attempted": True,
        "host_local": True,
        "pid": 42420,
        "process_group_id": 42420,
        "signal_scope": "process_group",
        "terminated": terminated,
        "survived": not terminated,
        "sigkill": not terminated,
    }


def test_timeout_exit_keeps_claim_until_process_group_exit_is_verified(
    kanban_home, monkeypatch,
):
    """The old run stays fenced until its whole process group is gone.

    This is the deterministic form of the production failure recorded on
    ``t_c79227ad`` (run 29302 → replacement 29318 nine seconds later) and
    ``t_2576e886`` (run 29320 → replacement 29321 sixteen seconds later): an
    iteration-limited run announced ``timed_out`` while still alive, a
    replacement was claimed, and both workers then wrote shared state.
    """
    pid = 42420
    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "0")

    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="fenced timeout", assignee="coder")
        claimed = kb.claim_task(conn, task_id, claimer=_local_lock())
        assert claimed is not None
        old_run_id = claimed.current_run_id
        assert old_run_id is not None
        kb._set_worker_pid(conn, task_id, pid)
        assert kb.request_worker_stop(
            conn,
            task_id,
            expected_run_id=old_run_id,
            outcome="timed_out",
            error="iteration budget exhausted (250/250)",
            metadata={"budget_used": 250, "budget_max": 250},
        )
        stopping = kb.get_run(conn, old_run_id)
        assert stopping is not None
        assert stopping.status == "stopping"
        assert stopping.outcome == "timed_out"
        assert kb.get_task(conn, task_id).status == "running"
        kb._record_worker_exit(
            pid,
            kb.KANBAN_TIMEOUT_EXIT_CODE << 8,
        )

        monkeypatch.setattr(
            kb,
            "_terminate_reclaimed_worker",
            lambda *_args, **_kwargs: _termination(terminated=False),
        )
        assert kb.detect_crashed_workers(conn) == []

        still_owned = kb.get_task(conn, task_id)
        assert still_owned.status == "running"
        assert still_owned.current_run_id == old_run_id
        assert still_owned.worker_pid == pid
        assert kb.claim_task(conn, task_id, claimer=_local_lock("replacement")) is None

        monkeypatch.setattr(
            kb,
            "_terminate_reclaimed_worker",
            lambda *_args, **_kwargs: _termination(terminated=True),
        )
        assert kb.detect_crashed_workers(conn) == []
        assert task_id in kb.detect_crashed_workers._last_timed_out

        requeued = kb.get_task(conn, task_id)
        assert requeued.status == "ready"
        assert requeued.current_run_id is None
        assert requeued.worker_pid is None

        old_run = conn.execute(
            "SELECT status, outcome, worker_pid FROM task_runs WHERE id = ?",
            (old_run_id,),
        ).fetchone()
        assert old_run["status"] == "timed_out"
        assert old_run["outcome"] == "timed_out"
        # Historical process identity remains attached to the terminal run.
        assert old_run["worker_pid"] == pid
        persisted_run = kb.get_run(conn, old_run_id)
        assert persisted_run is not None
        assert persisted_run.metadata["terminal_request"]["metadata"] == {
            "budget_used": 250,
            "budget_max": 250,
        }
        events = kb.list_events(conn, task_id)
        requested = [e for e in events if e.kind == "termination_requested"]
        terminal = [e for e in events if e.kind == "timed_out"]
        assert requested[-1].payload["process_group_exit_verified"] is False
        assert terminal[-1].payload["process_group_exit_verified"] is True
        assert terminal[-1].payload["run_id"] == old_run_id
        assert terminal[-1].payload["process_group_id"] == pid
        assert terminal[-1].payload["terminal_outcome"] == "timed_out"

        replacement = kb.claim_task(
            conn, task_id, claimer=_local_lock("replacement")
        )
        assert replacement is not None
        assert replacement.current_run_id != old_run_id


def test_dependency_wait_cannot_promote_or_reclaim_before_worker_exit(
    kanban_home, monkeypatch,
):
    """Dependency routing uses an exit barrier before returning to ``todo``.

    With no parent edge, ``recompute_ready`` may promote the card immediately;
    it still must not become ready until the blocking worker has exited.
    """
    pid = 42421
    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)
    monkeypatch.setenv("HERMES_KANBAN_CRASH_GRACE_SECONDS", "0")

    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="dependency handoff", assignee="coder")
        claimed = kb.claim_task(conn, task_id, claimer=_local_lock())
        assert claimed is not None
        old_run_id = claimed.current_run_id
        kb._set_worker_pid(conn, task_id, pid)

        assert kb.block_task(
            conn,
            task_id,
            reason="FINISH card owns packaging",
            kind="dependency",
            expected_run_id=old_run_id,
        )

        barrier = kb.get_task(conn, task_id)
        assert barrier.status == "running"
        assert barrier.current_run_id == old_run_id
        assert barrier.worker_pid == pid
        active_run = conn.execute(
            "SELECT status, outcome FROM task_runs WHERE id = ?", (old_run_id,)
        ).fetchone()
        assert active_run["status"] == "stopping"
        assert active_run["outcome"] == "blocked"
        assert kb.recompute_ready(conn) == 0
        assert kb.claim_task(conn, task_id, claimer=_local_lock("replacement")) is None

        monkeypatch.setattr(
            kb,
            "_terminate_reclaimed_worker",
            lambda *_args, **_kwargs: _termination(terminated=True),
        )
        assert kb.detect_crashed_workers(conn) == []

        waiting = kb.get_task(conn, task_id)
        assert waiting.status == "todo"
        assert waiting.current_run_id is None
        assert kb.recompute_ready(conn) == 1
        assert kb.get_task(conn, task_id).status == "ready"
        assert kb.claim_task(
            conn, task_id, claimer=_local_lock("replacement")
        ) is not None


def test_worker_block_cannot_be_unblocked_before_process_group_exit(
    kanban_home, monkeypatch,
):
    """Human-block routing retains ownership until the old group is gone."""
    pid = 42429
    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: True)

    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="human block handoff", assignee="coder")
        claimed = kb.claim_task(conn, task_id, claimer=_local_lock())
        assert claimed is not None
        run_id = claimed.current_run_id
        assert run_id is not None
        assert kb._set_worker_pid(conn, task_id, pid)

        assert kb.block_task(
            conn,
            task_id,
            reason="human decision required",
            kind="needs_input",
            expected_run_id=run_id,
        )

        barrier = kb.get_task(conn, task_id)
        assert barrier.status == "running"
        assert barrier.current_run_id == run_id
        assert barrier.worker_pid == pid
        stopping = kb.get_run(conn, run_id)
        assert stopping is not None
        assert stopping.status == "stopping"
        assert stopping.metadata["terminal_request"]["operation"] == "block_wait"
        assert kb.unblock_task(conn, task_id) is False
        assert kb.claim_task(conn, task_id, claimer=_local_lock("replacement")) is None

        monkeypatch.setattr(
            kb,
            "_terminate_reclaimed_worker",
            lambda *_args, **_kwargs: _termination(terminated=True),
        )
        assert kb.detect_crashed_workers(conn) == []

        blocked = kb.get_task(conn, task_id)
        assert blocked.status == "blocked"
        assert blocked.current_run_id is None
        assert blocked.worker_pid is None
        terminal = kb.get_run(conn, run_id)
        assert terminal is not None
        assert terminal.status == "blocked"
        assert terminal.outcome == "blocked"
        events = kb.list_events(conn, task_id)
        blocked_events = [event for event in events if event.kind == "blocked"]
        assert blocked_events[-1].payload["process_group_exit_verified"] is True


def test_late_spawn_pid_cannot_attach_to_replacement_run(kanban_home):
    """PID registration is fenced by the run and claim snapshot used to spawn."""
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="spawn race", assignee="coder")
        old = kb.claim_task(conn, task_id, claimer=_local_lock("old"))
        assert old is not None
        old_run_id = old.current_run_id
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
        replacement = kb.claim_task(
            conn,
            task_id,
            claimer=_local_lock("replacement"),
        )
        assert replacement is not None

        assert kb._set_worker_pid(
            conn,
            task_id,
            42424,
            expected_run_id=old_run_id,
            expected_claim_lock=old.claim_lock,
        ) is False
        current = kb.get_task(conn, task_id)
        assert current.current_run_id == replacement.current_run_id
        assert current.worker_pid is None
        assert kb.get_run(conn, replacement.current_run_id).worker_pid is None


def test_reclaim_signals_process_group_not_only_leader(kanban_home, monkeypatch):
    """POSIX reclaim targets the worker session/process group and verifies it."""
    if os.name == "nt":
        pytest.skip("process groups are POSIX-specific")

    pid = 42422
    alive = iter([True, True, False])
    group_signals = []
    monkeypatch.setattr(kb, "_process_group_alive", lambda _pgid: next(alive))
    monkeypatch.setattr(
        kb.os,
        "killpg",
        lambda pgid, sig: group_signals.append((pgid, sig)),
    )
    monkeypatch.setattr(
        kb.os,
        "kill",
        lambda *_args: pytest.fail("reclaim must not signal only the leader pid"),
    )
    monkeypatch.setattr(kb.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: True)
    monkeypatch.setattr(kb, "_cancel_worker_identity_matches", lambda *_a, **_k: True)

    result = kb._terminate_reclaimed_worker(
        pid,
        _local_lock(),
        task_id="t_process_group",
        expected_run_id=17,
        expected_db_path="/tmp/kanban.db",
    )

    assert group_signals == [(pid, signal.SIGTERM)]
    assert result["process_group_id"] == pid
    assert result["signal_scope"] == "process_group"
    assert result["identity_verified"] is True
    assert result["terminated"] is True
    assert result["survived"] is False


def test_dead_leader_with_live_descendants_stays_fenced(monkeypatch):
    """Without leader env proof, a live/reused PGID is never signalled or released."""
    if os.name == "nt":
        pytest.skip("process groups are POSIX-specific")

    pid = 42423
    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)
    monkeypatch.setattr(kb, "_process_group_alive", lambda _pgid: True)
    monkeypatch.setattr(
        kb.os,
        "killpg",
        lambda *_args: pytest.fail("unverified process group must not be signalled"),
    )

    result = kb._terminate_reclaimed_worker(
        pid,
        _local_lock(),
        task_id="t_process_group",
        expected_run_id=17,
        expected_db_path="/tmp/kanban.db",
    )

    assert result["identity_mismatch"] is True
    assert result["terminated"] is False
    assert result["survived"] is True


def test_dead_leader_with_verified_descendants_is_terminated(monkeypatch):
    """A verified orphaned worker group is killed rather than fenced forever."""
    if os.name == "nt":
        pytest.skip("process groups are POSIX-specific")

    pid = 42424
    alive = iter([True, True, False])
    group_signals = []
    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)
    monkeypatch.setattr(kb, "_process_group_alive", lambda _pgid: next(alive))
    monkeypatch.setattr(
        kb,
        "_orphaned_worker_group_identity_matches",
        lambda *_args, **_kwargs: True,
        raising=False,
    )
    monkeypatch.setattr(
        kb.os,
        "killpg",
        lambda pgid, sig: group_signals.append((pgid, sig)),
    )
    monkeypatch.setattr(kb.time, "sleep", lambda _seconds: None)

    result = kb._terminate_reclaimed_worker(
        pid,
        _local_lock(),
        task_id="t_process_group",
        expected_run_id=17,
        expected_db_path="/tmp/kanban.db",
    )

    assert group_signals == [(pid, signal.SIGTERM)]
    assert result["identity_verified"] is True
    assert result["terminated"] is True
    assert result["survived"] is False


def test_process_group_iteration_error_fails_closed(monkeypatch):
    """A lazy /proc iterator failure is not evidence that a group exited."""
    if os.name == "nt":
        pytest.skip("process groups are POSIX-specific")

    def broken_entries(_path):
        yield Path("/proc/1")
        raise OSError("proc scan interrupted")

    monkeypatch.setattr(kb.sys, "platform", "linux")
    monkeypatch.setattr(kb.Path, "iterdir", broken_entries)
    monkeypatch.setattr(kb.os, "killpg", lambda *_args: None)

    assert kb._process_group_alive(42430) is True


def test_non_linux_process_group_probe_error_fails_closed(monkeypatch):
    """Only explicit ESRCH proves absence on non-Linux POSIX hosts."""
    if os.name == "nt":
        pytest.skip("process groups are POSIX-specific")

    monkeypatch.setattr(kb.sys, "platform", "darwin")
    monkeypatch.setattr(
        kb.os,
        "killpg",
        lambda *_args: (_ for _ in ()).throw(OSError("indeterminate")),
    )

    assert kb._process_group_alive(42431) is True


def test_stopping_worker_is_terminated_by_supervisor_before_finalization(
    kanban_home, monkeypatch,
):
    """A persisted timeout intent makes the next supervisor tick kill the group."""
    pid = 42425
    terminations = []
    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: True)
    monkeypatch.setattr(
        kb,
        "_terminate_reclaimed_worker",
        lambda *args, **kwargs: terminations.append((args, kwargs))
        or _termination(terminated=True),
    )

    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="supervisor stop", assignee="coder")
        claimed = kb.claim_task(conn, task_id, claimer=_local_lock())
        assert claimed is not None
        run_id = claimed.current_run_id
        assert run_id is not None
        kb._set_worker_pid(conn, task_id, pid)
        assert kb.request_worker_stop(
            conn,
            task_id,
            expected_run_id=run_id,
            outcome="timed_out",
            error="iteration budget exhausted",
        )

        assert kb.detect_crashed_workers(conn) == []
        assert len(terminations) == 1
        task = kb.get_task(conn, task_id)
        assert task.status == "ready"
        assert task.current_run_id is None
        assert task.worker_pid is None
        run = kb.get_run(conn, run_id)
        assert run is not None
        assert run.status == "timed_out"
        assert run.outcome == "timed_out"


def test_spawn_pid_registration_error_terminates_new_group_before_release(
    kanban_home, monkeypatch, all_assignees_spawnable,
):
    """A post-Popen DB error cannot leave an untracked worker alive."""
    pid = 42426
    terminations = []

    def broken_registration(*_args, **_kwargs):
        raise RuntimeError("registration unavailable")

    monkeypatch.setattr(kb, "_set_worker_pid", broken_registration)
    monkeypatch.setattr(kb, "_default_spawn", lambda *_args, **_kwargs: pid)
    monkeypatch.setattr(
        kb,
        "_terminate_cancel_worker_group",
        lambda spawned_pid: terminations.append(int(spawned_pid)) or "stopped",
    )

    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="spawn registration", assignee="coder")
        result = kb.dispatch_once(conn, max_spawn=1, board="default")

        assert result.spawned == []
        assert terminations == [pid]
        task = kb.get_task(conn, task_id)
        assert task.status == "ready"
        assert task.current_run_id is None
        assert task.worker_pid is None


def test_old_failure_accounting_cannot_block_a_replacement_run(kanban_home):
    """Failure accounting after reclaim must not terminalize a newer owner."""
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="failure race", assignee="coder")
        old = kb.claim_task(conn, task_id, claimer=_local_lock("old"))
        assert old is not None
        old_run_id = old.current_run_id
        assert old_run_id is not None
        kb._set_worker_pid(conn, task_id, 42427)
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET status = 'ready', claim_lock = NULL, "
                "claim_expires = NULL, worker_pid = NULL WHERE id = ?",
                (task_id,),
            )
            kb._end_run(
                conn,
                task_id,
                outcome="crashed",
                status="crashed",
            )

        replacement = kb.claim_task(
            conn,
            task_id,
            claimer=_local_lock("replacement"),
        )
        assert replacement is not None
        replacement_run_id = replacement.current_run_id
        kb._set_worker_pid(conn, task_id, 42428)

        assert kb._record_task_failure(
            conn,
            task_id,
            error="old worker crashed",
            outcome="crashed",
            failure_limit=1,
            release_claim=False,
            end_run=False,
            event_payload_extra={"run_id": old_run_id},
        ) is False

        current = kb.get_task(conn, task_id)
        assert current.status == "running"
        assert current.current_run_id == replacement_run_id
        assert current.worker_pid == 42428


def test_max_runtime_defers_requeue_when_process_group_survives(
    kanban_home, monkeypatch,
):
    """A failed SIGTERM/SIGKILL verification must keep the old claim fenced."""
    now = 2_000_000
    monkeypatch.setattr(kb.time, "time", lambda: now)
    monkeypatch.setattr(kb.os, "kill", lambda *_args: None)
    monkeypatch.setattr(kb, "_pid_alive", lambda _pid: True)
    monkeypatch.setattr(
        kb,
        "_terminate_reclaimed_worker",
        lambda *_args, **_kwargs: _termination(terminated=False),
    )

    with kb.connect() as conn:
        task_id = kb.create_task(
            conn,
            title="runtime fence",
            assignee="coder",
            max_runtime_seconds=10,
        )
        claimed = kb.claim_task(conn, task_id, claimer=_local_lock())
        assert claimed is not None
        kb._set_worker_pid(conn, task_id, 42420)
        conn.execute(
            "UPDATE task_runs SET started_at = ? WHERE id = ?",
            (now - 60, claimed.current_run_id),
        )
        conn.commit()

        assert kb.enforce_max_runtime(conn) == []
        task = kb.get_task(conn, task_id)
        assert task.status == "running"
        assert task.current_run_id == claimed.current_run_id
        assert task.worker_pid == 42420
        assert kb.claim_task(conn, task_id, claimer=_local_lock("replacement")) is None

        events = kb.list_events(conn, task_id)
        assert any(event.kind == "reclaim_deferred" for event in events)
