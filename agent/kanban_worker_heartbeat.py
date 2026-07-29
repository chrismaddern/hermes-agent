"""Process-side heartbeat keepalive for dispatcher-spawned workers.

The agent's normal activity bridge only runs when model chunks or tools make
foreground progress. A provider request can remain silent longer than the
kanban stale-heartbeat threshold, so workers also need a liveness signal from
a thread that is independent of the model turn.
"""

from __future__ import annotations

import contextlib
import logging
import os
import threading
from collections.abc import Callable, Iterator
from typing import Optional

logger = logging.getLogger(__name__)

WORKER_HEARTBEAT_INTERVAL_SECONDS = 5 * 60.0


def _terminate_stale_worker(reason: str) -> None:
    """Send an immediate terminal signal to this worker's process group."""
    import signal

    pid = os.getpid()
    logger.error("terminating stale kanban worker pid=%s: %s", pid, reason)
    sigkill = getattr(signal, "SIGKILL", signal.SIGTERM)
    try:
        if os.name != "nt" and os.getpgrp() == pid and hasattr(os, "killpg"):
            os.killpg(pid, sigkill)  # windows-footgun: ok - POSIX branch
        else:
            os.kill(pid, sigkill)
    except (ProcessLookupError, OSError):
        logger.error("failed to signal stale kanban worker pid=%s", pid, exc_info=True)


def enforce_current_run_ownership(
    tool_name: Optional[str] = None,
    *,
    terminate_fn: Optional[Callable[[str], None]] = None,
) -> Optional[str]:
    """Fence a tool call when this process no longer owns the active run.

    Returns ``None`` for a current/non-kanban process.  A stale worker receives
    an immediate terminal signal before any tool dispatch; tests may inject a
    non-terminal callback and inspect the returned reason.  Database errors
    fail closed for the tool call without killing a potentially-current worker.
    """
    task_id = (os.environ.get("HERMES_KANBAN_TASK") or "").strip()
    run_id_raw = (os.environ.get("HERMES_KANBAN_RUN_ID") or "").strip()
    claim_lock = (os.environ.get("HERMES_KANBAN_CLAIM_LOCK") or "").strip()
    if not task_id and not run_id_raw and not claim_lock:
        return None
    if not task_id or not run_id_raw or not claim_lock:
        return "kanban worker identity is incomplete; tool dispatch fenced"
    try:
        expected_run_id = int(run_id_raw)
    except ValueError:
        return "kanban worker run id is invalid; tool dispatch fenced"

    from hermes_cli import kanban_db as kb

    try:
        with kb.connect_closing() as conn:
            row = conn.execute(
                "SELECT t.status, t.current_run_id, t.claim_lock AS current_claim_lock, "
                "       current.status AS run_status, "
                "       expected.worker_pid AS expected_worker_pid, "
                "       expected.claim_lock AS expected_claim_lock "
                "FROM tasks t "
                "LEFT JOIN task_runs current ON current.id = t.current_run_id "
                "LEFT JOIN task_runs expected ON expected.id = ? "
                "WHERE t.id = ?",
                (expected_run_id, task_id),
            ).fetchone()
    except Exception as exc:
        logger.warning("unable to verify kanban run ownership", exc_info=True)
        return f"kanban run ownership could not be verified: {type(exc).__name__}"

    # Nested subprocesses inherit the worker environment. Only the direct
    # dispatcher worker whose persisted run PID matches this process may
    # self-terminate; stale descendants are still fenced from tools and are
    # normally killed with the persisted process group by the supervisor.
    if row is None:
        return "kanban run ownership record is missing; tool dispatch fenced"
    if row["expected_worker_pid"] is None:
        return "kanban worker PID is not persisted yet; tool dispatch fenced"
    direct_worker = int(row["expected_worker_pid"]) == os.getpid()

    current_run_id = row["current_run_id"]
    current = (
        row is not None
        and row["status"] == "running"
        and current_run_id == expected_run_id
        and row["run_status"] == "running"
        and row["current_claim_lock"] == claim_lock
        and row["expected_claim_lock"] == claim_lock
    )
    if current:
        return None

    reason = (
        f"stale kanban run fenced: task={task_id} expected_run={expected_run_id} "
        f"current_run={current_run_id if row is not None else None} "
        f"task_status={row['status'] if row is not None else 'missing'} "
        f"run_status={row['run_status'] if row is not None else 'missing'} "
        f"tool={tool_name or 'unknown'}"
    )
    if direct_worker:
        (terminate_fn or _terminate_stale_worker)(reason)
    return reason


def _heartbeat_current_run() -> bool:
    """Refresh the current run and return whether this process still owns it.

    The dispatcher injects all three identity values. Requiring the run id and
    claim lock prevents a delayed thread from touching a task that has already
    been reclaimed and assigned to another worker.
    """
    task_id = (os.environ.get("HERMES_KANBAN_TASK") or "").strip()
    run_id_raw = (os.environ.get("HERMES_KANBAN_RUN_ID") or "").strip()
    claim_lock = (os.environ.get("HERMES_KANBAN_CLAIM_LOCK") or "").strip()
    if not task_id or not run_id_raw or not claim_lock:
        return False
    try:
        run_id = int(run_id_raw)
    except ValueError:
        return False

    from hermes_cli import kanban_db as kb

    with kb.connect_closing() as conn:
        if not kb.heartbeat_worker(
            conn,
            task_id,
            expected_run_id=run_id,
            expected_claim_lock=claim_lock,
            expected_worker_pid=os.getpid(),
        ):
            return False
        return kb.heartbeat_claim(
            conn,
            task_id,
            claimer=claim_lock,
            expected_run_id=run_id,
            expected_worker_pid=os.getpid(),
        )


class KanbanWorkerHeartbeat:
    """Run a heartbeat callback periodically on a daemon thread."""

    def __init__(
        self,
        heartbeat_fn: Callable[[], bool],
        *,
        interval_seconds: float = WORKER_HEARTBEAT_INTERVAL_SECONDS,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self._heartbeat_fn = heartbeat_fn
        self._interval_seconds = float(interval_seconds)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="hermes-kanban-worker-heartbeat",
            daemon=True,
        )

    @property
    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                still_active = self._heartbeat_fn()
            except Exception:
                # A transient DB lock or filesystem error must not kill either
                # the worker or its keepalive. The next interval retries.
                logger.debug("kanban worker heartbeat failed", exc_info=True)
            else:
                if not still_active:
                    self._stop_event.set()
                    return
            if self._stop_event.wait(self._interval_seconds):
                return


@contextlib.contextmanager
def worker_heartbeat_keepalive(
    *,
    interval_seconds: Optional[float] = None,
    heartbeat_fn: Optional[Callable[[], bool]] = None,
) -> Iterator[Optional[KanbanWorkerHeartbeat]]:
    """Keep a dispatched worker alive for the duration of the process scope.

    Outside a fully identified dispatcher worker this is a no-op. Tests may
    inject ``heartbeat_fn`` to exercise lifecycle behavior without board state.
    """
    if heartbeat_fn is None:
        required = (
            os.environ.get("HERMES_KANBAN_TASK"),
            os.environ.get("HERMES_KANBAN_RUN_ID"),
            os.environ.get("HERMES_KANBAN_CLAIM_LOCK"),
        )
        if not all(value and value.strip() for value in required):
            yield None
            return
        heartbeat_fn = _heartbeat_current_run

    keepalive = KanbanWorkerHeartbeat(
        heartbeat_fn,
        interval_seconds=(
            WORKER_HEARTBEAT_INTERVAL_SECONDS
            if interval_seconds is None
            else interval_seconds
        ),
    )
    keepalive.start()
    try:
        yield keepalive
    finally:
        keepalive.stop()
