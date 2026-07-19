from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tarfile
from argparse import Namespace
from io import StringIO
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban as kanban_cli
from hermes_cli import kanban_purge as purge


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb._INITIALIZED_PATHS.clear()
    kb.init_db()
    return home


def _archived_task(conn: sqlite3.Connection, **kwargs) -> str:
    task_id = kb.create_task(
        conn, title="sensitive title", body="sensitive body", **kwargs
    )
    assert kb.archive_task(conn, task_id)
    return task_id


def test_preview_is_content_free_non_destructive_and_hashes_token(kanban_home):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        kb.add_comment(conn, task_id, "operator", "sensitive comment")

        result = purge.preview_purge(conn, task_id, actor="coder")

        assert result.status == purge.PurgeStatus.PREVIEWED
        assert result.confirmation_token
        assert kb.get_task(conn, task_id) is not None
        row = conn.execute(
            "SELECT * FROM kanban_purge_operations WHERE id = ?", (result.operation_id,)
        ).fetchone()
        assert row["token_hash"] == purge.hash_confirmation_token(
            result.confirmation_token
        )
        persisted = json.dumps(dict(row), sort_keys=True)
        for secret in (
            "sensitive title",
            "sensitive body",
            "sensitive comment",
            result.confirmation_token,
        ):
            assert secret not in persisted
        assert all(
            isinstance(value, int) for value in json.loads(row["counts_json"]).values()
        )


def test_actor_is_a_bounded_profile_identifier(kanban_home):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        with pytest.raises(purge.PurgeValidationError, match="actor"):
            purge.preview_purge(conn, task_id, actor="arbitrary audit text")


def test_confirmation_is_bound_to_the_board_database(kanban_home, tmp_path):
    from hermes_cli.backup import safe_copy_sqlite_db

    with kb.connect() as conn:
        task_id = _archived_task(conn)
        preview = purge.preview_purge(conn, task_id, actor="tester")
        copied = tmp_path / "copied-board.sqlite3"
        source = Path(conn.execute("PRAGMA database_list").fetchone()[2])
        assert safe_copy_sqlite_db(source, copied)

    copied_conn = sqlite3.connect(copied)
    copied_conn.row_factory = sqlite3.Row
    try:
        with pytest.raises(purge.PurgeConfirmationError, match="identity"):
            purge.confirm_purge(
                copied_conn,
                task_id,
                operation_id=preview.operation_id,
                confirmation_token=preview.confirmation_token,
                actor="tester",
            )
    finally:
        copied_conn.close()


@pytest.mark.parametrize(
    "status",
    ["triage", "todo", "ready", "running", "blocked", "done", "scheduled", "review"],
)
def test_preview_rejects_every_non_archived_status(kanban_home, status):
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="live")
        conn.execute("UPDATE tasks SET status = ? WHERE id = ?", (status, task_id))
        conn.commit()
        with pytest.raises(purge.PurgeValidationError, match="archived"):
            purge.preview_purge(conn, task_id, actor="coder")
        assert kb.get_task(conn, task_id) is not None


def test_confirm_removes_registered_rows_and_owned_files_after_verified_backup(
    kanban_home,
):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        kb.add_comment(conn, task_id, "operator", "delete me")
        attachment_dir = kb.task_attachments_dir(task_id)
        attachment_dir.mkdir(parents=True)
        blob = attachment_dir / "payload.txt"
        blob.write_text("secret bytes", encoding="utf-8")
        conn.execute(
            "INSERT INTO task_attachments(task_id, filename, stored_path, size, created_at) "
            "VALUES (?, ?, ?, ?, 1)",
            (task_id, "payload.txt", str(blob), blob.stat().st_size),
        )
        logs = kb.worker_logs_dir()
        logs.mkdir(parents=True, exist_ok=True)
        current_log = logs / f"{task_id}.log"
        rotated_log = logs / f"{task_id}.log.2"
        current_log.write_text("current", encoding="utf-8")
        rotated_log.write_text("rotated", encoding="utf-8")
        conn.commit()

        preview = purge.preview_purge(conn, task_id, actor="coder")
        result = purge.confirm_purge(
            conn,
            task_id,
            operation_id=preview.operation_id,
            confirmation_token=preview.confirmation_token,
            actor="coder",
        )

        assert result.status == purge.PurgeStatus.COMPLETE
        assert kb.get_task(conn, task_id) is None
        for table in (
            "task_comments",
            "task_events",
            "task_runs",
            "task_attachments",
            "kanban_notify_subs",
        ):
            assert (
                conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE task_id = ?", (task_id,)
                ).fetchone()[0]
                == 0
            )
        assert not attachment_dir.exists()
        assert not current_log.exists()
        assert not rotated_log.exists()
        assert not (
            attachment_dir.parent / ".purge-staging" / preview.operation_id
        ).exists()
        assert not (
            current_log.parent / ".purge-staging" / preview.operation_id
        ).exists()
        backup = Path(result.backup_path)
        assert backup.is_dir()
        assert (backup / "board.sqlite3").is_file()
        assert (backup / "manifest.json").is_file()
        assert (backup / "files.tar.gz").is_file()
        assert (backup / "CHECKSUMS.sha256").is_file()
        assert (backup / "README.restore.txt").is_file()
        if os.name != "nt":
            assert backup.stat().st_mode & 0o777 == 0o700
            assert all(
                path.stat().st_mode & 0o777 == 0o600
                for path in backup.iterdir()
                if path.is_file()
            )


def test_confirmation_is_single_use_and_fails_closed_on_drift(kanban_home):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        preview = purge.preview_purge(conn, task_id, actor="coder")
        conn.execute(
            "INSERT INTO task_comments(task_id, author, body, created_at) VALUES (?, 'x', 'drift', 1)",
            (task_id,),
        )
        conn.commit()

        with pytest.raises(purge.PurgeConfirmationError, match="drift"):
            purge.confirm_purge(
                conn,
                task_id,
                operation_id=preview.operation_id,
                confirmation_token=preview.confirmation_token,
                actor="coder",
            )
        with pytest.raises(purge.PurgeConfirmationError):
            purge.confirm_purge(
                conn,
                task_id,
                operation_id=preview.operation_id,
                confirmation_token=preview.confirmation_token,
                actor="coder",
            )
        assert kb.get_task(conn, task_id) is not None


def test_file_drift_after_backup_is_not_deleted(kanban_home, monkeypatch):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        attachment_dir = kb.task_attachments_dir(task_id)
        attachment_dir.mkdir(parents=True)
        payload = attachment_dir / "payload.txt"
        payload.write_text("previewed", encoding="utf-8")
        preview = purge.preview_purge(conn, task_id, actor="tester")
        original_backup = purge.create_verified_backup

        def backup_then_drift(conn_arg, operation_id, manifest):
            result = original_backup(conn_arg, operation_id, manifest)
            payload.write_text("changed after backup", encoding="utf-8")
            return result

        monkeypatch.setattr(purge, "create_verified_backup", backup_then_drift)
        with pytest.raises(purge.PurgeConfirmationError, match="drift"):
            purge.confirm_purge(
                conn,
                task_id,
                operation_id=preview.operation_id,
                confirmation_token=preview.confirmation_token,
                actor="tester",
            )
        assert kb.get_task(conn, task_id) is not None
        assert payload.read_text(encoding="utf-8") == "changed after backup"
        operation = conn.execute(
            "SELECT backup_id, backup_sha256 FROM kanban_purge_operations WHERE id = ?",
            (preview.operation_id,),
        ).fetchone()
        assert operation["backup_id"] == preview.operation_id
        assert operation["backup_sha256"]


def test_incomplete_staging_compensation_is_high_risk(kanban_home, monkeypatch):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        preview = purge.preview_purge(conn, task_id, actor="tester")
        monkeypatch.setattr(
            purge,
            "_stage",
            lambda *_args: (_ for _ in ()).throw(
                purge.PurgeRollbackError("injected rollback failure")
            ),
        )

        with pytest.raises(purge.PurgeRollbackError, match="injected"):
            purge.confirm_purge(
                conn,
                task_id,
                operation_id=preview.operation_id,
                confirmation_token=preview.confirmation_token,
                actor="tester",
            )
        operation = conn.execute(
            "SELECT status FROM kanban_purge_operations WHERE id = ?",
            (preview.operation_id,),
        ).fetchone()
        assert operation["status"] == purge.PurgeStatus.ROLLBACK_FAILED.value


def test_preview_rejects_attachment_metadata_outside_canonical_root(
    kanban_home, tmp_path
):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        external = tmp_path / "external.txt"
        external.write_text("must survive", encoding="utf-8")
        conn.execute(
            "INSERT INTO task_attachments(task_id, filename, stored_path, size, created_at) "
            "VALUES (?, 'external.txt', ?, 1, 1)",
            (task_id, str(external)),
        )
        conn.commit()

        with pytest.raises(purge.PurgeValidationError, match="attachment"):
            purge.preview_purge(conn, task_id, actor="coder")
        assert external.read_text(encoding="utf-8") == "must survive"


@pytest.mark.skipif(os.name == "nt", reason="symlink creation requires privileges")
def test_symlinked_staging_root_is_refused(kanban_home, tmp_path):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        attachment_dir = kb.task_attachments_dir(task_id)
        attachment_dir.mkdir(parents=True)
        payload = attachment_dir / "payload.txt"
        payload.write_text("must survive", encoding="utf-8")
        preview = purge.preview_purge(conn, task_id, actor="tester")
        external = tmp_path / "external-staging"
        external.mkdir()
        (attachment_dir.parent / ".purge-staging").symlink_to(
            external, target_is_directory=True
        )

        with pytest.raises(purge.PurgeValidationError, match="staging"):
            purge.confirm_purge(
                conn,
                task_id,
                operation_id=preview.operation_id,
                confirmation_token=preview.confirmation_token,
                actor="tester",
            )
        assert kb.get_task(conn, task_id) is not None
        assert payload.read_text(encoding="utf-8") == "must survive"
        assert list(external.iterdir()) == []


def test_restore_reports_missing_source_and_staging_artifact(tmp_path):
    source = tmp_path / "source"
    staged = tmp_path / ".purge-staging" / "op" / "source"

    assert purge._restore_staged([(source, staged)]) is False


def test_task_scoped_schema_registry_covers_all_task_id_tables(kanban_home):
    with kb.connect() as conn:
        task_scoped = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
            if "task_id"
            in {column[1] for column in conn.execute(f'PRAGMA table_info("{row[0]}")')}
        }
    assert task_scoped <= purge.PURGE_TASK_ID_TABLES | purge.RETAINED_TASK_ID_TABLES


def test_preview_fails_closed_on_unknown_task_scoped_table(kanban_home):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        conn.execute("CREATE TABLE extension_records (task_id TEXT, payload TEXT)")
        conn.execute(
            "INSERT INTO extension_records VALUES (?, 'must survive')", (task_id,)
        )
        conn.commit()

        with pytest.raises(purge.PurgeValidationError, match="schema drift"):
            purge.preview_purge(conn, task_id, actor="tester")
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM extension_records WHERE task_id = ?", (task_id,)
            ).fetchone()[0]
            == 1
        )


def test_optional_plan_and_checkpoint_tables_are_purged_when_present(kanban_home):
    with kb.connect() as conn:
        conn.execute("CREATE TABLE task_plans (task_id TEXT, plan TEXT)")
        conn.execute(
            "CREATE TABLE task_checkpoints (task_id TEXT, seq INTEGER, git_ref TEXT, commit_sha TEXT)"
        )
        task_id = _archived_task(conn)
        conn.execute("INSERT INTO task_plans VALUES (?, 'secret plan')", (task_id,))
        conn.execute(
            "INSERT INTO task_checkpoints VALUES (?, 1, NULL, NULL)", (task_id,)
        )
        conn.commit()
        preview = purge.preview_purge(conn, task_id, actor="coder")
        result = purge.confirm_purge(
            conn,
            task_id,
            operation_id=preview.operation_id,
            confirmation_token=preview.confirmation_token,
            actor="coder",
        )
        assert result.status == purge.PurgeStatus.COMPLETE
        assert conn.execute("SELECT COUNT(*) FROM task_plans").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM task_checkpoints").fetchone()[0] == 0


def test_post_commit_cleanup_failure_is_resumable_and_idempotent(
    kanban_home, monkeypatch
):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        attachment_dir = kb.task_attachments_dir(task_id)
        attachment_dir.mkdir(parents=True)
        (attachment_dir / "x").write_text("x", encoding="utf-8")
        preview = purge.preview_purge(conn, task_id, actor="coder")
        original_cleanup = purge._cleanup_staged
        monkeypatch.setattr(
            purge,
            "_cleanup_staged",
            lambda entries: (_ for _ in ()).throw(OSError("injected")),
        )
        with pytest.raises(purge.PurgeCleanupPendingError) as raised:
            purge.confirm_purge(
                conn,
                task_id,
                operation_id=preview.operation_id,
                confirmation_token=preview.confirmation_token,
                actor="coder",
            )
        assert raised.value.result.exit_code == 3
        assert kb.get_task(conn, task_id) is None
        monkeypatch.setattr(purge, "_cleanup_staged", original_cleanup)
        resumed = purge.resume_purge(conn, preview.operation_id)
        assert resumed.status == purge.PurgeStatus.COMPLETE
        assert (
            purge.resume_purge(conn, preview.operation_id).status
            == purge.PurgeStatus.COMPLETE
        )


def test_resume_rejects_tampered_backup_manifest(kanban_home, monkeypatch):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        attachment_dir = kb.task_attachments_dir(task_id)
        attachment_dir.mkdir(parents=True)
        (attachment_dir / "x").write_text("old", encoding="utf-8")
        preview = purge.preview_purge(conn, task_id, actor="coder")
        monkeypatch.setattr(
            purge,
            "_cleanup_staged",
            lambda entries: (_ for _ in ()).throw(OSError("injected")),
        )
        with pytest.raises(purge.PurgeCleanupPendingError) as raised:
            purge.confirm_purge(
                conn,
                task_id,
                operation_id=preview.operation_id,
                confirmation_token=preview.confirmation_token,
                actor="coder",
            )
        backup = Path(raised.value.result.backup_path)
        (backup / "manifest.json").write_text("{}", encoding="utf-8")

        with pytest.raises(purge.PurgeValidationError, match="checksum"):
            purge.resume_purge(conn, preview.operation_id)


def test_resume_rejects_task_id_aba_without_overwriting_new_log(
    kanban_home, monkeypatch
):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        original = conn.execute(
            "SELECT * FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        log_path = kb.worker_log_path(task_id)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("old staged log", encoding="utf-8")
        preview = purge.preview_purge(conn, task_id, actor="coder")
        monkeypatch.setattr(
            purge,
            "_cleanup_staged",
            lambda entries: (_ for _ in ()).throw(OSError("injected")),
        )
        with pytest.raises(purge.PurgeCleanupPendingError):
            purge.confirm_purge(
                conn,
                task_id,
                operation_id=preview.operation_id,
                confirmation_token=preview.confirmation_token,
                actor="coder",
            )
        columns = list(original.keys())
        values = [original[column] for column in columns]
        values[columns.index("created_at")] += 1
        values[columns.index("title")] = "replacement task"
        conn.execute(
            f"INSERT INTO tasks ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            values,
        )
        conn.commit()
        log_path.write_text("new task log", encoding="utf-8")

        with pytest.raises(purge.PurgeRollbackError, match="task existence conflicts"):
            purge.resume_purge(conn, preview.operation_id)
        assert log_path.read_text(encoding="utf-8") == "new task log"


def test_resume_precommit_failure_without_backup_rolls_back_cleanly(kanban_home):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
        preview = purge.preview_purge(conn, task_id, actor="tester")
        conn.execute(
            "UPDATE kanban_purge_operations SET status = 'precommit_failed', "
            "token_hash = NULL, backup_id = NULL WHERE id = ?",
            (preview.operation_id,),
        )
        conn.commit()

        result = purge.resume_purge(conn, preview.operation_id)

        assert result.status is purge.PurgeStatus.ROLLED_BACK
        assert kb.get_task(conn, task_id) is not None


def test_cli_preview_then_stdin_confirmation_and_archive_rm_alias(
    kanban_home, monkeypatch, capsys
):
    with kb.connect() as conn:
        task_id = _archived_task(conn)
    preview_args = Namespace(
        task_id=task_id,
        confirm=False,
        confirm_stdin=False,
        resume=None,
        json=True,
    )
    assert kanban_cli._cmd_purge(preview_args) == 0
    preview_json = json.loads(capsys.readouterr().out)
    assert preview_json["status"] == "previewed"
    assert preview_json["confirmation_token"]
    monkeypatch.setattr(
        sys, "stdin", StringIO(preview_json["confirmation_token"] + "\n")
    )
    confirm_args = Namespace(
        task_id=task_id,
        confirm=False,
        confirm_stdin=True,
        resume=None,
        json=True,
    )
    assert kanban_cli._cmd_purge(confirm_args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "complete"

    with kb.connect() as conn:
        alias_task = _archived_task(conn)
    alias_args = Namespace(task_ids=[], purge_ids=[alias_task])
    assert kanban_cli._cmd_archive(alias_args) == 0
    assert "preview" in capsys.readouterr().err
    with kb.connect() as conn:
        assert kb.get_task(conn, alias_task) is not None


def test_verified_linked_worktree_and_checkpoint_ref_are_backed_up_and_removed(
    kanban_home, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main", str(repo)], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True
    )
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "tracked.txt").write_text("tracked", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "initial"],
        check=True,
        capture_output=True,
    )
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="worktree", workspace_kind="worktree")
        worktree = repo / ".worktrees" / task_id
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "worktree",
                "add",
                "-b",
                f"wt/{task_id}",
                str(worktree),
            ],
            check=True,
            capture_output=True,
        )
        (worktree / "worktree-only.txt").write_text("branch-only", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(worktree), "add", "worktree-only.txt"], check=True
        )
        subprocess.run(
            ["git", "-C", str(worktree), "commit", "-m", "worktree commit"],
            check=True,
            capture_output=True,
        )
        (worktree / "untracked.txt").write_text("untracked secret", encoding="utf-8")
        commit = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        ref = f"refs/hermes/ckpt/{task_id}/1"
        subprocess.run(["git", "-C", str(repo), "update-ref", ref, commit], check=True)
        conn.execute(
            "UPDATE tasks SET workspace_path = ? WHERE id = ?", (str(worktree), task_id)
        )
        conn.execute(
            "CREATE TABLE task_checkpoints (task_id TEXT, seq INTEGER, git_ref TEXT, "
            "commit_sha TEXT, workspace_path TEXT)"
        )
        conn.execute(
            "INSERT INTO task_checkpoints VALUES (?, 1, ?, ?, ?)",
            (task_id, ref, commit, str(worktree)),
        )
        conn.commit()
        assert kb.archive_task(conn, task_id)
        preview = purge.preview_purge(conn, task_id, actor="coder")
        result = purge.confirm_purge(
            conn,
            task_id,
            operation_id=preview.operation_id,
            confirmation_token=preview.confirmation_token,
            actor="coder",
        )
    assert result.status == purge.PurgeStatus.COMPLETE
    assert not worktree.exists()
    assert (
        subprocess.run(
            ["git", "-C", str(repo), "show-ref", "--verify", ref],
            capture_output=True,
        ).returncode
        != 0
    )
    assert (
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "show-ref",
                "--verify",
                f"refs/heads/wt/{task_id}",
            ],
            capture_output=True,
        ).returncode
        == 0
    )
    backup = Path(result.backup_path)
    bundles = list(backup.glob("repo-*.bundle"))
    assert len(bundles) == 1
    heads = subprocess.run(
        ["git", "-C", str(repo), "bundle", "list-heads", str(bundles[0])],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert commit in heads
    assert not subprocess.run(
        ["git", "-C", str(repo), "for-each-ref", "refs/hermes/purge-backup"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    with tarfile.open(backup / "files.tar.gz", "r:gz") as archive:
        assert archive.extractfile("files/0").read() == b"untracked secret"


def test_dirty_tracked_worktree_is_refused(kanban_home, tmp_path):
    repo = tmp_path / "repo-dirty"
    repo.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main", str(repo)], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    tracked = repo / "tracked.txt"
    tracked.write_text("committed", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "initial"],
        check=True,
        capture_output=True,
    )
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="dirty", workspace_kind="worktree")
        worktree = repo / ".worktrees" / task_id
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "worktree",
                "add",
                "-b",
                f"wt/{task_id}",
                str(worktree),
            ],
            check=True,
            capture_output=True,
        )
        (worktree / "tracked.txt").write_text("uncommitted", encoding="utf-8")
        conn.execute(
            "UPDATE tasks SET workspace_path = ? WHERE id = ?", (str(worktree), task_id)
        )
        conn.commit()
        assert kb.archive_task(conn, task_id)

        with pytest.raises(purge.PurgeValidationError, match="tracked"):
            purge.preview_purge(conn, task_id, actor="tester")
