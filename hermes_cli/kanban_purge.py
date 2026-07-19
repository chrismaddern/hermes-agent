"""Previewed, backed-up, audited hard purge for archived Kanban tasks.

SQLite, files, and Git do not share a transaction.  This module therefore uses
an explicit protocol: inventory and one-time confirmation, mandatory verified
backup, reversible external staging, one short database commit, then idempotent
cleanup.  Durable operation rows intentionally contain counts only; the full
sensitive manifest lives in the owner-only purge backup.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Optional

from hermes_cli import kanban_db as kb
from hermes_cli.backup import safe_copy_sqlite_db

PURGE_TASK_ID_TABLES = {
    "task_comments",
    "task_events",
    "task_runs",
    "kanban_notify_subs",
    "task_attachments",
    "task_plans",
    "task_checkpoints",
}
RETAINED_TASK_ID_TABLES = {"kanban_purge_operations"}
_DB_TABLES = (
    "tasks",
    "task_links",
    "task_comments",
    "task_events",
    "task_runs",
    "kanban_notify_subs",
    "task_attachments",
    "task_plans",
    "task_checkpoints",
)
TOKEN_TTL_SECONDS = 600
_ROTATED_LOG_RE = re.compile(
    r"^(?P<task>t_[A-Za-z0-9_-]+)\.log(?:\.(?P<generation>[1-9][0-9]*))?$"
)
_ACTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class PurgeStatus(str, Enum):
    PREVIEWED = "previewed"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"
    BACKING_UP = "backing_up"
    STAGED = "staged"
    DB_COMMITTED = "db_committed"
    CLEANUP_PENDING = "cleanup_pending"
    COMPLETE = "complete"
    PRECOMMIT_FAILED = "precommit_failed"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


class PurgeValidationError(ValueError):
    """The task or one of its resource ownership claims is unsafe."""


class PurgeConfirmationError(ValueError):
    """The one-time confirmation is invalid, expired, replayed, or stale."""


class PurgeCleanupPendingError(RuntimeError):
    def __init__(self, result: "PurgeResult") -> None:
        super().__init__("database purge committed; external cleanup pending")
        self.result = result


class PurgeRollbackError(RuntimeError):
    pass


@dataclass(frozen=True)
class PurgeManifest:
    schema_version: int
    task_id: str
    db_rows: Mapping[str, list[dict[str, Any]]]
    files: tuple[dict[str, Any], ...]
    owned_roots: tuple[dict[str, str], ...]
    excluded_dir_workspace: bool

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "schema_version": self.schema_version,
                "task_id": self.task_id,
                "db_rows": self.db_rows,
                "files": self.files,
                "owned_roots": self.owned_roots,
                "excluded_dir_workspace": self.excluded_dir_workspace,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @property
    def db_digest(self) -> str:
        raw = json.dumps(
            self.db_rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def safe_counts(self) -> dict[str, int]:
        counts = {f"rows_{table}": len(rows) for table, rows in self.db_rows.items()}
        counts["owned_files"] = len(self.files)
        counts["owned_bytes"] = sum(int(item["size"]) for item in self.files)
        counts["owned_roots"] = len(self.owned_roots)
        counts["external_dir_workspaces_excluded"] = int(self.excluded_dir_workspace)
        return counts


@dataclass(frozen=True)
class PurgePreview:
    operation_id: str
    task_id: str
    status: PurgeStatus
    expires_at: int
    confirmation_token: str
    counts: Mapping[str, int]


@dataclass(frozen=True)
class PurgeResult:
    operation_id: str
    task_id: str
    status: PurgeStatus
    backup_path: Optional[str]
    exit_code: int = 0


def hash_confirmation_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _db_path(conn: sqlite3.Connection) -> Path:
    for row in conn.execute("PRAGMA database_list"):
        if row[1] == "main" and row[2]:
            return Path(row[2]).resolve()
    raise PurgeValidationError("board database has no stable filesystem identity")


def _board_identity(conn: sqlite3.Connection) -> str:
    return hashlib.sha256(str(_db_path(conn)).encode("utf-8")).hexdigest()


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        is not None
    )


def _assert_schema_registry_complete(conn: sqlite3.Connection) -> None:
    registered = PURGE_TASK_ID_TABLES | RETAINED_TASK_ID_TABLES | {"task_links"}
    for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ):
        table = str(row[0])
        quoted = table.replace('"', '""')
        columns = {
            column[1] for column in conn.execute(f'PRAGMA table_info("{quoted}")')
        }
        if "task_id" in columns and table not in registered:
            raise PurgeValidationError(
                f"schema drift: unregistered task-scoped table {table!r}"
            )


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value)}
    return value


def _rows_for_task(
    conn: sqlite3.Connection, table: str, task_id: str
) -> list[dict[str, Any]]:
    if not _table_exists(conn, table):
        return []
    if table == "tasks":
        rows = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchall()
    elif table == "task_links":
        rows = conn.execute(
            "SELECT * FROM task_links WHERE parent_id = ? OR child_id = ? ORDER BY parent_id, child_id",
            (task_id, task_id),
        ).fetchall()
    else:
        rows = conn.execute(
            f'SELECT * FROM "{table}" WHERE task_id = ?', (task_id,)
        ).fetchall()
    return [{key: _json_value(row[key]) for key in sorted(row.keys())} for row in rows]


def _assert_regular_owned_file(path: Path, root: Path, label: str) -> Path:
    try:
        resolved_root = root.resolve(strict=False)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise PurgeValidationError(
            f"unsafe {label}: cannot resolve owned path"
        ) from exc
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise PurgeValidationError(
            f"unsafe {label}: path is outside canonical root"
        ) from exc
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise PurgeValidationError(f"unsafe {label}: cannot inspect path") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise PurgeValidationError(
            f"unsafe {label}: symlinks and non-regular files are refused"
        )
    return resolved


def _file_record(path: Path, kind: str, root: Path) -> dict[str, Any]:
    resolved = _assert_regular_owned_file(path, root, kind)
    digest = hashlib.sha256()
    size = 0
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {
        "path": str(resolved),
        "kind": kind,
        "size": size,
        "sha256": digest.hexdigest(),
    }


def _walk_owned_files(root: Path, kind: str) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise PurgeValidationError(f"unsafe {kind}: owned root is not a real directory")
    records: list[dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        for dirname in list(dirnames):
            child = current / dirname
            if child.is_symlink():
                raise PurgeValidationError(f"unsafe {kind}: symlink directory refused")
        for filename in filenames:
            records.append(_file_record(current / filename, kind, root))
    return sorted(records, key=lambda item: item["path"])


def _git(
    path: Path, *args: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(path), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if check and result.returncode != 0:
        raise PurgeValidationError("Git ownership or backup verification failed")
    return result


def _verified_worktree(task_id: str, workspace: Path) -> dict[str, str]:
    resolved = workspace.resolve()
    top = Path(_git(resolved, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    common = Path(
        _git(
            resolved, "rev-parse", "--path-format=absolute", "--git-common-dir"
        ).stdout.strip()
    ).resolve()
    repo = common.parent if common.name == ".git" else common
    expected = repo / ".worktrees" / task_id
    if top != resolved or resolved != expected.resolve(strict=False):
        raise PurgeValidationError(
            "worktree is not the exact Hermes task-owned linked checkout"
        )
    porcelain = _git(repo, "worktree", "list", "--porcelain").stdout.splitlines()
    listed = {
        Path(line[9:]).resolve() for line in porcelain if line.startswith("worktree ")
    }
    if resolved not in listed or resolved == repo.resolve():
        raise PurgeValidationError(
            "worktree is not registered as the exact linked checkout"
        )
    if _git(
        resolved, "status", "--porcelain=v1", "--untracked-files=no"
    ).stdout.strip():
        raise PurgeValidationError(
            "worktree has modified tracked content that is not covered by a Git bundle"
        )
    head = _git(resolved, "rev-parse", "HEAD").stdout.strip()
    return {
        "kind": "worktree",
        "path": str(resolved),
        "repo": str(repo.resolve()),
        "head": head,
    }


def _worktree_untracked_files(worktree: Path) -> list[Path]:
    relative: set[str] = set()
    for args in (
        ("ls-files", "--others", "--exclude-standard", "-z"),
        ("ls-files", "--others", "--ignored", "--exclude-standard", "-z"),
    ):
        output = _git(worktree, *args).stdout
        relative.update(item for item in output.split("\0") if item)
    files: list[Path] = []
    for item in sorted(relative):
        candidate = worktree / item
        if candidate.is_symlink() or not candidate.is_file():
            raise PurgeValidationError(
                "worktree untracked path is not a regular owned file"
            )
        files.append(candidate)
    return files


def build_manifest(
    conn: sqlite3.Connection,
    task_id: str,
    *,
    board: Optional[str] = None,
) -> PurgeManifest:
    _assert_schema_registry_complete(conn)
    task = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if task is None:
        raise PurgeValidationError("task not found")
    if task["status"] != "archived":
        raise PurgeValidationError("task must already be archived")
    if (
        task["claim_lock"]
        or task["claim_expires"]
        or task["worker_pid"]
        or task["current_run_id"]
    ):
        raise PurgeValidationError("archived task still has an active claim")

    db_rows = {table: _rows_for_task(conn, table, task_id) for table in _DB_TABLES}
    files: list[dict[str, Any]] = []
    roots: list[dict[str, str]] = []

    attachment_root = kb.task_attachments_dir(task_id, board=board)
    canonical_attachment_root = attachment_root.resolve(strict=False)
    for row in db_rows.get("task_attachments", []):
        stored = Path(str(row["stored_path"]))
        if stored.exists():
            _assert_regular_owned_file(stored, canonical_attachment_root, "attachment")
        else:
            try:
                stored.resolve(strict=False).relative_to(canonical_attachment_root)
            except ValueError as exc:
                raise PurgeValidationError("unsafe attachment metadata path") from exc
    attachment_files = _walk_owned_files(attachment_root, "attachment")
    files.extend(attachment_files)
    if attachment_root.exists():
        roots.append({"kind": "attachment", "path": str(attachment_root.resolve())})

    logs_root = kb.worker_logs_dir(board=board)
    if logs_root.exists():
        if logs_root.is_symlink() or not logs_root.is_dir():
            raise PurgeValidationError("unsafe log root")
        for candidate in logs_root.iterdir():
            match = _ROTATED_LOG_RE.fullmatch(candidate.name)
            if match and match.group("task") == task_id:
                files.append(_file_record(candidate, "log", logs_root))

    excluded_dir = task["workspace_kind"] == "dir"
    workspace_path = task["workspace_path"]
    if task["workspace_kind"] == "scratch" and workspace_path:
        workspace = Path(workspace_path)
        if workspace.exists():
            if not kb._is_managed_scratch_path(workspace):
                raise PurgeValidationError("unsafe scratch workspace path")
            roots.append({"kind": "scratch", "path": str(workspace.resolve())})
            files.extend(_walk_owned_files(workspace, "scratch"))
    elif (
        task["workspace_kind"] == "worktree"
        and workspace_path
        and Path(workspace_path).exists()
    ):
        worktree = Path(workspace_path)
        root = _verified_worktree(task_id, worktree)
        roots.append(root)
        files.extend(
            _file_record(path, "worktree_untracked", worktree)
            for path in _worktree_untracked_files(worktree)
        )

    for checkpoint in db_rows.get("task_checkpoints", []):
        git_ref = checkpoint.get("git_ref")
        commit_sha = checkpoint.get("commit_sha")
        seq = checkpoint.get("seq")
        checkpoint_workspace = checkpoint.get("workspace_path") or workspace_path
        if not git_ref and not commit_sha:
            continue
        if (
            not isinstance(seq, int)
            or seq < 1
            or git_ref != f"refs/hermes/ckpt/{task_id}/{seq}"
            or not isinstance(commit_sha, str)
            or not checkpoint_workspace
        ):
            raise PurgeValidationError("unsafe checkpoint ref metadata")
        workspace = Path(str(checkpoint_workspace))
        common = Path(
            _git(
                workspace, "rev-parse", "--path-format=absolute", "--git-common-dir"
            ).stdout.strip()
        ).resolve()
        repo = common.parent if common.name == ".git" else common
        actual = _git(repo, "rev-parse", git_ref).stdout.strip()
        if actual != commit_sha:
            raise PurgeValidationError(
                "checkpoint ref does not match its recorded commit"
            )
        roots.append({
            "kind": "checkpoint_ref",
            "path": str(repo.resolve()),
            "repo": str(repo.resolve()),
            "ref": git_ref,
            "commit": commit_sha,
            "seq": str(seq),
        })

    return PurgeManifest(
        schema_version=1,
        task_id=task_id,
        db_rows=db_rows,
        files=tuple(sorted(files, key=lambda item: (item["kind"], item["path"]))),
        owned_roots=tuple(sorted(roots, key=lambda item: (item["kind"], item["path"]))),
        excluded_dir_workspace=excluded_dir,
    )


def preview_purge(
    conn: sqlite3.Connection,
    task_id: str,
    *,
    actor: str,
    board: Optional[str] = None,
    now: Optional[int] = None,
) -> PurgePreview:
    if not _ACTOR_RE.fullmatch(actor):
        raise PurgeValidationError("invalid actor")
    manifest = build_manifest(conn, task_id, board=board)
    created = int(time.time() if now is None else now)
    expires = created + TOKEN_TTL_SECONDS
    operation_id = f"kp_{secrets.token_hex(16)}"
    token = secrets.token_urlsafe(32)
    counts = manifest.safe_counts()
    with kb.write_txn(conn):
        conn.execute(
            "UPDATE kanban_purge_operations SET status = ?, token_hash = NULL, updated_at = ? "
            "WHERE task_id = ? AND actor = ? AND status = ?",
            (
                PurgeStatus.SUPERSEDED.value,
                created,
                task_id,
                actor,
                PurgeStatus.PREVIEWED.value,
            ),
        )
        conn.execute(
            "INSERT INTO kanban_purge_operations "
            "(id, task_id, actor, board_identity, manifest_digest, token_hash, status, counts_json, "
            "created_at, expires_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                operation_id,
                task_id,
                actor,
                _board_identity(conn),
                manifest.digest,
                hash_confirmation_token(token),
                PurgeStatus.PREVIEWED.value,
                json.dumps(counts, sort_keys=True, separators=(",", ":")),
                created,
                expires,
                created,
            ),
        )
    return PurgePreview(
        operation_id, task_id, PurgeStatus.PREVIEWED, expires, token, counts
    )


def _operation(conn: sqlite3.Connection, operation_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM kanban_purge_operations WHERE id = ?", (operation_id,)
    ).fetchone()
    if row is None:
        raise PurgeConfirmationError("unknown purge operation")
    return row


def _set_operation(
    conn: sqlite3.Connection,
    operation_id: str,
    status: PurgeStatus,
    *,
    failure_code: Optional[str] = None,
    backup_id: Optional[str] = None,
    backup_sha256: Optional[str] = None,
    now: Optional[int] = None,
) -> None:
    timestamp = int(time.time() if now is None else now)
    conn.execute(
        "UPDATE kanban_purge_operations SET status = ?, failure_code = ?, "
        "backup_id = COALESCE(?, backup_id), backup_sha256 = COALESCE(?, backup_sha256), "
        "updated_at = ? WHERE id = ?",
        (status.value, failure_code, backup_id, backup_sha256, timestamp, operation_id),
    )


def _chmod_private(path: Path, mode: int) -> None:
    if os.name != "nt":
        path.chmod(mode)
        if path.stat().st_mode & 0o777 != mode:
            raise PurgeValidationError("cannot establish owner-only backup permissions")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _create_verified_git_bundles(
    manifest: PurgeManifest, operation_id: str, backup_dir: Path
) -> list[Path]:
    refs_by_repo: dict[str, set[str]] = {}
    temporary_refs: list[tuple[Path, str, str]] = []
    bundles: list[Path] = []
    caught: Optional[Exception] = None
    try:
        for index, root in enumerate(manifest.owned_roots):
            if root["kind"] == "checkpoint_ref":
                refs_by_repo.setdefault(root["repo"], set()).add(root["ref"])
            elif root["kind"] == "worktree":
                repo = Path(root["repo"])
                temporary_ref = (
                    f"refs/hermes/purge-backup/{operation_id}/worktree-{index}"
                )
                if _ref_value(repo, temporary_ref) is not None:
                    raise PurgeValidationError(
                        "temporary purge-backup ref already exists"
                    )
                _apply_ref_transaction(repo, [f"create {temporary_ref} {root['head']}"])
                temporary_refs.append((repo, temporary_ref, root["head"]))
                refs_by_repo.setdefault(root["repo"], set()).add(temporary_ref)

        for repo_text, refs in refs_by_repo.items():
            repo = Path(repo_text)
            bundle = (
                backup_dir
                / f"repo-{hashlib.sha256(str(repo).encode()).hexdigest()[:16]}.bundle"
            )
            _git(repo, "bundle", "create", str(bundle), *sorted(refs))
            _git(repo, "bundle", "verify", str(bundle))
            bundles.append(bundle)
    except Exception as exc:
        caught = exc

    cleanup_failed = False
    for repo, temporary_ref, commit in reversed(temporary_refs):
        try:
            if _ref_value(repo, temporary_ref) == commit:
                _apply_ref_transaction(repo, [f"delete {temporary_ref} {commit}"])
            if _ref_value(repo, temporary_ref) is not None:
                cleanup_failed = True
        except Exception:
            cleanup_failed = True
    if cleanup_failed:
        raise PurgeRollbackError(
            "temporary purge-backup refs could not be cleaned; manual intervention required"
        ) from caught
    if caught is not None:
        raise caught
    return bundles


def _verify_tar(
    path: Path, records: Optional[tuple[dict[str, Any], ...]] = None
) -> None:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if records is not None and [member.name for member in members] != [
            f"files/{index}" for index in range(len(records))
        ]:
            raise PurgeValidationError("backup tar does not match manifest members")
        for index, member in enumerate(members):
            member_path = Path(member.name)
            if (
                member_path.is_absolute()
                or ".." in member_path.parts
                or not member.isfile()
            ):
                raise PurgeValidationError("backup tar contains an unsafe member")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise PurgeValidationError("backup tar member is unreadable")
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
            if records is not None and (
                size != int(records[index]["size"])
                or digest.hexdigest() != records[index]["sha256"]
            ):
                raise PurgeValidationError("backup tar byte checksum mismatch")


def _fsync_path(path: Path) -> None:
    if not hasattr(os, "fsync"):
        return
    flags = os.O_RDONLY
    if path.is_dir() and hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError:
        if os.name == "nt" and path.is_dir():
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_verified_backup(
    conn: sqlite3.Connection,
    operation_id: str,
    manifest: PurgeManifest,
) -> tuple[Path, str]:
    backup_dir = _db_path(conn).parent / "purge-backups" / operation_id
    if backup_dir.exists():
        raise PurgeValidationError("purge backup already exists")
    backup_dir.mkdir(parents=True, mode=0o700)
    _chmod_private(backup_dir, 0o700)
    try:
        manifest_path = backup_dir / "manifest.json"
        manifest_path.write_bytes(manifest.canonical_bytes())

        db_backup = backup_dir / "board.sqlite3"
        if not safe_copy_sqlite_db(_db_path(conn), db_backup):
            raise PurgeValidationError("SQLite backup failed")
        check = sqlite3.connect(f"file:{db_backup}?mode=ro&immutable=1", uri=True)
        check.row_factory = sqlite3.Row
        try:
            if check.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise PurgeValidationError("SQLite backup quick_check failed")
            backup_rows = {
                table: _rows_for_task(check, table, manifest.task_id)
                for table in _DB_TABLES
            }
            backup_db_digest = hashlib.sha256(
                json.dumps(
                    backup_rows,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            if not hmac.compare_digest(backup_db_digest, manifest.db_digest):
                raise PurgeValidationError("SQLite backup task manifest mismatch")
        finally:
            check.close()
        # A read-only integrity check of a WAL-mode snapshot can materialize
        # transient sidecars.  They are not part of the self-contained backup
        # generation and must never be shipped beside the copied main file.
        for suffix in ("-wal", "-shm", "-journal"):
            Path(f"{db_backup}{suffix}").unlink(missing_ok=True)

        tar_path = backup_dir / "files.tar.gz"
        with tarfile.open(tar_path, "w:gz") as archive:
            for index, record in enumerate(manifest.files):
                source = Path(record["path"])
                if _sha256_file(source) != record["sha256"]:
                    raise PurgeValidationError("owned file drifted during backup")
                archive.add(source, arcname=f"files/{index}", recursive=False)
        _verify_tar(tar_path, manifest.files)

        readme = backup_dir / "README.restore.txt"
        readme.write_text(
            "Hermes archived-task purge backup. Never restore into a live Hermes home.\n\n"
            "ISOLATED RESTORE PROCEDURE\n"
            "1. Copy this whole directory to an isolated machine/home and run:\n"
            "     sha256sum -c CHECKSUMS.sha256\n"
            "2. Open board.sqlite3 read-only and require `PRAGMA quick_check` to return `ok`.\n"
            "3. Inspect manifest.json. Each files.tar.gz member `files/N` maps exactly to\n"
            "   manifest.files[N], including its original path, byte count, and SHA-256.\n"
            "   Extract to a new empty directory, verify those hashes, then choose destinations.\n"
            "4. For each repo-*.bundle run `git bundle verify <bundle>` in an isolated Git repo;\n"
            "   inspect `git bundle list-heads <bundle>` before fetching any refs.\n"
            "5. Never replace a live board database or existing task path automatically.\n\n"
            "This backup intentionally retains purged bytes. SQLite free pages/WAL, Git objects,\n"
            "filesystem/provider snapshots, and other backups may also retain bytes.\n",
            encoding="utf-8",
        )
        bundles = _create_verified_git_bundles(manifest, operation_id, backup_dir)
        members = [manifest_path, db_backup, tar_path, readme, *bundles]
        for member in members:
            _chmod_private(member, 0o600)
        checksums = backup_dir / "CHECKSUMS.sha256"
        checksums.write_text(
            "".join(f"{_sha256_file(member)}  {member.name}\n" for member in members),
            encoding="utf-8",
        )
        _chmod_private(checksums, 0o600)
        for line in checksums.read_text(encoding="utf-8").splitlines():
            expected, name = line.split("  ", 1)
            target = backup_dir / name
            if _sha256_file(target) != expected:
                raise PurgeValidationError("purge backup checksum verification failed")
        for member in (*members, checksums):
            _fsync_path(member)
        _fsync_path(backup_dir)
        _fsync_path(backup_dir.parent)
        return backup_dir, _sha256_file(checksums)
    except Exception:
        shutil.rmtree(backup_dir, ignore_errors=True)
        raise


def _staging_entries(
    manifest: PurgeManifest, operation_id: str
) -> list[tuple[Path, Path]]:
    entries: list[tuple[Path, Path]] = []
    rooted_files: set[str] = set()
    for root in manifest.owned_roots:
        if root["kind"] == "checkpoint_ref":
            continue
        source = Path(root["path"])
        destination = source.parent / ".purge-staging" / operation_id / source.name
        entries.append((source, destination))
        for record in manifest.files:
            try:
                Path(record["path"]).relative_to(source)
                rooted_files.add(record["path"])
            except ValueError:
                pass
    for record in manifest.files:
        if record["path"] in rooted_files:
            continue
        source = Path(record["path"])
        destination = source.parent / ".purge-staging" / operation_id / source.name
        entries.append((source, destination))
    return entries


def _prepare_staging_destination(source: Path, destination: Path) -> None:
    staging_root = source.parent / ".purge-staging"
    if destination.parent.parent != staging_root:
        raise PurgeValidationError("unsafe staging destination")
    for directory in (staging_root, destination.parent):
        if directory.exists() or directory.is_symlink():
            mode = directory.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise PurgeValidationError("staging root is a symlink or non-directory")
        else:
            directory.mkdir(mode=0o700)
        _chmod_private(directory, 0o700)
    if destination.exists() or destination.is_symlink():
        raise PurgeValidationError("staging destination already exists")


def _stage(manifest: PurgeManifest, operation_id: str) -> list[tuple[Path, Path]]:
    moved: list[tuple[Path, Path]] = []
    worktree_sources = {
        Path(root["path"]): Path(root["repo"])
        for root in manifest.owned_roots
        if root["kind"] == "worktree"
    }
    try:
        for source, destination in _staging_entries(manifest, operation_id):
            if not source.exists():
                raise PurgeValidationError("owned resource drifted before staging")
            _prepare_staging_destination(source, destination)
            repo = worktree_sources.get(source)
            if repo is not None:
                _git(repo, "worktree", "move", str(source), str(destination))
            else:
                os.replace(source, destination)
            moved.append((source, destination))
        return moved
    except Exception:
        if not _restore_staged(moved):
            raise PurgeRollbackError("staging failed and compensation was incomplete")
        raise


def _restore_staged(entries: list[tuple[Path, Path]]) -> bool:
    ok = True
    for source, destination in reversed(entries):
        try:
            if destination.exists():
                if source.exists() or source.is_symlink():
                    ok = False
                    continue
                source.parent.mkdir(parents=True, exist_ok=True)
                if source.parent.name == ".worktrees":
                    _git(
                        source.parent.parent,
                        "worktree",
                        "move",
                        str(destination),
                        str(source),
                    )
                else:
                    os.replace(destination, source)
            elif not source.exists() or source.is_symlink():
                ok = False
        except Exception:
            ok = False
    _remove_empty_staging_dirs(entries)
    return ok


def _remove_empty_staging_dirs(entries: list[tuple[Path, Path]]) -> None:
    operation_dirs = {destination.parent for _source, destination in entries}
    for operation_dir in operation_dirs:
        staging_root = operation_dir.parent
        if staging_root.name != ".purge-staging":
            continue
        for candidate in (operation_dir, staging_root):
            try:
                candidate.rmdir()
            except FileNotFoundError:
                pass
            except OSError:
                # Non-empty directories can contain another task/operation and
                # are intentionally retained; rmdir never removes their data.
                pass


def _cleanup_staged(entries: list[tuple[Path, Path]]) -> None:
    for source, destination in entries:
        if source.parent.name == ".worktrees":
            if destination.is_symlink():
                raise PurgeValidationError("staged worktree path became a symlink")
            if destination.exists():
                _git(
                    source.parent.parent,
                    "worktree",
                    "remove",
                    "--force",
                    str(destination),
                )
            _git(source.parent.parent, "worktree", "prune")
            continue
        if not destination.exists() and not destination.is_symlink():
            continue
        if destination.is_symlink():
            destination.unlink()
        elif destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        else:
            destination.unlink()
    _remove_empty_staging_dirs(entries)


def _ref_value(repo: Path, ref: str) -> Optional[str]:
    result = _git(repo, "show-ref", "--verify", "--hash", ref, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def _apply_ref_transaction(repo: Path, commands: list[str]) -> None:
    result = subprocess.run(
        ["git", "-C", str(repo), "update-ref", "--stdin"],
        input="start\n" + "\n".join(commands) + "\nprepare\ncommit\n",
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise PurgeValidationError("checkpoint ref transaction failed")


def _checkpoint_groups(
    manifest: PurgeManifest, operation_id: str
) -> dict[Path, list[tuple[str, str, str]]]:
    groups: dict[Path, list[tuple[str, str, str]]] = {}
    for root in manifest.owned_roots:
        if root["kind"] != "checkpoint_ref":
            continue
        staged_ref = f"refs/hermes/purge-staging/{operation_id}/{root['seq']}"
        groups.setdefault(Path(root["repo"]), []).append((
            root["ref"],
            staged_ref,
            root["commit"],
        ))
    return groups


def _stage_checkpoint_refs(manifest: PurgeManifest, operation_id: str) -> None:
    for repo, refs in _checkpoint_groups(manifest, operation_id).items():
        commands: list[str] = []
        for live_ref, staged_ref, commit in refs:
            if (
                _ref_value(repo, live_ref) != commit
                or _ref_value(repo, staged_ref) is not None
            ):
                raise PurgeValidationError("checkpoint ref drifted before staging")
            commands.extend((
                f"create {staged_ref} {commit}",
                f"delete {live_ref} {commit}",
            ))
        _apply_ref_transaction(repo, commands)


def _restore_checkpoint_refs(manifest: PurgeManifest, operation_id: str) -> bool:
    try:
        for repo, refs in _checkpoint_groups(manifest, operation_id).items():
            commands: list[str] = []
            for live_ref, staged_ref, commit in refs:
                live = _ref_value(repo, live_ref)
                staged = _ref_value(repo, staged_ref)
                if live == commit and staged is None:
                    continue
                if live is not None or staged != commit:
                    return False
                commands.extend((
                    f"create {live_ref} {commit}",
                    f"delete {staged_ref} {commit}",
                ))
            if commands:
                _apply_ref_transaction(repo, commands)
        return True
    except Exception:
        return False


def _cleanup_checkpoint_refs(manifest: PurgeManifest, operation_id: str) -> None:
    for repo, refs in _checkpoint_groups(manifest, operation_id).items():
        commands: list[str] = []
        for live_ref, staged_ref, commit in refs:
            if _ref_value(repo, live_ref) is not None:
                raise PurgeValidationError(
                    "live checkpoint ref unexpectedly remains after database commit"
                )
            staged = _ref_value(repo, staged_ref)
            if staged is None:
                continue
            if staged != commit:
                raise PurgeValidationError("staged checkpoint ref drifted")
            commands.append(f"delete {staged_ref} {commit}")
        if commands:
            _apply_ref_transaction(repo, commands)


def _read_backup_manifest(backup_dir: Path) -> PurgeManifest:
    raw = json.loads((backup_dir / "manifest.json").read_text(encoding="utf-8"))
    return PurgeManifest(
        schema_version=int(raw["schema_version"]),
        task_id=str(raw["task_id"]),
        db_rows=raw["db_rows"],
        files=tuple(raw["files"]),
        owned_roots=tuple(raw["owned_roots"]),
        excluded_dir_workspace=bool(raw["excluded_dir_workspace"]),
    )


def _verify_backup_generation(
    conn: sqlite3.Connection, row: sqlite3.Row, backup_dir: Path
) -> PurgeManifest:
    expected_root = _db_path(conn).parent / "purge-backups"
    if (
        backup_dir.is_symlink()
        or backup_dir.resolve() != (expected_root / row["id"]).resolve(strict=False)
        or not backup_dir.is_dir()
    ):
        raise PurgeValidationError("purge backup is unavailable or unsafe")
    checksums = backup_dir / "CHECKSUMS.sha256"
    if checksums.is_symlink() or not checksums.is_file():
        raise PurgeValidationError("purge backup checksum index is unavailable")
    if not row["backup_sha256"] or not hmac.compare_digest(
        _sha256_file(checksums), row["backup_sha256"]
    ):
        raise PurgeValidationError("purge backup checksum index drifted")

    indexed: dict[str, str] = {}
    for line in checksums.read_text(encoding="utf-8").splitlines():
        try:
            digest, name = line.split("  ", 1)
        except ValueError as exc:
            raise PurgeValidationError("malformed purge backup checksum index") from exc
        if (
            not re.fullmatch(r"[0-9a-f]{64}", digest)
            or Path(name).name != name
            or name in indexed
        ):
            raise PurgeValidationError("unsafe purge backup checksum entry")
        indexed[name] = digest
    required = {
        "manifest.json",
        "board.sqlite3",
        "files.tar.gz",
        "README.restore.txt",
    }
    if not required <= indexed.keys():
        raise PurgeValidationError("purge backup is incomplete")
    backup_entries = list(backup_dir.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in backup_entries):
        raise PurgeValidationError("purge backup contains an unsafe artifact")
    actual = {path.name for path in backup_entries if path.name != checksums.name}
    if actual != set(indexed):
        raise PurgeValidationError("purge backup file set drifted")
    for name, expected in indexed.items():
        target = backup_dir / name
        if (
            target.is_symlink()
            or not target.is_file()
            or _sha256_file(target) != expected
        ):
            raise PurgeValidationError("purge backup artifact checksum mismatch")

    manifest = _read_backup_manifest(backup_dir)
    if (
        manifest.schema_version != 1
        or manifest.task_id != row["task_id"]
        or not hmac.compare_digest(manifest.digest, row["manifest_digest"])
    ):
        raise PurgeValidationError("purge backup manifest identity mismatch")
    _verify_tar(backup_dir / "files.tar.gz", manifest.files)
    backup_db = sqlite3.connect(
        f"file:{backup_dir / 'board.sqlite3'}?mode=ro&immutable=1", uri=True
    )
    backup_db.row_factory = sqlite3.Row
    try:
        if backup_db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise PurgeValidationError("purge backup database quick_check failed")
        rows = {
            table: _rows_for_task(backup_db, table, manifest.task_id)
            for table in _DB_TABLES
        }
        digest = hashlib.sha256(
            json.dumps(
                rows,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(digest, manifest.db_digest):
            raise PurgeValidationError("purge backup database manifest mismatch")
    finally:
        backup_db.close()
    return manifest


def confirm_purge(
    conn: sqlite3.Connection,
    task_id: str,
    *,
    operation_id: str,
    confirmation_token: str,
    actor: str,
    board: Optional[str] = None,
    now: Optional[int] = None,
) -> PurgeResult:
    timestamp = int(time.time() if now is None else now)
    with kb.write_txn(conn):
        row = _operation(conn, operation_id)
        if row["status"] != PurgeStatus.PREVIEWED.value or not row["token_hash"]:
            raise PurgeConfirmationError(
                "purge confirmation was already consumed or is not previewed"
            )
        if (
            row["task_id"] != task_id
            or row["actor"] != actor
            or row["board_identity"] != _board_identity(conn)
        ):
            conn.execute(
                "UPDATE kanban_purge_operations SET token_hash = NULL, status = ?, failure_code = ?, updated_at = ? WHERE id = ?",
                (
                    PurgeStatus.PRECOMMIT_FAILED.value,
                    "identity_mismatch",
                    timestamp,
                    operation_id,
                ),
            )
            raise PurgeConfirmationError("purge confirmation identity mismatch")
        if timestamp > int(row["expires_at"]):
            conn.execute(
                "UPDATE kanban_purge_operations SET token_hash = NULL, status = ?, failure_code = ?, updated_at = ? WHERE id = ?",
                (PurgeStatus.EXPIRED.value, "expired", timestamp, operation_id),
            )
            raise PurgeConfirmationError("purge confirmation expired")
        if not hmac.compare_digest(
            row["token_hash"], hash_confirmation_token(confirmation_token)
        ):
            conn.execute(
                "UPDATE kanban_purge_operations SET token_hash = NULL, status = ?, failure_code = ?, updated_at = ? WHERE id = ?",
                (
                    PurgeStatus.PRECOMMIT_FAILED.value,
                    "invalid_token",
                    timestamp,
                    operation_id,
                ),
            )
            raise PurgeConfirmationError("invalid purge confirmation")
        conn.execute(
            "UPDATE kanban_purge_operations SET token_hash = NULL, status = ?, confirmed_at = ?, updated_at = ? WHERE id = ?",
            (PurgeStatus.BACKING_UP.value, timestamp, timestamp, operation_id),
        )
        expected_digest = row["manifest_digest"]

    try:
        manifest = build_manifest(conn, task_id, board=board)
    except Exception as exc:
        with kb.write_txn(conn):
            _set_operation(
                conn,
                operation_id,
                PurgeStatus.PRECOMMIT_FAILED,
                failure_code="manifest_drift",
            )
        raise PurgeConfirmationError("purge manifest drift") from exc
    if not hmac.compare_digest(manifest.digest, expected_digest):
        with kb.write_txn(conn):
            _set_operation(
                conn,
                operation_id,
                PurgeStatus.PRECOMMIT_FAILED,
                failure_code="manifest_drift",
            )
        raise PurgeConfirmationError("purge manifest drift")

    try:
        backup_dir, backup_sha = create_verified_backup(conn, operation_id, manifest)
    except Exception:
        with kb.write_txn(conn):
            _set_operation(
                conn,
                operation_id,
                PurgeStatus.PRECOMMIT_FAILED,
                failure_code="backup_failed",
            )
        raise

    # Link the verified generation before any reversible external mutation.
    # Recovery can distinguish "backup never completed" from "backup is
    # valid but staging/commit was interrupted" without storing its manifest.
    with kb.write_txn(conn):
        _set_operation(
            conn,
            operation_id,
            PurgeStatus.BACKING_UP,
            backup_id=operation_id,
            backup_sha256=backup_sha,
        )

    try:
        if build_manifest(conn, task_id, board=board).digest != expected_digest:
            raise PurgeConfirmationError("purge manifest drift after backup")
        staged = _stage(manifest, operation_id)
        try:
            _stage_checkpoint_refs(manifest, operation_id)
        except Exception:
            refs_restored = _restore_checkpoint_refs(manifest, operation_id)
            if not (_restore_staged(staged) and refs_restored):
                raise PurgeRollbackError(
                    "checkpoint staging failed and file compensation was incomplete"
                )
            raise
        with kb.write_txn(conn):
            _set_operation(
                conn,
                operation_id,
                PurgeStatus.STAGED,
                backup_id=operation_id,
                backup_sha256=backup_sha,
            )
    except PurgeRollbackError:
        with kb.write_txn(conn):
            _set_operation(
                conn,
                operation_id,
                PurgeStatus.ROLLBACK_FAILED,
                failure_code="rollback_failed",
                backup_id=operation_id,
                backup_sha256=backup_sha,
            )
        raise
    except Exception as exc:
        with kb.write_txn(conn):
            _set_operation(
                conn, operation_id, PurgeStatus.ROLLED_BACK, failure_code="stage_failed"
            )
        if isinstance(exc, PurgeConfirmationError):
            raise
        raise PurgeValidationError("purge staging failed") from exc

    try:
        with kb.write_txn(conn):
            operation = _operation(conn, operation_id)
            task = conn.execute(
                "SELECT status FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            current_rows = {
                table: _rows_for_task(conn, table, task_id) for table in _DB_TABLES
            }
            current_db_digest = hashlib.sha256(
                json.dumps(
                    current_rows,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            if (
                operation["status"] != PurgeStatus.STAGED.value
                or operation["task_id"] != task_id
                or operation["actor"] != actor
                or operation["board_identity"] != _board_identity(conn)
                or operation["manifest_digest"] != manifest.digest
                or operation["backup_id"] != operation_id
                or operation["backup_sha256"] != backup_sha
                or not task
                or task["status"] != "archived"
            ):
                raise PurgeConfirmationError(
                    "purge state changed before database commit"
                )
            if not hmac.compare_digest(current_db_digest, manifest.db_digest):
                raise PurgeConfirmationError("purge database drift before commit")
            if not kb._delete_task_rows_in_txn(conn, task_id):
                raise PurgeConfirmationError("archived task disappeared before commit")
            conn.execute(
                "UPDATE kanban_purge_operations SET status = ?, backup_id = ?, backup_sha256 = ?, "
                "db_committed_at = ?, updated_at = ? WHERE id = ?",
                (
                    PurgeStatus.DB_COMMITTED.value,
                    operation_id,
                    backup_sha,
                    timestamp,
                    timestamp,
                    operation_id,
                ),
            )
    except Exception:
        refs_restored = _restore_checkpoint_refs(manifest, operation_id)
        restored = _restore_staged(staged) and refs_restored
        with kb.write_txn(conn):
            _set_operation(
                conn,
                operation_id,
                PurgeStatus.ROLLED_BACK if restored else PurgeStatus.ROLLBACK_FAILED,
                failure_code="db_failed" if restored else "rollback_failed",
                backup_id=operation_id,
                backup_sha256=backup_sha,
            )
        if not restored:
            raise PurgeRollbackError(
                "database purge failed and staged resources were not fully restored"
            )
        raise

    try:
        _cleanup_checkpoint_refs(manifest, operation_id)
        _cleanup_staged(staged)
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE kanban_purge_operations SET status = ?, completed_at = ?, updated_at = ? WHERE id = ?",
                (PurgeStatus.COMPLETE.value, timestamp, timestamp, operation_id),
            )
    except Exception:
        with kb.write_txn(conn):
            _set_operation(
                conn,
                operation_id,
                PurgeStatus.CLEANUP_PENDING,
                failure_code="cleanup_failed",
            )
        result = PurgeResult(
            operation_id, task_id, PurgeStatus.CLEANUP_PENDING, str(backup_dir), 3
        )
        raise PurgeCleanupPendingError(result)

    return PurgeResult(operation_id, task_id, PurgeStatus.COMPLETE, str(backup_dir), 0)


def resume_purge(
    conn: sqlite3.Connection,
    operation_id: str,
) -> PurgeResult:
    row = _operation(conn, operation_id)
    if row["board_identity"] != _board_identity(conn):
        raise PurgeValidationError("purge operation belongs to a different board")
    backup_dir = _db_path(conn).parent / "purge-backups" / operation_id
    task_exists = (
        conn.execute("SELECT 1 FROM tasks WHERE id = ?", (row["task_id"],)).fetchone()
        is not None
    )
    if (
        row["backup_id"] is None
        and task_exists
        and row["status"]
        in {
            PurgeStatus.BACKING_UP.value,
            PurgeStatus.PRECOMMIT_FAILED.value,
        }
    ):
        # No external staging is attempted before a verified backup is durably
        # linked to the operation. A crash may leave an incomplete directory;
        # it is not a recovery point and is safe to discard by exact op id.
        if backup_dir.exists():
            if backup_dir.is_symlink() or backup_dir.parent.name != "purge-backups":
                raise PurgeRollbackError("unsafe incomplete purge-backup path")
            shutil.rmtree(backup_dir)
        with kb.write_txn(conn):
            _set_operation(conn, operation_id, PurgeStatus.ROLLED_BACK)
        return PurgeResult(
            operation_id, row["task_id"], PurgeStatus.ROLLED_BACK, None, 0
        )
    if row["backup_id"] != operation_id:
        raise PurgeValidationError("purge operation has no verified backup identity")
    manifest = _verify_backup_generation(conn, row, backup_dir)
    entries = _staging_entries(manifest, operation_id)
    if task_exists:
        if row["status"] not in {
            PurgeStatus.BACKING_UP.value,
            PurgeStatus.STAGED.value,
            PurgeStatus.PRECOMMIT_FAILED.value,
            PurgeStatus.ROLLED_BACK.value,
            PurgeStatus.ROLLBACK_FAILED.value,
        }:
            raise PurgeRollbackError("task existence conflicts with purge state")
        current_rows = {
            table: _rows_for_task(conn, table, row["task_id"]) for table in _DB_TABLES
        }
        current_digest = hashlib.sha256(
            json.dumps(
                current_rows,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(current_digest, manifest.db_digest):
            raise PurgeRollbackError(
                "task identity drifted; refusing to restore staged resources"
            )
        refs_restored = _restore_checkpoint_refs(manifest, operation_id)
        restored = _restore_staged(entries) and refs_restored
        if restored:
            try:
                restored = (
                    build_manifest(conn, row["task_id"]).digest == manifest.digest
                )
            except PurgeError:
                restored = False
        with kb.write_txn(conn):
            _set_operation(
                conn,
                operation_id,
                PurgeStatus.ROLLED_BACK if restored else PurgeStatus.ROLLBACK_FAILED,
                failure_code=None if restored else "rollback_failed",
            )
        if not restored:
            raise PurgeRollbackError("purge staging could not be fully restored")
        return PurgeResult(
            operation_id, row["task_id"], PurgeStatus.ROLLED_BACK, str(backup_dir), 0
        )

    if row["status"] not in {
        PurgeStatus.DB_COMMITTED.value,
        PurgeStatus.CLEANUP_PENDING.value,
        PurgeStatus.COMPLETE.value,
    }:
        raise PurgeRollbackError("missing task conflicts with pre-commit purge state")
    try:
        _cleanup_checkpoint_refs(manifest, operation_id)
        _cleanup_staged(entries)
        timestamp = int(time.time())
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE kanban_purge_operations SET status = ?, failure_code = NULL, completed_at = ?, updated_at = ? WHERE id = ?",
                (PurgeStatus.COMPLETE.value, timestamp, timestamp, operation_id),
            )
    except Exception as exc:
        with kb.write_txn(conn):
            _set_operation(
                conn,
                operation_id,
                PurgeStatus.CLEANUP_PENDING,
                failure_code="cleanup_failed",
            )
        raise PurgeCleanupPendingError(
            PurgeResult(
                operation_id,
                row["task_id"],
                PurgeStatus.CLEANUP_PENDING,
                str(backup_dir),
                3,
            )
        ) from exc
    return PurgeResult(
        operation_id, row["task_id"], PurgeStatus.COMPLETE, str(backup_dir), 0
    )
