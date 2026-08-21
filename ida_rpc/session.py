# (c) B. Kerler 2026, MIT license
"""Session persistence for ida-rpc daemon."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Session:
    """Stores daemon session state so it can be reconstructed after restart."""

    mode: str  # "gui" or "headless"
    project_idb: Path
    socket_path: Path
    ida_install_dir: Path | None = None
    arch: str | None = None  # Processor arch passed at start (e.g. "arm", "thumb", "aarch64")

    def __post_init__(self):
        self.project_idb = Path(self.project_idb)
        self.socket_path = Path(self.socket_path)
        if self.ida_install_dir is not None:
            self.ida_install_dir = Path(self.ida_install_dir)


def socket_path_for_project(idb: Path | str) -> Path:
    """Derive a deterministic local endpoint marker path from an IDB path."""
    idb = Path(idb)
    digest = hashlib.sha256(str(idb.resolve()).encode()).hexdigest()[:8]
    return Path(tempfile.gettempdir()) / f"ida-rpc-{digest}.sock"


def session_file_path(idb: Path | str) -> Path:
    """Return the path where session state is persisted for a given IDB."""
    idb = Path(idb)
    digest = hashlib.sha256(str(idb.resolve()).encode()).hexdigest()[:8]
    state_dir_env = os.environ.get("IDA_RPC_STATE_DIR")
    if state_dir_env:
        return Path(state_dir_env) / f"{digest}.json"
    return idb.resolve().parent / f".ida-rpc-{digest}.json"


def save(session: Session) -> None:
    """Persist session to disk only when its serialized value changed."""
    path = session_file_path(session.project_idb)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "mode": session.mode,
        "project_idb": str(Path(session.project_idb).resolve()),
        "socket_path": str(session.socket_path),
        "ida_install_dir": str(session.ida_install_dir) if session.ida_install_dir else None,
        "arch": session.arch,
    }
    content = json.dumps(data, indent=2, sort_keys=True) + "\n"
    try:
        if path.read_text() == content:
            return
    except FileNotFoundError:
        pass

    # Replace the state file atomically so status/restart never observes a
    # partially-written JSON document.
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def load(idb: Path | str) -> Session | None:
    """Load a previously saved session, or return None if not found."""
    idb = Path(idb)
    path = session_file_path(idb)
    if not path.exists():
        digest = hashlib.sha256(str(idb.resolve()).encode()).hexdigest()[:8]
        legacy_path = Path.home() / ".local" / "share" / "ida-rpc" / f"{digest}.json"
        if legacy_path.exists():
            path = legacy_path
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        ida_dir = data.get("ida_install_dir")
        return Session(
            mode=data["mode"],
            project_idb=Path(data["project_idb"]),
            socket_path=Path(data["socket_path"]),
            ida_install_dir=Path(ida_dir) if ida_dir else None,
            arch=data.get("arch"),
        )
    except (json.JSONDecodeError, KeyError):
        return None


def remove(idb: Path | str) -> None:
    """Remove persisted session file."""
    path = session_file_path(idb)
    if path.exists():
        path.unlink()
