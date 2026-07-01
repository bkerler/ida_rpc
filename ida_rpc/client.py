# (c) B. Kerler 2026, MIT license
"""Client for communicating with the ida-rpc daemon over Unix socket."""

from __future__ import annotations

import errno
import json
import select
import socket
import uuid
from pathlib import Path

from ida_rpc import session as session_mod


class DaemonNotRunning(Exception):
    """Raised when the daemon socket doesn't exist or can't be connected to."""
    pass


class DaemonError(Exception):
    """Raised when the daemon returns an error response (ok: false)."""

    def __init__(self, error: str, message: str, full_response: dict):
        super().__init__(message)
        self.error = error
        self.full_response = full_response


_TIMEOUT_ARG_KEYS = ("timeout", "analysis_timeout")
_DEFAULT_SOCKET_TIMEOUT: float = 120.0
_SOCKET_TIMEOUT_BUFFER: float = 30.0


def _derive_socket_timeout(args: dict | None) -> float:
    if not args:
        return _DEFAULT_SOCKET_TIMEOUT
    timeouts = [
        float(args[k])
        for k in _TIMEOUT_ARG_KEYS
        if args.get(k) is not None
    ]
    if timeouts:
        return max(timeouts) + _SOCKET_TIMEOUT_BUFFER
    return _DEFAULT_SOCKET_TIMEOUT


def send_request(
    socket_path: Path,
    cmd: str,
    args: dict | None = None,
    *,
    socket_timeout: float | None = None,
) -> dict:
    """Send a JSON-RPC-style request to the daemon and return the parsed response."""
    if not socket_path.exists():
        raise DaemonNotRunning(f"Socket not found: {socket_path}")

    effective_timeout = (
        socket_timeout if socket_timeout is not None
        else _derive_socket_timeout(args)
    )

    request = {
        "id": str(uuid.uuid4()),
        "cmd": cmd,
        "args": args or {},
    }
    request_bytes = (json.dumps(request) + "\n").encode("utf-8")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(effective_timeout)
        sock.setblocking(False)
        rc = sock.connect_ex(str(socket_path))
        if rc in (errno.ENOENT, errno.ECONNREFUSED):
            raise DaemonNotRunning(f"Cannot connect to daemon at {socket_path}: {errno.errorcode.get(rc, rc)}")
        if rc not in (0, errno.EINPROGRESS, errno.EAGAIN, errno.EWOULDBLOCK):
            raise OSError(rc, errno.errorcode.get(rc, "connect_ex failed"))
        if rc != 0:
            _, writable, exceptional = select.select([], [sock], [sock], effective_timeout)
            if exceptional or not writable:
                raise TimeoutError(f"Timed out connecting to daemon at {socket_path}")
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err in (errno.ENOENT, errno.ECONNREFUSED):
                raise DaemonNotRunning(f"Cannot connect to daemon at {socket_path}: {errno.errorcode.get(err, err)}")
            if err:
                raise OSError(err, errno.errorcode.get(err, "socket connect failed"))
        sock.setblocking(True)
        sock.settimeout(effective_timeout)
    except Exception:
        sock.close()
        raise

    try:
        sock.sendall(request_bytes)
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        sock.close()

    if not buf.strip():
        raise DaemonError("EmptyResponse", "Daemon returned empty response", {})

    response = json.loads(buf.decode().strip())

    if not response.get("ok", False):
        raise DaemonError(
            response.get("error", "UnknownError"),
            response.get("message", "Unknown error from daemon"),
            response,
        )

    return response


def send_request_with_auto_restart(
    project_idb: Path,
    cmd: str,
    args: dict | None = None,
    *,
    socket_timeout: float | None = None,
) -> dict:
    """Send a request, auto-restarting the daemon if it's not running."""
    from ida_rpc import daemon as daemon_mod

    sock_path = session_mod.socket_path_for_project(project_idb)

    try:
        return send_request(sock_path, cmd, args, socket_timeout=socket_timeout)
    except DaemonNotRunning:
        pass

    session = session_mod.load(project_idb)
    if session is None:
        project_idb = Path(project_idb).resolve()
        if not project_idb.exists():
            raise DaemonNotRunning(
                f"Daemon not running. Start it with: ida-rpc start --project {project_idb} --arch <arch>"
            )
        session = session_mod.Session(
            mode="headless",
            project_idb=project_idb,
            socket_path=sock_path,
        )

    try:
        daemon_mod.start_background(session)
    except Exception:
        restart_cmd = f"ida-rpc start --project {project_idb}"
        if not Path(project_idb).exists():
            restart_cmd += " --arch <arch>"
        raise DaemonNotRunning(
            f"Failed to restart daemon. Please run: {restart_cmd}"
        )

    return send_request(
        session.socket_path, cmd, args, socket_timeout=socket_timeout
    )
