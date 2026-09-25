# (c) B. Kerler 2026, MIT license
"""Platform-neutral local transport used by the ida-rpc client and server.

Unix domain sockets are the preferred transport on POSIX systems.  Windows
Python installations do not consistently provide ``socket.AF_UNIX`` (and
older supported IDA/Python combinations do not provide it at all), so use a
loopback TCP socket there.  The endpoint marker keeps the existing lifecycle
and discovery behavior, which expects a deterministic ``*.sock`` path.
"""

from __future__ import annotations

import hashlib
import errno
import json
import os
import socket
import tempfile
import uuid
from pathlib import Path


TCP_HOST = "127.0.0.1"
_TCP_PORT_MIN = 49152
_TCP_PORT_COUNT = 16384
_MARKER_VERSION = 1


def uses_unix_sockets() -> bool:
    """Return whether the current platform should use Unix sockets."""
    return os.name != "nt" and hasattr(socket, "AF_UNIX")


def endpoint_address(socket_path: Path) -> str | tuple[str, int]:
    """Return the published endpoint, including legacy empty TCP markers."""
    if uses_unix_sockets():
        return str(socket_path)
    data = endpoint_marker(socket_path)
    if data is not None:
        return TCP_HOST, data["port"]
    # Older Windows daemons wrote an empty marker and derived the TCP port.
    digest = hashlib.sha256(str(socket_path).encode("utf-8")).digest()
    port = _TCP_PORT_MIN + int.from_bytes(digest[:4], "big") % _TCP_PORT_COUNT
    return TCP_HOST, port


def endpoint_marker(socket_path: Path) -> dict | None:
    """Read a Windows marker; return None for Unix sockets and old markers."""
    if uses_unix_sockets():
        return None
    marker = Path(socket_path).read_text(encoding="utf-8").strip()
    if marker:
        data = json.loads(marker)
        if not isinstance(data, dict):
            raise ValueError(f"Invalid ida-rpc endpoint marker: {socket_path}")
        port = data.get("port")
        if data.get("version") != _MARKER_VERSION or type(port) is not int or not 0 < port < 65536:
            raise ValueError(f"Invalid ida-rpc endpoint marker: {socket_path}")
        return data
    return None


def _endpoint_is_live(socket_path: Path) -> bool:
    try:
        address = endpoint_address(socket_path)
        family = socket.AF_UNIX if isinstance(address, str) else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.0)
            probe.connect(address)
            if isinstance(address, str):
                return True
            request = {"id": str(uuid.uuid4()), "cmd": "ping", "args": {}}
            probe.sendall((json.dumps(request) + "\n").encode("utf-8"))
            response = b""
            while b"\n" not in response and len(response) < 4096:
                chunk = probe.recv(4096)
                if not chunk:
                    break
                response += chunk
        result = json.loads(response.split(b"\n", 1)[0])
        if result.get("ok") is not True or result.get("result", {}).get("status") != "alive":
            return False
        marker = endpoint_marker(socket_path)
        if marker and marker.get("project") and result["result"].get("project") != marker["project"]:
            return False
        return True
    except (OSError, ValueError, AttributeError, TypeError):
        return False


def create_server_socket(socket_path: Path, *, project_idb: Path | None = None) -> socket.socket:
    """Create, bind, and listen on the platform's local RPC endpoint."""
    socket_path = Path(socket_path)
    if socket_path.exists():
        if _endpoint_is_live(socket_path):
            raise OSError(errno.EADDRINUSE, f"ida-rpc endpoint already in use: {socket_path}")
        if uses_unix_sockets():
            socket_path.unlink()

    if uses_unix_sockets():
        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    else:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        # Let Windows choose a free, non-excluded port. The published marker
        # gives clients the actual address after listen() succeeds.
        bind_address = str(socket_path) if uses_unix_sockets() else (TCP_HOST, 0)
        server_sock.bind(bind_address)
        server_sock.listen(64)
        if not uses_unix_sockets():
            socket_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(prefix=f".{socket_path.name}.", dir=socket_path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                    json.dump({
                        "version": _MARKER_VERSION,
                        "port": server_sock.getsockname()[1],
                        "pid": os.getpid(),
                        "project": str(project_idb.resolve()) if project_idb else None,
                    }, stream)
                    stream.write("\n")
                os.replace(tmp_name, socket_path)
            finally:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
    except Exception:
        server_sock.close()
        raise
    return server_sock


def remove_endpoint_marker(socket_path: Path, *, expected_port: int | None = None) -> None:
    """Remove the Unix socket or the Windows TCP endpoint marker."""
    socket_path = Path(socket_path)
    if not socket_path.exists():
        return
    if expected_port is not None:
        try:
            marker = endpoint_marker(socket_path)
            if marker is None or marker.get("port") != expected_port or marker.get("pid") != os.getpid():
                return
        except (OSError, ValueError, AttributeError, TypeError):
            return
    socket_path.unlink()
