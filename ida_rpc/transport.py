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
import os
import socket
from pathlib import Path


TCP_HOST = "127.0.0.1"
_TCP_PORT_MIN = 49152
_TCP_PORT_COUNT = 16384


def uses_unix_sockets() -> bool:
    """Return whether the current platform should use Unix sockets."""
    return os.name != "nt" and hasattr(socket, "AF_UNIX")


def endpoint_address(socket_path: Path) -> str | tuple[str, int]:
    """Return the address accepted by ``socket.bind``/``socket.connect``."""
    if uses_unix_sockets():
        return str(socket_path)
    digest = hashlib.sha256(str(socket_path).encode("utf-8")).digest()
    port = _TCP_PORT_MIN + int.from_bytes(digest[:4], "big") % _TCP_PORT_COUNT
    return TCP_HOST, port


def create_server_socket(socket_path: Path) -> socket.socket:
    """Create, bind, and listen on the platform's local RPC endpoint."""
    socket_path = Path(socket_path)
    if socket_path.exists():
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
        server_sock.bind(endpoint_address(socket_path))
        server_sock.listen(64)
    except Exception:
        server_sock.close()
        raise

    # TCP has no filesystem endpoint.  The marker makes startup polling,
    # status, list, and cleanup behave consistently on every OS.
    if not uses_unix_sockets():
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        socket_path.touch()
    return server_sock


def remove_endpoint_marker(socket_path: Path) -> None:
    """Remove the Unix socket or the Windows TCP endpoint marker."""
    socket_path = Path(socket_path)
    if socket_path.exists():
        socket_path.unlink()
