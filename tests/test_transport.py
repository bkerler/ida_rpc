"""Tests for the platform-specific local RPC transport."""

from __future__ import annotations

import json
import threading

from ida_rpc import transport
from ida_rpc.client import send_request


def test_loopback_tcp_fallback(monkeypatch, tmp_path):
    """The Windows fallback works even when AF_UNIX is unavailable."""
    monkeypatch.setattr(transport, "uses_unix_sockets", lambda: False)
    socket_path = tmp_path / "ida-rpc-test.sock"
    server = transport.create_server_socket(socket_path)

    def serve_one():
        conn, _ = server.accept()
        try:
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            request = json.loads(data.decode().strip())
            response = {"id": request["id"], "ok": True, "result": {"cmd": request["cmd"]}}
            conn.sendall((json.dumps(response) + "\n").encode())
        finally:
            conn.close()

    thread = threading.Thread(target=serve_one, daemon=True)
    thread.start()
    try:
        result = send_request(socket_path, "ping")
        assert result["result"]["cmd"] == "ping"
        assert isinstance(transport.endpoint_address(socket_path), tuple)
        assert socket_path.exists()  # TCP has no socket file; this is its marker.
    finally:
        server.close()
        transport.remove_endpoint_marker(socket_path)
    thread.join(timeout=2)
    assert not socket_path.exists()
