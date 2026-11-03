"""Tests for the platform-specific local RPC transport."""

from __future__ import annotations

import json
import socket
import threading

import pytest

from ida_rpc import transport
from ida_rpc.client import send_request


def test_forced_tcp_transport(monkeypatch, tmp_path):
    monkeypatch.setenv("IDA_RPC_TRANSPORT", "tcp")
    path = tmp_path / "forced.sock"
    server = transport.create_server_socket(path)
    try:
        assert isinstance(transport.endpoint_address(path), tuple)
        assert path.exists()
    finally:
        server.close()
        transport.remove_endpoint_marker(path)


def test_codex_launcher_sets_loopback_transport(monkeypatch):
    from ida_rpc import codex

    call = {}
    monkeypatch.setattr(codex.os, "execvp", lambda file, args: call.update(file=file, args=args))
    monkeypatch.setattr(codex.sys, "argv", ["ida-rpc-codex", "--help"])
    codex.main()
    assert call["file"] == "codex"
    assert 'shell_environment_policy.set.IDA_RPC_TRANSPORT="tcp"' in call["args"]
    assert 'features.network_proxy={enabled=true,domains={"127.0.0.1"="allow"}}' in call["args"]
    assert call["args"][call["args"].index("--add-dir") + 1].endswith(".idapro")
    assert call["args"][-1] == "--help"


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="requires Unix sockets")
def test_forced_tcp_keeps_existing_unix_socket(monkeypatch, tmp_path):
    path = tmp_path / "existing.sock"
    existing = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        existing.bind(str(path))
        monkeypatch.setenv("IDA_RPC_TRANSPORT", "tcp")
        with pytest.raises(RuntimeError, match="Unix daemon already owns"):
            transport.create_server_socket(path)
        assert path.is_socket()
    finally:
        existing.close()
        path.unlink(missing_ok=True)


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
