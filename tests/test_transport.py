"""Tests for the platform-specific local RPC transport."""

from __future__ import annotations

import hashlib
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
    socket_path = tmp_path / "中文" / "ida-rpc-test.sock"
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
            response = {"id": request["id"], "ok": True, "result": {"status": "alive", "cmd": request["cmd"]}}
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
        marker = json.loads(socket_path.read_text(encoding="utf-8"))
        assert marker["port"] == server.getsockname()[1]
        assert marker["version"] == 1
    finally:
        server.close()
        transport.remove_endpoint_marker(socket_path)
    thread.join(timeout=2)
    assert not socket_path.exists()


def test_legacy_empty_marker_still_uses_deterministic_port(monkeypatch, tmp_path):
    monkeypatch.setattr(transport, "uses_unix_sockets", lambda: False)
    socket_path = tmp_path / "legacy.sock"
    socket_path.touch()
    digest = hashlib.sha256(str(socket_path).encode("utf-8")).digest()
    expected = 49152 + int.from_bytes(digest[:4], "big") % 16384
    assert transport.endpoint_address(socket_path) == ("127.0.0.1", expected)


def test_stale_marker_is_replaced_after_dynamic_bind(monkeypatch, tmp_path):
    monkeypatch.setattr(transport, "uses_unix_sockets", lambda: False)
    socket_path = tmp_path / "stale.sock"
    socket_path.write_text('{"version": 1, "port": 1, "pid": 999999}\n', encoding="utf-8")
    server = transport.create_server_socket(socket_path)
    try:
        assert transport.endpoint_address(socket_path) == server.getsockname()
    finally:
        server.close()
        transport.remove_endpoint_marker(socket_path)


def test_live_marker_cannot_be_replaced(monkeypatch, tmp_path):
    monkeypatch.setattr(transport, "uses_unix_sockets", lambda: False)
    socket_path = tmp_path / "live.sock"
    server = transport.create_server_socket(socket_path)

    def answer_probe():
        conn, _ = server.accept()
        with conn:
            request = json.loads(conn.recv(4096).decode("utf-8"))
            response = {"id": request["id"], "ok": True, "result": {"status": "alive"}}
            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

    thread = threading.Thread(target=answer_probe, daemon=True)
    thread.start()
    try:
        with pytest.raises(OSError, match="already in use"):
            transport.create_server_socket(socket_path)
        assert transport.endpoint_address(socket_path) == server.getsockname()
    finally:
        server.close()
        transport.remove_endpoint_marker(socket_path)
        thread.join(timeout=2)
