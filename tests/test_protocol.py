# (c) B. Kerler 2026, MIT license
"""Tests for the Unix socket protocol and server dispatch."""

from __future__ import annotations

import json
import socket
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# We need to test the server without IDA, so mock the tool registration
def _make_mock_context():
    """Create a mock context with program info."""
    ctx = MagicMock()
    ctx.get_program.return_value = MagicMock(
        name="test.i64",
        idb_path=Path("/tmp/test.i64"),
        analysis_complete=True,
    )
    # Simulate main-thread dispatch: just call the function directly
    ctx.run_on_main_thread = lambda fn, *a, **kw: fn(*a, **kw)
    return ctx


def _send_request(sock_path: Path, cmd: str, args: dict | None = None) -> dict:
    """Send a raw JSON request and return parsed response."""
    request = {
        "id": str(uuid.uuid4()),
        "cmd": cmd,
        "args": args or {},
    }
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(str(sock_path))
    s.sendall((json.dumps(request) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.decode().strip())


class TestProtocol:
    """Test the wire protocol without needing IDA."""

    @pytest.fixture(autouse=True)
    def setup_server(self, tmp_path):
        """Start a server with mock context in a background thread."""
        # Import and clear any existing handlers
        from ida_rpc.server import main as server_main
        server_main._HANDLERS.clear()

        # Register a test handler
        def echo_handler(ctx, args):
            return {"echo": args}

        server_main.register_handler("echo", echo_handler)

        # Reload modifications so the batch handler is registered in the clean registry
        from ida_rpc.server.tools import modifications
        import importlib
        importlib.reload(modifications)

        self.sock_path = tmp_path / "test.sock"
        from ida_rpc.session import Session
        session = Session(mode="headless", project_idb=tmp_path / "test.i64", socket_path=self.sock_path)

        self.ctx = _make_mock_context()
        self.server_thread = threading.Thread(
            target=server_main.run_server,
            args=(session, self.ctx),
            daemon=True,
        )
        self.server_thread.start()

        # Wait for socket to appear
        deadline = time.time() + 5
        while time.time() < deadline:
            if self.sock_path.exists():
                break
            time.sleep(0.05)
        assert self.sock_path.exists(), "Server socket did not appear"

    def test_ping(self):
        resp = _send_request(self.sock_path, "ping")
        assert resp["ok"] is True
        assert resp["result"]["status"] == "alive"

    def test_echo_handler(self):
        resp = _send_request(self.sock_path, "echo", {"hello": "world"})
        assert resp["ok"] is True
        assert resp["result"]["echo"] == {"hello": "world"}

    def test_unknown_command(self):
        resp = _send_request(self.sock_path, "nonexistent_cmd")
        assert resp["ok"] is False
        assert resp["error"] == "UnknownCommand"

    def test_stop(self):
        resp = _send_request(self.sock_path, "stop")
        assert resp["ok"] is True
        # Server should shut down — give it time to clean up
        deadline = time.time() + 5
        while time.time() < deadline:
            if not self.sock_path.exists():
                break
            time.sleep(0.1)
        assert not self.sock_path.exists()

    def test_invalid_json(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(str(self.sock_path))
        s.sendall(b"not valid json\n")
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        resp = json.loads(buf.decode().strip())
        assert resp["ok"] is False
        assert resp["error"] == "InvalidJSON"

    def test_request_id_echoed(self):
        req_id = "test-id-12345"
        request = {"id": req_id, "cmd": "ping", "args": {}}
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(str(self.sock_path))
        s.sendall((json.dumps(request) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        resp = json.loads(buf.decode().strip())
        assert resp["id"] == req_id

    def test_batch_handler(self):
        resp = _send_request(self.sock_path, "batch", {
            "commands": [
                {"cmd": "echo", "args": {"hello": "world"}},
                {"cmd": "nonexistent_cmd", "args": {}},
                {"cmd": "batch", "args": {"commands": []}},
            ],
        })
        assert resp["ok"] is True
        result = resp["result"]
        assert result["count"] == 3
        assert result["ok_count"] == 1
        assert result["error_count"] == 2

        assert result["results"][0]["ok"] is True
        assert result["results"][0]["cmd"] == "echo"
        assert result["results"][0]["result"] == {"echo": {"hello": "world"}}

        assert result["results"][1]["ok"] is False
        assert result["results"][1]["cmd"] == "nonexistent_cmd"
        assert result["results"][1]["error"] == "UnknownCommand"

        assert result["results"][2]["ok"] is False
        assert result["results"][2]["cmd"] == "batch"
        assert "nested batch" in result["results"][2]["message"].lower()
