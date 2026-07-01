# (c) B. Kerler 2026, MIT license
"""Tests for the client module."""

from __future__ import annotations

import json
import socket
import threading
import time
import uuid
from pathlib import Path

import pytest

from ida_rpc.client import DaemonError, DaemonNotRunning, send_request, send_request_with_auto_restart
from ida_rpc.client import (
    _DEFAULT_SOCKET_TIMEOUT,
    _SOCKET_TIMEOUT_BUFFER,
    _derive_socket_timeout,
)


class TestClient:
    """Test client send_request against a simple echo server."""

    @pytest.fixture(autouse=True)
    def setup_echo_server(self, tmp_path):
        self.sock_path = tmp_path / "echo.sock"

        def echo_server():
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(self.sock_path))
            srv.listen(5)
            srv.settimeout(5)
            try:
                while True:
                    try:
                        conn, _ = srv.accept()
                    except socket.timeout:
                        continue
                    buf = b""
                    while b"\n" not in buf:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        buf += chunk
                    if buf.strip():
                        req = json.loads(buf.decode().strip())
                        resp = {"id": req.get("id"), "ok": True, "result": {"cmd": req["cmd"]}}
                        conn.sendall((json.dumps(resp) + "\n").encode())
                    conn.close()
            except Exception:
                pass
            finally:
                srv.close()

        self.server_thread = threading.Thread(target=echo_server, daemon=True)
        self.server_thread.start()
        deadline = time.time() + 5
        while time.time() < deadline:
            if self.sock_path.exists():
                break
            time.sleep(0.05)

    def test_send_request_success(self):
        result = send_request(self.sock_path, "test_cmd")
        assert result["ok"] is True
        assert result["result"]["cmd"] == "test_cmd"

    def test_send_request_socket_missing(self, tmp_path):
        with pytest.raises(DaemonNotRunning):
            send_request(tmp_path / "nonexistent.sock", "test")

    def test_explicit_socket_timeout_is_respected(self):
        """socket_timeout kwarg is forwarded to the underlying socket."""
        import socket as _socket
        recorded = []
        orig_settimeout = _socket.socket.settimeout

        def fake_settimeout(self, t):
            recorded.append(t)
            orig_settimeout(self, t)

        _socket.socket.settimeout = fake_settimeout
        try:
            send_request(self.sock_path, "test_cmd", socket_timeout=42.0)
        finally:
            _socket.socket.settimeout = orig_settimeout

        assert 42.0 in recorded


class TestDeriveSocketTimeout:
    """Unit tests for the socket-timeout derivation logic."""

    def test_no_args_returns_default(self):
        assert _derive_socket_timeout(None) == _DEFAULT_SOCKET_TIMEOUT
        assert _derive_socket_timeout({}) == _DEFAULT_SOCKET_TIMEOUT
        assert _derive_socket_timeout({"binary": "ls"}) == _DEFAULT_SOCKET_TIMEOUT

    def test_timeout_arg_adds_buffer(self):
        result = _derive_socket_timeout({"timeout": 180})
        assert result == 180 + _SOCKET_TIMEOUT_BUFFER

    def test_analysis_timeout_arg_adds_buffer(self):
        result = _derive_socket_timeout({"analysis_timeout": 300})
        assert result == 300 + _SOCKET_TIMEOUT_BUFFER

    def test_takes_max_when_both_present(self):
        result = _derive_socket_timeout({"timeout": 60, "analysis_timeout": 300})
        assert result == 300 + _SOCKET_TIMEOUT_BUFFER

    def test_default_is_at_least_120(self):
        # Regression guard: default must not shrink below 2 minutes.
        assert _DEFAULT_SOCKET_TIMEOUT >= 120.0

    def test_buffer_is_positive(self):
        assert _SOCKET_TIMEOUT_BUFFER > 0

    def test_small_op_timeout_still_exceeds_default(self):
        # A decompile --timeout 5 should still give a reasonable socket window.
        result = _derive_socket_timeout({"timeout": 5})
        assert result == 5 + _SOCKET_TIMEOUT_BUFFER


class TestAutoRestart:
    """Regression tests for command-driven daemon startup."""

    def test_existing_project_without_session_does_not_require_arch(self, tmp_path, monkeypatch):
        project = tmp_path / "sample.i64"
        project.write_bytes(b"existing idb")
        captured = {}

        def fake_send_request(sock_path, cmd, args=None, *, socket_timeout=None):
            if "started" not in captured:
                captured["started"] = False
                raise DaemonNotRunning("missing")
            return {"ok": True, "result": {"cmd": cmd}}

        def fake_start_background(session):
            captured["session"] = session
            captured["started"] = True

        monkeypatch.setattr("ida_rpc.client.send_request", fake_send_request)
        monkeypatch.setattr("ida_rpc.daemon.start_background", fake_start_background)

        result = send_request_with_auto_restart(project, "metadata", {})

        assert result["ok"] is True
        assert captured["session"].project_idb == project.resolve()
        assert captured["session"].arch is None
        assert captured["session"].mode == "headless"

    def test_existing_project_restart_error_omits_arch(self, tmp_path, monkeypatch):
        project = tmp_path / "sample.i64"
        project.write_bytes(b"existing idb")

        def fake_send_request(sock_path, cmd, args=None, *, socket_timeout=None):
            raise DaemonNotRunning("missing")

        def fake_start_background(session):
            raise RuntimeError("boom")

        monkeypatch.setattr("ida_rpc.client.send_request", fake_send_request)
        monkeypatch.setattr("ida_rpc.daemon.start_background", fake_start_background)

        with pytest.raises(DaemonNotRunning) as exc:
            send_request_with_auto_restart(project, "metadata", {})

        message = str(exc.value)
        assert f"ida-rpc start --project {project.resolve()}" in message
        assert "--arch" not in message

    def test_missing_project_still_requires_arch(self, tmp_path, monkeypatch):
        project = tmp_path / "sample.i64"

        def fake_send_request(sock_path, cmd, args=None, *, socket_timeout=None):
            raise DaemonNotRunning("missing")

        monkeypatch.setattr("ida_rpc.client.send_request", fake_send_request)

        with pytest.raises(DaemonNotRunning) as exc:
            send_request_with_auto_restart(project, "metadata", {})

        assert "--arch <arch>" in str(exc.value)


class TestSession:
    """Test session persistence."""

    def test_socket_path_deterministic(self):
        from ida_rpc.session import socket_path_for_project
        p = Path("/tmp/test.i64")
        a = socket_path_for_project(p)
        b = socket_path_for_project(p)
        assert a == b
        assert str(a).startswith("/tmp/ida-rpc-")
        assert str(a).endswith(".sock")

    def test_save_and_load(self, tmp_path):
        from ida_rpc.session import Session, save, load
        idb = tmp_path / "test.i64"
        idb.touch()
        session = Session(
            mode="headless",
            project_idb=idb,
            socket_path=Path("/tmp/test.sock"),
            ida_install_dir=Path("/opt/ida"),
        )
        save(session)

        # Session file should now be written alongside the .i64 file
        session_files = list(tmp_path.glob(".ida-rpc-*.json"))
        assert len(session_files) == 1, "Expected exactly one session file next to .i64"

        loaded = load(idb)
        assert loaded is not None
        assert loaded.mode == "headless"
        assert loaded.project_idb == idb.resolve()
        assert loaded.ida_install_dir == Path("/opt/ida")

    def test_save_and_load_no_ida_dir(self, tmp_path):
        from ida_rpc.session import Session, save, load
        idb = tmp_path / "test.i64"
        idb.touch()
        session = Session(mode="gui", project_idb=idb, socket_path=Path("/tmp/s.sock"))
        save(session)
        loaded = load(idb)
        assert loaded is not None
        assert loaded.ida_install_dir is None

    def test_state_dir_env_var(self, tmp_path, monkeypatch):
        from ida_rpc.session import session_file_path
        custom_dir = tmp_path / "custom-state"
        custom_dir.mkdir()
        monkeypatch.setenv("IDA_RPC_STATE_DIR", str(custom_dir))
        idb = tmp_path / "test.i64"
        path = session_file_path(idb)
        assert path.parent == custom_dir

    def test_load_missing(self, tmp_path):
        from ida_rpc.session import load
        assert load(tmp_path / "nonexistent.i64") is None
