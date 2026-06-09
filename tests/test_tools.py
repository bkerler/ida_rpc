# (c) B. Kerler 2026, MIT license
"""Integration tests for ida-rpc tool handlers via live daemon.

These tests communicate with a running ida-rpc daemon over its Unix socket.
They do NOT import IDA modules directly — everything goes through the RPC client.

To run these tests:

    # 1. Start a headless daemon with a test binary
    ida-rpc start /tmp/test_binary --headless --detach

    # 2. Run the tests (they auto-detect the socket)
    pytest tests/test_tools.py -v

Or point to a different project:

    IDA_RPC_TEST_PROJECT=/path/to/my.i64 pytest tests/test_tools.py -v

If no daemon is running, tests are skipped automatically.
"""

from __future__ import annotations

import os
import pytest
from pathlib import Path

from ida_rpc.client import send_request, DaemonNotRunning
from ida_rpc.session import socket_path_for_project


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

TEST_PROJECT = Path(os.environ.get("IDA_RPC_TEST_PROJECT", "/tmp/test_binary.i64"))


def _daemon_available() -> bool:
    """Return True if a daemon is listening on the expected socket."""
    sock = socket_path_for_project(TEST_PROJECT)
    if not sock.exists():
        return False
    try:
        send_request(sock, "ping", {})
        return True
    except DaemonNotRunning:
        return False


@pytest.fixture(scope="module")
def rpc_client():
    """Yield a callable that sends RPC commands to the test daemon.

    Skips the entire module if no daemon is available.
    """
    if not _daemon_available():
        pytest.skip(
            f"No ida-rpc daemon found for {TEST_PROJECT}. "
            f"Start one with: ida-rpc start {TEST_PROJECT} --headless --detach"
        )

    sock = socket_path_for_project(TEST_PROJECT)

    def _call(cmd: str, args: dict | None = None) -> dict:
        resp = send_request(sock, cmd, args or {})
        return resp.get("result", {})

    return _call


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestToolsIntegration:
    """Integration tests that exercise handlers through the live daemon."""

    def test_functions_list(self, rpc_client):
        """functions handler returns a list of functions."""
        result = rpc_client("functions", {"limit": 10})
        assert "functions" in result
        assert "count" in result
        assert isinstance(result["functions"], list)
        assert len(result["functions"]) <= 10

    def test_metadata(self, rpc_client):
        """metadata handler returns binary info."""
        result = rpc_client("metadata")
        assert "name" in result
        assert "arch" in result
        assert "bits" in result
        assert result["bits"] in (32, 64)

    def test_decompile(self, rpc_client):
        """decompile handler returns C code for a known function."""
        result = rpc_client("decompile", {"func": "main"})
        assert "c_code" in result
        assert "address" in result
        assert "main" in result.get("name", "main").lower()

    def test_memory_map(self, rpc_client):
        """memory_map handler returns segments."""
        result = rpc_client("memory_map")
        assert "segments" in result
        assert "count" in result
        assert isinstance(result["segments"], list)
