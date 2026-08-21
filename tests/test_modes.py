"""GUI/headless execution boundary tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from ida_rpc.session import Session


def test_goto_rejects_headless_before_importing_gui_api():
    from ida_rpc.server.tools.navigation import _handle_goto

    ctx = type("Context", (), {"session": Session("headless", Path("x.i64"), Path("x.sock"))})()
    with pytest.raises(RuntimeError, match="GUI mode"):
        _handle_goto(ctx, {"target": "0x1000", "target_type": "address"})


def test_context_headless_runs_directly():
    from ida_rpc.server import context as context_module

    ctx = context_module.IdaContext(
        Session("headless", Path("x.i64"), Path("x.sock"))
    )
    assert ctx.gui is False
    assert ctx.run_on_main_thread(lambda: 42) == 42
