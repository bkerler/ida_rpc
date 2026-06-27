# (c) B. Kerler 2026, MIT license
"""Tests for function detail helpers."""

from __future__ import annotations

import types


def test_func_flags_to_list_skips_missing_ida_constants(monkeypatch):
    from ida_rpc.server.tools import function_details

    fake_ida_funcs = types.SimpleNamespace(
        FUNC_NORET=0x1,
        FUNC_LIB=0x4,
        FUNC_SP_READY=0x400,
    )
    monkeypatch.setitem(__import__("sys").modules, "ida_funcs", fake_ida_funcs)

    assert function_details._func_flags_to_list(0x1 | 0x4 | 0x400) == [
        "noreturn",
        "library",
        "sp_ready",
    ]
