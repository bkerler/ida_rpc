# (c) B. Kerler 2026, MIT license
"""Regression tests for set_comment verification semantics."""

from __future__ import annotations

import sys
import types


class FakeContext:
    def resolve_address(self, address: str) -> int:
        return int(address, 16)

    def run_on_main_thread(self, func):
        return func()

    def save(self):
        pass


def install_fake_ida_modules(monkeypatch):
    comments: dict[tuple[int, int], str] = {}

    ida_bytes = types.SimpleNamespace(
        set_cmt=lambda addr, comment, repeatable: comments.__setitem__((addr, repeatable), comment),
        get_cmt=lambda addr, repeatable: comments.get((addr, repeatable)),
    )
    monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)
    monkeypatch.setitem(sys.modules, "ida_name", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_funcs", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_typeinf", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_idaapi", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "idautils", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "idc", types.SimpleNamespace())
    return comments


def get_set_comment_handler():
    from ida_rpc.server import main as server_main
    from ida_rpc.server.tools import modifications  # noqa: F401

    return server_main._HANDLERS["set_comment"]


def test_repeatable_comment_verifies_against_repeatable_slot(monkeypatch):
    comments = install_fake_ida_modules(monkeypatch)
    handler = get_set_comment_handler()

    result = handler(
        FakeContext(),
        {"address": "0x1000", "comment": "repeat me", "comment_type": "repeatable"},
    )

    assert comments[(0x1000, 1)] == "repeat me"
    assert result["comment"] == "repeat me"
    assert result["verified"] is True


def test_eol_comment_verifies_against_nonrepeatable_slot(monkeypatch):
    comments = install_fake_ida_modules(monkeypatch)
    handler = get_set_comment_handler()

    result = handler(
        FakeContext(),
        {"address": "0x1000", "comment": "plain note", "comment_type": "eol"},
    )

    assert comments[(0x1000, 0)] == "plain note"
    assert result["comment"] == "plain note"
    assert result["verified"] is True
