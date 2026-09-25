"""Unit tests for memory handlers that do not need a live IDA session."""

from __future__ import annotations

import sys
import types

from ida_rpc.server.tools import memory


class _Context:
    def resolve_address(self, address: str) -> int:
        return int(address, 0)


def test_read_string_returns_empty_for_undefined_item(monkeypatch):
    calls = []
    fake_bytes = types.SimpleNamespace(
        get_item_size=lambda address: 0,
        get_strlit_contents=lambda *args: calls.append(args),
    )
    fake_idaapi = types.SimpleNamespace(BADADDR=-1)
    fake_nalt = types.SimpleNamespace(
        get_str_type=lambda address: fake_idaapi.BADADDR,
        STRTYPE_C=0,
    )
    monkeypatch.setitem(sys.modules, "ida_bytes", fake_bytes)
    monkeypatch.setitem(sys.modules, "ida_segment", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_ida", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_idaapi", fake_idaapi)
    monkeypatch.setitem(sys.modules, "idautils", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_nalt", fake_nalt)

    result = memory._handle_read_string(_Context(), {"address": "0x1000"})

    assert result == {
        "address": "0x1000",
        "text": None,
        "bytes": None,
        "length": 0,
        "strtype": "0x0",
    }
    assert calls == []


def test_read_string_falls_back_when_ida_rejects_inferred_type(monkeypatch):
    calls = []

    def get_strlit_contents(*args):
        calls.append(args)
        if len(calls) == 1:
            raise TypeError("invalid inferred string type")

    fake_bytes = types.SimpleNamespace(
        get_item_size=lambda address: 4,
        get_strlit_contents=get_strlit_contents,
    )
    fake_idaapi = types.SimpleNamespace(BADADDR=0xFFFFFFFFFFFFFFFF)
    fake_nalt = types.SimpleNamespace(
        get_str_type=lambda address: 0x1234,
        STRTYPE_C=0,
    )
    monkeypatch.setitem(sys.modules, "ida_bytes", fake_bytes)
    monkeypatch.setitem(sys.modules, "ida_segment", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_ida", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_idaapi", fake_idaapi)
    monkeypatch.setitem(sys.modules, "idautils", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_nalt", fake_nalt)

    result = memory._handle_read_string(_Context(), {"address": "0x1000"})

    assert result["text"] is None
    assert result["length"] == 0
    assert calls == [(0x1000, 4, 0x1234), (0x1000, 4, 0)]
