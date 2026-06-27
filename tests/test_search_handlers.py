# (c) B. Kerler 2026, MIT license
"""Unit tests for search handlers that can run without IDA."""

from __future__ import annotations

import sys
import types

from ida_rpc.server.tools import search


class _FakeString:
    def __init__(self, ea: int, value: str):
        self.ea = ea
        self._value = value
        self.strtype = 0

    def __str__(self) -> str:
        return self._value


class _FakeStrings:
    def __init__(self, _default_setup: bool):
        self._items = [
            _FakeString(0x1000, "first boot string"),
            _FakeString(0x2000, "remap control"),
            _FakeString(0x3000, "BOOTROM alias"),
        ]

    def setup(self, *, strtypes):
        self.strtypes = strtypes

    def __iter__(self):
        return iter(self._items)


class _FakeContext:
    def resolve_address(self, address: str) -> int:
        return int(address, 0)


def test_find_string_uses_string_list_filtering(monkeypatch):
    fake_idautils = types.SimpleNamespace(Strings=_FakeStrings)
    fake_ida_nalt = types.SimpleNamespace(STRTYPE_C=0, STRTYPE_C_16=1)
    monkeypatch.setitem(sys.modules, "idautils", fake_idautils)
    monkeypatch.setitem(sys.modules, "ida_nalt", fake_ida_nalt)

    result = search._handle_find_string(
        _FakeContext(),
        {"query": "boot", "address": "0x2000", "limit": 10},
    )

    assert result == {
        "query": "boot",
        "matches": [{"address": "0x3000", "text": "BOOTROM alias"}],
        "count": 1,
    }
