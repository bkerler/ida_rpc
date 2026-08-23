# (c) B. Kerler 2026, MIT license
"""Unit tests for debugger backend selection and process startup."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ida_rpc.server.tools import debugger


class _ImmediateContext:
    def __init__(self):
        self.dispatched = False

    def run_on_main_thread(self, callback):
        self.dispatched = True
        return callback()


class _FakeDebugger:
    def __init__(self, *, load_result=True, start_result=1, attach_result=1):
        self.load_result = load_result
        self.start_result = start_result
        self.attach_result = attach_result
        self.debugger_on = False
        self.running = False
        self.calls = []
        self.debugger_options = 0

    def load_debugger(self, backend, remote):
        self.calls.append(("load_debugger", backend, remote))
        return self.load_result

    def start_process(self, path, args, sdir):
        self.calls.append(("start_process", path, args, sdir))
        return self.start_result

    def attach_process(self, pid, event_id):
        self.calls.append(("attach_process", pid, event_id))
        return self.attach_result

    def is_debugger_on(self):
        return self.debugger_on

    def wait_for_next_event(self, flags, timeout):
        self.calls.append(("wait_for_next_event", flags, timeout))
        self.debugger_on = True
        self.running = False
        return 1

    def get_process_state(self):
        if self.running:
            return self.DSTATE_RUN
        return self.DSTATE_SUSP if self.debugger_on else self.DSTATE_NOTASK

    def continue_process(self):
        self.calls.append(("continue_process",))
        self.running = True
        return True

    def get_current_thread(self):
        return 1234

    def get_reg_val(self, name):
        return {"RIP": 0x14000146A, "RCX": 9}[name]

    def get_ip_val(self):
        return 0x14000146A

    def get_sp_val(self):
        return 0x12FF00

    def set_debugger_options(self, options):
        previous = self.debugger_options
        self.debugger_options = options
        self.calls.append(("set_debugger_options", options))
        return previous

    WFNE_SUSP = 4
    DOPT_START_BPT = 1
    DOPT_ENTRY_BPT = 2
    DSTATE_SUSP = -1
    DSTATE_NOTASK = 0
    DSTATE_RUN = 1


def _install_fake_debugger(monkeypatch, fake):
    unused = SimpleNamespace()
    monkeypatch.setattr(
        debugger,
        "_ida_dbg",
        lambda: (fake, unused, unused, unused),
    )


def test_select_backend_runs_on_main_thread(monkeypatch):
    fake = _FakeDebugger()
    ctx = _ImmediateContext()
    _install_fake_debugger(monkeypatch, fake)

    result = debugger._handle_debug_select_backend(
        ctx,
        {"backend": "win32", "remote": False},
    )

    assert ctx.dispatched is True
    assert result == {"backend": "win32", "remote": False, "loaded": True}
    assert fake.calls == [("load_debugger", "win32", False)]


def test_select_backend_reports_load_failure(monkeypatch):
    fake = _FakeDebugger(load_result=False)
    _install_fake_debugger(monkeypatch, fake)

    with pytest.raises(RuntimeError, match="Failed to load local debugger backend"):
        debugger._handle_debug_select_backend(
            _ImmediateContext(),
            {"backend": "missing", "remote": False},
        )


def test_start_selects_backend_before_process(monkeypatch):
    fake = _FakeDebugger()
    _install_fake_debugger(monkeypatch, fake)

    result = debugger._handle_debug_start(
        _ImmediateContext(),
        {
            "path": "sample.exe",
            "args": "--value 7",
            "sdir": "C:/sample",
            "backend": "win32",
            "remote": False,
        },
    )

    assert result == {
        "started": 1,
        "path": "sample.exe",
        "backend": "win32",
        "remote": False,
        "loaded": True,
        "suspend_at": "start",
        "debugger_options": fake.DOPT_START_BPT,
        "debugger_on": True,
        "state": "suspended",
        "events": [1],
    }
    assert fake.calls == [
        ("load_debugger", "win32", False),
        ("set_debugger_options", 0),
        ("set_debugger_options", fake.DOPT_START_BPT),
        ("start_process", "sample.exe", "--value 7", "C:/sample"),
        ("wait_for_next_event", fake.WFNE_SUSP, 10),
    ]


@pytest.mark.parametrize("start_result", [-1, 0])
def test_start_reports_ida_failure(monkeypatch, start_result):
    fake = _FakeDebugger(start_result=start_result)
    _install_fake_debugger(monkeypatch, fake)

    with pytest.raises(RuntimeError, match="Debugger process start"):
        debugger._handle_debug_start(
            _ImmediateContext(),
            {"path": "sample.exe"},
        )


def test_attach_selects_remote_backend_before_process(monkeypatch):
    fake = _FakeDebugger()
    _install_fake_debugger(monkeypatch, fake)

    result = debugger._handle_debug_attach(
        _ImmediateContext(),
        {"pid": 1234, "backend": "win32", "remote": True},
    )

    assert result["attached"] == 1
    assert result["backend"] == "win32"
    assert result["remote"] is True
    assert fake.calls == [
        ("load_debugger", "win32", True),
        ("attach_process", 1234, -1),
        ("wait_for_next_event", fake.WFNE_SUSP, 10),
    ]


def test_remote_requires_backend(monkeypatch):
    fake = _FakeDebugger()
    _install_fake_debugger(monkeypatch, fake)

    with pytest.raises(ValueError, match="remote requires"):
        debugger._handle_debug_start(
            _ImmediateContext(),
            {"remote": True},
        )


def test_start_can_suspend_at_entry(monkeypatch):
    fake = _FakeDebugger()
    _install_fake_debugger(monkeypatch, fake)

    result = debugger._handle_debug_start(
        _ImmediateContext(),
        {"path": "sample.exe", "suspend_at": "entry"},
    )

    assert result["suspend_at"] == "entry"
    assert result["debugger_options"] == fake.DOPT_ENTRY_BPT
    assert ("set_debugger_options", fake.DOPT_ENTRY_BPT) in fake.calls


def test_start_clears_old_suspension_options(monkeypatch):
    fake = _FakeDebugger()
    fake.debugger_options = (
        fake.DOPT_START_BPT | fake.DOPT_ENTRY_BPT | 0x100
    )
    _install_fake_debugger(monkeypatch, fake)

    result = debugger._handle_debug_start(
        _ImmediateContext(),
        {"path": "sample.exe", "suspend_at": "start"},
    )

    assert result["debugger_options"] == fake.DOPT_START_BPT | 0x100


@pytest.mark.parametrize(
    ("raw_state", "expected"),
    [(-1, "suspended"), (0, "not_started"), (1, "running")],
)
def test_debugger_state_uses_ida_constants(raw_state, expected):
    fake = _FakeDebugger()
    fake.get_process_state = lambda: raw_state

    assert debugger._debugger_state(fake) == expected


def test_continue_waits_for_next_suspension(monkeypatch):
    fake = _FakeDebugger()
    fake.debugger_on = True
    _install_fake_debugger(monkeypatch, fake)

    result = debugger._handle_debug_continue(
        _ImmediateContext(),
        {"wait_timeout": 3},
    )

    assert result == {
        "continued": True,
        "debugger_on": True,
        "state": "suspended",
        "events": [1],
        "process_exited": False,
    }
    assert fake.calls == [
        ("continue_process",),
        ("wait_for_next_event", fake.WFNE_SUSP, 3),
    ]


def test_get_requested_registers_returns_names_and_core_pointers(monkeypatch):
    fake = _FakeDebugger()
    fake.debugger_on = True
    _install_fake_debugger(monkeypatch, fake)

    result = debugger._handle_debug_get_registers(
        _ImmediateContext(),
        {"registers": ["RIP", "RCX"]},
    )

    assert result == {
        "tid": 1234,
        "instruction_pointer": "0x14000146a",
        "stack_pointer": "0x12ff00",
        "registers": [
            {"name": "RIP", "value": "0x14000146a"},
            {"name": "RCX", "value": "0x9"},
        ],
    }


def test_stack_trace_supports_ida_94_fields(monkeypatch):
    fake = _FakeDebugger()
    fake.debugger_on = True

    def collect_stack_trace(tid, trace):
        trace.append(SimpleNamespace(
            callea=0x14000146A,
            funcea=0x14000146A,
            fp=0x12FF00,
        ))
        return True

    fake.collect_stack_trace = collect_stack_trace
    ida_idd = SimpleNamespace(call_stack_t=list)
    ida_name = SimpleNamespace(get_name=lambda ea: "mix_score")
    monkeypatch.setattr(
        debugger,
        "_ida_dbg",
        lambda: (fake, SimpleNamespace(), ida_idd, ida_name),
    )

    result = debugger._handle_debug_stack_trace(_ImmediateContext(), {})

    assert result["frames"] == [{
        "level": 0,
        "address": "0x14000146a",
        "function_address": "0x14000146a",
        "frame_pointer": "0x12ff00",
        "function": "mix_score",
    }]
