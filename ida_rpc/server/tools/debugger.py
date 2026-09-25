# (c) B. Kerler 2026, MIT license
"""Debugger control tools: process control, breakpoints, registers, memory, stack trace."""

from __future__ import annotations

import math
import time

from ida_rpc.server.main import register_handler


def _ida_dbg():
    import ida_dbg
    import ida_idaapi
    import ida_idd
    import ida_name
    return ida_dbg, ida_idaapi, ida_idd, ida_name


def _ensure_debugger():
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    if not ida_dbg.is_debugger_on():
        raise RuntimeError("Debugger is not active. Start or attach to a process first.")


def _debugger_state(ida_dbg) -> str:
    state = ida_dbg.get_process_state()
    return {
        int(ida_dbg.DSTATE_SUSP): "suspended",
        int(ida_dbg.DSTATE_NOTASK): "not_started",
        int(ida_dbg.DSTATE_RUN): "running",
    }.get(state, f"unknown({state})")


def _wait_for_debugger(
    ida_dbg,
    timeout: int,
    *,
    require_event: bool = False,
    allow_exit: bool = False,
) -> dict:
    if timeout <= 0:
        raise ValueError("wait_timeout must be greater than zero")

    deadline = time.monotonic() + timeout
    events = []
    max_events = 64
    while True:
        debugger_on = bool(ida_dbg.is_debugger_on())
        state = _debugger_state(ida_dbg)
        if not require_event and debugger_on and state == "suspended":
            break
        if not require_event and allow_exit and state == "not_started":
            break

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        event = int(
            ida_dbg.wait_for_next_event(
                ida_dbg.WFNE_SUSP,
                max(1, math.ceil(remaining)),
            )
        )
        events.append(event)
        require_event = False
        if event <= 0:
            break
        if len(events) >= max_events:
            break

    debugger_on = bool(ida_dbg.is_debugger_on())
    state = _debugger_state(ida_dbg)
    process_exited = allow_exit and state == "not_started"
    if (not debugger_on or state != "suspended") and not process_exited:
        raise RuntimeError(
            "IDA accepted the debugger request but the debugger did not become "
            f"active and suspended within {timeout} seconds "
            f"(events={events}, debugger_on={debugger_on}, state={state})."
        )
    result = {
        "debugger_on": debugger_on,
        "state": state,
        "events": events,
    }
    if allow_exit:
        result["process_exited"] = process_exited
    return result


def _select_debugger_backend(ida_dbg, backend: str, remote: bool) -> dict:
    backend = backend.strip()
    if not backend:
        raise ValueError("Missing required argument: backend")
    if not ida_dbg.load_debugger(backend, remote):
        mode = "remote" if remote else "local"
        raise RuntimeError(
            f"Failed to load {mode} debugger backend '{backend}'. "
            "Use the backend's internal IDA name, for example 'win32' on Windows."
        )
    return {"backend": backend, "remote": remote, "loaded": True}


def _configure_initial_suspension(ida_dbg, suspend_at: str) -> dict:
    option_by_mode = {
        "start": ida_dbg.DOPT_START_BPT,
        "entry": ida_dbg.DOPT_ENTRY_BPT,
    }
    if suspend_at not in (*option_by_mode, "none"):
        raise ValueError("suspend_at must be one of: start, entry, none")

    previous = int(ida_dbg.set_debugger_options(0))
    suspend_flags = int(ida_dbg.DOPT_START_BPT) | int(ida_dbg.DOPT_ENTRY_BPT)
    configured = previous & ~suspend_flags
    if suspend_at != "none":
        configured |= int(option_by_mode[suspend_at])
    ida_dbg.set_debugger_options(configured)
    return {
        "suspend_at": suspend_at,
        "debugger_options": configured,
    }


def _handle_debug_select_backend(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    backend = str(args.get("backend", ""))
    remote = bool(args.get("remote", False))

    def do_select():
        return _select_debugger_backend(ida_dbg, backend, remote)

    return ctx.run_on_main_thread(do_select)


def _handle_debug_start(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    path = args.get("path", "")
    arglist = args.get("args", "")
    sdir = args.get("sdir", "")
    backend = str(args.get("backend", "")).strip()
    remote = bool(args.get("remote", False))
    wait_timeout = int(args.get("wait_timeout", 10))
    suspend_at = str(args.get("suspend_at", "start")).strip().lower()
    if remote and not backend:
        raise ValueError("remote requires a debugger backend")

    def do_start():
        selection = (
            _select_debugger_backend(ida_dbg, backend, remote)
            if backend
            else None
        )
        suspension = _configure_initial_suspension(ida_dbg, suspend_at)
        res = ida_dbg.start_process(path or None, arglist or None, sdir or None)
        if res != 1:
            reason = "cancelled" if res == 0 else "failed"
            raise RuntimeError(
                f"Debugger process start {reason} (IDA returned {res}). "
                "Select a compatible backend before starting."
            )
        result = {"started": res, "path": path or None}
        if selection:
            result.update(selection)
        result.update(suspension)
        result.update(_wait_for_debugger(
            ida_dbg,
            wait_timeout,
            require_event=suspend_at == "none",
            allow_exit=suspend_at == "none",
        ))
        return result

    return ctx.run_on_main_thread(do_start)


def _handle_debug_attach(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    pid = int(args.get("pid", 0))
    if pid <= 0:
        raise ValueError("Missing or invalid required argument: pid")
    backend = str(args.get("backend", "")).strip()
    remote = bool(args.get("remote", False))
    wait_timeout = int(args.get("wait_timeout", 10))
    if remote and not backend:
        raise ValueError("remote requires a debugger backend")

    def do_attach():
        selection = (
            _select_debugger_backend(ida_dbg, backend, remote)
            if backend
            else None
        )
        res = ida_dbg.attach_process(pid, -1)
        if res != 1:
            reason = "cancelled" if res == 0 else "failed"
            raise RuntimeError(
                f"Debugger attach {reason} (IDA returned {res}). "
                "Select a compatible backend before attaching."
            )
        result = {"attached": res, "pid": pid}
        if selection:
            result.update(selection)
        result.update(_wait_for_debugger(ida_dbg, wait_timeout))
        return result

    return ctx.run_on_main_thread(do_attach)


def _handle_debug_detach(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()

    def do_detach():
        res = ida_dbg.detach_process()
        return {"detached": res}

    return ctx.run_on_main_thread(do_detach)


def _handle_debug_exit(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()

    def do_exit():
        res = ida_dbg.exit_process()
        return {"exited": res}

    return ctx.run_on_main_thread(do_exit)


def _handle_debug_continue(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()
    wait_timeout = int(args.get("wait_timeout", 10))

    def do_continue():
        res = ida_dbg.continue_process()
        if not res:
            raise RuntimeError("IDA rejected the continue request")
        result = {"continued": bool(res)}
        result.update(_wait_for_debugger(
            ida_dbg,
            wait_timeout,
            require_event=True,
            allow_exit=True,
        ))
        return result

    return ctx.run_on_main_thread(do_continue)


def _handle_debug_suspend(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()
    wait_timeout = int(args.get("wait_timeout", 10))

    def do_suspend():
        res = ida_dbg.suspend_process()
        if not res:
            raise RuntimeError("IDA rejected the suspend request")
        result = {"suspended": bool(res)}
        result.update(_wait_for_debugger(
            ida_dbg,
            wait_timeout,
            require_event=True,
        ))
        return result

    return ctx.run_on_main_thread(do_suspend)


def _handle_debug_step_into(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()
    wait_timeout = int(args.get("wait_timeout", 10))

    def do_step():
        res = ida_dbg.step_into()
        if not res:
            raise RuntimeError("IDA rejected the step-into request")
        result = {"stepped": bool(res)}
        result.update(_wait_for_debugger(
            ida_dbg,
            wait_timeout,
            require_event=True,
            allow_exit=True,
        ))
        return result

    return ctx.run_on_main_thread(do_step)


def _handle_debug_step_over(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()
    wait_timeout = int(args.get("wait_timeout", 10))

    def do_step():
        res = ida_dbg.step_over()
        if not res:
            raise RuntimeError("IDA rejected the step-over request")
        result = {"stepped": bool(res)}
        result.update(_wait_for_debugger(
            ida_dbg,
            wait_timeout,
            require_event=True,
            allow_exit=True,
        ))
        return result

    return ctx.run_on_main_thread(do_step)


def _handle_debug_run_to(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()
    addr_str = args.get("address", "")
    if not addr_str:
        raise ValueError("Missing required argument: address")
    addr = ctx.resolve_address(addr_str)
    wait_timeout = int(args.get("wait_timeout", 10))

    def do_run():
        res = ida_dbg.run_to(addr)
        if not res:
            raise RuntimeError(f"IDA rejected the run-to request for 0x{addr:x}")
        result = {"ran_to": bool(res), "address": f"0x{addr:x}"}
        result.update(_wait_for_debugger(
            ida_dbg,
            wait_timeout,
            require_event=True,
            allow_exit=True,
        ))
        return result

    return ctx.run_on_main_thread(do_run)


def _handle_debug_status(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()

    return {
        "state": _debugger_state(ida_dbg),
        "debugger_on": ida_dbg.is_debugger_on(),
        "debugger_busy": ida_dbg.is_debugger_busy(),
    }


def _handle_debug_get_registers(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    tid = ida_dbg.get_current_thread()
    requested = [str(name).strip() for name in args.get("registers", [])]
    requested = [name for name in requested if name]
    if requested:
        registers = []
        for name in requested:
            value = ida_dbg.get_reg_val(name)
            registers.append({
                "name": name,
                "value": _format_register_value(value),
            })
        return {
            "tid": tid,
            "instruction_pointer": f"0x{int(ida_dbg.get_ip_val()):x}",
            "stack_pointer": f"0x{int(ida_dbg.get_sp_val()):x}",
            "registers": registers,
        }

    try:
        regvals = ida_dbg.get_reg_vals(tid, -1)
    except TypeError:
        # Compatibility with older IDAPython versions that used an output
        # parameter instead of returning regvals_t directly.
        regvals = ida_idd.regvals_t()
        ida_dbg.get_reg_vals(tid, 0, regvals)

    registers = []
    for i in range(len(regvals)):
        rv = regvals[i]
        registers.append({
            "index": i,
            "value": _format_register_value(rv, ida_idd),
        })

    return {
        "tid": tid,
        "instruction_pointer": f"0x{int(ida_dbg.get_ip_val()):x}",
        "stack_pointer": f"0x{int(ida_dbg.get_sp_val()):x}",
        "registers": registers,
    }


def _format_register_value(value, ida_idd=None) -> str:
    if isinstance(value, int):
        return f"0x{value:x}"
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if ida_idd is not None and value.rvtype == ida_idd.RVT_INT:
        return f"0x{value.ival:x}"
    if ida_idd is not None and value.rvtype == ida_idd.RVT_UNAVAILABLE:
        return "unavailable"
    return "custom"


def _handle_debug_set_register(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    regname = args.get("register", "")
    value = int(args.get("value", 0))
    if not regname:
        raise ValueError("Missing required argument: register")

    def do_set():
        ida_dbg.set_reg_val(regname, value)
        return {"register": regname, "value": f"0x{value:x}"}

    return ctx.run_on_main_thread(do_set)


def _handle_debug_read_memory(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    addr_str = args.get("address", "")
    length = int(args.get("length", 0))
    if not addr_str:
        raise ValueError("Missing required argument: address")
    if length <= 0 or length > 65536:
        raise ValueError("length must be between 1 and 65536")

    addr = ctx.resolve_address(addr_str)
    data = ida_idd.dbg_read_memory(addr, length)
    if data is None:
        raise RuntimeError(
            f"Failed to read {length} bytes of debugger memory at 0x{addr:x}"
        )
    data = bytes(data)

    return {
        "address": f"0x{addr:x}",
        "length": len(data),
        "hex": data.hex(),
    }


def _handle_debug_write_memory(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    addr_str = args.get("address", "")
    hex_str = args.get("hex", "")
    if not addr_str:
        raise ValueError("Missing required argument: address")
    if not hex_str:
        raise ValueError("Missing required argument: hex")

    addr = ctx.resolve_address(addr_str)
    hex_clean = hex_str.replace(" ", "").strip()
    data = bytes.fromhex(hex_clean)

    def do_write():
        nwritten = ida_dbg.write_dbg_memory(addr, data)
        return {
            "address": f"0x{addr:x}",
            "length": len(data),
            "written": nwritten,
        }

    return ctx.run_on_main_thread(do_write)


def _handle_debug_breakpoints(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    bpts = []
    qty = ida_dbg.get_bpt_qty()
    for i in range(qty):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt):
            bpts.append({
                "address": f"0x{bpt.ea:x}",
                "enabled": bpt.flags & ida_dbg.BPT_ENABLED != 0,
                "type": str(bpt.type),
                "size": bpt.size,
            })

    return {"breakpoints": bpts, "count": len(bpts)}


def _handle_debug_add_breakpoint(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    addr_str = args.get("address", "")
    if not addr_str:
        raise ValueError("Missing required argument: address")
    addr = ctx.resolve_address(addr_str)

    def do_add():
        res = ida_dbg.add_bpt(addr)
        return {"added": res, "address": f"0x{addr:x}"}

    return ctx.run_on_main_thread(do_add)


def _handle_debug_delete_breakpoint(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    addr_str = args.get("address", "")
    if not addr_str:
        raise ValueError("Missing required argument: address")
    addr = ctx.resolve_address(addr_str)

    def do_del():
        res = ida_dbg.del_bpt(addr)
        return {"deleted": res, "address": f"0x{addr:x}"}

    return ctx.run_on_main_thread(do_del)


def _handle_debug_enable_breakpoint(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    addr_str = args.get("address", "")
    enabled = bool(args.get("enabled", True))
    if not addr_str:
        raise ValueError("Missing required argument: address")
    addr = ctx.resolve_address(addr_str)

    def do_enable():
        if enabled:
            res = ida_dbg.enable_bpt(addr)
        else:
            res = ida_dbg.disable_bpt(addr)
        return {"address": f"0x{addr:x}", "enabled": enabled, "changed": res}

    return ctx.run_on_main_thread(do_enable)


def _handle_debug_stack_trace(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    tid = ida_dbg.get_current_thread()
    trace = ida_idd.call_stack_t()
    ida_dbg.collect_stack_trace(tid, trace)

    frames = []
    for i in range(len(trace)):
        entry = trace[i]
        call_address = int(getattr(entry, "callea", getattr(entry, "ea", 0)))
        function_address = int(getattr(entry, "funcea", call_address))
        fname = ida_name.get_name(function_address) or ""
        frames.append({
            "level": i,
            "address": f"0x{call_address:x}",
            "function_address": f"0x{function_address:x}",
            "frame_pointer": f"0x{int(getattr(entry, 'fp', 0)):x}",
            "function": fname,
        })

    return {"tid": tid, "frames": frames, "count": len(frames)}


def _handle_debug_modules(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    modinfo = ida_idd.modinfo_t()
    modules = []
    ok = ida_dbg.get_first_module(modinfo)
    while ok:
        modules.append({
            "name": modinfo.name or "",
            "base": f"0x{modinfo.base:x}",
            "size": modinfo.size,
        })
        ok = ida_dbg.get_next_module(modinfo)

    return {"modules": modules, "count": len(modules)}


def _handle_debug_threads(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    threads = []
    qty = ida_dbg.get_thread_qty()
    for i in range(qty):
        tid = ida_dbg.getn_thread(i)
        name = ida_dbg.getn_thread_name(i) or ""
        threads.append({
            "tid": tid,
            "name": name,
        })

    return {"threads": threads, "count": len(threads)}


register_handler("debug_select_backend", _handle_debug_select_backend)
register_handler("debug_start", _handle_debug_start)
register_handler("debug_attach", _handle_debug_attach)
register_handler("debug_detach", _handle_debug_detach)
register_handler("debug_exit", _handle_debug_exit)
register_handler("debug_continue", _handle_debug_continue)
register_handler("debug_suspend", _handle_debug_suspend)
register_handler("debug_step_into", _handle_debug_step_into)
register_handler("debug_step_over", _handle_debug_step_over)
register_handler("debug_run_to", _handle_debug_run_to)
register_handler("debug_status", _handle_debug_status)
register_handler("debug_get_registers", _handle_debug_get_registers)
register_handler("debug_set_register", _handle_debug_set_register)
register_handler("debug_read_memory", _handle_debug_read_memory)
register_handler("debug_write_memory", _handle_debug_write_memory)
register_handler("debug_breakpoints", _handle_debug_breakpoints)
register_handler("debug_add_breakpoint", _handle_debug_add_breakpoint)
register_handler("debug_delete_breakpoint", _handle_debug_delete_breakpoint)
register_handler("debug_enable_breakpoint", _handle_debug_enable_breakpoint)
register_handler("debug_stack_trace", _handle_debug_stack_trace)
register_handler("debug_modules", _handle_debug_modules)
register_handler("debug_threads", _handle_debug_threads)
