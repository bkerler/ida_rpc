# (c) B. Kerler 2026, MIT license
"""Debugger control tools: process control, breakpoints, registers, memory, stack trace."""

from __future__ import annotations

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


def _handle_debug_start(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    path = args.get("path", "")
    arglist = args.get("args", "")
    sdir = args.get("sdir", "")

    def do_start():
        res = ida_dbg.start_process(path or None, arglist or None, sdir or None)
        return {"started": res, "path": path or None}

    return ctx.run_on_main_thread(do_start)


def _handle_debug_attach(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    pid = int(args.get("pid", 0))
    if pid <= 0:
        raise ValueError("Missing or invalid required argument: pid")

    def do_attach():
        res = ida_dbg.attach_process(pid, -1)
        return {"attached": res, "pid": pid}

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

    def do_continue():
        res = ida_dbg.continue_process()
        return {"continued": res}

    return ctx.run_on_main_thread(do_continue)


def _handle_debug_suspend(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    def do_suspend():
        res = ida_dbg.suspend_process()
        return {"suspended": res}

    return ctx.run_on_main_thread(do_suspend)


def _handle_debug_step_into(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    def do_step():
        res = ida_dbg.step_into()
        return {"stepped": res}

    return ctx.run_on_main_thread(do_step)


def _handle_debug_step_over(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    def do_step():
        res = ida_dbg.step_over()
        return {"stepped": res}

    return ctx.run_on_main_thread(do_step)


def _handle_debug_run_to(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()
    addr_str = args.get("address", "")
    if not addr_str:
        raise ValueError("Missing required argument: address")
    addr = ctx.resolve_address(addr_str)

    def do_run():
        res = ida_dbg.run_to(addr)
        return {"ran_to": res, "address": f"0x{addr:x}"}

    return ctx.run_on_main_thread(do_run)


def _handle_debug_status(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()

    state = ida_dbg.get_process_state()
    state_map = {
        -1: "not_started",
        0: "running",
        1: "suspended",
    }

    return {
        "state": state_map.get(state, f"unknown({state})"),
        "debugger_on": ida_dbg.is_debugger_on(),
        "debugger_busy": ida_dbg.is_debugger_busy(),
    }


def _handle_debug_get_registers(ctx, args: dict) -> dict:
    ida_dbg, ida_idaapi, ida_idd, ida_name = _ida_dbg()
    _ensure_debugger()

    tid = ida_dbg.get_current_thread()
    regvals = ida_idd.regvals_t()
    ida_dbg.get_reg_vals(tid, 0, regvals)

    registers = []
    for i in range(len(regvals)):
        rv = regvals[i]
        registers.append({
            "index": i,
            "value": f"0x{rv.ival:x}" if rv.rvtype == ida_idd.RVT_INT else str(rv),
        })

    return {"tid": tid, "registers": registers}


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
    buf = bytearray(length)
    nread = ida_dbg.read_dbg_memory(addr, buf, length)
    data = bytes(buf[:nread]) if nread > 0 else b""

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
        fname = ida_name.get_name(entry.ea) or ""
        frames.append({
            "level": i,
            "address": f"0x{entry.ea:x}",
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
