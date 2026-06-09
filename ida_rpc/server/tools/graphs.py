# (c) B. Kerler 2026, MIT license
"""Graph export tools: function CFG and call graphs as GDL."""

from __future__ import annotations

import os
import tempfile

from ida_rpc.server.main import register_handler


def _ida():
    import ida_gdl
    import ida_funcs
    import ida_idaapi
    return ida_gdl, ida_funcs, ida_idaapi


def _handle_function_graph(ctx, args: dict) -> dict:
    ida_gdl, ida_funcs, ida_idaapi = _ida()

    func_name = args.get("func", "")
    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = ctx.find_function(func_name)
    func = ida_funcs.get_func(func_ea)
    if func is None:
        raise ValueError(f"Function not found at 0x{func_ea:x}")

    # Generate to a temp file and read back
    fd, path = tempfile.mkstemp(suffix=".gdl")
    os.close(fd)
    try:
        title = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
        res = ida_gdl.gen_flow_graph(path, title, func, func.start_ea, func.end_ea, 0)
        if not res:
            raise RuntimeError("Failed to generate function graph")
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            gdl = f.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    return {
        "name": title,
        "address": f"0x{func_ea:x}",
        "format": "gdl",
        "content": gdl,
    }


def _handle_call_graph(ctx, args: dict) -> dict:
    ida_gdl, ida_funcs, ida_idaapi = _ida()

    mode = args.get("mode", "simple")
    title = args.get("title", "call_graph")

    fd, path = tempfile.mkstemp(suffix=".gdl")
    os.close(fd)
    try:
        if mode == "simple":
            res = ida_gdl.gen_simple_call_chart(path, False, title, 0)
        else:
            res = ida_gdl.gen_complex_call_chart(path, False, title, 0, 0, 0)
        if not res:
            raise RuntimeError("Failed to generate call graph")
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            gdl = f.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    return {
        "mode": mode,
        "format": "gdl",
        "content": gdl,
    }


register_handler("function_graph", _handle_function_graph)
register_handler("call_graph", _handle_call_graph)
