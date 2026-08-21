# (c) B. Kerler 2026, MIT license
"""Cross-reference tools: xrefs to and from addresses/functions."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_xref
    import ida_funcs
    import ida_name
    import idautils
    import ida_idaapi
    import ida_bytes
    return ida_xref, ida_funcs, ida_name, idautils, ida_idaapi, ida_bytes


def _resolve_address(ctx, target: str) -> int:
    """Resolve a target (function name or hex address) to an EA."""
    try:
        return ctx.resolve_address(target)
    except ValueError:
        pass
    try:
        return ctx.find_function(target)
    except ValueError:
        pass
    # Try as symbol/name
    import ida_name
    import ida_idaapi
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, target)
    if ea != ida_idaapi.BADADDR:
        return ea
    raise ValueError(f"Cannot resolve target '{target}' to an address.")


def _handle_xrefs_to(ctx, args: dict) -> dict:
    _, ida_funcs, _, idautils, ida_idaapi, _ = _ida()

    _ = args.get("binary", "")
    target = args.get("target", "")
    limit = int(args.get("limit", 50))

    if not target:
        raise ValueError("Missing required argument: target")

    addr = _resolve_address(ctx, target)
    xrefs = []

    for ref in idautils.CodeRefsTo(addr, 1):
        if len(xrefs) >= limit:
            break
        from_func = ida_funcs.get_func_start(ref)
        xrefs.append({
            "from_address": f"0x{ref:x}",
            "from_function": ida_funcs.get_func_name(from_func) if from_func != ida_idaapi.BADADDR else None,
            "type": "code",
        })

    for ref in idautils.DataRefsTo(addr):
        if len(xrefs) >= limit:
            break
        from_func = ida_funcs.get_func_start(ref)
        xrefs.append({
            "from_address": f"0x{ref:x}",
            "from_function": ida_funcs.get_func_name(from_func) if from_func != ida_idaapi.BADADDR else None,
            "type": "data",
        })

    return {"xrefs": xrefs, "count": len(xrefs)}


def _handle_xrefs_from(ctx, args: dict) -> dict:
    _, ida_funcs, _, idautils, ida_idaapi, _ = _ida()

    _ = args.get("binary", "")
    target = args.get("target", "")
    limit = int(args.get("limit", 50))
    no_stack = bool(args.get("no_stack", False))

    if not target:
        raise ValueError("Missing required argument: target")

    addr = _resolve_address(ctx, target)
    xrefs = []

    # Check if target is a function
    func_ea = ida_funcs.get_func_start(addr)
    if func_ea != ida_idaapi.BADADDR:
        func_end = func_ea + ida_funcs.calc_func_size_ea(func_ea)
        # Iterate all instructions in the function
        for head in idautils.Heads(func_ea, func_end):
            for ref in idautils.CodeRefsFrom(head, 0):
                if len(xrefs) >= limit:
                    break
                if no_stack and ida_funcs.get_func_start(ref) == ida_idaapi.BADADDR and ref == ida_idaapi.BADADDR:
                    # Heuristic: skip stack references (IDA doesn't have a stack space concept like Ghidra)
                    continue
                to_func = ida_funcs.get_func_start(ref)
                xrefs.append({
                    "from_address": f"0x{head:x}",
                    "to_address": f"0x{ref:x}",
                    "to_function": ida_funcs.get_func_name(to_func) if to_func != ida_idaapi.BADADDR else None,
                    "type": "code",
                })
            for ref in idautils.DataRefsFrom(head):
                if len(xrefs) >= limit:
                    break
                to_func = ida_funcs.get_func_start(ref)
                xrefs.append({
                    "from_address": f"0x{head:x}",
                    "to_address": f"0x{ref:x}",
                    "to_function": ida_funcs.get_func_name(to_func) if to_func != ida_idaapi.BADADDR else None,
                    "type": "data",
                })
            if len(xrefs) >= limit:
                break
    else:
        # Single address lookup
        for ref in idautils.CodeRefsFrom(addr, 0):
            if len(xrefs) >= limit:
                break
            to_func = ida_funcs.get_func_start(ref)
            xrefs.append({
                "from_address": f"0x{addr:x}",
                "to_address": f"0x{ref:x}",
                "to_function": ida_funcs.get_func_name(to_func) if to_func != ida_idaapi.BADADDR else None,
                "type": "code",
            })
        for ref in idautils.DataRefsFrom(addr):
            if len(xrefs) >= limit:
                break
            to_func = ida_funcs.get_func_start(ref)
            xrefs.append({
                "from_address": f"0x{addr:x}",
                "to_address": f"0x{ref:x}",
                "to_function": ida_funcs.get_func_name(to_func) if to_func != ida_idaapi.BADADDR else None,
                "type": "data",
            })

    return {"xrefs": xrefs, "count": len(xrefs)}


register_handler("xrefs_to", _handle_xrefs_to)
register_handler("xrefs_from", _handle_xrefs_from)
