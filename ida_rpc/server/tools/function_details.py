# (c) B. Kerler 2026, MIT license
"""Rich function introspection: metadata, items, chunks, colors."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_funcs
    import ida_frame
    import ida_typeinf
    import ida_nalt
    import ida_idaapi
    import idautils
    import ida_bytes
    return ida_funcs, ida_frame, ida_typeinf, ida_nalt, ida_idaapi, idautils, ida_bytes


def _func_flags_to_list(flags: int) -> list[str]:
    import ida_funcs
    names = []
    mapping = (
        ("FUNC_NORET", "noreturn"),
        ("FUNC_FAR", "far"),
        ("FUNC_LIB", "library"),
        ("FUNC_STATIC", "static"),
        ("FUNC_FRAME", "frame"),
        ("FUNC_USERFAR", "userfar"),
        ("FUNC_HIDDEN", "hidden"),
        ("FUNC_THUNK", "thunk"),
        ("FUNC_BOTTOMBP", "bottombp"),
        ("FUNC_NORET_PENDING", "noreturn_pending"),
        ("FUNC_SP_READY", "sp_ready"),
        ("FUNC_PURGED_OK", "purged_ok"),
        ("FUNC_TAIL", "tail"),
    )
    for attr, name in mapping:
        bit = getattr(ida_funcs, attr, 0)
        if flags & bit:
            names.append(name)
    return names


def _iter_function_tails(ida_funcs, func):
    import ida_range
    tails = ida_range.rangevec_t()
    if not ida_funcs.get_func_tails(tails, func):
        return
    for tail in tails:
        yield tail


def _handle_function_info(ctx, args: dict) -> dict:
    ida_funcs, ida_frame, ida_typeinf, ida_nalt, ida_idaapi, idautils, ida_bytes = _ida()

    func_name = args.get("func", "")
    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = ctx.find_function(func_name)
    if ida_funcs.get_func_start(func_ea) == ida_idaapi.BADADDR:
        raise ValueError(f"Function not found at 0x{func_ea:x}")

    # Basic info
    name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
    flags_list = _func_flags_to_list(ida_funcs.get_func_flags(func_ea))

    # Frame info
    frame_size = 0
    ret_size = 0
    try:
        frame_size = ida_frame.get_frame_size_ea(func_ea)
        ret_size = ida_frame.get_frame_retsize_ea(func_ea)
    except Exception:
        pass

    # Prototype
    prototype = None
    try:
        tif = ida_typeinf.tinfo_t()
        if ida_funcs.get_func_type(func_ea, tif):
            prototype = ida_typeinf.print_tinfo(None, 0, 0, ida_typeinf.PRTYPE_1LINE, tif, None, None)
    except Exception:
        pass
    if not prototype:
        try:
            import ida_hexrays

            if ida_hexrays.init_hexrays_plugin():
                cfunc = ida_hexrays.decompile_function(func_ea)
                if cfunc is not None:
                    prototype = str(cfunc.type) or None
        except Exception:
            pass

    # Color
    color = None
    try:
        c = ida_nalt.get_item_color(func_ea)
        if c != ida_idaapi.DEFCOLOR:
            color = f"0x{c:08x}"
    except Exception:
        pass

    # Chunks
    chunks = []
    chunks.append({
        "start": f"0x{func_ea:x}",
        "end": f"0x{func_ea + ida_funcs.calc_func_size_ea(func_ea) - 1:x}",
        "owner": name,
        "primary": True,
    })
    for tail in _iter_function_tails(ida_funcs, func_ea):
        chunks.append({
            "start": f"0x{tail.start_ea:x}",
            "end": f"0x{tail.end_ea - 1:x}",
            "owner": name,
            "primary": False,
        })

    # Register arguments (regargs)
    regargs = []
    try:
        for i in range(ida_funcs.get_func_regarg_qty(func_ea)):
            ra = ida_funcs.regarg_t()
            if not ida_funcs.get_func_regarg(ra, func_ea, i):
                continue
            if ra:
                regargs.append({
                    "name": ra.name or "",
                    "reg": ra.reg,
                })
    except Exception:
        pass

    return {
        "name": name,
        "address": f"0x{func_ea:x}",
        "flags": flags_list,
        "size": ida_funcs.calc_func_size_ea(func_ea),
        "frame_size": frame_size,
        "ret_size": ret_size,
        "prototype": prototype,
        "color": color,
        "chunks": chunks,
        "regargs": regargs,
        "fixed_spd": bool(ida_funcs.get_func_flags(func_ea) & ida_funcs.FUNC_SP_READY),
    }


def _handle_function_items(ctx, args: dict) -> dict:
    ida_funcs, _, _, _, ida_idaapi, idautils, ida_bytes = _ida()

    func_name = args.get("func", "")
    if not func_name:
        raise ValueError("Missing required argument: func")

    limit = int(args.get("limit", 5000))

    func_ea = ctx.find_function(func_name)
    if ida_funcs.get_func_start(func_ea) == ida_idaapi.BADADDR:
        raise ValueError(f"Function not found at 0x{func_ea:x}")

    items = []
    for head in idautils.FuncItems(func_ea):
        if len(items) >= limit:
            break
        flags = ida_bytes.get_flags(head)
        item_type = "unknown"
        if ida_bytes.is_code(flags):
            item_type = "code"
        elif ida_bytes.is_data(flags):
            item_type = "data"
        elif ida_bytes.is_unknown(flags):
            item_type = "unknown"
        items.append({
            "address": f"0x{head:x}",
            "size": ida_bytes.get_item_size(head),
            "type": item_type,
        })

    return {
        "name": ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}",
        "address": f"0x{func_ea:x}",
        "items": items,
        "count": len(items),
    }


def _handle_function_chunks(ctx, args: dict) -> dict:
    ida_funcs, _, _, _, ida_idaapi, _, _ = _ida()

    func_name = args.get("func", "")
    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = ctx.find_function(func_name)
    if ida_funcs.get_func_start(func_ea) == ida_idaapi.BADADDR:
        raise ValueError(f"Function not found at 0x{func_ea:x}")

    name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
    chunks = []
    chunks.append({
        "start": f"0x{func_ea:x}",
        "end": f"0x{func_ea + ida_funcs.calc_func_size_ea(func_ea):x}",
        "owner": name,
        "primary": True,
    })
    for tail in _iter_function_tails(ida_funcs, func_ea):
        chunks.append({
            "start": f"0x{tail.start_ea:x}",
            "end": f"0x{tail.end_ea:x}",
            "owner": name,
            "primary": False,
        })

    return {
        "name": name,
        "address": f"0x{func_ea:x}",
        "chunks": chunks,
        "count": len(chunks),
    }


def _handle_set_function_color(ctx, args: dict) -> dict:
    ida_funcs, _, _, ida_nalt, ida_idaapi, _, _ = _ida()

    func_name = args.get("func", "")
    color_str = args.get("color", "")
    if not func_name:
        raise ValueError("Missing required argument: func")
    if not color_str:
        raise ValueError("Missing required argument: color")

    func_ea = ctx.find_function(func_name)
    if ida_funcs.get_func_start(func_ea) == ida_idaapi.BADADDR:
        raise ValueError(f"Function not found at 0x{func_ea:x}")

    color = int(color_str, 0)

    def do_set():
        ida_nalt.set_item_color(func_ea, color)
        return {
            "address": f"0x{func_ea:x}",
            "color": f"0x{color:08x}",
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


register_handler("function_info", _handle_function_info)
register_handler("function_items", _handle_function_items)
register_handler("function_chunks", _handle_function_chunks)
register_handler("set_function_color", _handle_set_function_color)
