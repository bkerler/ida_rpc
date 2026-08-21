# (c) B. Kerler 2026, MIT license
"""Stack frame and local variable tools."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_funcs
    import ida_frame
    import ida_typeinf
    import ida_idaapi
    import idautils
    return ida_funcs, ida_frame, ida_typeinf, ida_idaapi, idautils


def _get_func_and_frame(ctx, func_name: str):
    ida_funcs, ida_frame, ida_typeinf, ida_idaapi, idautils = _ida()
    func_ea = ctx.find_function(func_name)
    if ida_funcs.get_func_start(func_ea) == ida_idaapi.BADADDR:
        raise ValueError(f"Function not found at 0x{func_ea:x}")
    return func_ea


def _iter_frame_members(func_ea):
    """Yield frame member dicts using the IDA 9.x EA-based frame API."""
    ida_funcs, ida_frame, ida_typeinf, ida_idaapi, idautils = _ida()

    tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame_ea(tif, func_ea):
        return

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return

    for i in range(len(udt)):
        member = udt[i]
        mtype = ""
        try:
            mtype = ida_typeinf.print_tinfo(None, 0, 0, ida_typeinf.PRTYPE_1LINE, member.type, None, None) or ""
        except Exception:
            pass
        yield {
            "offset": member.offset // 8,  # convert to bytes
            "name": member.name or "",
            "size": member.size // 8,
            "type": mtype,
        }


def _handle_function_frame(ctx, args: dict) -> dict:
    ida_funcs, ida_frame, ida_typeinf, ida_idaapi, idautils = _ida()

    func_name = args.get("func", "")
    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = _get_func_and_frame(ctx, func_name)
    name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"

    frame_size = 0
    ret_size = 0
    try:
        frame_size = ida_frame.get_frame_size_ea(func_ea)
        ret_size = ida_frame.get_frame_retsize_ea(func_ea)
    except Exception:
        pass

    members = list(_iter_frame_members(func_ea))

    return {
        "name": name,
        "address": f"0x{func_ea:x}",
        "frame_size": frame_size,
        "ret_size": ret_size,
        "members": members,
        "count": len(members),
    }


def _handle_list_stack_vars(ctx, args: dict) -> dict:
    ida_funcs, ida_frame, ida_typeinf, ida_idaapi, idautils = _ida()

    func_name = args.get("func", "")
    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = _get_func_and_frame(ctx, func_name)
    name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"

    # Frame layout offsets (in bytes)
    # frame_off_args returns offset where arguments start
    # frame_off_lvars returns offset where local variables start
    try:
        args_offset = ida_frame.frame_off_args_ea(func_ea)
        lvars_offset = ida_frame.frame_off_lvars_ea(func_ea)
    except Exception:
        args_offset = None
        lvars_offset = None

    vars_list = []
    for m in _iter_frame_members(func_ea):
        var_type = "unknown"
        if args_offset is not None and lvars_offset is not None:
            if m["offset"] >= args_offset:
                var_type = "arg"
            elif m["offset"] < lvars_offset:
                var_type = "local"
            else:
                var_type = "saved_reg"
        vars_list.append({
            "offset": m["offset"],
            "name": m["name"],
            "size": m["size"],
            "type": m["type"],
            "var_type": var_type,
        })

    return {
        "name": name,
        "address": f"0x{func_ea:x}",
        "vars": vars_list,
        "count": len(vars_list),
    }


def _handle_rename_stack_var(ctx, args: dict) -> dict:
    ida_funcs, ida_frame, ida_typeinf, ida_idaapi, idautils = _ida()
    import idc

    func_name = args.get("func", "")
    offset = int(args.get("offset", -1))
    old_name = args.get("old_name", "")
    new_name = args.get("new_name", "")

    if not func_name:
        raise ValueError("Missing required argument: func")
    if not new_name:
        raise ValueError("Missing required argument: new_name")

    func_ea = _get_func_and_frame(ctx, func_name)

    # Resolve offset if old_name given
    if offset < 0 and old_name:
        for m in _iter_frame_members(func_ea):
            if m["name"] == old_name:
                offset = m["offset"]
                break
        if offset < 0:
            raise ValueError(f"Stack variable '{old_name}' not found in function '{func_name}'")

    if offset < 0:
        raise ValueError("Missing or invalid required argument: offset (or old_name)")

    import idc
    frame_id = idc.get_frame_id(func_ea)
    if frame_id == ida_idaapi.BADADDR:
        raise ValueError("Function has no frame")

    def do_rename():
        res = idc.set_member_name(frame_id, offset, new_name)
        return {
            "success": res,
            "address": f"0x{func_ea:x}",
            "offset": offset,
            "new_name": new_name,
        }

    result = ctx.run_on_main_thread(do_rename)
    ctx.save()
    return result


def _handle_set_stack_var_type(ctx, args: dict) -> dict:
    ida_funcs, ida_frame, ida_typeinf, ida_idaapi, idautils = _ida()

    func_name = args.get("func", "")
    offset = int(args.get("offset", -1))
    var_name = args.get("name", "")
    new_type = args.get("type", "")

    if not func_name:
        raise ValueError("Missing required argument: func")
    if not new_type:
        raise ValueError("Missing required argument: type")

    func_ea = _get_func_and_frame(ctx, func_name)

    # Resolve offset if name given
    if offset < 0 and var_name:
        for m in _iter_frame_members(func_ea):
            if m["name"] == var_name:
                offset = m["offset"]
                break
        if offset < 0:
            raise ValueError(f"Stack variable '{var_name}' not found in function '{func_name}'")

    if offset < 0:
        raise ValueError("Missing or invalid required argument: offset (or name)")

    tif = ida_typeinf.tinfo_t()
    if not ida_typeinf.parse_decl(tif, None, new_type, ida_typeinf.PT_SIL):
        raise ValueError(f"Failed to parse type: {new_type}")

    def do_set():
        res = ida_frame.set_frame_member_type_ea(func_ea, offset, tif)
        return {
            "success": res,
            "address": f"0x{func_ea:x}",
            "offset": offset,
            "type": new_type,
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_list_reg_vars(ctx, args: dict) -> dict:
    ida_funcs, ida_frame, ida_typeinf, ida_idaapi, idautils = _ida()

    func_name = args.get("func", "")
    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = _get_func_and_frame(ctx, func_name)
    name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"

    regvars = []
    try:
        for i in range(ida_frame.get_func_regvar_qty(func_ea)):
            rv = ida_frame.regvar_t()
            if not ida_frame.get_func_regvar(rv, func_ea, i):
                continue
            if rv:
                regvars.append({
                    "canonical": rv.canon or "",
                    "user": rv.user or "",
                    "description": rv.cmt or "",
                    "start": f"0x{rv.start_ea:x}",
                    "end": f"0x{rv.end_ea:x}",
                })
    except Exception:
        pass

    return {
        "name": name,
        "address": f"0x{func_ea:x}",
        "regvars": regvars,
        "count": len(regvars),
    }


def _handle_stack_var_xrefs(ctx, args: dict) -> dict:
    ida_funcs, ida_frame, ida_typeinf, ida_idaapi, idautils = _ida()

    func_name = args.get("func", "")
    offset = int(args.get("offset", -1))
    var_name = args.get("name", "")

    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = _get_func_and_frame(ctx, func_name)

    # Resolve offset if name given
    if offset < 0 and var_name:
        for m in _iter_frame_members(func_ea):
            if m["name"] == var_name:
                offset = m["offset"]
                break
        if offset < 0:
            raise ValueError(f"Stack variable '{var_name}' not found in function '{func_name}'")

    if offset < 0:
        raise ValueError("Missing or invalid required argument: offset (or name)")

    xrefs = ida_frame.xreflist_t()
    ida_frame.build_stkvar_xrefs_ea(xrefs, func_ea, offset, offset + 1)

    results = []
    for i in range(len(xrefs)):
        xr = xrefs[i]
        results.append({
            "address": f"0x{xr.ea:x}",
            "opnum": xr.opnum,
            "type": "read" if xr.type == 0 else "write",
        })

    return {
        "name": ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}",
        "address": f"0x{func_ea:x}",
        "offset": offset,
        "xrefs": results,
        "count": len(results),
    }


register_handler("function_frame", _handle_function_frame)
register_handler("list_stack_vars", _handle_list_stack_vars)
register_handler("rename_stack_var", _handle_rename_stack_var)
register_handler("set_stack_var_type", _handle_set_stack_var_type)
register_handler("list_reg_vars", _handle_list_reg_vars)
register_handler("stack_var_xrefs", _handle_stack_var_xrefs)
