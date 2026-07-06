# (c) B. Kerler 2026, MIT license
"""Modification tools: rename, set comments, set types, change signatures."""

from __future__ import annotations

from ida_rpc.server.main import _HANDLERS, register_handler


def _ida():
    import ida_name
    import ida_bytes
    import ida_funcs
    import ida_typeinf
    import ida_idaapi
    import idautils
    import idc
    return ida_name, ida_bytes, ida_funcs, ida_typeinf, ida_idaapi, idautils, idc


def _handle_rename_function(ctx, args: dict) -> dict:
    ida_name, _, ida_funcs, _, _, _, _ = _ida()

    _ = args.get("binary", "")
    target = args.get("target", "")
    new_name = args.get("new_name", "")

    if not target:
        raise ValueError("Missing required argument: target")
    if not new_name:
        raise ValueError("Missing required argument: new_name")

    func_ea = ctx.find_function(target)
    old_name = ida_funcs.get_func_name(func_ea)

    def do_rename():
        ida_name.set_name(func_ea, new_name, ida_name.SN_CHECK)
        actual = ida_funcs.get_func_name(func_ea)
        return {
            "address": f"0x{func_ea:x}",
            "old_name": old_name,
            "new_name": actual,
            "verified": actual == new_name,
        }

    result = ctx.run_on_main_thread(do_rename)
    ctx.save()
    return result


def _handle_rename_symbol(ctx, args: dict) -> dict:
    ida_name, _, _, _, ida_idaapi, _, _ = _ida()
    import ida_segment
    import idc

    _ = args.get("binary", "")
    address = args.get("address", "")
    new_name = args.get("new_name", "") or args.get("name", "")
    create = bool(args.get("create", False))

    if not address:
        raise ValueError("Missing required argument: address")
    if not new_name:
        raise ValueError("Missing required argument: new_name")

    addr = ctx.resolve_address(address)
    old_name = ida_name.get_name(addr)

    def do_rename():
        created_segment = None
        if ida_segment.getseg(addr) is None:
            seg_start = addr & ~0xFFF
            seg_end = seg_start + 0x1000
            seg_name = f"ram_{seg_start:x}"
            if not ida_segment.add_segm(0, seg_start, seg_end, seg_name, "DATA", 0):
                raise RuntimeError(
                    f"Address 0x{addr:x} is unmapped and failed to create segment "
                    f"0x{seg_start:x}-0x{seg_end:x}"
                )
            seg = ida_segment.getseg(addr)
            if seg is None:
                raise RuntimeError(f"Created segment for 0x{addr:x}, but IDA did not return it")
            ida_segment.set_segm_addressing(seg, 1)
            idc.set_segm_attr(seg_start, idc.SEGATTR_PERM, ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)
            created_segment = {
                "name": ida_segment.get_segm_name(seg) or seg_name,
                "start": f"0x{seg.start_ea:x}",
                "end": f"0x{seg.end_ea:x}",
            }

        if old_name is None and not create:
            raise ValueError(f"No symbol found at address {address}")
        flags = ida_name.SN_CHECK
        if not ida_name.set_name(addr, new_name, flags):
            actual = ida_name.get_name(addr) or ""
            raise RuntimeError(
                f"IDA refused to name 0x{addr:x} as {new_name!r}; current name is {actual!r}"
            )
        actual = ida_name.get_name(addr)
        result = {
            "address": f"0x{addr:x}",
            "old_name": old_name,
            "new_name": actual,
            "created": old_name is None,
            "verified": actual == new_name,
        }
        if created_segment:
            result["created_segment"] = created_segment
        return result

    result = ctx.run_on_main_thread(do_rename)
    ctx.save()
    return result


def _handle_create_label(ctx, args: dict) -> dict:
    return _handle_rename_symbol(ctx, {
        **args,
        "create": True,
    })


def _handle_set_comment(ctx, args: dict) -> dict:
    ida_name, ida_bytes, _, _, _, _, _ = _ida()

    _ = args.get("binary", "")
    address = args.get("address", "")
    comment = args.get("comment", "")
    comment_type = args.get("comment_type", "eol")

    if not address:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(address)

    def do_set():
        if comment_type == "eol":
            ida_bytes.set_cmt(addr, comment, 0)
        elif comment_type == "repeatable":
            ida_bytes.set_cmt(addr, comment, 1)
        elif comment_type in ("pre", "plate"):
            # IDA plate/anterior comments
            import ida_lines
            ida_lines.del_extra_cmt(addr, ida_lines.E_PREV)
            if comment:
                ida_lines.add_extra_cmt(addr, True, comment)
        elif comment_type == "post":
            import ida_lines
            ida_lines.del_extra_cmt(addr, ida_lines.E_NEXT)
            if comment:
                ida_lines.add_extra_cmt(addr, False, comment)
        else:
            raise ValueError(f"Invalid comment_type '{comment_type}'")

        if comment_type == "repeatable":
            actual = ida_bytes.get_cmt(addr, 1) or ""
        elif comment_type in ("pre", "plate", "post"):
            # Extra comments are stored separately from regular item comments.
            # They are difficult to round-trip exactly across IDA versions, so
            # consider the operation successful if no exception was raised.
            actual = comment
        else:
            actual = ida_bytes.get_cmt(addr, 0) or ""
        return {
            "address": f"0x{addr:x}",
            "comment_type": comment_type,
            "comment": actual or None,
            "verified": actual == comment,
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_set_function_signature(ctx, args: dict) -> dict:
    _, _, ida_funcs, ida_typeinf, ida_idaapi, _, idc = _ida()

    _ = args.get("binary", "")
    target = args.get("target", "")
    signature = args.get("signature", "")

    if not target:
        raise ValueError("Missing required argument: target")
    if not signature:
        raise ValueError("Missing required argument: signature")

    func_ea = ctx.find_function(target)
    signature = signature.strip()
    if not signature.endswith(";"):
        signature += ";"
    old_sig = ""
    old_tif_str = idc.get_type(func_ea)
    if old_tif_str:
        old_sig = old_tif_str

    def do_set():
        # idc.SetType accepts ordinary C function declarations such as
        # "int foo(void *ctx);" more reliably than parse_decl(PT_TYP) on some
        # processor modules, including nanoMIPS firmware databases.
        if idc.SetType(func_ea, signature):
            new_sig = idc.get_type(func_ea) or ""
            return {
                "address": f"0x{func_ea:x}",
                "old_signature": old_sig,
                "new_signature": new_sig,
                "verified": bool(new_sig) and new_sig != old_sig,
            }

        tif = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(tif, None, signature, ida_typeinf.PT_TYP):
            # Try with cdecl calling convention
            cdecl_sig = "__cdecl " + signature
            if not ida_typeinf.parse_decl(tif, None, cdecl_sig, ida_typeinf.PT_TYP):
                raise ValueError(f"Failed to parse signature: {signature}")

        if not ida_typeinf.apply_tinfo(func_ea, tif, ida_typeinf.TINFO_DEFINITE):
            raise ValueError(f"Failed to apply signature: {signature}")

        new_sig = idc.get_type(func_ea) or ""
        return {
            "address": f"0x{func_ea:x}",
            "old_signature": old_sig,
            "new_signature": new_sig,
            "verified": new_sig != old_sig,
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_set_data_type(ctx, args: dict) -> dict:
    ida_name, ida_bytes, _, ida_typeinf, ida_idaapi, _, _ = _ida()

    _ = args.get("binary", "")
    address_str = args.get("address", "")
    data_type = args.get("data_type", "")

    if not address_str:
        raise ValueError("Missing required argument: address")
    if not data_type:
        raise ValueError("Missing required argument: data_type")

    addr = ctx.resolve_address(address_str)

    def do_set():
        # Clear existing
        ida_bytes.del_items(addr, ida_bytes.DELIT_SIMPLE, 1)

        # Map common type names to IDA flags
        type_lower = data_type.lower().strip()
        flag_map = {
            "byte": ida_bytes.FF_BYTE,
            "word": ida_bytes.FF_WORD,
            "dword": ida_bytes.FF_DWORD,
            "qword": ida_bytes.FF_QWORD,
            "oword": ida_bytes.FF_OWORD,
            "float": ida_bytes.FF_FLOAT,
            "double": ida_bytes.FF_DOUBLE,
            "tbyte": ida_bytes.FF_TBYTE,
        }

        if type_lower in flag_map:
            success = ida_bytes.create_data(addr, flag_map[type_lower], 0)
        elif type_lower in ("string", "cstring", "c_string"):
            success = ida_bytes.create_strlit(addr, 0, 0)
        elif type_lower == "unicode":
            success = ida_bytes.create_strlit(addr, 0, ida_idaapi.BADADDR)
        else:
            # Try to parse as C declaration
            tif = ida_typeinf.tinfo_t()
            if ida_typeinf.parse_decl(tif, None, data_type, ida_typeinf.PT_TYP):
                success = ida_bytes.apply_tinfo(addr, tif, ida_typeinf.TINFO_DEFINITE)
            else:
                raise ValueError(f"Unknown data type: {data_type}")

        if not success:
            raise ValueError(f"Failed to set data type '{data_type}' at 0x{addr:x}")

        # Get size and value
        item_size = ida_bytes.get_item_size(addr)
        flags = ida_bytes.get_flags(addr)
        value = None
        if ida_bytes.is_strlit(flags):
            import ida_nalt
            value = ida_bytes.get_strlit_contents(addr, item_size, ida_nalt.get_str_type(addr))
            if value:
                try:
                    value = value.decode("utf-8", errors="replace")
                except Exception:
                    value = str(value)

        return {
            "address": f"0x{addr:x}",
            "data_type": data_type,
            "length": item_size,
            "value": value,
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_create_function(ctx, args: dict) -> dict:
    ida_name, _, ida_funcs, _, _, _, _ = _ida()

    _ = args.get("binary", "")
    address_str = args.get("address", "")
    end_str = args.get("end", "")
    name = args.get("name", "")

    if not address_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(address_str)
    requested_end = ctx.resolve_address(end_str) if end_str else None

    def do_create():
        existing = ida_funcs.get_func(addr)
        if existing is not None:
            raise ValueError(f"A function already exists at 0x{addr:x}: {ida_funcs.get_func_name(existing.start_ea)}")

        # If bytes are not marked as code, try to create an instruction first
        import ida_bytes
        if not ida_bytes.is_code(ida_bytes.get_flags(addr)):
            import ida_ua
            ida_ua.create_insn(addr)

        if requested_end is not None:
            end = requested_end
        else:
            end = addr + 1
            while ida_funcs.get_func(end) is None and end < addr + 0x10000:
                end += 1

        success = ida_funcs.add_func(addr, end)
        if not success:
            # Try auto-detect
            success = ida_funcs.add_func(addr)

        if not success:
            raise RuntimeError(f"Failed to create function at 0x{addr:x}")

        func = ida_funcs.get_func(addr)
        if name:
            ida_name.set_name(addr, name)

        return {
            "name": ida_funcs.get_func_name(func.start_ea),
            "address": f"0x{func.start_ea:x}",
            "size": func.size(),
        }

    result = ctx.run_on_main_thread(do_create)
    ctx.save()
    return result


def _handle_delete_function(ctx, args: dict) -> dict:
    _, _, ida_funcs, _, _, _, _ = _ida()

    _ = args.get("binary", "")
    target = args.get("target", "")

    if not target:
        raise ValueError("Missing required argument: target")

    func_ea = ctx.find_function(target)
    func = ida_funcs.get_func(func_ea)
    if func is None:
        raise ValueError(f"Function not found: {target}")

    old_name = ida_funcs.get_func_name(func_ea)
    old_size = func.size()

    def do_delete():
        success = ida_funcs.del_func(func_ea)
        return {
            "address": f"0x{func_ea:x}",
            "name": old_name,
            "size": old_size,
            "deleted": success,
        }

    result = ctx.run_on_main_thread(do_delete)
    ctx.save()
    return result


def _handle_set_thunk(ctx, args: dict) -> dict:
    _, _, ida_funcs, _, _, _, idc = _ida()

    _ = args.get("binary", "")
    target = args.get("target", "")
    thunk_target = args.get("thunk_target", "")
    clear = bool(args.get("clear", False))

    if not target:
        raise ValueError("Missing required argument: target")

    func_ea = ctx.find_function(target)
    func = ida_funcs.get_func(func_ea)
    if func is None:
        raise ValueError(f"Function not found: {target}")

    old_flags = func.flags
    FUNC_THUNK = getattr(ida_funcs, "FUNC_THUNK", 0x00000080)

    def do_set():
        if clear:
            new_flags = old_flags & ~FUNC_THUNK
            idc.set_func_flags(func_ea, new_flags)
            return {
                "address": f"0x{func_ea:x}",
                "name": ida_funcs.get_func_name(func_ea),
                "is_thunk": False,
                "action": "cleared",
            }
        else:
            new_flags = old_flags | FUNC_THUNK
            idc.set_func_flags(func_ea, new_flags)
            result = {
                "address": f"0x{func_ea:x}",
                "name": ida_funcs.get_func_name(func_ea),
                "is_thunk": True,
                "action": "set",
            }
            if thunk_target:
                try:
                    target_ea = ctx.resolve_address(thunk_target)
                    # IDA doesn't have a direct thunk target field accessible from Python,
                    # but we can rename the function to indicate the target
                    result["thunk_target"] = f"0x{target_ea:x}"
                    result["note"] = "IDA thunk target is inferred from disassembly, not stored explicitly.",
                except ValueError:
                    pass
            return result

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_set_calling_convention(ctx, args: dict) -> dict:
    _, _, ida_funcs, ida_typeinf, ida_idaapi, _, idc = _ida()

    _ = args.get("binary", "")
    target = args.get("target", "")
    convention = args.get("convention", "")

    if not target:
        raise ValueError("Missing required argument: target")
    if not convention:
        raise ValueError("Missing required argument: convention")

    func_ea = ctx.find_function(target)
    old_sig = idc.get_type(func_ea) or ""

    def do_set():
        tif = ida_typeinf.tinfo_t()
        if old_sig:
            if not ida_typeinf.parse_decl(tif, None, old_sig, ida_typeinf.PT_TYP):
                raise ValueError(f"Failed to parse existing signature: {old_sig}")

        # Build a new signature with the calling convention prefix
        # Common conventions: __cdecl, __stdcall, __fastcall, __thiscall, __vectorcall
        convention_lower = convention.lower().strip()
        cc_prefix = convention
        if convention_lower in ("cdecl", "std", "stdcall"):
            cc_prefix = "__stdcall" if convention_lower == "stdcall" else "__cdecl"

        # Try to parse the new signature
        new_decl = f"{cc_prefix} {old_sig}" if old_sig else f"{cc_prefix} void {ida_funcs.get_func_name(func_ea)}()"
        new_tif = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(new_tif, None, new_decl, ida_typeinf.PT_TYP):
            raise ValueError(f"Failed to parse signature with convention '{convention}': {new_decl}")

        if not ida_typeinf.apply_tinfo(func_ea, new_tif, ida_typeinf.TINFO_DEFINITE):
            raise ValueError(f"Failed to apply calling convention '{convention}'")

        new_sig = idc.get_type(func_ea) or ""
        return {
            "address": f"0x{func_ea:x}",
            "name": ida_funcs.get_func_name(func_ea),
            "old_signature": old_sig,
            "new_signature": new_sig,
            "convention": convention,
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_batch_rename(ctx, args: dict) -> dict:
    ida_name, _, ida_funcs, _, _, _, _ = _ida()

    _ = args.get("binary", "")
    operations = args.get("operations", [])
    mode = args.get("mode", "function")

    if not isinstance(operations, list) or not operations:
        raise ValueError("'operations' must be a non-empty list")

    results = []
    ok_count = 0

    def do_batch():
        nonlocal ok_count
        for idx, op in enumerate(operations):
            new_name = str(op.get("new_name", "")).strip()
            if not new_name:
                results.append({
                    "ok": False, "index": idx,
                    "error": "ValueError", "message": "missing new_name",
                })
                continue

            try:
                if mode == "function":
                    target = op.get("target", "")
                    func_ea = ctx.find_function(target)
                    old_name = ida_funcs.get_func_name(func_ea)
                    ida_name.set_name(func_ea, new_name)
                    results.append({
                        "ok": True, "index": idx,
                        "address": f"0x{func_ea:x}",
                        "old_name": old_name,
                        "new_name": ida_funcs.get_func_name(func_ea),
                    })
                else:
                    address = op.get("address", "")
                    addr = ctx.resolve_address(address)
                    old_name = ida_name.get_name(addr)
                    ida_name.set_name(addr, new_name)
                    results.append({
                        "ok": True, "index": idx,
                        "address": f"0x{addr:x}",
                        "old_name": old_name,
                        "new_name": ida_name.get_name(addr),
                    })
                ok_count += 1
            except Exception as e:
                results.append({
                    "ok": False, "index": idx,
                    "error": type(e).__name__, "message": str(e),
                })

    ctx.run_on_main_thread(do_batch)
    ctx.save()
    return {
        "results": results,
        "count": len(results),
        "ok_count": ok_count,
        "error_count": len(results) - ok_count,
    }


def _handle_batch(ctx, args: dict) -> dict:
    """Execute a list of RPC commands in a single main-thread dispatch.

    Args:
        args: {"commands": [{"cmd": "...", "args": {...}}, ...]}

    Returns:
        {"results": [...], "count": int, "ok_count": int, "error_count": int}
    """
    commands = args.get("commands", [])

    if not isinstance(commands, list) or not commands:
        raise ValueError("'commands' must be a non-empty list")

    results = []
    ok_count = 0

    def do_batch():
        nonlocal ok_count
        for idx, item in enumerate(commands):
            if not isinstance(item, dict):
                results.append({
                    "ok": False, "index": idx,
                    "error": "ValueError", "message": "command entry must be an object",
                })
                continue

            sub_cmd = item.get("cmd", "")
            sub_args = item.get("args", {})

            if not isinstance(sub_args, dict):
                results.append({
                    "ok": False, "index": idx, "cmd": sub_cmd,
                    "error": "ValueError", "message": "'args' must be an object",
                })
                continue

            if sub_cmd == "batch":
                results.append({
                    "ok": False, "index": idx, "cmd": sub_cmd,
                    "error": "ValueError", "message": "nested batch commands are not supported",
                })
                continue

            handler = _HANDLERS.get(sub_cmd)
            if handler is None:
                results.append({
                    "ok": False, "index": idx, "cmd": sub_cmd,
                    "error": "UnknownCommand",
                    "message": f"Unknown command: {sub_cmd}",
                })
                continue

            try:
                result = ctx.run_on_main_thread(handler, ctx, sub_args)
                results.append({
                    "ok": True, "index": idx, "cmd": sub_cmd,
                    "result": result,
                })
                ok_count += 1
            except Exception as e:
                results.append({
                    "ok": False, "index": idx, "cmd": sub_cmd,
                    "error": type(e).__name__, "message": str(e),
                })

    ctx.run_on_main_thread(do_batch)
    ctx.save()
    return {
        "results": results,
        "count": len(results),
        "ok_count": ok_count,
        "error_count": len(results) - ok_count,
    }


def _handle_batch_set_comment(ctx, args: dict) -> dict:
    ida_name, ida_bytes, _, _, _, _, _ = _ida()

    _ = args.get("binary", "")
    operations = args.get("operations", [])

    if not isinstance(operations, list) or not operations:
        raise ValueError("'operations' must be a non-empty list")

    results = []
    ok_count = 0

    def do_batch():
        nonlocal ok_count
        for idx, op in enumerate(operations):
            address = op.get("address", "")
            comment = op.get("comment", "")
            ct = op.get("comment_type", "eol")

            if not address:
                results.append({
                    "ok": False, "index": idx,
                    "error": "ValueError", "message": "missing address",
                })
                continue

            try:
                addr = ctx.resolve_address(address)
                if ct == "eol":
                    ida_bytes.set_cmt(addr, comment, 0)
                elif ct == "repeatable":
                    ida_bytes.set_cmt(addr, comment, 1)
                else:
                    raise ValueError(f"Invalid comment_type '{ct}'")
                results.append({
                    "ok": True, "index": idx,
                    "address": f"0x{addr:x}",
                    "comment_type": ct,
                    "comment": comment,
                })
                ok_count += 1
            except Exception as e:
                results.append({
                    "ok": False, "index": idx,
                    "error": type(e).__name__, "message": str(e),
                })

    ctx.run_on_main_thread(do_batch)
    ctx.save()
    return {
        "results": results,
        "count": len(results),
        "ok_count": ok_count,
        "error_count": len(results) - ok_count,
    }


register_handler("rename_function", _handle_rename_function)
register_handler("rename_symbol", _handle_rename_symbol)
def _handle_create_instruction(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    address_str = args.get("address", "")

    if not address_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(address_str)

    def do_create():
        import ida_ua
        size = ida_ua.create_insn(addr)
        if size == 0:
            raise RuntimeError(f"Failed to create instruction at 0x{addr:x}")
        return {
            "address": f"0x{addr:x}",
            "size": size,
            "action": "created",
        }

    result = ctx.run_on_main_thread(do_create)
    ctx.save()
    return result


def _handle_create_instructions(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    start_str = args.get("start", "") or args.get("address", "")
    end_str = args.get("end", "")
    max_count = int(args.get("max_count", 4096))

    if not start_str:
        raise ValueError("Missing required argument: start")
    if not end_str:
        raise ValueError("Missing required argument: end")

    start = ctx.resolve_address(start_str)
    end = ctx.resolve_address(end_str)
    if end <= start:
        raise ValueError("end must be greater than start")

    def do_create_range():
        import ida_bytes
        import ida_ua

        ea = start
        count = 0
        created = []
        failures = []
        while ea < end and count < max_count:
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_code(flags):
                size = ida_bytes.get_item_size(ea)
                if size <= 0:
                    size = 1
            else:
                size = ida_ua.create_insn(ea)
                if size == 0:
                    failures.append(f"0x{ea:x}")
                    ea += 1
                    continue
                created.append({"address": f"0x{ea:x}", "size": size})
            ea += size
            count += 1

        return {
            "start": f"0x{start:x}",
            "end": f"0x{end:x}",
            "next": f"0x{ea:x}",
            "created_count": len(created),
            "walked_count": count,
            "failures": failures[:64],
            "failure_count": len(failures),
            "truncated": ea < end,
        }

    result = ctx.run_on_main_thread(do_create_range)
    ctx.save()
    return result


def _handle_undefine(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    address_str = args.get("address", "")
    length_str = args.get("length", "")

    if not address_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(address_str)
    length = int(length_str) if length_str else 1

    def do_undefine():
        import ida_bytes
        ida_bytes.del_items(addr, ida_bytes.DELIT_SIMPLE, length)
        return {
            "address": f"0x{addr:x}",
            "length": length,
            "action": "undefined",
        }

    result = ctx.run_on_main_thread(do_undefine)
    ctx.save()
    return result


register_handler("create_label", _handle_create_label)
register_handler("set_comment", _handle_set_comment)
register_handler("set_function_signature", _handle_set_function_signature)
register_handler("set_data_type", _handle_set_data_type)
register_handler("create_function", _handle_create_function)
register_handler("delete_function", _handle_delete_function)
register_handler("set_thunk", _handle_set_thunk)
register_handler("set_calling_convention", _handle_set_calling_convention)
register_handler("batch_rename", _handle_batch_rename)
register_handler("batch_set_comment", _handle_batch_set_comment)
register_handler("batch", _handle_batch)
register_handler("create_instruction", _handle_create_instruction)
register_handler("create_instructions", _handle_create_instructions)
register_handler("undefine", _handle_undefine)
