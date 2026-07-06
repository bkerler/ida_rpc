# (c) B. Kerler 2026, MIT license
"""Decompiler tools: decompile functions to pseudo-C."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_hexrays
    import ida_funcs
    import ida_lines
    import ida_idaapi
    import ida_nalt
    import ida_typeinf
    return ida_hexrays, ida_funcs, ida_lines, ida_idaapi, ida_nalt, ida_typeinf


def _handle_decompile(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    func_name = args.get("func", "")

    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = ctx.find_function(func_name)

    try:
        ida_hexrays, ida_funcs, ida_lines, ida_idaapi, ida_nalt, ida_typeinf = _ida()
    except ImportError:
        raise RuntimeError("Hex-Rays decompiler is not available.")

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Failed to initialize Hex-Rays decompiler.")

    cfunc = ida_hexrays.decompile(func_ea)
    if cfunc is None:
        return {
            "name": ida_funcs.get_func_name(func_ea),
            "address": f"0x{func_ea:x}",
            "c_code": None,
            "error": "Decompilation failed",
        }

    # Build pseudo-code lines
    lines = []
    for line in cfunc.get_pseudocode():
        text = ida_lines.tag_remove(line.line)
        lines.append(text)

    c_code = "\n".join(lines)

    # Signature
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, func_ea):
        signature = str(tif)
    else:
        signature = ""

    return {
        "name": ida_funcs.get_func_name(func_ea),
        "address": f"0x{func_ea:x}",
        "signature": signature,
        "c_code": c_code,
    }


def _handle_decompile_all(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    limit = int(args.get("limit", 0))
    function_filter = args.get("function", "")

    try:
        ida_hexrays, ida_funcs, ida_lines, ida_idaapi, ida_nalt, ida_typeinf = _ida()
        import idautils
    except ImportError:
        raise RuntimeError("Hex-Rays decompiler is not available.")

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Failed to initialize Hex-Rays decompiler.")

    def do_decompile_all():
        results = []
        errors = []
        count = 0

        for func_ea in idautils.Functions():
            if limit and count >= limit:
                break

            fname = ida_funcs.get_func_name(func_ea)
            if function_filter and function_filter.lower() not in fname.lower():
                continue

            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc is None:
                    errors.append({
                        "address": f"0x{func_ea:x}",
                        "name": fname,
                        "error": "Decompilation failed",
                    })
                    continue

                lines = []
                for line in cfunc.get_pseudocode():
                    text = ida_lines.tag_remove(line.line)
                    lines.append(text)

                tif = ida_typeinf.tinfo_t()
                sig = ""
                if ida_nalt.get_tinfo(tif, func_ea):
                    sig = str(tif)

                results.append({
                    "address": f"0x{func_ea:x}",
                    "name": fname,
                    "signature": sig,
                    "c_code": "\n".join(lines),
                })
                count += 1
            except Exception as e:
                errors.append({
                    "address": f"0x{func_ea:x}",
                    "name": fname,
                    "error": str(e),
                })

        return {
            "functions": results,
            "count": len(results),
            "errors": errors,
            "error_count": len(errors),
        }

    return ctx.run_on_main_thread(do_decompile_all)


def _handle_decompile_lvars(ctx, args: dict) -> dict:
    func_name = args.get("func", "")
    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = ctx.find_function(func_name)

    try:
        ida_hexrays, ida_funcs, ida_lines, ida_idaapi, ida_nalt, ida_typeinf = _ida()
    except ImportError:
        raise RuntimeError("Hex-Rays decompiler is not available.")

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Failed to initialize Hex-Rays decompiler.")

    cfunc = ida_hexrays.decompile(func_ea)
    if cfunc is None:
        raise RuntimeError("Decompilation failed")

    def lvar_type(lv):
        typ = getattr(lv, "type", None)
        if callable(typ):
            try:
                typ = typ()
            except Exception:
                typ = None
        return typ

    def lvar_size(lv):
        size = getattr(lv, "size", None)
        if size is not None:
            return size
        width = getattr(lv, "width", None)
        if width is not None:
            return width
        typ = lvar_type(lv)
        if typ:
            try:
                return typ.get_size()
            except Exception:
                pass
        return None

    lvars = []
    for lv in cfunc.get_lvars():
        loc_str = "unknown"
        if lv.location.is_stkoff():
            loc_str = f"stack:{lv.location.stkoff()}"
        elif lv.location.is_reg1():
            loc_str = f"reg:{lv.location.reg1()}"
        elif lv.location.is_reg2():
            loc_str = f"reg:{lv.location.reg1()},{lv.location.reg2()}"

        lvars.append({
            "name": lv.name or "",
            "type": str(lvar_type(lv) or ""),
            "size": lvar_size(lv),
            "is_arg": lv.is_arg_var,
            "location": loc_str,
        })

    return {
        "name": ida_funcs.get_func_name(func_ea),
        "address": f"0x{func_ea:x}",
        "lvars": lvars,
        "count": len(lvars),
    }


def _handle_set_lvar_name(ctx, args: dict) -> dict:
    func_name = args.get("func", "")
    lvar_name = args.get("lvar", "")
    new_name = args.get("new_name", "")

    if not func_name:
        raise ValueError("Missing required argument: func")
    if not lvar_name:
        raise ValueError("Missing required argument: lvar")
    if not new_name:
        raise ValueError("Missing required argument: new_name")

    func_ea = ctx.find_function(func_name)

    try:
        ida_hexrays, ida_funcs, ida_lines, ida_idaapi, ida_nalt, ida_typeinf = _ida()
    except ImportError:
        raise RuntimeError("Hex-Rays decompiler is not available.")

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Failed to initialize Hex-Rays decompiler.")

    class _Modifier(ida_hexrays.user_lvar_modifier_t):
        def __init__(self, target_name, new_name):
            super().__init__()
            self.target_name = target_name
            self.new_name = new_name
            self.changed = False

        def modify_lvars(self, lvars):
            for lv in lvars.lvvec:
                if lv.name == self.target_name:
                    lv.name = self.new_name
                    self.changed = True
            return True

    def do_modify():
        if hasattr(ida_hexrays, "rename_lvar"):
            renamed = ida_hexrays.rename_lvar(func_ea, lvar_name, new_name)
            if renamed:
                return {
                    "address": f"0x{func_ea:x}",
                    "lvar": lvar_name,
                    "new_name": new_name,
                    "changed": True,
                }
        modifier = _Modifier(lvar_name, new_name)
        ida_hexrays.modify_user_lvars(func_ea, modifier)
        return {
            "address": f"0x{func_ea:x}",
            "lvar": lvar_name,
            "new_name": new_name,
            "changed": modifier.changed,
        }

    result = ctx.run_on_main_thread(do_modify)
    ctx.save()
    return result


def _handle_set_lvar_type(ctx, args: dict) -> dict:
    func_name = args.get("func", "")
    lvar_name = args.get("lvar", "")
    new_type = args.get("type", "")

    if not func_name:
        raise ValueError("Missing required argument: func")
    if not lvar_name:
        raise ValueError("Missing required argument: lvar")
    if not new_type:
        raise ValueError("Missing required argument: type")

    func_ea = ctx.find_function(func_name)

    try:
        ida_hexrays, ida_funcs, ida_lines, ida_idaapi, ida_nalt, ida_typeinf = _ida()
    except ImportError:
        raise RuntimeError("Hex-Rays decompiler is not available.")

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Failed to initialize Hex-Rays decompiler.")

    tif = ida_typeinf.tinfo_t()
    if not ida_typeinf.parse_decl(tif, None, new_type, ida_typeinf.PT_SIL):
        raise ValueError(f"Failed to parse type: {new_type}")

    class _Modifier(ida_hexrays.user_lvar_modifier_t):
        def __init__(self, target_name, new_type):
            super().__init__()
            self.target_name = target_name
            self.new_type = new_type
            self.changed = False

        def modify_lvars(self, lvars):
            for lv in lvars.lvvec:
                if lv.name == self.target_name:
                    lv.type = self.new_type
                    self.changed = True
            return True

    def do_modify():
        modifier = _Modifier(lvar_name, tif)
        ida_hexrays.modify_user_lvars(func_ea, modifier)
        return {
            "address": f"0x{func_ea:x}",
            "lvar": lvar_name,
            "type": new_type,
            "changed": modifier.changed,
        }

    result = ctx.run_on_main_thread(do_modify)
    ctx.save()
    return result


def _handle_decompile_microcode(ctx, args: dict) -> dict:
    func_name = args.get("func", "")
    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = ctx.find_function(func_name)
    maturity = int(args.get("maturity", ida_hexrays.MMAT_GLBOPT))

    try:
        ida_hexrays, ida_funcs, ida_lines, ida_idaapi, ida_nalt, ida_typeinf = _ida()
    except ImportError:
        raise RuntimeError("Hex-Rays decompiler is not available.")

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Failed to initialize Hex-Rays decompiler.")

    mba = ida_hexrays.gen_microcode(func_ea, None, None, 0, maturity)
    if mba is None:
        raise RuntimeError("Microcode generation failed")

    blocks = []
    for blk in mba.blocks:
        instructions = []
        insn = blk.head
        while insn:
            try:
                insn_str = insn.dstr()
            except Exception:
                insn_str = str(insn)
            instructions.append({
                "address": f"0x{insn.ea:x}",
                "text": insn_str,
                "opcode": insn.opcode,
            })
            insn = insn.next
        blocks.append({
            "serial": blk.serial,
            "start": f"0x{blk.start:x}",
            "end": f"0x{blk.end:x}",
            "instructions": instructions,
        })

    return {
        "name": ida_funcs.get_func_name(func_ea),
        "address": f"0x{func_ea:x}",
        "maturity": maturity,
        "blocks": blocks,
        "num_blocks": len(blocks),
    }


def _handle_decompiler_xrefs(ctx, args: dict) -> dict:
    func_name = args.get("func", "")
    target = args.get("target", "")

    if not func_name:
        raise ValueError("Missing required argument: func")
    if not target:
        raise ValueError("Missing required argument: target")

    func_ea = ctx.find_function(func_name)

    try:
        ida_hexrays, ida_funcs, ida_lines, ida_idaapi, ida_nalt, ida_typeinf = _ida()
    except ImportError:
        raise RuntimeError("Hex-Rays decompiler is not available.")

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Failed to initialize Hex-Rays decompiler.")

    cfunc = ida_hexrays.decompile(func_ea)
    if cfunc is None:
        raise RuntimeError("Decompilation failed")

    # Try to resolve target as address
    target_ea = None
    try:
        target_ea = ctx.resolve_address(target)
    except ValueError:
        pass

    refs = []
    for item in cfunc.treeitems:
        matched = False
        if target_ea is not None:
            # Check object references
            obj_ea = getattr(item, "obj_ea", None)
            num = getattr(item, "n", None)
            if item.op == ida_hexrays.cot_obj and obj_ea == target_ea:
                matched = True
            elif item.op == ida_hexrays.cot_num and num is not None:
                try:
                    matched = num.value(target_ea) == target_ea
                except Exception:
                    matched = False
        # Check name-based match for variables
        if not matched and hasattr(item, "name") and item.name == target:
            matched = True

        if matched:
            refs.append({
                "op": item.op,
                "address": f"0x{item.ea:x}",
            })

    return {
        "name": ida_funcs.get_func_name(func_ea),
        "address": f"0x{func_ea:x}",
        "target": target,
        "refs": refs,
        "count": len(refs),
    }


register_handler("decompile", _handle_decompile)
register_handler("decompile_all", _handle_decompile_all)
register_handler("decompile_lvars", _handle_decompile_lvars)
register_handler("set_lvar_name", _handle_set_lvar_name)
register_handler("set_lvar_type", _handle_set_lvar_type)
register_handler("decompile_microcode", _handle_decompile_microcode)
register_handler("decompiler_xrefs", _handle_decompiler_xrefs)
