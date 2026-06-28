# (c) B. Kerler 2026, MIT license
"""Analysis and listing tools: binaries, functions, imports, exports, metadata, relocations."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _filetype_name(ft: int) -> str:
    import ida_ida
    mapping = {
        ida_ida.f_ELF: "ELF",
        ida_ida.f_PE: "PE",
        ida_ida.f_MACHO: "Mach-O",
        ida_ida.f_COFF: "COFF",
        ida_ida.f_EXE: "EXE",
        ida_ida.f_COM: "COM",
        ida_ida.f_BIN: "Binary",
        ida_ida.f_HEX: "HEX",
        ida_ida.f_SREC: "SREC",
        ida_ida.f_OMF: "OMF",
        ida_ida.f_AOUT: "AOUT",
        ida_ida.f_NLM: "NLM",
        ida_ida.f_LX: "LX",
        ida_ida.f_LE: "LE",
        ida_ida.f_DRV: "DRV",
        ida_ida.f_AR: "AR",
        ida_ida.f_AIXAR: "AIXAR",
        ida_ida.f_ZIP: "ZIP",
        ida_ida.f_OMFLIB: "OMFLIB",
        ida_ida.f_W32RUN: "W32RUN",
        ida_ida.f_PRC: "PRC",
        ida_ida.f_PSXOBJ: "PSXOBJ",
        ida_ida.f_MD1IMG: "MD1IMG",
    }
    for attr in ["f_NE", "f_DMP"]:
        if hasattr(ida_ida, attr):
            mapping[getattr(ida_ida, attr)] = attr[2:]
    return mapping.get(ft, f"unknown({ft})")


def _arch_name(procname: str, bits: int) -> str:
    proc = (procname or "").strip()
    if proc.lower() == "arm" and bits == 64:
        return "aarch64"
    return proc


def _ida():
    import ida_idaapi
    import ida_loader
    import ida_funcs
    import ida_name
    import ida_nalt
    import ida_entry
    import idautils
    import ida_ida
    import ida_segment
    import ida_bytes
    import ida_frame
    import ida_typeinf
    return (
        ida_idaapi, ida_loader, ida_funcs, ida_name,
        ida_nalt, ida_entry, idautils, ida_ida, ida_segment, ida_bytes,
        ida_frame, ida_typeinf,
    )


def _current_binary_info(ctx) -> dict:
    _, _, _, _, _, _, _, ida_ida, _, _, _, _ = _ida()
    pi = ctx.get_program()
    bits = 64 if ida_ida.inf_is_64bit() else 32
    return {
        "name": pi.name,
        "path": str(pi.idb_path) if pi.idb_path else None,
        "arch": _arch_name(ida_ida.inf_get_procname(), bits),
        "bits": bits,
        "endian": "big" if ida_ida.inf_is_be() else "little",
        "format": _filetype_name(ida_ida.inf_get_filetype()),
        "base_address": f"0x{ida_ida.inf_get_min_ea():x}",
        "analysis_complete": pi.analysis_complete,
    }


def _handle_load(ctx, args: dict) -> dict:
    """Load a binary into IDA. In IDA context this is typically done by
    opening the IDB; loading a new binary requires launching IDA with it.
    """
    path = args.get("path")
    if not path:
        raise ValueError("Missing required argument: path")

    import os
    if not os.path.exists(path):
        raise FileNotFoundError(f"Binary not found: {path}")

    # IDA loads binaries into the current process; we can't hot-swap.
    # Return info about the current IDB and advise the user.
    info = _current_binary_info(ctx)
    return {
        "binary": info["name"],
        "path": info["path"],
        "arch": info["arch"],
        "bits": info["bits"],
        "endian": info["endian"],
        "format": info["format"],
        "base_address": info["base_address"],
        "note": "IDA loads binaries at process startup. Use 'ida-rpc start --project <idb> --arch <arch>' to open a different file.",
        "analysis_complete": info["analysis_complete"],
    }


def _handle_list_binaries(ctx, args: dict) -> dict:
    return {"binaries": [_current_binary_info(ctx)]}


def _handle_function(ctx, args: dict) -> dict:
    _, _, ida_funcs, ida_name, _, _, idautils, _, _, _, ida_frame, ida_typeinf = _ida()

    func_name = args.get("func", "")
    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = ctx.find_function(func_name)
    func = ida_funcs.get_func(func_ea)
    if func is None:
        raise ValueError(f"Function not found at 0x{func_ea:x}")

    name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"

    # Frame info
    frame_size = 0
    try:
        frame_size = ida_frame.get_frame_size(func)
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

    return {
        "name": name,
        "address": f"0x{func_ea:x}",
        "size": func.size(),
        "frame_size": frame_size,
        "prototype": prototype,
    }


def _handle_functions(ctx, args: dict) -> dict:
    import ida_funcs
    import idautils

    offset = int(args.get("offset", 0))
    limit = args.get("limit", None)
    if limit is not None:
        limit = int(limit)

    address_min_str = args.get("address_min", "")
    address_max_str = args.get("address_max", "")
    with_body = bool(args.get("with_body", False))

    address_min = None
    address_max = None
    if address_min_str:
        address_min = ctx.resolve_address(address_min_str)
    if address_max_str:
        address_max = ctx.resolve_address(address_max_str)

    functions = []
    skipped = 0
    for func_ea in idautils.Functions():
        if address_min is not None and func_ea < address_min:
            continue
        if address_max is not None and func_ea > address_max:
            break

        if skipped < offset:
            skipped += 1
            continue
        if limit is not None and len(functions) >= limit:
            break

        item = {
            "name": ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}",
            "address": f"0x{func_ea:x}",
        }
        if with_body:
            func = ida_funcs.get_func(func_ea)
            if func:
                item["body_min"] = f"0x{func.start_ea:x}"
                item["body_max"] = f"0x{func.end_ea - 1:x}"
                item["body_size"] = func.size()
        functions.append(item)

    return {
        "functions": functions,
        "count": len(functions),
        "offset": offset,
    }


def _handle_imports(ctx, args: dict) -> dict:
    _, _, _, _, ida_nalt, _, _, _, _, _, _, _ = _ida()

    imports = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        modname = ida_nalt.get_import_module_name(i) or "<unnamed>"

        def imp_cb(ea, name, ordinal):
            imports.append({
                "name": name or f"ordinal_{ordinal}",
                "address": f"0x{ea:x}",
                "library": modname,
            })
            return True

        ida_nalt.enum_import_names(i, imp_cb)

    return {"imports": imports, "count": len(imports)}


def _handle_exports(ctx, args: dict) -> dict:
    ida_idaapi, _, _, _, _, ida_entry, _, _, _, _, _, _ = _ida()

    exports = []
    nentries = ida_entry.get_entry_qty()
    for i in range(nentries):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        if ea != ida_idaapi.BADADDR:
            exports.append({
                "name": name or f"entry_{ordinal}",
                "address": f"0x{ea:x}",
            })

    return {"exports": exports, "count": len(exports)}


def _handle_metadata(ctx, args: dict) -> dict:
    ida_idaapi, _, _, _, _, _, idautils, ida_ida, ida_segment, _, _, _ = _ida()

    pi = ctx.get_program()

    # Count functions
    func_count = 0
    for _ in idautils.Functions():
        func_count += 1

    bits = 64 if ida_ida.inf_is_64bit() else 32
    return {
        "name": pi.name,
        "arch": _arch_name(ida_ida.inf_get_procname(), bits),
        "bits": bits,
        "endian": "big" if ida_ida.inf_is_be() else "little",
        "format": _filetype_name(ida_ida.inf_get_filetype()),
        "base_address": f"0x{ida_ida.inf_get_min_ea():x}",
        "num_functions": func_count,
    }


def _handle_relocations(ctx, args: dict) -> dict:
    ida_idaapi, _, _, _, _, _, _, ida_ida, _, _, _, _ = _ida()
    import ida_fixup

    _ = args.get("binary", "")
    limit = int(args.get("limit", 500))

    def do_list():
        results = []
        ea = ida_ida.inf_get_min_ea()
        while ea != ida_idaapi.BADADDR and len(results) < limit:
            ea = ida_fixup.get_next_fixup_ea(ea)
            if ea == ida_idaapi.BADADDR:
                break

            fix = ida_fixup.fixup_data_t()
            if not ida_fixup.get_fixup(fix, ea):
                ea += 1
                continue

            # Try to get a friendly name for the fixup type
            fix_type = fix.get_type()
            rtype_name = f"type_{fix_type}"
            try:
                import ida_idp
                # get_ph_fixture may not exist in all IDA versions
                if hasattr(ida_idp, 'get_ph_fixture'):
                    ph_name = ida_idp.get_ph_fixture(fix_type)
                    if ph_name:
                        rtype_name = ph_name
            except AttributeError:
                pass

            results.append({
                "address": f"0x{ea:x}",
                "type": rtype_name,
                "size": fix.calc_size(),
            })
            ea += 1

        return {"relocations": results, "count": len(results)}

    return ctx.run_on_main_thread(do_list)


def _handle_list_calling_conventions(ctx, args: dict) -> dict:
    _, _, _, _, _, _, _, ida_ida, _, _, _, _ = _ida()

    _ = args.get("binary", "")
    processor = ida_ida.inf_get_procname().lower()

    # Common conventions by architecture
    conventions = []
    if processor.startswith("x86") or processor.startswith("metapc"):
        conventions = [
            {"name": "__cdecl", "description": "Caller cleans stack"},
            {"name": "__stdcall", "description": "Callee cleans stack"},
            {"name": "__fastcall", "description": "First args in ECX/EDX (x86) or RCX/RDX/R8/R9 (x64)"},
            {"name": "__thiscall", "description": "ECX = this pointer"},
            {"name": "__vectorcall", "description": "Vector registers for args"},
        ]
    elif processor.startswith("arm") or processor.startswith("aarch64"):
        conventions = [
            {"name": "__cdecl", "description": "AAPCS / AAPCS64"},
            {"name": "__stdcall", "description": "Standard ARM calling convention"},
        ]
    elif processor.startswith("mips"):
        conventions = [
            {"name": "__cdecl", "description": "O32/N32/N64 ABI"},
        ]
    elif processor.startswith("ppc") or processor.startswith("powerpc"):
        conventions = [
            {"name": "__cdecl", "description": "System V PPC ABI"},
        ]
    else:
        conventions = [
            {"name": "__cdecl", "description": "Default C calling convention"},
            {"name": "__stdcall", "description": "Standard call"},
        ]

    return {
        "processor": processor,
        "conventions": conventions,
        "count": len(conventions),
    }


def _handle_save(ctx, args: dict) -> dict:
    ctx.save()
    pi = ctx.get_program()
    return {"saved": [pi.name]}


def _handle_add_entry(ctx, args: dict) -> dict:
    ida_idaapi, _, _, _, _, ida_entry, _, _, _, _, _, _ = _ida()

    addr_str = args.get("address", "")
    name = args.get("name", "")
    ordinal = int(args.get("ordinal", 0))
    makecode = bool(args.get("makecode", True))

    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)

    def do_add():
        res = ida_entry.add_entry(ordinal, addr, name or "", makecode, 0)
        return {
            "success": res,
            "address": f"0x{addr:x}",
            "name": name or "",
            "ordinal": ordinal,
        }

    result = ctx.run_on_main_thread(do_add)
    ctx.save()
    return result


def _handle_rename_entry(ctx, args: dict) -> dict:
    ida_idaapi, _, _, _, _, ida_entry, _, _, _, _, _, _ = _ida()

    ordinal = int(args.get("ordinal", -1))
    name = args.get("name", "")

    if ordinal < 0:
        raise ValueError("Missing or invalid required argument: ordinal")
    if not name:
        raise ValueError("Missing required argument: name")

    def do_rename():
        res = ida_entry.rename_entry(ordinal, name, 0)
        return {
            "success": res,
            "ordinal": ordinal,
            "name": name,
        }

    result = ctx.run_on_main_thread(do_rename)
    ctx.save()
    return result


register_handler("load", _handle_load)
register_handler("list_binaries", _handle_list_binaries)
register_handler("function", _handle_function)
register_handler("functions", _handle_functions)
register_handler("imports", _handle_imports)
register_handler("exports", _handle_exports)
register_handler("metadata", _handle_metadata)
register_handler("relocations", _handle_relocations)
register_handler("list_calling_conventions", _handle_list_calling_conventions)
register_handler("save", _handle_save)
register_handler("add_entry", _handle_add_entry)
register_handler("rename_entry", _handle_rename_entry)
