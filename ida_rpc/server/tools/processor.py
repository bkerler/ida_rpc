# (c) B. Kerler 2026, MIT license
"""Processor context tools: get/set ISA context registers.

Useful for ARM/Thumb switching and other processor-specific contexts.
"""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_idp
    import ida_idaapi
    import ida_ida
    return ida_idp, ida_idaapi, ida_ida


def _get_regnum(reg_name: str, ida_idp) -> int:
    """Get the register number for a segment register by name."""
    reg_name_lower = reg_name.lower()
    try:
        regnum = ida_idp.str2sreg(reg_name)
        if regnum >= 0:
            return regnum
    except Exception:
        pass
    try:
        regnum = ida_idp.str2reg(reg_name)
        if regnum >= 0:
            return regnum
    except Exception:
        pass
    try:
        for i, name in enumerate(ida_idp.ph.regnames):
            if name and name.lower() == reg_name_lower:
                return i
    except Exception:
        pass
    return -1


def _get_sreg(ea: int, regnum: int, ida_idaapi):
    """Read a segment register using the IDA 9.x segment-register API."""
    try:
        import ida_segregs
        return ida_segregs.get_sreg(ea, regnum)
    except Exception:
        pass
    return ida_idaapi.BADADDR


def _get_sreg_tag():
    import ida_segregs
    return ida_segregs.SR_user


def _set_sreg(ea: int, reg: str, regnum: int, value: int) -> tuple[bool, list[str]]:
    """Set a segment register value using the IDA 9.x API."""
    tag = _get_sreg_tag()
    try:
        import ida_segregs
        success = bool(ida_segregs.split_sreg_range(ea, regnum, value, tag))
        return success, [] if success else ["ida_segregs.split_sreg_range returned False"]
    except Exception as exc:
        return False, [f"ida_segregs.split_sreg_range: {exc}"]


def _iter_sregs(ida_idp):
    try:
        regnames = ida_idp.ph_get_regnames()
    except Exception:
        regnames = getattr(ida_idp.ph, "regnames", [])
    try:
        first = ida_idp.ph_get_reg_first_sreg()
        last = ida_idp.ph_get_reg_last_sreg()
    except Exception:
        first = getattr(ida_idp.ph, "reg_first_sreg", 0)
        last = getattr(ida_idp.ph, "reg_last_sreg", -1)
    for regnum in range(first, last + 1):
        name = regnames[regnum] if 0 <= regnum < len(regnames) else f"reg_{regnum}"
        if name:
            yield regnum, name


def _set_proc_options(ida_idp, options: str, confidence: int):
    normalized = options.strip().lower().replace("_", "-")
    if normalized in {"encoding=nanomips", "mips-encoding=nanomips"}:
        try:
            ida_idp.process_config_directive("MIPS_ENCODING=nanoMIPS", 3)
        except Exception:
            pass
    try:
        setter = getattr(ida_idp.ph, "set_proc_options")
        return setter(options, confidence)
    except AttributeError:
        pass
    try:
        return ida_idp.processor_t.set_proc_options(options, confidence)
    except AttributeError:
        import ida_ida

        procname = ida_ida.inf_get_procname()
        ok = ida_idp.set_processor_type(f"{procname}:{options}", confidence)
        return 1 if ok else -1


def _set_idp_options(ida_idp, keyword: str, value_type: int, value, idb_loaded: bool):
    try:
        setter = getattr(ida_idp.ph, "set_idp_options")
        return setter(keyword, value_type, value, idb_loaded)
    except AttributeError:
        pass
    try:
        return ida_idp.processor_t.set_idp_options(keyword, value_type, value, idb_loaded)
    except AttributeError:
        if keyword and isinstance(value, str):
            return _set_proc_options(ida_idp, f"{keyword}={value}", ida_idp.SETPROC_USER)
        raise


def _handle_get_processor_context(ctx, args: dict) -> dict:
    ida_idp, ida_idaapi, ida_ida = _ida()

    _ = args.get("binary", "")
    address = args.get("address", "")
    reg = args.get("register", "")

    if not address:
        if getattr(ctx.session, "mode", "headless") != "gui":
            raise ValueError("Missing required argument: address in headless mode")
        try:
            import ida_kernwin
            ea = ida_kernwin.get_screen_ea()
        except ImportError:
            raise ValueError("Missing required argument: address")
    else:
        ea = ctx.resolve_address(address)

    def do_get():
        processor = ida_ida.inf_get_procname()
        result = {
            "address": f"0x{ea:x}",
            "processor": processor,
            "tool_version": "processor-context-sregs-2026-07-04",
            "registers": {},
        }

        if reg:
            regnum = _get_regnum(reg, ida_idp)
            if regnum < 0:
                raise ValueError(f"Unknown register '{reg}' for processor '{processor}'")
            val = _get_sreg(ea, regnum, ida_idaapi)
            if val == ida_idaapi.BADADDR:
                val = None
            result["registers"][reg] = val
        else:
            # Return common context registers
            common_regs = []
            proc_lower = processor.lower() if processor else ""
            if "arm" in proc_lower:
                common_regs = ["T", "DS"]  # T = Thumb, DS = data segment
            elif "x86" in proc_lower or "8086" in proc_lower:
                common_regs = ["CS", "DS", "SS", "ES"]
            elif "mips" in proc_lower:
                common_regs = ["DS"]
            elif "ppc" in proc_lower or "powerpc" in proc_lower:
                common_regs = ["DS"]
            else:
                # Return first few segment registers
                common_regs = [name for name in ida_idp.ph.regnames if name][:4]

            for rname in common_regs:
                regnum = _get_regnum(rname, ida_idp)
                if regnum >= 0:
                    val = _get_sreg(ea, regnum, ida_idaapi)
                    if val == ida_idaapi.BADADDR:
                        val = None
                    result["registers"][rname] = val
            result["segment_registers"] = {}
            for regnum, rname in _iter_sregs(ida_idp):
                val = _get_sreg(ea, regnum, ida_idaapi)
                if val == ida_idaapi.BADADDR:
                    val = None
                result["segment_registers"][rname] = {
                    "number": regnum,
                    "value": val,
                }

        return result

    return ctx.run_on_main_thread(do_get)


def _handle_set_processor_context(ctx, args: dict) -> dict:
    ida_idp, ida_idaapi, ida_ida = _ida()

    _ = args.get("binary", "")
    address = args.get("address", "")
    end_str = args.get("end", "")
    reg = args.get("register", "")
    value = args.get("value")

    if not address:
        raise ValueError("Missing required argument: address")
    if not reg:
        raise ValueError("Missing required argument: register")
    if value is None:
        raise ValueError("Missing required argument: value")

    ea = ctx.resolve_address(address)
    end = ctx.resolve_address(end_str) if end_str else ea + 1
    value = int(value)

    def do_set():
        regnum = _get_regnum(reg, ida_idp)
        if regnum < 0:
            processor = ida_ida.inf_get_procname()
            raise ValueError(f"Unknown register '{reg}' for processor '{processor}'")

        ok, errors = _set_sreg(ea, reg, regnum, value)
        if not ok:
            raise RuntimeError(
                "Failed to set processor context. "
                "Tried all known segment register APIs: " + "; ".join(errors)
            )

        return {
            "address": f"0x{ea:x}",
            "end": f"0x{end:x}",
            "register": reg,
            "value": value,
            "action": "set",
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_get_abi_name(ctx, args: dict) -> dict:
    def do_get():
        import ida_typeinf
        return {"abi": ida_typeinf.get_abi_name()}

    return ctx.run_on_main_thread(do_get)


def _handle_set_abi_name(ctx, args: dict) -> dict:
    abi = args.get("abi", "")
    if not abi:
        raise ValueError("Missing required argument: abi")

    def do_set():
        import ida_typeinf
        old = ida_typeinf.get_abi_name()
        ok = ida_typeinf.set_abi_name(abi, True)
        new = ida_typeinf.get_abi_name()
        return {
            "old_abi": old,
            "new_abi": new,
            "requested_abi": abi,
            "verified": ok and new == abi,
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_set_processor_options(ctx, args: dict) -> dict:
    options = args.get("options", "")
    confidence_name = args.get("confidence", "user")
    if not options:
        raise ValueError("Missing required argument: options")

    def do_set():
        import ida_idp

        confidence_map = {
            "idb": ida_idp.SETPROC_IDB,
            "loader": ida_idp.SETPROC_LOADER,
            "loader_non_fatal": ida_idp.SETPROC_LOADER_NON_FATAL,
            "user": ida_idp.SETPROC_USER,
        }
        if isinstance(confidence_name, str):
            confidence_key = confidence_name.strip().lower().replace("-", "_")
            if confidence_key not in confidence_map:
                raise ValueError(f"Unknown processor option confidence: {confidence_name}")
            confidence = confidence_map[confidence_key]
        else:
            confidence = int(confidence_name)

        ret = _set_proc_options(ida_idp, options, confidence)
        return {
            "options": options,
            "confidence": confidence_name,
            "return_value": ret,
            "verified": ret >= 0,
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_set_idp_option(ctx, args: dict) -> dict:
    keyword = args.get("keyword", "")
    value = args.get("value")
    value_type_name = args.get("value_type", "str")
    idb_loaded = bool(args.get("idb_loaded", True))

    if not keyword:
        raise ValueError("Missing required argument: keyword")
    if value is None:
        raise ValueError("Missing required argument: value")

    def do_set():
        import ida_idp

        value_type_map = {
            "str": ida_idp.IDPOPT_STR,
            "string": ida_idp.IDPOPT_STR,
            "qstring": ida_idp.IDPOPT_STR_QSTRING,
            "longstr": ida_idp.IDPOPT_STR_LONG,
            "num": ida_idp.IDPOPT_NUM,
            "int": ida_idp.IDPOPT_NUM_INT,
            "char": ida_idp.IDPOPT_NUM_CHAR,
            "short": ida_idp.IDPOPT_NUM_SHORT,
            "range": ida_idp.IDPOPT_NUM_RANGE,
            "uns": ida_idp.IDPOPT_NUM_UNS,
            "bit": ida_idp.IDPOPT_BIT,
            "bool": ida_idp.IDPOPT_BIT_BOOL,
            "flt": ida_idp.IDPOPT_FLT,
            "i64": ida_idp.IDPOPT_I64,
            "i64_range": ida_idp.IDPOPT_I64_RANGE,
            "i64_uns": ida_idp.IDPOPT_I64_UNS,
        }
        if isinstance(value_type_name, str):
            type_key = value_type_name.strip().lower().replace("-", "_")
            if type_key not in value_type_map:
                raise ValueError(f"Unknown IDP option value type: {value_type_name}")
            value_type = value_type_map[type_key]
        else:
            value_type = int(value_type_name)

        send_value = value
        if value_type != ida_idp.IDPOPT_STR and value_type != ida_idp.IDPOPT_STR_QSTRING and value_type != ida_idp.IDPOPT_STR_LONG:
            try:
                send_value = int(value, 0) if isinstance(value, str) else int(value)
            except Exception:
                send_value = value

        ret = _set_idp_options(ida_idp, keyword, value_type, send_value, idb_loaded)
        return {
            "keyword": keyword,
            "value_type": value_type_name,
            "value": value,
            "idb_loaded": idb_loaded,
            "return_value": ret,
            "verified": ret in (None, "", 0, ida_idp.IDPOPT_OK),
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_process_config_directive(ctx, args: dict) -> dict:
    directive = args.get("directive", "")
    priority = int(args.get("priority", 2))
    if not directive:
        raise ValueError("Missing required argument: directive")

    def do_set():
        import ida_idp

        ret = ida_idp.process_config_directive(directive, priority)
        return {
            "directive": directive,
            "priority": priority,
            "return_value": ret,
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_registry_read(ctx, args: dict) -> dict:
    name = args.get("name", "")
    subkey = args.get("subkey")
    default = args.get("default")
    value_type = args.get("value_type", "str")
    if not name:
        raise ValueError("Missing required argument: name")

    def do_get():
        import ida_registry

        type_key = value_type.strip().lower()
        if type_key in {"int", "num", "dword"}:
            value = ida_registry.reg_read_int(name, int(default or 0), subkey)
        elif type_key in {"bool", "bit"}:
            value = ida_registry.reg_read_bool(name, bool(default), subkey)
        else:
            value = ida_registry.reg_read_string(name, subkey, default)
        return {
            "name": name,
            "subkey": subkey,
            "value_type": value_type,
            "value": value,
            "exists": ida_registry.reg_exists(name, subkey),
        }

    return ctx.run_on_main_thread(do_get)


def _handle_registry_write(ctx, args: dict) -> dict:
    name = args.get("name", "")
    value = args.get("value")
    subkey = args.get("subkey")
    value_type = args.get("value_type", "str")
    if not name:
        raise ValueError("Missing required argument: name")
    if value is None:
        raise ValueError("Missing required argument: value")

    def do_set():
        import ida_registry

        type_key = value_type.strip().lower()
        if type_key in {"int", "num", "dword"}:
            ida_registry.reg_write_int(name, int(value, 0) if isinstance(value, str) else int(value), subkey)
        elif type_key in {"bool", "bit"}:
            ida_registry.reg_write_bool(name, bool(value), subkey)
        else:
            ida_registry.reg_write_string(name, str(value), subkey)
        return {
            "name": name,
            "subkey": subkey,
            "value_type": value_type,
            "value": value,
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


register_handler("get_processor_context", _handle_get_processor_context)
register_handler("set_processor_context", _handle_set_processor_context)
register_handler("get_abi_name", _handle_get_abi_name)
register_handler("set_abi_name", _handle_set_abi_name)
register_handler("set_processor_options", _handle_set_processor_options)
register_handler("set_idp_option", _handle_set_idp_option)
register_handler("process_config_directive", _handle_process_config_directive)
register_handler("registry_read", _handle_registry_read)
register_handler("registry_write", _handle_registry_write)
