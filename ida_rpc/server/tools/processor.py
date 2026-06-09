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
        for i, name in enumerate(ida_idp.ph.regnames):
            if name and name.lower() == reg_name_lower:
                return i
    except Exception:
        pass
    return -1


def _get_sreg(ea: int, regnum: int, ida_idaapi):
    """Read a segment register value, trying multiple IDA APIs."""
    # Try idc.get_sreg (IDC compatibility)
    try:
        import idc
        return idc.get_sreg(ea, regnum)
    except Exception:
        pass
    # Try ida_bytes.get_sreg (older IDA)
    try:
        import ida_bytes
        return ida_bytes.get_sreg(ea, regnum)
    except AttributeError:
        pass
    # Try ida_segregs.get_sreg (IDA 9.x)
    try:
        import ida_segregs
        return ida_segregs.get_sreg(ea, regnum)
    except Exception:
        pass
    return ida_idaapi.BADADDR


def _set_sreg(ea: int, regnum: int, value: int, ida_idaapi) -> bool:
    """Set a segment register value, trying multiple IDA APIs."""
    # Try idc.split_sreg_range (IDC compatibility)
    try:
        import idc
        idc.split_sreg_range(ea, regnum, value, ida_idaapi.SR_user)
        return True
    except Exception:
        pass
    # Try ida_bytes.split_sreg_range (older IDA)
    try:
        import ida_bytes
        ida_bytes.split_sreg_range(ea, regnum, value, ida_idaapi.SR_user)
        return True
    except Exception:
        pass
    # Try ida_srarea.split_sreg_range (older IDA)
    try:
        import ida_srarea
        ida_srarea.split_sreg_range(ea, regnum, value, ida_idaapi.SR_user)
        return True
    except Exception:
        pass
    # Try ida_segregs.split_sreg_range (IDA 9.x)
    try:
        import ida_segregs
        ida_segregs.split_sreg_range(ea, regnum, value, ida_idaapi.SR_user)
        return True
    except Exception:
        pass
    return False


def _handle_get_processor_context(ctx, args: dict) -> dict:
    ida_idp, ida_idaapi, ida_ida = _ida()

    _ = args.get("binary", "")
    address = args.get("address", "")
    reg = args.get("register", "")

    if not address:
        # Use current screen EA if available
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

        if not _set_sreg(ea, regnum, value, ida_idaapi):
            raise RuntimeError(
                "Failed to set processor context. "
                "Segment register APIs are not available in this IDA version."
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


register_handler("get_processor_context", _handle_get_processor_context)
register_handler("set_processor_context", _handle_set_processor_context)
