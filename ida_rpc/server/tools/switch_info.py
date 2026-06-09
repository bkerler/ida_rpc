# (c) B. Kerler 2026, MIT license
"""Jump table / switch info extraction."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_nalt
    import ida_idaapi
    import ida_bytes
    return ida_nalt, ida_idaapi, ida_bytes


def _handle_get_switch_info(ctx, args: dict) -> dict:
    ida_nalt, ida_idaapi, ida_bytes = _ida()

    addr_str = args.get("address", "")
    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)

    si = ida_nalt.switch_info_t()
    if not ida_nalt.get_switch_info(si, addr):
        return {
            "address": f"0x{addr:x}",
            "has_switch": False,
        }

    cases = []
    for i in range(si.get_jrange_size()):
        jrange = si.get_jrange(i)
        if jrange:
            cases.append({
                "low": jrange.low,
                "high": jrange.high,
                "targets": [f"0x{t:x}" for t in jrange.targets],
            })

    # Try to get default case
    default_case = None
    try:
        def_ea = si.defjump
        if def_ea != ida_idaapi.BADADDR:
            default_case = f"0x{def_ea:x}"
    except Exception:
        pass

    return {
        "address": f"0x{addr:x}",
        "has_switch": True,
        "cases": cases,
        "default_case": default_case,
        "jump_target": f"0x{si.jump_ea:x}" if hasattr(si, "jump_ea") else None,
        "eltsize": si.get_jrange_eltsize() if hasattr(si, "get_jrange_eltsize") else None,
    }


register_handler("get_switch_info", _handle_get_switch_info)
