# (c) B. Kerler 2026, MIT license
"""File offset ↔ virtual address mapping."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_loader
    import ida_idaapi
    return ida_loader, ida_idaapi


def _handle_file_offset(ctx, args: dict) -> dict:
    ida_loader, ida_idaapi = _ida()

    addr_str = args.get("address", "")
    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)
    offset = ida_loader.get_fileregion_offset(addr)

    if offset == ida_idaapi.BADADDR:
        return {"address": f"0x{addr:x}", "offset": None}

    return {"address": f"0x{addr:x}", "offset": offset}


def _handle_file_offset_to_ea(ctx, args: dict) -> dict:
    ida_loader, ida_idaapi = _ida()

    offset = int(args.get("offset", -1))
    if offset < 0:
        raise ValueError("Missing or invalid required argument: offset")

    ea = ida_loader.get_fileregion_ea(offset)

    if ea == ida_idaapi.BADADDR:
        return {"offset": offset, "address": None}

    return {"offset": offset, "address": f"0x{ea:x}"}


register_handler("file_offset", _handle_file_offset)
register_handler("file_offset_to_ea", _handle_file_offset_to_ea)
