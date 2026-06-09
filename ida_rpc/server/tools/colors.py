# (c) B. Kerler 2026, MIT license
"""Item color tools."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_nalt
    import ida_idaapi
    return ida_nalt, ida_idaapi


def _handle_set_color(ctx, args: dict) -> dict:
    ida_nalt, ida_idaapi = _ida()

    addr_str = args.get("address", "")
    color_str = args.get("color", "")
    if not addr_str:
        raise ValueError("Missing required argument: address")
    if not color_str:
        raise ValueError("Missing required argument: color")

    addr = ctx.resolve_address(addr_str)
    color = int(color_str, 0)

    def do_set():
        ida_nalt.set_item_color(addr, color)
        return {"address": f"0x{addr:x}", "color": f"0x{color:08x}"}

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_get_color(ctx, args: dict) -> dict:
    ida_nalt, ida_idaapi = _ida()

    addr_str = args.get("address", "")
    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)
    color = ida_nalt.get_item_color(addr)

    if color == ida_idaapi.DEFCOLOR:
        return {"address": f"0x{addr:x}", "color": None}

    return {"address": f"0x{addr:x}", "color": f"0x{color:08x}"}


def _handle_del_color(ctx, args: dict) -> dict:
    ida_nalt, ida_idaapi = _ida()

    addr_str = args.get("address", "")
    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)

    def do_del():
        ida_nalt.del_item_color(addr)
        return {"address": f"0x{addr:x}", "deleted": True}

    result = ctx.run_on_main_thread(do_del)
    ctx.save()
    return result


register_handler("set_color", _handle_set_color)
register_handler("get_color", _handle_get_color)
register_handler("del_color", _handle_del_color)
