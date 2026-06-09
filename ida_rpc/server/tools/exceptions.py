# (c) B. Kerler 2026, MIT license
"""Try/catch block listing."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_tryblks
    import ida_idaapi
    import ida_range
    return ida_tryblks, ida_idaapi, ida_range


def _handle_list_try_blocks(ctx, args: dict) -> dict:
    ida_tryblks, ida_idaapi, ida_range = _ida()
    import ida_ida

    start_str = args.get("start", "")
    end_str = args.get("end", "")

    if start_str:
        start = ctx.resolve_address(start_str)
    else:
        start = ida_ida.inf_get_min_ea()

    if end_str:
        end = ctx.resolve_address(end_str)
    else:
        end = ida_ida.inf_get_max_ea()

    rng = ida_range.range_t(start, end)
    tbv = ida_tryblks.tryblks_t()
    ida_tryblks.get_tryblks(tbv, rng)

    blocks = []
    for tb in tbv:
        handlers = []
        for h in tb.handlers:
            handlers.append({
                "address": f"0x{h.ea:x}",
                "type": "catch" if isinstance(h, ida_tryblks.catch_t) else "seh",
            })
        blocks.append({
            "start": f"0x{tb.ea:x}",
            "end": f"0x{tb.end_ea():x}" if hasattr(tb, "end_ea") else None,
            "handlers": handlers,
        })

    return {"try_blocks": blocks, "count": len(blocks)}


register_handler("list_try_blocks", _handle_list_try_blocks)
