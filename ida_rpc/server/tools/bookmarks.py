# (c) B. Kerler 2026, MIT license
"""Bookmark tools for IDA Pro.

IDA bookmarks are per-view (disasm, pseudocode, etc.). We emulate global
bookmarks using a netnode with supval storage (address as index).
"""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _get_global_bookmark_node():
    import ida_netnode
    node = ida_netnode.netnode("$ida_rpc_bookmarks", 0, True)
    return node


def _handle_set_bookmark(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    address_str = args.get("address", "")
    bm_type = args.get("type", "Note")
    category = args.get("category", "")
    comment = args.get("comment", "")

    if not address_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(address_str)

    # Normalize type
    valid_types = {"Note", "Warning", "Error", "Info", "Analysis"}
    bm_type_norm = None
    for vt in valid_types:
        if bm_type.lower() == vt.lower():
            bm_type_norm = vt
            break
    if bm_type_norm is None:
        raise ValueError(f"Invalid bookmark type '{bm_type}'. Valid: {sorted(valid_types)}")

    def do_set():
        node = _get_global_bookmark_node()
        # Store as: addr -> "type|category|comment"
        val = f"{bm_type_norm}\x01{category}\x01{comment}"
        node.supset(addr, val)
        return {
            "address": f"0x{addr:x}",
            "type": bm_type_norm,
            "category": category,
            "comment": comment,
            "action": "created",
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_list_bookmarks(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    bm_type = args.get("type", "")
    address_str = args.get("address", "")
    limit = int(args.get("limit", 200))

    def do_list():
        node = _get_global_bookmark_node()
        import ida_idaapi
        bookmarks = []
        idx = node.supfirst()
        while idx != ida_idaapi.BADADDR:
            if len(bookmarks) >= limit:
                break
            val = node.supstr(idx)
            if val:
                parts = val.split("\x01", 2)
                btype = parts[0] if len(parts) > 0 else ""
                bcat = parts[1] if len(parts) > 1 else ""
                bcomment = parts[2] if len(parts) > 2 else ""

                if bm_type and bm_type.lower() != btype.lower():
                    idx = node.supnext(idx)
                    continue
                if address_str:
                    addr = ctx.resolve_address(address_str)
                    if idx != addr:
                        idx = node.supnext(idx)
                        continue

                bookmarks.append({
                    "address": f"0x{idx:x}",
                    "type": btype,
                    "category": bcat,
                    "comment": bcomment,
                })
            idx = node.supnext(idx)

        return {"bookmarks": bookmarks, "count": len(bookmarks)}

    return ctx.run_on_main_thread(do_list)


def _handle_remove_bookmark(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    address_str = args.get("address", "")
    bm_type = args.get("type", "Note")

    if not address_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(address_str)

    def do_remove():
        node = _get_global_bookmark_node()
        val = node.supstr(addr)
        if val:
            node.supdel(addr)
            return {"address": f"0x{addr:x}", "type": bm_type, "removed": True}
        return {"address": f"0x{addr:x}", "type": bm_type, "removed": False}

    result = ctx.run_on_main_thread(do_remove)
    ctx.save()
    return result


register_handler("set_bookmark", _handle_set_bookmark)
register_handler("list_bookmarks", _handle_list_bookmarks)
register_handler("remove_bookmark", _handle_remove_bookmark)
