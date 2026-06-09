# (c) B. Kerler 2026, MIT license
"""Patch management: list patched bytes, revert patches, scalar patches."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_bytes
    import ida_idaapi
    import ida_ida
    return ida_bytes, ida_idaapi, ida_ida


def _handle_list_patches(ctx, args: dict) -> dict:
    ida_bytes, ida_idaapi, ida_ida = _ida()

    start_str = args.get("start", "")
    end_str = args.get("end", "")
    limit = int(args.get("limit", 500))

    if start_str:
        start = ctx.resolve_address(start_str)
    else:
        start = ida_ida.inf_get_min_ea()

    if end_str:
        end = ctx.resolve_address(end_str)
    else:
        end = ida_ida.inf_get_max_ea()

    patches = []

    def visitor(ea, fpos, o, v):
        if len(patches) >= limit:
            return 1  # stop
        if ea < start or ea >= end:
            return 0
        patches.append({
            "address": f"0x{ea:x}",
            "original": f"0x{o:02x}",
            "patched": f"0x{v:02x}",
        })
        return 0

    ida_bytes.visit_patched_bytes(start, end, visitor)

    return {"patches": patches, "count": len(patches)}


def _handle_revert_patch(ctx, args: dict) -> dict:
    ida_bytes, ida_idaapi, ida_ida = _ida()

    start_str = args.get("start", "")
    end_str = args.get("end", "")
    if not start_str:
        raise ValueError("Missing required argument: start")

    start = ctx.resolve_address(start_str)
    if end_str:
        end = ctx.resolve_address(end_str)
    else:
        end = start + 1

    def do_revert():
        count = 0
        for ea in range(start, end):
            if ida_bytes.is_patched(ea):
                ida_bytes.revert_byte(ea)
                count += 1
        return {
            "start": f"0x{start:x}",
            "end": f"0x{end:x}",
            "count": count,
        }

    result = ctx.run_on_main_thread(do_revert)
    ctx.save()
    return result


def _handle_patch_byte(ctx, args: dict) -> dict:
    ida_bytes, ida_idaapi, ida_ida = _ida()

    addr_str = args.get("address", "")
    value = int(args.get("value", 0))
    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)

    def do_patch():
        ida_bytes.patch_byte(addr, value & 0xFF)
        return {
            "address": f"0x{addr:x}",
            "value": f"0x{value & 0xFF:02x}",
        }

    result = ctx.run_on_main_thread(do_patch)
    ctx.save()
    return result


def _handle_patch_word(ctx, args: dict) -> dict:
    ida_bytes, ida_idaapi, ida_ida = _ida()

    addr_str = args.get("address", "")
    value = int(args.get("value", 0))
    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)

    def do_patch():
        ida_bytes.patch_word(addr, value & 0xFFFF)
        return {
            "address": f"0x{addr:x}",
            "value": f"0x{value & 0xFFFF:04x}",
        }

    result = ctx.run_on_main_thread(do_patch)
    ctx.save()
    return result


def _handle_patch_dword(ctx, args: dict) -> dict:
    ida_bytes, ida_idaapi, ida_ida = _ida()

    addr_str = args.get("address", "")
    value = int(args.get("value", 0))
    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)

    def do_patch():
        ida_bytes.patch_dword(addr, value & 0xFFFFFFFF)
        return {
            "address": f"0x{addr:x}",
            "value": f"0x{value & 0xFFFFFFFF:08x}",
        }

    result = ctx.run_on_main_thread(do_patch)
    ctx.save()
    return result


def _handle_patch_qword(ctx, args: dict) -> dict:
    ida_bytes, ida_idaapi, ida_ida = _ida()

    addr_str = args.get("address", "")
    value = int(args.get("value", 0))
    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)

    def do_patch():
        ida_bytes.patch_qword(addr, value & 0xFFFFFFFFFFFFFFFF)
        return {
            "address": f"0x{addr:x}",
            "value": f"0x{value & 0xFFFFFFFFFFFFFFFF:016x}",
        }

    result = ctx.run_on_main_thread(do_patch)
    ctx.save()
    return result


register_handler("list_patches", _handle_list_patches)
register_handler("revert_patch", _handle_revert_patch)
register_handler("patch_byte", _handle_patch_byte)
register_handler("patch_word", _handle_patch_word)
register_handler("patch_dword", _handle_patch_dword)
register_handler("patch_qword", _handle_patch_qword)
