# (c) B. Kerler 2026, MIT license
"""Segment management tools: add, edit, delete, list segments."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_segment
    import ida_bytes
    import ida_idaapi
    import idautils
    import idc
    return ida_segment, ida_bytes, ida_idaapi, idautils, idc


def _handle_add_segment(ctx, args: dict) -> dict:
    ida_segment, ida_bytes, ida_idaapi, _, idc = _ida()

    _ = args.get("binary", "")
    start_str = args.get("start", "")
    end_str = args.get("end", "")
    name = args.get("name", "")
    sclass = args.get("class", "")
    align = int(args.get("align", ida_segment.saRelPara))
    flags = int(args.get("flags", 0))

    # Default segment class based on arch if not explicitly provided
    if not sclass:
        arch = getattr(ctx.session, "arch", None)
        if arch:
            arch_lower = arch.lower().strip()
            config = {
                "arm": "CODE32",
                "armv7": "CODE32",
                "armv7-a": "CODE32",
                "armv7-m": "CODE32",
                "armv7m": "CODE32",
                "thumb": "CODE16",
                "thumb2": "CODE16",
                "aarch64": "CODE64",
                "arm64": "CODE64",
                "armv8": "CODE64",
                "armv8-a": "CODE64",
                "x64": "CODE64",
                "x86_64": "CODE64",
                "x86-64": "CODE64",
                "amd64": "CODE64",
                "mips64": "CODE64",
                "mips64el": "CODE64",
                "mips64eb": "CODE64",
                "ppc64": "CODE64",
                "powerpc64": "CODE64",
                "riscv64": "CODE64",
            }
            sclass = config.get(arch_lower, "CODE")
        else:
            sclass = "CODE"

    if not start_str or not end_str:
        raise ValueError("Missing required arguments: start and end")

    start = ctx.resolve_address(start_str)
    end = ctx.resolve_address(end_str)
    if end <= start:
        raise ValueError("end must be greater than start")

    def do_add():
        # Check for overlap
        existing = ida_segment.getseg(start)
        if existing is not None:
            raise ValueError(f"A segment already exists at 0x{start:x}")

        success = ida_segment.add_segm(align, start, end, name or f"seg_{start:x}", sclass, flags)
        if not success:
            raise RuntimeError(f"Failed to add segment 0x{start:x}-0x{end:x}")

        seg = ida_segment.getseg(start)

        # Auto-configure bitness and permissions based on arch
        arch = getattr(ctx.session, "arch", None)
        if arch:
            arch_lower = arch.lower().strip()
            bitness_map = {
                "aarch64": 2, "arm64": 2, "armv8": 2, "armv8-a": 2,
                "x64": 2, "x86_64": 2, "x86-64": 2, "amd64": 2,
                "mips64": 2, "mips64el": 2, "mips64eb": 2,
                "ppc64": 2, "powerpc64": 2, "riscv64": 2,
                "arm": 1, "armv7": 1, "armv7-a": 1, "armv7-m": 1, "armv7m": 1,
                "thumb": 1, "thumb2": 1, "metapc": 1, "x86": 1,
                "i386": 1, "i486": 1, "i586": 1, "i686": 1,
                "mips": 1, "mipsel": 1, "mipsb": 1, "mipseb": 1,
                "ppc": 1, "powerpc": 1, "riscv": 1, "risc-v": 1, "riscv32": 1,
            }
            bitness = bitness_map.get(arch_lower, 1)
            ida_segment.set_segm_addressing(seg, bitness)
            # Set read + execute for code segments
            perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC
            idc.set_segm_attr(start, idc.SEGATTR_PERM, perm)

        return {
            "name": ida_segment.get_segm_name(seg) or "",
            "start": f"0x{seg.start_ea:x}",
            "end": f"0x{seg.end_ea - 1:x}",
            "size": seg.size(),
            "class": sclass,
        }

    result = ctx.run_on_main_thread(do_add)
    ctx.save()
    return result


def _handle_edit_segment(ctx, args: dict) -> dict:
    ida_segment, ida_bytes, ida_idaapi, _, idc = _ida()

    _ = args.get("binary", "")
    start_str = args.get("start", "")
    new_name = args.get("name", "")
    new_class = args.get("class", "")
    perm_read = args.get("perm_read")
    perm_write = args.get("perm_write")
    perm_exec = args.get("perm_exec")
    bitness = args.get("bitness")

    if not start_str:
        raise ValueError("Missing required argument: start")

    start = ctx.resolve_address(start_str)
    seg = ida_segment.getseg(start)
    if seg is None:
        raise ValueError(f"Segment not found at 0x{start:x}")

    def do_edit():
        changed = []
        if new_name:
            ida_segment.set_segm_name(seg, new_name)
            changed.append("name")
        if new_class:
            ida_segment.set_segm_class(seg, new_class)
            changed.append("class")

        perm = seg.perm
        if perm_read is not None:
            if perm_read:
                perm |= ida_segment.SEGPERM_READ
            else:
                perm &= ~ida_segment.SEGPERM_READ
            changed.append("perm_read")
        if perm_write is not None:
            if perm_write:
                perm |= ida_segment.SEGPERM_WRITE
            else:
                perm &= ~ida_segment.SEGPERM_WRITE
            changed.append("perm_write")
        if perm_exec is not None:
            if perm_exec:
                perm |= ida_segment.SEGPERM_EXEC
            else:
                perm &= ~ida_segment.SEGPERM_EXEC
            changed.append("perm_exec")
        if changed:
            idc.set_segm_attr(start, idc.SEGATTR_PERM, perm)

        if bitness is not None:
            # 0=16-bit, 1=32-bit, 2=64-bit
            ida_segment.set_segm_addressing(seg, int(bitness))
            changed.append("bitness")

        return {
            "start": f"0x{seg.start_ea:x}",
            "end": f"0x{seg.end_ea - 1:x}",
            "name": ida_segment.get_segm_name(seg) or "",
            "class": ida_segment.get_segm_class(seg) or "",
            "changed": changed,
        }

    result = ctx.run_on_main_thread(do_edit)
    ctx.save()
    return result


def _handle_delete_segment(ctx, args: dict) -> dict:
    ida_segment, ida_bytes, ida_idaapi, _, _ = _ida()

    _ = args.get("binary", "")
    start_str = args.get("start", "")

    if not start_str:
        raise ValueError("Missing required argument: start")

    start = ctx.resolve_address(start_str)
    seg = ida_segment.getseg(start)
    if seg is None:
        raise ValueError(f"Segment not found at 0x{start:x}")

    name = ida_segment.get_segm_name(seg) or ""
    end_ea = seg.end_ea

    def do_delete():
        success = ida_segment.del_segm(start, ida_segment.SEGMOD_KILL)
        return {
            "start": f"0x{start:x}",
            "end": f"0x{end_ea - 1:x}",
            "name": name,
            "deleted": success,
        }

    result = ctx.run_on_main_thread(do_delete)
    ctx.save()
    return result


def _handle_list_segments(ctx, args: dict) -> dict:
    ida_segment, _, _, idautils, _ = _ida()

    _ = args.get("binary", "")

    segments = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        perm = seg.perm
        segments.append({
            "name": ida_segment.get_segm_name(seg) or "",
            "start": f"0x{seg.start_ea:x}",
            "end": f"0x{seg.end_ea - 1:x}",
            "size": seg.size(),
            "read": bool(perm & ida_segment.SEGPERM_READ),
            "write": bool(perm & ida_segment.SEGPERM_WRITE),
            "execute": bool(perm & ida_segment.SEGPERM_EXEC),
            "initialized": True,
            "type": ida_segment.get_segm_class(seg) or "DEFAULT",
        })

    return {"segments": segments, "count": len(segments)}


register_handler("add_segment", _handle_add_segment)
register_handler("edit_segment", _handle_edit_segment)
register_handler("delete_segment", _handle_delete_segment)
register_handler("list_segments", _handle_list_segments)
