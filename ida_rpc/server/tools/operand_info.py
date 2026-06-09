# (c) B. Kerler 2026, MIT license
"""Operand structure path resolution."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_bytes
    import ida_ua
    import ida_typeinf
    import ida_idaapi
    return ida_bytes, ida_ua, ida_typeinf, ida_idaapi


def _handle_operand_struct_path(ctx, args: dict) -> dict:
    ida_bytes, ida_ua, ida_typeinf, ida_idaapi = _ida()

    addr_str = args.get("address", "")
    opnum = int(args.get("operand", 0))

    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)

    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, addr) == 0:
        raise ValueError(f"Failed to decode instruction at 0x{addr:x}")

    if opnum >= insn.ops:
        raise ValueError(f"Invalid operand number {opnum} (instruction has {insn.ops} operands)")

    path = ida_bytes.get_stroff_path(addr, opnum)
    if path is None or len(path) == 0:
        return {
            "address": f"0x{addr:x}",
            "operand": opnum,
            "has_path": False,
        }

    # Resolve path entries to names
    members = []
    for tid, offset in path:
        tif = ida_typeinf.tinfo_t()
        name = ""
        if tif.get_type_by_tid(tid):
            name = tif.get_type_name() or ""
        members.append({
            "name": name,
            "tid": tid,
            "offset": offset,
        })

    return {
        "address": f"0x{addr:x}",
        "operand": opnum,
        "has_path": True,
        "members": members,
    }


register_handler("operand_struct_path", _handle_operand_struct_path)
