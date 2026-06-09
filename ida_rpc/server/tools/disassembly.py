# (c) B. Kerler 2026, MIT license
"""Disassembly tools."""

from __future__ import annotations

from ida_rpc.server.main import register_handler

_DEFAULT_COUNT = 20
_MAX_COUNT = 1000


def _ida():
    import ida_ua
    import ida_bytes
    import ida_lines
    import ida_idaapi
    return ida_ua, ida_bytes, ida_lines, ida_idaapi


def _handle_disassemble(ctx, args: dict) -> dict:
    ida_ua, ida_bytes, ida_lines, ida_idaapi = _ida()

    _ = args.get("binary", "")
    address_str = args.get("address", "")
    count = int(args.get("count", _DEFAULT_COUNT))

    if not address_str:
        raise ValueError("Missing required argument: address")
    if count < 1:
        count = 1
    if count > _MAX_COUNT:
        count = _MAX_COUNT

    addr = ctx.resolve_address(address_str)

    # If addr is not a code head, find the next instruction
    actual_start = None
    if not ida_bytes.is_code(ida_bytes.get_flags(addr)):
        next_head = ida_bytes.next_head(addr, ida_idaapi.BADADDR)
        if next_head != ida_idaapi.BADADDR:
            actual_start = next_head
            addr = next_head

    instructions = []
    ea = addr
    for _ in range(count):
        if ea == ida_idaapi.BADADDR:
            break
        flags = ida_bytes.get_flags(ea)
        if not ida_bytes.is_code(flags):
            break

        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if size == 0:
            break

        raw = ida_bytes.get_bytes(ea, size)
        raw_hex = raw.hex() if raw else ""

        mnem = ida_lines.tag_remove(ida_ua.print_insn_mnem(ea) or "")
        ops = []
        for i in range(8):
            op = ida_ua.print_operand(ea, i)
            if op:
                ops.append(ida_lines.tag_remove(op))
        operand_str = ", ".join(ops)

        # Comment
        comment = ida_bytes.get_cmt(ea, 0) or None
        if not comment:
            comment = ida_bytes.get_cmt(ea, 1) or None

        instructions.append({
            "address": f"0x{ea:x}",
            "bytes": raw_hex,
            "mnemonic": mnem,
            "operands": operand_str,
            "length": size,
            "comment": comment,
        })

        # Advance to the next instruction.
        # next_head() skips non-head addresses (e.g., bytes inside a multi-byte
        # instruction or alignment padding). We first try ea+size; if that is
        # not marked as code we let next_head() find the next candidate.
        next_ea = ea + size
        if next_ea != ida_idaapi.BADADDR and not ida_bytes.is_code(ida_bytes.get_flags(next_ea)):
            next_ea = ida_bytes.next_head(next_ea, ida_idaapi.BADADDR)
        ea = next_ea

    result = {
        "address": f"0x{addr:x}",
        "count": len(instructions),
        "instructions": instructions,
        "listing": _format_listing(instructions),
    }
    if actual_start is not None:
        result["warning"] = (
            f"No instruction at {address_str}; disassembly started from the "
            f"next available instruction at 0x{actual_start:x}."
        )
    return result


def _format_listing(instructions: list) -> str:
    if not instructions:
        return ""
    max_bytes_len = max(len(i["bytes"]) for i in instructions)
    max_bytes_len = max(max_bytes_len, 2)
    bytes_col = max(max_bytes_len // 2 * 3 - 1, 8)

    lines = []
    for i in instructions:
        addr = i["address"]
        raw = i["bytes"]
        mnem = i["mnemonic"]
        ops = i["operands"]
        comment = i["comment"]

        hex_pairs = " ".join(raw[j:j+2] for j in range(0, len(raw), 2))
        hex_col = hex_pairs.ljust(bytes_col)

        instr_str = f"{mnem:<8} {ops}" if ops else mnem
        line = f"{addr}  {hex_col}  {instr_str}"
        if comment:
            line += f"  ; {comment}"
        lines.append(line)

    return "\n".join(lines)


register_handler("disassemble", _handle_disassemble)
