# (c) B. Kerler 2026, MIT license
"""Memory inspection tools: read raw bytes from a program's address space."""

from __future__ import annotations

from ida_rpc.server.main import register_handler

_MAX_READ_BYTES = 65536
_MAX_WRITE_BYTES = 4096


def _ida():
    import ida_bytes
    import ida_segment
    import ida_ida
    import ida_idaapi
    import idautils
    import ida_nalt
    return ida_bytes, ida_segment, ida_ida, ida_idaapi, idautils, ida_nalt


def _format_hexdump(start_addr: int, data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        line_addr = start_addr + offset
        left = chunk[:8]
        right = chunk[8:]
        hex_left = " ".join(f"{b:02x}" for b in left)
        hex_right = " ".join(f"{b:02x}" for b in right)
        hex_left = hex_left.ljust(8 * 3 - 1)
        hex_right = hex_right.ljust(8 * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{line_addr:08x}  {hex_left}  {hex_right}  |{ascii_part}|")
    return "\n".join(lines)


def _handle_read_bytes(ctx, args: dict) -> dict:
    ida_bytes, _, _, ida_idaapi, _, _ = _ida()

    _ = args.get("binary", "")
    address_str = args.get("address", "")
    length = args.get("length")

    if not address_str:
        raise ValueError("Missing required argument: address")
    if length is None:
        raise ValueError("Missing required argument: length")

    length = int(length)
    if length < 1:
        raise ValueError("length must be >= 1")
    if length > _MAX_READ_BYTES:
        raise ValueError(f"length must be <= {_MAX_READ_BYTES} (requested {length})")

    addr = ctx.resolve_address(address_str)
    data = ida_bytes.get_bytes(addr, length)
    if data is None:
        raise ValueError(f"Memory read failed at 0x{addr:x}")

    data = bytes(data)
    return {
        "address": f"0x{addr:x}",
        "length": len(data),
        "hex": data.hex(),
        "hexdump": _format_hexdump(addr, data),
    }


def _handle_write_bytes(ctx, args: dict) -> dict:
    ida_bytes, _, _, ida_idaapi, _, _ = _ida()

    _ = args.get("binary", "")
    address_str = args.get("address", "")
    hex_str = args.get("hex", "")

    if not address_str:
        raise ValueError("Missing required argument: address")
    if not hex_str:
        raise ValueError("Missing required argument: hex")

    hex_clean = hex_str.replace(" ", "").strip()
    if len(hex_clean) % 2 != 0:
        raise ValueError(f"Hex string must have an even number of characters (got {len(hex_clean)})")
    try:
        data = bytes.fromhex(hex_clean)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {e}") from e

    if len(data) < 1:
        raise ValueError("At least 1 byte is required")
    if len(data) > _MAX_WRITE_BYTES:
        raise ValueError(f"Write size must be <= {_MAX_WRITE_BYTES} bytes (requested {len(data)})")

    addr = ctx.resolve_address(address_str)

    def do_write():
        for i, b in enumerate(data):
            ida_bytes.patch_byte(addr + i, b)

        # Verify
        read_back = ida_bytes.get_bytes(addr, len(data))
        verified = read_back is not None and bytes(read_back) == data
        return {
            "address": f"0x{addr:x}",
            "length": len(data),
            "hex": data.hex(),
            "verified": verified,
        }

    result = ctx.run_on_main_thread(do_write)
    ctx.save()
    return result


def _handle_read_string(ctx, args: dict) -> dict:
    ida_bytes, _, _, ida_idaapi, _, ida_nalt = _ida()

    addr_str = args.get("address", "")
    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)
    strtype = args.get("strtype", None)
    if strtype is not None:
        strtype = int(strtype, 0)
    else:
        strtype = ida_nalt.get_str_type(addr)
        if strtype == ida_idaapi.BADADDR:
            strtype = ida_nalt.STRTYPE_C

    # Ask IDA for the current item size first; some builds reject -1 here.
    item_size = ida_bytes.get_item_size(addr)
    if item_size <= 0:
        item_size = 0

    # Try to get string contents
    contents = ida_bytes.get_strlit_contents(addr, item_size, strtype)
    if contents is None:
        return {
            "address": f"0x{addr:x}",
            "text": None,
            "bytes": None,
            "length": 0,
            "strtype": f"0x{strtype:x}",
        }

    raw = bytes(contents)
    # Attempt UTF-8 decode, fallback to latin-1
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")

    return {
        "address": f"0x{addr:x}",
        "text": text,
        "bytes": raw.hex(),
        "length": len(raw),
        "strtype": f"0x{strtype:x}",
    }


def _handle_create_string(ctx, args: dict) -> dict:
    ida_bytes, _, _, ida_idaapi, _, ida_nalt = _ida()

    addr_str = args.get("address", "")
    length = int(args.get("length", 0))
    strtype_str = args.get("strtype", "")

    if not addr_str:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(addr_str)

    if strtype_str:
        strtype = int(strtype_str, 0)
    else:
        strtype = ida_nalt.STRTYPE_C

    if length <= 0:
        raise ValueError("Missing or invalid required argument: length")

    def do_create():
        res = ida_bytes.create_strlit(addr, length, strtype)
        return {
            "address": f"0x{addr:x}",
            "length": length,
            "strtype": f"0x{strtype:x}",
            "success": res,
        }

    result = ctx.run_on_main_thread(do_create)
    ctx.save()
    return result


def _handle_memory_map(ctx, args: dict) -> dict:
    _, ida_segment, ida_ida, ida_idaapi, idautils, _ = _ida()

    _ = args.get("binary", "")

    segments = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.segment_info_t()
        if not ida_segment.get_segment_info(seg, seg_ea, ida_segment.GSI_ALL):
            continue
        perm = seg.get_perm()
        segments.append({
            "name": seg.get_name() or "",
            "start": f"0x{seg.start_ea:x}",
            "end": f"0x{seg.end_ea - 1:x}",
            "size": seg.end_ea - seg.start_ea,
            "read": bool(perm & ida_segment.SEGPERM_READ),
            "write": bool(perm & ida_segment.SEGPERM_WRITE),
            "execute": bool(perm & ida_segment.SEGPERM_EXEC),
            "initialized": True,
            "type": "DEFAULT",
        })

    return {"segments": segments, "count": len(segments)}


register_handler("read_bytes", _handle_read_bytes)
register_handler("write_bytes", _handle_write_bytes)
register_handler("read_string", _handle_read_string)
register_handler("create_string", _handle_create_string)
register_handler("memory_map", _handle_memory_map)
