# (c) B. Kerler 2026, MIT license
"""Search tools: strings, symbols, byte patterns."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_bytes
    import ida_search
    import ida_idaapi
    import idautils
    import ida_name
    return ida_bytes, ida_search, ida_idaapi, idautils, ida_name


def _normalize_byte_pattern(pattern: str) -> tuple[str, int]:
    """Normalize a byte pattern and return (ida_pattern, mask_len).

    Accepts patterns like:
      "55 8b ?? 83 ec"
      "558b??83ec"
      "90 90 90 EB ."
    Returns IDA-compatible space-separated hex with '??' wildcards.
    """
    p = pattern.strip()
    if " " not in p and len(p) > 2:
        p = " ".join(p[i:i+2] for i in range(0, len(p), 2))
    tokens = p.split()
    normalized = []
    for tok in tokens:
        tok = tok.strip()
        if tok in ("??", ".", "**", "xx"):
            normalized.append("??")
        else:
            try:
                val = int(tok, 16)
                if not (0 <= val <= 0xFF):
                    raise ValueError(f"Byte value out of range: {tok}")
                normalized.append(f"{val:02x}")
            except ValueError:
                raise ValueError(
                    f"Invalid byte pattern token: '{tok}'. "
                    f"Use hex bytes (00-ff) or '??' / '.' for wildcards."
                )
    if not normalized:
        raise ValueError("Empty byte pattern")
    return " ".join(normalized), len(normalized)


def _handle_find_bytes(ctx, args: dict) -> dict:
    ida_bytes, _, ida_idaapi, _, _ = _ida()
    import ida_ida

    _ = args.get("binary", "")
    pattern_str = args.get("pattern", "")
    limit = int(args.get("limit", 100))
    start_str = args.get("address", "")

    if not pattern_str:
        raise ValueError("Missing required argument: pattern")
    if limit < 1:
        limit = 1
    if limit > 10000:
        limit = 10000

    normalized, pat_len = _normalize_byte_pattern(pattern_str)

    if start_str:
        start = ctx.resolve_address(start_str)
    else:
        start = ida_ida.inf_get_min_ea()

    matches = []
    ea = start
    while ea != ida_idaapi.BADADDR and len(matches) < limit:
        ea = ida_bytes.find_bytes(normalized, ea, range_end=ida_idaapi.BADADDR,
                                  flags=ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW)
        if ea == ida_idaapi.BADADDR:
            break
        # Read context
        try:
            ctx_start = max(ea - 16, ida_ida.inf_get_min_ea())
            ctx_len = 16 + pat_len + 16
            raw = ida_bytes.get_bytes(ctx_start, ctx_len)
            context_hex = raw.hex() if raw else ""
        except Exception:
            try:
                raw = ida_bytes.get_bytes(ea, pat_len)
                context_hex = raw.hex() if raw else ""
            except Exception:
                context_hex = ""
        matches.append({
            "address": f"0x{ea:x}",
            "context_hex": context_hex,
        })
        # Search from next address to avoid finding the same match
        ea = ea + 1

    return {
        "pattern": normalized,
        "matches": matches,
        "count": len(matches),
        "truncated": len(matches) >= limit,
    }


def _handle_strings(ctx, args: dict) -> dict:
    _, _, _, idautils, _ = _ida()
    import ida_nalt

    _ = args.get("binary", "")
    query = args.get("query", "")
    limit = int(args.get("limit", 100))

    query_lower = query.lower() if query else None
    results = []
    s = idautils.Strings(False)
    s.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16])
    for item in s:
        if len(results) >= limit:
            break
        val = str(item)
        if query_lower is None or query_lower in val.lower():
            results.append({
                "address": f"0x{item.ea:x}",
                "value": val,
                "type": f"0x{item.strtype:x}",
            })

    return {"strings": results, "count": len(results)}


def _handle_find_string(ctx, args: dict) -> dict:
    ida_bytes, _, ida_idaapi, _, _ = _ida()
    import ida_ida
    import ida_nalt

    _ = args.get("binary", "")
    query = args.get("query", "")
    limit = int(args.get("limit", 100))
    start_str = args.get("address", "")

    if not query:
        raise ValueError("Missing required argument: query")

    if start_str:
        start = ctx.resolve_address(start_str)
    else:
        start = ida_ida.inf_get_min_ea()

    matches = []
    ea = start
    while ea != ida_idaapi.BADADDR and len(matches) < limit:
        # find_string searches for the next string literal
        ea = ida_bytes.find_string(ea, ida_idaapi.BADADDR, query, 0, ida_nalt.STRTYPE_C)
        if ea == ida_idaapi.BADADDR:
            break
        # Read string contents
        contents = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
        text = ""
        if contents:
            raw = bytes(contents)
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
        matches.append({
            "address": f"0x{ea:x}",
            "text": text,
        })
        ea = ea + 1

    return {
        "query": query,
        "matches": matches,
        "count": len(matches),
    }


def _handle_symbols(ctx, args: dict) -> dict:
    _, _, _, idautils, ida_name = _ida()
    import ida_idaapi

    _ = args.get("binary", "")
    query = args.get("query", "")
    limit = int(args.get("limit", 25))
    offset = int(args.get("offset", 0))

    if not query:
        raise ValueError("Missing required argument: query")

    query_lower = query.lower()
    results = []
    seen_addrs: set[str] = set()

    # Iterate all named items
    for ea, name in idautils.Names():
        if name and (query_lower in name.lower()):
            addr_str = f"0x{ea:x}"
            seen_addrs.add(addr_str)
            results.append({
                "name": name,
                "address": addr_str,
                "type": "name",
            })

    # Also check entries/exports
    import ida_entry
    nentries = ida_entry.get_entry_qty()
    for i in range(nentries):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        if name and (query_lower in name.lower()):
            addr_str = f"0x{ea:x}"
            if addr_str not in seen_addrs:
                seen_addrs.add(addr_str)
                results.append({
                    "name": name,
                    "address": addr_str,
                    "type": "export",
                })

    results.sort(key=lambda r: (
        0 if r["name"].lower() == query_lower else 1,
        r["name"].lower(),
    ))

    paginated = results[offset:offset + limit]
    return {"symbols": paginated, "count": len(paginated), "total": len(results)}


register_handler("find_bytes", _handle_find_bytes)
register_handler("strings", _handle_strings)
register_handler("find_string", _handle_find_string)
register_handler("symbols", _handle_symbols)
