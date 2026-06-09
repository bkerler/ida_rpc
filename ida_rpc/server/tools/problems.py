# (c) B. Kerler 2026, MIT license
"""IDA analysis problem listing."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_problems
    import ida_idaapi
    return ida_problems, ida_idaapi


# Problem type constants from ida_problems
_PROBLEM_TYPES = [
    "PR_NOBASE", "PR_NONAME", "PR_NOXREFS", "PR_JUMP", "PR_DISASM",
    "PR_HEAD", "PR_ILLADDR", "PR_MANYLINES", "PR_BADSTACK", "PR_ATTN",
    "PR_FINAL", "PR_ROLLED", "PR_COLLISION", "PR_DECIMP",
]


def _handle_list_problems(ctx, args: dict) -> dict:
    ida_problems, ida_idaapi = _ida()

    limit = int(args.get("limit", 500))
    type_filter = args.get("type", "")

    results = []

    for pt_name in _PROBLEM_TYPES:
        if not hasattr(ida_problems, pt_name):
            continue
        pt = getattr(ida_problems, pt_name)

        if type_filter and pt_name != type_filter:
            continue

        ea = ida_idaapi.BADADDR
        while True:
            ea = ida_problems.get_problem(pt, ea)
            if ea == ida_idaapi.BADADDR:
                break
            if len(results) >= limit:
                break
            desc = ida_problems.get_problem_desc(pt, ea)
            name = ida_problems.get_problem_name(pt, False)
            results.append({
                "type": pt_name,
                "address": f"0x{ea:x}",
                "description": desc or "",
                "category": name or pt_name,
            })
        if len(results) >= limit:
            break

    return {"problems": results, "count": len(results)}


register_handler("list_problems", _handle_list_problems)
