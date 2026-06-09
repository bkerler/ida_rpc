# (c) B. Kerler 2026, MIT license
"""Function tag tools.

IDA does not have native function tags like Ghidra, but we emulate them
using function color groups or repeatable comments with a tag prefix.
For simplicity, we use a netnode to store tags per function.
"""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _get_tag_node():
    import ida_netnode
    node = ida_netnode.netnode("$ida_rpc_tags", 0, True)
    return node


def _handle_tag_function(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    target = args.get("target", "")
    tag = args.get("tag", "")

    if not target:
        raise ValueError("Missing required argument: target")
    if not tag:
        raise ValueError("Missing required argument: tag")

    func_ea = ctx.find_function(target)
    import ida_funcs
    func_name = ida_funcs.get_func_name(func_ea)

    def do_tag():
        node = _get_tag_node()
        existing = node.supstr(func_ea)
        tags = set(existing.split(",") if existing else [])
        tags.add(tag.strip())
        node.supset(func_ea, ",".join(sorted(tags)))
        return {
            "address": f"0x{func_ea:x}",
            "name": func_name,
            "tag": tag,
            "all_tags": sorted(tags),
        }

    result = ctx.run_on_main_thread(do_tag)
    ctx.save()
    return result


def _handle_untag_function(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    target = args.get("target", "")
    tag = args.get("tag", "")

    if not target:
        raise ValueError("Missing required argument: target")
    if not tag:
        raise ValueError("Missing required argument: tag")

    func_ea = ctx.find_function(target)
    import ida_funcs
    func_name = ida_funcs.get_func_name(func_ea)

    def do_untag():
        node = _get_tag_node()
        existing = node.supstr(func_ea)
        tags = set(existing.split(",") if existing else [])
        removed = tag in tags
        tags.discard(tag)
        if tags:
            node.supset(func_ea, ",".join(sorted(tags)))
        else:
            node.supdel(func_ea)
        return {
            "address": f"0x{func_ea:x}",
            "name": func_name,
            "tag": tag,
            "removed": removed,
            "all_tags": sorted(tags),
        }

    result = ctx.run_on_main_thread(do_untag)
    ctx.save()
    return result


def _handle_list_tags(ctx, args: dict) -> dict:
    _ = args.get("binary", "")

    def do_list():
        node = _get_tag_node()
        all_tags = {}
        import idautils
        import ida_funcs
        for fea in idautils.Functions():
            ts = node.supstr(fea)
            if ts:
                for t in ts.split(","):
                    all_tags[t] = all_tags.get(t, 0) + 1
        tags_out = [{"name": k, "count": v} for k, v in sorted(all_tags.items())]
        return {"tags": tags_out, "count": len(tags_out)}

    return ctx.run_on_main_thread(do_list)


def _handle_functions_by_tag(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    tag = args.get("tag", "")
    limit = int(args.get("limit", 200))

    if not tag:
        raise ValueError("Missing required argument: tag")

    def do_search():
        node = _get_tag_node()
        results = []
        import idautils
        import ida_funcs
        for fea in idautils.Functions():
            ts = node.supstr(fea)
            if ts and tag in ts.split(","):
                results.append({
                    "address": f"0x{fea:x}",
                    "name": ida_funcs.get_func_name(fea),
                })
            if len(results) >= limit:
                break
        return {"functions": results, "count": len(results)}

    return ctx.run_on_main_thread(do_search)


register_handler("tag_function", _handle_tag_function)
register_handler("untag_function", _handle_untag_function)
register_handler("list_tags", _handle_list_tags)
register_handler("functions_by_tag", _handle_functions_by_tag)
