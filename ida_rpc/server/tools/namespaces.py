# (c) B. Kerler 2026, MIT license
"""Namespace tools.

IDA does not have a direct namespace API like Ghidra. In IDA, namespaces
are encoded into symbol names (e.g., 'ClassName::methodName'). We emulate
namespace management by parsing name prefixes.
"""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_name
    import idautils
    return ida_name, idautils


def _handle_create_namespace(ctx, args: dict) -> dict:
    _, idautils = _ida()

    _ = args.get("binary", "")
    namespace = args.get("namespace", "")
    parent = args.get("parent", "")

    if not namespace:
        raise ValueError("Missing required argument: namespace")

    # In IDA, namespaces are just name prefixes. We validate by
    # checking if any symbol already uses this prefix.
    full_ns = f"{parent}::{namespace}" if parent else namespace

    def do_create():
        # Check if namespace is already in use
        count = 0
        for ea, name in idautils.Names():
            if name.startswith(full_ns + "::"):
                count += 1

        return {
            "namespace": namespace,
            "parent": parent or None,
            "full_path": full_ns,
            "existing_symbols": count,
            "note": "IDA namespaces are implicit (encoded in symbol names). No explicit creation needed.",
        }

    return ctx.run_on_main_thread(do_create)


def _handle_list_namespaces(ctx, args: dict) -> dict:
    _, idautils = _ida()

    _ = args.get("binary", "")
    limit = int(args.get("limit", 200))

    def do_list():
        namespaces: dict[str, int] = {}
        for ea, name in idautils.Names():
            if "::" in name:
                # Collect all namespace prefixes
                parts = name.split("::")
                for i in range(len(parts) - 1):
                    ns = "::".join(parts[:i + 1])
                    namespaces[ns] = namespaces.get(ns, 0) + 1

        results = [
            {"name": ns, "symbol_count": count}
            for ns, count in sorted(namespaces.items(), key=lambda x: x[0])
        ]
        if limit:
            results = results[:limit]

        return {
            "namespaces": results,
            "count": len(results),
        }

    return ctx.run_on_main_thread(do_list)


register_handler("create_namespace", _handle_create_namespace)
register_handler("list_namespaces", _handle_list_namespaces)
