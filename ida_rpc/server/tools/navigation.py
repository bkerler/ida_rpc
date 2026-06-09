# (c) B. Kerler 2026, MIT license
"""Navigation tools (GUI-only): goto function/address in IDA UI."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _handle_goto(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    target = args.get("target", "")
    target_type = args.get("target_type", "function")

    if not target:
        raise ValueError("Missing required argument: target")

    try:
        import ida_kernwin
    except ImportError:
        raise RuntimeError(
            "The 'goto' command is only available in GUI mode. "
            "Start IDA without -A to use it."
        )

    if target_type == "function":
        addr = ctx.find_function(target)
    elif target_type == "address":
        addr = ctx.resolve_address(target)
    else:
        raise ValueError(f"Invalid target_type '{target_type}'. Use 'function' or 'address'.")

    success = bool(ida_kernwin.jumpto(addr))
    return {"address": f"0x{addr:x}", "success": success}


register_handler("goto", _handle_goto)
