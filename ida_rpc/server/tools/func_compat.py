# (c) B. Kerler 2026, MIT license
"""Compatibility helpers for IDA function APIs that changed across SDKs."""

from __future__ import annotations


def function_start(ida_funcs, ea: int, badaddr: int) -> int:
    """Get the containing function start on old and current IDA SDKs."""
    get_func_start = getattr(ida_funcs, "get_func_start", None)
    if get_func_start is not None:
        return get_func_start(ea)

    func = ida_funcs.get_func(ea)
    return func.start_ea if func is not None else badaddr


def function_size(ida_funcs, ea: int) -> int:
    """Get a function's byte size on old and current IDA SDKs."""
    calc_func_size_ea = getattr(ida_funcs, "calc_func_size_ea", None)
    if calc_func_size_ea is not None:
        return calc_func_size_ea(ea)

    func = ida_funcs.get_func(ea)
    return ida_funcs.calc_func_size(func) if func is not None else 0


def function_flags(ida_funcs, ea: int) -> int:
    """Read function flags across IDA SDKs."""
    get_func_flags = getattr(ida_funcs, "get_func_flags", None)
    if get_func_flags is not None:
        return int(get_func_flags(ea))

    func = ida_funcs.get_func(ea)
    return int(func.flags) if func is not None else 0


def get_function(ida_funcs, ea: int):
    """Return the func_t containing an EA on IDA SDKs that still expose it.

    IDA 9.4 removed the func_t getters; prefer the ea-based APIs there
    (get_func_start, get_func_entry_info, get_func_tails, ...). This helper
    only exists for the legacy fallback paths.
    """
    get_func = getattr(ida_funcs, "get_func", None)
    if get_func is not None:
        return get_func(ea)
    return None


def set_function_flags(ida_funcs, ea: int, flags: int) -> bool:
    """Write function flags across IDA SDKs."""
    set_func_flags = getattr(ida_funcs, "set_func_flags", None)
    if set_func_flags is not None:
        result = set_func_flags(ea, flags)
        return True if result is None else bool(result)

    func = ida_funcs.get_func(ea)
    if func is None:
        return False
    update_func = getattr(ida_funcs, "update_func", None)
    if update_func is None:
        raise AttributeError("IDA API provides no function-flag update method")
    func.flags = flags
    return bool(update_func(func))
