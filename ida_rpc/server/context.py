# (c) B. Kerler 2026, MIT license
"""IDA context wrapper for ida-rpc.

Provides a unified interface for accessing the current IDA database,
resolving functions/addresses, and running operations safely.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ida_rpc.session import Session

try:
    import ida_kernwin
    import ida_loader
    import ida_funcs
    import ida_auto
    import idautils
    INSIDE_IDA = True
except ImportError:
    INSIDE_IDA = False

logger = None

def _get_logger():
    global logger
    if logger is None:
        import logging
        logger = logging.getLogger("ida-rpc.context")
    return logger


@dataclass
class ProgramInfo:
    """Metadata for a loaded IDA database."""

    name: str
    idb_path: Path | None
    analysis_complete: bool = False
    load_time: float | None = None


class IdaContext:
    """Context wrapper for IDA Pro operations."""

    def __init__(self, session: Session):
        self.session = session
        self._lock = threading.RLock()

    def _ensure_analysis(self) -> None:
        """Wait for auto-analysis to complete if running inside IDA.
        Must be called from the main thread."""
        if not INSIDE_IDA:
            return
        ida_auto.auto_wait()

    def get_program(self, binary: str = "") -> ProgramInfo:
        """Resolve the current program. In IDA there is only one open IDB at a time
        per process, so we return the current one.

        The 'binary' argument is accepted for protocol compatibility but is
        currently unused (IDA is single-IDB per process).
        """
        if not INSIDE_IDA:
            raise RuntimeError("Not running inside IDA Pro")

        idb = Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
        return ProgramInfo(
            name=idb.name,
            idb_path=idb,
            analysis_complete=True,
            load_time=time.time(),
        )

    def current_ea(self) -> int:
        if not INSIDE_IDA:
            raise RuntimeError("Not running inside IDA Pro")
        return ida_kernwin.get_screen_ea()

    def resolve_address(self, addr_str: str) -> int:
        """Parse a hex address string into an EA."""
        if not INSIDE_IDA:
            raise RuntimeError("Not running inside IDA Pro")
        s = addr_str.strip()
        if s.lower().startswith("0x"):
            s = s[2:]
        try:
            return int(s, 16)
        except ValueError:
            raise ValueError(f"Invalid address: {addr_str}")

    def find_function(self, name_or_address: str) -> int:
        """Resolve a function by name or hex address. Returns the entry EA."""
        if not INSIDE_IDA:
            raise RuntimeError("Not running inside IDA Pro")

        # Try as address first
        try:
            ea = self.resolve_address(name_or_address)
            func = ida_funcs.get_func(ea)
            if func:
                return func.start_ea
        except ValueError:
            pass

        # Try as exact name
        name_lower = name_or_address.lower()
        exact = []
        partial = []
        for func_ea in idautils.Functions():
            fname = ida_funcs.get_func_name(func_ea)
            if fname and fname.lower() == name_lower:
                exact.append(func_ea)
            elif fname and name_lower in fname.lower():
                partial.append(func_ea)

        if len(exact) == 1:
            return exact[0]
        elif len(exact) > 1:
            suggestions = [f"{ida_funcs.get_func_name(ea)} @ 0x{ea:x}" for ea in exact]
            raise ValueError(f"Ambiguous function name '{name_or_address}'. Matches: {suggestions}")

        if len(partial) == 1:
            return partial[0]
        elif len(partial) > 1:
            suggestions = [f"{ida_funcs.get_func_name(ea)} @ 0x{ea:x}" for ea in partial[:10]]
            raise ValueError(f"Ambiguous function name '{name_or_address}'. Partial matches: {suggestions}")

        raise ValueError(f"Function '{name_or_address}' not found.")

    def run_on_main_thread(self, fn: Callable, *args, **kwargs):
        """Execute fn on IDA's main thread.

        Uses execute_sync to dispatch to the main thread when called
        from a background thread.
        """
        if not INSIDE_IDA:
            return fn(*args, **kwargs)

        import ida_kernwin

        # In IDA, the main thread is the one where the plugin init runs.
        # We can detect if we're on it by checking if execute_sync works
        # synchronously or by thread name heuristics.
        # For safety, always use execute_sync when called from a thread
        # that is not the main thread.
        is_main = threading.current_thread() is threading.main_thread()
        if is_main:
            return fn(*args, **kwargs)

        result_box = [None]
        exc_box = [None]

        def wrapper():
            try:
                result_box[0] = fn(*args, **kwargs)
            except Exception as e:
                exc_box[0] = e

        ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_WRITE)
        if exc_box[0] is not None:
            raise exc_box[0]
        return result_box[0]

    def save(self) -> None:
        """Save the current database."""
        if not INSIDE_IDA:
            return
        import ida_loader
        ida_loader.save_database(None, 0)

    def close(self) -> None:
        """Cleanup (no-op for IDA context)."""
        pass
