# (c) B. Kerler 2026, MIT license
"""IDA Pro plugin entry point for ida-rpc.

Install this file into IDA's plugins directory for GUI mode auto-load.
Default locations:
    Windows: %APPDATA%\Hex-Rays\IDA Pro\plugins\ida_rpc_plugin.py
    macOS:   ~/Library/Application Support/IDA Pro/plugins/ida_rpc_plugin.py
    Linux:   ~/.idapro/plugins/ida_rpc_plugin.py

For headless daemon mode, run:
    ida -A -L/tmp/ida.log <binary> -S/path/to/ida-rpc/ida_rpc_plugin.py
"""

from __future__ import annotations

import os
import sys
import threading

# Ensure ida_rpc is importable
# Use realpath to resolve symlinks
_PLUGIN_FILE = os.path.realpath(__file__)
_IDA_RPC_DIR = os.path.dirname(_PLUGIN_FILE)
if _IDA_RPC_DIR not in sys.path:
    sys.path.insert(0, _IDA_RPC_DIR)

_PROJECT_ROOT = os.path.dirname(_IDA_RPC_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import ida_idaapi
import ida_loader
import ida_auto

# Lazy import GUI-only modules
_ida_kernwin = None

def _get_kernwin():
    global _ida_kernwin
    if _ida_kernwin is None:
        try:
            import ida_kernwin
            _ida_kernwin = ida_kernwin
        except ImportError:
            _ida_kernwin = False
    return _ida_kernwin


from ida_rpc.session import Session, socket_path_for_project, save, load as load_session
from ida_rpc.server.main import run_server
from ida_rpc.server.context import IdaContext

# Global to prevent double initialization
_plugin_instance = None


def _configure_segments_for_arch(arch: str) -> None:
    """Auto-configure segments for raw binaries based on the requested arch."""
    import ida_segment
    import idautils
    import idc

    arch_lower = arch.lower().strip()

    # Map architecture to (segment_class, bitness)
    # bitness: 0=16-bit, 1=32-bit, 2=64-bit addresses
    config = {
        "arm": ("CODE32", 1),
        "thumb": ("CODE16", 1),
        "aarch64": ("CODE64", 2),
        "arm64": ("CODE64", 2),
        "metapc": ("CODE", 1),   # x86 32-bit default
        "x86": ("CODE", 1),
        "x64": ("CODE64", 2),
        "mips": ("CODE", 1),
        "mipsb": ("CODE", 1),
        "mips64": ("CODE64", 2),
        "ppc": ("CODE", 1),
        "ppc64": ("CODE64", 2),
    }

    seg_class, bitness = config.get(arch_lower, ("CODE", 1))

    # Apply to all segments (raw binaries typically have one segment)
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue

        # Set segment class
        ida_segment.set_segm_class(seg, seg_class)

        # Set bitness (address size)
        ida_segment.set_segm_addressing(seg, bitness)

        # Set read + execute permissions for code segments
        perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC
        idc.set_segm_attr(seg_ea, idc.SEGATTR_PERM, perm)

    print(f"ida-rpc: configured segments for arch='{arch}' (class={seg_class}, bitness={bitness})")


def _is_headless():
    kernwin = _get_kernwin()
    return kernwin is False or (kernwin and kernwin.cvar.batch)


class IdaRpcPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "IDA RPC daemon plugin"
    help = "Expose IDA Pro capabilities via JSON-RPC over Unix socket"
    wanted_name = "ida-rpc"
    wanted_hotkey = ""

    def __init__(self):
        self.server_thread = None
        self.session = None

    def init(self):
        global _plugin_instance
        if _plugin_instance is not None:
            print("ida-rpc: already initialized, skipping.")
            return ida_idaapi.PLUGIN_SKIP

        # In headless mode, only start server when run via -S script
        # (auto-loaded plugins cannot keep IDA alive in headless mode)
        if _is_headless() and __name__ != "__main__":
            print("ida-rpc: headless mode detected. Use -Sida_rpc_plugin.py to start the daemon.")
            return ida_idaapi.PLUGIN_SKIP

        # Determine current IDB path
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not idb_path:
            idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_ID0)
        if not idb_path:
            idb_path = "/tmp/ida-rpc-default.i64"

        idb_path = os.path.abspath(idb_path)
        socket_path = socket_path_for_project(idb_path)

        mode = "headless" if _is_headless() else "gui"

        # Try to load saved session to get arch and other metadata
        saved = load_session(idb_path)
        arch = saved.arch if saved else None

        self.session = Session(
            mode=mode,
            project_idb=idb_path,
            socket_path=socket_path,
            arch=arch,
        )
        save(self.session)

        # Wait for auto-analysis (must be on main thread)
        ida_auto.auto_wait()

        # Auto-configure segments for raw binaries when arch was specified
        if arch:
            _configure_segments_for_arch(arch)

        ctx = IdaContext(self.session)

        if mode == "headless":
            # In headless mode, run server synchronously on the main thread
            # so all IDA API calls naturally run on the main thread.
            try:
                run_server(self.session, ctx, synchronous=True)
            except Exception as e:
                print(f"ida-rpc server error: {e}")
            finally:
                ctx.close()
        else:
            # In GUI mode, run server in a background thread
            def _start_server():
                try:
                    run_server(self.session, ctx)
                except Exception as e:
                    print(f"ida-rpc server error: {e}")
                finally:
                    ctx.close()

            self.server_thread = threading.Thread(target=_start_server, daemon=True)
            self.server_thread.start()
        _plugin_instance = self
        print(f"ida-rpc plugin loaded. Socket: {socket_path}")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        global _plugin_instance
        if self.session and self.session.socket_path.exists():
            try:
                self.session.socket_path.unlink()
            except Exception:
                pass
        if _plugin_instance is self:
            _plugin_instance = None
        print("ida-rpc plugin terminated.")


def PLUGIN_ENTRY():
    return IdaRpcPlugin()


# If run as a script (e.g., -Sida_rpc_plugin.py), auto-start
# In headless mode, init() blocks on run_server(synchronous=True).
if __name__ == "__main__":
    plugin = IdaRpcPlugin()
    plugin.init()
