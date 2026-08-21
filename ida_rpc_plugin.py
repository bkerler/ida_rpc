# (c) B. Kerler 2026, MIT license
r"""IDA Pro plugin entry point for ida-rpc.

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
import tempfile
import sys
import threading
from pathlib import Path

# Ensure ida_rpc is importable
# Use realpath to resolve symlinks
_PLUGIN_FILE = os.path.realpath(__file__)
_IDA_RPC_DIR = os.path.dirname(_PLUGIN_FILE)
if _IDA_RPC_DIR not in sys.path:
    sys.path.insert(0, _IDA_RPC_DIR)

_PROJECT_ROOT = os.path.dirname(_IDA_RPC_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def _drop_stale_ida_rpc_modules() -> None:
    """Prefer this checkout when an auto-loaded plugin imported another copy."""
    expected = os.path.join(_IDA_RPC_DIR, "ida_rpc")
    loaded = sys.modules.get("ida_rpc")
    loaded_file = os.path.realpath(getattr(loaded, "__file__", "")) if loaded else ""
    if not loaded_file or loaded_file.startswith(expected):
        return
    for name in list(sys.modules):
        if name == "ida_rpc" or name.startswith("ida_rpc."):
            del sys.modules[name]


_drop_stale_ida_rpc_modules()

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


from ida_rpc.session import Session, socket_path_for_project, remove as remove_session, load as load_session
from ida_rpc.transport import remove_endpoint_marker
from ida_rpc.server.main import run_server
from ida_rpc.server.context import IdaContext

# Global to prevent double initialization
_plugin_instance = None


def _configure_segments_for_arch(arch: str) -> None:
    """Auto-configure segments for raw binaries based on the requested arch."""
    import ida_ida
    import ida_idp
    import idaapi
    import ida_segment
    import ida_segregs
    import ida_typeinf
    import ida_bytes
    import idautils

    arch_lower = arch.lower().strip()

    # Map architecture to (segment_class, bitness)
    # bitness: 0=16-bit, 1=32-bit, 2=64-bit addresses
    config = {
        "arm": ("CODE32", 1),
        "armv7": ("CODE32", 1),
        "armv7-a": ("CODE32", 1),
        "armv7-m": ("CODE32", 1),
        "armv7m": ("CODE32", 1),
        "thumb": ("CODE16", 1),
        "thumb2": ("CODE16", 1),
        "aarch64": ("CODE64", 2),
        "arm64": ("CODE64", 2),
        "armv8": ("CODE64", 2),
        "armv8-a": ("CODE64", 2),
        "metapc": ("CODE", 1),   # x86 32-bit default
        "x86": ("CODE", 1),
        "i386": ("CODE", 1),
        "i486": ("CODE", 1),
        "i586": ("CODE", 1),
        "i686": ("CODE", 1),
        "x64": ("CODE64", 2),
        "x86_64": ("CODE64", 2),
        "x86-64": ("CODE64", 2),
        "amd64": ("CODE64", 2),
        "mips": ("CODE", 1),
        "mipsel": ("CODE", 1),
        "mipsb": ("CODE", 1),
        "mips64": ("CODE64", 2),
        "mips64el": ("CODE64", 2),
        "mips64eb": ("CODE64", 2),
        "ppc": ("CODE", 1),
        "powerpc": ("CODE", 1),
        "ppc64": ("CODE64", 2),
        "powerpc64": ("CODE64", 2),
        "riscv": ("CODE", 1),
        "risc-v": ("CODE", 1),
        "riscv32": ("CODE", 1),
        "riscv64": ("CODE64", 2),
    }

    seg_class, bitness = config.get(arch_lower, ("CODE", 1))
    app_bitness = 64 if bitness == 2 else 32

    if arch_lower in {
        "arm", "armv7", "armv7-a", "armv7-m", "armv7m",
        "thumb", "thumb2", "aarch64", "arm64", "armv8", "armv8-a",
    }:
        ida_idp.set_processor_type("arm", ida_idp.SETPROC_LOADER_NON_FATAL)

    if idaapi.IDA_SDK_VERSION >= 900:
        if bitness == 2:
            ida_ida.inf_set_64bit(True)
        elif bitness == 1:
            ida_ida.inf_set_32bit(True)
        ida_ida.inf_set_app_bitness(app_bitness)
    else:
        inf = idaapi.get_inf_structure()
        if bitness == 2:
            inf.lflags |= idaapi.LFLG_64BIT
        else:
            inf.lflags &= ~idaapi.LFLG_64BIT

    # Apply to all segments (raw binaries typically have one segment)
    for seg_ea in idautils.Segments():
        seg = ida_segment.segment_info_t()
        if not ida_segment.get_segment_info(seg, seg_ea, ida_segment.GSI_ALL):
            continue

        # Set segment class
        ida_segment.set_segment_class(seg_ea, seg_class)

        # Set bitness (address size)
        ida_segment.set_segment_addressing(seg_ea, bitness)

        if arch_lower in {"aarch64", "arm64", "thumb", "thumb2"}:
            try:
                # IDA 9.4 exposes this through ida_segregs and expects the
                # numeric segment-register index, not the register name.
                regnum = ida_idp.ph.regnames.index("T")
                ida_segregs.set_default_sreg_value_ea(
                    seg.start_ea, regnum,
                    1 if arch_lower in {"thumb", "thumb2"} else 0,
                )
            except Exception:
                pass
        elif arch_lower in {"mips", "mipsel", "mipsl", "mipsb"}:
            try:
                if ida_bytes.get_bytes(seg.start_ea, 2) == b"\xc0\x60":
                    ida_typeinf.set_abi_name("n32")
                    try:
                        ida_idp.process_config_directive("MIPS_ENCODING=nanoMIPS", 3)
                    except Exception:
                        pass
                    try:
                        ida_idp.processor_t.set_proc_options("encoding=nanomips", ida_idp.SETPROC_LOADER_NON_FATAL)
                    except AttributeError:
                        ida_idp.set_processor_type("mipsl:encoding=nanomips", ida_idp.SETPROC_LOADER_NON_FATAL)
                    mips16 = ida_idp.str2sreg("mips16")
                    if mips16 >= 0:
                        ida_segregs.split_sreg_range(seg.start_ea, mips16, 1, ida_segregs.SR_user)
            except Exception:
                pass

        # Set read + execute permissions for code segments
        perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC
        seg.set_perm(perm)
        ida_segment.set_segment_info(seg)

    print(f"ida-rpc: configured segments for arch='{arch}' (class={seg_class}, bitness={bitness})")


def _is_headless():
    kernwin = _get_kernwin()
    return kernwin is False or (kernwin and kernwin.cvar.batch)


class IdaRpcPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "IDA RPC daemon plugin"
    help = "Expose IDA Pro capabilities via JSON-RPC over a local socket"
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
            idb_path = str(Path(tempfile.gettempdir()) / "ida-rpc-default.i64")

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
        # Auto-configure segments for raw binaries when arch was specified
        if arch:
            _configure_segments_for_arch(arch)

        # Wait for auto-analysis after raw import mode/bitness is corrected.
        ida_auto.auto_wait()

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
        if self.session:
            try:
                remove_endpoint_marker(self.session.socket_path)
            except Exception:
                pass
            try:
                remove_session(self.session.project_idb)
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
