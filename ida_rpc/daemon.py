# (c) B. Kerler 2026, MIT license
"""Daemon lifecycle management for ida-rpc."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from ida_rpc.session import Session
from ida_rpc.transport import endpoint_address


# IDA database companion file extensions that can become stale after a crash
_IDA_COMPANION_EXTS = (".id0", ".id1", ".id2", ".nam", ".til")


def _companion_files(idb_path: Path) -> list[Path]:
    """Return list of companion files for a given IDB path."""
    stem = idb_path.with_suffix("")
    return [Path(f"{stem}{ext}") for ext in _IDA_COMPANION_EXTS]


def has_stale_companions(idb_path: Path) -> bool:
    """Check if stale companion files exist (older than the .i64 itself)."""
    if not idb_path.exists():
        return False
    idb_mtime = idb_path.stat().st_mtime
    for companion in _companion_files(idb_path):
        if companion.exists() and companion.stat().st_mtime < idb_mtime:
            return True
    return False


def clean_companion_files(idb_path: Path) -> list[str]:
    """Remove companion files for the given IDB. Returns list of removed files."""
    removed = []
    for companion in _companion_files(idb_path):
        if companion.exists():
            companion.unlink()
            removed.append(str(companion))
    return removed


def is_running(socket_path: Path) -> bool:
    """Check if a daemon is responsive at the given socket path."""
    import socket as sock_mod
    import json
    import uuid

    if not socket_path.exists():
        return False

    try:
        address = endpoint_address(socket_path)
        family = sock_mod.AF_UNIX if isinstance(address, str) else sock_mod.AF_INET
        s = sock_mod.socket(family, sock_mod.SOCK_STREAM)
        try:
            s.settimeout(5)
            s.connect(address)
            request = {"id": str(uuid.uuid4()), "cmd": "ping", "args": {}}
            s.sendall((json.dumps(request) + "\n").encode())
            data = b""
            while b"\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            if data.strip():
                resp = json.loads(data.decode().strip())
                return resp.get("ok", False)
            return False
        finally:
            s.close()
    except Exception:
        return False


def start_blocking(session: Session) -> None:
    """Start the daemon in the foreground (blocking).

    This is used when the plugin is already running inside IDA and
    we just need to start the server component.
    """
    from ida_rpc import session as session_mod
    from ida_rpc.server.main import run_server

    session_mod.save(session)

    # When running inside IDA, the context is the current IDA instance
    from ida_rpc.server.context import IdaContext

    ctx = IdaContext(session)
    try:
        run_server(session, ctx)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        if hasattr(ctx, "close"):
            ctx.close()
        session_mod.remove(session.project_idb)


def start_background(
    session: Session,
    timeout: float = 60.0,
    *,
    binary_path: Path | None = None,
    extra_ida_args: list[str] | None = None,
) -> None:
    """Start the daemon in the background and wait for the socket to appear.

    Launches IDA (gui or idat headless) with the plugin auto-loaded.
    """
    from ida_rpc import session as session_mod

    session_mod.save(session)

    socket_stem = session.socket_path.stem
    log_path = session.socket_path.parent / f"{socket_stem}.log"

    env = dict(os.environ)
    ida_dir = (
        str(session.ida_install_dir)
        if session.ida_install_dir
        else env.get("IDA_INSTALL_DIR")
    )
    if ida_dir:
        env["IDA_INSTALL_DIR"] = ida_dir
    env.setdefault("LC_ALL", "C.UTF-8")
    env.setdefault("LANG", "C.UTF-8")

    # Determine IDA executable.  Windows IDA installations normally expose
    # ida64.exe/idat64.exe, while POSIX installations use ida/idat.
    ida_root = Path(ida_dir) if ida_dir else None
    if os.name == "nt":
        names = (
            ("idat64.exe", "idat.exe", "ida64.exe", "ida.exe")
            if session.mode == "headless"
            else ("ida64.exe", "ida.exe")
        )
    else:
        names = (
            ("idat", "idat64", "ida", "ida64")
            if session.mode == "headless"
            else ("ida", "ida64")
        )

    ida_exe = None
    if ida_root is not None:
        for name in names:
            candidate = ida_root / name
            if candidate.exists():
                ida_exe = candidate
                break
    else:
        for name in names:
            found = shutil.which(name)
            if found:
                ida_exe = Path(found)
                break

    if ida_exe is None:
        ida_exe = (ida_root / names[0]) if ida_root is not None else Path(names[0])
        if session.mode == "headless":
            env.setdefault("QT_QPA_PLATFORM", "offscreen")

    if not ida_exe.exists():
        raise FileNotFoundError(
            f"IDA executable not found: {ida_exe}\n"
            f"Set IDA_INSTALL_DIR to your IDA Pro installation directory, e.g.:\n"
            f"  export IDA_INSTALL_DIR=/opt/ida-pro-9.4\n"
            f"Or pass --ida-install-dir to the command."
        )
    if ida_exe.stem.lower() not in {"ida", "idat", "ida64", "idat64"}:
        raise RuntimeError(f"Refusing to launch non-IDA executable: {ida_exe}")

    # Build command to launch IDA with the plugin
    cmd = [str(ida_exe)]
    if session.mode == "headless":
        cmd.append("-A")
        # In headless mode the auto-loaded plugin returns PLUGIN_SKIP,
        # so we must also run it as a script via -S so __name__ == "__main__"
        # and the server actually starts.
        import ida_rpc
        _pkg = Path(ida_rpc.__file__).parent.parent
        plugin_candidates = [
            _pkg / "ida_rpc_plugin.py",
            Path(__file__).parent.parent / "ida_rpc_plugin.py",
            Path.cwd() / "ida_rpc_plugin.py",
        ]
        plugin_path = None
        for cand in plugin_candidates:
            if cand.exists():
                plugin_path = cand
                break
        if plugin_path is None:
            raise FileNotFoundError(
                f"ida_rpc_plugin.py not found. Searched: {plugin_candidates}\n"
                f"Reinstall with: pip install -e /path/to/ida_rpc"
            )
        cmd.append(f"-S{plugin_path}")

    if extra_ida_args:
        cmd.extend(extra_ida_args)

    # If the IDB exists, open it; otherwise open the binary (IDA creates the IDB)
    if session.project_idb.exists():
        cmd.append(str(session.project_idb))
    elif binary_path and binary_path.exists():
        # IDA creates the IDB next to the source binary by default.
        # If the binary is in a read-only directory (e.g. /usr/bin),
        # this fails silently. Force output path with -o.
        cmd.append(f"-o{session.project_idb}")
        cmd.append(str(binary_path))

    # IDA 9.4 refuses autonomous/batch startup until its EULA has been
    # acknowledged. Keep this after the input path, matching IDA's documented
    # command-line form and the working Windows invocation.
    if session.mode == "headless" and os.name == "nt":
        cmd.append("--accept-eula")

    # The plugin auto-starts the server when loaded
    try:
        with open(log_path, "a") as log_fh:
            log_fh.write("ida-rpc launch command: " + " ".join(cmd) + "\n")
            log_fh.flush()
            subprocess.Popen(
                cmd,
                stdout=log_fh,
                stderr=log_fh,
                start_new_session=True,
                env=env,
            )
    except Exception:
        session_mod.remove(session.project_idb)
        raise

    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_running(session.socket_path):
            return
        time.sleep(0.5)

    session_mod.remove(session.project_idb)

    raise TimeoutError(
        f"Daemon did not start within {timeout}s. "
        f"Check logs at {log_path}"
    )


def stop_daemon(socket_path: Path) -> bool:
    """Send a stop command to a running daemon. Returns True if stopped."""
    from ida_rpc.client import send_request, DaemonNotRunning

    try:
        send_request(socket_path, "stop")
        return True
    except DaemonNotRunning:
        return False
    except Exception as e:
        # The client intentionally has no logging helper.  Keep stop() a
        # best-effort lifecycle operation and report through the standard
        # library logger instead of raising a secondary ImportError while
        # handling a stale/unresponsive socket.
        import logging
        logging.getLogger("ida-rpc").warning(
            "Unexpected error stopping daemon: %s", e
        )
        return True


def main():
    """Entry point for ida-rpcd (background daemon)."""
    import argparse

    parser = argparse.ArgumentParser(description="ida-rpc daemon")
    parser.add_argument("--mode", choices=["gui", "headless"], required=True)
    parser.add_argument("--project", type=Path, required=True)
    args = parser.parse_args()

    from ida_rpc.session import Session, socket_path_for_project

    session = Session(
        mode=args.mode,
        project_idb=args.project,
        socket_path=socket_path_for_project(args.project),
    )

    start_blocking(session)


if __name__ == "__main__":
    main()
