# (c) B. Kerler 2026, MIT license
"""CLI entry point for ida-rpc."""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any

import click

from ida_rpc import __version__


class HexInt(click.ParamType):
    name = "integer"

    def convert(self, value, param, ctx):
        if isinstance(value, int):
            return value
        try:
            return int(value, 0)
        except (ValueError, TypeError):
            self.fail(
                f"{value!r} is not a valid integer (use decimal like 184 or hex like 0xb8)",
                param,
                ctx,
            )


HEX_INT = HexInt()
from ida_rpc import session as session_mod
from ida_rpc.client import DaemonError, DaemonNotRunning


CORE_CAPABILITIES = {
    "purpose": "IDA Pro reverse-engineering RPC over a local Unix socket",
    "output": "Automation commands print human-readable text to stdout by default. Use --json for JSON output or set IDA_RPC_JSON=1.",
    "project_option": "--project <idb>; falls back to IDA_RPC_PROJECT",
    "start_requires": "--arch <arch> is mandatory for start/open so IDA never guesses the processor",
    "agent_workflow": [
        "capabilities",
        "find-project <binary-or-idb>",
        "open <binary-or-idb> --arch <arch> --headless --detach",
        "status --project <idb>",
        "functions --project <idb> --limit 50",
        "decompile <function-or-address> --project <idb>",
        "rename-function <target> <new_name> --project <idb>",
        "set-comment <address> <comment> --project <idb>",
        "save --project <idb>",
    ],
    "commands": {
        "discovery": [
            "capabilities",
            "find-project",
            "status",
            "list",
            "list-binaries",
            "metadata",
        ],
        "open_and_lifecycle": [
            "open",
            "start",
            "restart",
            "stop",
            "save",
            "list-loaders",
        ],
        "analysis": [
            "functions",
            "function",
            "function-info",
            "function-items",
            "imports",
            "exports",
            "strings",
            "symbols",
            "find-bytes",
            "memory-map",
            "segments",
            "relocations",
            "list-problems",
            "basefind",
        ],
        "decompile_disassemble": [
            "decompile",
            "decompile-all",
            "decompile-lvars",
            "basic-blocks",
            "function-graph",
            "call-graph",
            "disassemble",
            "read-bytes",
            "read-string",
        ],
        "xrefs": [
            "xrefs-to",
            "xrefs-from",
            "decompiler-xrefs",
            "stack-var-xrefs",
        ],
        "modify": [
            "rename-function",
            "rename-symbol",
            "rename-stack-var",
            "set-lvar-name",
            "set-lvar-type",
            "set-stack-var-type",
            "create-label",
            "set-comment",
            "set-signature",
            "set-data-type",
            "create-function",
            "create-instruction",
            "undefine",
            "batch-rename",
            "batch-set-comment",
        ],
        "types": [
            "create-struct",
            "create-union",
            "create-enum",
            "modify-struct",
            "modify-enum",
            "list-data-types",
            "list-labels",
            "set-equate",
            "list-equates",
        ],
    },
}


LOADER_ALIASES = {
    "raw": "Binary file",
    "binary": "Binary file",
    "bin": "Binary file",
    "dump": "Binary file",
    "miniloader": "Rockchip MiniLoaderAll / LDR",
    "rk-miniloader": "Rockchip MiniLoaderAll / LDR",
    "rockchip-miniloader": "Rockchip MiniLoaderAll / LDR",
    "uboot-fit": "Rockchip U-Boot FIT image",
    "rk-uboot": "Rockchip U-Boot FIT image",
    "rkns": "Rockchip RKNS IDB/SPL image",
}

IDA_PROCESSOR_ALIASES = {
    "aarch64": "arm",
    "arm64": "arm",
    "armv8": "arm",
    "armv8-a": "arm",
    "armv7": "arm",
    "armv7-a": "arm",
    "armv7-m": "arm",
    "armv7m": "arm",
    "x86": "metapc",
    "i386": "metapc",
    "i486": "metapc",
    "i586": "metapc",
    "i686": "metapc",
    "x64": "metapc",
    "x86_64": "metapc",
    "x86-64": "metapc",
    "amd64": "metapc",
    "mipsel": "mips",
    "mipseb": "mips",
    "mips64": "mips",
    "mips64el": "mips",
    "mips64eb": "mips",
    "powerpc": "ppc",
    "powerpc64": "ppc",
    "ppc64": "ppc",
    "risc-v": "riscv",
    "riscv32": "riscv",
    "riscv64": "riscv",
    "8051": "i51",
    "mcs51": "i51",
    "m68k": "mc68k",
    "68k": "mc68k",
    "68000": "mc68k",
}


def _resolve_project(project: str | None) -> Path:
    if project:
        return Path(project).resolve()
    env = os.environ.get("IDA_RPC_PROJECT")
    if env:
        return Path(env).resolve()
    _error("MissingProject", "No project specified. Use --project or set IDA_RPC_PROJECT.")


def _emit_output(data: dict) -> None:
    click.echo(json.dumps(data, indent=2))


def _human_output(data: dict) -> None:
    if not data.get("ok", True):
        click.echo(f"Error: {data.get('error', 'Unknown')}: {data.get('message', '')}", err=True)
        return
    result = data.get("result", data)
    _format_object(result)


def _format_object(obj: Any, indent: int = 0) -> None:
    prefix = "  " * indent

    if isinstance(obj, str):
        click.echo(obj)
    elif isinstance(obj, list):
        if not obj:
            click.echo(f"{prefix}(empty)")
            return
        if all(isinstance(x, dict) for x in obj):
            text_keys = ("c_code", "listing", "hexdump", "content", "code")
            if any(any(k in x for k in text_keys) for x in obj):
                for i, item in enumerate(obj):
                    if i > 0:
                        click.echo()
                    header = item.get("name") or item.get("address") or f"item {i}"
                    click.echo(f"{prefix}[{header}]")
                    _format_object(item, indent + 1)
            else:
                _format_table(obj, indent)
        else:
            for item in obj:
                click.echo(f"{prefix}- {item}")
    elif isinstance(obj, dict):
        for key in ("listing", "hexdump", "c_code", "content", "code"):
            if key in obj and isinstance(obj[key], str):
                click.echo(obj[key])
                return

        _META_KEYS = {"count", "total", "offset", "limit", "truncated", "error_count"}
        list_keys = [k for k, v in obj.items() if isinstance(v, list)]
        if len(list_keys) == 1:
            key = list_keys[0]
            items = obj[key]
            meta = {k: v for k, v in obj.items() if k != key and k not in ("ok",)}
            if all(not isinstance(v, (dict, list)) for v in meta.values()) and set(meta.keys()).issubset(_META_KEYS):
                if meta:
                    meta_str = ", ".join(f"{k}={v}" for k, v in meta.items())
                    click.echo(f"{prefix}{key} ({len(items)} items, {meta_str}):")
                else:
                    click.echo(f"{prefix}{key} ({len(items)} items):")
                _format_object(items, indent + 1)
                return

        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                click.echo(f"{prefix}{k}:")
                _format_object(v, indent + 1)
            else:
                click.echo(f"{prefix}{k}: {v}")
    else:
        click.echo(f"{prefix}{obj}")


def _cell_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(x) for x in value)
    if isinstance(value, dict):
        return str(value)
    return str(value)


def _format_table(rows: list[dict], indent: int = 0) -> None:
    if not rows:
        return
    prefix = "  " * indent
    keys = list(dict.fromkeys(k for row in rows for k in row.keys()))
    widths: dict[str, int] = {k: len(k) for k in keys}
    for row in rows:
        for k in keys:
            widths[k] = max(widths[k], len(_cell_str(row.get(k))))

    header = "  ".join(k.ljust(widths[k]) for k in keys)
    click.echo(f"{prefix}{header}")
    click.echo(f"{prefix}{'-' * len(header)}")
    for row in rows:
        line = "  ".join(_cell_str(row.get(k)).ljust(widths[k]) for k in keys)
        click.echo(f"{prefix}{line}")


def _output(data: dict) -> None:
    ctx = click.get_current_context(silent=True)
    if ctx is not None and isinstance(ctx.obj, dict) and ctx.obj.get("json_output"):
        _emit_output(data)
    else:
        _human_output(data)


def _emit_error(error: str, message: str) -> None:
    click.echo(json.dumps({"ok": False, "error": error, "message": message}))
    sys.exit(1)


def _human_error(error: str, message: str) -> None:
    click.echo(f"Error: {error}: {message}", err=True)
    sys.exit(1)


def _error(error: str, message: str) -> None:
    ctx = click.get_current_context(silent=True)
    if ctx is not None and isinstance(ctx.obj, dict) and ctx.obj.get("json_output"):
        _emit_error(error, message)
    else:
        _human_error(error, message)


def _resolve_loader_name(loader: str | None) -> str | None:
    if not loader:
        return None
    return LOADER_ALIASES.get(loader.strip().lower(), loader)


def _resolve_processor_name(arch: str) -> str:
    normalized = arch.strip().lower()
    return IDA_PROCESSOR_ALIASES.get(normalized, arch)


def _recommended_start(target: Path, project: Path, exists: bool) -> str:
    arch_arg = "--arch <arch>"
    if exists:
        return f"ida-rpc open --project {project} {arch_arg} --headless --detach"
    return f"ida-rpc open {target} --project {project} {arch_arg} --headless --detach"


def _live_status(sock: Path) -> dict[str, Any]:
    from ida_rpc.client import send_request

    info: dict[str, Any] = {"binaries": None, "loaded": None}

    resp = send_request(sock, "list_binaries", {})
    if resp.get("ok"):
        binaries = resp["result"].get("binaries", [])
        info["binaries"] = binaries
        if binaries:
            first = binaries[0]
            info["loaded"] = {
                key: first.get(key)
                for key in (
                    "name", "path", "arch", "bits", "endian", "format",
                    "base_address", "analysis_complete",
                )
                if key in first
            }
            info.update({
                "processor": first.get("arch"),
                "bits": first.get("bits"),
                "endian": first.get("endian"),
                "format": first.get("format"),
                "base_address": first.get("base_address"),
            })

    return info


def _ida_install_dir(explicit: str | None = None) -> Path | None:
    if explicit:
        return Path(explicit)
    if os.environ.get("IDA_INSTALL_DIR"):
        return Path(os.environ["IDA_INSTALL_DIR"])
    return None


def _loader_dirs(ida_install_dir: str | None = None) -> list[Path]:
    dirs: list[Path] = []
    ida_dir = _ida_install_dir(ida_install_dir)
    if ida_dir:
        dirs.append(ida_dir / "loaders")
    for path in (
        Path.home() / ".idapro" / "loaders",
        Path.home() / ".idapro" / "Loaders",
    ):
        dirs.append(path)
    out: list[Path] = []
    seen: set[Path] = set()
    for path in dirs:
        resolved = path.expanduser()
        if resolved not in seen and resolved.exists():
            seen.add(resolved)
            out.append(resolved)
    return out


def _installed_loaders(ida_install_dir: str | None = None) -> list[dict]:
    loaders: list[dict] = []
    for directory in _loader_dirs(ida_install_dir):
        for path in sorted(directory.iterdir()):
            if path.suffix.lower() not in {".so", ".dll", ".dylib", ".py"}:
                continue
            loaders.append({
                "module": path.name,
                "stem": path.stem,
                "path": str(path),
                "source": "user" if ".idapro" in path.parts else "ida",
                "python": path.suffix.lower() == ".py",
            })
    return loaders


def _u32le(data: bytes, offset: int) -> int:
    import struct
    return struct.unpack_from("<I", data, offset)[0]


def _detect_loader_candidates(binary: Path | None) -> list[dict]:
    if binary is None or not binary.exists():
        return []
    candidates = [{"loader": "Binary file", "alias": "raw", "reason": "raw fallback"}]
    data = binary.read_bytes()[:0x20000]
    if data.startswith(b"\x7fELF"):
        candidates.append({"loader": "ELF", "module": "elf", "reason": "ELF magic"})
    if data.startswith(b"MZ"):
        candidates.append({"loader": "Portable executable", "module": "pe", "reason": "MZ header"})
    if len(data) >= 4 and _u32le(data, 0) in {0x544F4F42, 0x2052444C}:
        candidates.append({
            "loader": "Rockchip MiniLoaderAll / LDR",
            "alias": "miniloader",
            "module": "rk_miniloader",
            "reason": "Rockchip BOOT/LDR tag",
        })
    if b"\xd0\r\xfe\xed" in data[:0x2000]:
        candidates.append({
            "loader": "Rockchip U-Boot FIT image",
            "alias": "uboot-fit",
            "module": "rk_uboot_loader",
            "reason": "FIT/FDT magic",
        })
    return candidates


def _rpc_command(project: Path, cmd: str, args: dict) -> None:
    from ida_rpc.client import send_request_with_auto_restart
    try:
        resp = send_request_with_auto_restart(project, cmd, args)
        _output(resp)
    except DaemonNotRunning as e:
        _error("DaemonNotRunning", str(e))
    except DaemonError as e:
        _output(e.full_response)
        sys.exit(1)
    except Exception as e:
        if os.environ.get("IDA_RPC_DEBUG"):
            traceback.print_exc(file=sys.stderr)
        _error(type(e).__name__, str(e))


def _default_project_for_binary(binary: Path) -> Path:
    if binary.suffix.lower() in {".i64", ".idb"}:
        return binary
    return binary.with_suffix(".i64")


def _project_candidates(path: Path) -> list[Path]:
    candidates: list[Path] = []
    for candidate in (
        path,
        path.with_suffix(".i64"),
        path.with_suffix(".idb"),
        path.parent / "RE" / path.name / f"{path.name}.i64",
        path.parent / path.name / f"{path.name}.i64",
    ):
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _resolve_existing_or_default_project(path: Path) -> tuple[Path, bool]:
    for candidate in _project_candidates(path):
        if candidate.exists() and candidate.suffix.lower() in {".i64", ".idb"}:
            return candidate.resolve(), True
    return _default_project_for_binary(path).resolve(), False


@click.group()
@click.version_option(__version__, prog_name="ida-rpc")
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Output JSON instead of human-readable text (also set via IDA_RPC_JSON=1).",
)
@click.pass_context
def cli(ctx, json_output):
    """ida-rpc: CLI for the IDA Pro RPC daemon."""
    ctx.ensure_object(dict)
    ctx.obj["json_output"] = json_output or os.environ.get("IDA_RPC_JSON") in ("1", "true", "yes")


@cli.command(name="capabilities")
def capabilities():
    """Print agent-discoverable command capabilities."""
    _output({
        "ok": True,
        "result": {
            "version": __version__,
            **CORE_CAPABILITIES,
        },
    })


@cli.command(name="find-project")
@click.argument("path", required=False, default="")
def find_project(path: str):
    """Resolve the IDB path an agent should use for a binary or project."""
    target = Path(path).resolve() if path else _resolve_project(None)
    project, exists = _resolve_existing_or_default_project(target)
    session = session_mod.load(project) if exists else None
    _output({
        "ok": True,
        "result": {
            "input": str(target),
            "project": str(project),
            "exists": exists,
            "socket": str(session_mod.socket_path_for_project(project)),
            "session": {
                "exists": session is not None,
                "mode": session.mode if session else None,
            },
            "recommended_start": _recommended_start(target, project, exists),
        },
    })


@cli.command(name="list-loaders")
@click.argument("binary", required=False, default="")
@click.option("--ida-install-dir", "ida_install_dir", type=str, default=None)
def list_loaders(binary: str, ida_install_dir: str | None):
    """List available IDA loaders and aliases, optionally with candidates for a binary."""
    binary_path = Path(binary).resolve() if binary else None
    if binary_path is not None and not binary_path.exists():
        _error("FileNotFound", f"Binary not found: {binary}")
    aliases = [
        {"alias": alias, "loader": loader}
        for alias, loader in sorted(LOADER_ALIASES.items())
    ]
    _output({
        "ok": True,
        "result": {
            "binary": str(binary_path) if binary_path else None,
            "ida_install_dir": str(_ida_install_dir(ida_install_dir)) if _ida_install_dir(ida_install_dir) else None,
            "loader_dirs": [str(path) for path in _loader_dirs(ida_install_dir)],
            "aliases": aliases,
            "candidates": _detect_loader_candidates(binary_path),
            "installed": _installed_loaders(ida_install_dir),
        },
    })


@cli.command()
@click.argument("binary", required=False, default="")
@click.option("--project", "-p", type=str, help="IDB path to create/use (default: <binary>.i64)")
@click.option("--arch", "-a", type=str, required=True, help="Processor type (e.g., arm, aarch64, x86, mips, ppc)")
@click.option("--base", "-b", type=HEX_INT, help="Image base address for raw binaries")
@click.option("--loader", "-T", type=str, help="IDA loader/file type to force (for example: raw, 'Binary file', miniloader)")
@click.option("--headless", is_flag=True, help="Start in headless mode (no GUI)")
@click.option("--detach", is_flag=True, help="Start in background")
@click.option("--timeout", "-t", type=float, default=None)
@click.option("--ida-install-dir", "ida_install_dir", type=str, default=None)
@click.option("--clean", is_flag=True, help="Remove stale IDA companion files before starting")
def start(
    binary: str,
    project: str | None,
    arch: str | None,
    base: int | None,
    loader: str | None,
    headless: bool,
    detach: bool,
    timeout: float | None,
    ida_install_dir: str | None,
    clean: bool,
):
    """Open a binary in IDA and start the RPC daemon."""
    from ida_rpc.daemon import is_running, start_background, start_blocking

    # Binary is optional when opening an existing IDB
    if not binary and not project:
        _error("MissingArgument", "Provide either BINARY or --project")

    binary_path = None
    if binary:
        binary_path = Path(binary).resolve()
        if not binary_path.exists():
            _error("FileNotFound", f"Binary not found: {binary}")

    if project:
        idb_path = Path(project).resolve()
    elif binary_path:
        idb_path = binary_path.with_suffix(".i64")
    else:
        _error("MissingArgument", "Provide either BINARY or --project")

    # If no binary provided, the IDB must already exist
    if not binary_path and not idb_path.exists():
        _error("FileNotFound", f"IDB not found and no binary provided: {idb_path}")

    mode = "headless" if headless else "gui"
    sock = session_mod.socket_path_for_project(idb_path)
    if is_running(sock):
        _error(
            "AlreadyRunning",
            f"ida-rpc daemon already running for {idb_path} at {sock}. "
            "Use 'ida-rpc status' or stop it first.",
        )

    ida_dir_path = None
    if ida_install_dir:
        ida_dir_path = Path(ida_install_dir)
    elif os.environ.get("IDA_INSTALL_DIR"):
        ida_dir_path = Path(os.environ["IDA_INSTALL_DIR"])

    session = session_mod.Session(
        mode=mode,
        project_idb=idb_path,
        socket_path=sock,
        ida_install_dir=ida_dir_path,
        arch=arch,
    )

    imports_binary = bool(binary_path and not idb_path.exists())

    # Pass arch/base through to the background launcher
    extra_ida_args = []
    processor_name = _resolve_processor_name(arch)
    extra_ida_args.append(f"-p{processor_name}")
    if base is not None and imports_binary:
        extra_ida_args.append(f"-b{base:x}")
    loader_name = _resolve_loader_name(loader)
    if loader_name and imports_binary:
        extra_ida_args.append(f"-T{loader_name}")

    from ida_rpc.daemon import has_stale_companions, clean_companion_files

    if clean:
        removed = clean_companion_files(idb_path)
        if removed:
            click.echo(f"Cleaned stale companion files: {', '.join(removed)}", err=True)
    elif has_stale_companions(idb_path):
        click.echo(
            f"Warning: stale IDA companion files detected for {idb_path}. "
            f"Use --clean to remove them, or the daemon may fail to start.",
            err=True,
        )

    if detach:
        effective_timeout = timeout if timeout is not None else (60.0 if mode == "headless" else 180.0)
        try:
            start_background(
                session,
                timeout=effective_timeout,
                binary_path=binary_path if imports_binary else None,
                extra_ida_args=extra_ida_args,
            )
            _output({
                "ok": True,
                "result": {
                    "status": "started",
                    "mode": mode,
                    "project": str(idb_path),
                    "socket": str(sock),
                },
            })
        except TimeoutError as e:
            _error("StartTimeout", str(e))
        except Exception as e:
            if os.environ.get("IDA_RPC_DEBUG"):
                traceback.print_exc(file=sys.stderr)
            _error(type(e).__name__, str(e))
    else:
        if ida_dir_path:
            os.environ["IDA_INSTALL_DIR"] = str(ida_dir_path)
        click.echo(f"Starting ida-rpc daemon ({mode} mode)...", err=True)
        if binary_path:
            click.echo(f"  Binary: {binary_path}", err=True)
        click.echo(f"  Project: {idb_path}", err=True)
        click.echo(f"  Socket:  {sock}", err=True)
        if binary_path:
            effective_timeout = timeout if timeout is not None else (60.0 if mode == "headless" else 180.0)
            start_background(
                session,
                timeout=effective_timeout,
                binary_path=binary_path if imports_binary else None,
                extra_ida_args=extra_ida_args,
            )
            _output({
                "ok": True,
                "result": {
                    "status": "started",
                    "mode": mode,
                    "project": str(idb_path),
                    "socket": str(sock),
                },
            })
        else:
            start_blocking(session)


@cli.command(name="open")
@click.argument("binary", required=False, default="")
@click.option("--project", "-p", type=str, help="IDB path to create/use (default: <binary>.i64)")
@click.option("--arch", "-a", type=str, required=True, help="Processor type (e.g., arm, aarch64, x86, mips, ppc)")
@click.option("--base", "-b", type=HEX_INT, help="Image base address for raw binaries")
@click.option("--loader", "-T", type=str, help="IDA loader/file type to force (for example: raw, 'Binary file', miniloader)")
@click.option("--headless", is_flag=True, help="Start in headless mode (no GUI)")
@click.option("--detach", is_flag=True, help="Start in background")
@click.option("--timeout", "-t", type=float, default=None)
@click.option("--ida-install-dir", "ida_install_dir", type=str, default=None)
@click.option("--clean", is_flag=True, help="Remove stale IDA companion files before starting")
def open_project(
    binary: str,
    project: str | None,
    arch: str | None,
    base: int | None,
    loader: str | None,
    headless: bool,
    detach: bool,
    timeout: float | None,
    ida_install_dir: str | None,
    clean: bool,
):
    """Agent-friendly alias for 'start'."""
    start.callback(
        binary,
        project,
        arch,
        base,
        loader,
        headless,
        detach,
        timeout,
        ida_install_dir,
        clean,
    )


@cli.command()
@click.option("--project", "-p", type=str, help="Path to IDB file")
@click.option("--headless", is_flag=True, default=None)
@click.option("--timeout", "-t", type=float, default=None)
@click.option("--ida-install-dir", "ida_install_dir", type=str, default=None)
@click.option("--clean", is_flag=True, help="Remove stale IDA companion files before restarting")
def restart(
    project: str | None,
    headless: bool | None,
    timeout: float | None,
    ida_install_dir: str | None,
    clean: bool,
):
    """Restart the daemon for a project."""
    from ida_rpc.daemon import start_background, stop_daemon

    idb = _resolve_project(project)
    sock = session_mod.socket_path_for_project(idb)

    from ida_rpc.daemon import has_stale_companions, clean_companion_files

    stop_daemon(sock)

    if clean:
        removed = clean_companion_files(idb)
        if removed:
            click.echo(f"Cleaned stale companion files: {', '.join(removed)}", err=True)
    elif has_stale_companions(idb):
        click.echo(
            f"Warning: stale IDA companion files detected for {idb}. "
            f"Use --clean to remove them, or the daemon may fail to start.",
            err=True,
        )

    session = session_mod.load(idb)
    if session is None:
        if headless:
            session = session_mod.Session(
                mode="headless", project_idb=idb, socket_path=sock,
            )
        else:
            _error(
                "NoSession",
                f"No saved session for {idb}. Use 'ida-rpc start <binary> --arch <arch>' first, or pass '--headless'.",
            )

    if headless:
        session = session_mod.Session(
            mode="headless",
            project_idb=session.project_idb,
            socket_path=session.socket_path,
            ida_install_dir=session.ida_install_dir,
            arch=session.arch,
        )

    if ida_install_dir:
        session.ida_install_dir = Path(ida_install_dir)
    elif not session.ida_install_dir and os.environ.get("IDA_INSTALL_DIR"):
        session.ida_install_dir = Path(os.environ["IDA_INSTALL_DIR"])

    effective_timeout = timeout if timeout is not None else (60.0 if session.mode == "headless" else 180.0)

    try:
        start_background(session, timeout=effective_timeout)
        _output({"ok": True, "result": {"status": "restarted", "socket": str(sock)}})
    except TimeoutError as e:
        _error("RestartTimeout", str(e))
    except Exception as e:
        if os.environ.get("IDA_RPC_DEBUG"):
            traceback.print_exc(file=sys.stderr)
        _error(type(e).__name__, str(e))


@cli.command(name="list")
def list_projects():
    """List all active ida-rpc projects / daemons."""
    from ida_rpc.daemon import is_running

    socks = sorted(Path("/tmp").glob("ida-rpc-*.sock"))
    results = []
    for sock in socks:
        running = is_running(sock)
        entry = {"socket": str(sock), "running": running}
        if running:
            try:
                live = _live_status(sock)
                loaded = live.get("loaded") or {}
                entry.update({
                    "name": loaded.get("name"),
                    "path": loaded.get("path"),
                    "arch": live.get("processor"),
                    "bits": live.get("bits"),
                    "endian": live.get("endian"),
                    "format": live.get("format"),
                    "base_address": live.get("base_address"),
                    "analysis_complete": loaded.get("analysis_complete"),
                })
            except Exception:
                pass
        results.append(entry)

    _output({"ok": True, "result": {"projects": results, "count": len(results)}})


@cli.command()
@click.option("--project", "-p", type=str, help="Path to IDB file")
def status(project: str | None):
    """Check daemon health for a project."""
    from ida_rpc.daemon import is_running

    idb = _resolve_project(project)
    sock = session_mod.socket_path_for_project(idb)
    running = is_running(sock)
    session = session_mod.load(idb)

    mode_source = "running" if running else ("session" if session else None)

    live = {
        "binaries": None,
        "loaded": None,
        "processor": None,
        "bits": None,
        "endian": None,
        "format": None,
        "base_address": None,
    }
    if running:
        try:
            live.update(_live_status(sock))
        except Exception:
            pass

    _output({
        "ok": True,
        "result": {
            "running": running,
            "socket": str(sock),
            "mode": session.mode if session else None,
            "mode_source": mode_source,
            "project": str(idb),
            "arch": session.arch if session else None,
            **live,
        },
    })


@cli.command()
@click.option("--project", "-p", type=str, help="Path to IDB file")
@click.option("--all", "stop_all", is_flag=True, help="Stop all running ida-rpc daemons")
def stop(project: str | None, stop_all: bool):
    """Stop the daemon for a project, or all daemons with --all."""
    from ida_rpc.daemon import stop_daemon

    if stop_all:
        socks = sorted(Path("/tmp").glob("ida-rpc-*.sock"))
        stopped = []
        failed = []
        not_running = []
        for sock in socks:
            if stop_daemon(sock):
                stopped.append(str(sock))
            else:
                # Check if socket file still exists but daemon wasn't responsive
                if sock.exists():
                    not_running.append(str(sock))
                else:
                    failed.append(str(sock))
        _output({
            "ok": True,
            "result": {
                "status": "stopped_all",
                "stopped": stopped,
                "not_running": not_running,
                "failed": failed,
                "count": len(stopped),
            },
        })
        return

    idb = _resolve_project(project)
    sock = session_mod.socket_path_for_project(idb)

    if stop_daemon(sock):
        _output({"ok": True, "result": {"status": "stopped"}})
    else:
        _error("NotRunning", "Daemon is not running.")


# ---------------------------------------------------------------------------
# Analysis & Listing
# ---------------------------------------------------------------------------

@cli.command(name="function")
@click.argument("func")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def get_function(func: str, project: str | None):
    """Get information about a single function."""
    _rpc_command(_resolve_project(project), "function", {"func": func})


@cli.command(name="functions")
@click.option("--limit", "-l", type=int, default=None)
@click.option("--offset", "-o", type=int, default=0, show_default=True)
@click.option("--address-min", "address_min", default="")
@click.option("--address-max", "address_max", default="")
@click.option("--with-body", "with_body", is_flag=True, default=False)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_functions(
    limit: int | None,
    offset: int,
    address_min: str,
    address_max: str,
    with_body: bool,
    project: str | None,
):
    """List functions with optional pagination."""
    args: dict = {"offset": offset}
    if limit is not None:
        args["limit"] = limit
    if address_min:
        args["address_min"] = address_min
    if address_max:
        args["address_max"] = address_max
    if with_body:
        args["with_body"] = True
    _rpc_command(_resolve_project(project), "functions", args)


@cli.command(name="imports")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_imports(project: str | None):
    """List imported symbols."""
    _rpc_command(_resolve_project(project), "imports", {})


@cli.command(name="exports")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_exports(project: str | None):
    """List exported symbols."""
    _rpc_command(_resolve_project(project), "exports", {})


@cli.command(name="add-entry")
@click.argument("address")
@click.argument("name", default="")
@click.option("--ordinal", "-o", type=int, default=0)
@click.option("--no-makecode", is_flag=True, default=False)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def add_entry(address: str, name: str, ordinal: int, no_makecode: bool, project: str | None):
    """Add an entry point."""
    _rpc_command(_resolve_project(project), "add_entry", {
        "address": address, "name": name, "ordinal": ordinal, "makecode": not no_makecode,
    })


@cli.command(name="rename-entry")
@click.argument("ordinal", type=int)
@click.argument("name")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def rename_entry(ordinal: int, name: str, project: str | None):
    """Rename an entry point."""
    _rpc_command(_resolve_project(project), "rename_entry", {
        "ordinal": ordinal, "name": name,
    })


@cli.command(name="metadata")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def binary_metadata(project: str | None):
    """Show binary metadata."""
    _rpc_command(_resolve_project(project), "metadata", {})


@cli.command(name="relocations")
@click.option("--limit", "-l", type=int, default=500)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_relocations(limit: int, project: str | None):
    """List relocation/fixup entries."""
    _rpc_command(_resolve_project(project), "relocations", {"limit": limit})


@cli.command(name="calling-conventions")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_calling_conventions(project: str | None):
    """List valid calling conventions for the current processor."""
    _rpc_command(_resolve_project(project), "list_calling_conventions", {})


@cli.command(name="strings")
@click.argument("query", default="")
@click.option("--limit", "-l", type=int, default=100)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def search_strings(query: str, limit: int, project: str | None):
    """Search strings (empty query lists all)."""
    _rpc_command(_resolve_project(project), "strings", {"query": query, "limit": limit})


@cli.command(name="find-string")
@click.argument("query")
@click.option("--limit", "-l", type=int, default=100)
@click.option("--address", "-a", type=str, default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def find_string(query: str, limit: int, address: str, project: str | None):
    """Search for strings matching a query."""
    args: dict = {"query": query, "limit": limit}
    if address:
        args["address"] = address
    _rpc_command(_resolve_project(project), "find_string", args)


@cli.command(name="symbols")
@click.argument("query")
@click.option("--limit", "-l", type=int, default=25)
@click.option("--offset", "-o", type=int, default=0)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def search_symbols(query: str, limit: int, offset: int, project: str | None):
    """Search named symbols."""
    _rpc_command(_resolve_project(project), "symbols", {
        "query": query, "limit": limit, "offset": offset,
    })


@cli.command(name="find-bytes")
@click.argument("pattern")
@click.option("--limit", "-l", type=int, default=100)
@click.option("--address", "-a", type=str, default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def find_bytes(pattern: str, limit: int, address: str, project: str | None):
    """Search for a byte pattern."""
    args: dict = {"pattern": pattern, "limit": limit}
    if address:
        args["address"] = address
    _rpc_command(_resolve_project(project), "find_bytes", args)


@cli.command(name="memory-map")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def memory_map(project: str | None):
    """List memory segments with RWX permissions."""
    _rpc_command(_resolve_project(project), "memory_map", {})


@cli.command(name="segments")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_segments(project: str | None):
    """List segments (alias for memory-map)."""
    _rpc_command(_resolve_project(project), "list_segments", {})


@cli.command(name="basefind")
@click.argument("path", required=False, type=click.Path(exists=True))
@click.option("--str-len", "-sl", type=int, default=10, show_default=True, help="Minimum string length")
@click.option("--diff-len", "-dl", type=int, default=10, show_default=True, help="String/pointer diff window length")
@click.option("--samplerate", "-s", type=int, default=20, show_default=True, help="String validation samplerate")
@click.option("--min-abs-refs", type=int, default=4, show_default=True, help="Minimum absolute in-image references")
@click.option("--max-results", type=int, default=30, show_default=True, help="Maximum candidates to return")
@click.option("--no-filename-hints", is_flag=True, default=False, help="Do not seed candidates from hex-looking filename tokens")
@click.option("--project", "-p", type=str, help="Path to IDB file (only needed when PATH is omitted)")
def basefind(
    path: str | None,
    str_len: int,
    diff_len: int,
    samplerate: int,
    min_abs_refs: int,
    max_results: int,
    no_filename_hints: bool,
    project: str | None,
):
    """Scan a flat 32-bit binary to determine its load base.

    Runs locally when PATH is provided (no daemon required).
    When PATH is omitted, sends an RPC request to the daemon for the currently loaded binary.
    """
    args = {
        "str_len": str_len,
        "diff_len": diff_len,
        "samplerate": samplerate,
        "min_abs_refs": min_abs_refs,
        "max_results": max_results,
        "filename_hints": not no_filename_hints,
    }

    if path:
        # Run locally — no daemon needed
        from ida_rpc.server.tools.basefind import run_basefind
        result = run_basefind(path, **args)
        _output(result)
    else:
        # Fall back to RPC for the currently loaded binary
        _rpc_command(_resolve_project(project), "basefind", args)


# ---------------------------------------------------------------------------
# Decompilation & Disassembly
# ---------------------------------------------------------------------------

@cli.command(name="decompile")
@click.argument("func")
@click.option("--timeout", "-t", type=int, default=120, show_default=True)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def decompile(func: str, timeout: int, project: str | None):
    """Decompile a function to pseudo-C."""
    _rpc_command(_resolve_project(project), "decompile", {"func": func, "timeout": timeout})


@cli.command(name="decompile-all")
@click.option("--limit", "-l", type=int, default=0, show_default=True)
@click.option("--function", "-f", default="", help="Filter by function name substring")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def decompile_all(limit: int, function: str, project: str | None):
    """Bulk decompile all functions."""
    args: dict = {"limit": limit}
    if function:
        args["function"] = function
    _rpc_command(_resolve_project(project), "decompile_all", args)


@cli.command(name="decompile-lvars")
@click.argument("func")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def decompile_lvars(func: str, project: str | None):
    """List local variables of a function."""
    _rpc_command(_resolve_project(project), "decompile_lvars", {"func": func})


@cli.command(name="set-lvar-name")
@click.argument("func")
@click.argument("lvar")
@click.argument("new_name")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_lvar_name(func: str, lvar: str, new_name: str, project: str | None):
    """Rename a local variable."""
    _rpc_command(_resolve_project(project), "set_lvar_name", {
        "func": func, "lvar": lvar, "new_name": new_name,
    })


@cli.command(name="set-lvar-type")
@click.argument("func")
@click.argument("lvar")
@click.argument("type")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_lvar_type(func: str, lvar: str, type: str, project: str | None):
    """Set the type of a local variable."""
    _rpc_command(_resolve_project(project), "set_lvar_type", {
        "func": func, "lvar": lvar, "type": type,
    })


@cli.command(name="decompile-microcode")
@click.argument("func")
@click.option("--maturity", "-m", type=int, default=None)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def decompile_microcode(func: str, maturity: int | None, project: str | None):
    """Decompile a function to microcode."""
    args: dict = {"func": func}
    if maturity is not None:
        args["maturity"] = maturity
    _rpc_command(_resolve_project(project), "decompile_microcode", args)


@cli.command(name="decompiler-xrefs")
@click.argument("func")
@click.argument("target")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def decompiler_xrefs(func: str, target: str, project: str | None):
    """Find decompiler cross-references."""
    _rpc_command(_resolve_project(project), "decompiler_xrefs", {
        "func": func, "target": target,
    })


@cli.command(name="basic-blocks")
@click.argument("func")
@click.option("--limit", "-l", type=int, default=500)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def basic_blocks(func: str, limit: int, project: str | None):
    """List CFG basic blocks with successors/predecessors."""
    _rpc_command(_resolve_project(project), "basic_blocks", {"func": func, "limit": limit})


@cli.command(name="function-graph")
@click.argument("func")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def function_graph(func: str, project: str | None):
    """Generate a function flow graph."""
    _rpc_command(_resolve_project(project), "function_graph", {"func": func})


@cli.command(name="call-graph")
@click.option("--mode", type=click.Choice(["simple", "complex"]), default="simple")
@click.option("--title", default="call_graph")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def call_graph(mode: str, title: str, project: str | None):
    """Generate a call graph."""
    _rpc_command(_resolve_project(project), "call_graph", {"mode": mode, "title": title})


@cli.command(name="get-switch-info")
@click.argument("address")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def get_switch_info(address: str, project: str | None):
    """Get switch/jump-table information."""
    _rpc_command(_resolve_project(project), "get_switch_info", {"address": address})


@cli.command(name="disassemble")
@click.argument("address")
@click.option("--count", "-n", type=int, default=20, show_default=True)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def disassemble(address: str, count: int, project: str | None):
    """Disassemble instructions at an address."""
    _rpc_command(_resolve_project(project), "disassemble", {"address": address, "count": count})


@cli.command(name="assemble")
@click.argument("address")
@click.argument("instruction")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def assemble(address: str, instruction: str, project: str | None):
    """Assemble instruction text at an address."""
    _rpc_command(_resolve_project(project), "assemble", {"address": address, "instruction": instruction})


@cli.command(name="read-bytes")
@click.argument("address")
@click.argument("length", type=HEX_INT)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def read_bytes(address: str, length: int, project: str | None):
    """Hex dump bytes at an address."""
    _rpc_command(_resolve_project(project), "read_bytes", {"address": address, "length": length})


@cli.command(name="read-string")
@click.argument("address")
@click.option("--strtype", type=str, default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def read_string(address: str, strtype: str, project: str | None):
    """Read a string at an address."""
    args: dict = {"address": address}
    if strtype:
        args["strtype"] = strtype
    _rpc_command(_resolve_project(project), "read_string", args)


@cli.command(name="create-string")
@click.argument("address")
@click.argument("length", type=int)
@click.option("--strtype", type=str, default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def create_string(address: str, length: int, strtype: str, project: str | None):
    """Create a string at an address."""
    args: dict = {"address": address, "length": length}
    if strtype:
        args["strtype"] = strtype
    _rpc_command(_resolve_project(project), "create_string", args)


@cli.command(name="write-bytes")
@click.argument("address")
@click.argument("hex_data")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def write_bytes(address: str, hex_data: str, project: str | None):
    """Patch bytes at an address."""
    _rpc_command(_resolve_project(project), "write_bytes", {"address": address, "hex": hex_data})


@cli.command(name="list-patches")
@click.option("--start", default="")
@click.option("--end", default="")
@click.option("--limit", "-l", type=int, default=500)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_patches(start: str, end: str, limit: int, project: str | None):
    """List patched bytes."""
    args: dict = {"limit": limit}
    if start:
        args["start"] = start
    if end:
        args["end"] = end
    _rpc_command(_resolve_project(project), "list_patches", args)


@cli.command(name="revert-patch")
@click.argument("start")
@click.option("--end", default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def revert_patch(start: str, end: str, project: str | None):
    """Revert patched bytes."""
    args: dict = {"start": start}
    if end:
        args["end"] = end
    _rpc_command(_resolve_project(project), "revert_patch", args)


@cli.command(name="patch-byte")
@click.argument("address")
@click.argument("value", type=HEX_INT)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def patch_byte(address: str, value: int, project: str | None):
    """Patch a byte at an address."""
    _rpc_command(_resolve_project(project), "patch_byte", {"address": address, "value": value})


@cli.command(name="patch-word")
@click.argument("address")
@click.argument("value", type=HEX_INT)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def patch_word(address: str, value: int, project: str | None):
    """Patch a word at an address."""
    _rpc_command(_resolve_project(project), "patch_word", {"address": address, "value": value})


@cli.command(name="patch-dword")
@click.argument("address")
@click.argument("value", type=HEX_INT)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def patch_dword(address: str, value: int, project: str | None):
    """Patch a dword at an address."""
    _rpc_command(_resolve_project(project), "patch_dword", {"address": address, "value": value})


@cli.command(name="patch-qword")
@click.argument("address")
@click.argument("value", type=HEX_INT)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def patch_qword(address: str, value: int, project: str | None):
    """Patch a qword at an address."""
    _rpc_command(_resolve_project(project), "patch_qword", {"address": address, "value": value})


# ---------------------------------------------------------------------------
# Cross-References
# ---------------------------------------------------------------------------

@cli.command(name="list-problems")
@click.option("--type", "problem_type", default="")
@click.option("--limit", "-l", type=int, default=500)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_problems(problem_type: str, limit: int, project: str | None):
    """List IDA analysis problems."""
    args: dict = {"limit": limit}
    if problem_type:
        args["type"] = problem_type
    _rpc_command(_resolve_project(project), "list_problems", args)


@cli.command(name="file-offset")
@click.argument("address")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def file_offset(address: str, project: str | None):
    """Convert an address to a file offset."""
    _rpc_command(_resolve_project(project), "file_offset", {"address": address})


@cli.command(name="file-offset-to-ea")
@click.argument("offset", type=HEX_INT)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def file_offset_to_ea(offset: int, project: str | None):
    """Convert a file offset to an address."""
    _rpc_command(_resolve_project(project), "file_offset_to_ea", {"offset": offset})


@cli.command(name="function-info")
@click.argument("func")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def function_info(func: str, project: str | None):
    """Show detailed function information."""
    _rpc_command(_resolve_project(project), "function_info", {"func": func})


@cli.command(name="function-items")
@click.argument("func")
@click.option("--limit", "-l", type=int, default=5000)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def function_items(func: str, limit: int, project: str | None):
    """List items belonging to a function."""
    _rpc_command(_resolve_project(project), "function_items", {"func": func, "limit": limit})


@cli.command(name="function-chunks")
@click.argument("func")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def function_chunks(func: str, project: str | None):
    """List chunks of a function."""
    _rpc_command(_resolve_project(project), "function_chunks", {"func": func})


@cli.command(name="set-function-color")
@click.argument("func")
@click.argument("color", type=HEX_INT)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_function_color(func: str, color: int, project: str | None):
    """Set the color of a function."""
    _rpc_command(_resolve_project(project), "set_function_color", {"func": func, "color": f"0x{color:08x}"})


@cli.command(name="function-frame")
@click.argument("func")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def function_frame(func: str, project: str | None):
    """Show the stack frame of a function."""
    _rpc_command(_resolve_project(project), "function_frame", {"func": func})


@cli.command(name="list-stack-vars")
@click.argument("func")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_stack_vars(func: str, project: str | None):
    """List stack variables of a function."""
    _rpc_command(_resolve_project(project), "list_stack_vars", {"func": func})


@cli.command(name="rename-stack-var")
@click.argument("func")
@click.option("--offset", "-o", type=int, default=-1)
@click.option("--old-name", default="")
@click.option("--new-name", "-n", required=True)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def rename_stack_var(func: str, offset: int, old_name: str, new_name: str, project: str | None):
    """Rename a stack variable."""
    args: dict = {"func": func, "new_name": new_name}
    if offset >= 0:
        args["offset"] = offset
    if old_name:
        args["old_name"] = old_name
    _rpc_command(_resolve_project(project), "rename_stack_var", args)


@cli.command(name="set-stack-var-type")
@click.argument("func")
@click.option("--offset", "-o", type=int, default=-1)
@click.option("--name", default="")
@click.option("--type", "var_type", required=True)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_stack_var_type(func: str, offset: int, name: str, var_type: str, project: str | None):
    """Set the type of a stack variable."""
    args: dict = {"func": func, "type": var_type}
    if offset >= 0:
        args["offset"] = offset
    if name:
        args["name"] = name
    _rpc_command(_resolve_project(project), "set_stack_var_type", args)


@cli.command(name="list-reg-vars")
@click.argument("func")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_reg_vars(func: str, project: str | None):
    """List register variables of a function."""
    _rpc_command(_resolve_project(project), "list_reg_vars", {"func": func})


@cli.command(name="stack-var-xrefs")
@click.argument("func")
@click.option("--offset", "-o", type=int, default=-1)
@click.option("--name", default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def stack_var_xrefs(func: str, offset: int, name: str, project: str | None):
    """Find cross-references to a stack variable."""
    args: dict = {"func": func}
    if offset >= 0:
        args["offset"] = offset
    if name:
        args["name"] = name
    _rpc_command(_resolve_project(project), "stack_var_xrefs", args)


@cli.command(name="xrefs-to")
@click.argument("target")
@click.option("--limit", "-l", type=int, default=50)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def xrefs_to(target: str, limit: int, project: str | None):
    """Find references to a target."""
    _rpc_command(_resolve_project(project), "xrefs_to", {"target": target, "limit": limit})


@cli.command(name="xrefs-from")
@click.argument("target")
@click.option("--limit", "-l", type=int, default=50)
@click.option("--no-stack", "no_stack", is_flag=True, default=False)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def xrefs_from(target: str, limit: int, no_stack: bool, project: str | None):
    """Find references from a target."""
    _rpc_command(_resolve_project(project), "xrefs_from", {
        "target": target, "limit": limit, "no_stack": no_stack,
    })


# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------

@cli.command(name="goto")
@click.argument("target")
@click.argument("target_type", type=click.Choice(["function", "address"]), default="function")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def goto(target: str, target_type: str, project: str | None):
    """Jump to a function or address in the IDA UI."""
    _rpc_command(_resolve_project(project), "goto", {
        "target": target, "target_type": target_type,
    })


# ---------------------------------------------------------------------------
# Annotations & Modifications
# ---------------------------------------------------------------------------

@cli.command(name="rename-function")
@click.argument("target")
@click.argument("new_name")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def rename_function(target: str, new_name: str, project: str | None):
    """Rename a function."""
    _rpc_command(_resolve_project(project), "rename_function", {
        "target": target, "new_name": new_name,
    })


@cli.command(name="rename-symbol")
@click.argument("address")
@click.argument("new_name")
@click.option("--create", is_flag=True, default=False)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def rename_symbol(address: str, new_name: str, create: bool, project: str | None):
    """Rename a symbol."""
    _rpc_command(_resolve_project(project), "rename_symbol", {
        "address": address, "new_name": new_name, "create": create,
    })


@cli.command(name="create-label")
@click.argument("address")
@click.argument("name")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def create_label(address: str, name: str, project: str | None):
    """Create or rename a label."""
    _rpc_command(_resolve_project(project), "create_label", {
        "address": address, "name": name,
    })


@cli.command(name="set-comment")
@click.argument("address")
@click.argument("comment")
@click.option("--type", "comment_type", type=click.Choice(["plate", "pre", "post", "eol", "repeatable"]), default="eol")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_comment(address: str, comment: str, comment_type: str, project: str | None):
    """Set a comment at an address."""
    _rpc_command(_resolve_project(project), "set_comment", {
        "address": address, "comment": comment, "comment_type": comment_type,
    })


@cli.command(name="set-signature")
@click.argument("target")
@click.argument("signature")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_signature(target: str, signature: str, project: str | None):
    """Set a function's prototype/signature."""
    _rpc_command(_resolve_project(project), "set_function_signature", {
        "target": target, "signature": signature,
    })


@cli.command(name="set-data-type")
@click.argument("address")
@click.argument("data_type")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_data_type(address: str, data_type: str, project: str | None):
    """Set the data type at an address."""
    _rpc_command(_resolve_project(project), "set_data_type", {
        "address": address, "data_type": data_type,
    })


@cli.command(name="create-function")
@click.argument("address")
@click.option("--name", "-n", default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def create_function(address: str, name: str, project: str | None):
    """Create a function at an address."""
    args: dict = {"address": address}
    if name:
        args["name"] = name
    _rpc_command(_resolve_project(project), "create_function", args)


@cli.command(name="delete-function")
@click.argument("target")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def delete_function(target: str, project: str | None):
    """Delete a function definition."""
    _rpc_command(_resolve_project(project), "delete_function", {"target": target})


@cli.command(name="create-instruction")
@click.argument("address")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def create_instruction(address: str, project: str | None):
    """Mark bytes at address as an instruction."""
    _rpc_command(_resolve_project(project), "create_instruction", {"address": address})


@cli.command(name="undefine")
@click.argument("address")
@click.argument("length", type=int, default=1)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def undefine(address: str, length: int, project: str | None):
    """Undefine instruction or data at address."""
    _rpc_command(_resolve_project(project), "undefine", {"address": address, "length": length})


@cli.command(name="set-thunk")
@click.argument("target")
@click.option("--thunk-target", default="")
@click.option("--clear", is_flag=True, default=False)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_thunk(target: str, thunk_target: str, clear: bool, project: str | None):
    """Mark or unmark a function as a thunk."""
    args: dict = {"target": target, "clear": clear}
    if thunk_target:
        args["thunk_target"] = thunk_target
    _rpc_command(_resolve_project(project), "set_thunk", args)


@cli.command(name="set-calling-convention")
@click.argument("target")
@click.argument("convention")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_calling_convention(target: str, convention: str, project: str | None):
    """Change a function's calling convention."""
    _rpc_command(_resolve_project(project), "set_calling_convention", {
        "target": target, "convention": convention,
    })


@cli.command(name="batch-rename")
@click.option("--mode", type=click.Choice(["function", "symbol"]), default="function")
@click.option("--from-file", "from_file", type=click.Path(exists=True), help="JSON file with operations array")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def batch_rename(mode: str, from_file: str | None, project: str | None):
    """Bulk rename functions or symbols from a JSON file."""
    if from_file:
        with open(from_file) as f:
            data = json.load(f)
        operations = data if isinstance(data, list) else data.get("operations", [])
    else:
        click.echo("Error: --from-file is required for batch-rename", err=True)
        sys.exit(1)
    _rpc_command(_resolve_project(project), "batch_rename", {
        "mode": mode, "operations": operations,
    })


@cli.command(name="batch-set-comment")
@click.option("--from-file", "from_file", type=click.Path(exists=True), help="JSON file with operations array")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def batch_set_comment(from_file: str | None, project: str | None):
    """Bulk set comments from a JSON file."""
    if from_file:
        with open(from_file) as f:
            data = json.load(f)
        operations = data if isinstance(data, list) else data.get("operations", [])
    else:
        click.echo("Error: --from-file is required for batch-set-comment", err=True)
        sys.exit(1)
    _rpc_command(_resolve_project(project), "batch_set_comment", {
        "operations": operations,
    })


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

@cli.command(name="create-struct")
@click.argument("struct_name")
@click.argument("fields", nargs=-1, required=True)
@click.option("--if-not-exists", "if_not_exists", is_flag=True, default=False)
@click.option("--or-replace", "or_replace", is_flag=True, default=False)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def create_struct(struct_name: str, fields: tuple, if_not_exists: bool, or_replace: bool, project: str | None):
    """Create a struct type."""
    if len(fields) % 2 != 0:
        click.echo("Error: FIELDS must be pairs of TYPE NAME", err=True)
        sys.exit(1)
    field_list = [
        {"type": fields[i], "name": fields[i + 1]}
        for i in range(0, len(fields), 2)
    ]
    _rpc_command(_resolve_project(project), "create_struct", {
        "name": struct_name, "fields": field_list,
        "if_not_exists": if_not_exists, "or_replace": or_replace,
    })


@cli.command(name="create-union")
@click.argument("union_name")
@click.argument("fields", nargs=-1, required=True)
@click.option("--if-not-exists", "if_not_exists", is_flag=True, default=False)
@click.option("--or-replace", "or_replace", is_flag=True, default=False)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def create_union(union_name: str, fields: tuple, if_not_exists: bool, or_replace: bool, project: str | None):
    """Create a union type."""
    if len(fields) % 2 != 0:
        click.echo("Error: FIELDS must be pairs of TYPE NAME", err=True)
        sys.exit(1)
    field_list = [
        {"type": fields[i], "name": fields[i + 1]}
        for i in range(0, len(fields), 2)
    ]
    _rpc_command(_resolve_project(project), "create_union", {
        "name": union_name, "fields": field_list,
        "if_not_exists": if_not_exists, "or_replace": or_replace,
    })


@cli.command(name="create-enum")
@click.argument("enum_name")
@click.argument("values", nargs=-1, required=False)
@click.option("--size", "size", type=click.Choice(["1", "2", "4", "8"]), default="4")
@click.option("--if-not-exists", "if_not_exists", is_flag=True, default=False)
@click.option("--or-replace", "or_replace", is_flag=True, default=False)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def create_enum(enum_name: str, values: tuple, size: str, if_not_exists: bool, or_replace: bool, project: str | None):
    """Create an enum type."""
    if len(values) % 2 != 0:
        click.echo("Error: VALUES must be pairs of NAME VALUE", err=True)
        sys.exit(1)
    value_list = [
        {"name": values[i], "value": int(values[i + 1], 0)}
        for i in range(0, len(values), 2)
    ]
    _rpc_command(_resolve_project(project), "create_enum", {
        "name": enum_name, "values": value_list,
        "size": int(size), "if_not_exists": if_not_exists, "or_replace": or_replace,
    })


@cli.command(name="modify-struct")
@click.argument("struct_name")
@click.option("--action", type=click.Choice(["rename", "retype", "delete", "set_comment"]), required=True)
@click.option("--field", required=True)
@click.option("--new-field-name", default="")
@click.option("--new-type", default="")
@click.option("--comment", default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def modify_struct(struct_name: str, action: str, field: str, new_field_name: str, new_type: str, comment: str, project: str | None):
    """Modify a struct field."""
    args: dict = {"name": struct_name, "action": action, "field": field}
    if new_field_name:
        args["new_field_name"] = new_field_name
    if new_type:
        args["new_type"] = new_type
    if comment:
        args["comment"] = comment
    _rpc_command(_resolve_project(project), "modify_struct", args)


@cli.command(name="modify-enum")
@click.argument("enum_name")
@click.option("--action", type=click.Choice(["add", "remove"]), required=True)
@click.option("--member", required=True)
@click.option("--value", type=HEX_INT, default=0)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def modify_enum(enum_name: str, action: str, member: str, value: int, project: str | None):
    """Modify an enum member."""
    _rpc_command(_resolve_project(project), "modify_enum", {
        "name": enum_name, "action": action, "member": member, "value": value,
    })


@cli.command(name="clear-data-range")
@click.argument("start")
@click.option("--end", default="")
@click.option("--length", type=HEX_INT, default=0)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def clear_data_range(start: str, end: str, length: int, project: str | None):
    """Undefine data in an address range."""
    args: dict = {"start": start}
    if end:
        args["end"] = end
    elif length:
        args["length"] = length
    else:
        click.echo("Error: Provide either --end or --length", err=True)
        sys.exit(1)
    _rpc_command(_resolve_project(project), "clear_data_range", args)


@cli.command(name="apply-data-type-range")
@click.argument("start")
@click.argument("data_type")
@click.option("--end", default="")
@click.option("--length", type=HEX_INT, default=0)
@click.option("--type-size", "type_size", type=int, default=None)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def apply_data_type_range(start: str, data_type: str, end: str, length: int, type_size: int | None, project: str | None):
    """Stamp a data type across an address range."""
    args: dict = {"start": start, "data_type": data_type}
    if end:
        args["end"] = end
    elif length:
        args["length"] = length
    else:
        click.echo("Error: Provide either --end or --length", err=True)
        sys.exit(1)
    if type_size is not None:
        args["type_size"] = type_size
    _rpc_command(_resolve_project(project), "apply_data_type_range", args)


@cli.command(name="import-til")
@click.argument("path")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def import_til(path: str, project: str | None):
    """Import types from a TIL file."""
    _rpc_command(_resolve_project(project), "import_til", {"path": path})


@cli.command(name="export-til")
@click.argument("path")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def export_til(path: str, project: str | None):
    """Export types to a TIL file."""
    _rpc_command(_resolve_project(project), "export_til", {"path": path})


@cli.command(name="delete-type")
@click.argument("name")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def delete_type(name: str, project: str | None):
    """Delete a type by name."""
    _rpc_command(_resolve_project(project), "delete_type", {"name": name})


@cli.command(name="get-type-info")
@click.argument("name")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def get_type_info(name: str, project: str | None):
    """Get information about a type."""
    _rpc_command(_resolve_project(project), "get_type_info", {"name": name})


@cli.command(name="list-data-types")
@click.option("--category", default="all", type=click.Choice(["all", "struct", "enum", "union", "typedef", "pointer", "array", "other"]))
@click.option("--query", default="")
@click.option("--limit", "-l", type=int, default=200)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_data_types(category: str, query: str, limit: int, project: str | None):
    """List defined data types."""
    _rpc_command(_resolve_project(project), "list_data_types", {
        "category": category, "query": query, "limit": limit,
    })


@cli.command(name="list-labels")
@click.argument("address")
@click.option("--end", default="")
@click.option("--limit", "-l", type=int, default=100)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_labels(address: str, end: str, limit: int, project: str | None):
    """List labels near an address."""
    args: dict = {"address": address, "limit": limit}
    if end:
        args["end"] = end
    _rpc_command(_resolve_project(project), "list_labels", args)


@cli.command(name="set-equate")
@click.argument("address")
@click.argument("operand", type=int)
@click.argument("enum")
@click.option("--clear", is_flag=True, default=False)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_equate(address: str, operand: int, enum: str, clear: bool, project: str | None):
    """Attach an enum to an instruction operand."""
    _rpc_command(_resolve_project(project), "set_equate", {
        "address": address, "operand": operand, "enum": enum, "clear": clear,
    })


@cli.command(name="list-equates")
@click.option("--address", "-a", default="")
@click.option("--end", default="")
@click.option("--limit", "-l", type=int, default=200)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_equates(address: str, end: str, limit: int, project: str | None):
    """List enum operands."""
    args: dict = {"limit": limit}
    if address:
        args["address"] = address
    if end:
        args["end"] = end
    _rpc_command(_resolve_project(project), "list_equates", args)


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------

@cli.command(name="set-bookmark")
@click.argument("address")
@click.option("--type", "bm_type", type=click.Choice(["Note", "Warning", "Error", "Info", "Analysis"]), default="Note")
@click.option("--category", "-c", default="")
@click.option("--comment", "-m", default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_bookmark(address: str, bm_type: str, category: str, comment: str, project: str | None):
    """Set a bookmark at an address."""
    _rpc_command(_resolve_project(project), "set_bookmark", {
        "address": address,
        "type": bm_type, "category": category, "comment": comment,
    })


@cli.command(name="list-bookmarks")
@click.option("--type", "bm_type", default="")
@click.option("--address", "-a", default="")
@click.option("--limit", "-l", type=int, default=200)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_bookmarks(bm_type: str, address: str, limit: int, project: str | None):
    """List bookmarks."""
    args: dict = {"limit": limit}
    if bm_type:
        args["type"] = bm_type
    if address:
        args["address"] = address
    _rpc_command(_resolve_project(project), "list_bookmarks", args)


@cli.command(name="remove-bookmark")
@click.argument("address")
@click.option("--type", "bm_type", type=click.Choice(["Note", "Warning", "Error", "Info", "Analysis"]), default="Note")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def remove_bookmark(address: str, bm_type: str, project: str | None):
    """Remove a bookmark."""
    _rpc_command(_resolve_project(project), "remove_bookmark", {
        "address": address, "type": bm_type,
    })


# ---------------------------------------------------------------------------
# Segments
# ---------------------------------------------------------------------------

@cli.command(name="add-segment")
@click.argument("start")
@click.argument("end")
@click.option("--name", "-n", default="")
@click.option("--class", "sclass", default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def add_segment(start: str, end: str, name: str, sclass: str, project: str | None):
    """Create a new segment."""
    args: dict = {"start": start, "end": end}
    if name:
        args["name"] = name
    if sclass:
        args["class"] = sclass
    _rpc_command(_resolve_project(project), "add_segment", args)


@cli.command(name="edit-segment")
@click.argument("start")
@click.option("--name", "-n", default="")
@click.option("--class", "sclass", default="")
@click.option("--perm-read/--no-perm-read", default=None)
@click.option("--perm-write/--no-perm-write", default=None)
@click.option("--perm-exec/--no-perm-exec", default=None)
@click.option("--bitness", "-b", type=int, default=None, help="0=16-bit, 1=32-bit, 2=64-bit")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def edit_segment(start: str, name: str, sclass: str, perm_read: bool | None, perm_write: bool | None, perm_exec: bool | None, bitness: int | None, project: str | None):
    """Modify a segment."""
    args: dict = {"start": start}
    if name:
        args["name"] = name
    if sclass:
        args["class"] = sclass
    if perm_read is not None:
        args["perm_read"] = perm_read
    if perm_write is not None:
        args["perm_write"] = perm_write
    if perm_exec is not None:
        args["perm_exec"] = perm_exec
    if bitness is not None:
        args["bitness"] = bitness
    _rpc_command(_resolve_project(project), "edit_segment", args)


@cli.command(name="delete-segment")
@click.argument("start")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def delete_segment(start: str, project: str | None):
    """Delete a segment."""
    _rpc_command(_resolve_project(project), "delete_segment", {"start": start})


# ---------------------------------------------------------------------------
# Processor Context
# ---------------------------------------------------------------------------

@cli.command(name="debug-start")
@click.argument("path", required=False, default="")
@click.option("--args", default="")
@click.option("--sdir", default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_start(path: str, args: str, sdir: str, project: str | None):
    """Start debugging a program."""
    rpc_args: dict = {}
    if path:
        rpc_args["path"] = path
    if args:
        rpc_args["args"] = args
    if sdir:
        rpc_args["sdir"] = sdir
    _rpc_command(_resolve_project(project), "debug_start", rpc_args)


@cli.command(name="debug-attach")
@click.argument("pid", type=int)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_attach(pid: int, project: str | None):
    """Attach the debugger to a process."""
    _rpc_command(_resolve_project(project), "debug_attach", {"pid": pid})


@cli.command(name="debug-detach")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_detach(project: str | None):
    """Detach the debugger."""
    _rpc_command(_resolve_project(project), "debug_detach", {})


@cli.command(name="debug-exit")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_exit(project: str | None):
    """Exit the debugger."""
    _rpc_command(_resolve_project(project), "debug_exit", {})


@cli.command(name="debug-continue")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_continue(project: str | None):
    """Continue execution in the debugger."""
    _rpc_command(_resolve_project(project), "debug_continue", {})


@cli.command(name="debug-suspend")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_suspend(project: str | None):
    """Suspend execution."""
    _rpc_command(_resolve_project(project), "debug_suspend", {})


@cli.command(name="debug-step-into")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_step_into(project: str | None):
    """Single step into."""
    _rpc_command(_resolve_project(project), "debug_step_into", {})


@cli.command(name="debug-step-over")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_step_over(project: str | None):
    """Step over a call."""
    _rpc_command(_resolve_project(project), "debug_step_over", {})


@cli.command(name="debug-run-to")
@click.argument("address")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_run_to(address: str, project: str | None):
    """Run execution to an address."""
    _rpc_command(_resolve_project(project), "debug_run_to", {"address": address})


@cli.command(name="debug-status")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_status(project: str | None):
    """Get debugger status."""
    _rpc_command(_resolve_project(project), "debug_status", {})


@cli.command(name="debug-get-registers")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_get_registers(project: str | None):
    """Get debugger register values."""
    _rpc_command(_resolve_project(project), "debug_get_registers", {})


@cli.command(name="debug-set-register")
@click.argument("register")
@click.argument("value", type=HEX_INT)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_set_register(register: str, value: int, project: str | None):
    """Set a debugger register value."""
    _rpc_command(_resolve_project(project), "debug_set_register", {
        "register": register, "value": value,
    })


@cli.command(name="debug-read-memory")
@click.argument("address")
@click.argument("length", type=HEX_INT)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_read_memory(address: str, length: int, project: str | None):
    """Read memory from the debuggee."""
    _rpc_command(_resolve_project(project), "debug_read_memory", {
        "address": address, "length": length,
    })


@cli.command(name="debug-write-memory")
@click.argument("address")
@click.argument("hex_data")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_write_memory(address: str, hex_data: str, project: str | None):
    """Write memory in the debuggee."""
    _rpc_command(_resolve_project(project), "debug_write_memory", {
        "address": address, "hex": hex_data,
    })


@cli.command(name="debug-breakpoints")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_breakpoints(project: str | None):
    """List debugger breakpoints."""
    _rpc_command(_resolve_project(project), "debug_breakpoints", {})


@cli.command(name="debug-add-breakpoint")
@click.argument("address")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_add_breakpoint(address: str, project: str | None):
    """Add a debugger breakpoint."""
    _rpc_command(_resolve_project(project), "debug_add_breakpoint", {"address": address})


@cli.command(name="debug-delete-breakpoint")
@click.argument("address")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_delete_breakpoint(address: str, project: str | None):
    """Delete a debugger breakpoint."""
    _rpc_command(_resolve_project(project), "debug_delete_breakpoint", {"address": address})


@cli.command(name="debug-enable-breakpoint")
@click.argument("address")
@click.option("--enabled/--disabled", default=True)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_enable_breakpoint(address: str, enabled: bool, project: str | None):
    """Enable or disable a breakpoint."""
    _rpc_command(_resolve_project(project), "debug_enable_breakpoint", {
        "address": address, "enabled": enabled,
    })


@cli.command(name="debug-stack-trace")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_stack_trace(project: str | None):
    """Get the debugger stack trace."""
    _rpc_command(_resolve_project(project), "debug_stack_trace", {})


@cli.command(name="debug-modules")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_modules(project: str | None):
    """List modules in the debuggee."""
    _rpc_command(_resolve_project(project), "debug_modules", {})


@cli.command(name="debug-threads")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def debug_threads(project: str | None):
    """List debugger threads."""
    _rpc_command(_resolve_project(project), "debug_threads", {})


@cli.command(name="get-processor-context")
@click.option("--address", "-a", default="")
@click.option("--register", "-r", default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def get_processor_context(address: str, register: str, project: str | None):
    """Read processor context registers."""
    args: dict = {}
    if address:
        args["address"] = address
    if register:
        args["register"] = register
    _rpc_command(_resolve_project(project), "get_processor_context", args)


@cli.command(name="set-processor-context")
@click.argument("address")
@click.argument("register")
@click.argument("value", type=HEX_INT)
@click.option("--end", default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_processor_context(address: str, register: str, value: int, end: str, project: str | None):
    """Set a processor context register."""
    args: dict = {"address": address, "register": register, "value": value}
    if end:
        args["end"] = end
    _rpc_command(_resolve_project(project), "set_processor_context", args)


@cli.command(name="operand-struct-path")
@click.argument("address")
@click.argument("operand", type=int, default=0)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def operand_struct_path(address: str, operand: int, project: str | None):
    """Get struct path for an operand."""
    _rpc_command(_resolve_project(project), "operand_struct_path", {
        "address": address, "operand": operand,
    })


@cli.command(name="set-color")
@click.argument("address")
@click.argument("color", type=HEX_INT)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def set_color(address: str, color: int, project: str | None):
    """Set the color at an address."""
    _rpc_command(_resolve_project(project), "set_color", {
        "address": address, "color": f"0x{color:08x}",
    })


@cli.command(name="get-color")
@click.argument("address")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def get_color(address: str, project: str | None):
    """Get the color at an address."""
    _rpc_command(_resolve_project(project), "get_color", {"address": address})


@cli.command(name="del-color")
@click.argument("address")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def del_color(address: str, project: str | None):
    """Delete the color at an address."""
    _rpc_command(_resolve_project(project), "del_color", {"address": address})


@cli.command(name="list-try-blocks")
@click.option("--start", default="")
@click.option("--end", default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_try_blocks(start: str, end: str, project: str | None):
    """List try/catch blocks."""
    args: dict = {}
    if start:
        args["start"] = start
    if end:
        args["end"] = end
    _rpc_command(_resolve_project(project), "list_try_blocks", args)


# ---------------------------------------------------------------------------
# Namespaces
# ---------------------------------------------------------------------------

@cli.command(name="create-namespace")
@click.argument("namespace")
@click.option("--parent", default="")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def create_namespace(namespace: str, parent: str, project: str | None):
    """Create a namespace."""
    args: dict = {"namespace": namespace}
    if parent:
        args["parent"] = parent
    _rpc_command(_resolve_project(project), "create_namespace", args)


@cli.command(name="list-namespaces")
@click.option("--limit", "-l", type=int, default=200)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_namespaces(limit: int, project: str | None):
    """List namespaces."""
    _rpc_command(_resolve_project(project), "list_namespaces", {"limit": limit})


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

@cli.command(name="tag-function")
@click.argument("target")
@click.argument("tag")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def tag_function(target: str, tag: str, project: str | None):
    """Tag a function."""
    _rpc_command(_resolve_project(project), "tag_function", {"target": target, "tag": tag})


@cli.command(name="untag-function")
@click.argument("target")
@click.argument("tag")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def untag_function(target: str, tag: str, project: str | None):
    """Remove a tag from a function."""
    _rpc_command(_resolve_project(project), "untag_function", {"target": target, "tag": tag})


@cli.command(name="list-tags")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_tags(project: str | None):
    """List all function tags."""
    _rpc_command(_resolve_project(project), "list_tags", {})


@cli.command(name="functions-by-tag")
@click.argument("tag")
@click.option("--limit", "-l", type=int, default=200)
@click.option("--project", "-p", type=str, help="Path to IDB file")
def functions_by_tag(tag: str, limit: int, project: str | None):
    """Find functions by tag."""
    _rpc_command(_resolve_project(project), "functions_by_tag", {"tag": tag, "limit": limit})


@cli.command(name="lumina-config")
@click.option("--secondary", is_flag=True, help="Inspect secondary Lumina settings.")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def lumina_config(secondary: bool, project: str | None):
    """Read Lumina configuration source information from IDA."""
    _rpc_command(_resolve_project(project), "lumina_config", {"secondary": secondary})


@cli.command(name="lumina-pull-signatures")
@click.argument("target", required=False)
@click.option("--all", "all_functions", is_flag=True, help="Pull signatures for all functions.")
@click.option("--apply/--no-apply", "apply_md", default=True, help="Apply pulled metadata to the IDB.")
@click.option("--force", is_flag=True, help="Force-apply returned metadata after pulling.")
@click.option("--seen-file", is_flag=True, help="Do not increment Lumina frequency counters.")
@click.option("--secondary", is_flag=True, help="Use the secondary Lumina server.")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def lumina_pull_signatures(target: str | None, all_functions: bool, apply_md: bool,
                           force: bool, seen_file: bool, secondary: bool,
                           project: str | None):
    """Pull function signatures from the configured Lumina server."""
    _rpc_command(_resolve_project(project), "lumina_pull_signatures", {
        "target": target or "",
        "all": all_functions,
        "apply": apply_md,
        "force": force,
        "seen_file": seen_file,
        "secondary": secondary,
    })


@cli.command(name="lumina-push-signatures")
@click.argument("target", required=False)
@click.option("--all", "all_functions", is_flag=True, help="Push signatures for all functions.")
@click.option("--mode", type=click.Choice(["better", "override", "no-override", "merge"]), default="better")
@click.option("--min-func-size", type=int, default=0)
@click.option("--secondary", is_flag=True, help="Use the secondary Lumina server.")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def lumina_push_signatures(target: str | None, all_functions: bool, mode: str,
                           min_func_size: int, secondary: bool, project: str | None):
    """Push function signatures to the configured Lumina server."""
    _rpc_command(_resolve_project(project), "lumina_push_signatures", {
        "target": target or "",
        "all": all_functions,
        "mode": mode,
        "min_func_size": min_func_size,
        "secondary": secondary,
    })


# ---------------------------------------------------------------------------
# Lifecycle helpers
# ---------------------------------------------------------------------------

@cli.command(name="save")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def save_program(project: str | None):
    """Save the database."""
    _rpc_command(_resolve_project(project), "save", {})


@cli.command(name="list-binaries")
@click.option("--project", "-p", type=str, help="Path to IDB file")
def list_binaries(project: str | None):
    """List binaries loaded in the current IDB."""
    _rpc_command(_resolve_project(project), "list_binaries", {})


def main():
    try:
        return cli.main(standalone_mode=False)
    except click.ClickException as e:
        _error(type(e).__name__, e.format_message())
    except click.Abort:
        _error("Abort", "Command aborted")
