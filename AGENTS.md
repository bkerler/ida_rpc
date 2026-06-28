# AGENTS.md — ida-rpc

Agent-focused guidance for developing and extending the IDA Pro RPC plugin.

## Automatic Reverse Engineering Usage

When reversing binaries with IDA Pro, prefer `ida-rpc` before screen scraping,
manual GUI steps, or ad hoc IDAPython scripts.

Use these stable agent probes first:

```bash
ida-rpc capabilities
ida-rpc find-project <binary-or-idb>
ida-rpc list-loaders <binary>
```

Then use:

```bash
ida-rpc open <binary-or-idb> --arch <arch> --headless --detach
ida-rpc open <raw.bin> --arch arm --base 0x8000 --loader raw --headless --detach
ida-rpc open <loader.bin> --arch arm --loader miniloader --headless --detach
ida-rpc status --project <idb>
ida-rpc metadata --project <idb>
ida-rpc functions --project <idb> --limit 50
ida-rpc decompile <function-or-address> --project <idb>
ida-rpc xrefs-to <target> --project <idb>
ida-rpc xrefs-from <target> --project <idb>
ida-rpc rename-function <target> <new_name> --project <idb>
ida-rpc set-comment <address> <comment> --project <idb>
ida-rpc save --project <idb>
```

All automation commands print human-readable text to stdout by default. Pass
`--json` (before the subcommand) or set `IDA_RPC_JSON=1` for JSON output. Treat
`{"ok": false, ...}` (JSON mode) or `Error: <error>: <message>` (human mode) as
a recoverable tool error. Set `IDA_RPC_DEBUG=1` only when a traceback is needed.

RPC queries should always be run outside the sandbox.

## Project Overview

`ida-rpc` is a JSON-RPC daemon that runs **inside IDA Pro** (as a plugin) and exposes reverse-engineering capabilities over a Unix domain socket. It is wire-format compatible with [ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc).

```
┌─────────────┐      Unix Socket       ┌──────────────────────────────┐
│  LLM agent  │  ──── JSON/newline ──→ │  ida-rpc daemon              │
│  (via CLI)  │  ←── JSON/newline ───  │  (IDA Python plugin + server)│
└─────────────┘                        └──────────────────────────────┘
```

## Repository Layout

| Path | Purpose |
|------|---------|
| `ida_rpc_plugin.py` | IDA Pro plugin entry point (loaded by IDA on startup) |
| `ida_rpc/cli.py` | Click-based CLI (`ida-rpc` command) |
| `ida_rpc/client.py` | Unix socket client + error types |
| `ida_rpc/daemon.py` | Daemon lifecycle (`start`, `stop`, `restart`) |
| `ida_rpc/session.py` | Session persistence (JSON state files) |
| `ida_rpc/server/main.py` | JSON-line socket server, handler registry |
| `ida_rpc/server/context.py` | `IdaContext` — wraps IDA database, thread-safe dispatch |
| `ida_rpc/server/tools/` | One module per command family (see below) |

### Tools Modules

| Module | Commands |
|--------|----------|
| `analysis.py` | `load`, `list_binaries`, `functions`, `imports`, `exports`, `metadata`, `relocations`, `list_calling_conventions`, `save` |
| `basefind.py` | `basefind` |
| `decompiler.py` | `decompile`, `decompile_all` |
| `disassembly.py` | `disassemble` |
| `assembler.py` | `assemble` |
| `search.py` | `find_bytes`, `strings`, `symbols` |
| `memory.py` | `read_bytes`, `write_bytes`, `memory_map` |
| `segments.py` | `add_segment`, `edit_segment`, `delete_segment`, `list_segments` |
| `xrefs.py` | `xrefs_to`, `xrefs_from` |
| `navigation.py` | `goto` (GUI only) |
| `modifications.py` | `rename_function`, `rename_symbol`, `create_label`, `set_comment`, `set_function_signature`, `set_data_type`, `create_function`, `delete_function`, `create_instruction`, `undefine`, `set_thunk`, `set_calling_convention`, `batch_rename`, `batch_set_comment` |
| `data_types.py` | `create_struct`, `create_union`, `create_enum`, `list_data_types`, `list_labels`, `modify_struct`, `modify_enum`, `clear_data_range`, `apply_data_type_range`, `set_equate`, `list_equates` |
| `bookmarks.py` | `set_bookmark`, `list_bookmarks`, `remove_bookmark` |
| `cfg.py` | `basic_blocks` |
| `tags.py` | `tag_function`, `untag_function`, `list_tags`, `functions_by_tag` |
| `processor.py` | `get_processor_context`, `set_processor_context` |
| `namespaces.py` | `create_namespace`, `list_namespaces` |

## Development Environment

- **IDA Pro Version:** 9.3 SP2 at `$(IDA_INSTALL_DIR)` (e.g. `/home/bjk/bin/ida-pro-9.3sp2`)
- **Plugin install path:** `$IDAUSR/plugins/ida_rpc_plugin.py` (default `$IDAUSR` is `~/.idapro/` on Linux, `~/Library/Application Support/IDA Pro/` on macOS, `%APPDATA%\Hex-Rays\IDA Pro\` on Windows)
- **Plugin symlink (dev):** `ln -s /path/to/ida-rpc/ida_rpc_plugin.py $(IDA_INSTALL_DIR)/plugins/ida_rpc_plugin.py`
- **Python package:** `pip install -e /path/to/ida-rpc`
- **Entry points:** `ida-rpc` (CLI), `ida-rpcd` (daemon)

### Loader Selection

Use `list-loaders` before opening ambiguous or raw firmware:

```bash
ida-rpc list-loaders /path/to/blob.bin
ida-rpc list-loaders /path/to/blob.bin --ida-install-dir /opt/ida-pro-9.3sp2
```

`list-loaders` reports:

- `aliases`: convenient names accepted by `--loader`, such as `raw`,
  `miniloader`, `uboot-fit`, and `rkns`.
- `candidates`: file-specific guesses based on cheap magic checks.
- `installed`: loader modules found under `$IDA_INSTALL_DIR/loaders`,
  `~/.idapro/loaders`, and `~/.idapro/Loaders`.

Force a loader with `start/open --loader` or `-T`:

```bash
ida-rpc open firmware.bin --arch arm --base 0x8000 --loader raw --headless --detach
ida-rpc open loader.bin --arch arm --loader miniloader --headless --detach
ida-rpc open image.itb --arch arm --loader "Rockchip U-Boot FIT image" --headless --detach
```

Known aliases:

| Alias | IDA loader string |
|-------|-------------------|
| `raw`, `binary`, `bin`, `dump` | `Binary file` |
| `miniloader`, `rk-miniloader`, `rockchip-miniloader` | `Rockchip MiniLoaderAll / LDR` |
| `uboot-fit`, `rk-uboot` | `Rockchip U-Boot FIT image` |
| `rkns` | `Rockchip RKNS IDB/SPL image` |

### Installing / Updating

```bash
# Production install via the IDA Plugin Manager
hcli plugin install ida-rpc

# Development install (after code changes, reinstall so the symlinked plugin sees updates)
pip install -e /path/to/ida-rpc

# Or use uv
uv pip install -e /path/to/ida-rpc
```

## Adding a New Command

1. **Pick or create a tools module** in `ida_rpc/server/tools/`. Group by semantic area.
2. **Write the handler function:**

```python
from ida_rpc.server.main import register_handler

def _handle_my_command(ctx, args: dict) -> dict:
    # ctx: IdaContext — provides resolve_address(), find_function(), run_on_main_thread()
    # args: dict of command arguments from the JSON request
    # Must return a dict (will be JSON-serialized)
    result = {"foo": "bar"}
    return result

register_handler("my_command", _handle_my_command)
```

3. **Import the module** in `ida_rpc/server/tools/__init__.py`:

```python
from ida_rpc.server.tools import my_module
```

4. **Add CLI passthrough** in `ida_rpc/cli.py`:

```python
@cli.command(name="my-command")
@click.argument("something")
@click.option("--project", "-p", type=str)
def my_command(something: str, project: str | None):
    _rpc_command(_resolve_project(project), "my_command", {
        "something": something,
    })
```

5. **Add tests** in `tests/test_cli_commands.py` and `tests/test_handler_registration.py`.

6. **Test it:**

```bash
ida-rpc start --project /tmp/test.i64 --arch arm --headless --detach
ida-rpc my-command some_value
```

## Thread Safety Rules (CRITICAL)

IDA Python APIs **must run on IDA's main thread**. Violating this causes:

```
RuntimeError: Function can be called from the main thread only
```

### Rules

1. **Read-only handlers** (e.g., `functions`, `decompile`) can run on any thread **if** they only use `idautils` / `ida_funcs` / `ida_bytes` in read mode. Most of these work fine without `run_on_main_thread`.
2. **Write handlers** (rename, comment, type changes, struct creation) **must** wrap their mutating work:

```python
def do_write():
    ida_name.set_name(addr, new_name)
    # ...

result = ctx.run_on_main_thread(do_write)
ctx.save()   # Persist the IDB after mutations
return result
```

3. **The server** already serializes all handler calls with `_HANDLER_LOCK`. This prevents concurrent mutation but does not solve the main-thread requirement.
4. **`ctx.run_on_main_thread()`** uses `ida_kernwin.execute_sync(MFF_WRITE)` when called from a background thread. In headless mode where the server runs on the main thread, it executes synchronously.

## IDA API Patterns

### Lazy Imports

Inside handlers, always import IDA modules lazily (they are not available outside IDA):

```python
def _ida():
    import ida_funcs, ida_name, idautils
    return ida_funcs, ida_name, idautils
```

### Resolving Addresses

Use `ctx.resolve_address(s)` for hex strings. Use `ctx.find_function(name)` for name resolution (exact match preferred, falls back to partial).

### Decompiler

Hex-Rays must be initialized per-handler:

```python
import ida_hexrays
if not ida_hexrays.init_hexrays_plugin():
    raise RuntimeError("Hex-Rays not available")
cfunc = ida_hexrays.decompile(func_ea)
```

### Type Parsing

Use `ida_typeinf.parse_decl()` + `ida_typeinf.apply_tinfo()` for signatures and data types.

### Segment Registers / Processor Context

For ARM T-mode and other processor context:

```python
import ida_bytes, ida_idp, ida_idaapi
# Get register number by name
regnum = ida_idp.ph.regnames.index("T")
# Read
val = ida_bytes.get_sreg(ea, regnum)
# Write range
ida_bytes.split_sreg_range(ea, regnum, value, ida_idaapi.SR_user)
```

### Assembler

The `assemble` command uses Keystone Engine. It is an optional dependency:

```python
# In the handler
from keystone import Ks, KsError
ks = Ks(arch, mode)
encoding, count = ks.asm(instruction, addr)
```

## Wire Protocol

Request (one JSON line, newline-terminated):

```json
{"id": "uuid", "cmd": "functions", "args": {"binary": "foo.i64", "limit": 10}}
```

Response (one JSON line):

```json
{"id": "uuid", "ok": true, "result": {"functions": [...], "count": 10}}
```

Error response:

```json
{"id": "uuid", "ok": false, "error": "ValueError", "message": "..."}
```

## Headless vs GUI Mode

| Mode | Executable | Plugin behavior |
|------|------------|-----------------|
| GUI | `ida` | Server spawns thread per connection, `run_on_main_thread` dispatches via `execute_sync` |
| Headless | `ida -A` | Server runs on main thread (`synchronous=True`), blocks IDA exit |

### Headless Launch

```bash
# Use ida (GUI binary) with -A. idat fails silently with "error code 2"
# when creating new databases in read-only directories on Linux.
ida -A -L/tmp/ida.log -S/path/to/ida-rpc/ida_rpc_plugin.py /path/to/binary
```

The plugin keeps IDA alive with a sleep loop after the server starts.

### Raw Binary Auto-Configuration

`--arch` is mandatory for `ida-rpc start/open`. The plugin uses it to auto-configure segments before auto-analysis:

| Arch | Segment class | Bitness | Perms |
|------|--------------|---------|-------|
| `arm` | `CODE32` | 1 (32-bit) | read + exec |
| `thumb` | `CODE16` | 1 (32-bit) | read + exec |
| `aarch64` / `arm64` | `CODE64` | 2 (64-bit) | read + exec |
| `metapc` / `x86` | `CODE` | 1 (32-bit) | read + exec |
| `x64` | `CODE64` | 2 (64-bit) | read + exec |

This is handled by `_configure_segments_for_arch()` in `ida_rpc_plugin.py`. The `arch` is stored in the `Session` object and persisted across restarts.

## Session & Socket Paths

- Socket path: `/tmp/ida-rpc-<hash>.sock` where hash = SHA256(IDB path)[:8]
- Session file: `.ida-rpc-<hash>.json` next to the IDB (or `$IDA_RPC_STATE_DIR/<hash>.json`)
- CLI resolves project via `--project` flag or `IDA_RPC_PROJECT` env var

## Testing

Run all tests:

```bash
pytest tests/ -v
```

### Test Files

| File | What it tests |
|------|---------------|
| `test_client.py` | Socket client, session persistence, timeout derivation |
| `test_protocol.py` | Wire protocol, server dispatch, ping/stop/invalid JSON |
| `test_cli_commands.py` | All CLI commands exist, parse args correctly, build right RPC payloads |
| `test_handler_registration.py` | All server handlers are registered, no duplicates |
| `test_tools.py` | Integration tests (require IDA Pro — skipped by default) |

### Adding Tests for a New Command

1. Add to `test_cli_commands.py` — `TestCliCommandsExist` parametrized list and `TestCliRpcCommands` parametrized list.
2. Add to `test_handler_registration.py` — `_EXPECTED_HANDLERS` set.

### Manual Testing Checklist

After adding or changing a command:

1. Reinstall: `pip install -e .`
2. Run unit tests: `pytest tests/ -v`
3. Start headless daemon: `ida-rpc start --project /tmp/test.i64 --arch arm --headless --detach`
4. Run the command via CLI and verify JSON output
5. Check `ida-rpc status --project /tmp/test.i64`
6. Stop: `ida-rpc stop --project /tmp/test.i64` (or `ida-rpc stop --all` to close every open project at once)

## Common Pitfalls

- **Forgot `ctx.save()` after mutations** — changes are lost when IDA exits.
- **Calling IDA APIs outside `run_on_main_thread`** in write handlers — crashes or `RuntimeError`.
- **Not importing IDA modules lazily** — `ImportError` when CLI client imports the module.
- **Hex-Rays not initialized** — `decompile` fails with cryptic errors.
- **Symlink broken** — if you move the repo, recreate the symlink in IDA's plugins dir.
- **Keystone not installed** — `assemble` command fails; install with `pip install keystone-engine`.
- **Missing `register_handler` call** — handler exists but is never dispatched because `register_handler()` was forgotten.
- **Missing module import in `__init__.py`** — module loads fine but `register_all_tools()` never imports it.
- **Missing CLI command** — handler works via raw JSON-RPC but has no `ida-rpc` subcommand.
