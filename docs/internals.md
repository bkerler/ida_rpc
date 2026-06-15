# ida-rpc — Implementation Internals

Read this when you are **adding new commands, debugging IDA API issues, or working
on the daemon internals**. For everyday RE workflows, `SKILL.md` is enough.

## Session Persistence

Session files are JSON blobs that let `restart` and `send_request_with_auto_restart`
recreate the daemon without the user having to pass `--mode` / `--headless` again.

**File location** (resolution order):
1. `$IDA_RPC_STATE_DIR/<hash>.json` — if the env var is set
2. `<idb-parent>/.ida-rpc-<hash>.json` — alongside the IDB file (default)
3. Backward compat: `~/.local/share/ida-rpc/<hash>.json` — checked by `load()` only

**Fields stored**: `mode`, `project_idb`, `socket_path`, `ida_install_dir`
(`ida_install_dir` is `null` when not explicitly provided).

**`IDA_INSTALL_DIR` propagation**: `start_background()` builds the subprocess env
from `session.ida_install_dir` → current `IDA_INSTALL_DIR` → nothing, in that
order. This ensures the daemon child gets the right env var even when launched from
cron/systemd/nohup contexts that strip non-standard env vars.

## Background Start & Logs

`start_background()` in `daemon.py`:
1. Saves the session file.
2. Spawns `idat -A <idb>` (headless) or `ida <idb>` (GUI) with `start_new_session=True`
   so the child survives the parent's exit. New raw imports pass `-o<idb>` and
   any requested loader/processor arguments before the input binary.
3. Polls the socket (0.5 s interval) until it's responsive or the timeout expires.
4. On timeout the error message includes the log file path.

Log file: `/tmp/ida-rpc-<hash>.log` (same stem as the socket). On timeout:
```bash
tail -50 /tmp/ida-rpc-*.log
```

## Loader Discovery and Selection

`list-loaders` is a local CLI command and does not require a running daemon. It
combines three data sources:

1. Loader aliases defined in `ida_rpc.cli.LOADER_ALIASES`.
2. Installed loader modules from `$IDA_INSTALL_DIR/loaders`, `~/.idapro/loaders`,
   and `~/.idapro/Loaders`.
3. Cheap file-specific candidates from `_detect_loader_candidates()`.

`start/open --loader` accepts either an alias or the exact IDA loader string.
Aliases are resolved before command construction and passed to IDA as `-T<loader>`.
If no explicit loader is provided and a new raw import includes `--arch`,
`daemon.start_background()` adds `-TBinary file` to avoid IDA waiting for loader
selection.

`--base` is a byte address in the ida-rpc CLI. `cli.start()` converts it to
IDA's `-b` paragraph units before spawning IDA.

IDA's AArch64 processor lives in the ARM processor module. The CLI preserves the
session architecture as `aarch64` / `arm64`, but passes `-parm` to IDA and lets
the plugin set 64-bit ARM database flags before analysis.

## Analysis Control

In IDA, auto-analysis runs automatically when a binary is opened. When a saved
session has an architecture, the plugin first applies raw-binary segment class,
bitness, and ARM64 database flags, then waits for analysis to complete
(`ida_auto.auto_wait()`) before starting the RPC server.

The `load` RPC response always includes `"analysis_complete": bool`.

## Known Implementation Gotchas

### 1. Thread safety — main thread only
IDA Python APIs must run on IDA's main thread. `IdaContext.run_on_main_thread()`
uses `ida_kernwin.execute_sync(MFF_WRITE)` when called from a background thread.
In headless mode the server runs synchronously on the main thread, so this is a no-op.

### 2. Hex-Rays initialization
The decompiler must be initialized per-handler with `ida_hexrays.init_hexrays_plugin()`.
This is a no-op if already initialized, so it's safe to call repeatedly.

### 3. Saving the IDB
Unlike Ghidra's project model, IDA saves directly to the `.i64` / `.idb` file.
`ctx.save()` calls `ida_loader.save_database(None, 0)`. All write handlers call
`ctx.save()` after mutation to persist changes.

### 4. Single-IDB limitation
IDA can only have one database open per process. The `binary` argument in commands
is accepted for protocol compatibility with ghidra-rpc but is effectively ignored.

### 5. Headless mode keeps IDA alive
`idat -A` auto-exits after the `-S` script completes unless the script blocks. The
plugin blocks the main thread with a sleep loop after the server starts, keeping IDA
alive for RPC connections.

### 6. Address resolution
`ctx.resolve_address()` parses hex strings. `ctx.find_function()` resolves by exact
or partial name match. Use `ctx.find_function()` for function targets and
`ctx.resolve_address()` for raw addresses.

### 7. Decompiler global lock
Hex-Rays uses a global decompiler instance. No pool is needed — just ensure all
decompiler calls are serialized (the `_HANDLER_LOCK` already does this).

### 8. GUI restart timeout
IDA GUI startup regularly takes 30–90 s on cold hardware. `restart` defaults to
**180 s** in GUI mode. The CLI returns `ok: true` with a `"warning"` field when the
daemon starts but doesn't become ping-responsive within the timeout.

### 9. Type parsing with `ida_typeinf`
IDA 9.x uses `ida_typeinf.parse_decl()` + `ida_typeinf.apply_tinfo()` for signatures
and data types. The older `ida_struct` API is used for struct creation but type
application goes through `ida_typeinf`.

### 10. Netnode-based features
Bookmarks and function tags are emulated using IDA netnodes (`ida_netnode.netnode`)
because IDA does not have native equivalents for all ghidra-rpc features. These are
stored in the IDB and survive saves.

### 11. Segment register changes
Processor context (e.g., ARM T-bit) is managed via `ida_bytes.split_sreg_range()`.
This is processor-specific — not all processors use segment registers for mode switching.

### 12. Assembler dependency
The `assemble` command requires **Keystone Engine** (`pip install keystone-engine`).
It is an optional dependency. If Keystone is not installed, the command returns a
clear error message.

### 13. Tooling bugs during RE
When an ida-rpc bug blocks an analysis task, fix ida-rpc first, add a regression
test, reinstall the package when the installed CLI is used, then resume analysis.
This keeps target-specific RE work from accumulating local workarounds.

## IDA API Quick Reference

| Module | Contents |
|--------|----------|
| `ida_ida` / `ida_idaapi` | Core constants, `BADADDR`, `inf_get_procname()` |
| `ida_loader` | `get_path()`, `save_database()` |
| `ida_funcs` | `get_func()`, `add_func()`, `del_func()`, `get_func_name()`, `set_func_flags()` |
| `ida_name` | `set_name()`, `get_name()`, `get_name_ea()` |
| `ida_bytes` | `get_bytes()`, `patch_byte()`, `get_flags()`, `is_code()`, `split_sreg_range()` |
| `ida_segment` | `getseg()`, `get_segm_name()`, `add_segm()`, `del_segm()` |
| `ida_typeinf` | `tinfo_t`, `parse_decl()`, `apply_tinfo()` |
| `ida_struct` | `add_struc()`, `get_struc()`, `add_struc_member()`, `set_member_name()`, `set_member_tinfo()`, `del_struc_member()` |
| `ida_enum` | `add_enum()`, `add_enum_member()`, `del_enum_member()`, `get_enum_name()` |
| `ida_hexrays` | `init_hexrays_plugin()`, `decompile()` |
| `ida_gdl` | `FlowChart` — basic block iteration |
| `ida_xref` | Cross-reference flags |
| `ida_search` / `ida_bytes` | `find_bytes()` |
| `ida_nalt` | String types, import enumeration |
| `ida_entry` | Export enumeration |
| `ida_netnode` | Persistent storage in IDB (netnodes) |
| `ida_kernwin` | `execute_sync()`, `jumpto()`, `is_idaq()` |
| `ida_auto` | `auto_wait()` |
| `ida_fixup` | `get_fixup()`, `get_next_fixup_ea()` |
| `idautils` | `Functions()`, `Heads()`, `CodeRefsTo()`, `Strings()`, `Names()`, `Segments()` |

## Reference Project: ghidra-rpc

The wire format and CLI design are based on [ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc).
Consult it when working on protocol compatibility or multi-backend clients.

## Feature Parity Notes

Commands that map closely to Ghidra:
- All analysis/listing commands (`functions`, `imports`, `exports`, `metadata`, `strings`, `symbols`, `find_bytes`)
- All modification commands (`rename_function`, `set_comment`, `set_function_signature`, `set_data_type`, `create_function`)
- Data type commands (`create_struct`, `create_union`, `create_enum`, `list_data_types`)
- Cross-references (`xrefs_to`, `xrefs_from`)

IDA-specific additions (no Ghidra equivalent):
- `list-loaders` / `--loader` — loader discovery and forced IDA loader selection
- `relocations` — IDA fixup table
- `calling_conventions` / `list_calling_conventions` — processor-specific conventions
- `get_processor_context` / `set_processor_context` — segment register control
- `assemble` — Keystone-based assembly patching
- `decompile_all` — bulk decompilation
- `delete_function`, `set_thunk`, `set_calling_convention` — function metadata
- `modify_struct`, `modify_enum`, `clear_data_range`, `apply_data_type_range` — data type authoring
- `set_equate`, `list_equates` — enum operand attachment
- `add_segment`, `edit_segment`, `delete_segment` — segment management

Ghidra-specific commands not ported (no IDA equivalent):
- `pcode` — Ghidra's intermediate representation
- `version_track`, `function_diff`, `match_function` — multi-binary correlation
