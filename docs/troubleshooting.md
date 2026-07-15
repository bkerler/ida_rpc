# Troubleshooting

## IDA_INSTALL_DIR Not Found

**Symptom**: Daemon fails to start with "IDA executable not found"

**Fix**: Set the environment variable to your IDA Pro installation:
```bash
export IDA_INSTALL_DIR=/opt/ida-pro-9.4
```
This must be set in the terminal where the daemon runs, or pass `--ida-install-dir`.

## Hex-Rays Not Available

**Symptom**: `decompile` fails with "Hex-Rays decompiler is not available"

**Fix**: Hex-Rays is a separate license from IDA Pro. Ensure it is installed and
activated in your IDA installation.

## Keystone Not Available

**Symptom**: `assemble` fails with "Keystone engine is not installed"

**Fix**: Install the optional Keystone dependency:
```bash
pip install keystone-engine
```

## Stale Socket File

**Symptom**: "Address already in use" or daemon won't start, but `status` shows not running.

**Fix**: Remove the stale socket file:
```bash
# Find the socket path
ida-rpc status --project /path/to/binary.i64
# Remove it
rm /tmp/ida-rpc-XXXXXXXX.sock
# Start again
ida-rpc start --project /path/to/binary.i64 --arch <arch> --headless
```

The daemon normally cleans up its socket on shutdown, but if it's killed (SIGKILL, power
loss), the socket file may remain.

## Project Already Running

**Symptom**: `ida-rpc start` fails with `AlreadyRunning`.

**Cause**: The project already has a responsive ida-rpc daemon. `start` refuses
to launch a second IDA instance for the same IDB/socket.

**Fix**: Reuse the running daemon or stop it first:

```bash
ida-rpc status --project /path/to/binary.i64
ida-rpc stop --project /path/to/binary.i64
ida-rpc start --project /path/to/binary.i64 --arch <arch> --headless --detach
```

## Stale Database Files

**Symptom**: Daemon times out with `StartTimeout`. Log shows:
```
Failed to initialize IDA as library (error code 4)
Check ida.log!
```

**Cause**: Previous unclean shutdowns leave stale companion files
(`.id0`, `.id1`, `.id2`, `.nam`, `.til`) that IDA cannot open.

**Fix** — use the `--clean` flag:
```bash
ida-rpc start --project /path/to/binary.i64 --arch <arch> --headless --detach --clean
```

Or manually remove the stale files:
```bash
rm /path/to/binary.id0 /path/to/binary.id1 /path/to/binary.id2 /path/to/binary.nam /path/to/binary.til
```

## Raw Binary Import Times Out

**Symptom**: `ida-rpc start raw.bin --arch ... --base ... --headless --detach`
times out, and the log only shows the IDA launch command with no Python traceback.

**Cause**: IDA may be waiting for loader selection, or the wrong loader was forced.

**Fix**: List loaders and force one explicitly:

```bash
ida-rpc list-loaders raw.bin
ida-rpc start raw.bin --arch arm --base 0x8000 --loader raw --headless --detach --clean
```

For custom loaders, use the alias or exact IDA loader string:

```bash
ida-rpc start loader.bin --arch arm --loader miniloader --headless --detach --clean
ida-rpc start image.itb --arch arm --loader "Rockchip U-Boot FIT image" --headless --detach --clean
```

`--base` is a byte address in the ida-rpc CLI. For example, `--base 0x03000000`
is converted to IDA's paragraph form `-b300000` internally.

For AArch64 raw binaries, use `--arch aarch64` or `--arch arm64`; ida-rpc passes
IDA's internal ARM processor module (`-parm`) and configures the database as
64-bit before auto-analysis.

## Loader Not Listed

**Symptom**: `ida-rpc list-loaders` does not show a custom loader.

**Cause**: The loader is not in a directory scanned by ida-rpc.

**Fix**: Place Python loaders under one of:

```bash
$IDA_INSTALL_DIR/loaders
~/.idapro/loaders
~/.idapro/Loaders
```

Then rerun:

```bash
ida-rpc list-loaders /path/to/binary --ida-install-dir /path/to/ida
```

## GUI Restart Reports Timeout (or `ok: true` With Warning)

**Symptom**: `ida-rpc restart` in GUI mode returns a response with a `warning` field
instead of a clean `{"status": "restarted"}`.

**Cause**: GUI startup (IDA boot + project open) routinely takes 30–90 s or more on a
cold machine.

**Fix**: `restart` now defaults to **180 s** in GUI mode. If the socket becomes responsive
within that window you get `{"ok": true, "status": "restarted"}`. If the daemon starts
listening but has not yet responded to a ping within 180 s, you get a warning. The daemon
**is** running — simply retry your first command in a few seconds.

**Override the timeout** if your machine is especially slow:
```bash
ida-rpc restart --project /tmp/re.i64 --timeout 300
```

## Connection Timeout

**Symptom**: Commands hang for 2 minutes then fail.

**Cause**: The daemon is processing a heavy operation (large binary analysis, decompilation
of a very complex function).

**Fix**: Wait for the operation to complete. For decompilation of complex functions,
increase `--timeout`. Check the daemon's stderr log for progress:
```bash
tail -f /tmp/ida-rpc-*.log
```

## "Function not found" Errors

**Symptom**: Commands fail with "Function 'foo' not found" even though the name appears
in the functions list.

**Cause**: IDA function names are case-sensitive in some contexts. Also, auto-generated
names like `sub_401000` may have been renamed by a previous command.

**Fix**: Use `ida-rpc functions` to list current names. Use partial matching —
`ida-rpc decompile parse` will match `parse_arguments` if it's unambiguous.
Use hex addresses (`0x401000`) as a fallback.

## Changes Lost After Stop

**Symptom**: Applied renames/comments but they are gone after restarting IDA.

**Cause**: The IDB was not saved. Most write handlers auto-save, but if the daemon
crashes or is killed with SIGKILL, in-flight changes may be lost.

**Fix**: Always run `ida-rpc save` after batch operations. Check that the IDB file
timestamp updates after writes.

## Plugin Not Loading in IDA

**Symptom**: IDA starts but the RPC server doesn't appear in the log.

**Fix**:
1. Verify the plugin is in IDA's plugins directory:
   ```bash
   ls /path/to/ida-pro/plugins/ida_rpc_plugin.py
   ```
2. Check IDA's output window for Python errors.
3. Ensure `pip install -e /path/to/ida-rpc` was run so imports resolve.
4. Try copying instead of symlinking (some systems have symlink restrictions).

## Headless Mode Exits Immediately

**Symptom**: `idat -A -Sida_rpc_plugin.py /path/to/binary` exits immediately.

**Cause**: The plugin might be erroring out before starting the server, or the server
thread is dying.

**Fix**: Check the log file (`-L/tmp/ida.log`) for Python tracebacks. Ensure the
plugin file is readable and the `ida_rpc` package is importable from IDA's Python.

## `RuntimeError: Function can be called from the main thread only`

**Symptom**: Commands return this error when the server is running in GUI mode.

**Cause**: An IDA API was called from a background thread without going through
`ida_kernwin.execute_sync()`.

**Fix**: This is an internal bug — the handler forgot `ctx.run_on_main_thread()`.
File an issue or patch the handler in `ida_rpc/server/tools/`.

## macOS Issues

**Symptom**: GUI mode has display or rendering problems on macOS.

**Fix**: IDA on macOS uses its own Qt framework. Ensure you are running the native
macOS IDA binary, not a Linux binary under emulation. For automation, headless mode
is more reliable on macOS.

## `restart` Fails with "NoSession"

**Symptom**: `ida-rpc restart` fails with
`"No saved session for /path. Use 'ida-rpc start <binary> --arch <arch>' first."`

**Cause**: `restart` needs a saved session (created by a previous `start`) to know
which mode (GUI / headless) to use.

**Fix**: Pass `--headless` to `restart` so it can create a fresh headless session
without requiring a prior start:
```bash
ida-rpc restart --project /tmp/re.i64 --headless
```

## Batch Commands Fail with JSON Errors

**Symptom**: `batch-rename`, `batch-set-comment`, or `batch` fails with a JSON parsing error.

**Fix**: Ensure the JSON file uses the expected shape.

For `batch-rename` / `batch-set-comment`, provide a list of operation objects:
```json
[
  {"target": "sub_401000", "new_name": "foo"},
  {"target": "sub_401010", "new_name": "bar"}
]
```

For the generic `batch` command, provide a list of command objects (or an object
with a `"commands"` key):
```json
[
  {"cmd": "rename_function", "args": {"target": "sub_401000", "new_name": "foo"}},
  {"cmd": "set_comment", "args": {"address": "0x401000", "comment": "note"}}
]
```

## Processor Context Register Not Found

**Symptom**: `get-processor-context` or `set-processor-context` fails with "Unknown register".

**Cause**: The register name does not exist in the current processor's segment register list.

**Fix**: Use `ida-rpc get-processor-context` without `--register` to see available registers
for the current processor.
