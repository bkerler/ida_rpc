# Troubleshooting

Read this only after a concrete ida-rpc failure. Start with the narrow symptom; do not apply every recovery action.

Adapted from upstream [troubleshooting](https://github.com/bkerler/ida_rpc/blob/main/docs/troubleshooting.md).

## Startup failures

| Symptom | First checks |
|---|---|
| IDA executable not found | command resolution, `IDA_INSTALL_DIR`, `--ida-install-dir` |
| `AlreadyRunning` | Reuse the responsive daemon or stop it normally |
| `StartTimeout` | Read the exact daemon log path from the error; confirm IDA process and loader state |
| Stale endpoint | Run `status`; use normal `stop`; remove only the exact stale marker after verifying no process owns it |
| `NoSession` on restart | Use a fresh `open`/`start` with explicit project and architecture |
| GUI timeout warning | Wait briefly and retry `status`; GUI startup may exceed the initial poll window |

`--clean` can remove IDA companion files. Treat it as destructive recovery: resolve the exact project, ensure no daemon is running, preserve the only valuable database, and use it only when the user authorized cleanup or recreation.

## Load and analysis failures

- For raw or ambiguous files, run `list-loaders` and force the intended loader rather than retrying blindly.
- Confirm `--base` is a byte address and architecture matches the target.
- If a custom loader is absent, inspect configured loader directories; do not copy or install one unless requested.
- If analysis appears incomplete, inspect `status`, logs, function count, segments, and entry points before concluding the binary has no code.

## Command failures

| Error | Response |
|---|---|
| Hex-Rays unavailable | Continue with disassembly, CFG, xrefs, and bytes; report the missing decompiler |
| Keystone unavailable | Do not install automatically; report that `assemble` needs the optional dependency |
| Function not found | Refresh names, use exact case, then exact address |
| Ambiguous function | Use the address returned in the candidates |
| Main-thread error | Treat as an ida-rpc handler bug; do not repeat the same call indefinitely |
| Heavy operation timeout | Narrow the target or raise the command timeout once with a justified bound |
| Batch JSON error | Validate UTF-8 JSON shape and command names before retrying |

## Persistence failures

After an authorized edit, read back the value and run `save` once. Verify the response and, when relevant, the IDB timestamp. Do not infer persistence solely from a successful mutation response after a daemon crash.

## Debugger failures

If `debug-start` returns `started: -1`, read [debugger](debugger.md). Check `debugger_on`; the installed build may lack a command to load the backend.

## Stopping

Always attempt normal `stop`. After failure, verify `status`. Do not kill unrelated IDA processes or delete broad temporary directories.
