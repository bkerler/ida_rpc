# Setup and lifecycle

Read this for installation requests, first use, project selection, and daemon lifecycle. For an already working installation, skip directly to the core workflow in `SKILL.md`.

Adapted from upstream [install](https://github.com/bkerler/ida_rpc/blob/main/docs/install.md) and [quick start](https://github.com/bkerler/ida_rpc/blob/main/docs/quickstart.md) documentation.

## Prerequisites

- IDA Pro 9.0 or newer and a valid license.
- Hex-Rays is optional for disassembly but required for decompilation and microcode.
- The `ida-rpc` CLI and IDA plugin must both be installed.
- `IDA_INSTALL_DIR` may point to the directory containing `ida`/`idat`; `--ida-install-dir` can override it per start.

Do not install or upgrade dependencies merely because a task uses this skill. Installation is in scope only when the user asks for setup or the declared prerequisite is missing.

## Live discovery

Use the installed CLI as the source of truth:

```text
ida-rpc --version
ida-rpc --json capabilities
ida-rpc --json find-project <absolute-binary-or-idb>
ida-rpc list-loaders <absolute-binary>
ida-rpc <subcommand> --help
```

`find-project` returns the recommended IDB path, endpoint, session state, and a recommended start command. Prefer that command over inventing flags.

## Starting

- For a recognized PE or ELF, the file header normally supplies architecture information.
- For raw inputs, explicitly provide architecture, base, and loader.
- For automation, use detached headless mode; use GUI mode only when the task requires IDA UI context.
- For a system binary or read-only input location, choose an explicit writable IDB path.

After starting, run `status --project <idb>` and cross-check the loaded binary, processor, bitness, endianness, format, and image base.

## Session use

Pass `--project <idb>` on every command or set `IDA_RPC_PROJECT` in a stable caller environment. Do not rely on a shell-local variable that another process cannot see.

Commands open one connection per request. The daemon may auto-restart from session state, but do not treat auto-restart as proof that the expected binary was loaded; re-run `status`.

## Saving and stopping

Most writes auto-save, but explicit `save` after a verified logical batch is safer. Read-only work should not save merely to update timestamps.

If the task started the daemon:

```text
ida-rpc --json stop --project <idb>
ida-rpc --json status --project <idb>
```

Verify `running: false` before reporting completion.
