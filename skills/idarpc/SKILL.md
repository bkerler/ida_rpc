---
name: idarpc
description: Analyze and, when explicitly authorized, modify binaries or IDA databases through ida-rpc, including decompilation, cross-references, types, patches, firmware loading, and debugger control. Use for IDA Pro RPC workflows; do not use for IDASQL- or Ghidra-specific requests.
---

# IDA RPC

Use `ida-rpc` as a structured local interface to one IDA database per daemon. Prefer the live CLI over remembered syntax because installed versions can differ from upstream documentation.

## Non-negotiable rules

- `ida-rpc` is already installed and available on `PATH`. Do not install, upgrade, relocate, or patch it unless the user explicitly requests tool maintenance.
- Resolve the target binary or IDB to an absolute path before starting a daemon.
- Use `--json` before the subcommand when output will be parsed or compared by an agent.
- Start with `capabilities`, `find-project`, and, for ambiguous or raw inputs, `list-loaders`.
- Treat the complete `capabilities` and `<command> --help` output as interface contracts. Do not truncate them before confirming a command and its arguments, and never invent a command, flag, or JSON key by analogy.
- Keep JSON stdout separate from diagnostic stderr. Do not pipe `2>&1` into a JSON parser. Inspect one raw response before extracting fields, check `ok`, and preserve `error` plus `message` on failure.
- Reuse one responsive daemon for a project. IDA opens one IDB per process; never start two daemons against the same IDB.
- Treat inspection, explanation, triage, comparison, and audit requests as read-only. Rename, retype, comment, patch, create, delete, debug, or save only when the requested outcome authorizes it.
- Before a mutation, read the exact target. After it, re-read the result and save once per logical batch when persistence is required.
- Bound large listings with `--limit`, `--offset`, address ranges, or function filters. Prefer addresses when a name is ambiguous.
- A daemon can accept multiple client connections, but handler execution and Hex-Rays work are serialized. Use separate IDBs and daemons for real parallelism.
- If this task started the daemon, stop it before finishing, including after recoverable failures.

## Minimal workflow

1. Probe the installed interface:

   ```text
   ida-rpc --json capabilities
   ida-rpc --json find-project <absolute-binary-or-idb>
   ```

2. Use the returned project path and recommended start command. For raw or ambiguous files, run `list-loaders` before `open`.
3. Verify `status` and confirm the loaded path, processor, bitness, format, and image base.
4. Orient cheaply with `metadata`, bounded `functions`, `imports`, `exports`, and targeted `strings`.
5. Narrow candidates with `symbols`, `xrefs-to`, and `xrefs-from`; decompile or disassemble only selected functions.
6. For authorized edits, mutate narrowly, verify, then `save` once for the batch.
7. Stop the daemon if this task started it.

## Reference router

Read only the first reference that matches the current task. Load another only when the work crosses into that topic.

| Task | Reference |
|---|---|
| Installation, first launch, project resolution, start/stop lifecycle | [setup and lifecycle](references/setup-and-lifecycle.md) |
| Ordinary static analysis, decompilation, xrefs, graphs, strings, bytes | [static analysis](references/static-analysis.md) |
| Authorized renames, comments, types, frames, segments, patches, batches | [editing and types](references/editing-and-types.md) |
| Raw firmware, custom loaders, base discovery, ARM/Thumb context | [firmware and loaders](references/firmware-and-loaders.md) |
| Process debugging, breakpoints, registers, runtime memory | [debugger](references/debugger.md) |
| Transport, sessions, threading, serialization, protocol, new handlers | [internals](references/internals.md) |
| Startup, socket, IDB, Hex-Rays, timeout, or handler failures | [troubleshooting](references/troubleshooting.md) |
| Broad behavior inventory of one binary | [binary audit workflow](references/flows/binary-audit.md) |
| Authorized vulnerability investigation | [vulnerability research workflow](references/flows/vulnerability-research.md) |
| Compare old and new binary versions | [patch analysis workflow](references/flows/patch-analysis.md) |

## Output expectations

- Answer the user's question first and include only evidence needed to verify it.
- Preserve exact addresses, names, bytes, command errors, and tool version.
- Separate observed facts from inference.
- State whether the target binary or IDB was changed and whether changes were saved.
- Distinguish IDB creation and automatic analysis from analyst-authored changes such as renames, types, comments, or patches.
- When the user requests a process log, include the normalized command sequence, selected raw JSON evidence and errors, and the final debugger and daemon state.
- Never claim runtime debugging, GUI focus, or a successful mutation without reading back evidence.
