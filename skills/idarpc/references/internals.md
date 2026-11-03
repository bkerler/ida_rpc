# Implementation internals

Read this when investigating transport, concurrency, session persistence, protocol compatibility, or an ida-rpc implementation bug. Everyday reverse engineering should not load it.

Adapted from upstream [implementation internals](https://github.com/bkerler/ida_rpc/blob/main/docs/internals.md).

## Architecture

- The CLI sends one newline-delimited JSON request over a local endpoint and reads one response.
- Linux and macOS normally use Unix domain sockets; Windows uses loopback TCP with an OS-assigned port published in the project marker.
- One daemon hosts one IDA process and one IDB.
- Session JSON records the project, mode, endpoint, and optional IDA installation path so restart and auto-restart can reconstruct the daemon.

## Concurrency

Connections can arrive concurrently, but command handlers are protected by a global lock. Headless mode drains requests on IDA's main thread; GUI mode dispatches IDA work through `execute_sync`. Hex-Rays also uses a global decompiler instance.

Consequences:

- Parallel clients against one daemon queue rather than accelerate decompilation.
- Use separate IDBs and daemon processes for real parallel read-only work.
- Never point multiple daemons at the same writable IDB.
- Batch commands reduce transport round trips, not handler serialization.

## Startup and persistence

Detached startup saves session state, launches IDA with its `-L` log switch, and polls the endpoint until responsive or until IDA exits. GUI cold starts can take substantially longer than headless starts. Each launch writes separate IDA and launch logs under `ida_rpc/logs` or a temporary fallback directory; use the exact paths returned by startup errors.

IDA saves directly to `.i64`/`.idb`. Mutation handlers normally call the save routine after committing. A crash can still lose an in-flight change, so verify and save logical batches.

## Analysis invariants

- IDA APIs that require the main thread must be routed through the context dispatcher.
- Hex-Rays must be initialized before decompilation handlers use it.
- Auto-analysis should finish before the server becomes ready.
- Address targets and function-name targets use different resolution paths; ambiguous partial names should be replaced by exact addresses.
- Bookmarks and tags may be stored in netnodes and persist with the IDB.

## Protocol

Successful responses have `id`, `ok: true`, and `result`. Errors have `id`, `ok: false`, `error`, and `message`. The design is broadly compatible with ghidra-rpc, but backend-specific commands and argument conventions differ; inspect live capabilities rather than assuming parity.

When adding or fixing handlers, add a regression test and reinstall only when the user asked to maintain ida-rpc itself.
