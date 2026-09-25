# Debugger control

Read this only for an explicit dynamic-debugging request. Starting, attaching to, controlling, or writing memory in a process is a runtime side effect and is not implied by static analysis.

The upstream README lists debugger commands, while the installed CLI remains the source of truth. Probe each required command with `--help` before starting a process.

## Command groups

| Need | Commands |
|---|---|
| Backend | `debug-select-backend`; `debug-start`/`debug-attach` with `--backend` and `--remote`/`--local` |
| Lifecycle | `debug-start`, `debug-attach`, `debug-detach`, `debug-exit` |
| Execution | `debug-continue`, `debug-suspend`, `debug-step-into`, `debug-step-over`, `debug-run-to` |
| State | `debug-status`, `debug-threads`, `debug-modules`, `debug-stack-trace` |
| Registers | `debug-get-registers [--register NAME]`, `debug-set-register` |
| Runtime memory | `debug-read-memory`, `debug-write-memory` |
| Breakpoints | `debug-breakpoints`, `debug-add-breakpoint`, `debug-delete-breakpoint`, `debug-enable-breakpoint` |

## Safe workflow

1. Confirm the executable path, arguments, working directory, backend, and whether launching or attaching is authorized.
2. Select the backend separately with `debug-select-backend`, or atomically with `debug-start --backend <name>` or `debug-attach --backend <name>`.
3. Start or attach and require a successful response with `debugger_on: true` and `state: suspended`. The start command defaults to a process-start breakpoint; use `--suspend-at entry` when the program entry is the intended first stop.
4. Resolve the current runtime address after startup, then add a breakpoint at an exact address. Record the module base, RVA, and runtime address as separate values (`runtime address = module base + RVA`); do not label a function address as the module base or reuse a preferred image-base address after ASLR rebasing without checking it.
5. Continue, step, or run-to. These commands wait for suspension or process exit by default; use a bounded `--wait-timeout` appropriate to the target.
6. At a stop, read named registers with repeated `--register` options and corroborate the instruction pointer with the stack trace and expected function address.
7. Remove temporary breakpoints and detach or exit as requested.
8. Stop the ida-rpc daemon if this task started it.

## Backend selection

Backend values are IDA debugger plugin identifiers, not display labels. For example, the local Windows debugger uses `win32`. Pass `--remote` only together with an explicit backend.

For a headless workflow, start the ida-rpc daemon with `open --detach`; manually opening the program in the IDA GUI is not required. Backend selection and process startup still occur inside the IDA process through RPC.

Older installed builds may lack `debug-select-backend` and the `--backend` options. Probe the live CLI before debugging. Treat `debugger_on` as authoritative, and do not claim end-to-end debugging until a real process has stopped at an expected address. Do not use GUI automation unless the user asks for it.

## Runtime writes

`debug-set-register` and `debug-write-memory` change live process state. Read the current value first, make the smallest requested change, read it back, and report the effect. These commands do not replace IDB patch commands.

`debug-read-memory` reads the live process, while `read-bytes` reads the IDB. Do not substitute one for the other when runtime state matters. A SWIG `TypeError` mentioning `read_dbg_memory` and `void *` identifies an older handler that passed a Python buffer to IDA's low-level API; record it as a tool compatibility defect rather than retrying address variants. Upgrade or patch the tool only when maintenance is authorized.
