# Debugger control

Read this only for an explicit dynamic-debugging request. Starting, attaching to, controlling, or writing memory in a process is a runtime side effect and is not implied by static analysis.

The upstream README lists debugger commands, while the installed CLI remains the source of truth. Probe each required command with `--help` before starting a process.

## Command groups

| Need | Commands |
|---|---|
| Lifecycle | `debug-start`, `debug-attach`, `debug-detach`, `debug-exit` |
| Execution | `debug-continue`, `debug-suspend`, `debug-step-into`, `debug-step-over`, `debug-run-to` |
| State | `debug-status`, `debug-threads`, `debug-modules`, `debug-stack-trace` |
| Registers | `debug-get-registers`, `debug-set-register` |
| Runtime memory | `debug-read-memory`, `debug-write-memory` |
| Breakpoints | `debug-breakpoints`, `debug-add-breakpoint`, `debug-delete-breakpoint`, `debug-enable-breakpoint` |

## Safe workflow

1. Confirm the executable path, arguments, working directory, and whether launching or attaching is authorized.
2. Start or attach, then poll `debug-status` until `debugger_on` is true and the state is suitable for the next action.
3. Add a breakpoint at an exact module-relative or rebased runtime address.
4. Continue or run-to; verify suspension before reading registers, memory, or stack.
5. After each step command, poll status again. Debugger APIs can be asynchronous.
6. Remove temporary breakpoints and detach or exit as requested.
7. Stop the ida-rpc daemon if this task started it.

## Known activation gap

Some ida-rpc builds expose `debug-start` but not a command that calls IDA's `ida_dbg.load_debugger()` to select the local backend. In that state:

- `debug-start` can return `started: -1`;
- `debug-status` can show `debugger_on: false` even if `state` appears to be `running`;
- breakpoints, registers, modules, and stack commands fail with `Debugger is not active`.

Treat `debugger_on` as authoritative. Do not claim CLI-driven debugging works end to end until a process is actually active. Do not use GUI automation unless the user asks for it. If the installed build lacks backend activation, report the missing capability rather than patching the tool or using another interface without permission.

## Runtime writes

`debug-set-register` and `debug-write-memory` change live process state. Read the current value first, make the smallest requested change, read it back, and report the effect. These commands do not replace IDB patch commands.
