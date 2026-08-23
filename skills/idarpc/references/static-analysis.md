# Static analysis

Read this for normal binary inspection. It intentionally omits mutations, firmware import, debugger control, and implementation internals.

The command sequence is derived from the upstream [quick start](https://github.com/bkerler/ida_rpc/blob/main/docs/quickstart.md) and [binary audit workflow](https://github.com/bkerler/ida_rpc/blob/main/docs/flows/binary-audit.md).

## Funnel

1. Confirm identity with `status` and `metadata`.
2. Inventory behavior cheaply with bounded `functions`, `imports`, `exports`, `relocations`, and targeted `strings`.
3. Resolve candidates with `symbols`, `function`, `function-info`, or an exact address.
4. Map relationships with `xrefs-to`, `xrefs-from`, `decompiler-xrefs`, and bounded graph commands.
5. Inspect selected functions with `decompile`, `decompile-lvars`, `basic-blocks`, `function-items`, or `disassemble`.
6. Use `decompile-microcode` only when pseudo-C is insufficient and Hex-Rays IR materially helps.

## Efficient querying

- Page function lists with `--limit` and `--offset`; do not request an unbounded whole-program dump by default.
- Search strings with a concrete substring and small limit, then map matching addresses to referencing functions.
- Prefer `xrefs-from <function> --no-stack` when only code/data relationships matter.
- Decompile by exact address when partial names are ambiguous.
- For one function, prefer `function-info` before combining many separate probes.
- Use `decompile-all` only for an explicit bulk-export or diff workflow and provide a filter or limit when practical.

## Evidence rules

- Decompiled code is an interpretation. Cross-check security-sensitive conclusions with disassembly, xrefs, types, or microcode.
- A missing xref does not exclude indirect calls, callbacks, exception edges, runtime resolution, or obfuscation.
- Distinguish import presence from actual reachability.
- Preserve exact addresses and names in notes so another tool or analyst can reproduce the path.

## Useful command families

| Question | Commands |
|---|---|
| What is this binary? | `status`, `metadata`, `memory-map`, `relocations` |
| What can it do? | `imports`, `exports`, `strings`, `functions` |
| What is this function? | `function`, `function-info`, `decompile`, `disassemble` |
| Who calls it? | `xrefs-to`, `decompiler-xrefs` |
| What does it use? | `xrefs-from`, `function-items` |
| What is its control flow? | `basic-blocks`, `function-graph`, `call-graph`, `get-switch-info` |
| What do the bytes contain? | `read-bytes`, `read-string`, `find-bytes`, `file-offset` |
| What did Hex-Rays infer? | `decompile-lvars`, `decompile-microcode` |

Use `<command> --help` before relying on an uncommon flag.
