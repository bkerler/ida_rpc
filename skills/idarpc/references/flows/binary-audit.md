# Binary audit workflow

Read this for a broad, authorized behavior inventory of one binary. For a narrow function question, use [static analysis](../static-analysis.md) instead.

Adapted from the upstream [binary audit workflow](https://github.com/bkerler/ida_rpc/blob/main/docs/flows/binary-audit.md).

## Sequence

1. Confirm the exact target and daemon identity with `status` and `metadata`.
2. Record processor, bitness, format, image base, entry points, segments, and function count.
3. Inventory imports, exports, relocations, and targeted strings.
4. Identify entry functions, xref-heavy utilities, parsers, dispatchers, and boundary functions.
5. Decompile selected roots and walk outward with `xrefs-from`; use `xrefs-to` to find callers.
6. Build bounded function or call graphs only around selected roots.
7. Cross-check important pseudo-C with disassembly, CFG, types, and bytes.
8. Report behaviors, evidence addresses, uncertainty, and uncovered areas.

## Scaling

- Page `functions` deterministically and retain the last offset or address.
- Filter `decompile-all`; do not export every function unless the requested deliverable needs it.
- Group candidates before deep analysis so library/runtime code does not dominate context.
- Treat indirect calls, callbacks, and runtime imports as explicit coverage gaps.

## Annotation boundary

An audit is read-only unless the user asks to improve the IDB. If annotations are authorized, read [editing and types](../editing-and-types.md), rename as conclusions become stable, verify propagation, and save once per batch.
