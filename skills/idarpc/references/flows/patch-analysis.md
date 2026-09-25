# Patch analysis workflow

Read this when comparing two authorized binary versions to explain a patch or behavioral change.

Adapted from the upstream [patch analysis workflow](https://github.com/bkerler/ida_rpc/blob/main/docs/flows/patch-analysis.md).

## Project layout

Create or resolve a separate IDB and daemon for each version. IDA is single-IDB per process, and endpoint paths derive from the project path. Never open both daemons on the same IDB.

## Sequence

1. Verify identity, architecture, image base, format, and function count for both versions.
2. Compare imports, exports, strings, segments, and entry points.
3. Page and compare function inventories to find added, removed, moved, or renamed candidates.
4. Match stable symbols first; for stripped or relocated code, use byte patterns, signatures, call neighborhoods, constants, and structure.
5. Decompile matched candidates in both projects and normalize only obvious relocation or auto-name noise.
6. Compare CFG, calls, constants, types, and instruction bytes for security-sensitive changes.
7. Trace all callers of the changed behavior and search for unfixed variants elsewhere.
8. Report the actual semantic change, evidence from both versions, confidence, and unmatched coverage.

## Efficiency

- Focus on changed candidates rather than bulk-decompiling both programs immediately.
- Use `decompile-all` only when an external whole-program diff is explicitly needed.
- Keep project arguments explicit so commands cannot accidentally query the wrong version.
- Parallel work requires separate IDBs and daemon processes; each daemon still serializes its own handlers.

## Limitations

ida-rpc does not provide Ghidra-style version tracking in every release. External diffing and heuristic function matching can produce false matches. Confirm important changes at assembly level and do not interpret an unmatched function as deleted without considering compiler, linker, or optimization differences.
