# Firmware and loaders

Read this for raw binaries, firmware images, custom loaders, load-base discovery, or ARM/Thumb repair.

Based on upstream [quick start](https://github.com/bkerler/ida_rpc/blob/main/docs/quickstart.md), [internals](https://github.com/bkerler/ida_rpc/blob/main/docs/internals.md), and [troubleshooting](https://github.com/bkerler/ida_rpc/blob/main/docs/troubleshooting.md).

## Import decision

1. Run `list-loaders <binary>` before opening an ambiguous file.
2. Use a recognized loader when available.
3. Use `--loader raw` only for a true flat image or when the user explicitly chooses raw import.
4. For a new raw IDB, supply `--arch` and the byte-address `--base`.
5. Existing IDBs ignore raw-import options such as base and loader; repair the database through segment and processor-context commands instead.

Common architecture choices include `arm`, `thumb`, `aarch64`/`arm64`, `x86`/`metapc`, `x64`, `mips`, `mipsb`, `mips64`, `ppc`, and `ppc64`. Confirm against live `--help` and `status`.

## Unknown base

`basefind` is a local pre-import heuristic for flat 32-bit binaries. Treat candidates as hypotheses:

1. Collect several candidates with bounded results.
2. Prefer candidates supported by pointer density, strings, vectors, or known platform layout.
3. Load the best candidate into a disposable or explicitly chosen IDB.
4. Validate entry points, strings, xrefs, and disassembly before accepting the base.

## ARM and Thumb

- Inspect available context registers before setting one.
- For Thumb-oriented raw firmware, choosing `--arch thumb` at import is preferable to repairing a large range later.
- If a region is misclassified, inspect bytes and current processor context, clear only the exact affected range when authorized, set the mode over a bounded range, re-disassemble, then create or repair functions.
- Do not generalize one region's T/Thumb state to the entire firmware.

## Segments

Use `segments`/`memory-map` to verify addresses, size, class, bitness, and permissions. Segment creation, deletion, range clearing, and byte loading are mutations and require explicit authorization.

## Loader failures

If import times out with no Python traceback, inspect the daemon log and loader candidates. Do not repeatedly retry different destructive `--clean` or loader combinations against the same only copy of an IDB.
