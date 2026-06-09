# Binary Audit Workflow

## Command Sequence

```bash
# Open binary in IDA and start daemon
ida-rpc start /path/to/binary --headless --detach

# Or if IDB already exists:
ida-rpc start /path/to/binary --project /path/to/existing.i64 --headless --detach

export IDA_RPC_PROJECT=/path/to/binary.i64

ida-rpc metadata          # arch, bits, format, compiler
ida-rpc imports           # external dependencies / capabilities
ida-rpc exports           # relevant for shared libraries
ida-rpc strings "<term>"  # run with several terms: http, error, password, key, /
ida-rpc functions         # entry points, named functions, xref-heavy utilities
ida-rpc decompile main    # start here, work outward
```

## Non-Obvious Tips

**`functions` pagination** — the response includes `total` (all functions) and `count`
(this page), so you know how many pages remain:
```bash
ida-rpc functions --limit 100 --offset 0
ida-rpc functions --limit 100 --offset 100
```

**`xrefs-from`** — shows all code and data references from a function. Use this to
build a call graph:
```bash
ida-rpc xrefs-from <func>
```

**Rename propagation** — renaming a function immediately improves the decompiled
output of all its callers (Hex-Rays uses names in pseudo-code), so rename as you go
rather than at the end.

**Memory map for segment analysis** — identify executable vs data segments:
```bash
ida-rpc memory-map | jq '.result.segments[] | select(.execute == true)'
```

**Bulk decompile for review** — decompile all functions matching a pattern:
```bash
ida-rpc decompile-all --function "parse" --limit 20 | jq '.result.functions[].name'
```

**Processor context for ARM** — check if you're in Thumb mode:
```bash
ida-rpc get-processor-context --register T
```
