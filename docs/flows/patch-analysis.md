# Patch Analysis Workflow

Compare two versions of a binary to understand what changed — useful for analyzing
security patches, update diffs, or understanding version differences.

## Step 1: Create IDBs for Both Versions

```bash
# Create IDB for old version
ida-rpc start /path/to/binary_v1 --headless --detach

# Create IDB for new version
ida-rpc start /path/to/binary_v2 --headless --detach
```

## Step 2: Start Daemons for Both

```bash
export IDA_RPC_PROJECT_V1=/path/to/binary_v1.i64
export IDA_RPC_PROJECT_V2=/path/to/binary_v2.i64
```

Note: Each IDB needs its own daemon because IDA is single-IDB per process. The
socket paths are derived from the IDB path hash, so they won't conflict.

## Step 3: Compare Function Lists

```bash
# Get function counts
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V1 ida-rpc metadata | jq '.result.num_functions'
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V2 ida-rpc metadata | jq '.result.num_functions'

# List all functions
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V1 ida-rpc functions > /tmp/v1_funcs.json
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V2 ida-rpc functions > /tmp/v2_funcs.json
```

## Step 4: Find Changed Functions

Use external diff tools on the function lists:

```bash
# Extract function names for diffing
jq -r '.result.functions[].name' /tmp/v1_funcs.json | sort > /tmp/v1_names.txt
jq -r '.result.functions[].name' /tmp/v2_funcs.json | sort > /tmp/v2_names.txt

# Functions only in v1 (removed)
comm -23 /tmp/v1_names.txt /tmp/v2_names.txt

# Functions only in v2 (added)
comm -13 /tmp/v1_names.txt /tmp/v2_names.txt
```

## Step 5: Diff Changed Functions by Name

For functions that exist in both but may have changed:

```bash
# Decompile the same-named function in both versions
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V1 ida-rpc decompile parse_arguments > /tmp/v1_parse.json
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V2 ida-rpc decompile parse_arguments > /tmp/v2_parse.json

# Extract C code and diff
jq -r '.result.c_code' /tmp/v1_parse.json > /tmp/v1_parse.c
jq -r '.result.c_code' /tmp/v2_parse.json > /tmp/v2_parse.c
diff -u /tmp/v1_parse.c /tmp/v2_parse.c
```

## Step 6: Match Functions by Signature (Address Changed)

When functions move due to code shifts, use byte signature matching:

```bash
# Find a function's byte pattern in v1
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V1 ida-rpc disassemble 0x401000 --count 5 | jq '.result.instructions[].bytes'

# Search for that pattern in v2
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V2 ida-rpc find-bytes "55 8b ec 83 ec"
```

## Step 7: Bulk Decompile for External Diffing

For comprehensive comparison, use `decompile-all` to export all decompiled code:

```bash
# Decompile all functions in v1
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V1 ida-rpc decompile-all --limit 0 > /tmp/v1_all.json

# Decompile all functions in v2
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V2 ida-rpc decompile-all --limit 0 > /tmp/v2_all.json
```

## Step 8: Investigate New Functions

New functions in the patched version may be:
- Security mitigations (stack canary checks, input sanitizers)
- Replacements for vulnerable functions
- New features

```bash
# Decompile each new function
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V2 ida-rpc decompile <new_function>

# See who calls it
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V2 ida-rpc xrefs-to <new_function>
```

## Step 9: Cross-Reference Analysis

For patched functions, check if the fix is complete:

```bash
# Find all callers of the patched function
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V2 ida-rpc xrefs-to <patched_function>

# Check if similar patterns exist elsewhere (variant analysis)
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V2 ida-rpc strings "strcpy" --limit 50
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V2 ida-rpc xrefs-to strcpy
```

## Step 10: Assembly-Level Diffing

For small, critical functions, compare the raw assembly:

```bash
# Disassemble the patched function in both versions
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V1 ida-rpc disassemble 0x401000 --count 20 > /tmp/v1_asm.json
IDA_RPC_PROJECT=$IDA_RPC_PROJECT_V2 ida-rpc disassemble 0x401000 --count 20 > /tmp/v2_asm.json

# Compare instruction bytes
jq -r '.result.instructions[] | "\(.address): \(.mnemonic) \(.operands)"' /tmp/v1_asm.json
```

## Tips

- **Start with function list diffing**: It immediately shows added/removed functions.
- **Use byte patterns for moved functions**: When code shifts, names may stay the same
  but addresses change. Byte patterns help locate the actual code.
- **Focus on the diff, not the whole binary.** Most code will be identical — zero in on
  what changed.
- **Check nearby functions too.** A patch might change a helper function that's used by
  the function you're interested in.
- **IDA's single-IDB limitation means two daemons**: Unlike Ghidra which can load
  multiple binaries in one process, you need separate daemon instances for each version.
  The socket paths are deterministic, so scripts can reference both consistently.
- **Use `decompile-all` for bulk export**: Much faster than looping `decompile` per function.
