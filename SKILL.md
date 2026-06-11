# SKILL.md — ida-rpc

How to use `ida-rpc` as a reverse-engineering skill inside an agent workflow.

## What This Skill Provides

Direct, structured access to IDA Pro's analysis engine without GUI interaction. Every command returns JSON — no screen scraping, no MCP protocol overhead. Works in both interactive (GUI) and automation (headless) modes.

## When to Use This Skill

- You need to **decompile, disassemble, or analyze** a binary.
- You need **cross-references, function lists, imports, exports, or strings**.
- You need to **rename functions, set comments, or create data types** programmatically.
- You need **segment editing, processor context switching (ARM/Thumb), or assembly patching**.
- You are working in an **automation pipeline** or **multi-agent system**.

## What this skill requires
- RPC queries should always be run outside the sandbox.

## Quick Start Workflow

### 1. Discover capabilities and project path

```bash
ida-rpc capabilities
ida-rpc find-project /path/to/binary-or-existing.i64
```

Use `capabilities` as the stable automation probe. It returns JSON describing
the supported command groups and the recommended agent workflow.

### 2. Start the Daemon

```bash
# Open a binary and start the daemon
ida-rpc open /path/to/binary --headless --detach

# Open an existing database (.i64 or .idb)
ida-rpc open --project /path/to/existing.i64 --headless --detach

# For raw binaries, specify architecture and base address
ida-rpc open /path/to/raw.bin --arch arm --base 0x8000 --headless --detach

# When opening a system binary (e.g. /usr/bin/ls), specify a writable project path
ida-rpc open /usr/bin/ls --project /tmp/ls_analysis.i64 --headless --detach
```

### 3. Set the default project

```bash
export IDA_RPC_PROJECT=/path/to/binary.i64
```

### 4. Check status and list loaded binaries

```bash
# Check if a daemon is running for a project
ida-rpc status --project /tmp/ls_analysis.i64

# List all currently loaded binaries in a project
ida-rpc list-binaries --project /tmp/ls_analysis.i64

# List all active ida-rpc daemons on this machine
ida-rpc list
```

### 5. Run analysis commands

All commands output JSON. Use `jq` for filtering if needed.

```bash
# List functions (paginated)
ida-rpc functions --limit 20

# Decompile a function
ida-rpc decompile main

# Search for strings containing "password"
ida-rpc strings "password" --limit 20

# Find byte pattern
ida-rpc find-bytes "55 8b ec 83 ec"

# Get cross-references to a function
ida-rpc xrefs-to target_function

# Read raw bytes at an address
ida-rpc read-bytes 0x401000 64
```

### 6. Make annotations

```bash
# Rename a function
ida-rpc rename-function sub_401000 my_awesome_function

# Set a comment
ida-rpc set-comment 0x401020 "This is the entry point"

# Create a struct
ida-rpc create-struct my_struct "int" field1 "char" field2

# Set a bookmark
ida-rpc set-bookmark 0x401000 --type Analysis --comment "Suspicious loop"
```

### 7. Save and stop

```bash
ida-rpc save
ida-rpc stop
```

## Command Reference for Agents

### Lifecycle

| Command | Args | Description |
|---------|------|-------------|
| `capabilities` | | Print agent-discoverable JSON command capabilities |
| `find-project <binary-or-idb>` | | Resolve IDB path, socket path, session state, and recommended start command |
| `open <binary-or-idb> [--project <idb>] [--headless] [--detach]` | | Agent-friendly alias for `start` |
| `start <binary> [--project <idb>] [--arch <arch>] [--base <addr>] [--headless] [--detach] [--clean]` | | Open binary and start daemon |
| `start --project <idb> [--headless] [--detach] [--clean]` | | Open an existing database |
| `stop --project <idb>` | | Stop daemon |
| `status --project <idb>` | | Check health + list loaded binaries |
| `restart --project <idb> [--headless] [--clean]` | | Restart daemon |
| `list` | | List all active projects/daemons |
| `list-binaries --project <idb>` | | List binaries loaded in the current IDB |

### Analysis & Listing

| Command | Args | Description |
|---------|------|-------------|
| `functions [--limit N] [--offset N] [--with-body]` | | List functions with optional pagination |
| `imports` | | List imported symbols |
| `exports` | | List exported symbols |
| `metadata` | | Binary metadata (arch, bits, format, base addr) |
| `relocations [--limit N]` | | List relocation/fixup entries |
| `calling-conventions` | | List valid calling conventions for current processor |
| `strings [query] [--limit N]` | | Search strings (empty query = all) |
| `symbols <query> [--limit N]` | | Search named symbols |
| `find-bytes <pattern> [--limit N]` | | Byte pattern search (supports `??` wildcards) |
| `memory-map` | | List memory segments with RWX permissions |
| `segments` | | Alias for memory-map (explicit segment listing) |
| `basefind <path> [--max-results N] [--min-abs-refs N] [--str-len N] [--diff-len N] [--samplerate N] [--no-filename-hints]` | | Scan a flat 32-bit binary to determine its load base (runs locally, no daemon needed) |

### Decompilation & Disassembly

| Command | Args | Description |
|---------|------|-------------|
| `decompile <func> [--timeout N]` | | Decompile function to pseudo-C |
| `decompile-all [--limit N] [--function <filter>]` | | Bulk decompile all functions |
| `basic-blocks <func> [--limit N]` | | CFG basic blocks with successors/predecessors |
| `disassemble <address> [--count N]` | | Disassemble instructions (default 20, max 1000) |
| `assemble <address> <instruction>` | | Assemble instruction text (requires Keystone Engine) |
| `read-bytes <address> <length>` | | Hex dump with ASCII |
| `write-bytes <address> <hex>` | | Patch bytes (max 4096) |

### Cross-References

| Command | Args | Description |
|---------|------|-------------|
| `xrefs-to <target> [--limit N]` | | References **to** target (function name or address) |
| `xrefs-from <target> [--limit N] [--no-stack]` | | References **from** target |

### Annotations & Modifications

| Command | Args | Description |
|---------|------|-------------|
| `rename-function <target> <new_name>` | | Rename function |
| `rename-symbol <address> <new_name> [--create]` | | Rename symbol at address |
| `create-label <address> <name>` | | Create a named label |
| `set-comment <address> <comment> [--type plate\|pre\|post\|eol\|repeatable]` | | Set comment |
| `set-signature <target> <signature>` | | Set function prototype (C syntax) |
| `set-data-type <address> <type>` | | Set data type (byte, word, dword, qword, string, or C decl) |
| `create-function <address> [--name N]` | | Create function at address |
| `delete-function <target>` | | Delete a function definition |
| `create-instruction <address>` | | Mark bytes at address as an instruction |
| `undefine <address> [length]` | | Undefine instruction or data at address |
| `set-thunk <target> [--thunk-target <addr>] [--clear]` | | Mark/unmark function as thunk |
| `set-calling-convention <target> <convention>` | | Change function calling convention |
| `batch-rename --from-file <json>` | | Bulk rename functions/symbols |
| `batch-set-comment --from-file <json>` | | Bulk set comments |

### Data Types

| Command | Args | Description |
|---------|------|-------------|
| `create-struct <name> <fields...> [--if-not-exists] [--or-replace]` | | Fields as `TYPE NAME TYPE NAME ...` pairs |
| `create-union <name> <fields...> [--if-not-exists] [--or-replace]` | | Same pair format as struct |
| `create-enum <name> [values...] [--size 1\|2\|4\|8]` | | Values as `NAME VALUE NAME VALUE ...` pairs |
| `modify-struct <name> --action {rename,retype,delete,set_comment} --field <name>` | | Modify an existing struct field |
| `modify-enum <name> --action {add,remove} --member <name> [--value N]` | | Add/remove enum members |
| `list-data-types [--category all\|struct\|enum\|union] [--query Q] [--limit N]` | | List defined types |
| `list-labels <address> [--end <addr>] [--limit N]` | | List symbols at or near an address |
| `set-equate <address> <operand> <enum> [--clear]` | | Attach enum to instruction operand |
| `list-equates [--address <addr>] [--end <addr>] [--limit N]` | | List all enum operands |
| `clear-data-range <start> [--end <addr> \| --length N]` | | Undefine data in a range |
| `apply-data-type-range <start> <type> [--end <addr> \| --length N]` | | Stamp a type across a range |

### Segments

| Command | Args | Description |
|---------|------|-------------|
| `add-segment <start> <end> [--name N] [--class C]` | | Create a new segment |
| `edit-segment <start> [--name N] [--class C] [--perm-read/--no-perm-read ...] [--bitness 0\|1\|2]` | | Modify segment name, class, permissions, or bitness |
| `delete-segment <start>` | | Delete a segment |

### Processor Context

| Command | Args | Description |
|---------|------|-------------|
| `get-processor-context [--address <addr>] [--register <name>]` | | Read processor context registers (e.g., ARM T-bit) |
| `set-processor-context <address> <register> <value> [--end <addr>]` | | Set processor context register over a range |

### Namespaces

| Command | Args | Description |
|---------|------|-------------|
| `create-namespace <namespace> [--parent <ns>]` | | Validate/create namespace |
| `list-namespaces [--limit N]` | | List all namespaces with symbol counts |

### Bookmarks

| Command | Args | Description |
|---------|------|-------------|
| `set-bookmark <address> [--type Note\|Warning\|Error\|Info\|Analysis] [--category C] [--comment M]` | | Set bookmark |
| `list-bookmarks [--type T] [--address A] [--limit N]` | | List bookmarks |
| `remove-bookmark <address> [--type T]` | | Remove bookmark |

### Tags

| Command | Args | Description |
|---------|------|-------------|
| `tag-function <target> <tag>` | | Tag a function |
| `untag-function <target> <tag>` | | Remove tag from function |
| `list-tags` | | List all tags with counts |
| `functions-by-tag <tag> [--limit N]` | | Find functions by tag |

## Agent Workflow Patterns

### Pattern 1: Explore → Analyze → Annotate

```bash
# 1. Discover
ida-rpc functions --limit 50 | jq '.result.functions[].name'

# 2. Deep-dive
ida-rpc decompile suspicious_func | jq '.result.c_code'
ida-rpc xrefs-to suspicious_func | jq '.result.xrefs[]'

# 3. Annotate findings
ida-rpc rename-function suspicious_func decrypt_payload
ida-rpc set-comment 0x401234 "Calls decrypt_payload"
ida-rpc save
```

### Pattern 2: Batch String Hunt

```bash
# Find all strings matching a pattern, then decompile their xrefs
ida-rpc strings "auth" --limit 20 | jq '.result.strings[] | .address'
# For each string address, find xrefs-to, then decompile the referencing functions
```

### Pattern 3: Structural Analysis

```bash
# Get memory map
ida-rpc memory-map | jq '.result.segments[] | select(.execute == true)'

# Find functions in a specific address range
ida-rpc functions --address-min 0x401000 --address-max 0x410000

# Decompile each function in that range
for name in $(ida-rpc functions --address-min 0x401000 --address-max 0x410000 | jq -r '.result.functions[].name'); do
    ida-rpc decompile "$name"
done
```

### Pattern 4: Find Raw Binary Base Address

When you have a firmware dump or bare-metal image and don't know the load address, use `basefind` before loading:

```bash
# Scan a raw binary for likely base addresses (no daemon needed)
ida-rpc basefind /path/to/dump.bin --max-results 10

# Example output:
# {
#   "candidates": [
#     {"base": "0x8000000", "score": 10025, "refs": 25, "string_refs": 0, "source": "early-pointer"},
#     {"base": "0x8010000", "score": 18, "refs": 18, "string_refs": 0, "source": "absolute"}
#   ]
# }

# Use the best candidate to start IDA
ida-rpc start /path/to/dump.bin --base 0x8000000 --arch arm --headless --detach
```

**Tuning parameters:**
- `--str-len` (default 10): minimum printable-string length
- `--diff-len` (default 10): string/pointer delta window length
- `--samplerate` (default 20): sparse validation rate for large files
- `--min-abs-refs` (default 4): threshold for absolute-reference candidates

### Pattern 5: Loading Raw Binaries and Memory Segments

When IDA cannot auto-detect the file format (e.g., firmware dumps, bare-metal images), load the raw binary, fix segment bitness/permissions, and then define functions.

```bash
# 1. Start the daemon with a raw binary
#    --base is the byte address (not paragraphs)
#    --arch selects the processor module and auto-configures the segment
ida-rpc start /path/to/dump.bin \
  --project /tmp/firmware.i64 \
  --base 0x8200000 \
  --arch arm \
  --headless --detach

# 2. The segment is auto-configured: class=CODE32, bitness=1, read+exec.
#    No manual edit-segment needed when --arch is provided.

# 3. Create functions at known entry points
ida-rpc create-function 0x8211170 --name func_entry

# 4. Disassemble and verify
ida-rpc disassemble 0x8211170 --count 20
ida-rpc functions --limit 20
```

**Loading a raw binary with explicit file offset, load address, and size:**

```bash
# Step 1: Create an empty database and start the daemon
#    Pass --arch so add-segment auto-configures class/bitnesss/perms.
ida-rpc start --project /tmp/firmware.i64 --arch arm --headless --detach

# Step 2: Create a segment at the target load address
#    Class, bitness, and permissions are auto-configured from --arch.
ida-rpc add-segment 0x08000000 0x08020000 --name FLASH

# Step 3: Extract bytes from a specific file offset and load them
#         dd:  bs=1 skip=<file_offset> count=<size>
dd if=/path/to/dump.bin bs=1 skip=0x2000 count=0x10000 of=/tmp/extracted.bin
python3 -c "import sys; print(open('/tmp/extracted.bin','rb').read().hex())" > /tmp/extracted.hex
ida-rpc write-bytes 0x08000000 "$(cat /tmp/extracted.hex)"

# Step 4: Define functions and analyze
ida-rpc create-function 0x08000000 --name reset_handler
ida-rpc disassemble 0x08000000 --count 10
ida-rpc functions --limit 20
```

**Supported `--arch` values for raw binary auto-configuration:**

| `--arch` value | Processor | Segment class | Bitness | Notes |
|----------------|-----------|--------------|---------|-------|
| `arm` | ARM 32-bit (ARM mode) | `CODE32` | 1 (32-bit) | A1/T32 instructions |
| `thumb` | ARM 32-bit (Thumb mode) | `CODE16` | 1 (32-bit) | **Use this for Thumb-only or mixed ARM/Thumb firmware** |
| `aarch64` | ARM 64-bit | `CODE64` | 2 (64-bit) | Also accepted: `arm64` |
| `metapc` | Intel x86 | `CODE` | 1 (32-bit) | 32-bit x86 |
| `x86` | Intel x86 | `CODE` | 1 (32-bit) | Alias for `metapc` |
| `x64` | Intel x64 | `CODE64` | 2 (64-bit) | 64-bit x86-64 |
| `mips` | MIPS (little-endian) | `CODE` | 1 (32-bit) | |
| `mipsb` | MIPS (big-endian) | `CODE` | 1 (32-bit) | |
| `mips64` | MIPS 64-bit | `CODE64` | 2 (64-bit) | |
| `ppc` | PowerPC 32-bit | `CODE` | 1 (32-bit) | |
| `ppc64` | PowerPC 64-bit | `CODE64` | 2 (64-bit) | |

**Important notes on architecture selection:**

- **`thumb` vs `arm`:** For 32-bit ARM firmware that is primarily Thumb code (common in Cortex-M/MCU binaries), use `--arch thumb`. This sets the segment class to `CODE16`, which tells IDA to disassemble in Thumb mode by default. If you later encounter ARM-mode functions, use `set-processor-context` to switch the T-bit (see Pattern 5).
- For raw binaries, IDA may default to 64-bit addressing even for 32-bit processors. Passing `--arch` auto-configures the segment with the correct bitness and class. If you did not pass `--arch`, manually set bitness with `edit-segment --bitness 1` before creating functions.

**Segment class values:** `CODE`, `DATA`, `CONST`, `BSS`, `STACK`, `HEAP`, `XTRN`.

### Pattern 6: ARM/Thumb Mode Switching

```bash
# Check current processor context at an address
ida-rpc get-processor-context --address 0x8000 --register T

# Switch to Thumb mode (T=1) for a range
ida-rpc set-processor-context 0x8000 T 1 --end 0x9000
```

### Pattern 7: Bulk Decompile for Diffing

```bash
# Decompile all functions matching a pattern
ida-rpc decompile-all --function "parse" --limit 50 | jq '.result.functions[].c_code'
```

### Pattern 8: Assembly Patching

```bash
# Assemble a nop sled at an address (requires Keystone Engine)
ida-rpc assemble 0x401000 "nop"
ida-rpc assemble 0x401001 "jmp 0x401050"
```

## JSON Response Structure

Every successful response:

```json
{
  "id": "<uuid>",
  "ok": true,
  "result": { ... }
}
```

Every error response:

```json
{
  "id": "<uuid>",
  "ok": false,
  "error": "ValueError",
  "message": "Function 'foo' not found."
}
```

Parse with `jq .result` to extract the payload, or check `.ok` first.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `IDA_RPC_PROJECT` | Default `--project` path |
| `IDA_INSTALL_DIR` | Path to IDA Pro installation (for auto-launch) |
| `IDA_RPC_STATE_DIR` | Directory for session JSON files (default: next to IDB) |

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `DaemonNotRunning` | Run `ida-rpc start <binary> --headless --detach` |
| Socket exists but daemon unresponsive | `ida-rpc stop` then `ida-rpc start` |
| Hex-Rays errors | Ensure Hex-Rays decompiler is installed and licensed |
| `Function can be called from the main thread only` | Internal bug — handler forgot `ctx.run_on_main_thread()` |
| Changes lost after stop | Forgot `ida-rpc save` — mutations are auto-saved by most handlers, but explicit save is safest |
| Assembler fails | Install Keystone Engine: `pip install keystone-engine` |

## Programmatic Use (Python)

```python
from ida_rpc.client import send_request
from ida_rpc.session import socket_path_for_project
from pathlib import Path

sock = socket_path_for_project("/tmp/test.i64")
resp = send_request(sock, "functions", {"limit": 10})
print(resp["result"]["functions"])
```

## Protocol Compatibility Note

The wire format (`{"id", "cmd", "args"}` → `{"id", "ok", "result/error"}`) is designed to be compatible with ghidra-rpc. If you have existing clients built for Ghidra, point them at the IDA socket path and most read-only commands will work with minimal or no changes.
