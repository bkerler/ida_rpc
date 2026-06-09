# Quick Start

This guide walks you through a first session with ida-rpc.

## 1. Start the Daemon

Open a terminal and start the daemon. This blocks and shows logs:

```bash
# Headless (no GUI) — good for automated analysis
ida-rpc start /path/to/binary --headless

# Or with GUI — opens IDA interactively
ida-rpc start /path/to/binary

# For raw binaries, specify architecture and base address
ida-rpc start /path/to/raw.bin --arch arm --base 0x8000 --headless
```

For automation, start in the background (returns once the socket is responsive):
```bash
ida-rpc start /path/to/binary --headless --detach
```

The `.i64` IDB file will be created next to the binary if it doesn't exist. You can
override the IDB path with `--project`:
```bash
ida-rpc start /path/to/binary --project /custom/path.i64 --headless --detach
```

## 2. Set the Default Project

```bash
export IDA_RPC_PROJECT=/path/to/binary.i64
```

All subsequent commands will use this project automatically.

## 3. Explore

```bash
# What architecture?
ida-rpc metadata

# List functions (use --limit/--offset for large binaries)
ida-rpc functions
ida-rpc functions --limit 50 --offset 0

# Search for interesting strings
ida-rpc strings "error" --limit 20

# Decompile a function (--timeout for slow/complex functions)
ida-rpc decompile main
ida-rpc decompile main --timeout 120

# List relocations
ida-rpc relocations --limit 50

# See calling conventions for this architecture
ida-rpc calling-conventions
```

## 4. Investigate

```bash
# Who calls a particular function?
ida-rpc xrefs-to "strcmp"

# What does a function call?
ida-rpc xrefs-from main --no-stack

# Disassemble at an address
ida-rpc disassemble 0x401000 --count 10

# Read raw bytes
ida-rpc read-bytes 0x401000 64
```

## 5. Annotate

```bash
# Rename a function you've identified
ida-rpc rename-function sub_401000 parse_arguments

# Add a comment
ida-rpc set-comment 0x00401234 "Parses CLI arguments" --type pre

# Change a function's calling convention
ida-rpc set-calling-convention sub_401000 __stdcall

# Mark a function as a thunk
ida-rpc set-thunk sub_401000

# Delete a function definition
ida-rpc delete-function sub_401000
```

## 6. Data Type Authoring

```bash
# Create a struct
ida-rpc create-struct my_struct "int" field1 "char" field2

# Modify an existing struct field
ida-rpc modify-struct my_struct --action rename --field field1 --new-field-name count

# Create an enum
ida-rpc create-enum my_enum "A" 0 "B" 1 "C" 2

# Add a member to an existing enum
ida-rpc modify-enum my_enum --action add --member "D" --value 3

# Clear a range of undefined data
ida-rpc clear-data-range 0x401000 --length 0x100

# Stamp a type across a range
ida-rpc apply-data-type-range 0x401000 dword --length 0x40
```

## 7. Segment Management

```bash
# List segments
ida-rpc segments

# Add a new segment
ida-rpc add-segment 0x100000 0x110000 --name .custom --class DATA

# Edit segment permissions
ida-rpc edit-segment 0x100000 --perm-read --perm-write --no-perm-exec

# Delete a segment
ida-rpc delete-segment 0x100000
```

## 8. Processor Context (ARM/Thumb)

```bash
# Check Thumb mode status at an address
ida-rpc get-processor-context --address 0x8000 --register T

# Switch to Thumb mode for a range
ida-rpc set-processor-context 0x8000 T 1 --end 0x9000
```

## 9. Assembler Patching

```bash
# Assemble instructions (requires Keystone Engine)
ida-rpc assemble 0x401000 "nop"
ida-rpc assemble 0x401001 "mov eax, ebx"
```

## 10. Bulk Operations

```bash
# Decompile all functions matching a pattern
ida-rpc decompile-all --function "parse" --limit 20

# Batch rename from a JSON file
# File format: [{"target": "sub_401000", "new_name": "foo"}, ...]
ida-rpc batch-rename --from-file renames.json

# Batch set comments from a JSON file
# File format: [{"address": "0x401000", "comment": "note"}, ...]
ida-rpc batch-set-comment --from-file comments.json
```

## 11. Stop

```bash
ida-rpc stop
```

Or just Ctrl+C the daemon terminal. All programs are saved automatically on clean
shutdown. Write operations (rename, set-comment, etc.) also auto-save after each
change, so your edits survive restarts.

## Tips

- **No `binary` argument needed**: Since IDA is single-IDB per process, all RE
  commands (functions, decompile, xrefs, etc.) operate on the current project.
  Just set `IDA_RPC_PROJECT` and run commands without specifying a binary.
- **Function targets are flexible**: Use function name (`main`), hex address (`0x401000`),
  or partial name if unambiguous.
- **Auto-restart**: If the daemon crashes, commands will try to restart it automatically
  from the saved session. If that fails, you'll get a clear error message.
- **Write verification**: All write operations (rename, set-comment, set-signature,
  set-data-type) return a `verified` boolean confirming the change was committed.
- **Auto-save**: Every write operation saves to the IDB on disk automatically. Changes
  survive daemon restarts and are visible when you reopen the database in IDA GUI.
- **Signature semicolons**: Trailing `;` is stripped automatically — you can paste
  C prototypes verbatim.
- **List active projects**: `ida-rpc list` shows all running daemons and their sockets.
- **Assembler dependency**: `assemble` requires Keystone Engine (`pip install keystone-engine`).
