# Editing, types, and patches

Read this only when the user requests changes to the IDB, analysis metadata, or bytes. Ordinary explanation and audit tasks remain read-only.

This reference reorganizes mutation material from the upstream [quick start](https://github.com/bkerler/ida_rpc/blob/main/docs/quickstart.md).

## Mutation protocol

1. Read the exact current target and stable address.
2. Confirm name resolution is unambiguous.
3. Apply the narrowest command that produces the requested outcome.
4. Re-read the target and check `verified` or equivalent returned evidence.
5. Re-decompile affected callers when a rename, signature, type, or calling convention should propagate.
6. Save once for the verified batch.

Do not combine unrelated edits under one authorization. Never patch a target binary merely to demonstrate capability.

## Routing

| Change | Commands |
|---|---|
| Names and comments | `rename-function`, `rename-symbol`, `create-label`, `set-comment` |
| Function metadata | `set-signature`, `set-calling-convention`, `set-thunk`, `create-function`, `delete-function` |
| Decompiler locals | `decompile-lvars`, `set-lvar-name`, `set-lvar-type` |
| Stack/register variables | `function-frame`, `list-stack-vars`, `rename-stack-var`, `set-stack-var-type`, `list-reg-vars` |
| Types | `create-struct`, `create-union`, `create-enum`, `modify-struct`, `modify-enum`, `set-data-type` |
| Type libraries | `import-til`, `export-til`, `get-type-info`, `delete-type` |
| Data ranges | `clear-data-range`, `apply-data-type-range`, `create-string`, `undefine` |
| Operands | `set-equate`, `list-equates`, `operand-struct-path` |
| Segments | `add-segment`, `edit-segment`, `delete-segment` |
| Bytes | `write-bytes`, `assemble`, `patch-byte`, `patch-word`, `patch-dword`, `patch-qword`, `revert-patch` |
| Organization | `set-bookmark`, `tag-function`, `create-namespace`, colors |

## Ordering

- Apply function signatures and stable types before renaming decompiler locals; re-decompilation can renumber auto-generated variables.
- Create or import a type before applying it to memory or variables.
- Read `list-patches` before reverting or layering byte changes.
- After segment or processor-context edits, re-run disassembly before creating functions.

## Batch operations

Use `batch-rename`, `batch-set-comment`, or generic `batch` for many homogeneous operations. Put non-trivial JSON in a UTF-8 file, validate its shape, and review per-item results. Batch commands reduce round trips but do not make IDA handlers execute in parallel.

If a batch partially succeeds, report the exact successful and failed items before deciding whether a retry is safe.
