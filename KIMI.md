# Kimi Reverse Engineering Tooling

Use `ida-rpc` automatically for IDA Pro binary reversing tasks.

Start with:

```bash
/home/bjk/Projects/ida_rpc/.venv/bin/ida-rpc capabilities
/home/bjk/Projects/ida_rpc/.venv/bin/ida-rpc find-project <binary-or-idb>
```

Then use `open`, `metadata`, `functions`, `decompile`, `disassemble`,
`strings`, `xrefs-to`, `xrefs-from`, `rename-function`, `set-comment`, and
`save`. Every command returns JSON.
