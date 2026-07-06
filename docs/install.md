# Installing ida-rpc

## Prerequisites

1. **IDA Pro** (9.0+): Must be installed and licensed. Hex-Rays decompiler is optional but recommended.
2. **Python 3.10+**: Check with `python3 --version`.
3. **uv** or **pip**: For package installation.

## Set IDA_INSTALL_DIR

Point this at your IDA Pro installation directory (the one containing `ida` and `idat`):

```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
export IDA_INSTALL_DIR=/opt/ida-pro-9.3sp2
```

This is optional but recommended — the daemon will try to find IDA automatically if not set.

## Install ida-rpc

### Option 1: IDA Plugin Manager (recommended)

Install directly from the IDA Plugin Repository using [HCLI](https://hcli.docs.hex-rays.com/):

```bash
hcli plugin install ida-rpc
```

The plugin manager will:
- Extract the plugin into your IDA user directory
- Install Python dependencies automatically
- Handle upgrades with `hcli plugin upgrade ida-rpc`

Default plugin installation locations (`$IDAUSR/plugins/`):

| OS | Default `$IDAUSR` path |
|----|------------------------|
| Windows | `%APPDATA%\Hex-Rays\IDA Pro\` |
| macOS | `~/Library/Application Support/IDA Pro/` |
| Linux | `~/.idapro/` |

You can override `$IDAUSR` when testing across multiple IDA versions:

```bash
export IDAUSR=~/.idapro93/
hcli plugin install ida-rpc
```

### Option 2: pip (development or custom setups)

```bash
# From the ida-rpc directory
pip install -e /path/to/ida-rpc

# Or with uv
uv pip install -e /path/to/ida-rpc
```

When installing via pip, you still need to make the plugin visible to IDA (see below).

## Manual Plugin Installation

If you are not using the Plugin Manager, the plugin file must be accessible to IDA Pro. Two options:

### Option A: Symlink into `$IDAUSR/plugins/` (recommended for development)

```bash
ln -s /path/to/ida-rpc/ida_rpc_plugin.py $IDAUSR/plugins/ida_rpc_plugin.py
```

### Option B: Copy into `$IDAUSR/plugins/`

```bash
cp /path/to/ida-rpc/ida_rpc_plugin.py $IDAUSR/plugins/
```

### Option C: Symlink into IDA installation directory

```bash
ln -s /path/to/ida-rpc/ida_rpc_plugin.py $(IDA_INSTALL_DIR)/plugins/ida_rpc_plugin.py
```

## Verify Installation

```bash
ida-rpc --version
# Should print: ida-rpc, version 0.1.5
```

## What Gets Installed

- `ida-rpc` — the CLI you'll use for all commands
- `ida-rpcd` — the background daemon entry point (used internally by `ida-rpc restart`)

Both are Python entry points. No global packages are modified.

## Dependencies

Installed automatically:
- `click` — CLI framework

IDA Pro's bundled Python provides all other required modules (`ida_*`, `idautils`, etc.).
