"""Start a Codex session with loopback RPC available inside its sandbox."""

import os
import sys
from pathlib import Path


def main() -> None:
    ida_user_dir = str(Path(os.environ.get("IDAUSR", Path.home() / ".idapro")).expanduser().resolve())
    os.execvp("codex", [
        "codex", "--sandbox", "workspace-write", "--add-dir", ida_user_dir,
        "-c", "sandbox_workspace_write.network_access=true",
        "-c", 'features.network_proxy={enabled=true,domains={"127.0.0.1"="allow"}}',
        "-c", 'shell_environment_policy.set.IDA_RPC_TRANSPORT="tcp"',
        *sys.argv[1:],
    ])
