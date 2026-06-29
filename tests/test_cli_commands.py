# (c) B. Kerler 2026, MIT license
"""Tests for CLI command registration and argument parsing."""

from __future__ import annotations

import json
import pytest
from click.testing import CliRunner

from ida_rpc import session as session_mod
from ida_rpc.cli import cli


class TestCliCommandsExist:
    """Verify all CLI commands can show their help without error."""

    runner = CliRunner()

    @pytest.mark.parametrize("cmd", [
        "capabilities", "find-project", "open",
        "start", "restart", "list", "status", "stop",
        "list-loaders",
        "function", "functions", "imports", "exports", "metadata",
        "relocations", "calling-conventions",
        "strings", "symbols", "find-bytes", "find-string",
        "memory-map", "segments",
        "decompile", "decompile-all", "basic-blocks", "disassemble",
        "assemble", "read-bytes", "write-bytes", "read-string", "create-string",
        "xrefs-to", "xrefs-from",
        "goto",
        "rename-function", "rename-symbol", "create-label",
        "set-comment", "set-signature", "set-data-type",
        "create-function", "delete-function",
        "set-thunk", "set-calling-convention",
        "batch-rename", "batch-set-comment",
        "create-struct", "create-union", "create-enum",
        "modify-struct", "modify-enum",
        "clear-data-range", "apply-data-type-range",
        "list-data-types", "list-labels",
        "set-equate", "list-equates",
        "set-bookmark", "list-bookmarks", "remove-bookmark",
        "add-segment", "edit-segment", "delete-segment",
        "get-processor-context", "set-processor-context",
        "create-namespace", "list-namespaces",
        "tag-function", "untag-function", "list-tags", "functions-by-tag",
        "save", "list-binaries", "basefind",
        "function-info", "function-items", "function-chunks", "set-function-color",
        "list-patches", "revert-patch", "patch-byte", "patch-word",
        "patch-dword", "patch-qword",
        "list-problems",
        "file-offset", "file-offset-to-ea",
        "add-entry", "rename-entry",
        "function-graph", "call-graph", "get-switch-info",
        "function-frame", "list-stack-vars", "rename-stack-var",
        "set-stack-var-type", "list-reg-vars", "stack-var-xrefs",
        "decompile-lvars", "set-lvar-name", "set-lvar-type",
        "decompile-microcode", "decompiler-xrefs",
        "debug-start", "debug-attach", "debug-detach", "debug-exit",
        "debug-continue", "debug-suspend", "debug-step-into", "debug-step-over",
        "debug-run-to", "debug-status", "debug-get-registers", "debug-set-register",
        "debug-read-memory", "debug-write-memory", "debug-breakpoints",
        "debug-add-breakpoint", "debug-delete-breakpoint", "debug-enable-breakpoint",
        "debug-stack-trace", "debug-modules", "debug-threads",
        "import-til", "export-til", "delete-type", "get-type-info",
        "operand-struct-path", "set-color", "get-color", "del-color",
        "list-try-blocks",
    ])
    def test_command_help(self, cmd: str):
        result = self.runner.invoke(cli, [cmd, "--help"])
        assert result.exit_code == 0, f"Command '{cmd}' failed: {result.output}"
        assert result.output.startswith("Usage:")


class TestCliStartArgs:
    """Test the start command argument structure."""

    runner = CliRunner()

    @pytest.mark.parametrize(("arch", "processor"), [
        ("x86", "metapc"),
        ("x86_64", "metapc"),
        ("amd64", "metapc"),
        ("aarch64", "arm"),
        ("armv7-m", "arm"),
        ("mips64el", "mips"),
        ("powerpc64", "ppc"),
        ("risc-v", "riscv"),
        ("riscv64", "riscv"),
        ("8051", "i51"),
        ("m68k", "mc68k"),
    ])
    def test_resolve_processor_aliases(self, arch, processor):
        from ida_rpc.cli import _resolve_processor_name

        assert _resolve_processor_name(arch) == processor

    def test_start_requires_binary_or_project(self):
        result = self.runner.invoke(cli, ["start", "--arch", "arm"])
        assert result.exit_code != 0
        assert "Provide either BINARY or --project" in result.output

    def test_start_requires_arch(self, tmp_path):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x00" * 4)

        result = self.runner.invoke(cli, ["start", str(binary), "--headless", "--detach"])

        assert result.exit_code != 0
        assert "Missing option" in result.output
        assert "--arch" in result.output

    def test_open_requires_arch(self, tmp_path):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x00" * 4)

        result = self.runner.invoke(cli, ["open", str(binary), "--headless", "--detach"])

        assert result.exit_code != 0
        assert "Missing option" in result.output
        assert "--arch" in result.output

    def test_start_accepts_options(self):
        # We can't actually start IDA, but we can verify argument parsing
        result = self.runner.invoke(cli, [
            "start", "/nonexistent", "--project", "/tmp/test.i64",
            "--arch", "arm", "--base", "0x1000", "--headless", "--detach",
        ])
        # Should fail because binary doesn't exist (click.Path validates it)
        assert result.exit_code != 0

    def test_start_fails_if_project_is_already_running(self, tmp_path, monkeypatch):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x00" * 4)
        project = tmp_path / "sample.i64"

        monkeypatch.setattr("ida_rpc.daemon.is_running", lambda sock: True)
        monkeypatch.setattr(
            "ida_rpc.daemon.start_background",
            lambda *args, **kwargs: pytest.fail("start_background must not be called"),
        )
        monkeypatch.setattr(
            "ida_rpc.daemon.start_blocking",
            lambda *args, **kwargs: pytest.fail("start_blocking must not be called"),
        )

        result = self.runner.invoke(cli, [
            "start", str(binary), "--project", str(project),
            "--arch", "arm", "--headless", "--detach",
        ])

        assert result.exit_code != 0
        assert "AlreadyRunning" in result.output
        assert str(project) in result.output

    def test_start_passes_raw_base_address_to_ida(self, tmp_path, monkeypatch):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x00" * 4)
        project = tmp_path / "sample.i64"
        captured = {}

        def fake_start_background(session, timeout, *, binary_path=None, extra_ida_args=None):
            captured["session"] = session
            captured["timeout"] = timeout
            captured["binary_path"] = binary_path
            captured["extra_ida_args"] = extra_ida_args

        monkeypatch.setattr("ida_rpc.daemon.start_background", fake_start_background)

        result = self.runner.invoke(cli, [
            "start", str(binary), "--project", str(project),
            "--arch", "aarch64", "--base", "0x03000000",
            "--headless", "--detach",
        ])

        assert result.exit_code == 0, result.output
        assert captured["binary_path"] == binary
        assert captured["extra_ida_args"] == ["-parm", "-b3000000"]

    def test_start_passes_loader_option_to_ida(self, tmp_path, monkeypatch):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x00" * 4)
        project = tmp_path / "sample.i64"
        captured = {}

        def fake_start_background(session, timeout, *, binary_path=None, extra_ida_args=None):
            captured["extra_ida_args"] = extra_ida_args

        monkeypatch.setattr("ida_rpc.daemon.start_background", fake_start_background)

        result = self.runner.invoke(cli, [
            "start", str(binary), "--project", str(project),
            "--arch", "aarch64", "--base", "0x03000000",
            "--loader", "raw", "--headless", "--detach",
        ])

        assert result.exit_code == 0, result.output
        assert captured["extra_ida_args"] == ["-parm", "-b3000000", "-TBinary file"]

    def test_start_maps_x86_arch_to_ida_metapc_processor(self, tmp_path, monkeypatch):
        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"MZ\x00\x00")
        project = tmp_path / "sample.i64"
        captured = {}

        def fake_start_background(session, timeout, *, binary_path=None, extra_ida_args=None):
            captured["session"] = session
            captured["binary_path"] = binary_path
            captured["extra_ida_args"] = extra_ida_args

        monkeypatch.setattr("ida_rpc.daemon.start_background", fake_start_background)

        result = self.runner.invoke(cli, [
            "start", str(binary), "--project", str(project),
            "--arch", "x86", "--headless", "--detach",
        ])

        assert result.exit_code == 0, result.output
        assert captured["session"].arch == "x86"
        assert captured["binary_path"] == binary
        assert captured["extra_ida_args"] == ["-pmetapc"]

    def test_start_ignores_raw_import_options_for_existing_idb(self, tmp_path, monkeypatch):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x00" * 4)
        binary.with_suffix(".i64").write_bytes(b"existing idb")
        captured = {}

        def fake_start_background(session, timeout, *, binary_path=None, extra_ida_args=None):
            captured["binary_path"] = binary_path
            captured["extra_ida_args"] = extra_ida_args

        monkeypatch.setattr("ida_rpc.daemon.start_background", fake_start_background)

        result = self.runner.invoke(cli, [
            "start", str(binary),
            "--arch", "arm", "--base", "0x10000",
            "--loader", "raw", "--headless", "--detach",
        ])

        assert result.exit_code == 0, result.output
        assert captured["binary_path"] is None
        assert captured["extra_ida_args"] == ["-parm"]

    def test_start_without_detach_launches_ida_for_binary(self, tmp_path, monkeypatch):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x00" * 4)
        project = tmp_path / "sample.i64"
        captured = {}

        def fake_start_background(session, timeout, *, binary_path=None, extra_ida_args=None):
            captured["session"] = session
            captured["timeout"] = timeout
            captured["binary_path"] = binary_path
            captured["extra_ida_args"] = extra_ida_args

        def fake_start_blocking(session):
            raise AssertionError("binary startup must launch IDA, not run a local non-IDA server")

        monkeypatch.setattr("ida_rpc.daemon.start_background", fake_start_background)
        monkeypatch.setattr("ida_rpc.daemon.start_blocking", fake_start_blocking)

        result = self.runner.invoke(cli, [
            "start", str(binary), "--project", str(project),
            "--arch", "aarch64", "--base", "0x03000000",
            "--headless",
        ])

        assert result.exit_code == 0, result.output
        assert captured["binary_path"] == binary
        assert captured["extra_ida_args"] == ["-parm", "-b3000000"]


class TestCliAgentDiscovery:
    """Test commands intended for automated agent discovery."""

    runner = CliRunner()

    def test_capabilities_outputs_json(self):
        result = self.runner.invoke(cli, ["--json", "capabilities"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ok"] is True
        assert "agent_workflow" in data["result"]
        assert "decompile" in data["result"]["commands"]["decompile_disassemble"]

    def test_find_project_for_binary_default(self, tmp_path):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x7fELF")

        result = self.runner.invoke(cli, ["--json", "find-project", str(binary)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ok"] is True
        assert data["result"]["project"] == str(binary.with_suffix(".i64"))
        assert data["result"]["exists"] is False
        assert "--arch <arch>" in data["result"]["recommended_start"]

    def test_list_loaders_for_rockchip_miniloader(self, tmp_path):
        binary = tmp_path / "loader.bin"
        binary.write_bytes((0x544F4F42).to_bytes(4, "little") + b"\x00" * 128)

        result = self.runner.invoke(cli, ["--json", "list-loaders", str(binary)])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["ok"] is True
        assert any(item["alias"] == "raw" for item in data["result"]["aliases"])
        assert any(
            item.get("alias") == "miniloader"
            for item in data["result"]["candidates"]
        )


class TestCliRpcCommands:
    """Test that RE commands build correct RPC args."""

    runner = CliRunner()

    @pytest.mark.parametrize("cmd,extra_args,expected_rpc_cmd,expected_keys", [
        ("function", ["main"], "function", {"func"}),
        ("functions", ["--limit", "10"], "functions", {"limit"}),
        ("imports", [], "imports", set()),
        ("exports", [], "exports", set()),
        ("add-entry", ["0x1000", "entry"], "add_entry", {"address", "name", "ordinal", "makecode"}),
        ("rename-entry", ["1", "new_entry"], "rename_entry", {"ordinal", "name"}),
        ("metadata", [], "metadata", set()),
        ("relocations", ["--limit", "50"], "relocations", {"limit"}),
        ("calling-conventions", [], "list_calling_conventions", set()),
        ("strings", ["hello", "--limit", "20"], "strings", {"query", "limit"}),
        ("find-string", ["hello", "--limit", "20"], "find_string", {"query", "limit"}),
        ("symbols", ["main", "--limit", "5"], "symbols", {"query", "limit", "offset"}),
        ("find-bytes", ["55 8b ec", "--limit", "10"], "find_bytes", {"pattern", "limit"}),
        ("memory-map", [], "memory_map", set()),
        ("segments", [], "list_segments", set()),
        ("decompile", ["main"], "decompile", {"func", "timeout"}),
        ("decompile-all", ["--limit", "5", "--function", "sub"], "decompile_all", {"limit", "function"}),
        ("basic-blocks", ["main"], "basic_blocks", {"func", "limit"}),
        ("disassemble", ["0x1000"], "disassemble", {"address", "count"}),
        ("assemble", ["0x1000", "nop"], "assemble", {"address", "instruction"}),
        ("read-bytes", ["0x1000", "0x10"], "read_bytes", {"address", "length"}),
        ("read-string", ["0x1000"], "read_string", {"address"}),
        ("create-string", ["0x1000", "10"], "create_string", {"address", "length"}),
        ("write-bytes", ["0x1000", "90"], "write_bytes", {"address", "hex"}),
        ("list-patches", [], "list_patches", {"limit"}),
        ("revert-patch", ["0x1000"], "revert_patch", {"start"}),
        ("patch-byte", ["0x1000", "0x90"], "patch_byte", {"address", "value"}),
        ("patch-word", ["0x1000", "0x9090"], "patch_word", {"address", "value"}),
        ("patch-dword", ["0x1000", "0x90909090"], "patch_dword", {"address", "value"}),
        ("patch-qword", ["0x1000", "0x1"], "patch_qword", {"address", "value"}),
        ("list-problems", [], "list_problems", {"limit"}),
        ("file-offset", ["0x1000"], "file_offset", {"address"}),
        ("file-offset-to-ea", ["0x400"], "file_offset_to_ea", {"offset"}),
        ("function-info", ["main"], "function_info", {"func"}),
        ("function-items", ["main"], "function_items", {"func", "limit"}),
        ("function-chunks", ["main"], "function_chunks", {"func"}),
        ("set-function-color", ["main", "0xff0000"], "set_function_color", {"func", "color"}),
        ("function-graph", ["main"], "function_graph", {"func"}),
        ("call-graph", [], "call_graph", {"mode", "title"}),
        ("get-switch-info", ["0x1000"], "get_switch_info", {"address"}),
        ("function-frame", ["main"], "function_frame", {"func"}),
        ("list-stack-vars", ["main"], "list_stack_vars", {"func"}),
        ("rename-stack-var", ["main", "--new-name", "var_1"], "rename_stack_var", {"func", "new_name"}),
        ("set-stack-var-type", ["main", "--type", "int"], "set_stack_var_type", {"func", "type"}),
        ("list-reg-vars", ["main"], "list_reg_vars", {"func"}),
        ("stack-var-xrefs", ["main"], "stack_var_xrefs", {"func"}),
        ("decompile-lvars", ["main"], "decompile_lvars", {"func"}),
        ("set-lvar-name", ["main", "var", "new_var"], "set_lvar_name", {"func", "lvar", "new_name"}),
        ("set-lvar-type", ["main", "var", "int"], "set_lvar_type", {"func", "lvar", "type"}),
        ("decompile-microcode", ["main"], "decompile_microcode", {"func"}),
        ("decompiler-xrefs", ["main", "sub_1000"], "decompiler_xrefs", {"func", "target"}),
        ("debug-start", [], "debug_start", set()),
        ("debug-attach", ["1234"], "debug_attach", {"pid"}),
        ("debug-detach", [], "debug_detach", set()),
        ("debug-exit", [], "debug_exit", set()),
        ("debug-continue", [], "debug_continue", set()),
        ("debug-suspend", [], "debug_suspend", set()),
        ("debug-step-into", [], "debug_step_into", set()),
        ("debug-step-over", [], "debug_step_over", set()),
        ("debug-run-to", ["0x1000"], "debug_run_to", {"address"}),
        ("debug-status", [], "debug_status", set()),
        ("debug-get-registers", [], "debug_get_registers", set()),
        ("debug-set-register", ["rax", "0x1"], "debug_set_register", {"register", "value"}),
        ("debug-read-memory", ["0x1000", "0x10"], "debug_read_memory", {"address", "length"}),
        ("debug-write-memory", ["0x1000", "90"], "debug_write_memory", {"address", "hex"}),
        ("debug-breakpoints", [], "debug_breakpoints", set()),
        ("debug-add-breakpoint", ["0x1000"], "debug_add_breakpoint", {"address"}),
        ("debug-delete-breakpoint", ["0x1000"], "debug_delete_breakpoint", {"address"}),
        ("debug-enable-breakpoint", ["0x1000"], "debug_enable_breakpoint", {"address", "enabled"}),
        ("debug-stack-trace", [], "debug_stack_trace", set()),
        ("debug-modules", [], "debug_modules", set()),
        ("debug-threads", [], "debug_threads", set()),
        ("import-til", ["/tmp/test.til"], "import_til", {"path"}),
        ("export-til", ["/tmp/test.til"], "export_til", {"path"}),
        ("delete-type", ["MyStruct"], "delete_type", {"name"}),
        ("get-type-info", ["MyStruct"], "get_type_info", {"name"}),
        ("operand-struct-path", ["0x1000", "0"], "operand_struct_path", {"address", "operand"}),
        ("set-color", ["0x1000", "0xff0000"], "set_color", {"address", "color"}),
        ("get-color", ["0x1000"], "get_color", {"address"}),
        ("del-color", ["0x1000"], "del_color", {"address"}),
        ("list-try-blocks", [], "list_try_blocks", set()),
        ("xrefs-to", ["main"], "xrefs_to", {"target", "limit"}),
        ("xrefs-from", ["main"], "xrefs_from", {"target", "limit", "no_stack"}),
        ("goto", ["main"], "goto", {"target", "target_type"}),
        ("rename-function", ["sub_1000", "new_name"], "rename_function", {"target", "new_name"}),
        ("rename-symbol", ["0x1000", "sym"], "rename_symbol", {"address", "new_name", "create"}),
        ("create-label", ["0x1000", "label"], "create_label", {"address", "name"}),
        ("set-comment", ["0x1000", "note"], "set_comment", {"address", "comment", "comment_type"}),
        ("set-signature", ["main", "void f()"], "set_function_signature", {"target", "signature"}),
        ("set-data-type", ["0x1000", "dword"], "set_data_type", {"address", "data_type"}),
        ("create-function", ["0x1000"], "create_function", {"address"}),
        ("delete-function", ["sub_1000"], "delete_function", {"target"}),
        ("set-thunk", ["sub_1000"], "set_thunk", {"target", "clear"}),
        ("set-calling-convention", ["main", "__stdcall"], "set_calling_convention", {"target", "convention"}),
        ("create-struct", ["MyStruct", "int", "a"], "create_struct", {"name", "fields"}),
        ("create-union", ["MyUnion", "int", "a"], "create_union", {"name", "fields"}),
        ("create-enum", ["MyEnum", "A", "0"], "create_enum", {"name", "values", "size"}),
        ("modify-struct", ["S", "--action", "rename", "--field", "a"], "modify_struct", {"name", "action", "field"}),
        ("modify-enum", ["E", "--action", "add", "--member", "A"], "modify_enum", {"name", "action", "member", "value"}),
        ("clear-data-range", ["0x1000", "--length", "0x10"], "clear_data_range", {"start", "length"}),
        ("apply-data-type-range", ["0x1000", "dword", "--length", "0x10"], "apply_data_type_range", {"start", "data_type", "length"}),
        ("list-data-types", [], "list_data_types", {"category", "query", "limit"}),
        ("list-labels", ["0x1000"], "list_labels", {"address", "limit"}),
        ("set-equate", ["0x1000", "0", "ENUM"], "set_equate", {"address", "operand", "enum", "clear"}),
        ("list-equates", [], "list_equates", {"limit"}),
        ("set-bookmark", ["0x1000"], "set_bookmark", {"address", "type", "category", "comment"}),
        ("list-bookmarks", [], "list_bookmarks", {"limit"}),
        ("remove-bookmark", ["0x1000"], "remove_bookmark", {"address", "type"}),
        ("add-segment", ["0x1000", "0x2000"], "add_segment", {"start", "end"}),
        ("edit-segment", ["0x1000"], "edit_segment", {"start"}),
        ("delete-segment", ["0x1000"], "delete_segment", {"start"}),
        ("get-processor-context", [], "get_processor_context", set()),
        ("set-processor-context", ["0x1000", "T", "1"], "set_processor_context", {"address", "register", "value"}),
        ("create-namespace", ["ns"], "create_namespace", {"namespace"}),
        ("list-namespaces", [], "list_namespaces", {"limit"}),
        ("tag-function", ["main", "important"], "tag_function", {"target", "tag"}),
        ("untag-function", ["main", "important"], "untag_function", {"target", "tag"}),
        ("list-tags", [], "list_tags", set()),
        ("functions-by-tag", ["important"], "functions_by_tag", {"tag", "limit"}),
        ("save", [], "save", set()),
        ("list-binaries", [], "list_binaries", set()),
        ("basefind", ["--max-results", "10"], "basefind", {"max_results", "filename_hints", "str_len", "diff_len", "samplerate", "min_abs_refs"}),
    ])
    def test_rpc_command_structure(self, cmd, extra_args, expected_rpc_cmd, expected_keys, monkeypatch):
        """Verify that CLI commands send the expected RPC command and keys."""
        calls = []

        def fake_rpc_command(project, cmd_name, args):
            calls.append((cmd_name, args))
            # Print JSON so the CLI exits cleanly
            print(json.dumps({"ok": True, "result": {}}))

        monkeypatch.setattr("ida_rpc.cli._rpc_command", fake_rpc_command)
        monkeypatch.setenv("IDA_RPC_PROJECT", "/tmp/test.i64")

        result = self.runner.invoke(cli, [cmd] + extra_args)

        assert result.exit_code == 0, f"Command '{cmd}' failed: {result.output}"
        assert len(calls) == 1, f"Expected 1 RPC call for '{cmd}', got {len(calls)}"
        actual_cmd, actual_args = calls[0]
        assert actual_cmd == expected_rpc_cmd, f"Expected RPC cmd '{expected_rpc_cmd}', got '{actual_cmd}'"
        assert expected_keys.issubset(set(actual_args.keys())), (
            f"Command '{cmd}' missing expected keys. Expected {expected_keys}, got {set(actual_args.keys())}"
        )


class TestBatchCommands:
    """Test batch-rename and batch-set-comment CLI commands."""

    runner = CliRunner()

    def test_batch_rename_from_file(self, tmp_path, monkeypatch):
        calls = []

        def fake_rpc_command(project, cmd_name, args):
            calls.append((cmd_name, args))
            print(json.dumps({"ok": True, "result": {}}))

        monkeypatch.setattr("ida_rpc.cli._rpc_command", fake_rpc_command)
        monkeypatch.setenv("IDA_RPC_PROJECT", "/tmp/test.i64")

        ops = [{"target": "sub_1000", "new_name": "foo"}]
        fpath = tmp_path / "ops.json"
        fpath.write_text(json.dumps(ops))

        result = self.runner.invoke(cli, ["batch-rename", "--from-file", str(fpath)])
        assert result.exit_code == 0
        assert calls[0][0] == "batch_rename"
        assert calls[0][1]["mode"] == "function"
        assert len(calls[0][1]["operations"]) == 1

    def test_batch_set_comment_from_file(self, tmp_path, monkeypatch):
        calls = []

        def fake_rpc_command(project, cmd_name, args):
            calls.append((cmd_name, args))
            print(json.dumps({"ok": True, "result": {}}))

        monkeypatch.setattr("ida_rpc.cli._rpc_command", fake_rpc_command)
        monkeypatch.setenv("IDA_RPC_PROJECT", "/tmp/test.i64")

        ops = [{"address": "0x1000", "comment": "note"}]
        fpath = tmp_path / "ops.json"
        fpath.write_text(json.dumps(ops))

        result = self.runner.invoke(cli, ["batch-set-comment", "--from-file", str(fpath)])
        assert result.exit_code == 0
        assert calls[0][0] == "batch_set_comment"
        assert len(calls[0][1]["operations"]) == 1

    def test_batch_rename_without_file_fails(self, monkeypatch):
        monkeypatch.setenv("IDA_RPC_PROJECT", "/tmp/test.i64")
        result = self.runner.invoke(cli, ["batch-rename"])
        assert result.exit_code != 0


class TestStopAll:
    """Test stop --all enumerates and stops all daemons."""

    runner = CliRunner()

    def test_stop_all_finds_and_stops_sockets(self, tmp_path, monkeypatch):
        stopped = []

        def fake_stop_daemon(sock):
            stopped.append(str(sock))
            return True

        monkeypatch.setattr("ida_rpc.daemon.stop_daemon", fake_stop_daemon)

        # Create fake socket files
        sock1 = tmp_path / "ida-rpc-aaaa.sock"
        sock2 = tmp_path / "ida-rpc-bbbb.sock"
        other = tmp_path / "other.sock"
        sock1.write_text("")
        sock2.write_text("")
        other.write_text("")

        # Patch glob to use our temp dir
        import pathlib
        original_glob = pathlib.Path.glob

        def fake_glob(self, pattern):
            if pattern == "ida-rpc-*.sock" and str(self) == "/tmp":
                return sorted(
                    p for p in tmp_path.iterdir()
                    if p.name.startswith("ida-rpc-") and p.name.endswith(".sock")
                )
            return original_glob(self, pattern)

        monkeypatch.setattr(pathlib.Path, "glob", fake_glob)

        result = self.runner.invoke(cli, ["--json", "stop", "--all"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["ok"] is True
        assert data["result"]["status"] == "stopped_all"
        assert len(data["result"]["stopped"]) == 2
        assert set(stopped) == {str(sock1), str(sock2)}

    def test_stop_all_reports_not_running(self, tmp_path, monkeypatch):
        def fake_stop_daemon(sock):
            return False

        monkeypatch.setattr("ida_rpc.daemon.stop_daemon", fake_stop_daemon)

        sock1 = tmp_path / "ida-rpc-aaaa.sock"
        sock1.write_text("")

        import pathlib
        original_glob = pathlib.Path.glob

        def fake_glob(self, pattern):
            if pattern == "ida-rpc-*.sock" and str(self) == "/tmp":
                return sorted(
                    p for p in tmp_path.iterdir()
                    if p.name.startswith("ida-rpc-") and p.name.endswith(".sock")
                )
            return original_glob(self, pattern)

        monkeypatch.setattr(pathlib.Path, "glob", fake_glob)

        result = self.runner.invoke(cli, ["--json", "stop", "--all"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["ok"] is True
        assert data["result"]["not_running"] == [str(sock1)]
        assert data["result"]["stopped"] == []

    def test_stop_still_requires_project_without_all(self):
        result = self.runner.invoke(cli, ["stop"])
        assert result.exit_code != 0
        assert "No project specified" in result.output


class TestStatus:
    """Test status combines persisted session settings with live IDA metadata."""

    runner = CliRunner()

    def test_status_reports_arch_and_live_metadata(self, tmp_path, monkeypatch):
        project = tmp_path / "test.i64"
        state_dir = tmp_path / "state"
        monkeypatch.setenv("IDA_RPC_STATE_DIR", str(state_dir))

        session = session_mod.Session(
            mode="headless",
            project_idb=project,
            socket_path=session_mod.socket_path_for_project(project),
            arch="aarch64",
        )
        session_mod.save(session)

        monkeypatch.setattr("ida_rpc.daemon.is_running", lambda sock: True)

        def fake_send_request(sock, cmd, args):
            if cmd == "list_binaries":
                return {"ok": True, "result": {"binaries": [{
                    "name": "test",
                    "path": "/tmp/test.bin",
                    "arch": "aarch64",
                    "bits": 64,
                    "endian": "little",
                    "format": "Binary file",
                    "base_address": "0x3000000",
                }]}}
            raise AssertionError(f"unexpected RPC command: {cmd}")

        monkeypatch.setattr("ida_rpc.client.send_request", fake_send_request)

        result = self.runner.invoke(cli, ["--json", "status", "--project", str(project)])

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["ok"] is True
        assert data["result"]["arch"] == "aarch64"
        assert data["result"]["processor"] == "aarch64"
        assert data["result"]["bits"] == 64
        assert data["result"]["loaded"]["name"] == "test"
        assert data["result"]["loaded"]["arch"] == "aarch64"
        assert data["result"]["binaries"][0]["arch"] == "aarch64"


class TestListProjects:
    """Test multi-project listing includes loaded architecture/settings."""

    runner = CliRunner()

    def test_list_reports_live_architecture(self, tmp_path, monkeypatch):
        sock = tmp_path / "ida-rpc-test.sock"
        sock.write_text("")

        monkeypatch.setattr("pathlib.Path.glob", lambda self, pattern: [sock])
        monkeypatch.setattr("ida_rpc.daemon.is_running", lambda path: True)
        monkeypatch.setattr("ida_rpc.cli._live_status", lambda path: {
            "loaded": {
                "name": "sample.i64",
                "path": "/tmp/sample.i64",
                "analysis_complete": True,
            },
            "processor": "aarch64",
            "bits": 64,
            "endian": "little",
            "format": "Binary",
            "base_address": "0x0",
        })

        result = self.runner.invoke(cli, ["--json", "list"])

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        project = data["result"]["projects"][0]
        assert project["arch"] == "aarch64"
        assert project["bits"] == 64
        assert project["endian"] == "little"
        assert project["analysis_complete"] is True


class TestClearDataRangeArgs:
    """Test clear-data-range requires end or length."""

    runner = CliRunner()

    def test_requires_end_or_length(self, monkeypatch):
        monkeypatch.setenv("IDA_RPC_PROJECT", "/tmp/test.i64")
        result = self.runner.invoke(cli, ["clear-data-range", "0x1000"])
        assert result.exit_code != 0
        assert "Error:" in result.output


class TestApplyDataTypeRangeArgs:
    """Test apply-data-type-range requires end or length."""

    runner = CliRunner()

    def test_requires_end_or_length(self, monkeypatch):
        monkeypatch.setenv("IDA_RPC_PROJECT", "/tmp/test.i64")
        result = self.runner.invoke(cli, ["apply-data-type-range", "0x1000", "dword"])
        assert result.exit_code != 0
        assert "Error:" in result.output
