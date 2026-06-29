# (c) B. Kerler 2026, MIT license
"""Tests that all expected server handlers are registered."""

from __future__ import annotations

import pytest


# Expected handler names after register_all_tools() has been called.
_EXPECTED_HANDLERS = {
    # Analysis
    "load", "list_binaries", "function", "functions", "imports", "exports",
    "metadata", "relocations", "list_calling_conventions", "save",
    "basefind", "add_entry", "rename_entry",
    # Search
    "find_bytes", "strings", "find_string", "symbols",
    # Xrefs
    "xrefs_to", "xrefs_from",
    # Navigation
    "goto",
    # Modifications
    "rename_function", "rename_symbol", "create_label",
    "set_comment", "set_function_signature", "set_data_type",
    "create_function", "delete_function", "set_thunk",
    "set_calling_convention", "batch_rename", "batch_set_comment",
    "create_instruction", "undefine",
    # Memory
    "read_bytes", "write_bytes", "read_string", "create_string",
    "memory_map", "list_segments",
    # Disassembly
    "disassemble", "assemble",
    # CFG
    "basic_blocks",
    # Decompiler
    "decompile", "decompile_all",
    # Data types
    "create_struct", "create_union", "create_enum",
    "list_data_types", "list_labels",
    "modify_struct", "modify_enum",
    "clear_data_range", "apply_data_type_range",
    "set_equate", "list_equates",
    # Bookmarks
    "set_bookmark", "list_bookmarks", "remove_bookmark",
    # Tags
    "tag_function", "untag_function", "list_tags", "functions_by_tag",
    # Segments
    "add_segment", "edit_segment", "delete_segment",
    # Processor
    "get_processor_context", "set_processor_context",
    # Namespaces
    "create_namespace", "list_namespaces",
    # Function details
    "function_info", "function_items", "function_chunks", "set_function_color",
    # Patches
    "list_patches", "revert_patch", "patch_byte", "patch_word",
    "patch_dword", "patch_qword",
    # Problems
    "list_problems",
    # File mapping
    "file_offset", "file_offset_to_ea",
    # Graph exports
    "function_graph", "call_graph",
    # Switch info
    "get_switch_info",
    # Frames
    "function_frame", "list_stack_vars", "rename_stack_var",
    "set_stack_var_type", "list_reg_vars", "stack_var_xrefs",
    # Decompiler
    "decompile_lvars", "set_lvar_name", "set_lvar_type",
    "decompile_microcode", "decompiler_xrefs",
    # Debugger
    "debug_start", "debug_attach", "debug_detach", "debug_exit",
    "debug_continue", "debug_suspend", "debug_step_into", "debug_step_over",
    "debug_run_to", "debug_status", "debug_get_registers", "debug_set_register",
    "debug_read_memory", "debug_write_memory", "debug_breakpoints",
    "debug_add_breakpoint", "debug_delete_breakpoint", "debug_enable_breakpoint",
    "debug_stack_trace", "debug_modules", "debug_threads",
    # Type system
    "import_til", "export_til", "delete_type", "get_type_info",
    # Operand info
    "operand_struct_path",
    # Colors
    "set_color", "get_color", "del_color",
    # Exceptions
    "list_try_blocks",
    # Lumina
    "lumina_config", "lumina_pull_signatures", "lumina_push_signatures",
}


class TestHandlerRegistration:
    """Verify handler registration after calling register_all_tools."""

    @pytest.fixture(scope="module", autouse=True)
    def ensure_registered(self):
        """Ensure all tool handlers are registered once for this test module."""
        import sys
        from ida_rpc.server import main as server_main
        # Only register if handlers are missing
        if len(server_main._HANDLERS) < len(_EXPECTED_HANDLERS):
            # Remove cached tool modules to force re-registration
            for mod in list(sys.modules.keys()):
                if mod.startswith("ida_rpc.server.tools.") or mod == "ida_rpc.server.tools":
                    del sys.modules[mod]
            from ida_rpc.server.tools import register_all_tools
            register_all_tools()

    @pytest.mark.parametrize("cmd", sorted(_EXPECTED_HANDLERS))
    def test_handler_registered(self, cmd: str):
        from ida_rpc.server import main as server_main
        assert cmd in server_main._HANDLERS, f"Handler '{cmd}' is not registered"

    def test_handler_count_matches_expected(self):
        from ida_rpc.server import main as server_main
        actual = set(server_main._HANDLERS.keys())
        missing = _EXPECTED_HANDLERS - actual
        extra = actual - _EXPECTED_HANDLERS
        assert not missing, f"Missing handlers: {sorted(missing)}"
        assert not extra, f"Unexpected extra handlers: {sorted(extra)}"
