# (c) B. Kerler 2026, MIT license
"""Tool handlers for ida-rpc."""


def register_all_tools():
    """Register all tool command handlers."""
    # Import each module to trigger handler registration
    from ida_rpc.server.tools import analysis
    from ida_rpc.server.tools import decompiler
    from ida_rpc.server.tools import search
    from ida_rpc.server.tools import xrefs
    from ida_rpc.server.tools import navigation
    from ida_rpc.server.tools import modifications
    from ida_rpc.server.tools import memory
    from ida_rpc.server.tools import disassembly
    from ida_rpc.server.tools import data_types
    from ida_rpc.server.tools import bookmarks
    from ida_rpc.server.tools import cfg
    from ida_rpc.server.tools import tags
    from ida_rpc.server.tools import segments
    from ida_rpc.server.tools import processor
    from ida_rpc.server.tools import namespaces
    from ida_rpc.server.tools import assembler
    from ida_rpc.server.tools import basefind
    from ida_rpc.server.tools import function_details
    from ida_rpc.server.tools import patches
    from ida_rpc.server.tools import problems
    from ida_rpc.server.tools import file_mapping
    from ida_rpc.server.tools import graphs
    from ida_rpc.server.tools import switch_info
    from ida_rpc.server.tools import frames
    from ida_rpc.server.tools import debugger
    from ida_rpc.server.tools import operand_info
    from ida_rpc.server.tools import colors
    from ida_rpc.server.tools import exceptions
