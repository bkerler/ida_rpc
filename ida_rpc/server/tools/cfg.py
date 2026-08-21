# (c) B. Kerler 2026, MIT license
"""Control-flow graph tools: basic blocks."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_gdl
    import ida_funcs
    import ida_idaapi
    import idautils
    import ida_bytes
    return ida_gdl, ida_funcs, ida_idaapi, idautils, ida_bytes


def _handle_basic_blocks(ctx, args: dict) -> dict:
    ida_gdl, ida_funcs, ida_idaapi, idautils, ida_bytes = _ida()

    _ = args.get("binary", "")
    func_name = args.get("func", "")
    limit = min(int(args.get("limit", 500)), 5000)

    if not func_name:
        raise ValueError("Missing required argument: func")

    func_ea = ctx.find_function(func_name)
    if ida_funcs.get_func_start(func_ea) == ida_idaapi.BADADDR:
        raise ValueError(f"Function not found at 0x{func_ea:x}")

    fc = ida_gdl.FlowChart(bounds=(func_ea, func_ea + ida_funcs.calc_func_size_ea(func_ea)))
    blocks = []
    total_edges = 0

    for block in fc:
        if len(blocks) >= limit:
            break

        # Count instructions in block
        instr_count = 0
        for head in idautils.Heads(block.start_ea, block.end_ea):
            if ida_bytes.is_code(ida_bytes.get_flags(head)):
                instr_count += 1

        # Block type classification
        block_type = "normal"
        type_map = {
            ida_gdl.fcb_normal: "normal",
            ida_gdl.fcb_indjump: "indirect_jump",
            ida_gdl.fcb_ret: "return",
            ida_gdl.fcb_cndret: "conditional_return",
            ida_gdl.fcb_noret: "no_return",
            ida_gdl.fcb_enoret: "external_no_return",
            ida_gdl.fcb_extern: "external",
            ida_gdl.fcb_error: "error",
        }
        if hasattr(block, "type") and block.type in type_map:
            block_type = type_map[block.type]

        successors = []
        for succ in block.succs():
            successors.append({
                "address": f"0x{succ.start_ea:x}",
                "type": "normal",
            })
            total_edges += 1

        predecessors = []
        for pred in block.preds():
            predecessors.append(f"0x{pred.start_ea:x}")

        blocks.append({
            "start": f"0x{block.start_ea:x}",
            "end": f"0x{block.end_ea - 1:x}",
            "size": block.end_ea - block.start_ea,
            "instructions": instr_count,
            "block_type": block_type,
            "successors": successors,
            "predecessors": predecessors,
        })

    return {
        "name": ida_funcs.get_func_name(func_ea),
        "address": f"0x{func_ea:x}",
        "blocks": blocks,
        "num_blocks": len(blocks),
        "edges": total_edges,
    }


register_handler("basic_blocks", _handle_basic_blocks)
