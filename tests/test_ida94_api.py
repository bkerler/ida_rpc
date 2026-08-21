"""Static guards for IDA 9.4 API compatibility."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
PROJECT_SOURCES = [ROOT / "ida_rpc", ROOT / "ida_rpc_plugin.py"]


@pytest.mark.parametrize(
    "pattern",
    (
        "ida_funcs.get_func(",
        "ida_segment.getseg(",
        "ida_segment.get_segm_name(",
        "ida_segment.get_segm_class(",
        "ida_segment.set_segm_name(",
        "ida_segment.set_segm_class(",
        "ida_segment.set_segm_addressing(",
        "ida_gdl.gen_flow_graph(",
        "ida_frame.get_frame_size(",
        "ida_frame.get_frame_retsize(",
        "ida_frame.get_func_frame(",
        "ida_frame.frame_off_args(",
        "ida_frame.frame_off_lvars(",
        "ida_frame.set_frame_member_type(",
        "ida_frame.build_stkvar_xrefs(",
        "ida_hexrays.decompile(",
    ),
)
def test_no_ida94_deprecated_calls(pattern: str):
    matches = []
    for source in PROJECT_SOURCES:
        paths = [source] if source.is_file() else source.rglob("*.py")
        for path in paths:
            text = path.read_text(encoding="utf-8")
            if pattern in text:
                matches.append(str(path.relative_to(ROOT)))
    assert not matches, f"deprecated IDA 9.4 call {pattern!r} remains in {matches}"


def test_ida94_install_exposes_replacement_apis():
    ida_root = Path(os.environ.get("IDA_INSTALL_DIR", "/home/bjk/bin/ida-pro-9.4"))
    if not (ida_root / "python").is_dir():
        pytest.skip("IDA Pro installation is not available")

    required = {
        "ida_segment.py": ("get_segment_info", "get_segment_name", "set_segment_info"),
        "ida_funcs.py": ("get_func_start", "get_func_entry_info", "calc_func_size_ea"),
        "ida_frame.py": ("get_frame_size_ea", "get_func_frame_ea", "set_frame_member_type_ea"),
        "ida_gdl.py": ("gen_flow_graph_ea", "qflow_chart_ea_t"),
        "ida_hexrays.py": ("decompile_function", "decomp_ranges_t"),
    }
    for module, symbols in required.items():
        text = (ida_root / "python" / module).read_text(encoding="utf-8")
        for symbol in symbols:
            assert symbol in text, f"IDA 9.4 replacement {symbol} missing from {module}"
