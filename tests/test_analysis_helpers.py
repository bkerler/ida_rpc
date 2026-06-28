# (c) B. Kerler 2026, MIT license
"""Unit tests for analysis helper normalization."""

from ida_rpc.server.tools.analysis import _arch_name


def test_arch_name_reports_aarch64_for_64_bit_arm_processor():
    assert _arch_name("ARM", 64) == "aarch64"
    assert _arch_name("arm", 64) == "aarch64"


def test_arch_name_keeps_32_bit_arm_processor():
    assert _arch_name("ARM", 32) == "ARM"
    assert _arch_name("arm", 32) == "arm"


def test_arch_name_keeps_non_arm_processor():
    assert _arch_name("metapc", 64) == "metapc"
