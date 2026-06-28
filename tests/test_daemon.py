# (c) B. Kerler 2026, MIT license
"""Tests for IDA daemon launch command construction."""

from __future__ import annotations

from pathlib import Path

from ida_rpc.daemon import start_background
from ida_rpc.session import Session


def test_binary_launch_lets_ida_choose_loader_by_default(tmp_path, monkeypatch):
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    idat_exe = ida_dir / "idat"
    idat_exe.write_text("#!/bin/sh\n")

    binary = tmp_path / "raw.bin"
    binary.write_bytes(b"\x00" * 4)
    project = tmp_path / "raw.i64"
    socket_path = tmp_path / "ida-rpc-test.sock"
    captured = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd

        class Proc:
            pass

        return Proc()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr("ida_rpc.daemon.is_running", lambda _: True)

    session = Session(
        mode="headless",
        project_idb=project,
        socket_path=socket_path,
        ida_install_dir=ida_dir,
        arch="aarch64",
    )

    start_background(
        session,
        timeout=1,
        binary_path=binary,
        extra_ida_args=["-parm", "-b300000"],
    )

    assert "-parm" in captured["cmd"]
    assert captured["cmd"][0] == str(idat_exe)
    assert "-b300000" in captured["cmd"]
    assert "-TBinary file" not in captured["cmd"]
    assert f"-o{project}" in captured["cmd"]
    assert str(binary) in captured["cmd"]


def test_explicit_loader_is_passed_to_ida(tmp_path, monkeypatch):
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    idat_exe = ida_dir / "idat"
    idat_exe.write_text("#!/bin/sh\n")

    binary = tmp_path / "loader.bin"
    binary.write_bytes(b"\x00" * 4)
    project = tmp_path / "loader.i64"
    captured = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd

        class Proc:
            pass

        return Proc()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr("ida_rpc.daemon.is_running", lambda _: True)

    session = Session(
        mode="headless",
        project_idb=project,
        socket_path=tmp_path / "ida-rpc-test.sock",
        ida_install_dir=ida_dir,
        arch="aarch64",
    )

    start_background(
        session,
        timeout=1,
        binary_path=binary,
        extra_ida_args=["-parm", "-b300000", "-TRockchip MiniLoaderAll / LDR"],
    )

    assert captured["cmd"].count("-TBinary file") == 0
    assert captured["cmd"][0] == str(idat_exe)
    assert "-TRockchip MiniLoaderAll / LDR" in captured["cmd"]
