# (c) B. Kerler 2026, MIT license
"""Tests for IDA daemon launch command construction."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ida_rpc.daemon import start_background
from ida_rpc.session import Session, load, session_file_path


def test_binary_launch_lets_ida_choose_loader_by_default(tmp_path, monkeypatch):
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    idat_exe = ida_dir / ("idat.exe" if os.name == "nt" else "idat")
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
    assert "--accept-eula" not in captured["cmd"]
    assert any(arg.startswith("-L") for arg in captured["cmd"])
    assert "-TBinary file" not in captured["cmd"]
    assert f"-o{project}" in captured["cmd"]
    assert str(binary) in captured["cmd"]


def test_explicit_loader_is_passed_to_ida(tmp_path, monkeypatch):
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    idat_exe = ida_dir / ("idat.exe" if os.name == "nt" else "idat")
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


def test_early_ida_exit_reports_code_and_ida_log(tmp_path, monkeypatch):
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    (ida_dir / ("idat.exe" if os.name == "nt" else "idat")).touch()
    project = tmp_path / "sample.i64"
    project.touch()
    launch_log = tmp_path / "launch.log"
    ida_log = tmp_path / "ida.log"
    monkeypatch.setattr("ida_rpc.daemon._startup_log_paths", lambda _: (launch_log, ida_log))
    monkeypatch.setattr("ida_rpc.daemon.is_running", lambda _: False)

    class ExitedProcess:
        pid = 1234

        def poll(self):
            return 17

    def fake_popen(cmd, **kwargs):
        ida_log.write_text("bind failed: WinError 10013\n", encoding="utf-8")
        return ExitedProcess()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    session = Session("headless", project, tmp_path / "endpoint.sock", ida_install_dir=ida_dir)
    with pytest.raises(RuntimeError, match="exit code 17") as exc:
        start_background(session, timeout=10)
    assert "WinError 10013" in str(exc.value)
    assert not session_file_path(project).exists()


def test_timeout_reports_live_process_and_keeps_session(tmp_path, monkeypatch):
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    (ida_dir / ("idat.exe" if os.name == "nt" else "idat")).touch()
    project = tmp_path / "sample.i64"
    project.touch()
    monkeypatch.setattr(
        "ida_rpc.daemon._startup_log_paths",
        lambda _: (tmp_path / "launch.log", tmp_path / "ida.log"),
    )
    monkeypatch.setattr("ida_rpc.daemon.is_running", lambda _: False)

    class RunningProcess:
        pid = 4321

        def poll(self):
            return None

    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: RunningProcess())
    session = Session("headless", project, tmp_path / "endpoint.sock", ida_install_dir=ida_dir)
    with pytest.raises(TimeoutError, match="process 4321 is still running"):
        start_background(session, timeout=0.01)
    assert load(project) is not None


def test_launch_uses_original_path_spelling(tmp_path, monkeypatch):
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    (ida_dir / ("idat.exe" if os.name == "nt" else "idat")).touch()
    project = tmp_path / "sample.i64"
    project.touch()
    captured = {}

    class RunningProcess:
        pid = 1234

        def poll(self):
            return None

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        return RunningProcess()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr("ida_rpc.daemon.is_running", lambda _: True)
    session = Session(
        "headless", project, tmp_path / "endpoint.sock",
        ida_install_dir=ida_dir, launch_project_idb=tmp_path / "SAMPLE~1.i64",
    )
    start_background(session, timeout=1)
    assert str(session.launch_project_idb) == captured["cmd"][-1]
    assert load(project).launch_project_idb == session.launch_project_idb
