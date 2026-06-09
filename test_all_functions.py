#!/usr/bin/env python3
# (c) B. Kerler 2026, MIT license
"""Integration test script that exercises every ida-rpc command."""

import json
import socket
import sys
import traceback
from pathlib import Path

SOCK_PATH = Path("/tmp/ida-rpc-541666b8.sock")


def send(cmd: str, args: dict | None = None, timeout: float = 30.0):
    req = {"id": "test", "cmd": cmd, "args": args or {}}
    data = (json.dumps(req) + "\n").encode()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(str(SOCK_PATH))
    try:
        sock.sendall(data)
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        sock.close()
    return json.loads(buf.decode().strip())


def test(name, cmd, args=None, timeout=30.0, check=None, expect_fail=False):
    try:
        resp = send(cmd, args, timeout=timeout)
        if resp.get("ok"):
            result = resp.get("result", {})
            if check:
                check(result)
            if expect_fail:
                print(f"  UNEX  {name}: expected failure but succeeded")
                return False
            print(f"  PASS  {name}")
            return True
        else:
            if expect_fail:
                print(f"  XFAIL {name}: {resp.get('error')} - {resp.get('message')}")
                return True
            print(f"  FAIL  {name}: {resp.get('error')} - {resp.get('message')}")
            return False
    except Exception as e:
        if expect_fail:
            print(f"  XPASS {name}: {e}")
            return True
        print(f"  ERR   {name}: {e}")
        traceback.print_exc()
        return False


def main():
    if not SOCK_PATH.exists():
        print(f"Socket not found: {SOCK_PATH}")
        sys.exit(1)

    passed = 0
    failed = 0

    # --- Basic / Analysis (read-only) ---
    print("\n=== Analysis ===")
    if test("ping", "ping", {}, check=lambda r: r.get("status") == "alive"):
        passed += 1
    else:
        failed += 1

    for name, cmd, args in [
        ("metadata", "metadata", {}),
        ("functions", "functions", {"limit": 5}),
        ("imports", "imports", {}),
        ("exports", "exports", {}),
        ("relocations", "relocations", {}),
        ("list_calling_conventions", "list_calling_conventions", {}),
        ("list_binaries", "list_binaries", {}),
    ]:
        if test(name, cmd, args):
            passed += 1
        else:
            failed += 1

    # --- Memory ---
    print("\n=== Memory ===")
    for name, cmd, args in [
        ("memory_map", "memory_map", {}),
        ("list_segments", "list_segments", {}),
        ("read_bytes", "read_bytes", {"address": "0x0", "length": 16}),
    ]:
        if test(name, cmd, args):
            passed += 1
        else:
            failed += 1

    # --- Navigation / Disassembly ---
    print("\n=== Navigation / Disassembly ===")
    if test("goto", "goto", {"target": "0x0", "target_type": "address"}):
        passed += 1
    else:
        failed += 1

    if test("disassemble", "disassemble", {"address": "0x0", "count": 5}):
        passed += 1
    else:
        failed += 1

    # --- Xrefs ---
    print("\n=== Xrefs ===")
    for name, cmd, args in [
        ("xrefs_to", "xrefs_to", {"target": "0x0"}),
        ("xrefs_from", "xrefs_from", {"target": "0x0"}),
    ]:
        if test(name, cmd, args):
            passed += 1
        else:
            failed += 1

    # --- Search ---
    print("\n=== Search ===")
    for name, cmd, args in [
        ("find_bytes", "find_bytes", {"pattern": "00 00 00 00"}),
        ("strings", "strings", {"limit": 5}),
        ("symbols", "symbols", {"query": "start", "limit": 5}),
    ]:
        if test(name, cmd, args):
            passed += 1
        else:
            failed += 1

    # --- CFG ---
    print("\n=== CFG ===")
    if test("basic_blocks", "basic_blocks", {"func": "start"}):
        passed += 1
    else:
        failed += 1

    # --- Processor ---
    print("\n=== Processor ===")
    if test("get_processor_context", "get_processor_context", {}):
        passed += 1
    else:
        failed += 1
    if test("get_processor_context reg", "get_processor_context", {"reg": "T"}):
        passed += 1
    else:
        failed += 1
    # set_processor_context may fail on architectures without segment registers
    if test("set_processor_context", "set_processor_context",
            {"address": "0x20", "register": "T", "value": 0}, expect_fail=True):
        passed += 1
    else:
        failed += 1

    # --- Decompiler ---
    print("\n=== Decompiler ===")
    for name, cmd, args, to in [
        ("decompile", "decompile", {"func": "start"}, 120.0),
        ("decompile_all", "decompile_all", {"limit": 2}, 120.0),
    ]:
        if test(name, cmd, args, timeout=to):
            passed += 1
        else:
            failed += 1

    # --- Data Types (read-only first) ---
    print("\n=== Data Types ===")
    for name, cmd, args, to in [
        ("list_data_types", "list_data_types", {}, 120.0),
        ("list_labels", "list_labels", {"address": "0x20"}, 60.0),
        ("list_equates", "list_equates", {}, 60.0),
    ]:
        if test(name, cmd, args, timeout=to):
            passed += 1
        else:
            failed += 1

    # --- Bookmarks ---
    print("\n=== Bookmarks ===")
    for name, cmd, args in [
        ("set_bookmark", "set_bookmark", {"address": "0x20", "description": "test"}),
        ("list_bookmarks", "list_bookmarks", {}),
        ("remove_bookmark", "remove_bookmark", {"address": "0x20"}),
    ]:
        if test(name, cmd, args):
            passed += 1
        else:
            failed += 1

    # --- Namespaces ---
    print("\n=== Namespaces ===")
    for name, cmd, args in [
        ("create_namespace", "create_namespace", {"namespace": "test_ns"}),
        ("list_namespaces", "list_namespaces", {}),
    ]:
        if test(name, cmd, args):
            passed += 1
        else:
            failed += 1

    # --- Tags ---
    print("\n=== Tags ===")
    for name, cmd, args in [
        ("tag_function", "tag_function", {"target": "start", "tag": "test_tag"}),
        ("list_tags", "list_tags", {}),
        ("functions_by_tag", "functions_by_tag", {"tag": "test_tag"}),
        ("untag_function", "untag_function", {"target": "start", "tag": "test_tag"}),
    ]:
        if test(name, cmd, args):
            passed += 1
        else:
            failed += 1

    # --- Assembler ---
    print("\n=== Assembler ===")
    if test("assemble", "assemble", {"address": "0x20", "instruction": "NOP"}):
        passed += 1
    else:
        failed += 1

    # --- Segments (careful - read-only list done above) ---
    print("\n=== Segments ===")
    # Skip destructive segment tests on a real database

    # --- Modifications (careful) ---
    print("\n=== Modifications ===")
    # These are destructive; skip on real DB

    # --- Save ---
    print("\n=== Save ===")
    if test("save", "save", {}):
        passed += 1
    else:
        failed += 1

    # --- Stop ---
    print("\n=== Stop ===")
    if test("stop", "stop", {}):
        passed += 1
    else:
        failed += 1

    print(f"\n{'='*40}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total:  {passed + failed}")

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
