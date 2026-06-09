# (c) B. Kerler 2026, MIT license
"""Basefind tool: scan a flat 32-bit binary to determine its load base.

Embedded adaptation of the basefind algorithm.
"""

from __future__ import annotations

import array
import collections
import os
import re
import struct
import time
from dataclasses import dataclass

from ida_rpc.server.main import register_handler


PRINTABLE_RE_TEMPLATE = rb"[ -~\t\r\n]{%d,}"
U32_SIZE = 4
STRING_DELTA_MAX_SIZE = 16 * 1024 * 1024
EARLY_POINTER_SCAN_SIZE = 0x40
EARLY_TARGET_OFFSETS = (U32_SIZE,)


@dataclass(frozen=True)
class Candidate:
    base: int
    refs: int
    string_refs: int
    score: int
    source: str


def get_pointers(buf: bytes) -> list[int]:
    words = struct.iter_unpack("<I", memoryview(buf)[: len(buf) & ~3])
    return sorted({word for (word,) in words})


def get_words(buf: bytes) -> list[int]:
    words = struct.iter_unpack("<I", memoryview(buf)[: len(buf) & ~3])
    return [word for (word,) in words]


def get_word_array(buf: bytes) -> array.array:
    words = array.array("I")
    words.frombytes(memoryview(buf)[: len(buf) & ~3])
    if words.itemsize != U32_SIZE:
        raise RuntimeError("native unsigned int is not 32-bit")
    if struct.pack("=I", 1) != struct.pack("<I", 1):
        words.byteswap()
    return words


def get_strings(buf: bytes, min_length: int) -> list[int]:
    pattern = re.compile(PRINTABLE_RE_TEMPLATE % min_length)
    return [m.start() for m in pattern.finditer(buf)]


def get_differences(values: list[int]) -> array.array:
    differences = array.array("L")
    last = 0
    for value in values:
        differences.append(value - last)
        last = value
    return differences

def count_string_refs(ptrset: set[int], strings: list[int], base: int, samplerate: int = 1) -> int:
    if not strings:
        return 0

    count = 0
    step = max(1, samplerate)
    for string_offset in strings[::step]:
        if base + string_offset in ptrset:
            count += 1
    return count * step


def count_abs_refs(ptrs, base: int, size: int) -> int:
    end = base + size
    return sum(1 for ptr in ptrs if base <= (ptr & ~1) < end)


def string_delta_candidates(
    ptrs: list[int],
    strings: list[int],
    diff_len: int,
    samplerate: int,
) -> dict[int, tuple[int, str]]:
    if len(strings) <= diff_len or len(ptrs) <= diff_len:
        return {}

    str_diffs = get_differences(strings)
    ptr_diffs = get_differences(ptrs)
    ptr_diffs_b = ptr_diffs.tobytes()
    ptrset = set(ptrs)
    found: dict[int, tuple[int, str]] = {}

    for si in range(0, len(str_diffs) - diff_len):
        needle = str_diffs[si : si + diff_len].tobytes()
        pi = ptr_diffs_b.find(needle)
        if pi == -1:
            continue

        pi //= ptr_diffs.itemsize
        base = ptrs[pi] - strings[si]
        if base < 0 or base in found:
            continue

        found[base] = (count_string_refs(ptrset, strings, base, samplerate), "string-delta")

    return found


def absolute_candidates(
    ptrs,
    size: int,
    alignment: int,
    min_refs: int,
    max_results: int,
) -> dict[int, tuple[int, str]]:
    max_base = 0xFFFFFFFF - size
    events: collections.Counter[int] = collections.Counter()

    for ptr in ptrs:
        ptr &= ~1
        if ptr < size:
            continue

        top_nibble = ptr >> 28
        if top_nibble in (0xE, 0xF):
            continue

        start = max(0, ptr - size + 1)
        end = min(ptr, max_base)
        start = (start + alignment - 1) & ~(alignment - 1)
        end &= ~(alignment - 1)
        if start <= end:
            events[start] += 1
            if end <= max_base - alignment:
                events[end + alignment] -= 1

    if not events:
        return {}

    candidates: dict[int, tuple[int, str]] = {}
    refs = 0
    last_base: int | None = None
    best_base = 0
    best_refs = 0

    def flush_run() -> None:
        nonlocal best_base, best_refs
        if best_refs >= min_refs:
            candidates[best_base] = (best_refs, "absolute")
        best_refs = 0

    for base, delta in sorted(events.items()):
        if last_base is not None and base != last_base + alignment:
            flush_run()
        refs += delta
        if refs > best_refs:
            best_base = base
            best_refs = refs
        last_base = base
    flush_run()

    return dict(sorted(candidates.items(), key=lambda item: item[1][0], reverse=True)[: max_results * 16])


def early_pointer_candidates(
    buf: bytes,
    size: int,
    alignment: int,
    min_refs: int,
    max_results: int,
) -> dict[int, tuple[int, str]]:
    max_base = 0xFFFFFFFF - size
    candidates: collections.Counter[int] = collections.Counter()
    scan_size = min(len(buf) & ~(U32_SIZE - 1), EARLY_POINTER_SCAN_SIZE)

    for (ptr,) in struct.iter_unpack("<I", memoryview(buf)[:scan_size]):
        ptr &= ~1
        if ptr < size:
            continue

        top_nibble = ptr >> 28
        if top_nibble in (0xE, 0xF):
            continue

        for target_offset in EARLY_TARGET_OFFSETS:
            if target_offset >= len(buf):
                continue
            base = ptr - target_offset
            if 0 <= base <= max_base and base & (alignment - 1) == 0:
                candidates[base] += 1

    return {
        base: (refs, "early-pointer")
        for base, refs in sorted(candidates.items(), key=lambda item: item[1], reverse=True)[: max_results * 16]
        if refs >= min_refs
    }


def find_bases(
    buf: bytes,
    filename: str,
    str_len: int,
    diff_len: int,
    samplerate: int,
    min_abs_refs: int,
    max_results: int,
    filename_hints: bool,
) -> tuple[list[Candidate], int, int, bool]:
    strings = get_strings(buf, str_len)
    raw_ptrs = get_word_array(buf)
    ptrs = get_pointers(buf) if len(buf) <= STRING_DELTA_MAX_SIZE else []

    found = string_delta_candidates(ptrs, strings, diff_len, samplerate) if ptrs else {}
    forced_bases: set[int] = set(found)
    abs_ptrs = ptrs if ptrs else raw_ptrs
    for base, value in absolute_candidates(abs_ptrs, len(buf), U32_SIZE, min_abs_refs, max_results).items():
        refs, source = value
        old = found.get(base)
        if old is None or (old[1] == "absolute" and refs > old[0]):
            found[base] = (refs, source)
    for base, value in early_pointer_candidates(buf, len(buf), U32_SIZE, 1, max_results).items():
        old = found.get(base)
        if old is None or old[1] == "absolute":
            found[base] = (max(old[0] if old else 0, value[0]), value[1])
        forced_bases.add(base)

    if filename_hints:
        for match in re.finditer(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{5,16})(?![0-9a-fA-F])", filename):
            base = int(match.group(1), 16)
            if 0 <= base <= 0xFFFFFFFF - len(buf):
                forced_bases.add(base)
                found[base] = (max(found.get(base, (0, ""))[0], count_abs_refs(abs_ptrs, base, len(buf))), "filename-hint")

    ptrset = set(ptrs) if ptrs else set()
    results: list[Candidate] = []
    large_file = len(buf) > STRING_DELTA_MAX_SIZE
    prelim = sorted(found.items(), key=lambda item: item[1][0], reverse=True)[: max_results * 16]
    for base in forced_bases:
        item = (base, found[base])
        if item not in prelim:
            prelim.append(item)
    for base, (refs, source) in prelim:
        string_refs = count_string_refs(ptrset, strings, base, 1) if ptrset else 0
        if not large_file or source == "filename-hint":
            refs = max(refs, count_abs_refs(abs_ptrs, base, len(buf)))
        if refs < min_abs_refs and string_refs == 0:
            continue

        score = refs + string_refs * 8
        if source == "filename-hint":
            score += 10000
        elif source == "early-pointer":
            score += 10000
        results.append(Candidate(base, refs, string_refs, score, source))

    results.sort(key=lambda c: (c.score, c.refs, c.string_refs, -c.base), reverse=True)
    return results[:max_results], len(strings), len(ptrs) if ptrs else len(raw_ptrs), bool(ptrs)


def run_basefind(
    path: str,
    str_len: int = 10,
    diff_len: int = 10,
    samplerate: int = 20,
    min_abs_refs: int = 4,
    max_results: int = 30,
    filename_hints: bool = True,
) -> dict:
    """Run basefind on a file and return a JSON-serializable result."""
    with open(path, "rb") as f:
        buf = f.read()

    started = time.perf_counter()
    results, string_count, ptr_count, unique_words = find_bases(
        buf,
        os.path.basename(path),
        str_len,
        diff_len,
        samplerate,
        min_abs_refs,
        max_results,
        filename_hints,
    )
    elapsed = time.perf_counter() - started
    word_label = "unique_words" if unique_words else "raw_words"

    return {
        "ok": True,
        "result": {
            "file": os.path.basename(path),
            "size": len(buf),
            "strings": string_count,
            "pointers": ptr_count,
            "word_analysis": word_label,
            "elapsed_seconds": round(elapsed, 3),
            "candidates": [
                {
                    "base": f"0x{c.base:x}",
                    "refs": c.refs,
                    "string_refs": c.string_refs,
                    "score": c.score,
                    "source": c.source,
                }
                for c in results
            ],
            "count": len(results),
        },
    }


def _handle_basefind(ctx, args: dict) -> dict:
    path = args.get("path")
    if not path:
        # Try to get the original input file path from IDA
        try:
            import ida_loader
            path = ida_loader.get_path(ida_loader.PATH_TYPE_LDR)
        except (ImportError, AttributeError):
            path = None
        if not path:
            raise ValueError("Missing required argument: path (and could not determine input file from IDA)")

    return run_basefind(
        path,
        str_len=int(args.get("str_len", 10)),
        diff_len=int(args.get("diff_len", 10)),
        samplerate=int(args.get("samplerate", 20)),
        min_abs_refs=int(args.get("min_abs_refs", 4)),
        max_results=int(args.get("max_results", 30)),
        filename_hints=bool(args.get("filename_hints", True)),
    )["result"]


register_handler("basefind", _handle_basefind)
