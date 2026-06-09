# (c) B. Kerler 2026, MIT license
"""Assembler tool: assemble instruction text at an address.

Tries Keystone Engine first, falls back to any available IDA assembler.
"""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _get_ks_arch_mode():
    """Return (arch, mode) tuple for Keystone based on current IDA processor."""
    import ida_ida
    proc = ida_ida.inf_get_procname().lower()
    is_64 = ida_ida.inf_is_64bit()
    is_be = ida_ida.inf_is_be()

    try:
        from keystone import (
            KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_X86, KS_ARCH_MIPS, KS_ARCH_PPC,
            KS_MODE_ARM, KS_MODE_THUMB, KS_MODE_LITTLE_ENDIAN, KS_MODE_BIG_ENDIAN,
            KS_MODE_32, KS_MODE_64, KS_MODE_MIPS32, KS_MODE_MIPS64,
        )
    except ImportError:
        return None

    endian = KS_MODE_BIG_ENDIAN if is_be else KS_MODE_LITTLE_ENDIAN

    if proc.startswith("arm"):
        if is_64:
            return (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        return (KS_ARCH_ARM, KS_MODE_THUMB if "thumb" in proc else KS_MODE_ARM)
    elif proc.startswith("x86") or proc.startswith("metapc"):
        return (KS_ARCH_X86, KS_MODE_64 if is_64 else KS_MODE_32)
    elif proc.startswith("mips"):
        return (KS_ARCH_MIPS, (KS_MODE_MIPS64 if is_64 else KS_MODE_MIPS32) | endian)
    elif proc.startswith("ppc") or proc.startswith("powerpc"):
        return (KS_ARCH_PPC, endian)

    return None


def _handle_assemble(ctx, args: dict) -> dict:
    _ = args.get("binary", "")
    address = args.get("address", "")
    instruction = args.get("instruction", "")

    if not address:
        raise ValueError("Missing required argument: address")
    if not instruction:
        raise ValueError("Missing required argument: instruction")

    addr = ctx.resolve_address(address)

    def do_assemble():
        ks_tuple = _get_ks_arch_mode()
        if ks_tuple is None:
            raise RuntimeError(
                "Keystone engine is not installed or unsupported processor. "
                "Install it with: pip install keystone-engine"
            )

        from keystone import Ks, KsError
        ks = Ks(*ks_tuple)
        try:
            encoding, count = ks.asm(instruction, addr)
        except KsError as e:
            raise ValueError(f"Assembly failed: {e}")

        if not encoding:
            raise ValueError(f"Assembly produced no bytes for: {instruction}")

        data = bytes(encoding)

        # Write bytes to IDA
        import ida_bytes
        for i, b in enumerate(data):
            ida_bytes.patch_byte(addr + i, b)

        return {
            "address": f"0x{addr:x}",
            "instruction": instruction,
            "bytes": data.hex(),
            "length": len(data),
            "count": count,
        }

    result = ctx.run_on_main_thread(do_assemble)
    ctx.save()
    return result


register_handler("assemble", _handle_assemble)
