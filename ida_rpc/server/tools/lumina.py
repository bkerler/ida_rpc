# (c) B. Kerler 2026, MIT license
"""Lumina tools: read configured server state and push/pull function metadata."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_funcs
    import ida_ida
    import ida_lumina
    import ida_pro
    import ida_typeinf
    import idautils
    import idc
    return ida_funcs, ida_ida, ida_lumina, ida_pro, ida_typeinf, idautils, idc


def _func_eas(ctx, args: dict, ida_funcs, idautils) -> list[int]:
    target = args.get("target", "")
    all_functions = bool(args.get("all", False))
    if target and all_functions:
        raise ValueError("Use either target or all, not both")
    if target:
        return [ctx.find_function(target)]
    if all_functions:
        return list(idautils.Functions())
    raise ValueError("Missing required argument: target (or pass all=true)")


def _eavec(eas: list[int], ida_pro):
    vec = ida_pro.eavec_t()
    for ea in eas:
        vec.push_back(ea)
    return vec


def _prototype(ea: int, ida_funcs, ida_typeinf, idc) -> str:
    tif = ida_typeinf.tinfo_t()
    if ida_funcs.get_func_type(ea, tif):
        return ida_typeinf.print_tinfo(None, 0, 0, ida_typeinf.PRTYPE_1LINE, tif, None, None) or ""
    return idc.get_type(ea) or ""


def _code_name(code: int, ida_lumina) -> str:
    for name in ("PDRES_BADPTN", "PDRES_NOT_FOUND", "PDRES_ERROR", "PDRES_OK", "PDRES_ADDED"):
        if getattr(ida_lumina, name, None) == code:
            return name
    return f"0x{code:x}"


def _result_rows(eas: list[int], codes, ida_funcs, ida_lumina) -> list[dict]:
    rows = []
    code_list = list(codes) if codes is not None else []
    for i, ea in enumerate(eas):
        code = int(code_list[i]) if i < len(code_list) else None
        row = {
            "address": f"0x{ea:x}",
            "name": ida_funcs.get_func_name(ea) or "",
        }
        if code is not None:
            row["code"] = code
            row["status"] = _code_name(code, ida_lumina)
        rows.append(row)
    return rows


def _connected_lumina_client(ida_lumina, secondary: bool = False):
    flags = ida_lumina.LFEAT_SECONDARY_MD if secondary else ida_lumina.LFEAT_PRIMARY_MD
    client = ida_lumina.get_server_connection2(flags)
    if not client:
        which = "secondary" if secondary else "primary"
        raise RuntimeError(f"Could not connect to configured {which} Lumina server")
    return client


def _handle_lumina_config(ctx, args: dict) -> dict:
    _, _, ida_lumina, _, _, _, _ = _ida()

    def collect():
        secondary = bool(args.get("secondary", False))
        feature = ida_lumina.LFEAT_SECONDARY_MD if secondary else ida_lumina.LFEAT_PRIMARY_MD
        client = ida_lumina.get_server_connection2(feature | ida_lumina.GCSF_NO_CONNECT)
        result = {
            "configured_by": {
                "ida_options": "Options > General > Lumina",
                "primary_override": "-Olumina:host=<host>:port=<port>[:user=<user>[:pass=<pass>]]",
                "secondary_override": "-Osecondary_lumina:host=<host>:port=<port>",
            },
            "secondary": secondary,
            "client_available": bool(client),
            "secrets_redacted": True,
        }
        return result

    return ctx.run_on_main_thread(collect)


def _handle_lumina_pull_signatures(ctx, args: dict) -> dict:
    ida_funcs, _, ida_lumina, ida_pro, ida_typeinf, idautils, idc = _ida()
    apply = bool(args.get("apply", False))
    seen_file = bool(args.get("seen_file", False))
    secondary = bool(args.get("secondary", False))
    force = bool(args.get("force", False))

    def pull():
        eas = _func_eas(ctx, args, ida_funcs, idautils)
        before = {ea: _prototype(ea, ida_funcs, ida_typeinf, idc) for ea in eas}
        flags = 0
        if apply:
            flags |= ida_lumina.PULL_MD_AUTO_APPLY
        if seen_file:
            flags |= ida_lumina.PULL_MD_SEEN_FILE
        client = _connected_lumina_client(ida_lumina, secondary)
        res = client.pull_md(_eavec(eas, ida_pro), flags)
        if apply and force and res is not None:
            apply_flags = getattr(ida_lumina, "AMDF_FORCE", 0)
            for i, md in enumerate(res.results):
                if i < len(eas):
                    ida_lumina.apply_metadata(eas[i], md, apply_flags)
        after = {ea: _prototype(ea, ida_funcs, ida_typeinf, idc) for ea in eas}
        rows = _result_rows(eas, getattr(res, "codes", None), ida_funcs, ida_lumina)
        for row in rows:
            ea = int(row["address"], 16)
            row["old_signature"] = before.get(ea, "")
            row["new_signature"] = after.get(ea, "")
            row["changed"] = before.get(ea, "") != after.get(ea, "")
        return {
            "applied": apply,
            "secondary": secondary,
            "count": len(rows),
            "functions": rows,
        }

    result = ctx.run_on_main_thread(pull)
    if apply:
        ctx.save()
    return result


def _handle_lumina_push_signatures(ctx, args: dict) -> dict:
    ida_funcs, _, ida_lumina, ida_pro, ida_typeinf, idautils, idc = _ida()
    secondary = bool(args.get("secondary", False))
    mode = args.get("mode", "better")

    def push():
        eas = _func_eas(ctx, args, ida_funcs, idautils)
        opts = ida_lumina.push_md_opts_t()
        opts.eas = _eavec(eas, ida_pro)
        opts.min_func_size = int(args.get("min_func_size", 0) or 0)
        mode_map = {
            "better": ida_lumina.PMF_PUSH_OVERRIDE_IF_BETTER_OR_DIFFERENT,
            "override": ida_lumina.PMF_PUSH_OVERRIDE,
            "no-override": ida_lumina.PMF_PUSH_DO_NOT_OVERRIDE,
            "merge": ida_lumina.PMF_PUSH_MERGE,
        }
        if mode not in mode_map:
            raise ValueError(f"Invalid mode '{mode}'")
        client = _connected_lumina_client(ida_lumina, secondary)
        res = ida_lumina.push_md_result_t()
        ok = bool(client.push_md(res, opts, None, mode_map[mode]))
        pushed_eas = [int(ea) for ea in getattr(res, "eas", [])] or eas
        rows = _result_rows(pushed_eas, getattr(res, "codes", None), ida_funcs, ida_lumina)
        for row in rows:
            ea = int(row["address"], 16)
            row["signature"] = _prototype(ea, ida_funcs, ida_typeinf, idc)
        return {
            "ok": ok,
            "secondary": secondary,
            "mode": mode,
            "count": len(rows),
            "functions": rows,
        }

    return ctx.run_on_main_thread(push)


register_handler("lumina_config", _handle_lumina_config)
register_handler("lumina_pull_signatures", _handle_lumina_pull_signatures)
register_handler("lumina_push_signatures", _handle_lumina_push_signatures)
