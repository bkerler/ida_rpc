# (c) B. Kerler 2026, MIT license
"""Data-type authoring tools: structs, unions, enums, labels, equates."""

from __future__ import annotations

from ida_rpc.server.main import register_handler


def _ida():
    import ida_typeinf
    import ida_name
    import ida_idaapi
    import idautils
    import ida_bytes
    import idc
    return ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc


def _get_struct_members(sid, ida_typeinf):
    """Return list of member dicts for a struct/union by sid."""
    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(sid):
        return []
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return []
    members = []
    for udm in udt:
        if not udm.is_gap():
            members.append({
                "offset": udm.offset // 8,
                "name": udm.name,
                "type_str": str(udm.type) if not udm.type.empty() else "",
                "size": udm.size // 8,
            })
    return members


def _find_udm_index(sid, field_name, ida_typeinf):
    """Find the UDM index of a struct member by name. Returns index or -1."""
    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(sid):
        return -1
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return -1
    for i, udm in enumerate(udt):
        if udm.name == field_name:
            return i
    return -1


def _get_enum_members(eid, ida_typeinf):
    """Return list of member dicts for an enum by eid."""
    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(eid):
        return []
    ei = ida_typeinf.enum_type_data_t()
    if not tif.get_enum_details(ei):
        return []
    members = []
    for em in ei:
        members.append({
            "name": em.name,
            "value": em.value,
        })
    return members


def _handle_create_struct(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    struct_name = args.get("name", "")
    fields = args.get("fields", [])
    if_not_exists = bool(args.get("if_not_exists", False))
    or_replace = bool(args.get("or_replace", False))

    if not struct_name:
        raise ValueError("Missing required argument: name")

    def do_create():
        sid = idc.get_struc_id(struct_name)
        if sid != ida_idaapi.BADADDR:
            if if_not_exists:
                return _summarize_struct(sid, already_existed=True, ida_typeinf=ida_typeinf)
            elif or_replace:
                idc.del_struc(sid)
            else:
                raise ValueError(f"Struct '{struct_name}' already exists")

        sid = idc.add_struc(0, struct_name, False)
        if sid == ida_idaapi.BADADDR:
            raise RuntimeError(f"Failed to create struct '{struct_name}'")

        for fld in fields:
            ftype = fld.get("type", "")
            fname = fld.get("name", "")
            if not ftype or not fname:
                raise ValueError(f"Each field must have 'type' and 'name': {fld}")

            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, ftype, ida_typeinf.PT_TYP):
                raise ValueError(f"Failed to parse field type: {ftype}")

            size = tif.get_size()
            if size == ida_idaapi.BADADDR or size <= 0:
                size = 1

            offset = idc.get_struc_size(sid)
            idc.add_struc_member(sid, fname, offset, ida_bytes.FF_DATA, 0, size)

            # Set detailed type if parsing succeeded
            udm_idx = _find_udm_index(sid, fname, ida_typeinf)
            if udm_idx >= 0:
                struct_tif = ida_typeinf.tinfo_t()
                if struct_tif.get_type_by_tid(sid):
                    struct_tif.set_udm_type(udm_idx, tif, 0)

        return _summarize_struct(sid, already_existed=False, ida_typeinf=ida_typeinf)

    def _summarize_struct(sid, already_existed=False, ida_typeinf=None):
        fields_out = _get_struct_members(sid, ida_typeinf)
        size = idc.get_struc_size(sid)
        return {
            "name": struct_name,
            "path": f"/{struct_name}",
            "size": size,
            "fields": fields_out,
            "already_existed": already_existed,
        }

    result = ctx.run_on_main_thread(do_create)
    ctx.save()
    return result


def _handle_create_union(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    union_name = args.get("name", "")
    fields = args.get("fields", [])
    if_not_exists = bool(args.get("if_not_exists", False))
    or_replace = bool(args.get("or_replace", False))

    if not union_name:
        raise ValueError("Missing required argument: name")

    def do_create():
        sid = idc.get_struc_id(union_name)
        if sid != ida_idaapi.BADADDR:
            if if_not_exists:
                return _summarize_union(sid, already_existed=True, ida_typeinf=ida_typeinf)
            elif or_replace:
                idc.del_struc(sid)
            else:
                raise ValueError(f"Union '{union_name}' already exists")

        sid = idc.add_struc(0, union_name, True)
        if sid == ida_idaapi.BADADDR:
            raise RuntimeError(f"Failed to create union '{union_name}'")

        for fld in fields:
            ftype = fld.get("type", "")
            fname = fld.get("name", "")
            if not ftype or not fname:
                raise ValueError(f"Each field must have 'type' and 'name': {fld}")

            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, ftype, ida_typeinf.PT_TYP):
                raise ValueError(f"Failed to parse field type: {ftype}")

            size = tif.get_size()
            if size == ida_idaapi.BADADDR or size <= 0:
                size = 1

            idc.add_struc_member(sid, fname, 0, ida_bytes.FF_DATA, 0, size)

            udm_idx = _find_udm_index(sid, fname, ida_typeinf)
            if udm_idx >= 0:
                union_tif = ida_typeinf.tinfo_t()
                if union_tif.get_type_by_tid(sid):
                    union_tif.set_udm_type(udm_idx, tif, 0)

        return _summarize_union(sid, already_existed=False, ida_typeinf=ida_typeinf)

    def _summarize_union(sid, already_existed=False, ida_typeinf=None):
        fields_out = _get_struct_members(sid, ida_typeinf)
        size = idc.get_struc_size(sid)
        return {
            "name": union_name,
            "path": f"/{union_name}",
            "size": size,
            "fields": fields_out,
            "already_existed": already_existed,
        }

    result = ctx.run_on_main_thread(do_create)
    ctx.save()
    return result


def _handle_create_enum(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    enum_name = args.get("name", "")
    values = args.get("values", [])
    size = int(args.get("size", 4))
    if_not_exists = bool(args.get("if_not_exists", False))
    or_replace = bool(args.get("or_replace", False))

    if not enum_name:
        raise ValueError("Missing required argument: name")

    def do_create():
        eid = idc.get_enum(enum_name)
        if eid != ida_idaapi.BADADDR:
            if if_not_exists:
                return _summarize_enum(eid, already_existed=True, ida_typeinf=ida_typeinf)
            elif or_replace:
                idc.del_enum(eid)
            else:
                raise ValueError(f"Enum '{enum_name}' already exists")

        eid = idc.add_enum(0, enum_name, ida_bytes.hex_flag())
        if eid == ida_idaapi.BADADDR:
            raise RuntimeError(f"Failed to create enum '{enum_name}'")

        for v in values:
            vname = v.get("name", "")
            vvalue = v.get("value", 0)
            if not vname:
                continue
            idc.add_enum_member(eid, vname, vvalue)

        return _summarize_enum(eid, already_existed=False, ida_typeinf=ida_typeinf)

    def _summarize_enum(eid, already_existed=False, ida_typeinf=None):
        members = _get_enum_members(eid, ida_typeinf)
        return {
            "name": enum_name,
            "path": f"/{enum_name}",
            "size": size,
            "values": members,
            "already_existed": already_existed,
        }

    result = ctx.run_on_main_thread(do_create)
    ctx.save()
    return result


def _handle_list_data_types(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    category = args.get("category", "all")
    query = args.get("query", "").lower()
    limit = int(args.get("limit", 200))

    data_types = []

    ordinal_limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, ordinal_limit):
        if len(data_types) >= limit:
            break
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(None, ordinal):
            continue

        name = idc.get_numbered_type_name(ordinal) or ""
        if not name:
            continue
        if query and query not in name.lower():
            continue

        if category in ("all", "struct") and tif.is_struct():
            data_types.append({
                "name": name,
                "path": f"/{name}",
                "category": "struct",
                "size": tif.get_size(),
            })
        elif category in ("all", "union") and tif.is_union():
            data_types.append({
                "name": name,
                "path": f"/{name}",
                "category": "union",
                "size": tif.get_size(),
            })
        elif category in ("all", "enum") and tif.is_enum():
            data_types.append({
                "name": name,
                "path": f"/{name}",
                "category": "enum",
                "size": tif.get_enum_width(),
            })

    return {
        "data_types": data_types,
        "count": len(data_types),
    }


def _handle_list_labels(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    address = args.get("address", "")
    end_addr = args.get("end", "")
    limit = int(args.get("limit", 100))

    results = []

    if end_addr:
        start = ctx.resolve_address(address)
        end = ctx.resolve_address(end_addr)
        ea = start
        while ea <= end and len(results) < limit:
            name = ida_name.get_name(ea)
            if name:
                results.append({"address": f"0x{ea:x}", "name": name})
            ea = ida_bytes.next_head(ea, end + 1)
    else:
        addr = ctx.resolve_address(address)
        name = ida_name.get_name(addr)
        if name:
            results.append({"address": f"0x{addr:x}", "name": name})

    return {
        "labels": results,
        "count": len(results),
    }


def _handle_modify_struct(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    struct_name = args.get("name", "")
    action = args.get("action", "")
    field_name = args.get("field", "")
    new_field_name = args.get("new_field_name", "")
    new_type = args.get("new_type", "")
    new_comment = args.get("comment", "")

    if not struct_name:
        raise ValueError("Missing required argument: name")
    if not action:
        raise ValueError("Missing required argument: action")
    if not field_name:
        raise ValueError("Missing required argument: field")

    def do_modify():
        sid = idc.get_struc_id(struct_name)
        if sid == ida_idaapi.BADADDR:
            raise ValueError(f"Struct '{struct_name}' not found")

        udm_idx = _find_udm_index(sid, field_name, ida_typeinf)
        if udm_idx < 0:
            raise ValueError(f"Field '{field_name}' not found in struct '{struct_name}'")

        # Get member offset for idc operations
        tif = ida_typeinf.tinfo_t()
        if not tif.get_type_by_tid(sid):
            raise ValueError("Failed to get struct type")
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            raise ValueError("Failed to get struct details")
        member_offset = None
        for udm in udt:
            if udm.name == field_name:
                member_offset = udm.offset // 8
                break
        if member_offset is None:
            raise ValueError(f"Field '{field_name}' offset not found")

        if action == "rename":
            if not new_field_name:
                raise ValueError("Missing required argument: new_field_name")
            success = idc.set_member_name(sid, member_offset, new_field_name)
            return {
                "action": "rename",
                "struct": struct_name,
                "field": field_name,
                "new_name": new_field_name,
                "success": success,
            }

        elif action == "retype":
            if not new_type:
                raise ValueError("Missing required argument: new_type")
            new_tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(new_tif, None, new_type, ida_typeinf.PT_TYP):
                raise ValueError(f"Failed to parse type: {new_type}")
            success = tif.set_udm_type(udm_idx, new_tif, 0)
            return {
                "action": "retype",
                "struct": struct_name,
                "field": field_name,
                "new_type": new_type,
                "success": success,
            }

        elif action == "delete":
            success = idc.del_struc_member(sid, member_offset)
            return {
                "action": "delete",
                "struct": struct_name,
                "field": field_name,
                "success": success,
            }

        elif action == "set_comment":
            success = idc.set_member_cmt(sid, member_offset, new_comment, True)
            return {
                "action": "set_comment",
                "struct": struct_name,
                "field": field_name,
                "comment": new_comment,
                "success": success,
            }

        else:
            raise ValueError(f"Invalid action '{action}'. Use: rename, retype, delete, set_comment")

    result = ctx.run_on_main_thread(do_modify)
    ctx.save()
    return result


def _handle_modify_enum(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    enum_name = args.get("name", "")
    action = args.get("action", "")
    member_name = args.get("member", "")
    member_value = args.get("value", 0)

    if not enum_name:
        raise ValueError("Missing required argument: name")
    if not action:
        raise ValueError("Missing required argument: action")

    def do_modify():
        eid = idc.get_enum(enum_name)
        if eid == ida_idaapi.BADADDR:
            raise ValueError(f"Enum '{enum_name}' not found")

        if action == "add":
            if not member_name:
                raise ValueError("Missing required argument: member")
            success = idc.add_enum_member(eid, member_name, int(member_value))
            return {
                "action": "add",
                "enum": enum_name,
                "member": member_name,
                "value": int(member_value),
                "success": success == 0,
            }

        elif action == "remove":
            if not member_name:
                raise ValueError("Missing required argument: member")
            cid = idc.get_enum_member_by_name(member_name)
            if cid == ida_idaapi.BADADDR:
                raise ValueError(f"Member '{member_name}' not found in enum '{enum_name}'")
            value = idc.get_enum_member_value(cid)
            bmask = idc.get_first_bmask(eid)
            # Find serial by iterating members
            serial = 0
            val = idc.get_first_enum_member(eid, bmask)
            while val != ida_idaapi.BADADDR:
                mc = idc.get_enum_member(eid, val, serial, bmask)
                if mc == cid:
                    break
                serial += 1
                if serial > 1000:
                    serial = 0
                    break
            success = idc.del_enum_member(eid, value, serial, bmask)
            return {
                "action": "remove",
                "enum": enum_name,
                "member": member_name,
                "value": value,
                "success": success == 0,
            }

        else:
            raise ValueError(f"Invalid action '{action}'. Use: add, remove")

    result = ctx.run_on_main_thread(do_modify)
    ctx.save()
    return result


def _handle_clear_data_range(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    start_str = args.get("start", "")
    end_str = args.get("end", "")
    length = args.get("length")

    if not start_str:
        raise ValueError("Missing required argument: start")

    start = ctx.resolve_address(start_str)
    if end_str:
        end = ctx.resolve_address(end_str)
    elif length is not None:
        end = start + int(length)
    else:
        raise ValueError("Provide either 'end' or 'length'")

    if end <= start:
        raise ValueError("end must be greater than start")

    def do_clear():
        count = 0
        ea = start
        while ea < end:
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 1)
            ea = ida_bytes.next_head(ea, end)
            if ea == ida_idaapi.BADADDR:
                break
            count += 1
        return {
            "start": f"0x{start:x}",
            "end": f"0x{end:x}",
            "bytes_cleared": end - start,
            "items_deleted": count,
        }

    result = ctx.run_on_main_thread(do_clear)
    ctx.save()
    return result


def _handle_apply_data_type_range(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    start_str = args.get("start", "")
    end_str = args.get("end", "")
    length = args.get("length")
    data_type = args.get("data_type", "")
    type_size = args.get("type_size")

    if not start_str:
        raise ValueError("Missing required argument: start")
    if not data_type:
        raise ValueError("Missing required argument: data_type")

    start = ctx.resolve_address(start_str)
    if end_str:
        end = ctx.resolve_address(end_str)
    elif length is not None:
        end = start + int(length)
    else:
        raise ValueError("Provide either 'end' or 'length'")

    if end <= start:
        raise ValueError("end must be greater than start")

    def do_apply():
        item_size = 1
        flag_map = {
            "byte": (ida_bytes.FF_BYTE, 1),
            "word": (ida_bytes.FF_WORD, 2),
            "dword": (ida_bytes.FF_DWORD, 4),
            "qword": (ida_bytes.FF_QWORD, 8),
            "oword": (ida_bytes.FF_OWORD, 16),
            "float": (ida_bytes.FF_FLOAT, 4),
            "double": (ida_bytes.FF_DOUBLE, 8),
        }

        type_lower = data_type.lower().strip()
        if type_lower in flag_map:
            flag, item_size = flag_map[type_lower]
        elif type_size is not None:
            item_size = int(type_size)
            flag = ida_bytes.FF_DATA
        else:
            tif = ida_typeinf.tinfo_t()
            if ida_typeinf.parse_decl(tif, None, data_type, ida_typeinf.PT_TYP):
                item_size = tif.get_size()
                if item_size == ida_idaapi.BADADDR or item_size <= 0:
                    item_size = 1
            flag = ida_bytes.FF_DATA

        count = 0
        ea = start
        while ea + item_size <= end:
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, item_size)
            if type_lower in flag_map:
                ida_bytes.create_data(ea, flag, item_size, ida_idaapi.BADADDR)
            else:
                tif = ida_typeinf.tinfo_t()
                if ida_typeinf.parse_decl(tif, None, data_type, ida_typeinf.PT_TYP):
                    ida_bytes.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
                else:
                    ida_bytes.create_data(ea, flag, item_size, ida_idaapi.BADADDR)
            ea += item_size
            count += 1

        return {
            "start": f"0x{start:x}",
            "end": f"0x{end:x}",
            "data_type": data_type,
            "item_size": item_size,
            "items_applied": count,
        }

    result = ctx.run_on_main_thread(do_apply)
    ctx.save()
    return result


def _handle_set_equate(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    address = args.get("address", "")
    operand = int(args.get("operand", 0))
    enum_name = args.get("enum", "")
    clear = bool(args.get("clear", False))

    if not address:
        raise ValueError("Missing required argument: address")

    addr = ctx.resolve_address(address)

    def do_set():
        if clear:
            ida_bytes.clr_op_type(addr, operand)
            return {
                "address": f"0x{addr:x}",
                "operand": operand,
                "action": "cleared",
            }

        if not enum_name:
            raise ValueError("Missing required argument: enum")

        eid = idc.get_enum(enum_name)
        if eid == ida_idaapi.BADADDR:
            raise ValueError(f"Enum '{enum_name}' not found")

        success = ida_bytes.op_enum(addr, operand, eid, 0)
        return {
            "address": f"0x{addr:x}",
            "operand": operand,
            "enum": enum_name,
            "action": "set",
            "success": success,
        }

    result = ctx.run_on_main_thread(do_set)
    ctx.save()
    return result


def _handle_list_equates(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    address = args.get("address", "")
    end_str = args.get("end", "")
    limit = int(args.get("limit", 200))

    def do_list():
        results = []
        if address:
            start = ctx.resolve_address(address)
            if end_str:
                end = ctx.resolve_address(end_str)
            else:
                end = start + 1
            ea = start
            while ea < end and len(results) < limit:
                flags = ida_bytes.get_flags(ea)
                for op in range(2):
                    if ida_bytes.is_enum(flags, op):
                        eid = ida_bytes.get_enum_id(ea, op)
                        if eid != ida_idaapi.BADADDR:
                            enum_name = idc.get_enum_name(eid)
                            results.append({
                                "address": f"0x{ea:x}",
                                "operand": op,
                                "enum": enum_name,
                            })
                ea = ida_bytes.next_head(ea, end)
                if ea == ida_idaapi.BADADDR:
                    break
        else:
            for ea in idautils.Heads():
                if len(results) >= limit:
                    break
                flags = ida_bytes.get_flags(ea)
                if not ida_bytes.is_code(flags):
                    continue
                for op in range(2):
                    if ida_bytes.is_enum(flags, op):
                        eid = ida_bytes.get_enum_id(ea, op)
                        if eid != ida_idaapi.BADADDR:
                            enum_name = idc.get_enum_name(eid)
                            results.append({
                                "address": f"0x{ea:x}",
                                "operand": op,
                                "enum": enum_name,
                            })
        return {"equates": results, "count": len(results)}

    return ctx.run_on_main_thread(do_list)


def _handle_import_til(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    path = args.get("path", "")
    if not path:
        raise ValueError("Missing required argument: path")

    def do_import():
        res = ida_typeinf.import_type(None, -1, path)
        return {"imported": res, "path": path}

    result = ctx.run_on_main_thread(do_import)
    ctx.save()
    return result


def _handle_export_til(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    path = args.get("path", "")
    if not path:
        raise ValueError("Missing required argument: path")

    def do_export():
        til = ida_typeinf.get_idati()
        res = ida_typeinf.save_til(til, path, None)
        return {"exported": res, "path": path}

    result = ctx.run_on_main_thread(do_export)
    ctx.save()
    return result


def _handle_delete_type(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    name = args.get("name", "")
    if not name:
        raise ValueError("Missing required argument: name")

    def do_delete():
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(ida_typeinf.get_idati(), name):
            raise ValueError(f"Type '{name}' not found")
        res = ida_typeinf.del_named_type(ida_typeinf.get_idati(), name, ida_typeinf.NTF_TYPE)
        return {"deleted": res, "name": name}

    result = ctx.run_on_main_thread(do_delete)
    ctx.save()
    return result


def _handle_get_type_info(ctx, args: dict) -> dict:
    ida_typeinf, ida_name, ida_idaapi, idautils, ida_bytes, idc = _ida()

    name = args.get("name", "")
    if not name:
        raise ValueError("Missing required argument: name")

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name):
        return {"name": name, "declaration": None}

    decl = ida_typeinf.print_tinfo(None, 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, None)
    return {"name": name, "declaration": decl or ""}


register_handler("create_struct", _handle_create_struct)
register_handler("create_union", _handle_create_union)
register_handler("create_enum", _handle_create_enum)
register_handler("list_data_types", _handle_list_data_types)
register_handler("list_labels", _handle_list_labels)
register_handler("modify_struct", _handle_modify_struct)
register_handler("modify_enum", _handle_modify_enum)
register_handler("clear_data_range", _handle_clear_data_range)
register_handler("apply_data_type_range", _handle_apply_data_type_range)
register_handler("set_equate", _handle_set_equate)
register_handler("list_equates", _handle_list_equates)
register_handler("import_til", _handle_import_til)
register_handler("export_til", _handle_export_til)
register_handler("delete_type", _handle_delete_type)
register_handler("get_type_info", _handle_get_type_info)
