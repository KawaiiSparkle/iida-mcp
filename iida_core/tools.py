"""All MCP tool definitions and implementations for IDA static analysis."""
import os
import struct as pystruct
import hashlib
import json

import idautils
import idaapi
import ida_funcs
import ida_bytes
import ida_frame
import ida_name
import ida_nalt
import ida_segment
import ida_xref
import ida_ua
import ida_typeinf
import ida_entry
import ida_auto
import ida_gdl
import ida_lines
import ida_ida
import ida_loader
import ida_idaapi
import ida_kernwin
import idc

from .thread_safe import read, write
from .cache import get_cache
from .elf import parse_elf

# ============================================================
# Tool schema definitions (MCP tools/list response)
# ============================================================

def _t(name, desc, params=None):
    """Helper to build tool schema entry."""
    schema = {"name": name, "description": desc}
    if params:
        schema["inputSchema"] = {
            "type": "object",
            "properties": params,
            "required": [k for k, v in params.items() if not v.get("optional")]
        }
    else:
        schema["inputSchema"] = {"type": "object", "properties": {}}
    return schema

_F = {"type": "string", "description": "file_id"}
_A = {"type": "string", "description": "hex address"}
_N = {"type": "integer", "description": "count", "optional": True}
_Q = {"type": "string", "description": "filter query", "optional": True}
_OFF = {"type": "integer", "description": "offset for pagination", "optional": True}
_STR_PAIR = {"type": "array", "items": {"type": "string"}, "minItems": 2, "maxItems": 2}
_COMMENT_ITEM = {
    "type": "array",
    "items": {"anyOf": [{"type": "string"}, {"type": "integer"}]},
    "minItems": 2,
    "maxItems": 3,
}
_BATCH_OP = {
    "type": "array",
    "items": {"anyOf": [{"type": "string"}, {"type": "object"}]},
    "minItems": 2,
    "maxItems": 2,
}

TOOLS_SCHEMA = [
    _t("list_files", "List connected IDA instances"),
    _t("get_info", "IDB info: filename, paths, arch, bits, entry, address range, segment/function counts, and loader type", {"f": _F}),
    _t("read_file_bytes", "Read raw original file bytes at file offset", {"f": _F, "off": {"type":"integer","description":"file offset"}, "sz": {"type":"integer","description":"size"}}),
    _t("addr_to_fileoff", "Convert IDB address to raw file offset", {"f": _F, "a": _A}),
    _t("parse_pe", "Parse PE header from raw file", {"f": _F}),
    _t("parse_elf", "Parse ELF metadata; use detail=full for section/symbol/reloc samples", {"f": _F, "detail": {"type":"string","description":"summary/full (default summary)","optional":True}, "limit": {"type":"integer","description":"max sample rows per heavy table (default 128)","optional":True}}),
    _t("get_cursor", "Get the current IDA UI cursor address", {"f": _F}),
    _t("get_cursor_func", "Get the function under the current IDA UI cursor", {"f": _F}),
    _t("list_functions", "List functions (paginated, filterable)", {"f": _F, "q": _Q, "off": _OFF, "n": _N}),
    _t("get_func_info", "Get function info: name, start, end, size, frame", {"f": _F, "a": _A}),
    _t("get_func_by_name", "Find a function by exact name", {"f": _F, "name": {"type":"string","description":"function name"}}),
    _t("decompile", "Decompile function to pseudocode", {"f": _F, "a": _A}),
    _t("get_func_type", "Get function prototype/type declaration", {"f": _F, "a": _A}),
    _t("get_callers", "List functions that call this address", {"f": _F, "a": _A}),
    _t("get_callees", "List functions called by this function", {"f": _F, "a": _A}),
    _t("get_vars", "List decompiled function variables and arguments: [name, type, kind, location]", {"f": _F, "a": _A}),
    _t("disassemble", "Disassemble N instructions at address", {"f": _F, "a": _A, "n": _N}),
    _t("read_bytes", "Read bytes from IDB at address", {"f": _F, "a": _A, "sz": {"type":"integer","description":"size"}}),
    _t("read_value", "Read an integer value from IDB memory. size is 1, 2, 4, or 8 bytes. Returns [dec, hex].", {"f": _F, "a": _A, "sz": {"type":"integer","description":"1/2/4/8 bytes"}}),
    _t("read_string", "Read a string literal from IDB at address", {"f": _F, "a": _A, "strtype": {"type":"integer","description":"IDA STRTYPE_* constant; default uses IDA default","optional":True}, "max": {"type":"integer","description":"max bytes to read","optional":True}}),
    _t("get_head", "Get item head address containing the given address", {"f": _F, "a": _A}),
    _t("get_name", "Get name/label at address", {"f": _F, "a": _A}),
    _t("set_name", "Set name/label at address", {"f": _F, "a": _A, "name": {"type":"string","description":"new name"}}),
    _t("get_comment", "Get comment at address", {"f": _F, "a": _A, "rep": {"type":"integer","description":"1=repeatable","optional":True}}),
    _t("set_comment", "Set comment at address", {"f": _F, "a": _A, "cmt": {"type":"string","description":"comment text"}, "rep": {"type":"integer","description":"1=repeatable","optional":True}}),
    _t("set_pseudocode_comment", "Set Hex-Rays pseudocode comment at address", {"f": _F, "a": _A, "cmt": {"type":"string","description":"comment text"}, "rep": {"type":"integer","description":"1=repeatable","optional":True}}),
    _t("search_names", "Search all names/labels by substring", {"f": _F, "q": {"type":"string","description":"substring"}, "n": _N}),
    _t("list_globals", "List named non-function globals (paginated, filterable)", {"f": _F, "q": _Q, "off": _OFF, "n": _N}),
    _t("read_global", "Read a named global value", {"f": _F, "name": {"type":"string","description":"global name"}, "sz": {"type":"integer","description":"override byte size","optional":True}}),
    _t("get_type", "Get type info at address", {"f": _F, "a": _A}),
    _t("set_type", "Apply C type declaration at address", {"f": _F, "a": _A, "decl": {"type":"string","description":"C type declaration"}}),
    _t("set_c_decls", "Parse one or more C typedef/struct/enum declarations into local types", {"f": _F, "decl": {"type":"string","description":"C declarations"}}),
    _t("list_types", "List local types. kind may be struct, enum, type, or all.", {"f": _F, "q": _Q, "kind": {"type":"string","description":"struct/enum/type/all (default all)","optional":True}}),
    _t("get_type_decl", "Get a local type declaration plus member details when available.", {"f": _F, "name": {"type":"string","description":"local type name"}}),
    _t("read_struct", "Read memory as an IDA struct and parse fields. source=idb reads IDB bytes, source=kernel reads runtime kernel memory.", {"f": _F, "name": {"type":"string","description":"struct name"}, "a": _A, "source": {"type":"string","description":"idb/kernel (default idb)","optional":True}, "enums": {"type":"integer","description":"include enum candidates for integer fields (default 1)","optional":True}}),
    _t("delete_type", "Delete a local type by name: struct, enum, typedef, or alias", {"f": _F, "name": {"type":"string","description":"local type name"}}),
    _t("find_enum_value", "Find enum constants matching a numeric value, including bitmask flag candidates.", {"f": _F, "val": {"type":"string","description":"numeric value, e.g. 3 or 0x15F0"}, "q": {"type":"string","description":"optional enum/name substring filter","optional":True}, "n": _N}),
    _t("list_segments", "List all segments/sections", {"f": _F}),
    _t("get_segment_info", "Get segment info for address", {"f": _F, "a": _A}),
    _t("xrefs_to", "Get all cross-references TO this address", {"f": _F, "a": _A}),
    _t("xrefs_from", "Get all cross-references FROM this address", {"f": _F, "a": _A}),
    _t("xrefs_to_field", "Find xrefs to a struct field by struct and field name", {"f": _F, "struct": {"type":"string","description":"struct name"}, "field": {"type":"string","description":"field name"}}),
    _t("search_bytes", "Search for byte pattern (e.g. '48 8B ?? 90')", {"f": _F, "pat": {"type":"string","description":"hex pattern with ?? wildcards"}, "start": {"type":"string","description":"start addr","optional":True}, "dir": {"type":"integer","description":"1=down 0=up","optional":True}}),
    _t("search_strings", "Search string list by substring", {"f": _F, "q": _Q, "off": _OFF, "n": _N}),
    _t("search_imm", "Search little-endian encoded immediate/value bytes using minimal width (1/2/4/8). Example val=15F0 searches F0 15.", {"f": _F, "val": {"type":"string","description":"hex value string, e.g. 15F0 or 0x15F0"}}),
    _t("list_imports", "List import table", {"f": _F}),
    _t("list_exports", "List export table", {"f": _F}),
    _t("list_entries", "List entry points", {"f": _F}),
    _t("get_cfg", "Get function control flow graph as basic block nodes and edges", {"f": _F, "a": _A}),
    _t("patch_bytes", "Patch bytes in IDB at address (modifies database)", {"f": _F, "a": _A, "hex": {"type":"string","description":"hex bytes to write"}}),
    _t("patch_asm", "Assemble one or more instructions with keystone and patch bytes at address", {"f": _F, "a": _A, "asm": {"type":"string","description":"assembly text, e.g. nop, ret, mov rax, 1, or mov x0, #1"}}),
    _t("patch_list", "List all patched bytes in IDB", {"f": _F}),
    _t("bookmark_list", "List all bookmarks", {"f": _F}),
    _t("bookmark_set", "Set bookmark at address", {"f": _F, "a": _A, "desc": {"type":"string","description":"description"}}),
    _t("bookmark_delete", "Delete bookmark at address", {"f": _F, "a": _A}),
    _t("reanalyze", "Trigger IDA auto-analysis and wait", {"f": _F}),
    _t("create_function", "Create function at address", {"f": _F, "a": _A, "end": {"type":"string","description":"end addr","optional":True}}),
    _t("delete_function", "Delete function at address", {"f": _F, "a": _A}),
    _t("make_data", "Define data at address", {"f": _F, "a": _A, "sz": {"type":"integer","description":"size"}, "type": {"type":"string","description":"byte/word/dword/qword","optional":True}}),
    _t("undefine", "Undefine (make unknown) bytes at address", {"f": _F, "a": _A, "sz": {"type":"integer","description":"size"}}),
    _t("rename_var", "Rename a decompiled local variable", {"f": _F, "a": _A, "old": {"type":"string","description":"old name"}, "new": {"type":"string","description":"new name"}}),
    _t("retype_var", "Change type of a decompiled variable", {"f": _F, "a": _A, "var": {"type":"string","description":"var name"}, "decl": {"type":"string","description":"C type"}}),
    _t("list_frame_vars", "List a function's stack frame variables: [offset, size, name, type]", {"f": _F, "a": _A}),
    _t("create_frame_var", "Create a stack frame variable at byte offset", {"f": _F, "a": _A, "name": {"type":"string","description":"variable name"}, "off": {"type":"integer","description":"frame byte offset"}, "decl": {"type":"string","description":"C type (default unsigned char)","optional":True}}),
    _t("delete_frame_var", "Delete a stack frame variable by name", {"f": _F, "a": _A, "name": {"type":"string","description":"variable name"}}),
    _t("rename_frame_var", "Rename a stack frame variable", {"f": _F, "a": _A, "old": {"type":"string","description":"old name"}, "new": {"type":"string","description":"new name"}}),
    _t("retype_frame_var", "Change a stack frame variable type", {"f": _F, "a": _A, "name": {"type":"string","description":"variable name"}, "decl": {"type":"string","description":"C type"}}),
    _t("batch", "Batch execute multiple tools in one call", {"f": {"type":"string","description":"default file_id","optional":True}, "ops": {"type":"array","description":"[[tool_name,{args}],...]","items":_BATCH_OP}}),
    _t("get_func_by_addr", "Find which function contains the given address (any addr, not just func start)", {"f": _F, "a": _A}),
    _t("call_tree", "Build forward call tree (recursive callees from function)", {"f": _F, "a": _A, "depth": {"type":"integer","description":"max depth (default 5)","optional":True}}),
    _t("callers_tree", "Build reverse call tree (recursive callers of function)", {"f": _F, "a": _A, "depth": {"type":"integer","description":"max depth (default 5)","optional":True}}),
    _t("kernel_read", "Read kernel memory via iida-mcp-ioctl driver (SEH protected). Returns hex string of bytes.", {"a": {"type":"string","description":"kernel virtual address (hex, e.g. fffff80455740000)"}, "sz": {"type":"integer","description":"size in bytes (max 65536)"}}),
    _t("kernel_modules", "List all loaded kernel modules via driver. Returns [[base_hex, size, name, path], ...]"),
    _t("kernel_module_base", "Get kernel module base address and size by name via driver. Returns [base_hex, size]", {"name": {"type":"string","description":"module name, e.g. ntoskrnl or nvlddmkm"}}),
    _t("calc", "Integer calculator. Evaluate arithmetic expression with hex(0x)/dec/oct(0o)/bin(0b). Supports + - * / % ** << >> & | ^ ~. Returns [dec, hex]", {"expr": {"type":"string","description":"expression, e.g. 0xfffff804+0x1000*3"}}),
    _t("disasm_bytes", "Disassemble raw hex bytes (no IDB needed). Returns [[offset, hex, mnemonic, operands], ...]", {"hex": {"type":"string","description":"hex bytes, e.g. 1f2003d5 or 48 89 e5"}, "arch": {"type":"string","description":"x86/x64/arm/arm64/aarch64/armv8a (default x64)","optional":True}, "addr": {"type":"string","description":"base address for display (default 0)","optional":True}}),
    _t("kernel_read_values", "Read kernel memory and interpret as typed values. Use a for one address or addrs for batch. fmt defaults to p(pointer).", {"a": {"type":"string","description":"single kernel virtual address (hex)","optional":True}, "addrs": {"type":"array","description":"batch kernel virtual addresses [hex_addr, ...]","items":{"type":"string"},"optional":True}, "fmt": {"type":"string","description":"format: p(pointer/u64) d(u32) w(u16) b(u8) s(null-term string) or NNx(raw bytes). e.g. p, ppd, 16x. default p","optional":True}}),
    _t("ida_to_runtime", "Convert IDA virtual address to runtime kernel address. Uses runtime module base from driver + IDA segment info to compute correct mapping per-section.", {"f": _F, "a": _A, "mod": {"type":"string","description":"kernel module name (e.g. nvlddmkm)","optional":True}}),
]


# ============================================================
# Tool implementations
# ============================================================

def _ea(s):
    """Parse hex address string to int."""
    if isinstance(s, int):
        return s
    return int(s, 16)


def _num(s):
    """Parse a user-facing numeric value: decimal by default, hex with 0x or A-F."""
    if isinstance(s, int):
        return s
    text = str(s).strip().replace('_', '')
    if not text:
        raise ValueError('empty numeric value')
    if text.lower().startswith(('0x', '0o', '0b')):
        return int(text, 0)
    if any(c in text.lower() for c in 'abcdef'):
        return int(text, 16)
    return int(text, 10)


def _hex(val):
    """Int to hex string without 0x prefix."""
    return format(val, 'x')


def _pt_sil():
    return getattr(ida_typeinf, 'PT_SIL', getattr(idc, 'PT_SIL', 0))


def _ntf_replace():
    return getattr(ida_typeinf, 'NTF_REPLACE', getattr(idc, 'NTF_REPLACE', 1))


def _tinfo_present(tif):
    try:
        return tif.present()
    except:
        try:
            return not tif.empty()
        except:
            return False


def _parse_tinfo_decl(tif, til, decl):
    """Parse a C declaration across IDA 8.x/9.x return-value differences."""
    try:
        r = ida_typeinf.parse_decl(tif, til, decl, _pt_sil())
        return bool(r) or _tinfo_present(tif)
    except TypeError:
        pass
    try:
        return bool(tif.parse(decl, til, _pt_sil())) or _tinfo_present(tif)
    except:
        return False


def _apply_tinfo(ea, tif):
    flags = getattr(ida_typeinf, 'TINFO_DEFINITE', getattr(idaapi, 'TINFO_DEFINITE', 0))
    for mod in (idaapi, ida_typeinf):
        fn = getattr(mod, 'apply_tinfo', None)
        if fn:
            try:
                if fn(ea, tif, flags):
                    return True
            except:
                pass
    return False


def _apply_type_decl(ea, decl):
    try:
        if idc.SetType(ea, decl):
            return True
    except:
        pass
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if _parse_tinfo_decl(tif, til, decl):
        return _apply_tinfo(ea, tif)
    return False


def _type_ordinal_by_name(til, name):
    if not name:
        return 0
    try:
        ordinal = ida_typeinf.get_type_ordinal(til, name)
        if ordinal:
            return ordinal
    except:
        pass
    try:
        limit = idc.get_ordinal_limit()
    except:
        try:
            limit = ida_typeinf.get_ordinal_qty(til) + 1
        except:
            limit = 0
    for ordinal in range(1, limit):
        try:
            if idc.get_numbered_type_name(ordinal) == name:
                return ordinal
        except:
            pass
    return 0


def _local_type_ordinals(til):
    try:
        limit = ida_typeinf.get_ordinal_qty(til) + 1
        return range(1, limit)
    except:
        pass
    try:
        limit = idc.get_ordinal_limit()
        return range(1, limit)
    except:
        return range(1, 0)


def _save_local_type_decl(decl):
    """Create/update a named local type in a way that works on IDA 8.3 and 9.x."""
    try:
        ordinal = idc.set_local_type(-1, decl, _pt_sil())
        if ordinal:
            return ordinal
    except:
        pass

    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not _parse_tinfo_decl(tif, til, decl):
        return 0
    name = tif.get_type_name()
    if not name:
        return 0

    for saver in ('set_named_type', 'save_type'):
        fn = getattr(tif, saver, None)
        if not fn:
            continue
        try:
            if saver == 'set_named_type':
                fn(til, name, _ntf_replace())
            else:
                fn(_ntf_replace())
            ordinal = _type_ordinal_by_name(til, name)
            if ordinal:
                return ordinal
        except:
            pass

    try:
        ordinal = _type_ordinal_by_name(til, name) or ida_typeinf.alloc_type_ordinal(til)
        tif.set_numbered_type(til, ordinal, _ntf_replace(), name)
        return _type_ordinal_by_name(til, name) or ordinal
    except:
        return 0


def _delete_local_type(name):
    til = ida_typeinf.get_idati()
    ordinal = _type_ordinal_by_name(til, name)
    if not ordinal:
        return 'not found'
    try:
        ida_typeinf.del_numbered_type(til, ordinal)
    except:
        try:
            idc.set_local_type(ordinal, '', 0)
        except:
            return 'fail'
    return 'ok' if not _type_ordinal_by_name(til, name) else 'fail'


def _block_succs(block):
    try:
        return list(block.succs())
    except:
        pass
    try:
        return [block.succ(i) for i in range(block.nsucc())]
    except:
        return []


def _block_preds(block):
    try:
        return list(block.preds())
    except:
        pass
    try:
        return [block.pred(i) for i in range(block.npred())]
    except:
        return []


def _addr_ctx(ea):
    """Get context for an address: (func_name, comment). Runs on IDA main thread."""
    func = ida_funcs.get_func(ea)
    fname = ida_funcs.get_func_name(func.start_ea) if func else ''
    cmt = ida_bytes.get_cmt(ea, 0) or ida_bytes.get_cmt(ea, 1) or ''
    return fname, cmt


def _bin_search_ea(result):
    if isinstance(result, tuple):
        result = result[0]
    return result


def _get_input_path():
    return ida_nalt.get_input_file_path()


# --- 4.1 Meta & File ---

def _info(args):
    def _impl():
        input_path = ida_nalt.get_input_file_path()
        idb_path = ''
        try:
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        except:
            pass
        procname = ida_ida.inf_get_procname()
        is64 = ida_ida.inf_is_64bit()
        is32 = ida_ida.inf_is_32bit_exactly() if hasattr(ida_ida, 'inf_is_32bit_exactly') else not is64
        return {
            'file': os.path.basename(input_path),
            'path': input_path,
            'idb': idb_path,
            'proc': procname,
            'bits': 64 if is64 else (32 if is32 else 16),
            'entry': _hex(ida_ida.inf_get_start_ea()),
            'min': _hex(ida_ida.inf_get_min_ea()),
            'max': _hex(ida_ida.inf_get_max_ea()),
            'segs': ida_segment.get_segm_qty(),
            'funcs': ida_funcs.get_func_qty(),
            'type': ida_loader.get_file_type_name(),
            'compiler': ida_ida.inf_get_cc_id()
        }
    return read(_impl)


def _cursor(args):
    def _impl():
        return _hex(idaapi.get_screen_ea())
    return read(_impl)


def _cursor_func(args):
    def _impl():
        ea = idaapi.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func'}
        return [
            _hex(func.start_ea),
            ida_funcs.get_func_name(func.start_ea),
            func.size()
        ]
    return read(_impl)


def _fraw(args):
    off = args.get('off', 0)
    sz = min(args.get('sz', 256), 0x100000)  # cap at 1MB
    if off < 0:
        return {'e': 'off must be non-negative'}
    if sz <= 0:
        return ''
    path = read(_get_input_path)
    with open(path, 'rb') as fp:
        fp.seek(off)
        data = fp.read(sz)
    return data.hex()


def _fmap(args):
    ea = _ea(args['a'])
    def _impl():
        return ida_loader.get_fileregion_offset(ea)
    offset = read(_impl)
    return offset if offset != -1 else None


def _fpath(args):
    return read(_get_input_path)


# --- 4.2 PE/ELF ---

def _pe(args):
    path = read(_get_input_path)
    with open(path, 'rb') as fp:
        dos = fp.read(64)
        if dos[:2] != b'MZ':
            return {'e': 'not PE'}
        pe_off = pystruct.unpack_from('<I', dos, 60)[0]
        fp.seek(pe_off)
        sig = fp.read(4)
        if sig != b'PE\x00\x00':
            return {'e': 'bad PE sig'}
        coff = fp.read(20)
        machine, nsections, timestamp = pystruct.unpack_from('<HHI', coff, 0)
        opt_size = pystruct.unpack_from('<H', coff, 16)[0]
        opt = fp.read(opt_size)
        magic = pystruct.unpack_from('<H', opt, 0)[0]
        is64 = magic == 0x20b
        if is64:
            entry = pystruct.unpack_from('<I', opt, 16)[0]
            image_base = pystruct.unpack_from('<Q', opt, 24)[0]
            subsystem = pystruct.unpack_from('<H', opt, 68)[0]
            nrva = pystruct.unpack_from('<I', opt, 108)[0]
        else:
            entry = pystruct.unpack_from('<I', opt, 16)[0]
            image_base = pystruct.unpack_from('<I', opt, 28)[0]
            subsystem = pystruct.unpack_from('<H', opt, 68)[0]
            nrva = pystruct.unpack_from('<I', opt, 92)[0]

        sections = []
        for _ in range(nsections):
            shdr = fp.read(40)
            sname = shdr[:8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize, vaddr, rawsz, rawoff = pystruct.unpack_from('<IIII', shdr, 8)
            chars = pystruct.unpack_from('<I', shdr, 36)[0]
            sections.append([sname, _hex(vaddr), vsize, rawsz, rawoff, chars])

        return {
            'machine': machine,
            'timestamp': timestamp,
            'image_base': _hex(image_base),
            'entry': _hex(entry),
            'subsystem': subsystem,
            'is64': is64,
            'sections': sections
        }


def _elf(args):
    path = read(_get_input_path)
    return parse_elf(path, args.get('detail', 'summary'), args.get('limit', 128))


# --- 4.3 Functions ---

def _fl(args):
    q = args.get('q', '')
    off = args.get('off', 0)
    n = min(args.get('n', 100), 1000)
    if n <= 0:
        return []
    cache = get_cache()
    data = cache.get_functions(q, off, n)
    eas = [ea for ea, _, _ in data]
    def _get_comments(addrs=eas):
        return {a: (ida_bytes.get_cmt(a, 0) or ida_bytes.get_cmt(a, 1) or '') for a in addrs}
    cmts = read(_get_comments) if eas else {}
    results = []
    for ea, name, sz in data:
        row = [_hex(ea), name, sz]
        c = cmts.get(ea, '')
        if c:
            row.append(c)
        results.append(row)
    return results


def _fi(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func'}
        tif = ida_typeinf.tinfo_t()
        ida_typeinf.guess_tinfo(tif, ea)
        frame_size = ida_frame.get_frame_size(func) if func.frame != idaapi.BADADDR else 0
        return [
            _hex(func.start_ea),
            ida_funcs.get_func_name(func.start_ea),
            func.size(),
            func.flags,
            frame_size,
            func.frsize,
            func.argsize,
            str(tif) if tif.present() else ''
        ]
    return read(_impl)


def _fbn(args):
    name = args['name']
    def _impl():
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            return {'e': 'not found'}
        func = ida_funcs.get_func(ea)
        if not func or func.start_ea != ea:
            return {'e': 'not a function', 'addr': _hex(ea)}
        return [
            _hex(func.start_ea),
            ida_funcs.get_func_name(func.start_ea),
            func.size()
        ]
    return read(_impl)


def _dec(args):
    ea = _ea(args['a'])
    def _impl():
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                lines = cfunc.get_pseudocode()
                text = '\n'.join(ida_lines.tag_remove(l.line) for l in lines)
                return text
            return {'e': 'decompile failed'}
        except Exception as ex:
            return {'e': str(ex)}
    return read(_impl)


def _decl(args):
    ea = _ea(args['a'])
    def _impl():
        tif = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(tif, ea) or ida_typeinf.guess_tinfo(tif, ea):
            name = ida_funcs.get_func_name(ea) or ''
            return tif.dstr() if not name else str(tif) + ' ' + name
        return ''
    return read(_impl)


def _sft(args):
    ea = _ea(args['a'])
    decl = args['decl']
    def _impl():
        return 'ok' if _apply_type_decl(ea, decl) else 'fail'
    return write(_impl)


def _cf(args):
    ea = _ea(args['a'])
    def _impl():
        results = []
        for xref in idautils.CodeRefsTo(ea, 0):
            fn = ida_funcs.get_func(xref)
            fname = ida_funcs.get_func_name(fn.start_ea) if fn else ''
            cmt = ida_bytes.get_cmt(fn.start_ea, 0) or ida_bytes.get_cmt(fn.start_ea, 1) or '' if fn else ''
            row = [_hex(xref), fname]
            if cmt:
                row.append(cmt)
            results.append(row)
        return results
    return read(_impl)


def _ct(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return []
        seen = set()
        results = []
        for item_ea in idautils.FuncItems(func.start_ea):
            for xref in idautils.CodeRefsFrom(item_ea, 0):
                fn = ida_funcs.get_func(xref)
                if fn and fn.start_ea != func.start_ea and fn.start_ea not in seen:
                    seen.add(fn.start_ea)
                    name = ida_funcs.get_func_name(fn.start_ea) or ''
                    cmt = ida_bytes.get_cmt(fn.start_ea, 0) or ida_bytes.get_cmt(fn.start_ea, 1) or ''
                    row = [_hex(fn.start_ea), name]
                    if cmt:
                        row.append(cmt)
                    results.append(row)
        return results
    return read(_impl)


def _decompiled_vars(ea):
    try:
        import ida_hexrays
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return []
        results = []
        for v in cfunc.lvars:
            kind = 'arg' if v.is_arg_var else 'local'
            try:
                loc = v.location.dstr() if v.is_arg_var else (v.location.stkoff() if v.is_stk_var() else -1)
            except:
                loc = ''
            results.append([v.name, str(v.tif), kind, loc])
        return results
    except:
        return []


def _vars(args):
    ea = _ea(args['a'])
    return read(lambda: _decompiled_vars(ea))


def _fv(args):
    ea = _ea(args['a'])
    def _impl():
        rows = _decompiled_vars(ea)
        return [[name, typ, loc] for name, typ, kind, loc in rows if kind == 'local']
    return read(_impl)


def _fa(args):
    ea = _ea(args['a'])
    def _impl():
        rows = _decompiled_vars(ea)
        return [[name, typ, loc] for name, typ, kind, loc in rows if kind == 'arg']
    return read(_impl)


# --- 4.4 Disassembly & Bytes ---

def _dis(args):
    ea = _ea(args['a'])
    n = min(args.get('n', 32), 512)
    if n <= 0:
        return []
    def _impl():
        results = []
        cur = ea
        for _ in range(n):
            sz = ida_bytes.get_item_size(cur)
            if sz == 0:
                break
            raw = ida_bytes.get_bytes(cur, sz)
            insn = ida_ua.insn_t()
            cmt = ida_bytes.get_cmt(cur, 0) or ida_bytes.get_cmt(cur, 1) or ''
            if ida_ua.decode_insn(insn, cur) > 0:
                mnem = insn.get_canon_mnem()
                ops = ida_lines.tag_remove(idc.GetDisasm(cur))
                ops_part = ops[len(mnem):].strip() if ops.startswith(mnem) else ops
                row = [_hex(cur), raw.hex() if raw else '', mnem, ops_part]
            else:
                row = [_hex(cur), raw.hex() if raw else '', 'db', '']
            if cmt:
                row.append(cmt)
            results.append(row)
            cur += sz
        return results
    return read(_impl)


def _rb(args):
    ea = _ea(args['a'])
    sz = min(args.get('sz', 16), 0x100000)
    if sz <= 0:
        return ''
    def _impl():
        data = ida_bytes.get_bytes(ea, sz)
        return data.hex() if data else ''
    return read(_impl)


def _read_int(args, size):
    ea = _ea(args['a'])
    if size not in (1, 2, 4, 8):
        return {'e': 'sz must be 1, 2, 4, or 8'}
    def _impl():
        if size == 1:
            val = idc.get_wide_byte(ea)
        elif size == 2:
            val = idc.get_wide_word(ea)
        elif size == 4:
            val = idc.get_wide_dword(ea)
        else:
            val = idc.get_qword(ea)
        return [val, _hex(val)]
    return read(_impl)


def _rval(args):
    return _read_int(args, args.get('sz', 8))


def _rbyte(args):
    return _read_int(args, 1)


def _rword(args):
    return _read_int(args, 2)


def _rdword(args):
    return _read_int(args, 4)


def _rqword(args):
    return _read_int(args, 8)


def _rstr(args):
    ea = _ea(args['a'])
    strtype = args.get('strtype')
    maxlen = min(args.get('max', 4096), 0x100000)
    def _impl():
        if strtype is not None:
            st = strtype
        else:
            try:
                st = ida_nalt.get_default_str_type()
            except:
                st = getattr(idc, 'STRTYPE_C', getattr(ida_nalt, 'STRTYPE_C', 0))
        data = idc.get_strlit_contents(ea, maxlen, st)
        if data is None:
            raw = ida_bytes.get_bytes(ea, maxlen) or b''
            nul = raw.find(b'\x00')
            if nul >= 0:
                raw = raw[:nul]
            data = raw
        if isinstance(data, (bytes, bytearray)):
            return data.decode('utf-8', errors='replace')
        return str(data)
    return read(_impl)


def _wb(args):
    ea = _ea(args['a'])
    hexstr = args['hex']
    data = bytes.fromhex(hexstr)
    def _impl():
        if ida_segment.getseg(ea) is None:
            return {'e': 'address not mapped'}
        return 'ok' if ida_bytes.put_bytes(ea, data) else 'fail'
    return write(_impl)


def _head(args):
    ea = _ea(args['a'])
    def _impl():
        return _hex(ida_bytes.get_item_head(ea))
    return read(_impl)


# --- 4.5 Names & Comments ---

def _gn(args):
    ea = _ea(args['a'])
    def _impl():
        n = ida_name.get_name(ea)
        if n:
            demang = ida_name.demangle_name(n, 0)
            return demang if demang else n
        return ''
    return read(_impl)


def _sn(args):
    ea = _ea(args['a'])
    name = args['name']
    def _impl():
        return 'ok' if ida_name.set_name(ea, name, ida_name.SN_NOWARN) else 'fail'
    return write(_impl)


def _gc(args):
    ea = _ea(args['a'])
    rep = args.get('rep', 0)
    def _impl():
        return ida_bytes.get_cmt(ea, bool(rep)) or ''
    return read(_impl)


def _sc(args):
    ea = _ea(args['a'])
    cmt = args['cmt']
    rep = args.get('rep', 0)
    def _impl():
        ida_bytes.set_cmt(ea, cmt, bool(rep))
        return 'ok'
    return write(_impl)


def _set_pseudocode_comment(ea, cmt, rep=False):
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            return False, 'hexrays unavailable'

        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return False, 'decompile failed'

        if ea == cfunc.entry_ea:
            idc.set_func_cmt(ea, cmt, bool(rep))
            cfunc.refresh_func_ctext()
            ok = (idc.get_func_cmt(ea, bool(rep)) or '') == cmt
            return ok, '' if ok else 'function comment not saved'

        eamap = cfunc.get_eamap()
        if ea not in eamap:
            return False, 'address not in pseudocode map'

        nearest_ea = eamap[ea][0].ea
        tl = ida_hexrays.treeloc_t()
        tl.ea = nearest_ea
        for itp in range(ida_hexrays.ITP_SEMI, ida_hexrays.ITP_COLON):
            tl.itp = itp
            cfunc.set_user_cmt(tl, cmt)
            cfunc.save_user_cmts()
            cfunc.refresh_func_ctext()
            if cfunc.get_user_cmt(tl, ida_hexrays.RETRIEVE_ALWAYS) == cmt:
                return True, ''
        return False, 'user comment not saved'
    except Exception as ex:
        return False, str(ex)


def _spc(args):
    ea = _ea(args['a'])
    cmt = args['cmt']
    rep = args.get('rep', 0)
    def _impl():
        ok, reason = _set_pseudocode_comment(ea, cmt, bool(rep))
        return {'ok': ok, 'e': reason} if not ok else {'ok': True}
    return write(_impl)


def _an(args):
    q = args['q']
    n = min(args.get('n', 50), 500)
    if n <= 0:
        return []
    cache = get_cache()
    data = cache.get_names(q, n)
    return [[_hex(ea), name] for ea, name in data]


def _lg(args):
    q = (args.get('q') or '').lower()
    off = args.get('off', 0)
    n = min(args.get('n', 100), 1000)
    if n <= 0:
        return []
    def _impl():
        results = []
        skipped = 0
        for ea, name in idautils.Names():
            if ida_funcs.get_func(ea):
                continue
            if q and q not in name.lower():
                continue
            if skipped < off:
                skipped += 1
                continue
            size = ida_bytes.get_item_size(ea) or 0
            tif = ida_typeinf.tinfo_t()
            row = [_hex(ea), name, size]
            if idaapi.get_tinfo(tif, ea) and _tinfo_present(tif):
                row.append(str(tif))
            results.append(row)
            if len(results) >= n:
                break
        return results
    return read(_impl)


def _global_value(ea, size=0):
    name = ida_name.get_name(ea) or ''
    if size:
        data = ida_bytes.get_bytes(ea, min(size, 0x100000)) or b''
        return {'addr': _hex(ea), 'name': name, 'size': len(data), 'raw': data.hex()}

    item_size = ida_bytes.get_item_size(ea) or 0
    if item_size <= 0 or item_size > 16:
        item_size = 8 if ida_ida.inf_is_64bit() else 4

    if item_size == 1:
        val = idc.get_wide_byte(ea)
    elif item_size == 2:
        val = idc.get_wide_word(ea)
    elif item_size == 4:
        val = idc.get_wide_dword(ea)
    elif item_size == 8:
        val = idc.get_qword(ea)
    else:
        data = ida_bytes.get_bytes(ea, item_size) or b''
        return {'addr': _hex(ea), 'name': name, 'size': item_size, 'raw': data.hex()}

    return {'addr': _hex(ea), 'name': name, 'size': item_size, 'value': _hex(val), 'dec': val}


def _rg(args):
    name = args['name']
    size = args.get('sz', 0)
    def _impl():
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            return {'e': 'not found'}
        return _global_value(ea, size)
    return read(_impl)


def _rga(args):
    ea = _ea(args['a'])
    size = args.get('sz', 0)
    def _impl():
        return _global_value(ea, size)
    return read(_impl)


# --- 4.6 Types ---

def _gt(args):
    ea = _ea(args['a'])
    def _impl():
        tif = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(tif, ea):
            return str(tif)
        if ida_typeinf.guess_tinfo(tif, ea):
            return str(tif)
        return ''
    return read(_impl)


def _st(args):
    ea = _ea(args['a'])
    decl = args['decl']
    def _impl():
        return 'ok' if _apply_type_decl(ea, decl) else 'fail'
    return write(_impl)


def _cdecls(args):
    decl = args['decl']
    def _impl():
        til = ida_typeinf.get_idati()
        flags = getattr(ida_typeinf, 'HTI_DCL', 0) | getattr(ida_typeinf, 'HTI_PAK1', 0)
        try:
            errors = ida_typeinf.parse_decls(til, decl, None, flags)
            return {'errors': errors}
        except Exception as ex:
            return {'e': str(ex)}
    return write(_impl)


def _tl(args):
    q = args.get('q', '').lower()
    def _impl():
        til = ida_typeinf.get_idati()
        results = []
        for ordinal in _local_type_ordinals(til):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ordinal):
                if tif.is_struct():
                    name = tif.get_type_name()
                    if not q or q in name.lower():
                        results.append([name, tif.get_size()])
        return results
    return read(_impl)


def _types(args):
    q = (args.get('q') or '').lower()
    kind = (args.get('kind') or 'all').lower()
    def _impl():
        til = ida_typeinf.get_idati()
        results = []
        for ordinal in _local_type_ordinals(til):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal):
                continue
            name = tif.get_type_name() or ''
            if q and q not in name.lower():
                continue
            if tif.is_struct():
                row_kind = 'struct'
            elif tif.is_enum():
                row_kind = 'enum'
            else:
                row_kind = 'type'
            if kind != 'all' and kind != row_kind:
                continue
            results.append([ordinal, name, row_kind, tif.get_size()])
        return results
    return read(_impl)


def _tg(args):
    name = args['name']
    def _impl():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(til, name):
            return tif.dstr()
        return ''
    return read(_impl)


def _type_decl(args):
    name = args['name']
    def _impl():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, name):
            return {'e': 'not found'}
        if tif.is_struct():
            return _struct_detail_in_ida(name)
        if tif.is_enum():
            members = []
            for member in _enum_constants_from_tif(tif):
                row = [member[0], _hex(member[1]), member[1]]
                if len(member) > 2 and member[2]:
                    row.append(member[2])
                members.append(row)
            return {
                'name': name,
                'kind': 'enum',
                'size': tif.get_size(),
                'decl': tif.dstr(),
                'members': members
            }
        return {
            'name': name,
            'kind': 'type',
            'size': tif.get_size(),
            'decl': tif.dstr()
        }
    return read(_impl)


def _tsa(args):
    ea = _ea(args['a'])
    def _impl():
        tif = ida_typeinf.tinfo_t()
        if not idaapi.get_tinfo(tif, ea):
            return {'e': 'no type'}
        if not tif.is_struct():
            return {'e': 'not struct', 'type': str(tif)}
        return {
            'addr': _hex(ea),
            'name': tif.get_type_name() or '',
            'size': tif.get_size(),
            'decl': tif.dstr()
        }
    return read(_impl)


def _struct_member_attr(member, name, default=None):
    try:
        v = getattr(member, name)
        return v() if callable(v) else v
    except:
        return default


def _struct_member_bits(member):
    for attr in ('size', 'size_bits'):
        v = _struct_member_attr(member, attr)
        if isinstance(v, int) and v >= 0:
            return v
    try:
        t = _struct_member_attr(member, 'type')
        if t:
            sz = t.get_size()
            if sz and sz > 0:
                return sz * 8
    except:
        pass
    return 0


def _enum_member_attr(member, name, default=None):
    try:
        v = getattr(member, name)
        return v() if callable(v) else v
    except:
        return default


def _enum_constants_from_tif(tif):
    constants = []
    try:
        enum_data = ida_typeinf.enum_type_data_t()
        if tif.get_enum_details(enum_data):
            for member in enum_data:
                name = _enum_member_attr(member, 'name', '') or ''
                value = _enum_member_attr(member, 'value')
                if value is None:
                    value = _enum_member_attr(member, 'val')
                if not name or value is None:
                    continue
                try:
                    value = int(value)
                except:
                    continue
                cmt = _enum_member_attr(member, 'cmt', '') or ''
                row = [name, value]
                if cmt:
                    row.append(cmt)
                constants.append(row)
    except:
        pass
    if constants:
        return constants
    try:
        return _enum_constants_from_decl(tif.dstr())
    except:
        return []


def _struct_detail_in_ida(name):
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name):
        return {'e': 'not found'}

    result = {
        'name': name,
        'size': tif.get_size(),
        'decl': tif.dstr(),
        'members': []
    }

    try:
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return result
        for m in udt:
            off_bits = _struct_member_attr(m, 'offset', 0) or 0
            size_bits = _struct_member_bits(m)
            mname = _struct_member_attr(m, 'name', '') or ''
            mtif = _struct_member_attr(m, 'type')
            mtype = str(mtif) if mtif else ''
            cmt = _struct_member_attr(m, 'cmt', '') or ''
            result['members'].append([
                off_bits // 8,
                size_bits // 8 if size_bits else 0,
                mname,
                mtype,
                cmt
            ])
    except Exception as ex:
        result['member_error'] = str(ex)
    return result


def _tgd(args):
    name = args['name']
    def _impl():
        return _struct_detail_in_ida(name)
    return read(_impl)


def _ts(args):
    decl = args['decl']
    def _impl():
        ordinal = _save_local_type_decl(decl)
        return 'ok' if ordinal else 'parse error'
    return write(_impl)


def _td(args):
    name = args['name']
    def _impl():
        return _delete_local_type(name)
    return write(_impl)


def _el(args):
    q = args.get('q', '').lower()
    def _impl():
        til = ida_typeinf.get_idati()
        results = []
        for ordinal in _local_type_ordinals(til):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ordinal):
                if tif.is_enum():
                    name = tif.get_type_name()
                    if not q or q in name.lower():
                        results.append([name, tif.get_size()])
        return results
    return read(_impl)


def _eg(args):
    name = args['name']
    def _impl():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(til, name):
            return tif.dstr()
        return ''
    return read(_impl)


def _enum_eval_expr(expr, known):
    import re
    expr = expr.strip()
    expr = re.sub(r'\b([0-9A-Fa-f]+)[uUlL]+\b', r'\1', expr)
    expr = re.sub(r'\b[A-Za-z_][A-Za-z0-9_]*\b', lambda m: str(known.get(m.group(0), 0)), expr)
    if not all(c in '0123456789abcdefABCDEFxX+-*/%()<>&|^~ \t' for c in expr):
        raise ValueError('bad enum expr')
    return int(eval(compile(expr, '<enum>', 'eval'), {"__builtins__": {}}, {}))


def _enum_constants_from_decl(decl):
    import re
    body_match = re.search(r'\{(.*)\}', decl, re.S)
    if not body_match:
        return []
    body = re.sub(r'/\*.*?\*/|//.*?$', '', body_match.group(1), flags=re.S | re.M)
    parts = [p.strip() for p in body.split(',') if p.strip()]
    consts = []
    known = {}
    cur = -1
    for part in parts:
        m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*(.*))?$', part)
        if not m:
            continue
        cname = m.group(1)
        expr = (m.group(2) or '').strip()
        try:
            cur = _enum_eval_expr(expr, known) if expr else cur + 1
        except:
            cur += 1
        known[cname] = cur
        consts.append([cname, cur])
    return consts


def _find_enum_value_in_ida(val, q='', limit=50):
    q = (q or '').lower()
    til = ida_typeinf.get_idati()
    exact = []
    flags = []
    for ordinal in _local_type_ordinals(til):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal) or not tif.is_enum():
            continue
        ename = tif.get_type_name() or ''
        decl = tif.dstr()
        consts = _enum_constants_from_tif(tif)
        names_text = ' '.join(c[0] for c in consts).lower()
        if q and q not in ename.lower() and q not in decl.lower() and q not in names_text:
            continue
        if not consts:
            continue

        ex = [[n, _hex(v)] for n, v, *_ in consts if v == val]
        if ex:
            exact.append([ename, ex])

        parts = [[n, _hex(v)] for n, v, *_ in consts if v and (val & v) == v]
        if parts:
            flags.append([ename, parts[:32]])

        if len(exact) + len(flags) >= limit:
            break

    return {'value': _hex(val), 'exact': exact[:limit], 'flags': flags[:limit]}


def _find_enum_value(args):
    val = _num(args['val'])
    q = args.get('q', '').lower()
    limit = min(args.get('n', 50), 500)
    def _impl():
        return _find_enum_value_in_ida(val, q, limit)

    return read(_impl)


def _guess_field_size(mtype, msize):
    if msize:
        return msize
    t = (mtype or '').lower()
    if '*' in t or 'qword' in t or '__int64' in t or 'uint64' in t:
        return 8
    if 'dword' in t or '__int32' in t or 'uint32' in t or 'int ' in t:
        return 4
    if 'word' in t or '__int16' in t or 'uint16' in t:
        return 2
    if 'byte' in t or 'char' in t or 'bool' in t:
        return 1
    return 0


def _read_struct(args):
    name = args['name']
    ea = _ea(args['a'])
    source = args.get('source', 'idb').lower()
    include_enums = bool(args.get('enums', 1))

    detail = read(lambda: _struct_detail_in_ida(name))
    if isinstance(detail, dict) and 'e' in detail:
        return detail

    size = int(detail.get('size') or 0)
    if size <= 0:
        return {'e': 'struct has unknown size', 'struct': detail}
    if size > 0x100000:
        return {'e': 'struct too large (max 1MB)', 'size': size}

    if source == 'kernel':
        from .kdriver import read_kernel_memory
        raw = read_kernel_memory(ea, size)
        if isinstance(raw, dict):
            return raw
        data = bytes.fromhex(raw)
    elif source == 'idb':
        data = read(lambda: ida_bytes.get_bytes(ea, size))
        if not data:
            return {'e': f'no IDB bytes at {_hex(ea)}'}
    else:
        return {'e': 'source must be idb or kernel'}

    fields = []
    enum_cache = {}
    for off, msize, mname, mtype, cmt in detail.get('members', []):
        fsize = _guess_field_size(mtype, int(msize or 0))
        if fsize <= 0:
            fsize = 1
        raw = data[off:off + fsize] if off < len(data) else b''
        row = {
            'off': _hex(off),
            'size': fsize,
            'name': mname,
            'type': mtype,
            'raw': raw.hex()
        }
        if cmt:
            row['cmt'] = cmt
        if raw and fsize <= 8:
            val = int.from_bytes(raw.ljust(fsize, b'\x00'), 'little')
            row['value'] = _hex(val)
            if include_enums and val:
                q = (mtype or mname or '').replace('*', '').replace('const ', '').strip()
                key = (val, q)
                if key not in enum_cache:
                    enum_cache[key] = read(lambda v=val, qq=q: _find_enum_value_in_ida(v, qq, 8))
                    if not enum_cache[key].get('exact') and not enum_cache[key].get('flags') and q:
                        enum_cache[key] = read(lambda v=val: _find_enum_value_in_ida(v, '', 8))
                cand = enum_cache[key]
                if cand.get('exact') or cand.get('flags'):
                    row['enum'] = cand
        elif raw and ('char' in (mtype or '').lower() or fsize > 8):
            z = raw.find(b'\x00')
            preview = raw[:z if z >= 0 else min(len(raw), 64)]
            try:
                row['str'] = preview.decode('utf-8', errors='replace')
            except:
                pass
        fields.append(row)

    return {
        'addr': _hex(ea),
        'source': source,
        'struct': name,
        'size': size,
        'raw': data[:size].hex(),
        'fields': fields
    }


def _es(args):
    decl = args['decl']
    def _impl():
        ordinal = _save_local_type_decl(decl)
        return 'ok' if ordinal else 'parse error'
    return write(_impl)


def _lti(args):
    q = args.get('q', '').lower()
    def _impl():
        til = ida_typeinf.get_idati()
        results = []
        for ordinal in _local_type_ordinals(til):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ordinal):
                name = tif.get_type_name()
                if name and (not q or q in name.lower()):
                    results.append([ordinal, name, tif.dstr()])
        return results
    return read(_impl)


def _ltg(args):
    ordinal = args['ord']
    def _impl():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(til, ordinal):
            return tif.dstr()
        return ''
    return read(_impl)


def _lts(args):
    decl = args['decl']
    def _impl():
        ordinal = _save_local_type_decl(decl)
        return ordinal if ordinal else 'fail'
    return write(_impl)


# --- 4.7 Segments ---

def _segs(args):
    cache = get_cache()
    data = cache.get_segments()
    return [[_hex(s), _hex(e), name, cls, perm, bits] for s, e, name, cls, perm, bits in data]


def _segi(args):
    ea = _ea(args['a'])
    def _impl():
        seg = ida_segment.getseg(ea)
        if not seg:
            return None
        return {
            'start': _hex(seg.start_ea),
            'end': _hex(seg.end_ea),
            'name': ida_segment.get_segm_name(seg),
            'cls': ida_segment.get_segm_class(seg),
            'perm': seg.perm,
            'bits': seg.bitness
        }
    return read(_impl)


# --- 4.8 Xrefs ---

def _xto(args):
    ea = _ea(args['a'])
    def _impl():
        results = []
        for xref in idautils.XrefsTo(ea, 0):
            fn, cmt = _addr_ctx(xref.frm)
            row = [_hex(xref.frm), xref.type, fn]
            if cmt:
                row.append(cmt)
            results.append(row)
        return results
    return read(_impl)


def _xfrom(args):
    ea = _ea(args['a'])
    def _impl():
        results = []
        for xref in idautils.XrefsFrom(ea, 0):
            fn, cmt = _addr_ctx(xref.to)
            row = [_hex(xref.to), xref.type, fn]
            if cmt:
                row.append(cmt)
            results.append(row)
        return results
    return read(_impl)


def _xtof(args):
    struct_name = args['struct']
    field_name = args['field']
    def _impl():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, struct_name):
            return {'e': 'struct not found'}

        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return {'e': 'cannot read struct'}

        field_off = None
        field_tid = idaapi.BADADDR
        for member in udt:
            name = _struct_member_attr(member, 'name', '') or ''
            if name != field_name:
                continue
            field_off = (_struct_member_attr(member, 'offset', 0) or 0) // 8
            try:
                field_tid = _struct_member_attr(member, 'tid', idaapi.BADADDR)
            except:
                field_tid = idaapi.BADADDR
            break

        if field_off is None:
            return {'e': 'field not found'}

        results = []
        if field_tid != idaapi.BADADDR:
            for xref in idautils.XrefsTo(field_tid, 0):
                fn, cmt = _addr_ctx(xref.frm)
                row = [_hex(xref.frm), xref.type, fn]
                if cmt:
                    row.append(cmt)
                results.append(row)
        elif hasattr(ida_typeinf, 'get_udm_tid'):
            try:
                field_tid = ida_typeinf.get_udm_tid(tif, field_off * 8)
                if field_tid != idaapi.BADADDR:
                    for xref in idautils.XrefsTo(field_tid, 0):
                        fn, cmt = _addr_ctx(xref.frm)
                        row = [_hex(xref.frm), xref.type, fn]
                        if cmt:
                            row.append(cmt)
                        results.append(row)
            except:
                pass

        return {
            'struct': struct_name,
            'field': field_name,
            'off': field_off,
            'xrefs': results
        }
    return read(_impl)


# --- 4.9 Search ---

def _srch(args):
    pat = args['pat']
    start = _ea(args['start']) if 'start' in args else None
    direction = args.get('dir', 1)

    def _impl():
        if start is None:
            s = ida_ida.inf_get_min_ea()
        else:
            s = start
        flag = ida_bytes.BIN_SEARCH_FORWARD if direction else ida_bytes.BIN_SEARCH_BACKWARD
        flag |= ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW
        compiled = ida_bytes.compiled_binpat_vec_t()
        ida_bytes.parse_binpat_str(compiled, s, pat, 16)
        results = []
        ea = s
        for _ in range(256):
            ea = _bin_search_ea(ida_bytes.bin_search(ea, ida_ida.inf_get_max_ea(), compiled, flag))
            if ea == idaapi.BADADDR:
                break
            func = ida_funcs.get_func(ea)
            fname = ida_funcs.get_func_name(func.start_ea) if func else ''
            results.append([_hex(ea), fname])
            ea += 1
        return results
    return read(_impl)


def _strs(args):
    q = args.get('q', '')
    off = args.get('off', 0)
    n = min(args.get('n', 100), 1000)
    if n <= 0:
        return []
    cache = get_cache()
    data = cache.get_strings(q, off, n)
    return [[_hex(ea), s, st] for ea, s, st in data]


def _imm(args):
    val = _ea(args['val'])
    def _impl():
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        flag = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW

        if val <= 0xFF:
            w = 1
        elif val <= 0xFFFF:
            w = 2
        elif val <= 0xFFFFFFFF:
            w = 4
        else:
            w = 8

        pat_bytes = val.to_bytes(w, byteorder='little')
        pat_hex = ' '.join(f'{b:02X}' for b in pat_bytes)
        compiled = ida_bytes.compiled_binpat_vec_t()
        ida_bytes.parse_binpat_str(compiled, min_ea, pat_hex, 16)

        results = []
        ea = min_ea
        for _ in range(512):
            ea = _bin_search_ea(ida_bytes.bin_search(ea, max_ea, compiled, flag))
            if ea == idaapi.BADADDR:
                break
            func = ida_funcs.get_func(ea)
            fname = ida_funcs.get_func_name(func.start_ea) if func else ''
            results.append([_hex(ea), fname])
            ea += 1
            if len(results) >= 256:
                break
        return results
    return read(_impl)


# --- 4.10 Imports/Exports ---

def _imp(args):
    cache = get_cache()
    data = cache.get_imports()
    return [[mod, name, _hex(ea), ordinal] for mod, name, ea, ordinal in data]


def _exp(args):
    cache = get_cache()
    data = cache.get_exports()
    return [[_hex(ea), name, ordinal] for ea, name, ordinal in data]


def _ent(args):
    def _impl():
        results = []
        qty = ida_entry.get_entry_qty()
        for i in range(qty):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal) or ''
            results.append([_hex(ea), name])
        return results
    return read(_impl)


# --- 4.11 CFG ---

def _cfg(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func'}
        fc = ida_gdl.FlowChart(func)
        nodes = []
        edges = []
        for block in fc:
            nodes.append([_hex(block.start_ea), _hex(block.end_ea)])
            for succ_block in _block_succs(block):
                edges.append([_hex(block.start_ea), _hex(succ_block.start_ea)])
        return {'nodes': nodes, 'edges': edges}
    return read(_impl)


def _preds(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return []
        fc = ida_gdl.FlowChart(func)
        for block in fc:
            if block.start_ea <= ea < block.end_ea:
                return [_hex(pred.start_ea) for pred in _block_preds(block)]
        return []
    return read(_impl)


def _succs(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return []
        fc = ida_gdl.FlowChart(func)
        for block in fc:
            if block.start_ea <= ea < block.end_ea:
                return [_hex(succ.start_ea) for succ in _block_succs(block)]
        return []
    return read(_impl)


# --- 4.17 Call trees ---

def _ctree(args):
    """Build forward call tree: function -> all callees recursively.
    Uses CodeRefsFrom which only returns code-to-code refs (faster than XrefsFrom)."""
    ea = _ea(args['a'])
    max_depth = min(args.get('depth', 5), 16)

    def _impl():
        tree = {}
        visited = set()

        def _walk(func_ea, depth):
            if depth > max_depth or func_ea in visited:
                return
            visited.add(func_ea)
            func = ida_funcs.get_func(func_ea)
            if not func:
                return
            seen = set()
            callees = []
            for item_ea in idautils.FuncItems(func.start_ea):
                for target in idautils.CodeRefsFrom(item_ea, 0):
                    tfunc = ida_funcs.get_func(target)
                    if tfunc and tfunc.start_ea != func_ea and tfunc.start_ea not in seen:
                        seen.add(tfunc.start_ea)
                        callees.append((tfunc.start_ea, ida_funcs.get_func_name(tfunc.start_ea) or ''))
            node_key = _hex(func_ea)
            tree[node_key] = {
                'name': ida_funcs.get_func_name(func_ea) or '',
                'calls': [[_hex(c[0]), c[1]] for c in callees]
            }
            for c_ea, _ in callees:
                _walk(c_ea, depth + 1)

        _walk(ea, 0)
        return tree
    return read(_impl)


def _ctreet(args):
    """Build reverse call tree: who calls this function, recursively up.
    Uses CodeRefsTo which is O(xrefs to entry point) per function, no FuncItems scan."""
    ea = _ea(args['a'])
    max_depth = min(args.get('depth', 5), 16)

    def _impl():
        tree = {}
        visited = set()

        def _walk(func_ea, depth):
            if depth > max_depth or func_ea in visited:
                return
            visited.add(func_ea)
            seen = set()
            callers = []
            for xref_ea in idautils.CodeRefsTo(func_ea, 0):
                cfunc = ida_funcs.get_func(xref_ea)
                if cfunc and cfunc.start_ea != func_ea and cfunc.start_ea not in seen:
                    seen.add(cfunc.start_ea)
                    callers.append((cfunc.start_ea, ida_funcs.get_func_name(cfunc.start_ea) or ''))
            node_key = _hex(func_ea)
            tree[node_key] = {
                'name': ida_funcs.get_func_name(func_ea) or '',
                'callers': [[_hex(c[0]), c[1]] for c in callers]
            }
            for c_ea, _ in callers:
                _walk(c_ea, depth + 1)

        _walk(ea, 0)
        return tree
    return read(_impl)


# --- 4.12 Patches & Bookmarks ---

def _pat(args):
    ea = _ea(args['a'])
    hexstr = args['hex']
    data = bytes.fromhex(hexstr)
    def _impl():
        if ida_segment.getseg(ea) is None:
            return {'e': 'address not mapped'}
        for i, b in enumerate(data):
            cur = idc.get_wide_byte(ea + i)
            if cur == b:
                continue
            ida_bytes.patch_byte(ea + i, b)
            if idc.get_wide_byte(ea + i) != b:
                return 'fail'
        return 'ok'
    return write(_impl)


_KS_CACHE = {}


def _normalize_arch_name(arch, bits=None):
    text = (arch or '').strip().lower().replace('_', '-')
    text = text.replace(' ', '')
    aliases = {
        'amd64': 'x64',
        'x86-64': 'x64',
        'x86_64': 'x64',
        'metapc64': 'x64',
        'i386': 'x86',
        'i686': 'x86',
        'aarch64': 'arm64',
        'arm64': 'arm64',
        'armv8': 'arm64',
        'armv8a': 'arm64',
        'armv8-a': 'arm64',
    }
    if text in aliases:
        return aliases[text]
    if text.startswith('aarch64') or text.startswith('arm64') or text.startswith('armv8'):
        return 'arm64'
    if text.startswith('arm'):
        return 'arm64' if bits == 64 else 'arm'
    if text.startswith('metapc') or text.startswith('80'):
        return 'x64' if bits == 64 else 'x86'
    if text.startswith('mips'):
        return 'mips'
    if text.startswith('ppc'):
        return 'ppc'
    return text


def _ks_for_idb():
    try:
        import keystone
    except ImportError:
        return None, 'keystone not installed (pip install keystone-engine)'

    proc = (ida_ida.inf_get_procname() or '').lower()
    is64 = ida_ida.inf_is_64bit()
    is32 = ida_ida.inf_is_32bit_exactly() if hasattr(ida_ida, 'inf_is_32bit_exactly') else not is64
    bits = 64 if is64 else (32 if is32 else 16)
    proc_arch = _normalize_arch_name(proc, bits)
    key = (proc_arch, bits)
    if key in _KS_CACHE:
        return _KS_CACHE[key], ''

    arch = None
    mode = None
    if proc_arch in ('x86', 'x64'):
        arch = keystone.KS_ARCH_X86
        mode = keystone.KS_MODE_64 if bits == 64 else (keystone.KS_MODE_32 if bits == 32 else keystone.KS_MODE_16)
    elif proc_arch == 'arm64':
        arch = keystone.KS_ARCH_ARM64
        mode = keystone.KS_MODE_LITTLE_ENDIAN
    elif proc_arch == 'arm':
        arch = keystone.KS_ARCH_ARM
        mode = keystone.KS_MODE_ARM
    elif proc_arch == 'mips':
        arch = keystone.KS_ARCH_MIPS
        mode = (keystone.KS_MODE_MIPS64 if bits == 64 else keystone.KS_MODE_MIPS32) | keystone.KS_MODE_LITTLE_ENDIAN
    elif proc_arch == 'ppc':
        arch = keystone.KS_ARCH_PPC
        mode = (keystone.KS_MODE_PPC64 if bits == 64 else keystone.KS_MODE_PPC32) | keystone.KS_MODE_BIG_ENDIAN

    if arch is None:
        return None, f'unsupported processor for keystone: {proc} {bits}-bit'

    try:
        ks = keystone.Ks(arch, mode)
    except Exception as ex:
        return None, str(ex)
    _KS_CACHE[key] = ks
    return ks, ''


def _pasm(args):
    ea = _ea(args['a'])
    asm = args['asm']
    def _impl():
        ks, err = _ks_for_idb()
        if ks is None:
            return {'e': err}
        try:
            encoding, count = ks.asm(asm, ea)
        except Exception as ex:
            return {'e': f'assemble failed: {ex}'}
        if not encoding:
            return {'e': 'assemble produced no bytes'}
        data = bytes(encoding)
        for i, b in enumerate(data):
            ida_bytes.patch_byte(ea + i, b)
        return {'addr': _hex(ea), 'bytes': data.hex(), 'count': count}
    return write(_impl)


def _patl(args):
    def _impl():
        patches = []
        class _visitor:
            def __call__(self, ea, fpos, o, v):
                patches.append([_hex(ea), format(o & 0xFF, '02x'), format(v & 0xFF, '02x')])
                return 0
        ida_bytes.visit_patched_bytes(0, idaapi.BADADDR, _visitor())
        return patches
    return read(_impl)


def _bml(args):
    def _impl():
        results = []
        slot = 1
        while True:
            ea = idc.get_bookmark(slot)
            if ea is None or ea == idaapi.BADADDR:
                break
            desc = idc.get_bookmark_desc(slot) or ''
            results.append([_hex(ea), desc])
            slot += 1
        return results
    return read(_impl)


def _bms(args):
    ea = _ea(args['a'])
    desc = args.get('desc', '')
    def _impl():
        slot = 1
        while True:
            existing = idc.get_bookmark(slot)
            if existing is None or existing == idaapi.BADADDR:
                break
            slot += 1
        idc.put_bookmark(ea, 0, 0, 0, slot, desc)
        return 'ok'
    return write(_impl)


def _bmd(args):
    ea = _ea(args['a'])
    def _impl():
        slot = 1
        while True:
            existing = idc.get_bookmark(slot)
            if existing is None or existing == idaapi.BADADDR:
                break
            if existing == ea:
                idc.put_bookmark(idaapi.BADADDR, 0, 0, 0, slot, '')
                return 'ok'
            slot += 1
        return 'not found'
    return write(_impl)


# --- 4.13 Analysis ---

def _aa(args):
    def _impl():
        ida_auto.auto_wait()
        return 'ok'
    return write(_impl)


def _mkfn(args):
    ea = _ea(args['a'])
    end = _ea(args['end']) if 'end' in args else idaapi.BADADDR
    def _impl():
        return 'ok' if ida_funcs.add_func(ea, end) else 'fail'
    return write(_impl)


def _delfn(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if func:
            ida_funcs.del_func(func.start_ea)
            return 'ok'
        return 'no func'
    return write(_impl)


def _mkdt(args):
    ea = _ea(args['a'])
    sz = args.get('sz', 1)
    dtype = args.get('type', 'byte')
    def _impl():
        if sz <= 0:
            return {'e': 'sz must be positive'}
        if ida_segment.getseg(ea) is None:
            return {'e': 'address not mapped'}
        type_map = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8}
        dsz = type_map.get(dtype, sz)
        if dsz == 1:
            ok = ida_bytes.create_byte(ea, sz)
        elif dsz == 2:
            ok = ida_bytes.create_word(ea, sz)
        elif dsz == 4:
            ok = ida_bytes.create_dword(ea, sz)
        elif dsz == 8:
            ok = ida_bytes.create_qword(ea, sz)
        else:
            return {'e': 'type must be byte, word, dword, or qword'}
        return 'ok' if ok else 'fail'
    return write(_impl)


def _undef(args):
    ea = _ea(args['a'])
    sz = args['sz']
    def _impl():
        if sz <= 0:
            return {'e': 'sz must be positive'}
        if ida_segment.getseg(ea) is None:
            return {'e': 'address not mapped'}
        return 'ok' if ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, sz) else 'fail'
    return write(_impl)


# --- 4.14 Decompiler advanced ---

def _rnv(args):
    ea = _ea(args['a'])
    old = args['old']
    new = args['new']
    def _impl():
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                return 'decompile failed'
            lv = None
            for v in cfunc.lvars:
                if v.name == old:
                    lv = v
                    break
            if not lv:
                return 'var not found'
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = lv
            lsi.name = new
            if ida_hexrays.modify_user_lvar_info(cfunc.entry_ea, ida_hexrays.MLI_NAME, lsi):
                return 'ok'
            return 'fail'
        except Exception as ex:
            return str(ex)
    return write(_impl)


def _rtv(args):
    ea = _ea(args['a'])
    var_name = args['var']
    decl = args['decl']
    def _impl():
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                return 'decompile failed'
            lv = None
            for v in cfunc.lvars:
                if v.name == var_name:
                    lv = v
                    break
            if not lv:
                return 'var not found'
            tif = ida_typeinf.tinfo_t()
            til = ida_typeinf.get_idati()
            decl_s = decl if decl.rstrip().endswith(';') else decl + ';'
            if not _parse_tinfo_decl(tif, til, decl_s):
                return 'parse error'
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = lv
            lsi.type = tif
            if ida_hexrays.modify_user_lvar_info(cfunc.entry_ea, ida_hexrays.MLI_TYPE, lsi):
                return 'ok'
            return 'fail'
        except Exception as ex:
            return str(ex)
    return write(_impl)


def _func_frame_tif(func):
    if hasattr(ida_frame, 'get_func_frame'):
        try:
            tif = ida_typeinf.tinfo_t()
            if ida_frame.get_func_frame(tif, func):
                return tif
        except:
            pass
    return None


def _frame_udm_index(tif, name):
    try:
        idx = tif.find_udm(name)
        if idx is not None and idx >= 0:
            return idx
    except:
        pass
    try:
        udt = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt):
            for idx, member in enumerate(udt):
                if (_struct_member_attr(member, 'name', '') or '') == name:
                    return idx
    except:
        pass
    return -1


def _frame_member_info(func, name):
    tif = _func_frame_tif(func)
    if tif is not None:
        try:
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                for idx, member in enumerate(udt):
                    if (_struct_member_attr(member, 'name', '') or '') == name:
                        off_bits = _struct_member_attr(member, 'offset', 0) or 0
                        size_bits = _struct_member_bits(member)
                        return {
                            'tif': tif,
                            'idx': idx,
                            'off': off_bits // 8,
                            'size': size_bits // 8 if size_bits else 1,
                        }
        except:
            pass

    ida_struct, sptr = _frame_struct(func)
    if ida_struct and sptr:
        try:
            member = ida_struct.get_member_by_name(sptr, name)
            if member:
                return {
                    'struct': ida_struct,
                    'sptr': sptr,
                    'member': member,
                    'off': member.soff,
                    'size': max(member.eoff - member.soff, 1),
                }
        except:
            pass
    return None


def _parse_frame_type(decl):
    tif = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()
    decl = decl or 'unsigned char'
    decl = decl if decl.rstrip().endswith(';') else decl + ';'
    if not _parse_tinfo_decl(tif, til, decl):
        return None
    return tif


def _frame_struct(func):
    try:
        import ida_struct
        sptr = ida_struct.get_struct(func.frame)
        return ida_struct, sptr
    except:
        return None, None


def _fv_frame(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func'}

        tif = _func_frame_tif(func)
        if tif is not None:
            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                return []
            results = []
            for member in udt:
                off_bits = _struct_member_attr(member, 'offset', 0) or 0
                size_bits = _struct_member_bits(member)
                mtif = _struct_member_attr(member, 'type')
                results.append([
                    off_bits // 8,
                    size_bits // 8 if size_bits else 0,
                    _struct_member_attr(member, 'name', '') or '',
                    str(mtif) if mtif else ''
                ])
            return results

        ida_struct, sptr = _frame_struct(func)
        if not ida_struct or not sptr:
            return []
        results = []
        for i in range(sptr.memqty):
            member = sptr.get_member(i)
            if not member:
                continue
            results.append([
                member.soff,
                member.eoff - member.soff,
                ida_struct.get_member_name(member.id) or '',
                ''
            ])
        return results
    return read(_impl)


def _cfv(args):
    ea = _ea(args['a'])
    name = args['name']
    off = args.get('off', args.get('offset'))
    off = off if isinstance(off, int) else int(off, 0)
    decl = args.get('decl', 'unsigned char')
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func'}
        mtif = _parse_frame_type(decl)
        if mtif is None:
            return {'e': 'parse error'}

        if hasattr(ida_frame, 'add_frame_member'):
            try:
                return 'ok' if ida_frame.add_frame_member(func, name, off, mtif, None) else 'fail'
            except Exception as ex:
                return {'e': str(ex)}

        ida_struct, sptr = _frame_struct(func)
        if not ida_struct or not sptr:
            return {'e': 'no frame'}
        size = max(mtif.get_size(), 1)
        flags = ida_bytes.byte_flag()
        if size == 2:
            flags = ida_bytes.word_flag()
        elif size == 4:
            flags = ida_bytes.dword_flag()
        elif size == 8:
            flags = ida_bytes.qword_flag()
        try:
            rc = ida_struct.add_struc_member(sptr, name, off, flags, None, size)
            if rc != 0:
                return {'e': f'add_struc_member rc={rc}'}
            try:
                member = ida_struct.get_member_by_name(sptr, name)
                if member:
                    ida_struct.set_member_tinfo(sptr, member, 0, mtif, 0)
            except:
                pass
            return 'ok'
        except Exception as ex:
            return {'e': str(ex)}
    return write(_impl)


def _dfv(args):
    ea = _ea(args['a'])
    name = args['name']
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func'}

        info = _frame_member_info(func, name)
        if not info:
            return {'e': 'not found'}
        if hasattr(ida_frame, 'delete_frame_members'):
            try:
                if ida_frame.delete_frame_members(func, info['off'], info['off'] + info['size']):
                    return 'ok'
            except Exception as ex:
                frame_err = str(ex)
            else:
                frame_err = 'delete_frame_members failed'

        tif = info.get('tif')
        if tif is not None:
            try:
                return 'ok' if tif.del_udm(info['idx']) == ida_typeinf.TERR_OK else {'e': frame_err}
            except Exception as ex:
                return {'e': str(ex)}

        ida_struct, sptr = _frame_struct(func)
        if not ida_struct or not sptr:
            return {'e': 'no frame'}
        member = info.get('member') or ida_struct.get_member_by_name(sptr, name)
        if not member:
            return {'e': 'not found'}
        ida_struct.del_struc_member(sptr, member.soff)
        return 'ok'
    return write(_impl)


def _rfv(args):
    ea = _ea(args['a'])
    old = args['old']
    new = args['new']
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func'}

        info = _frame_member_info(func, old)
        if not info:
            return {'e': 'not found'}
        tif = info.get('tif')
        if tif is not None:
            try:
                return 'ok' if tif.rename_udm(info['idx'], new) == ida_typeinf.TERR_OK else 'fail'
            except Exception as ex:
                return {'e': str(ex)}

        ida_struct, sptr = _frame_struct(func)
        if not ida_struct or not sptr:
            return {'e': 'rename requires legacy frame struct API'}
        member = info.get('member') or ida_struct.get_member_by_name(sptr, old)
        if not member:
            return {'e': 'not found'}
        return 'ok' if ida_struct.set_member_name(sptr, member.soff, new) else 'fail'
    return write(_impl)


def _tfv(args):
    ea = _ea(args['a'])
    name = args['name']
    decl = args['decl']
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func'}
        mtif = _parse_frame_type(decl)
        if mtif is None:
            return {'e': 'parse error'}

        info = _frame_member_info(func, name)
        if not info:
            return {'e': 'not found'}
        if hasattr(ida_frame, 'set_frame_member_type'):
            try:
                if ida_frame.set_frame_member_type(func, info['off'], mtif, None):
                    return 'ok'
            except Exception as ex:
                frame_err = str(ex)
            else:
                frame_err = 'set_frame_member_type failed'

        tif = info.get('tif')
        if tif is not None:
            try:
                return 'ok' if tif.set_udm_type(info['idx'], mtif) == ida_typeinf.TERR_OK else {'e': frame_err}
            except Exception as ex:
                return {'e': str(ex)}

        ida_struct, sptr = _frame_struct(func)
        if not ida_struct or not sptr:
            return {'e': 'no frame'}
        member = info.get('member') or ida_struct.get_member_by_name(sptr, name)
        if not member:
            return {'e': 'not found'}
        try:
            return 'ok' if ida_struct.set_member_tinfo(sptr, member, 0, mtif, 0) else 'fail'
        except Exception as ex:
            return {'e': str(ex)}
    return write(_impl)


# --- 4.18 Batch write tools ---

def _batch_set_names(args):
    entries = args['names']
    def _impl():
        ok = 0
        for item in entries:
            ea = _ea(item[0])
            name = item[1]
            if ida_name.set_name(ea, name, ida_name.SN_NOWARN):
                ok += 1
        return {'ok': ok, 'fail': len(entries) - ok}
    return write(_impl)


def _batch_set_comments(args):
    entries = args['comments']
    def _impl():
        for item in entries:
            ea = _ea(item[0])
            text = item[1]
            rep = bool(item[2]) if len(item) > 2 else False
            ida_bytes.set_cmt(ea, text, rep)
        return {'ok': len(entries)}
    return write(_impl)


def _batch_set_types(args):
    entries = args['types']
    def _impl():
        ok = 0
        for item in entries:
            ea = _ea(item[0])
            decl = item[1]
            if _apply_type_decl(ea, decl):
                ok += 1
        return {'ok': ok, 'fail': len(entries) - ok}
    return write(_impl)


# --- 4.19 Enhanced read tools ---

def _batch_decompile(args):
    addrs = [_ea(a) for a in args['addrs']]
    def _impl():
        try:
            import ida_hexrays
        except:
            return {'e': 'hexrays not available'}
        results = []
        for ea in addrs:
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    lines = cfunc.get_pseudocode()
                    text = '\n'.join(ida_lines.tag_remove(l.line) for l in lines)
                    results.append([_hex(ea), text])
                else:
                    results.append([_hex(ea), None])
            except:
                results.append([_hex(ea), None])
        return results
    return read(_impl)


def _get_func_by_addr(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func at this addr'}
        start = func.start_ea
        name = ida_funcs.get_func_name(start) or ''
        cmt = ida_bytes.get_cmt(start, 0) or ida_bytes.get_cmt(start, 1) or ''
        return [_hex(start), name, cmt]
    return read(_impl)


# --- Kernel driver tools (iida-mcp-ioctl) ---

def _kernel_read(args):
    from .kdriver import read_kernel_memory
    return read_kernel_memory(_ea(args['a']), int(args['sz']))

def _kernel_modules(args):
    from .kdriver import get_module_list
    return get_module_list()

def _kernel_module_base(args):
    from .kdriver import get_module_base
    return get_module_base(args['name'])


def _kernel_read_values(args):
    from .kdriver import read_kernel_memory
    fmt = args.get('fmt', 'p').strip() or 'p'

    total = 0
    ops = []
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c == 'p':
            ops.append(('p', 8)); total += 8; i += 1
        elif c == 'd':
            ops.append(('d', 4)); total += 4; i += 1
        elif c == 'w':
            ops.append(('w', 2)); total += 2; i += 1
        elif c == 'b':
            ops.append(('b', 1)); total += 1; i += 1
        elif c == 's':
            ops.append(('s', 256)); total += 256; i += 1
        elif c.isdigit():
            j = i
            while j < len(fmt) and fmt[j].isdigit():
                j += 1
            if j < len(fmt) and fmt[j] == 'x':
                n = int(fmt[i:j])
                ops.append(('x', n)); total += n; i = j + 1
            else:
                return {'e': f'bad fmt at pos {i}: digits must end with x'}
        else:
            return {'e': f'bad fmt char: {c}'}

    if total == 0:
        return {'e': 'empty format'}
    if total > 65536:
        return {'e': 'total read too large'}

    def _read_one(addr_s):
        addr = _ea(addr_s)
        raw = read_kernel_memory(addr, total)
        if isinstance(raw, dict):
            return raw
        data = bytes.fromhex(raw)

        result = []
        off = 0
        for typ, sz in ops:
            if off + sz > len(data):
                result.append(None)
                break
            if typ == 'p':
                v = pystruct.unpack_from('<Q', data, off)[0]
                result.append(format(v, 'x'))
            elif typ == 'd':
                v = pystruct.unpack_from('<I', data, off)[0]
                result.append(v)
            elif typ == 'w':
                v = pystruct.unpack_from('<H', data, off)[0]
                result.append(v)
            elif typ == 'b':
                result.append(data[off])
            elif typ == 's':
                end = data.find(b'\x00', off, off + sz)
                if end == -1:
                    end = off + sz
                result.append(data[off:end].decode('utf-8', errors='replace'))
            elif typ == 'x':
                result.append(data[off:off + sz].hex())
            off += sz
        return result[0] if len(result) == 1 else result

    if 'addrs' in args:
        return [[a, _read_one(a)] for a in args.get('addrs', [])]
    if 'a' not in args:
        return {'e': 'a or addrs required'}
    return _read_one(args['a'])


def _ida_to_runtime(args):
    ea = _ea(args['a'])

    def _get_seg_and_pe():
        seg = ida_segment.getseg(ea)
        if not seg:
            return None
        seg_start = seg.start_ea
        seg_name = ida_segment.get_segm_name(seg)

        path = ida_nalt.get_input_file_path()
        image_base = 0
        sections = []
        try:
            with open(path, 'rb') as fp:
                dos = fp.read(64)
                if dos[:2] == b'MZ':
                    pe_off = pystruct.unpack_from('<I', dos, 60)[0]
                    fp.seek(pe_off + 4)
                    coff = fp.read(20)
                    nsections = pystruct.unpack_from('<H', coff, 2)[0]
                    opt_size = pystruct.unpack_from('<H', coff, 16)[0]
                    opt = fp.read(opt_size)
                    magic = pystruct.unpack_from('<H', opt, 0)[0]
                    if magic == 0x20b:
                        image_base = pystruct.unpack_from('<Q', opt, 24)[0]
                    else:
                        image_base = pystruct.unpack_from('<I', opt, 28)[0]
                    for _ in range(nsections):
                        shdr = fp.read(40)
                        sname = shdr[:8].rstrip(b'\x00').decode('ascii', errors='replace')
                        vaddr = pystruct.unpack_from('<I', shdr, 12)[0]
                        sections.append((sname, vaddr))
        except:
            pass

        return {
            'ea': ea,
            'seg_start': seg_start,
            'seg_name': seg_name,
            'image_base': image_base,
            'sections': sections,
            'filename': os.path.basename(path)
        }

    info = read(_get_seg_and_pe)
    if info is None:
        return {'e': f'address {_hex(ea)} not in any segment'}

    rva = ea - info['image_base']

    mod_name = args.get('mod', '')
    if not mod_name:
        fname = info['filename']
        dot = fname.rfind('.')
        mod_name = fname[:dot] if dot > 0 else fname

    from .kdriver import get_module_base
    mod_result = get_module_base(mod_name)
    if isinstance(mod_result, dict) and 'e' in mod_result:
        return {'e': f'driver: {mod_result["e"]}. provide mod= or load driver.', 'rva': _hex(rva)}

    runtime_base = int(mod_result[0], 16)
    runtime_addr = runtime_base + rva

    return {
        'ida': _hex(ea),
        'rva': _hex(rva),
        'runtime_base': mod_result[0],
        'runtime': format(runtime_addr, 'x'),
        'mod': mod_name
    }


# --- Standalone utilities (no IDB required) ---

_CALC_ALLOWED = set('0123456789abcdefABCDEFxXoObB+-*/%()<>&|^~ \t')

def _calc(args):
    expr = args['expr'].strip()
    if not expr:
        return {'e': 'empty expression'}
    if not all(c in _CALC_ALLOWED for c in expr):
        return {'e': 'invalid characters in expression'}
    try:
        val = eval(compile(expr, '<calc>', 'eval', flags=0), {"__builtins__": {}}, {})
        if not isinstance(val, int):
            return {'e': 'result is not integer'}
        return [val, format(val & 0xFFFFFFFFFFFFFFFF, 'x')]
    except Exception as ex:
        return {'e': str(ex)}


def _disasm_bytes(args):
    try:
        import capstone
    except ImportError:
        return {'e': 'capstone not installed (pip install capstone)'}

    raw = bytes.fromhex(args['hex'].replace(' ', ''))
    arch_str = _normalize_arch_name(args.get('arch', 'x64'))
    base = _ea(args['addr']) if 'addr' in args else 0

    arch_map = {
        'x86':   (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        'x64':   (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        'arm':   (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        'arm64': (capstone.CS_ARCH_ARM64, getattr(capstone, 'CS_MODE_LITTLE_ENDIAN', 0)),
    }
    if arch_str not in arch_map:
        return {'e': f'unknown arch: {arch_str}, use x86/x64/arm/arm64/aarch64/armv8a'}

    cs_arch, cs_mode = arch_map[arch_str]
    md = capstone.Cs(cs_arch, cs_mode)
    result = []
    for insn in md.disasm(raw, base):
        result.append([format(insn.address, 'x'), insn.bytes.hex(), insn.mnemonic, insn.op_str])
    if not result:
        return {'e': 'no valid instructions'}
    return result


# ============================================================
# Dispatch table
# ============================================================

DISPATCH = {
    'get_info': _info,
    'read_file_bytes': _fraw,
    'addr_to_fileoff': _fmap,
    'parse_pe': _pe,
    'parse_elf': _elf,
    'get_cursor': _cursor,
    'get_cursor_func': _cursor_func,
    'list_functions': _fl,
    'get_func_info': _fi,
    'get_func_by_name': _fbn,
    'decompile': _dec,
    'get_func_type': _decl,
    'get_callers': _cf,
    'get_callees': _ct,
    'get_vars': _vars,
    'disassemble': _dis,
    'read_bytes': _rb,
    'read_value': _rval,
    'read_string': _rstr,
    'get_head': _head,
    'get_name': _gn,
    'set_name': _sn,
    'get_comment': _gc,
    'set_comment': _sc,
    'set_pseudocode_comment': _spc,
    'search_names': _an,
    'list_globals': _lg,
    'read_global': _rg,
    'get_type': _gt,
    'set_type': _st,
    'set_c_decls': _cdecls,
    'list_types': _types,
    'get_type_decl': _type_decl,
    'read_struct': _read_struct,
    'delete_type': _td,
    'find_enum_value': _find_enum_value,
    'list_segments': _segs,
    'get_segment_info': _segi,
    'xrefs_to': _xto,
    'xrefs_from': _xfrom,
    'xrefs_to_field': _xtof,
    'search_bytes': _srch,
    'search_strings': _strs,
    'search_imm': _imm,
    'list_imports': _imp,
    'list_exports': _exp,
    'list_entries': _ent,
    'get_cfg': _cfg,
    'patch_bytes': _pat,
    'patch_asm': _pasm,
    'patch_list': _patl,
    'bookmark_list': _bml,
    'bookmark_set': _bms,
    'bookmark_delete': _bmd,
    'reanalyze': _aa,
    'create_function': _mkfn,
    'delete_function': _delfn,
    'make_data': _mkdt,
    'undefine': _undef,
    'rename_var': _rnv,
    'retype_var': _rtv,
    'list_frame_vars': _fv_frame,
    'create_frame_var': _cfv,
    'delete_frame_var': _dfv,
    'rename_frame_var': _rfv,
    'retype_frame_var': _tfv,
    'call_tree': _ctree,
    'callers_tree': _ctreet,
    'get_func_by_addr': _get_func_by_addr,
    'kernel_read': _kernel_read,
    'kernel_modules': _kernel_modules,
    'kernel_module_base': _kernel_module_base,
    'kernel_read_values': _kernel_read_values,
    'ida_to_runtime': _ida_to_runtime,
    'calc': _calc,
    'disasm_bytes': _disasm_bytes,
}


_CACHE_INVALIDATING = frozenset([
    'set_name', 'set_type', 'delete_type',
    'set_c_decls', 'patch_bytes', 'patch_asm',
    'create_function', 'delete_function', 'make_data', 'undefine', 'reanalyze',
    'rename_var', 'retype_var', 'create_frame_var', 'delete_frame_var',
    'rename_frame_var', 'retype_frame_var'
])


def execute_tool(tool, args):
    """Execute a single tool. Used as local_handler."""
    fn = DISPATCH.get(tool)
    if not fn:
        return {'e': f'unknown tool: {tool}'}
    try:
        result = fn(args)
        if tool in _CACHE_INVALIDATING:
            import threading
            cache = get_cache()
            cache.invalidate()
            threading.Thread(target=cache.ensure_built, daemon=True).start()
        return result
    except Exception as ex:
        return {'e': str(ex)}
