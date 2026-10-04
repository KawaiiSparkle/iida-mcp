"""ELF metadata parsing helpers."""
import os
import struct as pystruct


ELF_MACHINE_NAMES = {
    3: 'x86',
    8: 'MIPS',
    20: 'PowerPC',
    21: 'PowerPC64',
    40: 'ARM',
    62: 'x86-64',
    183: 'AArch64',
    243: 'RISC-V',
}

ELF_TYPE_NAMES = {
    0: 'NONE',
    1: 'REL',
    2: 'EXEC',
    3: 'DYN',
    4: 'CORE',
}

ELF_PH_TYPE_NAMES = {
    0: 'NULL',
    1: 'LOAD',
    2: 'DYNAMIC',
    3: 'INTERP',
    4: 'NOTE',
    5: 'SHLIB',
    6: 'PHDR',
    7: 'TLS',
    0x6474e550: 'GNU_EH_FRAME',
    0x6474e551: 'GNU_STACK',
    0x6474e552: 'GNU_RELRO',
    0x6474e553: 'GNU_PROPERTY',
}

ELF_SH_TYPE_NAMES = {
    0: 'NULL',
    1: 'PROGBITS',
    2: 'SYMTAB',
    3: 'STRTAB',
    4: 'RELA',
    5: 'HASH',
    6: 'DYNAMIC',
    7: 'NOTE',
    8: 'NOBITS',
    9: 'REL',
    11: 'DYNSYM',
    14: 'INIT_ARRAY',
    15: 'FINI_ARRAY',
    0x6ffffff5: 'GNU_ATTRIBUTES',
    0x6ffffff6: 'GNU_HASH',
    0x6ffffffe: 'VERNEED',
    0x6fffffff: 'VERSYM',
}

ELF_DYN_TAG_NAMES = {
    0: 'NULL',
    1: 'NEEDED',
    2: 'PLTRELSZ',
    3: 'PLTGOT',
    4: 'HASH',
    5: 'STRTAB',
    6: 'SYMTAB',
    7: 'RELA',
    8: 'RELASZ',
    9: 'RELAENT',
    10: 'STRSZ',
    11: 'SYMENT',
    12: 'INIT',
    13: 'FINI',
    14: 'SONAME',
    15: 'RPATH',
    17: 'REL',
    18: 'RELSZ',
    19: 'RELENT',
    20: 'PLTREL',
    23: 'JMPREL',
    25: 'INIT_ARRAY',
    26: 'FINI_ARRAY',
    27: 'INIT_ARRAYSZ',
    28: 'FINI_ARRAYSZ',
    29: 'RUNPATH',
    0x6ffffef5: 'GNU_HASH',
    0x6ffffff0: 'VERSYM',
    0x6ffffffe: 'VERNEED',
    0x6fffffff: 'VERNEEDNUM',
}

ELF_DYNAMIC_SCAN_LIMIT = 65536


def _hex(val):
    return format(val, 'x')


def parse_elf(path, detail='summary', limit=128):
    detail = (detail or 'summary').strip().lower()
    full_detail = detail in ('full', 'all', 'verbose')
    limit = min(max(int(limit), 1), 1024)
    with open(path, 'rb') as fp:
        ident = fp.read(16)
        if len(ident) < 16 or ident[:4] != b'\x7fELF':
            return {'e': 'not ELF'}
        ei_class = ident[4]  # 1=32, 2=64
        ei_data = ident[5]   # 1=LE, 2=BE
        if ei_class not in (1, 2):
            return {'e': f'unsupported ELF class: {ei_class}'}
        if ei_data not in (1, 2):
            return {'e': f'unsupported ELF data encoding: {ei_data}'}
        endian = '<' if ei_data == 1 else '>'
        is64 = ei_class == 2
        file_size = os.path.getsize(path)

        if is64:
            hdr = fp.read(48)
            if len(hdr) < 48:
                return {'e': 'truncated ELF64 header'}
            etype, machine = pystruct.unpack_from(endian + 'HH', hdr, 0)
            entry = pystruct.unpack_from(endian + 'Q', hdr, 8)[0]
            phoff = pystruct.unpack_from(endian + 'Q', hdr, 16)[0]
            shoff = pystruct.unpack_from(endian + 'Q', hdr, 24)[0]
            flags = pystruct.unpack_from(endian + 'I', hdr, 32)[0]
            ehsize = pystruct.unpack_from(endian + 'H', hdr, 36)[0]
            phentsize = pystruct.unpack_from(endian + 'H', hdr, 38)[0]
            phnum = pystruct.unpack_from(endian + 'H', hdr, 40)[0]
            shentsize = pystruct.unpack_from(endian + 'H', hdr, 42)[0]
            shnum = pystruct.unpack_from(endian + 'H', hdr, 44)[0]
            shstrndx = pystruct.unpack_from(endian + 'H', hdr, 46)[0]
        else:
            hdr = fp.read(36)
            if len(hdr) < 36:
                return {'e': 'truncated ELF32 header'}
            etype, machine = pystruct.unpack_from(endian + 'HH', hdr, 0)
            entry = pystruct.unpack_from(endian + 'I', hdr, 8)[0]
            phoff = pystruct.unpack_from(endian + 'I', hdr, 12)[0]
            shoff = pystruct.unpack_from(endian + 'I', hdr, 16)[0]
            flags = pystruct.unpack_from(endian + 'I', hdr, 20)[0]
            ehsize = pystruct.unpack_from(endian + 'H', hdr, 24)[0]
            phentsize = pystruct.unpack_from(endian + 'H', hdr, 26)[0]
            phnum = pystruct.unpack_from(endian + 'H', hdr, 28)[0]
            shentsize = pystruct.unpack_from(endian + 'H', hdr, 30)[0]
            shnum = pystruct.unpack_from(endian + 'H', hdr, 32)[0]
            shstrndx = pystruct.unpack_from(endian + 'H', hdr, 34)[0]

        def _read_at(off, size, cap=0x400000):
            if off < 0 or size <= 0 or off >= file_size:
                return b''
            fp.seek(off)
            return fp.read(min(size, file_size - off, cap))

        def _cstr(blob, off):
            if off is None or off < 0 or off >= len(blob):
                return ''
            end = blob.find(b'\x00', off)
            if end < 0:
                end = len(blob)
            return blob[off:end].decode('utf-8', errors='replace')

        phdr = []
        phdrs = []
        if phoff:
            expected = 56 if is64 else 32
            ent = phentsize or expected
            if ent < expected:
                return {'e': f'bad ELF program header size: {ent}'}
            for idx in range(min(phnum, 64)):
                p = _read_at(phoff + idx * ent, ent, cap=ent)
                if len(p) < expected:
                    break
                if is64:
                    ptype, pflags = pystruct.unpack_from(endian + 'II', p, 0)
                    poff, pvaddr, ppaddr, pfilesz, pmemsz, palign = pystruct.unpack_from(endian + 'QQQQQQ', p, 8)
                else:
                    ptype, poff, pvaddr, ppaddr, pfilesz, pmemsz, pflags, palign = pystruct.unpack_from(endian + 'IIIIIIII', p, 0)
                phdr.append([ptype, _hex(pvaddr), pmemsz, pflags])
                phdrs.append({
                    'type': ptype,
                    'type_name': ELF_PH_TYPE_NAMES.get(ptype, _hex(ptype)),
                    'off': poff,
                    'vaddr': _hex(pvaddr),
                    'paddr': _hex(ppaddr),
                    'filesz': pfilesz,
                    'memsz': pmemsz,
                    'flags': pflags,
                    'align': palign,
                })

        sections_raw = []
        sections = []
        section_by_name = {}
        if shoff and shentsize:
            expected = 64 if is64 else 40
            if shentsize < expected:
                return {'e': f'bad ELF section header size: {shentsize}'}
            for idx in range(min(shnum, 4096)):
                sh = _read_at(shoff + idx * shentsize, shentsize, cap=shentsize)
                if len(sh) < expected:
                    break
                if is64:
                    name_off, stype, sflags, saddr, soff, ssize, slink, sinfo, salign, sent = pystruct.unpack_from(endian + 'IIQQQQIIQQ', sh, 0)
                else:
                    name_off, stype, sflags, saddr, soff, ssize, slink, sinfo, salign, sent = pystruct.unpack_from(endian + 'IIIIIIIIII', sh, 0)
                sections_raw.append({
                    'name_off': name_off, 'type': stype, 'flags': sflags,
                    'addr': saddr, 'off': soff, 'size': ssize, 'link': slink,
                    'info': sinfo, 'align': salign, 'entsize': sent,
                })

        shstr = b''
        if 0 <= shstrndx < len(sections_raw):
            sec = sections_raw[shstrndx]
            shstr = _read_at(sec['off'], sec['size'])

        for idx, sec in enumerate(sections_raw):
            name = _cstr(shstr, sec['name_off'])
            row = {
                'idx': idx,
                'name': name,
                'type': sec['type'],
                'type_name': ELF_SH_TYPE_NAMES.get(sec['type'], _hex(sec['type'])),
                'addr': _hex(sec['addr']),
                'off': sec['off'],
                'size': sec['size'],
                'flags': sec['flags'],
                'link': sec['link'],
                'info': sec['info'],
                'align': sec['align'],
                'entsize': sec['entsize'],
            }
            sections.append(row)
            if name:
                section_by_name[name] = row

        def _section_data(index_or_name):
            sec = section_by_name.get(index_or_name) if isinstance(index_or_name, str) else None
            if sec is None and isinstance(index_or_name, int) and 0 <= index_or_name < len(sections):
                sec = sections[index_or_name]
            return _read_at(sec['off'], sec['size']) if sec else b''

        strtab_cache = {}
        def _strtab(index):
            if index not in strtab_cache:
                strtab_cache[index] = _section_data(index)
            return strtab_cache[index]

        dynamic = []
        dynamic_count = 0
        dynamic_scan_truncated = False
        needed = []
        soname = ''
        dynstr = _section_data('.dynstr')
        dynsec = section_by_name.get('.dynamic')
        if dynsec:
            expected = 16 if is64 else 8
            ent = dynsec.get('entsize') or expected
            data = _section_data('.dynamic')
            if ent >= expected:
                dynamic_count = dynsec['size'] // ent
                scan_size = min(len(data), ELF_DYNAMIC_SCAN_LIMIT * ent)
                saw_dynamic_null = False
                for off in range(0, scan_size, ent):
                    if off + expected > len(data):
                        break
                    if is64:
                        tag, val = pystruct.unpack_from(endian + 'qQ', data, off)
                    else:
                        tag, val = pystruct.unpack_from(endian + 'iI', data, off)
                    item = None
                    if len(dynamic) < limit:
                        item = {'tag': tag, 'name': ELF_DYN_TAG_NAMES.get(tag, _hex(tag & 0xFFFFFFFFFFFFFFFF)), 'val': _hex(val)}
                    if tag in (1, 14, 15, 29):
                        text = _cstr(dynstr, val)
                        if item is not None:
                            item['str'] = text
                        if tag == 1 and text:
                            needed.append(text)
                        elif tag == 14:
                            soname = text
                    if item is not None:
                        dynamic.append(item)
                    if tag == 0:
                        saw_dynamic_null = True
                        break
                dynamic_scan_truncated = not saw_dynamic_null and scan_size < len(data)

        result = {
            'class': ei_class,
            'class_name': 'ELF64' if is64 else 'ELF32',
            'machine': machine,
            'machine_name': ELF_MACHINE_NAMES.get(machine, str(machine)),
            'entry': _hex(entry),
            'type': etype,
            'type_name': ELF_TYPE_NAMES.get(etype, str(etype)),
            'phdr': phdr,
            'phnum': phnum,
            'shnum': shnum,
            'needed': needed,
            'soname': soname,
            'dynamic_scan_truncated': dynamic_scan_truncated,
        }
        if full_detail:
            symbols = []
            def _parse_symbols(section_name):
                sec = section_by_name.get(section_name)
                if not sec:
                    return None
                data = _section_data(section_name)
                strings = _strtab(sec['link'])
                expected = 24 if is64 else 16
                ent = sec['entsize'] or expected
                if ent < expected:
                    return None
                count = sec['size'] // ent
                rows = []
                for idx in range(min(count, limit)):
                    off = idx * ent
                    if off + expected > len(data):
                        break
                    if is64:
                        st_name, st_info, st_other, st_shndx, st_value, st_size = pystruct.unpack_from(endian + 'IBBHQQ', data, off)
                    else:
                        st_name, st_value, st_size, st_info, st_other, st_shndx = pystruct.unpack_from(endian + 'IIIBBH', data, off)
                    name = _cstr(strings, st_name)
                    if not name and st_value == 0 and st_size == 0:
                        continue
                    rows.append({'name': name, 'value': _hex(st_value), 'size': st_size, 'bind': st_info >> 4, 'type': st_info & 0xF, 'shndx': st_shndx})
                return {'section': section_name, 'count': count, 'returned': len(rows), 'items': rows}

            for name in ('.dynsym', '.symtab'):
                parsed = _parse_symbols(name)
                if parsed:
                    symbols.append(parsed)

            relocations = []
            relocation_sections_count = 0
            relocation_items_returned = 0
            relocations_truncated = False
            for sec in sections:
                if sec['type'] not in (4, 9):
                    continue
                relocation_sections_count += 1
                if len(relocations) >= limit:
                    relocations_truncated = True
                    continue
                data = _section_data(sec['idx'])
                expected = (24 if is64 else 12) if sec['type'] == 4 else (16 if is64 else 8)
                ent = sec['entsize'] or expected
                if ent < expected:
                    continue
                count = sec['size'] // ent
                rows = []
                remaining = limit - relocation_items_returned
                if remaining <= 0:
                    relocations_truncated = True
                    continue
                for off in range(0, min(len(data), remaining * ent), ent):
                    if off + expected > len(data):
                        break
                    if is64:
                        if sec['type'] == 4:
                            r_offset, r_info, r_addend = pystruct.unpack_from(endian + 'QQq', data, off)
                        else:
                            r_offset, r_info = pystruct.unpack_from(endian + 'QQ', data, off)
                            r_addend = None
                        sym_index = r_info >> 32
                        r_type = r_info & 0xFFFFFFFF
                    else:
                        if sec['type'] == 4:
                            r_offset, r_info, r_addend = pystruct.unpack_from(endian + 'IIi', data, off)
                        else:
                            r_offset, r_info = pystruct.unpack_from(endian + 'II', data, off)
                            r_addend = None
                        sym_index = r_info >> 8
                        r_type = r_info & 0xFF
                    item = {'off': _hex(r_offset), 'type': r_type, 'sym': sym_index}
                    if r_addend is not None:
                        item['addend'] = r_addend
                    rows.append(item)
                    relocation_items_returned += 1
                if len(rows) < count:
                    relocations_truncated = True
                relocations.append({'section': sec['name'], 'type': sec['type_name'], 'count': count, 'returned': len(rows), 'items': rows})

            result.update({
                'data': ei_data,
                'endian': 'little' if ei_data == 1 else 'big',
                'flags': flags,
                'ehsize': ehsize,
                'phoff': phoff,
                'phentsize': phentsize,
                'phdrs': phdrs,
                'shoff': shoff,
                'shentsize': shentsize,
                'shstrndx': shstrndx,
                'sections_count': len(sections),
                'sections_returned': min(len(sections), limit),
                'sections': sections[:limit],
                'dynamic_count': dynamic_count,
                'dynamic_returned': len(dynamic),
                'dynamic': dynamic,
                'symbols': symbols,
                'relocation_sections_count': relocation_sections_count,
                'relocation_sections_returned': len(relocations),
                'relocation_items_returned': relocation_items_returned,
                'relocations_truncated': relocations_truncated,
                'relocations': relocations,
            })
        return result
