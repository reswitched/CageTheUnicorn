import inlines

(DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ,
 DT_RELAENT, DT_STRSZ, DT_SYMENT, DT_INIT, DT_FINI, DT_SONAME, DT_RPATH, DT_SYMBOLIC, DT_REL,
 DT_RELSZ, DT_RELENT, DT_PLTREL, DT_DEBUG, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW, DT_INIT_ARRAY,
 DT_FINI_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ, DT_RUNPATH, DT_FLAGS) = xrange(31)
DT_GNU_HASH = 0x6ffffef5
DT_VERSYM = 0x6ffffff0
DT_RELACOUNT = 0x6ffffff9
DT_RELCOUNT = 0x6ffffffa
DT_FLAGS_1 = 0x6ffffffb
DT_VERDEF = 0x6ffffffc
DT_VERDEFNUM = 0x6ffffffd

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

R_AARCH64_ABS64 = 257       # *reloc_addr = sym_val + addend
R_AARCH64_GLOB_DAT = 1025   # *reloc_addr = sym_val + addend
R_AARCH64_JUMP_SLOT = 1026  # *reloc_addr = sym_val + addend
R_AARCH64_RELATIVE = 1027   # *reloc_addr += base_addr + addend

def relocate(ctu, loadbase):
	def do_rela(roff, size, isJumprel):
		for i in xrange(0, size, 0x18):
			addr = loadbase + roff + i
			offset, info, addend = ctu.read64(addr), ctu.read64(addr+8), ctu.readS64(addr+16)
			rtype, rsym = info & 0xFFFFFFFF, info >> 32
			ea = loadbase + offset
			symname, symval = symbols[rsym]

			if rtype == R_AARCH64_RELATIVE:
				if symname:
					exports[symname] = loadbase + addend
				ctu.write64(ea, loadbase + addend)
			elif rtype == R_AARCH64_JUMP_SLOT or rtype == R_AARCH64_GLOB_DAT:
				if symval is None:
					imports[symname] = ea, 0
				else:
					exports[symname] = symval
					ctu.write64(ea, symval)
			elif rtype == R_AARCH64_ABS64:
				if symval is None:
					imports[symname] = ea, addend
				else:
					exports[symname] = symval + addend
					ctu.write64(ea, symval + addend)

	modoff = ctu.read32(loadbase + 4)
	assert ctu.readmem(loadbase + modoff, 4) == 'MOD0'

	dynoff = loadbase + modoff + ctu.read32(loadbase + modoff + 4)
	dynamic = {}
	while True:
		tag, val = ctu.read64(dynoff), ctu.read64(dynoff + 8)
		dynoff += 16
		if tag == DT_NULL:
			break
		dynamic[tag] = val

	strtabsize = dynamic[DT_STRSZ]
	strtab = ctu.readmem(loadbase + dynamic[DT_STRTAB], strtabsize)
	symbols = []
	imports = {}
	exports = {}
	addr = loadbase + dynamic[DT_SYMTAB]
	while True:
		stName, stShndx, stValue = (
			ctu.read32(addr), 
			ctu.read16(addr+6), 
			ctu.read64(addr+8), 
		)
		addr += 24
		if stName >= strtabsize:
			break
		name = strtab[stName:].split('\0', 1)[0]
		if stShndx:
			if name in inlines.functions and inlines.functions[name][2]:
				exports[name] = inlines.functions[name][1]
				symbols.append((name, inlines.functions[name][1]))
			else:
				exports[name] = loadbase + stValue
				symbols.append((name, loadbase + stValue))
		else:
			if name in inlines.functions and inlines.functions[name][2]:
				symbols.append((name, inlines.functions[name][1]))
			else:
				symbols.append((name, None))
	
	if DT_RELA in dynamic:
		do_rela(dynamic[DT_RELA], dynamic[DT_RELASZ], False)
	if DT_JMPREL in dynamic:
		do_rela(dynamic[DT_JMPREL], dynamic[DT_PLTRELSZ], True)

	return imports, exports
