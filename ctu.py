import gzip, math, os, os.path, re, signal, struct, sys, yaml
from cmd import Cmd
import lz4.block

import colorama
from colorama import Fore, Back, Style

from unicorn import *
from unicorn.arm64_const import *

from capstone import *

from ceval import ceval, compile
import util
from util import *
import inlines, relocation
from svc import SvcHandler
from threadmanager import ThreadManager
import mmio

TRACE_NONE = 0
TRACE_INSTRUCTION = 1
TRACE_BLOCK = 2
TRACE_FUNCTION = 4
TRACE_MEMORY = 8
TRACE_MEMCHECK = 16

def colorDepth(depth):
	colors = [Fore.RED, Fore.WHITE, Fore.GREEN, Fore.YELLOW, Style.BRIGHT + Fore.BLUE, Fore.MAGENTA, Fore.CYAN]

	return colors[depth % len(colors)]

INSN_PER_SLICE = 100000000 # How many instructions to execute per thread slice

class HandleJar(object):
	def __init__(self, ctu):
		self.ctu = ctu
		self.jar = {}

	def __setitem__(self, handle, obj):
		self.jar[handle] = obj

	def __getitem__(self, handle):
		if handle in self.jar:
			return self.jar[handle]
		print '~~ Unknown handle 0x%08x ~~' % handle
		self.ctu.debugbreak()
		return None

	def __delitem__(self, handle):
		del self.jar[handle]

	def __contains__(self, handle):
		return handle in self.jar

	def items(self):
		return self.jar.items()

	def replace(self, old, new):
		self.jar = {k:v if v is not old else new for k, v in self.jar.items()}

class CTU(Cmd, object):
	def __init__(self, flags=0):
		Cmd.__init__(self)

		colorama.init()
		self.initialized = False
		self.exiting = False
		self.firstLoad = True

		IPCMessage.ctu = self

		self.flags = 0
		self.sublevel = 0
		self.breakpoints = set()
		self.watchpoints = []

		self.terminateOnFullSleep = False # Terminate when all threads go to sleep

		self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
		self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

		self.mu.hook_add(UC_HOOK_CODE, self.hook_insn_bytes)
		self.mu.hook_add(UC_HOOK_BLOCK, self.trace_block)
		self.mu.hook_add(UC_HOOK_MEM_READ, self.trace_mem_read)
		self.mu.hook_add(UC_HOOK_MEM_WRITE, self.trace_mem_write)
		self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self.trace_unmapped)
		self.mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self.trace_unmapped)
		self.mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.trace_unmapped)

		self.insnhooks = {}
		self.fetchhooks = {}

		self.termaddr = 1 << 61 # Pseudoaddress upon which to terminate execution
		self.mu.mem_map(self.termaddr, 0x1000)
		self.mu.mem_write(self.termaddr, '\x1F\x20\x03\xD5') # NOP

		for i in xrange(30):
			self.hookinsn(0xD53BD060 + i, (lambda i: lambda _, __: self.tlshook(i))(i))

		self.svch = SvcHandler(self)

		self.mappings = []

		self.reset()
		self.enableFP()

		self.mu.mem_map(inlines.magicBase, 0x1000)

		self.execfunc = None
		self.initialized = True

	def reset(self):
		self.debugging = False
		self.started = False
		self.restarting = False
		self.singlestep = False
		self.mainGlobalScope = None

		self.skipbp = False
		
		for addr, size in self.mappings:
			self.mu.mem_unmap(addr, size)
		self.mappings = []
		self.checkmaps = {}
		self.checktriggers = []

		self.usHeapSize = 0

		self.mmiobase = 1 << 58
		self.mmiosize = 0
		self.mmiomap = []
		for cls in mmio.mmioClasses:
			self.mmiomap.append((cls.physbase, self.mmiobase + self.mmiosize, cls.size, cls(self)))
			self.mmiosize += cls.size
		self.map(self.mmiobase, self.mmiosize)

		self.writehooks = {}
		self.readhooks = {}

		self.handles = HandleJar(self)
		self.handleIter = 0xd000

		self.handles[0xFFFF8001] = Process(0x1234)
		self.handles[0xDEADBEEF] = Process(0xDEAD)

		self.threads = ThreadManager(self)
		self.threadIter = 0

		self.exports = {}

		self.funcReplacements = {}

		self.loadbase = 0
		self.loadsize = 0

		self.heapbase = 7 << 24
		self.heapsize = 32 * 1024 * 1024 # 32MB
		self.heapoff = 0
		self.map(self.heapbase, self.heapsize)

		self.stacktop = 7 << 24
		self.stacksize = 8 * 1024 * 1024 # 8MB
		self.map(self.stacktop - self.stacksize, self.stacksize)

		self.writemem(self.heapbase, '\0' * self.heapsize, check=False)
		self.writemem(self.stacktop - self.stacksize, '\0' * self.stacksize, check=False)

		for i in xrange(32):
			self.reg(i, 0)

	@property
	def threadId(self):
		if self.threads.current is None:
			return '?'
		else:
			return str(self.threads.current.id)

	def newHandle(self, obj):
		i = self.handleIter
		self.handleIter += 1
		self.handles[i] = obj
		return i

	def replaceHandle(self, old, new):
		self.handles.replace(old, new)

	def closeHandle(self, handle):
		if handle == 0xDEADBEEF or handle == 0xFFFF8001:
			return
		elif handle in self.handles:
			obj = self.handles[handle]
			print 'Closing handle:', obj
			if hasattr(obj, 'close'):
				obj.close()
			del self.handles[handle]

	def map(self, base, size):
		if (base & 0xFFF) != 0:
			off = base & 0xFFF
			base -= off
			size += off
		if (size & 0xFFF) != 0:
			size = (size & 0xFFFFFFFFFFFFF000) + 0x1000
		if (base, size) not in self.mappings:
			self.mappings.append((base, size))
			self.mu.mem_map(base, size)
			if self.flags & TRACE_MEMCHECK:
				self.checkmaps[base] = [0] * (size >> 3)

	def unmap(self, base, size):
		if (base & 0xFFF) != 0:
			off = base & 0xFFF
			base -= off
			size += off
		if (size & 0xFFF) != 0:
			size = (size & 0xFFFFFFFFFFFFF000) + 0x1000
		if (base, size) in self.mappings:
			del self.mappings[self.mappings.index((base, size))]
			self.mu.mem_unmap(base, size)
			if self.flags & TRACE_MEMCHECK:
				del self.checkmaps[base]

	def getmap(self, addr):
		for base, size in self.mappings:
			if base <= addr < base + size:
				return base, size
		return -1, -1

	def checkread(self, addr, size):
		if not (self.flags & TRACE_MEMCHECK):
			return
		miss = None
		base, rsize = self.getmap(addr)
		for i in xrange(size):
			caddr = addr + i
			if not (base <= caddr < base + rsize):
				base, rsize = self.getmap(caddr)
				if base == -1:
					continue
			off = caddr - base
			if (self.checkmaps[base][off >> 3] & (1 << (off & 7))) == 0:
				miss = caddr
				break
		tlsbase = self.threads.current.tlsbase if self.threads.current is not None else 1 << 64
		if miss is not None:
			print '[%s:%s] Read from uninitialized memory at %s (reading %i bytes from %s)' % (self.threadId, raw(self.threads.current.lastinsn), raw(miss), size, raw(addr))
			if tlsbase <= miss < tlsbase + 0x100:
				self.debugbreak()
			else:
				for taddr, tsize in self.checktriggers:
					if taddr <= miss < taddr + tsize:
						self.debugbreak()
		elif addr == tlsbase and size == 4:
			self.checkwrite(addr, size, unset=True)

	def checkwrite(self, addr, size, unset=False, trigger=False):
		if not (self.flags & TRACE_MEMCHECK):
			return
		base, rsize = self.getmap(addr)
		for i in xrange(size):
			caddr = addr + i
			if not (base <= caddr < base + rsize):
				base, rsize = self.getmap(caddr)
				if base == -1:
					continue
			off = caddr - base
			if unset:
				self.checkmaps[base][off >> 3] &= 0xFF ^ (1 << (off & 7))
			else:
				self.checkmaps[base][off >> 3] |= 1 << (off & 7)

		if trigger:
			self.checktriggers.append((addr, size))
			if len(self.checktriggers) == 5:
				self.checktriggers.pop(0)

	def setup(self, func):
		self.execfunc = func

	def load(self, dn):
		load = yaml.load(file(dn + '/load.yaml'))

		if 'nro' in load and not 'nxo' in load:
			load['nxo'] = load['nro']
		elif 'nso' in load and not 'nxo' in load:
			load['nxo'] = load['nso']

		if 'bundle' in load:
			self.loadmemory(dn + '/' + load['bundle'])
		elif 'mod' in load:
			self.loadmod(dn + '/' + load['mod'])
		elif 'nxo' in load:
			if not isinstance(load['nxo'], list):
				load['nxo'] = [load['nxo']]
			ibase = 0x7100000000
			self.loadbase = ibase
			allImports = []
			for name in load['nxo']:
				print 'Loading', name
				fn = dn + '/' + name
				if os.path.exists(fn):
					imports, exports = self.loadnso(fn, loadbase=ibase)
				else:
					imports, exports = self.loadnro(fn + '.nro', loadbase=ibase)
				self.exports.update(exports)
				allImports.append(imports)
				ibase += 0x100000000
			self.loadsize = ibase - self.loadbase
			if True:#self.firstLoad and len(load['nso']) == 1:
				Address.display_specialized = False

			for imports in allImports:
				for name, (addr, addend) in imports.items():
					if name in self.exports:
						self.write64(addr, self.exports[name] + addend)
					else:
						print 'Unresolved import:', name

		if 'maps' in load:
			for name, (base, fn) in load['maps'].items():
				mapLoader(dn + '/' + fn, name, base)

		if self.mainGlobalScope is not None:
			self.mainGlobalScope.update(util.addressTypes)

		self.firstLoad = False

	def runExecFunc(self):
		if self.execfunc is None:
			return

		self.mainGlobalScope = self.execfunc.func_globals
		self.execfunc(self)

	def run(self, flags=0):
		fl = self.flags
		self.reset()
		self.flags = fl | flags
		self.runExecFunc()

	def enableFP(self):
		addr = 0
		self.mu.mem_map(addr, 0x1000)
		self.mu.mem_write(addr, '\x41\x10\x38\xd5\x00\x00\x01\xaa\x40\x10\x18\xd5\x40\x10\x38\xd5\xc0\x03\x5f\xd6')
		assert (self.call(addr, 3 << 20) >> 20) & 3 == 3
		self.mu.mem_unmap(addr, 0x1000)

	def loadmod(self, fn):
		data = file(fn, 'rb').read()

		moff, = struct.unpack('<I', data[4:8])
		assert data[moff:moff+4] == 'MOD0'

		bssStart, bssEnd = struct.unpack('<II', data[moff+0x08:moff+0x10])
		bssStart, bssEnd = bssStart + moff, bssEnd + moff
		moff += struct.unpack('<I', data[moff+0x18:moff+0x1C])[0]
		base, = struct.unpack('<Q', data[moff+0x20:moff+0x28])

		overlength = 0
		if bssStart < len(data):
			data = data[:bssStart]
			overlength = bssEnd - bssStart
		else:
			self.map(base + bssStart, bssEnd - bssStart)

		self.map(base, len(data) + overlength)
		self.writemem(base, data)

		defineAddressClass('Main', base, len(data))

	def loadnso(self, fn, loadbase=0x7100000000, relocate=True):
		data = file(fn, 'rb').read()
		assert data[0:4] == 'NSO0'

		toff, tloc, tsize = struct.unpack('<III', data[0x10:0x1C])
		roff, rloc, rsize = struct.unpack('<III', data[0x20:0x2C])
		doff, dloc, dsize = struct.unpack('<III', data[0x30:0x3C])
		bsssize, = struct.unpack('<I', data[0x3C:0x40])

		text = lz4.block.decompress(data[toff:roff], uncompressed_size=tsize)
		rd = lz4.block.decompress(data[roff:doff], uncompressed_size=rsize)
		data = lz4.block.decompress(data[doff:], uncompressed_size=dsize)

		full = text
		if rloc >= len(full):
			full += '\0' * (rloc - len(full))
			full += rd
		else:
			full = full[:rloc] + rd
		if dloc >= len(full):
			full += '\0' * (dloc - len(full))
			full += data
		else:
			full = full[:dloc] + data

		self.map(loadbase, len(full) + bsssize)
		self.writemem(loadbase, full)
		defineAddressClass(fn.rsplit('/', 1)[-1].split('.', 1)[0].title(), loadbase, len(full))

		if relocate:
			return relocation.relocate(self, loadbase)

	def loadnro(self, fn, loadbase=0x7100000000, relocate=True):
		data = file(fn, 'rb').read()
		assert data[0x10:0x14] == 'NRO0'

		tloc, tsize, rloc, rsize, dloc, dsize = struct.unpack('<IIIIII', data[0x20:0x20 + 6 * 4])
		modoff, = struct.unpack('<I', data[4:8])
		assert data[modoff:modoff+4] == 'MOD0'
		bssoff, bssend = struct.unpack('<II', data[modoff+8:modoff+16])
		bsssize = bssend - bssoff

		text = data[tloc:tloc+tsize]
		rd = data[rloc:rloc+rsize]
		data = data[dloc:dloc+dsize]

		full = text
		if rloc >= len(full):
			full += '\0' * (rloc - len(full))
			full += rd
		else:
			full = full[:rloc] + rd
		if dloc >= len(full):
			full += '\0' * (dloc - len(full))
			full += data
		else:
			full = full[:dloc] + data

		if len(full) < bssoff:
			full += '\0' * (bssoff - len(full))

		if bsssize & 0xFFF:
			bsssize = (bsssize & 0xFFFFF000) + 0x1000

		self.map(loadbase, len(full) + bsssize)
		try:
			self.writemem(loadbase, full)
		except:
			import traceback
			traceback.print_exc()
		defineAddressClass(fn.rsplit('/', 1)[-1].split('.', 1)[0].title(), loadbase, len(full))

		if relocate:
			return relocation.relocate(self, loadbase)

	def loadmemory(self, fn):
		if not os.path.isfile(fn) and os.path.isfile(fn + '.gz'):
			with gzip.GzipFile(fn + '.gz', 'rb') as ifp:
				with file(fn, 'wb') as ofp:
					print 'Decompressing membundle'
					ofp.write(ifp.read())
					print 'Done!'

		with file(fn, 'rb') as fp:
			regions, mainbase, wkcbase = struct.unpack('<IQQ', fp.read(20))
			rmap = []
			for i in xrange(regions):
				addr, dlen = struct.unpack('<QI', fp.read(12))
				data = fp.read(dlen)
				self.map(addr, dlen)
				rmap.append((addr, dlen))
				self.writemem(addr, data)

		mainsize = 0
		wkcsize = 0
		inMain = inWKC = False
		last = 0
		rmap.sort(key=lambda x: x[0])
		for (addr, dlen) in rmap:
			if addr == mainbase:
				inMain = True
				last = addr
			elif addr == wkcbase:
				inWKC = True
				last = addr

			if (inMain or inWKC) and last != addr:
				inMain = inWKC = False
			elif inMain:
				mainsize += dlen
				last = addr + dlen
			elif inWKC:
				wkcsize += dlen
				last = addr + dlen

		defineAddressClass('Main', mainbase, mainsize)
		defineAddressClass('Wkc', wkcbase, wkcsize)

	def findMmioObj(self, virtaddr):
		if self.mmiobase <= virtaddr < self.mmiobase + self.mmiosize:
			for pbase, vbase, size, obj in self.mmiomap:
				if vbase <= virtaddr < vbase + size:
					return obj, virtaddr - vbase + pbase
		return None, 0

	def trace_mem_read(self, mu, access, addr, size, value, user_data):
		obj, paddr = self.findMmioObj(addr)
		if obj is not None:
			nval = obj.read(paddr, size)
			if nval is None:
				nval = 0
			if size == 1:
				self.write8(addr, nval)
			elif size == 2:
				self.write16(addr, nval)
			elif size == 4:
				self.write32(addr, nval)
			elif size == 8:
				self.write64(addr, nval)
		#if addr == 0x710062b698:
		#	if size == 4:
		#		self.write32(addr, 0xdeadbeef)
		if self.flags & TRACE_MEMORY:
			value = None
			if size == 1:
				value = self.read8(addr, check=False)
			elif size == 2:
				value = self.read16(addr, check=False)
			elif size == 4:
				value = self.read32(addr, check=False)
			elif size == 8:
				value = self.read64(addr, check=False)
			print '[%s:%s] %i byte read from %s = %s' % (self.threadId, raw(self.threads.current.lastinsn), size, raw(addr), '0x%x' % value if value is not None else 'unmapped')

		if addr in self.readhooks:
			val = self.readhooks[addr](self, size)
			if val is not None:
				if size == 1:
					self.write8(addr, val)
				elif size == 2:
					self.write16(addr, val)
				elif size == 4:
					self.write32(addr, val)
				elif size == 8:
					self.write64(addr, val)
				print '[%s:%s] %i detoured byte read from %s = %s' % (self.threadId, raw(self.threads.current.lastinsn), size, raw(addr), '0x%x' % val if val is not None else 'unmapped')
			#self.debugbreak()
		self.checkread(addr, size)

	def trace_mem_write(self, mu, access, addr, size, value, user_data):
		obj, paddr = self.findMmioObj(addr)
		if obj is not None:
			obj.write(paddr, size, value)
		if self.flags & TRACE_MEMORY:
			print '[%s:%s] %i byte write to %s = 0x%x' % (self.threadId, raw(self.threads.current.lastinsn), size, raw(addr), value)
		if self.flags & TRACE_MEMCHECK:
			self.checkwrite(addr, size)
		if addr in self.writehooks:
			if size == 1:
				self.write8(addr, value)
			elif size == 2:
				self.write16(addr, value)
			elif size == 4:
				self.write32(addr, value)
			elif size == 8:
				self.write64(addr, value)

			if self.writehooks[addr](self, addr, size, value):
				del self.writehooks[addr]

	def trace_unmapped(self, mu, access, addr, size, value, user_data):
		if access == UC_MEM_FETCH_UNMAPPED:
			print '[%s:%s] Unmapped fetch of %s' % (self.threadId, raw(self.threads.current.lastinsn), raw(addr))
		elif access == UC_MEM_READ_UNMAPPED:
			print '[%s:%s] Unmapped %i byte read from %s' % (self.threadId, raw(self.threads.current.lastinsn), size, raw(addr))
		elif access == UC_MEM_WRITE_UNMAPPED:
			print '[%s:%s] Unmapped %i byte write to %s = 0x%x' % (self.threadId, raw(self.threads.current.lastinsn), size, raw(addr), value)
		self.debugbreak()

	def trace_insn(self, mu, addr, size, user_data):
		if not self.initialized:
			return
		for ins in self.md.disasm(str(mu.mem_read(addr, size)), addr):
			print "[%s] 0x%08x:    %s  %s" % (self.threadId, ins.address, ins.mnemonic, ins.op_str)
			print 'x0=0x%x' % self.reg(0)

	def trace_block(self, mu, addr, size, user_data):
		if not self.initialized or (self.flags & TRACE_BLOCK) == 0:
			return
		print '[%s] Block at %s' % (self.threadId, raw(addr, pad=True))
		"""if addr == MainAddress(0x1ec928) or addr == MainAddress(0x1ec9e0) or addr == MainAddress(0x1ecab4):
			print '\nFATAL:\n%s\n%s\n%s\n' % (
				self.readmem(self.reg(0), 0x100).split('\0', 1)[0], 
				self.readmem(self.reg(1), 0x100).split('\0', 1)[0], 
				self.readmem(self.reg(2), 0x100).split('\0', 1)[0]
			)
			self.stop()"""

	def trace_func(self, mu, addr, size, user_data):
		thread = self.threads.current
		if not self.initialized or thread is None:
			return
		if thread.blx:
			thread.callstack.append(addr)
			if self.flags & TRACE_FUNCTION:
				plen = len('[%s]' % self.threadId + ' ' + '  ' * len(thread.callstack))
				#print ' ' * plen + '-> X0 -- %s  X1 -- %s' % (raw(self.reg(0)), raw(self.reg(1)))
				print '[%s]' % self.threadId, '  ' * len(thread.callstack) + colorDepth(len(thread.callstack)) + '-> %s' % raw(addr), Style.RESET_ALL
			thread.blx = False
		insn = self.read32(addr)

		bl_mask  = 0b11101100 << 24
		bl_match = 0b10000100 << 24

		blr_mask  = 0b011011111010 << 20
		blr_match = 0b010001100010 << 20

		ret_mask = 0b011011110110 << 20
		ret_match = 0b010001100100 << 20

		if (insn & bl_mask) == bl_match or (insn & blr_mask) == blr_match:
			thread.blx = True
		elif (insn & ret_mask) == ret_match:
			if self.flags & TRACE_FUNCTION:
				if len(thread.callstack):
					plen = len('[%s]' % self.threadId + ' ' + '  ' * len(thread.callstack))
					print '[%s]' % self.threadId, '  ' * len(thread.callstack) + colorDepth(len(thread.callstack)) + '<- %s' % raw(thread.callstack.pop()), Style.RESET_ALL
					#print ' ' * plen + '<- X0 -- %s' % raw(self.reg(0))
			elif len(thread.callstack):
				thread.callstack.pop()

	def hook_insn_bytes(self, mu, addr, size, user_data):
		self.threads.switched = False
		self.threadIter += 1
		if self.threadIter >= INSN_PER_SLICE:
			self.threadIter = 0
			if self.threads.next(pcOffset=0):
				return
		thread = self.threads.current
		if addr in inlines.reverse:
			inlines.reverse[addr](self)
			self.pc = self.reg(30)
			self.threads.current.blx = False
			return
		elif addr in self.funcReplacements:
			func = self.funcReplacements[addr]
			func()
			if self.pc == addr:
				self.pc = self.reg(30)
			if thread.blx:
				thread.blx = False
			elif self.flags & TRACE_FUNCTION:
				if len(thread.callstack):
					print '[%s]' % self.threadId, '  ' * len(thread.callstack) + colorDepth(len(thread.callstack)) + '<- %s' % raw(thread.callstack.pop()), Style.RESET_ALL
			return

		if self.restarting:
			return

		if addr in self.fetchhooks:
			self.fetchhooks[addr]()

		if self.skipbp and not self.singlestep:
			self.skipbp = False
		elif self.singlestep or addr in self.breakpoints:
			if self.singlestep:
				self.singlestep = False
			else:
				print 'Breakpoint at %s' % raw(addr)
				self.skipbp = True
			self.debugbreak()
		else:
			for code, func in self.watchpoints:
				if func(self):
					print 'Watchpoint %s triggered at %s' % (code, raw(addr))
					self.skipbp = True
					self.debugbreak()
					break

		if self.flags & TRACE_INSTRUCTION and self.flags & TRACE_FUNCTION:
			if self.threads.current is not None and self.threads.current.blx:
				self.trace_func(mu, addr, size, user_data)
				self.trace_insn(mu, addr, size, user_data)
			else:
				self.trace_insn(mu, addr, size, user_data)
				self.trace_func(mu, addr, size, user_data)
		elif self.flags & TRACE_INSTRUCTION:
			self.trace_insn(mu, addr, size, user_data)
			self.trace_func(mu, addr, size, user_data)
		else:
			self.trace_func(mu, addr, size, user_data)

		self.threads.current.lastinsn = addr

		insn, = struct.unpack('<I', self.mu.mem_read(addr, 4))

		if insn in self.insnhooks:
			if self.insnhooks[insn](self, addr) == False:
				self.pc += 4

	def hookinsn(self, insn, func=None):
		def sub(func):
			assert insn not in self.insnhooks
			self.insnhooks[insn] = func
		if func is None:
			return sub
		sub(func)

	def hookfetch(self, addr, func=None):
		addr = native(addr)
		def sub(func):
			assert addr not in self.fetchhooks
			self.fetchhooks[addr] = func
		if func is None:
			return sub
		sub(func)

	def hookread(self, addr):
		addr = native(addr)
		def sub(func):
			assert addr not in self.readhooks
			self.readhooks[addr] = func
		return sub

	def hookwrite(self, addr, func=None):
		def sub(func):
			assert addr not in self.fetchhooks
			self.writehooks[addr] = func
		if func is None:
			return sub
		sub(func)

	def replaceFunction(self, addr):
		addr = native(addr)

		def sub(func):
			regcount = func.__code__.co_argcount - 1

			def dsub():
				args = [self.reg(i) for i in xrange(regcount)]
				ret = func(self, *args)
				if isinstance(ret, tuple) or isinstance(ret, list):
					for i, v in enumerate(ret):
						self.reg(i, v)
				elif ret is not None:
					self.reg(0, ret)

			self.funcReplacements[addr] = dsub
			dsub.original = func

			return func

		return sub

	def tlshook(self, reg):
		self.reg(reg, self.threads.current.tlsbase)
		return False

	def call(self, pc, *args, **kwargs):
		_start = kwargs['_start'] if '_start' in kwargs else False

		if pc in self.exports:
			print 'Calling', pc
			pc = self.exports[pc]
		thread = self.threads.create(native(pc), native(self.stacktop), *map(native, args))
		if _start:
			thread.regs[0+2] = 0
			thread.regs[1+2] = thread.handle

		if not self.started:
			self.started = True
			first = True
			while first or (not self.exiting and (self.threads.switched or len(self.threads.running))):
				first = False
				self.threads.current.thaw()
				try:
					self.mu.emu_start(native(pc), self.termaddr + 4)
				except:
					import traceback
					traceback.print_exc()
					print 'Exception at %s' % raw(self.threads.current.lastinsn)
					self.dumpregs()
					break
				if self.threads.current is not None:
					pc = self.threads.current.regs[0]

			if self.exiting:
				sys.exit(0)

			self.threads.clear()
			self.started = False

		if self.restarting:
			self.restarting = False
			raise Restart()

		return self.mu.reg_read(UC_ARM64_REG_X0)

	def stop(self):
		self.mu.reg_write(UC_ARM64_REG_PC, self.termaddr)
		self.exiting = True

	def malloc(self, size):
		self.heapoff += size
		assert self.heapoff <= self.heapsize
		return self.heapbase + self.heapoff - size

	def free(self, ptr):
		pass # Lol.

	def writemem(self, addr, data, check=True):
		try:
			addr = native(addr)
			self.mu.mem_write(addr, data)

			if check:
				self.checkwrite(addr, len(data))
			return True
		except unicorn.UcError:
			return False

	def write8(self, addr, data, check=True):
		return self.writemem(addr, struct.pack('<B', data), check=check)
	def write16(self, addr, data, check=True):
		return self.writemem(addr, struct.pack('<H', data), check=check)
	def write32(self, addr, data, check=True):
		return self.writemem(addr, struct.pack('<I', data), check=check)
	def write64(self, addr, data, check=True):
		return self.writemem(addr, struct.pack('<Q', data), check=check)

	def readmem(self, addr, size, check=True):
		try:
			addr = native(addr)
			if check and self.flags & TRACE_MEMCHECK:
				self.checkread(addr, size)
			return str(self.mu.mem_read(addr, size))
		except unicorn.UcError:
			return None

	def read8(self, addr, check=True):
		v = self.readmem(addr, 1, check=check)
		return struct.unpack('<B', v)[0] if v is not None else None
	def readS8(self, addr, check=True):
		v = self.readmem(addr, 1, check=check)
		return struct.unpack('<b', v)[0] if v is not None else None
	def read16(self, addr, check=True):
		v = self.readmem(addr, 2, check=check)
		return struct.unpack('<H', v)[0] if v is not None else None
	def readS16(self, addr, check=True):
		v = self.readmem(addr, 2, check=check)
		return struct.unpack('<h', v)[0] if v is not None else None
	def read32(self, addr, check=True):
		v = self.readmem(addr, 4, check=check)
		return struct.unpack('<I', v)[0] if v is not None else None
	def readS32(self, addr, check=True):
		v = self.readmem(addr, 4, check=check)
		return struct.unpack('<i', v)[0] if v is not None else None
	def read64(self, addr, check=True):
		v = self.readmem(addr, 8, check=check)
		return struct.unpack('<Q', v)[0] if v is not None else None
	def readS64(self, addr, check=True):
		v = self.readmem(addr, 8, check=check)
		return struct.unpack('<q', v)[0] if v is not None else None

	def readstring(self, addr):
		if addr is None:
			return None
		ret = ''
		while True:
			c = self.read8(addr)
			addr += 1
			if c == 0 or c is None:
				return ret
			ret += chr(c)

	def memregions(self):
		lastend = 0
		for begin, end, perms in sorted(self.mu.mem_regions(), key=lambda x: x[0]):
			if begin > lastend:
				yield lastend, begin, -1
			yield begin, end + 1, perms
			lastend = end + 1
		if lastend != 1 << 64:
			yield lastend, 1 << 64, -1

	def reg(self, i, val=None):
		sr = {'LR': 30, 'SP': 31}
		for ri in xrange(32):
			sr['X%i' % ri] = ri

		if isinstance(i, str) and i.upper() in sr:
			i = sr[i.upper()]

		if i <= 28:
			c = UC_ARM64_REG_X0 + i
		elif i == 29 or i == 30:
			c = UC_ARM64_REG_X29 + i - 29
		elif i == 31:
			c = UC_ARM64_REG_SP
		else:
			return None

		if val is None:
			return self.mu.reg_read(c)
		else:
			self.mu.reg_write(c, native(val))
			return True

	@property
	def pc(self):
		return self.mu.reg_read(UC_ARM64_REG_PC)

	@pc.setter
	def pc(self, val):
		self.mu.reg_write(UC_ARM64_REG_PC, val)

	def dumpregs(self):
		sr = {30: 'LR', 31: 'SP'}
		print '-' * 52
		for i in xrange(0, 32, 2):
			an = sr[i] if i in sr else 'X%i' % i
			bn = sr[i + 1] if i + 1 in sr else 'X%i' % (i + 1)
			an += ' ' * (3 - len(an))
			bn += ' ' * (3 - len(bn))
			print '%s - 0x%016x    %s - 0x%016x' % (
				an, self.reg(i),
				bn, self.reg(i + 1)
			)
		print '-' * 52
		print

	def dumpmem(self, addr, size, check=False):
		addr = native(addr)
		data = self.readmem(addr, size, check=check)
		if data is None:
			print 'Unmapped memory at %s' % raw(addr)
			return
		data = map(ord, data)

		fmt = '%%0%ix |' % (int(math.log(addr + size, 16)) + 1)
		for i in xrange(0, len(data), 16):
			print fmt % (addr + i),
			ascii = ''
			for j in xrange(16):
				if i + j < len(data):
					print '%02x' % data[i + j], 
					if 0x20 <= data[i+j] <= 0x7E:
						ascii += chr(data[i+j])
					else:
						ascii += '.'
				else:
					print '  ', 
					ascii += ' '
				if j == 7:
					print '',
					ascii += ' '
			print '|', ascii

	def reprompt(self):
		if self.started:
			self.prompt = '[%s] ctu %s> ' % (self.threadId, raw(self.mu.reg_read(UC_ARM64_REG_PC)))
		else:
			self.prompt = 'ctu> '

	def debug(self, sub=False):
		self.debugging = True
		self.reprompt()
		try:
			self.sublevel += 1
			while True:
				try:
					self.cmdloop()
					break
				except KeyboardInterrupt:
					print
		finally:
			self.sublevel -= 1
		if self.sublevel == 1:
			self.prompt = 'ctu> '

	def debugbreak(self):
		try:
			self.debug(sub=True)
		except Restart:
			self.restarting = True
			return self.stop()

	def print_topics(self, header, cmds, cmdlen, maxcol):
		nix = 'EOF', 'b', 'c', 's', 'r', 't'
		if header is not None:
			Cmd.print_topics(self, header, [cmd for cmd in cmds if cmd not in nix], cmdlen, maxcol)

	def do_EOF(self, line):
		print
		try:
			if raw_input('Really exit? y/n: ').startswith('y'):
				self.exiting = True
				sys.exit()
		except EOFError:
			print
			self.exiting = True
			sys.exit()
	def do_exit(self, line):
		"""exit
		Exit the debugger."""
		sys.exit()

	def do_start(self, line):
		"""s/start
		Start or restart the code."""
		if self.sublevel != 1:
			raise Restart()

		while True:
			self.reset()
			try:
				self.runExecFunc()
				break
			except Restart:
				print 'got restart at', self.sublevel
				continue
	do_s = do_start

	def do_trace(self, line):
		"""t/trace (i/instruction | b/block | f/function | m/memory)
		Toggles tracing of instructions, blocks, functions, or memory."""
		if line.startswith('i'):
			self.flags ^= TRACE_INSTRUCTION
			print 'Instruction tracing', 'on' if self.flags & TRACE_INSTRUCTION else 'off'
		elif line.startswith('b'):
			self.flags ^= TRACE_BLOCK
			print 'Block tracing', 'on' if self.flags & TRACE_BLOCK else 'off'
		elif line.startswith('f'):
			self.flags ^= TRACE_FUNCTION
			print 'Function tracing', 'on' if self.flags & TRACE_FUNCTION else 'off'
		elif line.startswith('m'):
			self.flags ^= TRACE_MEMORY
			print 'Memory tracing', 'on' if self.flags & TRACE_MEMORY else 'off'
		else:
			print 'Unknown trace flag'
	do_t = do_trace

	def do_memcheck(self, line):
		"""mc/memcheck
		Toggles memory access validations."""
		self.flags ^= TRACE_MEMCHECK
		print 'Memcheck', 'on' if self.flags & TRACE_MEMCHECK else 'off'
	do_mc = do_memcheck

	def do_break(self, addr):
		"""b/break [name]
		Without `name`, list breakpoints.
		Given a symbol name or address, toggle breakpoint."""
		if addr == '':
			print 'Breakpoints:'
			for addr in self.breakpoints:
				print '*', addr
			return

		try:
			addr = raw(addr)
		except BadAddr:
			print 'Invalid address/symbol'
			return

		if addr in self.breakpoints:
			print 'Removing breakpoint at %s' % addr
			self.breakpoints.remove(addr)
		else:
			print 'Breaking at %s' % addr
			self.breakpoints.add(addr)
	do_b = do_break
	def complete_break(self, text, line, begidx, endidx):
		ftext = line.split(' ', 1)[1] if ' ' in line else ''
		cut = len(ftext) - len(text)
		return [sym[cut:] for sym in symbols.keys() if sym.startswith(ftext)]
	complete_b = complete_break

	def do_bt(self, line):
		"""bt
		Prints the call stack."""
		print 'Call stack:'
		for i, x in enumerate(self.threads.current.callstack[::-1]):
			print '%03i: %s' % (i, raw(x))

	def do_sym(self, name):
		"""sym <name>
		Prints the address of a given symbol."""
		try:
			print raw(name)
		except BadAddr:
			print 'Invalid address/symbol'
	complete_sym = complete_break

	def do_continue(self, line):
		"""c/continue
		Continues execution of the code."""
		if self.sublevel == 1:
			print 'Not running'
		else:
			return True
	do_c = do_continue

	def do_next(self, line):
		"""n/next
		Step to the next instruction."""
		if self.sublevel == 1:
			print 'Not running'
		else:
			self.singlestep = True
			return True
	do_n = do_next

	def do_regs(self, line):
		"""r/reg/regs [reg [value]]
		No parameters: Display registers.
		Reg parameter: Display one register.
		Otherwise: Assign a value (always hex, or a symbol) to a register."""
		if line == '':
			return self.dumpregs()
		elif ' ' in line:
			r, v = line.split(' ', 1)
			try:
				v = raw(v)
				if self.reg(r, v) is None:
					print 'Invalid register'
			except BadAddr:
				print 'Invalid address/Symbol'
		else:
			v = self.reg(line)
			if v is False:
				print 'Invalid register'
			else:
				print '0x%016x' % v
	do_r = do_reg = do_regs

	def do_exec(self, line):
		"""x/exec <code>
		Evaluates a given line of C."""
		try:
			val = ceval(line, self)
		except:
			import traceback
			traceback.print_exc()
			print 'Execution failed'
			return

		if val is not None:
			print '0x%x' % val
	do_x = do_exec

	def do_dump(self, line):
		"""dump <address> [size]
		Dumps `size` (default: 0x100) bytes of memory at an address.
		If the address takes the form `*register` (e.g. `*X1`) then the value of that register will be used."""
		line = list(line.split(' '))
		if len(line[0]) == 0:
			print 'No address'
		elif len(line) <= 2:
			if len(line[0]) and line[0][0] == '*':
				line[0] = self.reg(line[0][1:])
				if line[0] is None:
					print 'Invalid register'
					return
			else:
				try:
					line[0] = raw(line[0])
				except BadAddr:
					print 'Invalid address/symbol'
					return
			if len(line) == 2:
				line[1] = parseInt(line[1])
				if line[1] is None or line[1] >= 0x10000:
					print 'Invalid size'
					return
			self.dumpmem(line[0], 0x100 if len(line) == 1 else line[1])
		else:
			print 'Too many parameters'

	def do_save(self, line):
		"""save <address> <size> <fn>
		Writes `size` bytes of memory to a file.
		If the address or size takes the form `*register` (e.g. `*X1`) then the value of that register will be used."""

		line = list(line.split(' '))
		addr, size, fn = line
		addr = self.reg(addr[1:]) if addr.startswith('*') else parseInt(addr)
		size = self.reg(size[1:]) if size.startswith('*') else parseInt(size)
		with file(fn, 'wb') as fp:
			fp.write(self.readmem(addr, size))
		print 'Wrote to file'

	def do_ad(self, line):
		"""ad
		Toggle address display specialization."""
		Address.display_specialized = not Address.display_specialized
		print '%s specialized address display' % ('Enabled' if Address.display_specialized else 'Disabled')
		self.reprompt()

	def do_watch(self, line):
		"""w/watch [expression]
		Breaks when expression evaluates to true.
		Without an expression, list existing watchpoints."""
		if line == '':
			print 'Watchpoints:'
			for code, _ in self.watchpoints:
				print '*', code
			return

		if line in [code for code, _ in self.watchpoints]:
			self.watchpoints = [(code, func) for code, func in self.watchpoints if code != line]
			print 'Watchpoint deleted'
		else:
			self.watchpoints.append((line, compile(line)))
			print 'Watchpoint added'
	do_w = do_watch

	def do_memregions(self, line):
		"""mr/memregions
		Displays mapped memory regions."""
		print 'Mapped memory regions'
		print '---------------------'
		for begin, end, perms in self.memregions():
			if perms != -1:
				print '%016x - %016x' % (begin, end)
	do_mr = do_memregions

def debug(*flags):
	def sub(func):
		ctu = CTU()
		ctu.setup(func)
		ctu.flags |= reduce(lambda a, x: a | x, flags, TRACE_NONE)
		ctu.debug()
		return func

	if len(flags) == 1 and callable(flags[0]):
		func = flags[0]
		flags = [TRACE_NONE]
		return sub(func)
	else:
		return sub

def run(*flags):
	def sub(func):
		ctu = CTU()
		ctu.setup(func)
		ctu.flags |= reduce(lambda a, x: a | x, flags, TRACE_NONE)
		ctu.run()
		return func

	if len(flags) == 1 and callable(flags[0]):
		func = flags[0]
		flags = [TRACE_NONE]
		return sub(func)
	else:
		return sub
