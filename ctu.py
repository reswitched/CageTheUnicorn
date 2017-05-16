import gzip, math, os, re, struct, sys
from cmd import Cmd

import colorama
from colorama import Fore, Back, Style

from unicorn import *
from unicorn.arm64_const import *

from capstone import *

from ceval import ceval, compile
from util import *
from svc import SvcHandler

TRACE_NONE = 0
TRACE_INSTRUCTION = 1
TRACE_BLOCK = 2
TRACE_FUNCTION = 4

def colorDepth(depth):
	colors = [Fore.RED, Fore.WHITE, Fore.GREEN, Fore.YELLOW, Style.BRIGHT + Fore.BLUE, Fore.MAGENTA, Fore.CYAN]

	return colors[depth % len(colors)]

class CTU(Cmd, object):
	def __init__(self, flags=0):
		Cmd.__init__(self)

		colorama.init()
		self.initialized = False

		self.flags = 0
		self.sublevel = 0
		self.breakpoints = set()
		self.watchpoints = []

		self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
		self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

		self.mu.hook_add(UC_HOOK_CODE, self.hook_insn_bytes)
		self.mu.hook_add(UC_HOOK_BLOCK, self.trace_block)

		self.insnhooks = {}

		self.termaddr = 1 << 61 # Pseudoaddress upon which to terminate execution
		self.mu.mem_map(self.termaddr, 0x1000)
		self.mu.mem_write(self.termaddr, '\x1F\x20\x03\xD5') # NOP

		self.stacktop = 1 << 48
		self.stacksize = 8 * 1024 * 1024 # 8MB
		self.mu.mem_map(self.stacktop - self.stacksize, self.stacksize)

		self.heapbase = 1 << 50
		self.heapsize = 32 * 1024 * 1024 # 32MB
		self.heapoff = 0
		self.mu.mem_map(self.heapbase, self.heapsize)

		self.tlsbase = 1 << 49
		self.tlssize = 1024 * 1024 # 1MB
		self.mu.mem_map(self.tlsbase, self.tlssize)

		for i in xrange(30):
			self.hookinsn(0xD53BD060 + i, (lambda i: lambda _, __: self.tlshook(i))(i))

		self.svch = SvcHandler(self)

		self.reset()
		self.enableFP()

		self.execfunc = None
		self.initialized = True

	def reset(self):
		self.debugging = False
		self.started = False
		self.restarting = False
		self.singlestep = False

		self.skipbp = False
		self.lastinsn = None
		self.blx = False
		self.callstack = []

		self.loadmemory()
		if not self.initialized:
			mapLoader('main.map', MainAddress, 0x19e5006000)
			mapLoader('webkit_wkc.map', WKCAddress, 0x3C0D91E000)

		self.heapoff = 0
		self.mu.mem_write(self.heapbase, '\0' * self.heapsize)
		self.mu.mem_write(self.stacktop - self.stacksize, '\0' * self.stacksize)

		self.mu.mem_write(self.tlsbase + 0x1F8, struct.pack('<Q', 0x5AF9C2D000 + 0xFD3840))

		for i in xrange(32):
			self.reg(i, 0)

	def setup(self, func):
		self.execfunc = func

	def run(self, flags=0):
		self.reset()
		assert self.execfunc is not None
		self.flags = flags
		self.execfunc(self)

	def enableFP(self):
		addr = 1 << 62
		self.mu.mem_map(addr, 0x1000)
		self.mu.mem_write(addr, '\x41\x10\x38\xd5\x00\x00\x01\xaa\x40\x10\x18\xd5\x40\x10\x38\xd5\xc0\x03\x5f\xd6')
		assert (self.call(addr, 3 << 20) >> 20) & 3 == 3

	def loadmemory(self):
		if not os.path.isfile('membundle.bin'):
			with gzip.GzipFile('membundle.bin.gz', 'rb') as ifp:
				with file('membundle.bin', 'wb') as ofp:
					print 'Decompressing membundle'
					ofp.write(ifp.read())
					print 'Done!'

		with file('membundle.bin', 'rb') as fp:
			regions, mainbase, wkcbase = struct.unpack('<IQQ', fp.read(20))
			if not self.initialized:
				rmap = []
			for i in xrange(regions):
				addr, dlen = struct.unpack('<QI', fp.read(12))
				data = fp.read(dlen)
				if not self.initialized:
					self.mu.mem_map(addr, dlen)
					rmap.append((addr, dlen))
				self.mu.mem_write(addr, data)

		if not self.initialized:
			MainAddress.realbase = mainbase
			WKCAddress.realbase = wkcbase
			MainAddress.realsize = WKCAddress.realsize = 0
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
					MainAddress.realsize += dlen
					last = addr + dlen
				elif inWKC:
					WKCAddress.realsize += dlen
					last = addr + dlen

	def trace_insn(self, mu, addr, size, user_data):
		if not self.initialized:
			return
		for ins in self.md.disasm(str(mu.mem_read(addr, size)), addr):
			print("0x%08x:    %s  %s" % (ins.address, ins.mnemonic, ins.op_str))

	def trace_block(self, mu, addr, size, user_data):
		if not self.initialized or (self.flags & TRACE_BLOCK) == 0:
			return
		print 'Block at %s - %s' % (raw(addr, pad=True), raw(addr + size, pad=True))
		if addr == MainAddress(0x1ec928) or addr == MainAddress(0x1ec9e0) or addr == MainAddress(0x1ecab4):
			print '\nFATAL:\n%s\n%s\n%s\n' % (
				self.readmem(self.reg(0), 0x100).split('\0', 1)[0], 
				self.readmem(self.reg(1), 0x100).split('\0', 1)[0], 
				self.readmem(self.reg(2), 0x100).split('\0', 1)[0]
			)
			self.stop()

	def trace_func(self, mu, addr, size, user_data):
		if not self.initialized:
			return
		if self.blx:
			self.callstack.append(addr)
			print '  ' * len(self.callstack) + colorDepth(len(self.callstack)) + '-> %s' % raw(addr), Style.RESET_ALL
			self.blx = False
		insn, = struct.unpack('<I', self.mu.mem_read(addr, 4))

		bl_mask  = 0b11101100 << 24
		bl_match = 0b10000100 << 24

		blr_mask  = 0b011011111010 << 20
		blr_match = 0b010001100010 << 20

		ret_mask = 0b011011110110 << 20
		ret_match = 0b010001100100 << 20

		if (insn & bl_mask) == bl_match or (insn & blr_mask) == blr_match:
			self.blx = True
		elif (insn & ret_mask) == ret_match:
			print '  ' * len(self.callstack) + colorDepth(len(self.callstack)) + '<- %s' % raw(self.callstack.pop()), Style.RESET_ALL

	def hook_insn_bytes(self, mu, addr, size, user_data):
		if self.restarting:
			return

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
			if self.blx:
				self.trace_func(mu, addr, size, user_data)
				self.trace_insn(mu, addr, size, user_data)
			else:
				self.trace_insn(mu, addr, size, user_data)
				self.trace_func(mu, addr, size, user_data)
		elif self.flags & TRACE_INSTRUCTION:
			self.trace_insn(mu, addr, size, user_data)
		elif self.flags & TRACE_FUNCTION:
			self.trace_func(mu, addr, size, user_data)

		self.lastinsn = addr

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

	def tlshook(self, reg):
		self.reg(reg, self.tlsbase)
		return False

	def call(self, pc, *args):
		self.started = True

		self.callstack.append(pc)

		self.mu.reg_write(UC_ARM64_REG_X30, self.termaddr)
		self.mu.reg_write(UC_ARM64_REG_SP, self.stacktop)

		for i, v in enumerate(args):
			self.mu.reg_write(UC_ARM64_REG_X0 + i, v)

		try:
			self.mu.emu_start(native(pc), self.termaddr + 4)
		except:
			import traceback
			traceback.print_exc()
			print 'Exception at %s' % raw(self.lastinsn)
			self.dumpregs()

		self.started = False

		if self.restarting:
			self.restarting = False
			raise Restart()

		return self.mu.reg_read(UC_ARM64_REG_X0)

	def stop(self):
		self.mu.reg_write(UC_ARM64_REG_PC, self.termaddr)

	def malloc(self, size):
		self.heapoff += size
		assert self.heapoff <= self.heapsize
		return self.heapbase + self.heapoff - size

	def writemem(self, addr, data):
		try:
			self.mu.mem_write(addr, data)
			return True
		except unicorn.UcError:
			return False

	def readmem(self, addr, size):
		try:
			return self.mu.mem_read(native(addr), size)
		except unicorn.UcError:
			return None

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

	def dumpmem(self, addr, size):
		addr = native(addr)
		data = self.readmem(addr, size)
		if data is None:
			print 'Unmapped memory at %s' % raw(addr)
			return

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
			self.prompt = 'ctu %s> ' % raw(self.mu.reg_read(UC_ARM64_REG_PC))
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
				sys.exit()
		except EOFError:
			print
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
				self.execfunc(self)
				break
			except Restart:
				print 'got restart at', self.sublevel
				continue
	do_s = do_start

	def do_trace(self, line):
		"""t/trace (i/instruction | b/block | f/function)
		Toggles tracing of instructions, blocks, or functions."""
		if line.startswith('i'):
			self.flags ^= TRACE_INSTRUCTION
			print 'Instruction tracing', 'on' if self.flags & TRACE_INSTRUCTION else 'off'
		elif line.startswith('b'):
			self.flags ^= TRACE_BLOCK
			print 'Block tracing', 'on' if self.flags & TRACE_BLOCK else 'off'
		elif line.startswith('f'):
			self.flags ^= TRACE_FUNCTION
			print 'Function tracing', 'on' if self.flags & TRACE_FUNCTION else 'off'
		else:
			print 'Unknown trace flag'
	do_t = do_trace

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

	def do_ad(self, line):
		"""ad
		Toggle address display specialization."""
		Address.display_specialized = not Address.display_specialized
		print '%s specialized address display' % ('Enabled' if Address.display_specialized else 'Disabled')
		self.reprompt()

	def do_watch(self, line):
		"""w/watch <expression>
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

def debug(func):
	ctu = CTU()
	ctu.setup(func)
	ctu.debug()
	return func

def run(flags=TRACE_NONE):
	def sub(func):
		ctu = CTU()
		ctu.setup(func)
		ctu.run(flags)
		return func

	if callable(flags):
		func = flags
		flags = TRACE_NONE
		return sub(func)
	else:
		return sub
