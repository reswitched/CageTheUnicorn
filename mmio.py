from util import *

mmioClasses = []

def register(base, size):
	def sub(cls):
		cls.physbase = base
		cls.size = size
		mmioClasses.append(cls)
		return cls
	return sub

class MmioBase(object):
	def __init__(self, ctu):
		self.ctu = ctu
		self.stored = {}
		self.setup()

	def setup(self):
		pass

	def sread(self, addr, size):
		pass

	def swrite(self, addr, size, value):
		return False

	def read(self, addr, size):
		pc = raw(self.ctu.threads.current.lastinsn)
		print '[%s:%s] MMIO Read %x -- %i bytes' % (self.ctu.threadId, pc, addr, size)
		val = self.sread(addr, size)
		if val is None:
			print 'Unknown MMIO read from %x' % addr
			if addr in self.stored:
				print 'Had stored value'
				return self.stored[addr]
			else:
				return 0
		else:
			return val

	def write(self, addr, size, value):
		pc = raw(self.ctu.threads.current.lastinsn)
		print '[%s:%s] MMIO Write %x -- %x -- %i bytes' % (self.ctu.threadId, pc, addr, value, size)

		if self.swrite(addr, size, value) is False:
			print 'Unhandled MMIO write to %x' % addr
			self.stored[addr] = value

@register(0x70000000, 0x1000)
class Apb(MmioBase):
	pass

@register(0x7000f800, 0x400)
class Fuses(MmioBase):
	pass

@register(0x700e3000, 0x100)
class MipiCal(MmioBase):
	pass

@register(0x70019000, 0x1000)
class Mc(MmioBase):
	def sread(self, addr, size):
		if addr == 0x70019670:
			return 0xfff00000
		elif addr == 0x70019674:
			return 0x1000

@register(0x50000000, 0x24000)
class Host1x(MmioBase):
	pass

@register(0x54200000, 0x400000)
class Display(MmioBase):
	pass

@register(0x57000000, 0x1000000)
class GpuRegs(MmioBase):
	pass

@register(0x58000000, 0x100000)
class GpuBar1(MmioBase):
	pass
