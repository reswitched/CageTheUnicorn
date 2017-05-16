import re

class Restart(Exception):
	pass
class BadAddr(Exception):
	pass

symbols = {}
invsyms = {}
def mapLoader(fn, acls, base):
	cut = 'nullsub_', 'def_%s' % ('%x' % base)[:2]
	with file(fn, 'r') as fp:
		for line in fp:
			if not line.startswith(' 00000001:'):
				continue
			addr = acls(int(line[10:26], 16) - base)
			name = line[33:].strip().split('(', 1)[0]
			if any(name.startswith(x) for x in cut):
				continue
			symbols[name] = addr
			invsyms[addr] = name

class Address(object):
	display_specialized = True

	def __init__(self, addr, pad=False, raw=False):
		self.addr = addr + (0 if raw else self.baseaddr)
		self.pad = pad

	def __hash__(self):
		return self.addr.__hash__()

	def __eq__(self, b):
		b = raw(b)
		return self.addr == b.addr

	@property
	def baseaddr(self):
		return type(self).realbase

	@property
	def offset(self):
		return self.addr - self.baseaddr

	def to(self, cls):
		if isinstance(self, cls):
			return self
		return cls(self.addr, pad=self.pad, raw=True)

	@property
	def symbol(self):
		if self in invsyms:
			return invsyms[self]

	def __str__(self):
		if not Address.display_specialized and not isinstance(self, RawAddress):
			return self.to(RawAddress).__str__()
		sym = self.symbol
		if sym is None:
			return self.mname % (('0x%016x' if self.pad else '0x%x') % self.offset)
		else:
			return self.mname % (('%s @ 0x%016x' if self.pad else '%s @ 0x%x') % (sym, self.offset))

	def __add__(self, b):
		return type(self)(self.addr + b, pad=self.pad, raw=True)

	def specialize(self):
		if not isinstance(self, RawAddress):
			return self.to(RawAddress).specialize()

		if WKCAddress.realbase <= self.addr < WKCAddress.realbase + WKCAddress.realsize:
			return self.to(WKCAddress)
		elif MainAddress.realbase <= self.addr < MainAddress.realbase + MainAddress.realbase:
			return self.to(MainAddress)
		return self

class RawAddress(Address):
	mname = '%s'
	realbase = 0
	realsize = 1 << 64
class WKCAddress(Address):
	mname = 'WKC(%s)'
	# realbase/size assigned at runtime
class MainAddress(Address):
	mname = 'Main(%s)'
	# realbase/size assigned at runtime

def raw(addr, pad=False):
	if isinstance(addr, str) or isinstance(addr, unicode):
		if addr in symbols:
			return symbols[addr]
		else:
			raise BadAddr()
	elif isinstance(addr, Address):
		return addr.to(RawAddress)
	return RawAddress(addr, pad=pad).specialize()
def native(addr):
	if isinstance(addr, Address):
		return addr.addr
	else:
		return addr

def parseInt(addr, implicitHex=False):
	if (implicitHex or addr.startswith('0x')) and re.match(r'^(0x)?[0-9a-fA-F]+$', addr):
		return int(addr[2:] if addr.startswith('0x') else addr, 16)
	elif re.match(r'^[0-9]+$', addr):
		return int(addr)
	else:
		return None
