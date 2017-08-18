import os, re, struct, time
from threading import RLock, Thread

class Restart(Exception):
	pass
class BadAddr(Exception):
	pass

symbols = {}
invsyms = {}
def mapLoader(fn, acls, base):
	if not os.path.exists(fn):
		print 'Missing map file', fn
		return
	acls = addressTypes[acls + 'Address']
	cut = 'nullsub_', 'def_%s' % ('%x' % base)[:2], 'sub_%s' % ('%x' % base)[:2], 'loc_%s' % ('%x' % base)[:2]
	with file(fn, 'r') as fp:
		for line in fp:
			if not line.startswith(' 00000'):
				continue
			addr = acls(int(line[10:26], 16) - base)
			name = line[33:].strip().split('(', 1)[0]
			if any(name.startswith(x) for x in cut):
				continue
			symbols[name] = addr
			invsyms[addr] = name

def nukeSymbols():
	global symbols, invsyms
	symbols = {}
	invsyms = {}

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

		for cls in addressTypes.values():
			if cls != RawAddress and cls.realbase <= self.addr < cls.realbase + cls.realsize:
				return self.to(cls)
		return self

class RawAddress(Address):
	mname = '%s'
	aprefix = '*'
	realbase = 0
	realsize = 1 << 64

addressTypes = dict(RawAddress=RawAddress)
def defineAddressClass(name, base, size):
	cname = name + 'Address'
	if cname not in addressTypes:
		cls = type(cname, (Address, ), dict(mname=name + '(%s)', aprefix='%s:' % name.lower(), realbase=base, realsize=size))
		globals()[cname] = cls
		addressTypes[cname] = cls
	else:
		cls = addressTypes[cname]
		cls.realbase = base
		cls.realsize = size

def raw(addr, pad=False):
	if addr is None:
		addr = 0
	if isinstance(addr, str) or isinstance(addr, unicode):
		if addr in symbols:
			return symbols[addr]

		if addr.startswith('0x'):
			addr = '*' + addr

		for cls in addressTypes.values():
			if addr.startswith(cls.aprefix):
				return cls(parseInt(addr[len(cls.aprefix):], implicitHex=True))
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

class Process(object):
	def __init__(self, id):
		self.id = id

class Waitable(object):
	def setup(self):
		self.waitable_setup = True
		self.waitable_lock = RLock()
		self.waitable_waiters = []
		self.waitable_presignaled = False, None, None
		self.waitable_presignalable = True

	def makeHandle(self):
		return IPCMessage.ctu.newHandle(self) # XXX: hackhackhack

	def acquire(self):
		if not hasattr(self, 'waitable_setup'):
			self.setup()

		self.waitable_lock.acquire()

	def release(self):
		self.waitable_lock.release()

	def wait(self, func):
		def presignal():
			self.acquire()
			if func(self, *pa, **pk) in (True, False):
				pass
			else:
				self.waitable_waiters.append(func)
			self.waitable_presignaled = False, None, None
			self.release()
		self.acquire()
		dp, pa, pk = self.waitable_presignaled
		if dp:
			Thread(target=presignal).start()
		else:
			self.waitable_waiters.append(func)
		self.release()

	def unwait(self, func):
		self.acquire()
		self.waitable_waiters = [x for x in self.waitable_waiters if x is not func]
		self.release()

	def signal(self, *args, **kwargs):
		self.acquire()
		if len(self.waitable_waiters) == 0 and self.waitable_presignalable:
			self.waitable_presignaled = True, args, kwargs
		else:
			remove = []
			realhit = False
			for i, func in enumerate(self.waitable_waiters):
				ret = func(self, *args, **kwargs)
				if ret == True or ret == False:
					remove.append(i)
				if ret != False:
					realhit = True
			for i in remove[::-1]:
				del self.waitable_waiters[i]
			if not realhit and self.waitable_presignalable:
				self.waitable_presignaled = True, args, kwargs
		self.release()

	def signalOne(self, *args, **kwargs):
		self.acquire()
		if len(self.waitable_waiters) != 0:
			realhit = False
			while len(self.waitable_waiters) != 0:
				func = self.waitable_waiters[0]
				ret = func(self, *args, **kwargs)
				if ret == True or ret == False:
					del self.waitable_waiters[0]
				if ret != False:
					realhit = True
					break
			if not realhit and self.waitable_presignalable:
				self.waitable_presignaled = True, args, kwargs
		elif self.waitable_presignalable:
			self.waitable_presignaled = True, args, kwargs
		self.release()

class Timer(Waitable):
	def signalIn(self, seconds):
		def sleeper():
			time.sleep(seconds)
			self.signal()
		Thread(target=sleeper).start()

class InstantWaitable(Waitable):
	def wait(self, func):
		Waitable.wait(self, func)
		Thread(target=self.signal).start()

class Port(Waitable):
	def __init__(self, name):
		self.name = name
		self.queue = []

	def push(self, obj):
		self.acquire()
		self.queue.append(obj)
		self.signalOne()
		self.release()

	def pop(self):
		self.acquire()
		v = self.queue.pop(0)
		self.release()
		return v

	def __repr__(self):
		return 'Port<%s>' % self.name

class Pipe(Waitable):
	@staticmethod
	def new():
		a = Pipe()
		a.other = b = Pipe(a)
		return a, b

	def __init__(self, other=None):
		self.other = other
		self.queue = []
		self.accepted = False
		self.closed = False

	def acquire(self):
		Waitable.acquire(self)
		Waitable.acquire(self.other)

	def release(self):
		Waitable.release(self)
		Waitable.release(self.other)

	def accept(self):
		self.accepted = True

	def waitForAccept(self):
		while not self.accepted:
			time.sleep(0.1)

	def push(self, obj):
		self.other.acquire()
		self.other.queue.append(obj)
		self.other.signal()
		self.other.release()

	def pop(self):
		while not self.closed and not IPCMessage.ctu.exiting and len(self.queue) == 0:
			time.sleep(0.1)

		if self.closed or IPCMessage.ctu.exiting:
			return None

		self.acquire()
		val = self.queue.pop(0)
		self.release()
		return val

	def close(self):
		self.acquire()
		print 'Closing pipes', self, self.other
		self.closed = True
		self.other.closed = True
		self.signal()
		self.other.signal()
		self.release()

def hexify(obj, name, pname=None):
	def sub(v):
		if isinstance(v, list) or isinstance(v, tuple):
			return '[%s]' % ', '.join(map(sub, v))
		elif v is None:
			return 'None'
		else:
			return '0x%x' % v

	pname = name if pname is None else pname
	value = getattr(obj, pname)
	if len(value) == 0:
		return ''

	return ', %s=%s' % (name, sub(value))

class IPCMessage(object):
	def __init__(self, cmdId=0):
		self.type = -1
		self.cmdId = cmdId
		self.request = False

		self.domainParams = None
		self.pid = -1
		self.dataBuffer = []

		self.aDescriptors = []
		self.bDescriptors = []
		self.cDescriptors = []
		self.xDescriptors = []

		self.copiedHandles = []
		self.movedHandles = []

	def setType(self, type):
		self.type = type
		return self
	def hasPID(self, pid=0x1234):
		self.pid = pid
		return self
	def data(self, *args):
		self.dataBuffer += list(args)
		return self
	def aDescriptor(self, addr, size, perms):
		self.aDescriptors.append((addr, size, perms))
		return self
	def bDescriptor(self, addr, size, perms):
		self.bDescriptors.append((addr, size, perms))
		return self
	def cDescriptor(self, addr, size):
		self.cDescriptors.append((addr, size))
		return self
	def xDescriptor(self, addr, size, counter):
		self.xDescriptors.append((addr, size, counter))
		return self
	def copyHandle(self, handle):
		if not isinstance(handle, int) and not isinstance(handle, long):
			handle = self.ctu.newHandle(handle)
		self.copiedHandles.append(handle)
		return self
	def moveHandle(self, handle):
		if not isinstance(handle, int) and not isinstance(handle, long):
			handle = self.ctu.newHandle(handle)
		self.movedHandles.append(handle)
		return self

	def unpack(self, buf, request=True, domain=False, test=True):
		self.request = request
		self.type = buf[0] & 0xFFFF

		xCount, aCount, bCount, wCount = (buf[0] >> 16) & 0xF, (buf[0] >> 20) & 0xF, (buf[0] >> 24) & 0xF, buf[0] >> 28
		assert wCount == 0

		wlen, hasC, hasHD = buf[1] & 0x3FF, ((buf[1] >> 10) & 0x3) in (2, 3), (buf[1] >> 31) == 1
		pos = 2

		if hasHD:
			hd = buf[pos]
			pos += 1
			hasPID, copyCount, moveCount = bool(hd & 1), (hd >> 1) & 0xF, hd >> 5
			if hasPID:
				self.pid = buf[pos] | (buf[pos + 1] << 32) # I don't think this is ever populated by the app, this would be done by kernel
				pos += 2
			for i in xrange(copyCount):
				self.copiedHandles.append(buf[pos])
				pos += 1
			for i in xrange(moveCount):
				self.movedHandles.append(buf[pos])
				pos += 1

		for i in xrange(xCount):
			a, b = buf[pos:pos+2]
			pos += 2
			if a is None or b is None:
				addr, size, counter = None, None, None
			else:
				addr = b | ((((a >> 12) & 0xF) | ((a >> 2) & 0x70)) << 32)
				size = a >> 16
				counter = a & 0xE3F
			self.xDescriptors.append((addr, size, counter))

		for i in xrange(aCount + bCount):
			a, b, c = buf[pos:pos+3]
			pos += 3
			if a is None or b is None or c is None:
				addr, size, perm = None, None, None
			else:
				addr = b | (((((c >> 2) << 4) & 0x70) | ((c >> 28) & 0xF)) << 32)
				size = a | (((c >> 24) & 0xF) << 32)
				perm = c & 0x3
			if i < aCount:
				self.aDescriptors.append((addr, size, perm))
			else:
				self.bDescriptors.append((addr, size, perm))

		end = pos + wlen

		if pos & 3:
			pos += 4 - (pos & 3)

		if self.type != 5 and domain:
			domainData = buf[pos:pos+4]
			if None in domainData:
				self.domainParams = None, None, None, None
			else:
				dcmd, sicount, rawsize, objid = domainData[0] & 0xFF, (domainData[0] >> 8) & 0xFF, domainData[0] >> 16, domainData[1]
				self.domainParams = dcmd, sicount, rawsize, objid
			pos += 4

		term = 0x49434653 if request else 0x4f434653
		if self.type != 2 and (not domain or self.type == 5 or self.domainParams[0] != 2) and buf[pos] != term:
			print '!SFCO/SFCI not found!'

		pos += 2

		if hasC:
			end -= 2

		while pos < end:
			a, b = buf[pos:pos+2]
			if a is None and b is None:
				self.dataBuffer.append(None)
			elif a is None and b is not None:
				self.dataBuffer.append(b << 32)
			elif a is not None and b is None:
				self.dataBuffer.append(a)
			else:
				self.dataBuffer.append(a | (b << 32))
			pos += 2

		if len(self.dataBuffer) != 0:
			self.cmdId, self.dataBuffer = self.dataBuffer[0], self.dataBuffer[1:]
		else:
			self.cmdId = 0

		if hasC:
			a, b = buf[pos], buf[pos+1]
			if a is None or b is None:
				addr, size = None, None
			else:
				addr = a | ((b & 0xFFFF) << 32)
				size = b >> 16
			self.cDescriptors.append((addr, size))
			pos += 2

		self.data = self.dataBuffer

		return self

	def pack(self, domain=False):
		rbuf = []
		rbuf.append(0x49434653 if self.request else 0x4f434653)
		rbuf.append(0)
		rbuf.append(self.cmdId)
		rbuf.append(0)
		if isinstance(self.data, list):
			self.dataBuffer = self.data
		for x in self.dataBuffer:
			if x is None:
				rbuf.append(None)
			else:
				rbuf.append(x & 0xFFFFFFFF)
				rbuf.append((x >> 32) & 0xFFFFFFFF)

		for addr, size in self.cDescriptors:
			if addr is None or size is None:
				rbuf.append(None)
				rbuf.append(None)
			else:
				laddr, haddr = addr & 0xFFFFFFFF, addr >> 32
				rbuf.append(laddr)
				rbuf.append((haddr & 0xFFFF) | (size << 16))

		hdbuf = []
		if self.pid != -1 or len(self.copiedHandles) != 0 or len(self.movedHandles) != 0:
			hdbuf.append(
				(1 if self.pid != -1 else 0) | 
				(len(self.copiedHandles) << 1) | 
				(len(self.movedHandles) << 5)
			)
			if self.pid != -1:
				hdbuf.append(self.pid & 0xFFFFFFFF)
				hdbuf.append((self.pid >> 32) & 0xFFFFFFFF)
			hdbuf += self.copiedHandles
			hdbuf += self.movedHandles

		dbuf = []
		for addr, size, counter in self.xDescriptors:
			if addr is None or size is None or counter is None:
				dbuf.append(None)
				dbuf.append(None)
			else:
				laddr, haddr = addr & 0xFFFFFFFF, addr >> 32
				dbuf.append(
					(counter & 0x3F) | 
					(((haddr & 0x70) >> 4) << 6) | 
					(counter & 0xE00) | 
					((haddr & 0xF) << 12) | 
					(size << 16)
				)
				dbuf.append(laddr)
		for addr, size, perms in (self.aDescriptors + self.bDescriptors):
			if addr is None or size is None or perms is None:
				dbuf.append(None)
				dbuf.append(None)
				dbuf.append(None)
			else:
				laddr, haddr = addr & 0xFFFFFFFF, addr >> 32
				lsize, hsize = size & 0xFFFFFFFF, size >> 32
				dbuf.append(lsize)
				dbuf.append(laddr)
				dbuf.append(
					perms | 
					(((haddr & 0x70) >> 4) << 2) | 
					((hsize & 0xF) << 24) | 
					((haddr & 0xF) << 28)
				)

		hbuf = [
			(
				self.type | 
				(len(self.xDescriptors) << 16) | 
				(len(self.aDescriptors) << 20) | 
				(len(self.bDescriptors) << 24)
			), 
			((1 << 31) if len(hdbuf) else 0) | 
			((2 << 10) if len(self.cDescriptors) else 0)
		]

		tbuf = hbuf + hdbuf + dbuf
		slen = len(tbuf)
		while (len(tbuf) & 3) != 0:
			tbuf.append(None)
		if domain:
			tbuf += [0, 0, 0, 0]
		tbuf += rbuf
		tbuf[1] |= len(tbuf) - slen - (len(self.cDescriptors) << 1) + 2

		return tbuf

	def __repr__(self):
		return '%s(%s%s%s%s%s%s%s%s%s%s)' % (
				self.__class__.__name__, 
				'cmdId=%i' % self.cmdId, 
				', type=%i' % self.type if self.type != 0 else '', 
				', pid=0x%x' % self.pid if self.pid != -1 else '', 
				hexify(self, 'data', 'dataBuffer'), 
				hexify(self, 'aDescriptors'), 
				hexify(self, 'bDescriptors'), 
				hexify(self, 'cDescriptors'), 
				hexify(self, 'xDescriptors'), 
				hexify(self, 'copiedHandles'), 
				hexify(self, 'movedHandles'), 
			)

def formatString(ctu, fmts, startreg=None, stack=None, values=None):
	cfmt='''\
	(                                  # start of capture group 1
	%                                  # literal "%"
	(?:                                # first option
	(?:[-+0 #]{0,5})                   # optional flags
	(?:\d+|\*)?                        # width
	(?:\.(?:\d+|\*))?                  # precision
	(?:h|l|ll|w|I|I32|I64)?            # size
	[cCdiouxXeEfgGaAnpsSZ]             # type
	) |                                # OR
	%%)                                # literal "%%"
	'''
	args = []
	replacements = []
	for m in re.finditer(cfmt, fmts, flags=re.X):
		fmt = m.group(1)
		if startreg is not None:
			val = ctu.reg(startreg)
			startreg += 1
		elif stack is not None:
			val = ctu.read64(stack)
			stack += 8
		else:
			val = values.pop(0)
		if fmt == '%s':
			args.append(ctu.readstring(val))
		elif fmt == '%p':
			args.append(val)
			replacements.append((m.start(1), m.end(1), '%016x'))
		elif fmt == '%llx':
			args.append(val)
			replacements.append((m.start(1), m.end(1), '%016x'))
		else:
			args.append(val)
	replacements.reverse()
	for s, e, r in replacements:
		fmts = fmts[:s] + r + fmts[e:]
	return fmts % tuple(args)
