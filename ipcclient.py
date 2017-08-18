from socket import *
from struct import pack, unpack
import math, sys

def dump(data):
	data = map(ord, data)
	fmt = '%%0%ix |' % (int(math.log(len(data), 16)) + 1)
	for i in xrange(0, len(data), 16):
		print fmt % i,
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

def hexify(obj, name, pname=None):
	def sub(v):
		if isinstance(v, list) or isinstance(v, tuple):
			return '[%s]' % ', '.join(map(sub, v))
		elif isinstance(v, str):
			return 'buf<0x%x>' % len(v)
		else:
			return '0x%x' % v

	pname = name if pname is None else pname
	value = getattr(obj, pname)
	if len(value) == 0:
		return ''

	return ', %s=%s' % (name, sub(value))

class IPCMessage(object):
	def __init__(self, cmdId=0, client=None):
		self.client = client

		self.type = -1
		self.cmdId = cmdId
		self.request = False

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
	def hasPID(self, pid=0xDEAD):
		self.pid = pid
		return self
	def data(self, *args):
		self.dataBuffer += list(args)
		return self
	def aDescriptor(self, data, perms):
		self.aDescriptors.append((data, perms))
		return self
	def bDescriptor(self, data, perms):
		self.bDescriptors.append((data, perms))
		return self
	def cDescriptor(self, data):
		self.cDescriptors.append(data)
		return self
	def xDescriptor(self, data, counter):
		self.xDescriptors.append((data, counter))
		return self
	def copyHandle(self, handle):
		self.copiedHandles.append(handle)
		return self
	def moveHandle(self, handle):
		self.movedHandles.append(handle)
		return self

	def sendTo(self, handle):
		return self.client.sendMsg(handle, self)

	def __repr__(self):
		return '%s(%s%s%s%s%s%s%s%s%s)' % (
				self.__class__.__name__, 
				'cmdId=%i' % self.cmdId, 
				', type=%i' % self.type if self.type != 0 else '', 
				hexify(self, 'data', 'dataBuffer'), 
				hexify(self, 'aDescriptors'), 
				hexify(self, 'bDescriptors'), 
				hexify(self, 'cDescriptors'), 
				hexify(self, 'xDescriptors'), 
				hexify(self, 'copiedHandles'), 
				hexify(self, 'movedHandles'), 
			)

class Client(object):
	def __init__(self, host='127.0.0.1'):
		self.sock = socket(AF_INET, SOCK_STREAM)
		self.sock.connect((host, 31337))

		self.autoHandles = {}

	def getService(self, name):
		if name not in self.autoHandles:
			print 'Getting service', name
			self.writeint(0)
			self.writedata(name)
			self.autoHandles[name] = self.readint()
		return self.autoHandles[name]

	def closeHandle(self, handle):
		print 'Closing handle %x' % handle
		self.writeint(1)
		self.writeint(handle)

	def ipcMsg(self, cmdId):
		return IPCMessage(cmdId, client=self)

	def sendMsg(self, nameOrHandle, msg):
		if isinstance(nameOrHandle, str) or isinstance(nameOrHandle, unicode):
			handle = self.getService(nameOrHandle)
			name = nameOrHandle
		else:
			handle = nameOrHandle
			name = None

		self.writeint(2)
		self.writeint(4 if msg.type == -1 else msg.type)
		self.writeint(len(msg.dataBuffer) + 1)
		map(self.writeint, [msg.cmdId] + list(msg.dataBuffer))
		self.writeint(msg.pid)
		self.writeint(len(msg.copiedHandles))
		map(self.writeint, msg.copiedHandles)
		self.writeint(len(msg.movedHandles))
		map(self.writeint, msg.movedHandles)
		self.writeint(len(msg.aDescriptors))
		[(self.writedata(y), self.writeint(z)) for y, z in msg.aDescriptors]
		self.writeint(len(msg.bDescriptors))
		[(self.writedata(y), self.writeint(z)) for y, z in msg.bDescriptors]
		self.writeint(len(msg.cDescriptors))
		[self.writedata(y) for y in msg.cDescriptors]
		self.writeint(len(msg.xDescriptors))
		[(self.writedata(y), self.writeint(z)) for y, z in msg.xDescriptors]
		self.writeint(handle)

		error_code = self.readint()
		if error_code != 0:
			if error_code == 0xf601 and name is not None:
				del self.autoHandles[name]
			return error_code, None

		data = [self.readint() for i in xrange(self.readint(0))]
		copy = [self.readint() for i in xrange(self.readint(0))]
		move = [self.readint() for i in xrange(self.readint(0))]
		a = [(self.readdata(), self.readint()) for i in xrange(self.readint(0))]
		b = [(self.readdata(), self.readint()) for i in xrange(self.readint(0))]
		c = [self.readdata() for i in xrange(self.readint(0))]
		x = [(self.readdata(), self.readint()) for i in xrange(self.readint(0))]
		request_type = self.readint()

		if request_type is None:
			return None

		msg = IPCMessage(data[0])
		msg.setType(request_type)
		msg.data(*data[1:])
		map(msg.copyHandle, copy)
		map(msg.moveHandle, move)
		map(lambda v: msg.aDescriptor(*v), a)
		map(lambda v: msg.bDescriptor(*v), b)
		map(lambda v: msg.cDescriptor(v), c)
		map(lambda v: msg.xDescriptor(*v), x)
		msg.data = msg.dataBuffer
		return 0, msg

	def readint(self, default=None):
		data = self.sock.recv(8)
		if len(data) != 8:
			return default
		return unpack('<Q', data)[0]
	def readdata(self, default=None):
		size = self.readint()
		if size is None:
			return default
		odata = ''
		while len(odata) != size:
			data = self.sock.recv(size - len(odata))
			if len(data) == 0:
				return None
			odata += data
		return odata
	def writeint(self, v):
		self.sock.send(pack('<Q', v & 0xFFFFFFFFFFFFFFFF))
	def writedata(self, v):
		self.writeint(len(v))
		if isinstance(v, str) or isinstance(v, unicode):
			self.sock.send(v)
		else:
			self.sock.send(''.join(map(chr, v)))
