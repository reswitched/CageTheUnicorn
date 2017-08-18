import types

from util import *

services = {}

def register(name):
	def sub(cls):
		cls.serviceName = name
		services[name] = cls
		return cls
	return sub

def command(request):
	def sub(func):
		func.cmdId = request
		return func
	return sub

class stub(object):
	def __init__(self, cmdId=None):
		self.cmdId = cmdId
		self._data = []
		self.movedHandles = []
		self.copiedHandles = []

	def data(self, *data):
		self._data += list(data)
		return self

	def moveHandle(self, cls, *args, **kwargs):
		self.movedHandles.append((cls, args, kwargs))
		return self

	def copyHandle(self, cls, *args, **kwargs):
		self.copiedHandles.append((cls, args, kwargs))
		return self

	def __call__(self, message):
		print 'Stub %s handler for %r to %r' % (self.name, message, self.service)
		msg = IPCMessage(0)
		msg = msg.data(*self._data)
		for cls, args, kwargs in self.movedHandles:
			if isinstance(cls, type) and issubclass(cls, IPCService):
				args = [self.service.ipc] + list(args)
			if callable(cls):
				msg = msg.moveHandle(cls(*args, **kwargs))
			else:
				msg = msg.moveHandle(cls)
		for cls, args, kwargs in self.copiedHandles:
			if isinstance(cls, type) and issubclass(cls, IPCService):
				args = [self.service.ipc] + list(args)
			if callable(cls):
				msg = msg.copyHandle(cls(*args, **kwargs))
			else:
				msg = msg.copyHandle(cls)
		return msg

def partial(origcls):
	def sub(newcls):
		for x in dir(newcls):
			if x != '__setup__' and x.startswith('__'):
				continue
			func = getattr(newcls, x)
			ofunc = getattr(origcls, x)
			if isinstance(func, stub):
				fsub = func
			else:
				fsub = func.__func__
				if hasattr(func, 'cmdId'):
					fsub.cmdId = func.cmdId
			if hasattr(fsub, 'cmdId'):
				assert fsub.cmdId is None or fsub.cmdId == ofunc.cmdId
			if hasattr(ofunc, 'cmdId'):
				fsub.cmdId = ofunc.cmdId
			setattr(origcls, x, fsub)
	return sub

class IPCService(object):
	def __init__(self, ipc, *args, **kwargs):
		self.ipc = ipc
		self.ctu = ipc.ctu
		self.commands = {}
		for name in dir(self):
			func = getattr(self, name)
			if hasattr(func, 'cmdId'):
				self.commands[func.cmdId] = func
				if isinstance(func, stub):
					func.service = self
					func.name = name
		self.__setup__(*args, **kwargs)

	def __setup__(self):
		pass

	def dispatch(self, handle, buffer):
		incoming = IPCMessage().unpack(buffer)
		print incoming
		for addr, size, _ in incoming.bDescriptors:
			if size == 0:
				continue
			self.ctu.checkwrite(addr, size, unset=True, trigger=True)
			self.ctu.writemem(addr, '\0' * size, check=False)
		for addr, size in incoming.cDescriptors:
			if size == 0:
				continue
			print `addr, size`
			self.ctu.checkwrite(addr, size, unset=True, trigger=True)
			self.ctu.writemem(addr, '\0' * size, check=False)
		print self, incoming
		resp = self.handle(handle, incoming)
		if isinstance(resp, tuple):
			ret, resp = resp
		else:
			ret, resp = 0, resp
		if isinstance(resp, IPCMessage):
			#print ', '.join('%08x' % x for x in resp.pack())
			if resp.type == -1:
				resp.type = 0
			return ret, resp.pack()
		elif isinstance(resp, int) or isinstance(resp, long) or resp is None:
			return ret, IPCMessage(resp if resp is not None else 0).setType(0).pack()
		else:
			return ret, resp

	def handle(self, handle, message):
		if message.type == 5:
			if (5, message.cmdId) in self.commands:
				return self.commands[(5, message.cmdId)](message)
			print 'Unhandled message to %s: %r' % (self.__class__.__name__, message)
			self.ipc.ctu.debugbreak()
		elif message.type == 4:
			if message.cmdId in self.commands:
				return self.commands[message.cmdId](message)
			print 'Unhandled message to %s: %r' % (self.__class__.__name__, message)
			self.ipc.ctu.debugbreak()
		elif message.type == 2:
			print 'Closing handle for', self
			self.ctu.closeHandle(handle)
			return 0, IPCMessage(0).setType(0).pack()
		else:
			print 'Unknown message type to %s: %r' % (self.__class__.__name__, message)
			self.ipc.ctu.debugbreak()

	@command((5, 0))
	def ConvertSessionToDomain(self, message):
		dd = DomainDispatcher(self.ipc)
		id = dd.add(self)
		self.ctu.replaceHandle(self, dd)

		return IPCMessage(0).data(id)

	@command((5, 2))
	def DuplicateSession(self, message):
		return IPCMessage(0).moveHandle(self)

	@command((5, 3))
	def QueryPointerBufferSize(self, message):
		return IPCMessage(0).data(0x500)

	@command((5, 4))
	def DuplicateSessionEx(self, message):
		return IPCMessage(0).moveHandle(self)

class DomainDispatcher(IPCService):
	def __init__(self, ipc):
		IPCService.__init__(self, ipc)
		self.handles = {}
		self.handleIter = 0xefff

	def add(self, obj):
		self.handleIter += 1
		self.handles[self.handleIter] = obj
		return self.handleIter

	def dispatch(self, handle, buffer):
		print 'Domain dispatcher got a buffer!'
		incoming = IPCMessage().unpack(buffer, domain=True)
		print incoming
		if incoming.type == 2:
			print 'Closing domain dispatcher'
			self.ctu.closeHandle(handle)
			return 0, IPCMessage(0).setType(0).pack()
		elif incoming.type == 5:
			print 'Type 5 to domain dispatch...'
			return IPCService.dispatch(self, handle, buffer)

		dcmd, sicount, rawsize, objid = incoming.domainParams
		if dcmd == 1:
			print 'Passthrough message for', self.handles[objid]
			ret, buf = self.handles[objid].dispatch(None, incoming.pack() + [None] * 16)
			if buf is not None:
				msg = IPCMessage().unpack(buf + [None] * 16, request=False)
				if len(msg.movedHandles) != 0:
					repl = []
					for hnd in msg.movedHandles:
						repl.append(self.add(self.ctu.handles[hnd]))
						del self.ctu.handles[hnd]
					msg.movedHandles = []
					msg.data = repl + msg.data
				buf = msg.pack(domain=True)
				print 'Repacked passthrough message for domain'
			return ret, buf
		elif dcmd == 2:
			obj = self.handles[objid]
			print 'Close virtual handle', obj
			if hasattr(obj, 'close'):
				obj.close()
			del self.handles[objid]
			return 0, IPCMessage(0).setType(0).pack()
		else:
			print 'Unhandled domain dispatch command: %x %x %x %x' % (dcmd, sicount, rawsize, objid)
			self.ctu.debugbreak()
