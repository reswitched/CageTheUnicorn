from util import *
import struct

handlers = {}
def handler(num):
	def sub(func):
		handlers[num] = func
		return func
	return sub

class SvcHandler(object):
	def __init__(self, ctu):
		self.ctu = ctu

		for i in xrange(0x60):
			ctu.hookinsn(0xD4000001 | (i << 5), (lambda i: lambda _, __: self.svcDispatch(i))(i))

	def svcDispatch(self, svc):
		if svc in handlers:
			print 'svc %x' % svc
			handlers[svc](self)
			return False

		print 'Unhandled: SVC 0x%02x @ %s' % (svc, raw(self.ctu.pc))
		self.ctu.debugbreak()
		return False

	def ipcDispatcher(self, handle, addr, size):
		print 'IPC! Handle: %08x' % handle
		self.ctu.dumpmem(addr, size)

	@handler(0x1D)
	def SignalEvent(self):
		self.ctu.reg(0, 0)

	@handler(0x21)
	def SendSyncRequest(self):
		return self.ipcDispatcher(self.ctu.reg(0), self.ctu.tlsbase, 0x100)

	@handler(0x22)
	def SendSyncRequestEx(self):
		return self.ipcDispatcher(self.ctu.reg(2), self.ctu.reg(0), self.ctu.reg(1))

	@handler(0x25)
	def GetThreadId(self):
		self.ctu.writemem(self.ctu.reg(0), struct.pack('<Q', 0xf00))
		self.ctu.reg(0, 0)
