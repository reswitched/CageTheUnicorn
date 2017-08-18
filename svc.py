import ipcbridge
from ipc import IPC
from sync import *
from util import *
from threadmanager import Thread

import struct, threading
from time import sleep
from svcHelper import svcToName

handlers = {}
def handler(num):
	def sub(func):
		def dsub(self):
			args = (self.ctu.reg(i) for i in xrange(func.__code__.co_argcount - 1))
			ret = func(self, *args)
			if ret is None:
				return
			if isinstance(ret, tuple):
				for i, v in enumerate(ret):
					self.ctu.reg(i, native(v))
			else:
				self.ctu.reg(0, native(ret))
		handlers[num] = dsub
		return func
	return sub

class SvcHandler(object):
	def __init__(self, ctu):
		self.ctu = ctu
		self.ipc = IPC(self.ctu)
		ipcbridge.start(self.ctu)

		self.mutexes = {}
		self.semaphores = {}

		for i in xrange(0x80):
			ctu.hookinsn(0xD4000001 | (i << 5), (lambda i: lambda _, __: self.svcDispatch(i))(i))

	def svcDispatch(self, svc):
		if svc in handlers:
			print '[%i] %s' %(self.ctu.threads.current.id, svcToName(svc))
			handlers[svc](self)
			return False

		print 'Unhandled: SVC %s 0x%02x @ %s' % (svcToName(svc), svc, raw(self.ctu.pc))
		self.ctu.debugbreak()
		return False

	def ipcDispatcher(self, handle, addr, size):
		self.ctu.dumpmem(addr, 0x80)
		buffer = struct.unpack('<' + 'I' * (size >> 2), self.ctu.readmem(addr, size, check=False))
		ret, buffer = self.ipc.recv(handle, buffer)
		self.ctu.writemem(addr, '\0' * 0x100, check=False)
		self.ctu.checkwrite(addr, 0x100, unset=True)
		if buffer is not None:
			obuf = ''
			for i, x in enumerate(buffer):
				if x is not None:
					self.ctu.write32(addr + i * 4, x)
			self.ctu.dumpmem(addr, 0x80)
		return ret

	@handler(0x01)
	def SetHeapSize(self, _, size):
		self.ctu.usHeapSize = size
		addr = 0xaa0000000
		self.ctu.map(addr, size)
		return 0, addr

	@handler(0x03)
	def SetMemoryAttribute(self, addr, size, state0, state1):
		return 0

	@handler(0x04)
	def MirrorStack(self, dest, src, size):
		print 'Mirror stack: %x %x %x' % (dest, src, size)
		self.ctu.map(dest, size)
		self.ctu.writemem(dest, self.ctu.readmem(src, size))
		return 0

	@handler(0x05)
	def UnmapMemory(self, dest, src, size):
		print 'UnmapMemory %x %x %x' % (dest, src, size)
		self.ctu.unmap(dest, size)
		return 0

	@handler(0x06)
	def QueryMemory(self, meminfo, pageinfo, addr):
		print 'QueryMemory %x (%x %x)' % (addr, meminfo, pageinfo)
		for begin, end, perms in self.ctu.memregions():
			if begin <= addr < end:
				print 'Found region at %x-%x' % (begin, end)
				self.ctu.write64(meminfo + 0x00, begin)
				self.ctu.write64(meminfo + 0x08, end - begin)
				self.ctu.write64(meminfo + 0x10, 0 if perms == -1 else 3) # FREE or CODE
				if perms == -1:
					cperm = 0
				else:
					offset = self.ctu.read32(begin + 4)
					if begin + offset + 4 < end and self.ctu.readmem(begin + offset, 4) == 'MOD0':
						cperm = 5
					else:
						cperm = 3
				self.ctu.write64(meminfo + 0x18, cperm)
				break

		return 0, 0

	@handler(0x07)
	def ExitProcess(self):
		print 'EXIT PROCESS'
		self.ctu.debugbreak()
		return 0,0

	@handler(0x08)
	def CreateThread(self, out, pc, x0, sp, prio, proc):
		print 'Creating thread at %s' % raw(pc)
		thread = self.ctu.threads.create(pc, sp, x0)
		self.ctu.write64(out, thread.handle)
		return 0, thread.handle

	@handler(0x09)
	def StartThread(self, handle):
		thread = self.ctu.handles[handle]
		print 'Starting thread %i at %s (SP=%s)' % (thread.id, raw(thread.regs[0]), raw(thread.regs[1]))
		thread.active = True
		self.ctu.threads.running.append(thread)
		return 0

	@handler(0x0A)
	def ExitThread(self):
		print 'Exiting thread %i' % self.ctu.threads.current.id
		self.ctu.threads.exit()

	@handler(0x0B)
	def SleepThread(self, ns):
		sec = ns / 1000000000.
		print 'Sleeping thread for %f seconds' % sec
		thread = self.ctu.threads.current
		timer = Timer()

		@timer.wait
		def waiter(trigger):
			while thread.active:
				time.sleep(0.01)
			thread.resume()
			return True

		timer.signalIn(sec)
		thread.suspend()

	@handler(0x0C)
	def GetThreadPriority(self, handle):
		return 0, 0

	@handler(0x0D)
	def SetThreadPriority(self, handle, priority):
		return 0

	@handler(0x0E)
	def GetThreadCoreMask(self):
		return 0, 0xFF, 0xFF

	@handler(0x0F)
	def SetThreadCoreMask(self):
		return 0

	@handler(0x10)
	def GetCurrentProcessorNumber(self):
		return 0

	@handler(0x11)
	def SignalEvent(self, handle):
		print 'SignalEvent %x' % handle
		#print self.ctu.handles[handle]
		return 0

	@handler(0x12)
	def ClearEvent(self, handle):
		print 'ClearEvent %x' % handle
		print self.ctu.handles[handle]
		return 0

	@handler(0x13)
	def MapMemoryBlock(self, handle, addr, size, perm):
		print 'Map memory block: %x %x %x %x' % (handle, addr, size, perm)
		obj = self.ctu.handles[handle]
		assert obj.size == size
		assert obj.addr is None
		self.ctu.map(addr, size)
		obj.addr = addr
		return 0

	@handler(0x15)
	def CreateTransferMemory(self, addr, size, perm):
		print 'CreateTransferMemory %x %x %x' % (addr, size, perm)
		return 0, 0

	@handler(0x16)
	def CloseHandle(self, handle):
		self.ctu.closeHandle(handle)
		return 0

	@handler(0x17)
	def ResetSignal(self, handle):
		print 'ResetSignal %x' % handle
		return 0

	@handler(0x18)
	def WaitSynchronization(self, out, handles, numHandles, timeout):
		print '[%i] WaitSynchronization %x %i %x' % (self.ctu.threads.current.id, handles, numHandles, timeout)
		objs = [self.ctu.handles[self.ctu.read32(handles + i * 4)] for i in xrange(numHandles)]
		print objs

		for i, obj in enumerate(objs):
			if isinstance(obj, Thread) and obj.terminated:
				return 0, i

		"""for obj in objs:
			if isinstance(obj, Port) and self.ctu.threads.current.id != 0:
				print 'Waiting for ports on non-zero thread?  Nope.'
				objs = [Waitable()]
				break"""

		for obj in objs:
			obj.acquire()

		for i, obj in enumerate(objs):
			if isinstance(obj, Pipe) and (obj.closed or len(obj.queue) > 0):
				obj.waitable_presignaled = False, None, None
				for sobj in objs:
					sobj.release()
				return 0, i

		triggered = [False]
		setup = False
		thread = self.ctu.threads.current
		def waiter(trigger, canceled=False):
			if triggered[0]:
				return False
			triggered[0] = True
			while thread.active:
				time.sleep(0.01)

			thread.blockers = []

			print 'WaitSynchronization done!  Canceled == %r' % canceled

			thread.regs[0+2] = 0xec01 if canceled else 0 # X0 = 0
			thread.regs[1+2] = 0 if canceled else objs.index(trigger) # X1 = index of handle
			thread.resume()
			return True

		thread.blockers = objs
		for obj in objs:
			obj.wait(waiter)
			obj.release()

		thread.suspend()

	@handler(0x19)
	def CancelSynchronization(self, handle):
		print 'CancelSynchronization %x' % handle
		thread = self.ctu.handles[handle]
		for blocker in thread.blockers:
			blocker.signal(True)
		return 0

	def ensureMutex(self, ptr):
		if isinstance(ptr, Mutex):
			return ptr
		elif ptr not in self.mutexes:
			print 'Making new mutex for %x' % ptr
			self.mutexes[ptr] = Mutex(self.ctu, ptr)
		return self.mutexes[ptr]

	def ensureSema(self, ptr):
		if isinstance(ptr, Semaphore):
			return ptr
		elif ptr not in self.semaphores:
			print 'Making new semaphore for %x' % ptr
			self.semaphores[ptr] = Semaphore(self.ctu, ptr)
		return self.semaphores[ptr]

	@handler(0x1A)
	def LockMutex(self, curthread, mutexAddr, reqthread):
		print 'LockMutex %x %x %x' % (curthread, mutexAddr, reqthread)
		mutex = self.ensureMutex(mutexAddr)
		owner = mutex.value & 0xBFFFFFFF
		thread = self.ctu.threads.current
		if owner != 0 and owner is not reqthread:
			print 'Could not get mutex lock.  Waiting.'
			mutex.hasWaiters = 1
			@mutex.wait
			def waiter(trigger):
				while thread.active: # In case we haven't finished suspending when the mutex releases
					time.sleep(0.1)
				if mutex.owner is None:
					mutex.owner = reqthread
					thread.regs[0+2] = 0
					thread.resume()
					return True
				else:
					mutex.hasWaiters = 1
			if thread.active:
				thread.suspend()
		else:
			mutex.owner = reqthread
			if not thread.active:
				thread.regs[0+2] = 0
				thread.resume()
			else:
				return 0

	@handler(0x1B)
	def UnlockMutex(self, mutex):
		print 'UnlockMutex %x' % mutex
		mutex = self.ensureMutex(mutex)
		owner = mutex.owner
		assert mutex.owner is None or mutex.owner is self.ctu.threads.current

		mutex.guestRelease()

	@handler(0x1C)
	def WaitProcessWideKeyAtomic(self, mutexAddr, sema, threadHandle, timeout):
		print 'WaitProcessWideKeyAtomic %x %x %x %i' % (mutexAddr, sema, threadHandle, timeout)

		thread = self.ctu.handles[threadHandle]
		print 'WaitProcessWideKeyAtomic on thread', thread.id
		mutex = self.ensureMutex(mutexAddr)
		sema = self.ensureSema(sema)

		# Mutex should always be locked on wait!
		assert mutex.owner is thread

		if sema.value > 0:
			sema.decrement()
			return 0

		@sema.wait
		def waiter(trigger):
			while thread.active: # In case we haven't finished suspending
				time.sleep(0.1)
			sema.decrement()
			print 'Attempting to wake thread to get mutex back:', thread.id
			self.LockMutex(0, mutexAddr, threadHandle)
			return True

		mutex.guestRelease()
		thread.suspend()

	@handler(0x1D)
	def SignalProcessWideKey(self, sema, target):
		print 'SignalProcessWideKey %x %x' % (sema, target)
		sema = self.ensureSema(sema)
		sema.increment()
		if target == 1:
			sema.signalOne()
		elif target == 0xFFFFFFFF:
			sema.signal()
		return 0

	@handler(0x1F)
	def ConnectToPort(self, out, name):
		handle = self.ipc.connectToPort(self.ctu.readstring(name))
		self.ctu.write64(out, handle)
		return 0, handle

	@handler(0x21)
	def SendSyncRequest(self):
		return self.ipcDispatcher(self.ctu.reg(0), self.ctu.threads.current.tlsbase, 0x100)

	@handler(0x22)
	def SendSyncRequestEx(self):
		return self.ipcDispatcher(self.ctu.reg(2), self.ctu.reg(0), self.ctu.reg(1))

	@handler(0x24)
	def GetProcessID(self, out, handle):
		print 'GetProcessID %x %x' % (out, handle)
		process = self.ctu.handles[handle]
		self.ctu.write32(out, process.id)
		return 0, process.id

	@handler(0x25)
	def GetThreadId(self, p_threadid):
		self.ctu.write64(p_threadid, self.ctu.threads.current.id)
		return 0

	@handler(0x26)
	def Break(self, X0, X1, info):
		print 'svcBreak HIT!'
		print 'X0=%016x'%X0
		print 'X1=%016x'%X1
		print 'X2=%016x'%info
		self.ctu.debugbreak()
		return 0

	@handler(0x27)
	def OutputDebugString(self, ptr, size):
		print 'Debug string:', self.ctu.readmem(ptr, size).rstrip('\0')

	@handler(0x29)
	def GetInfo(self, out, id1, handle, id2):
		res = None
		print 'Get info: %i:%i %x -> %x' % (id1, id2, handle, out)
		process = self.ctu.handles[handle if handle != 0 else 0xFFFF8001] # Assume current process for faking
		if id1 == 0 and id2 == 0:
			res = 0xF
		elif id1 == 1 and id2 == 0:
			res = 0xfffffffff0000000
		elif id1 == 2 and id2 == 0:
			res = 0x7100000000
		elif id1 == 3 and id2 == 0:
			res = 0x1000000000
		elif id1 == 4 and id2 == 0:
			res = 0xaa0000000 # Heap base?
		elif id1 == 5 and id2 == 0:
			res = self.ctu.usHeapSize # Heap region size
		elif id1 == 6 and id2 == 0:
			res = 0x100000
		elif id1 == 7 and id2 == 0:
			res = 0x10000
		elif id1 == 12 and id2 == 0:
			res = 0x8000000
		elif id1 == 13 and id2 == 0:
			res = 0x7ff8000000
		elif id1 == 14 and id2 == 0:
			res = self.ctu.loadbase
		elif id1 == 15 and id2 == 0:
			res = self.ctu.loadsize
		elif id1 == 18 and id2 == 0:
			res = 0x0100000000000036
		elif id1 == 11:
			res = 0

		if res is None:
			print 'Unknown getinfo!'
			self.ctu.write64(out, 0)
			return 1, 0
		else:
			self.ctu.write64(out, res)
			return 0, res

	@handler(0x40)
	def CreateSession(self, clientOut, serverOut, unk):
		print 'Creating session %x %x %x' % (clientOut, serverOut, unk)
		a, b = Pipe.new()
		ah, bh = self.ctu.newHandle(a), self.ctu.newHandle(b)
		self.ctu.write32(clientOut, ah)
		self.ctu.write32(serverOut, bh)
		return 0, ah, bh

	@handler(0x41)
	def AcceptSession(self, out, port):
		port = self.ctu.handles[port]
		print 'Accept session on', port
		pipe = port.pop()
		pipe.accept()
		handle = self.ctu.newHandle(pipe)
		self.ctu.write32(out, handle)
		return 0, handle

	@handler(0x43)
	def ReplyAndReceive(self, out, handles, numHandles, replySession, timeout):
		#print 'ReplyAndReceive %x %x %i %x %x' % (out, handles, numHandles, replySession, timeout)

		addr = self.ctu.threads.current.tlsbase

		if replySession != 0:
			handle = self.ctu.handles[replySession]
			print 'Writing outgoing IPC message:'
			self.ctu.dumpmem(addr, 0x100)
			handle.push(self.ctu.readmem(addr, 0x100, check=False))

		if numHandles == 0:
			return 0xf601, 0

		objs = [self.ctu.handles[self.ctu.read32(handles + i * 4)] for i in xrange(numHandles)]
		assert len(objs) == 1 and isinstance(objs[0], Pipe)
		print objs[0]
		objs[0].acquire()
		if objs[0].closed:
			print 'Pipe is closed.'
			return 0xf601, 0
		self.ctu.write32(out, 0) # Index into handles
		data = objs[0].pop()
		objs[0].release()
		if data is None:
			return 0xf601, 0
		self.ctu.writemem(addr, data)
		print 'Read incoming IPC message:'
		self.ctu.dumpmem(addr, len(data))
		return 0, 0

	@handler(0x45)
	def CreateEvent(self, clientOut, serverOut, unk):
		print 'Creating event?  Totally fake %x %x %x' % (clientOut, serverOut, unk)
		a, b = Pipe.new()
		ah, bh = self.ctu.newHandle(a), self.ctu.newHandle(b)
		self.ctu.write32(clientOut, ah)
		self.ctu.write32(serverOut, bh)
		return 0, ah, bh

	@handler(0x4E)
	def ReadWriteRegister(self, out, reg, rwm, val):
		print 'ReadWriteRegister %x %x %x %x' % (out, reg, rwm, val)
		robj = None
		for pbase, vbase, size, obj in self.ctu.mmiomap:
			if pbase <= reg < pbase + size:
				robj = obj
				break
		if robj is None:
			print '!Unknown physical address!'
			self.ctu.debugbreak()
			return 0, 0

		if rwm == 0xFFFFFFFF:
			obj.write(reg, 4, val)
		elif rwm == 0x00000000:
			val = obj.read(reg, 4)
		else:
			tval = obj.read(reg, 4)
			tval &= (0xFFFFFFFF ^ rwm)
			val |= tval
			obj.write(reg, 4, val)
		return 0, val

	@handler(0x50)
	def CreateMemoryBlock(self, out, size, perm):
		print 'Attempting to create memory block: %x %x' % (size, perm)
		handle = self.ctu.newHandle(MemoryBlock(size, perm))
		self.ctu.write64(out, handle)
		return 0, handle

	@handler(0x51)
	def MapTransferMemory(self, handle, addr, size, perm):
		print 'MapTransferMemory %x %x %x %x' % (handle, addr, size, perm)
		self.ctu.map(addr, size)
		return 0

	@handler(0x52)
	def UnmapTransferMemory(self, handle, addr, size):
		print 'UnmapTransferMemory %x %x %x' % (handle, addr, size)
		self.ctu.unmap(addr, size)
		return 0

	@handler(0x53)
	def CreateInterruptEvent(self, out, irq):
		print 'CreateInterruptEvent %x %x' % (out, irq)
		interruptWaitable = Waitable()
		print interruptWaitable
		return 0, self.ctu.newHandle(interruptWaitable)

	@handler(0x55)
	def QueryIoMapping(self, out, physaddr, size):
		print 'QueryIoMapping %x %x' % (physaddr, size)
		res = None
		for pbase, vbase, msize, obj in self.ctu.mmiomap:
			if pbase <= physaddr < pbase + msize:
				res = physaddr - pbase + vbase
				break
		if res is None:
			print '!Unknown physical address!'
			self.ctu.debugbreak()
			res = 0
		self.ctu.write64(out, res)
		return 0, res

	@handler(0x56)
	def CreateDeviceAddressSpace(self, out, base, size):
		print 'CreateDeviceAddressSpace %x %x %x' % (out, base, size)
		obj = DeviceMemory(base, size)
		handle = self.ctu.newHandle(obj)
		self.ctu.write32(out, handle)
		return 0, handle

	@handler(0x57)
	def AttachDeviceAddressSpace(self, handle, dev, addr):
		print 'AttachDeviceAddressSpace %x %x %x' % (handle, dev, addr)
		return 0, 0

	@handler(0x59)
	def MapDeviceAddressSpaceByForce(self, handle, phandle, paddr, size, maddr, perm):
		print 'MapDeviceAddressSpaceByForce %x %x %x %x %x %x' % (handle, phandle, paddr, size, maddr, perm)
		return 0, 0

	@handler(0x5c)
	def UnmapDeviceAddressSpace(self, unk0, phandle, maddr, size):
		print 'UnmapDeviceAddressSpace %x %x %x %x' % (unk0, phandle, maddr, size)
		return 0

	@handler(0x74)
	def MapProcessMemory(self, dstaddr, handle, srcaddr, size):
		print 'MapProcessMemory %x %x %x %x' % (handle, dstaddr, srcaddr, size)
		self.ctu.map(dstaddr, size)
		self.ctu.writemem(dstaddr, self.ctu.readmem(srcaddr, size))
		return 0

	@handler(0x75)
	def UnmapProcessMemory(self, dstaddr, handle, srcaddr, size):
		print 'UnmapProcessMemory %x %x %x %x' % (handle, dstaddr, srcaddr, size)
		self.ctu.unmap(dstaddr, size)
		return 0

	@handler(0x77)
	def MapProcessCodeMemory(self, handle, dstaddr, srcaddr, size):
		print 'MapProcessCodeMemory %x %x %x %x' % (handle, dstaddr, srcaddr, size)
		self.ctu.map(dstaddr, size)
		return 0

	@handler(0x78)
	def UnmapProcessCodeMemory(self, handle, dstaddr, srcaddr, size):
		print 'UnmapProcessCodeMemory %x %x %x %x' % (handle, dstaddr, srcaddr, size)
		self.ctu.unmap(dstaddr, size)
		return 0

class MemoryBlock(object):
	def __init__(self, size, perm):
		self.size = size
		self.perm = perm
		self.addr = None

class DeviceMemory(object):
	def __init__(self, gaddr, size):
		self.gaddr = gaddr
		self.caddr = None
		self.size = size
