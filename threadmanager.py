import os, signal, time
from util import *
from ipc import LrService

from unicorn.arm64_const import *

class ThreadManager(object):
	def __init__(self, ctu):
		self.ctu = ctu

		self.clear()
		self.startupCompleted = False

	def next(self, pcOffset=0):
		try:
			while True:
				if len(self.running) == 0:
					if self.current is None:
						if self.ctu.terminateOnFullSleep:
							self.clear()
							self.create(self.ctu.termaddr, 0)
							return
						elif not self.startupCompleted:
							print 'Started!'
							self.startupCompleted = True
						while len(self.running) == 0:
							time.sleep(0.01)
					else:
						return

				new = self.running.pop(0)
				if new.active:
					break
		except KeyboardInterrupt:
			self.ctu.stop()
			return

		if self.current is not None:
			self.current.freeze(pcOffset=pcOffset)
			if self.current.active:
				self.running.append(self.current)
		self.current = new
		self.ctu.pc = self.ctu.termaddr # Trap out of CTU
		self.switched = True
		return True

	def clear(self):
		self.threads = []
		self.threadCount = 0
		self.threadId = 0
		self.running = []
		self.current = None
		self.switched = False

	def create(self, pc, sp, *regs):
		thread = Thread(self.ctu, self.threadId, pc, sp, regs)
		self.threadId += 1
		self.threads.append(thread)
		self.threadCount = len(self.threads)
		return thread

	def exit(self, id=None):
		if id is None:
			id = self.current.id

		for i, thread in enumerate(self.threads):
			if thread.id == id:
				print 'Terminating thread...'
				thread.terminate()
				return

class Thread(Waitable):
	def __init__(self, ctu, id, pc, sp, regs):
		self.ctu = ctu
		self.id = id
		self.handle = self.ctu.newHandle(self)
		self.active = len(self.ctu.threads.threads) == 0
		self.terminated = False
		self.blx = True

		self.regs = [pc, sp] + list(regs) + [0] * (67 - len(regs))
		if self.regs[30+2] == 0:
			self.regs[30+2] = self.ctu.termaddr # LR == termaddr

		self.callstack = []
		self.lastinsn = None

		self.tlssize = 1024 * 1024 # 1MB
		self.tlsbase = (1 << 24) + self.tlssize * self.id
		self.ctu.map(self.tlsbase, self.tlssize)
		self.ctu.writemem(self.tlsbase, '\0' * self.tlssize)
		self.ctu.write64(self.tlsbase + 0x1F8, self.tlsbase + 0x200)
		self.ctu.write64(self.tlsbase + 0x3B8, self.handle)
		#tname = 'MediaPlayerHandler'
		#threadname = self.ctu.malloc(len(tname) + 1)
		#self.ctu.writemem(threadname, tname + '\0')
		#self.ctu.write64(self.tlsbase + 0x3A8, threadname)

		self.blockers = []
	
		if self.active:
			self.ctu.threads.current = self

	def terminate(self):
		if self.ctu.threads.current is self:
			self.ctu.threads.current = None

		self.signal()
		self.active = False
		self.terminated = True
		self.ctu.threads.threads = [x for x in self.ctu.threads.threads if x is not self]
		self.ctu.threads.running = [x for x in self.ctu.threads.running if x is not self]
		self.ctu.threads.threadCount -= 1
		self.ctu.threads.next()
		print 'Killed thread id %i. Switched to %i at 0x%x' % (self.id, self.ctu.threads.current.id, self.ctu.threads.current.regs[0])

	def suspend(self):
		if not self.active:
			return
		if self is self.ctu.threads.current:
			self.freeze(pcOffset=+4)
			self.ctu.threads.current = None
			self.active = False
			self.ctu.threads.next()
		else:
			self.active = False

	def resume(self):
		self.active = True
		self.ctu.threads.running.append(self)

	def freeze(self, pcOffset=0):
		regs = self.regs
		mu = self.ctu.mu
		regs[0] = mu.reg_read(UC_ARM64_REG_PC) + pcOffset
		regs[1] = mu.reg_read(UC_ARM64_REG_SP)
		for i in xrange(29):
			regs[i+2] = mu.reg_read(UC_ARM64_REG_X0 + i)
		regs[29+2] = mu.reg_read(UC_ARM64_REG_X29)
		regs[30+2] = mu.reg_read(UC_ARM64_REG_X30)
		for i in xrange(32):
			regs[i+33] = mu.reg_read(UC_ARM64_REG_Q0 + i)
		regs[66] = mu.reg_read(UC_ARM64_REG_NZCV)
		
		#self.ctu.dumpregs()
		print 'Thread %i frozen PC=%x, SP=%x, LR=%x' % (self.id, regs[0], regs[1], regs[30+2])

	def thaw(self):
		regs = self.regs
		mu = self.ctu.mu
		mu.reg_write(UC_ARM64_REG_PC, regs[0])
		mu.reg_write(UC_ARM64_REG_SP, regs[1])
		for i in xrange(29):
			mu.reg_write(UC_ARM64_REG_X0 + i, regs[i+2])
		mu.reg_write(UC_ARM64_REG_X29, regs[29+2])
		mu.reg_write(UC_ARM64_REG_X30, regs[30+2])
		for i in xrange(32):
			mu.reg_write(UC_ARM64_REG_Q0 + i, regs[i+33])
		mu.reg_write(UC_ARM64_REG_NZCV, regs[66])

		print 'Thread %i thawed PC=%x, SP=%x, LR=%x' % (self.id, regs[0], regs[1], regs[30+2])
		#self.ctu.dumpregs()
