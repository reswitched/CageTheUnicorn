from util import *
from threading import Thread

class Mutex(Waitable):
	def __init__(self, ctu, ptr):
		self.setup()
		self.ctu = ctu
		self.ptr = ptr
		self.waitable_presignalable = False

	@property
	def value(self):
		return self.ctu.read32(self.ptr)
	
	@property
	def owner(self):
		handle = self.value & 0xBFFFFFFF
		if handle == 0:
			return None
		return self.ctu.handles[handle]

	@owner.setter
	def owner(self, handle):
		if handle not in self.ctu.handles: # We must have the object
			for sh, so in self.ctu.handles.items():
				if handle is so:
					handle = sh
					break
		self.ctu.write32(self.ptr, (self.ctu.read32(self.ptr) & 0x40000000) | handle)

	@property
	def hasWaiters(self):
		return self.ctu.read32(self.ptr) >> 28

	@hasWaiters.setter
	def hasWaiters(self, value):
		self.ctu.write32(self.ptr, (self.ctu.read32(self.ptr) & 0xBFFFFFFF) | (int(value) << 30))

	def guestRelease(self):
		self.owner = 0
		Thread(target=self.signal).start()

class Semaphore(Waitable):
	def __init__(self, ctu, ptr):
		self.setup()
		self.ctu = ctu
		self.ptr = ptr
		self.waitable_presignalable = False

		self.value = 0

	@property
	def value(self):
		return self.ctu.read32(self.ptr)

	@value.setter
	def value(self, value):
		self.ctu.write32(self.ptr, value)

	def increment(self):
		self.acquire()
		self.value += 1
		self.release()

	def decrement(self):
		self.acquire()
		self.value -= 1
		self.release()
