from select import select
from socket import *
from struct import pack, unpack
from threading import Thread
import sys

from util import *

PORT = 31337

buffers = []
nullbuf = '\0' * (1024 * 1024)

def start(ctu):
	Thread(target=threadstart, args=(ctu, )).start()

def threadstart(ctu):
	def waitSock(sock):
		while True:
			rl, wl, el = select([sock], [], [], .1)
			if ctu.exiting:
				sys.exit()
			elif len(rl):
				break

	server = socket(AF_INET, SOCK_STREAM)
	server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	server.bind(('', PORT))
	server.listen(5)
	while True:
		waitSock(server)
		sock, _ = server.accept()

		while not ctu.threads.startupCompleted:
			time.sleep(0.1)

		for i in xrange(24):
			addr = (i + 1) * (1 << 20) + (1 << 28)
			ctu.map(addr, 1024 * 1024)
			buffers.append(addr)

		def readint(default=None):
			waitSock(sock)
			data = sock.recv(8)
			if len(data) != 8:
				return default
			return unpack('<Q', data)[0]
		def readdata(default=None):
			waitSock(sock)
			size = readint()
			if size is None:
				return default
			odata = ''
			while len(odata) != size:
				data = sock.recv(size - len(odata))
				if len(data) == 0:
					return None
				odata += data
			return odata
		def writeint(v):
			try:
				sock.send(pack('<Q', v))
			except:
				pass
		def writedata(v):
			try:
				writeint(len(v))
				sock.send(v)
			except:
				pass

		openHandles = []

		while True:
			waitSock(sock)
			cmd = readint()
			if cmd is None: # Connection dropped
				break
			elif cmd == 0: # Open service
				name = readdata()
				if name is None:
					break
				print 'Open service', name
				port = servicePorts[name]
				port.acquire()
				cp, sp = Pipe.new()
				cp.accept()
				port.push(sp)
				port.release()
				sp.waitForAccept()
				handle = ctu.newHandle(cp)
				openHandles.append(handle)
				writeint(handle)
			elif cmd == 1: # Close handle
				handle = readint()
				if handle is None:
					break
				print 'Close handle', handle
				openHandles = [x for x in openHandles if x != handle]
				ctu.closeHandle(handle)
			elif cmd == 2: # IPC Message
				request_type = readint()
				data = [readint() for i in xrange(readint(0))]
				pid = readint()
				copy = [readint() for i in xrange(readint(0))]
				move = [readint() for i in xrange(readint(0))]
				a = [(readdata(), readint()) for i in xrange(readint(0))]
				b = [(readdata(), readint()) for i in xrange(readint(0))]
				c = [readdata() for i in xrange(readint(0))]
				x = [(readdata(), readint()) for i in xrange(readint(0))]
				handle = readint()

				if handle is None:
					break

				msg = IPCMessage(data[0])
				msg.setType(request_type)
				msg.data(*data[1:])
				if pid != 0xFFFFFFFFFFFFFFFF:
					msg.hasPID(pid)
				map(msg.copyHandle, copy)
				map(msg.moveHandle, move)
				bufI = 0

				for data, perms in a:
					if len(data) == 0:
						addr = 0
					else:
						addr = buffers[bufI]
						ctu.writemem(addr, nullbuf, check=False)
						ctu.writemem(addr, data)
					print 'A descriptor at %x' % addr
					msg.aDescriptor(addr, len(data), perms)
					bufI += 1
				for data, perms in b:
					if len(data) == 0:
						addr = 0
					else:
						addr = buffers[bufI]
						ctu.writemem(addr, nullbuf, check=False)
						ctu.writemem(addr, data)
					print 'B descriptor at %x' % addr
					msg.bDescriptor(addr, len(data), perms)
					bufI += 1
				for data in c:
					if len(data) == 0:
						addr = 0xf00ba1
					else:
						addr = buffers[bufI]
						ctu.writemem(addr, nullbuf)
						ctu.writemem(addr, data)
					print 'C descriptor at %x' % addr
					msg.cDescriptor(addr, len(data))
					bufI += 1
				for data, counter in x:
					if len(data) == 0:
						addr = 0xf00ba3
					else:
						addr = buffers[bufI]
						ctu.writemem(addr, nullbuf)
						ctu.writemem(addr, data)
					print 'X descriptor at %x' % addr
					msg.xDescriptor(addr, len(data), counter)
					bufI += 1

				msg.request = True
				data = msg.pack()
				data = pack('<' + 'I' * len(data), *[(x if x is not None else 0) & 0xFFFFFFFF for x in data])
				obj = ctu.handles[handle]
				print 'IPC message to', obj, obj.other, msg
				if obj.closed:
					print 'But pipe is closed!'
					writeint(0xf601)
					continue

				obj.push(data)
				resp = obj.pop()

				if resp is None:
					print 'IPC port closed!'
					openHandles = [x for x in openHandles if x != handle]
					writeint(0xf601)
				else:
					writeint(0)
					resp = IPCMessage().unpack(unpack('<' + 'I' * (len(resp) / 4), resp), request=False)
					writeint(len(resp.dataBuffer) + 1)
					map(writeint, [resp.cmdId] + resp.dataBuffer)
					writeint(len(resp.copiedHandles))
					map(writeint, resp.copiedHandles)
					writeint(len(resp.movedHandles))
					map(writeint, resp.movedHandles)
					writeint(len(msg.aDescriptors))
					[(writedata(ctu.readmem(addr, size)), writeint(perms)) for addr, size, perms in msg.aDescriptors]
					writeint(len(msg.bDescriptors))
					[(writedata(ctu.readmem(addr, size)), writeint(perms)) for addr, size, perms in msg.bDescriptors]
					writeint(len(msg.cDescriptors))
					[writedata(ctu.readmem(addr, size)) for addr, size in msg.cDescriptors]
					writeint(len(msg.xDescriptors))
					[(writedata(ctu.readmem(addr, size)), writeint(counter)) for addr, size, counter in msg.xDescriptors]
					writeint(resp.type)

					openHandles += resp.movedHandles

		for handle in openHandles:
			print 'IPC bridge closing handle %x' % handle
			ctu.closeHandle(handle)

servicePorts = {}

def register(name, port):
	servicePorts[name] = port
