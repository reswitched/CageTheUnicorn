import os, os.path, shutil, struct, yaml
import ipcbridge
from util import *

from ipcbase import *
from ipcstubs import *

class IPC(object):
	def __init__(self, ctu):
		self.ctu = ctu

	def connectToPort(self, name):
		if name == 'sm:':
			return self.ctu.newHandle(SmService(self))
		else:
			print 'Attempt to connect to unknown port: %r' % name
			self.ctu.debugbreak()

	def recv(self, handle, buffer):
		if handle not in self.ctu.handles or not hasattr(self.ctu.handles[handle], 'dispatch'):
			print 'BAD HANDLE FOR IPC! %x -- %r' % (handle, self.ctu.handles[handle] if handle in self.ctu.handles else None)
			self.ctu.debugbreak()
			return 0, IPCMessage(0).setType(0).pack()
		obj = self.ctu.handles[handle]
		return obj.dispatch(handle, buffer)

@register('sm:')
class SmService(IPCService):
	def __init__(self, *args, **kwargs):
		IPCService.__init__(self, *args, **kwargs)
		self.initialized = False

	@command(0)
	def Initialize(self, message):
		print 'Initialize SM!', message
		if self.initialized:
			print 'Already initialized'
		self.initialized = True

	@command(1)
	def GetService(self, message):
		name = struct.pack('<Q', message.dataBuffer[0]).rstrip('\0')
		if name in services:
			print 'Successfully got service:', `name`
			return IPCMessage().moveHandle(services[name](self.ipc))
		else:
			print 'Attempted to get unknown service:', `name`
			self.ipc.ctu.debugbreak()

	@command(2)
	def RegisterService(self, message):
		name, maxSessions = struct.pack('<Q', message.dataBuffer[0]).rstrip('\0'), message.dataBuffer[1]
		print 'Register service!', name, message
		svcport = Port(name)
		ipcbridge.register(name, svcport)
		return IPCMessage().moveHandle(svcport)

	@command(3)
	def UnregisterService(self, message):
		pass

@partial(ILibraryAppletSelfAccessor)
class ImplILibraryAppletSelfAccessor:
	GetLibraryAppletInfo = stub().data(0x13)

@partial(IStorageAccessor)
class ImplIStorageAccessor:
	def __setup__(self, name):
		self.name = name

	def GetSize(self, message):
		print 'Getting IStorage length for', self.name
		if self.name == 'nn::am::service::IProcessWindingController::PopContext':
			size = 0x38
		else:
			print '~~Unknown IStorage size!  %s ~~' % self.name
			size = 0x2000
		return IPCMessage(0).data(size)

	def Read(self, message):
		addr, size, _ = message.bDescriptors[0]
		if size == 0:
			return
		self.ctu.write16(addr + 0, 0)
		self.ctu.write32(addr + 4, 5)

@partial(IStorage)
class ImplIStorage:
	def __setup__(self, name):
		self.name = name

	def Open(self, message):
		return IPCMessage(0).moveHandle(IStorageAccessor(self.ipc, self.name))

@partial(ILibraryAppletAccessor)
class ImplILibraryAppletAccessor:
	GetAppletStateChangedEvent = stub(0).copyHandle(InstantWaitable)

@partial(IApplicationDisplayService)
class ImplIApplicationDisplayService:
	def OpenLayer(self, message):
		addr = message.bDescriptors[0][0]
		self.ctu.write32(addr + 0x00, 0x30)
		self.ctu.write32(addr + 0x04, 0x80)
		self.ctu.write32(addr + 0x08, 1 << 2)
		self.ctu.write32(addr + 0x0c, 0)
		self.ctu.write64(addr + 0x10, 0x40)
		self.ctu.write64(addr + 0x90, 0x20)
		self.ctu.write32(addr + 0xb0, 4)
		return IPCMessage(0).data(0xec069d45)

@partial(ICommonStateGetter)
class ImplICommonStateGetter:
	GetEventHandle = stub().copyHandle(Waitable)

@register('arp:r')
class ArpRService(IPCService):
	unk0 = stub(0)
	unk2 = stub(2)

@register('arp:w')
class ArpWService(IPCService):
	class ArpW0Service(IPCService):
		unk1 = stub(1)

	unk0 = stub(0).moveHandle(ArpW0Service)

@register('bgtc:t')
class BgtcTService(IPCService):
	unk2 = stub(2)

	@command(3)
	def Unknown3(self, message):
		print 'bgtc:t(3) unknown', message
		return IPCMessage().copyHandle(Waitable())

	@command(5)
	def Unknown5(self, message):
		print 'bgtc:t(5) unknown', message
		self.ctu.dumpmem(message.xDescriptors[0][0], message.xDescriptors[0][1])

	@command(14)
	def Unknown14(self, message):
		print 'bgtc:t(14) unknown', message
		return IPCMessage().copyHandle(Waitable())

class BgtcT14Service(IPCService):
	pass

@register('bsd:s')
class BsdSService(IPCService):
	Init = stub(0)
	unk1 = stub(1)

@register('btm')
class BtmService(IPCService):
	unk2 = stub(2)

@register('caps:a')
class CapsAService(IPCService):
	pass

@register('caps:c')
class CapsCService(IPCService):
	pass

@register('caps:ss')
class CapsSsService(IPCService):
	pass

@register('es')
class EsService(IPCService):
	pass

@register('fatal:u')
class FatalUService(IPCService):
	@command(2)
	def FatalError(self, message):
		print '!!! FATAL ERROR: 0x%X !!!' % ( (message.data[0] >> 9) & 0xFFF )
		stackSize = self.ipc.ctu.read64(message.aDescriptors[0][0] + 0x240)
		print 'Stack trace'
		print '-'*28
		for i in xrange(0, stackSize):
			print '\t[%d] %016x'%(i, self.ipc.ctu.read64(message.aDescriptors[0][0] + 0x130 + (i * 8)))
		print '-'*28
		self.ipc.ctu.dumpregs()
		self.ipc.ctu.debugbreak()
		return IPCMessage().data(message.data[0])

@register('fsp-pr')
class FspPrService(IPCService):
	pass

@register('fsp-srv')
class FspSrvService(IPCService):
	Init = stub(1)

	@command(18)
	def MountSdCard(self, message):
		return IPCMessage(0).moveHandle(IFileSystem(self.ipc, 'sdcard'))

	@command(23)
	def CreateSystemSaveData(self, message):
		id = message.data[3]
		dir = 'syssave_%x' % id
		print 'CreateSystemSaveData 0x%016x' % id
		IFileSystem(self.ipc, dir)
		return IPCMessage(0).data(0)

	@command(52)
	def MountSystemSaveData(self, message):
		id = message.data[4]
		dir = 'syssave_%x' % id
		print 'MountSystemSaveData 0x%016x' % id
		if id in (0x8000000000000047, ) and not os.path.exists('SwitchFS/' + dir):
			return IPCMessage(0x7d402)
		return IPCMessage(0).data(0, 0).moveHandle(IFileSystem(self.ipc, dir))

	@command(200)
	def OpenHost(self, message):
		print 'OpenHost'
		return IPCMessage(0).moveHandle(FSIStorage(self.ipc, 'host'))

	@command(202)
	def OpenDataStorageByDataId(self, message):
		print 'OpenDataStorageByDataId', message
		fn = 'archives/%016X.bin' % message.data[1]
		return IPCMessage(0).moveHandle(FSIStorage(self.ipc, fn))

	@command(400)
	def OpenDeviceOperator(self, message):
		return IPCMessage(0).moveHandle(DeviceOperator(self.ipc))

	@command(500)
	def OpenSdCardDetectionEventNotifier(self, message):
		return IPCMessage(0).moveHandle(IEventNotifier(self.ipc))

	@command(501)
	def OpenGameCardDetectionEventNotifier(self, message):
		return IPCMessage(0).moveHandle(IEventNotifier(self.ipc))

	unk620 = stub(620)
	DisableAutoSaveDataCreation = stub(1003)

class IEventNotifier(IPCService):
	@command(0)
	def BindEvent(self, message):
		print 'IEventNotifier:BindEvent', message
		return IPCMessage(0).copyHandle(Waitable())

class FSIStorage(IPCService):
	def __init__(self, ipc, path):
		IPCService.__init__(self, ipc)
		self.path = 'SwitchFS/' + path
		self.fp = file(self.path, 'rb')

	def __repr__(self):
		return 'FSIStorage(%r)' % self.path

	@command(0)
	def Read(self, message):
		print 'FSIStorage:Read', message
		offset, length = message.data[0:2]
		addr, size, _ = message.bDescriptors[0]
		assert length == size
		print 'Reading from %x-%x into %x' % (offset, offset + length, addr)
		self.fp.seek(offset, 0)
		self.ctu.writemem(addr, self.fp.read(size))
		return IPCMessage(0).data(size)

class IFileSystem(IPCService):
	def __init__(self, ipc, path):
		IPCService.__init__(self, ipc)
		self.path = 'SwitchFS/' + path

		if not os.path.exists(self.path):
			os.makedirs(self.path)

	def __repr__(self):
		return 'IFileSystem(%r)' % self.path

	@command(0)
	def CreateFile(self, message):
		print 'IFileSystem:CreateFile', message
		try:
			path = self.ctu.readstring(message.xDescriptors[0][0])
			if path:
				rpath = self.path + '/' + path
				print rpath
				file(rpath, 'wb').close()
			else:
				print 'Empty filename?'
		except:
			print 'WTF?!?!?!'

	@command(1)
	def DeleteFile(self, message):
		print 'IFileSystem:DeleteFile', message
		path = self.ctu.readstring(message.xDescriptors[0][0])
		rpath = self.path + '/' + path
		print rpath

	@command(2)
	def CreateDirectory(self, message):
		print 'IFileSystem:CreateDirectory', message
		path = self.ctu.readstring(message.xDescriptors[0][0])
		rpath = self.path + '/' + path
		print rpath
		if not os.path.exists(rpath):
			os.makedirs(rpath)

	@command(4)
	def DeleteDirectoryRecursively(self, message):
		print 'IFileSystem:DeleteDirectoryRecursively', message
		path = self.ctu.readstring(message.xDescriptors[0][0])
		rpath = self.path + '/' + path
		print rpath
		if os.path.exists(rpath):
			shutil.rmtree(rpath, ignore_errors=True)

	@command(7)
	def GetEntryType(self, message):
		print 'IFileSystem:GetEntryType', message
		path = self.ctu.readstring(message.xDescriptors[0][0])
		rpath = self.path + '/' + path
		print rpath
		if os.path.exists(rpath):
			return IPCMessage(0).data(0 if os.path.isdir(rpath) else 1)
		else:
			return IPCMessage(0x7d402)

	@command(8)
	def OpenFile(self, message):
		print 'IFileSystem:OpenFile', message
		path = self.ctu.readstring(message.xDescriptors[0][0])
		rpath = self.path + '/' + path
		mode = message.data[0]
		print rpath
		if os.path.exists(rpath) or mode & 2:
			return IPCMessage(0).moveHandle(IFile(self.ipc, rpath, ['', 'rb', 'wb+', 'wb+', 'ab+', 'ab+', 'ab+', 'ab+'][mode]))
		elif path == '/systemseed.dat':
			file(rpath, 'wb').close()
			return IPCMessage().moveHandle(IFile(self.ipc, rpath, ['', 'rb', 'wb+', 'wb+', 'ab+', 'ab+', 'ab+', 'ab+'][mode]))
		else:
			return IPCMessage(0x7d402)

	@command(10)
	def Commit(self, message):
		print 'IFileSystem:Commit', message

class IFile(IPCService):
	def __init__(self, ipc, path, mode):
		IPCService.__init__(self, ipc)
		self.path = path
		self.mode = mode
		if mode.endswith('+'):
			if not os.path.exists(path):
				file(path, 'w').close()
		self.fp = file(path, mode)

	def __repr__(self):
		return 'IFile(%r, %r)' % (self.path, self.mode)

	def close(self):
		self.fp.close()

	@command(0)
	def Read(self, message):
		addr, size, _ = message.bDescriptors[0]
		print 'Reading 0x%x bytes from %s' % (size, self.path)
		self.ctu.writemem(addr, self.fp.read(size))
		return IPCMessage(0).data(size)

	@command(1)
	def Write(self, message):
		addr, size, _ = message.aDescriptors[0]
		print 'Writing 0x%x bytes to %s' % (size, self.path)
		self.fp.write(self.ctu.readmem(addr, size))
		return IPCMessage(0).data(size)

	@command(2)
	def Flush(self, message):
		self.fp.flush()

	@command(3)
	def SetSize(self, message):
		cur = self.fp.tell()
		size = message.data[0]
		print 'Setting size %x for %s with mode %r' % (size, self.path, self.mode)
		self.fp.seek(0, 2)
		csize = self.fp.tell()
		if csize == size:
			pass
		elif csize < size:
			self.fp.write('\0' * (size - csize))
		else:
			self.fp.seek(0)
			data = self.fp.read()
			self.fp.close()
			self.fp = file(self.path, self.mode)
			self.fp.write(data)
			if cur >= size:
				cur = 0
		self.fp.seek(cur)

	@command(4)
	def GetSize(self, message):
		cur = self.fp.tell()
		self.fp.seek(0, 2)
		ret = IPCMessage(0).data(self.fp.tell())
		self.fp.seek(cur)
		return ret

class DeviceOperator(IPCService):
	@command(0)
	def IsSdCardInserted(self, message):
		return IPCMessage(0).data(0)

	@command(200)
	def IsGameCardInserted(self, message):
		return IPCMessage(0).data(0)

@register('gpio')
class GpioService(IPCService):
	@command(1)
	def getPadSessionSubService(self, message):
		return IPCMessage(0).moveHandle(PadSession(self.ipc))

class PadSession(IPCService):
	unk0 = stub(0)
	unk8 = stub(8)
	unk9 = stub(0)

@register('ldr:ro')
class LdrRoService(IPCService):
	Initialize = stub(4)

@register('ldr:shel')
class LdrShelService(IPCService):
	pass

@register('lm')
class LmService(IPCService):
	@command(0)
	def Initialize(self, message):
		print 'Initialize lm'
		return IPCMessage(0).moveHandle(ILogger(self.ipc))

class ILogger(IPCService):
	@command(0)
	def unk0(self, message):
		print self.ctu.readmem(message.xDescriptors[0][0], message.xDescriptors[0][1])
		return IPCMessage(0)

@register('lr')
class LrService(IPCService):
	@command(0)
	def Unknown0(self, message):
		print 'lr(0) unknown', message
		return IPCMessage(0).moveHandle(Lr0Service(self.ipc))

class Lr0Service(IPCService):
	@command(2)
	def Unknown2(self, message):
		print 'lr(0)(2) unknown', message
		self.ctu.writemem(message.cDescriptors[0][0], 'omgwtfhax\0')
		return IPCMessage(0)

@register('ncm')
class NcmService(IPCService):
	unk2 = stub(2)
	unk3 = stub(3)

	@command(4)
	def Unknown4(self, message):
		print 'ncm(4) unknown'
		return IPCMessage().moveHandle(Ncm4Service(self.ipc))
	@command(5)
	def Unknown5(self, message):
		print 'ncm(5) unknown'
		return IPCMessage().moveHandle(Ncm5Service(self.ipc))

	unk9 = stub(9)
	unk11 = stub(11)

class Ncm4Service(IPCService):
	unk10 = stub(10)

	@command(13)
	def Unknown13(self, message):
		return IPCMessage(0).data(0, 0)

class Ncm5Service(IPCService):
	@command(5)
	def Unknown5(self, message):
		return IPCMessage(0).data(0, 0)

	unk7 = stub(7)
	unk8 = stub(8)
	unk15 = stub(15)

@register('nim')
class NimService(IPCService):
	class Nim12Service(IPCService):
		unk2 = stub(2)

	unk2 = stub(2)
	unk8 = stub(8)
	unk12 = stub(12).copyHandle(Waitable).moveHandle(Nim12Service)
	unk40 = stub(40)

@register('npns:s')
class NpnsSService(IPCService):
	# nn::ssl::sf::ISslService::SetInterfaceVersion
	@command(5)
	def SetInterfaceVersion(self, message):
		return IPCMessage().copyHandle(Waitable())

	@command(7)
	def Unknown7(self, message):
		return IPCMessage().copyHandle(Waitable())

	@command(103)
	def Unknown103(self, message):
		return IPCMessage().data(0, 0).moveHandle(Waitable())

@register('ns:ec')
class NsEcService(IPCService):
	pass

@register('ns:su')
class NsSuService(IPCService):
	pass

@register('ns:vm')
class NsVmService(IPCService):
	pass

@register('nsd:u')
class NsdUService(IPCService):
	@command(11)
	def Unknown11(self, message):
		print 'nsd:u(11) unknown', message
		self.ctu.writemem(message.bDescriptors[0][0], '\0' * message.bDescriptors[0][1])

@register('nvdrv')
@register('nvdrv:a')
@register('nvdrv:s')
@register('nvdrv:t')
class NvdrvService(IPCService):
	@command(0)
	def Open(self, message):
		dev = self.ctu.readstring(message.aDescriptors[0][0])
		dev_hnd = self.ctu.newHandle(dev)
		print 'Attempting to open device:%s %x'%(dev, dev_hnd)
		return IPCMessage(0).data(dev_hnd)

	@command(1)
	def Ioctl(self, message):
		print 'Ioctl:', message
		self.ctu.dumpmem(message.xDescriptors[0][0], message.xDescriptors[0][1]) 
		return IPCMessage(0).data(1234)

	@command(2)
	def Close(self, message):
		print 'Close:',message
		return IPCMessage(0).data(0)

	@command(3)
	def Init(self, message):
		print 'Init:', message
		return IPCMessage(0).data(0, 0)

	@command(4)
	def QueryEvent(self, message):
		print 'QueryEvent:', message
		return IPCMessage(0).data(0, 0)

	@command(5)
	def MapSharedMem(self, message):
		print 'MapSharedMem:', message
		return IPCMessage(0).data(0, 0)

	@command(8)
	def BindDisplayService(self, message):
		print 'BindDisplayService: ', message
		return IPCMessage(0).data(0, 0)
	unk13 = stub(13)

@register('ovln:snd')
class OvlnSndService(IPCService):
	@command(0)
	def Unknown0(self, message):
		if message.data[0] == 0x79616c7265766f:
			return IPCMessage().moveHandle(OvlnSndOverlay(self.ipc))
		else:
			self.ctu.debugbreak()

class OvlnSndOverlay(IPCService):
	pass

@register('pcie')
class PCIeService(IPCService):
	pass

@register('pdm:qry')
class PdmQryService(IPCService):
	pass

@register('pl:u')
class PlUService(IPCService):
	unk0 = stub(0).data(0, 0, 0, 0)
	unk1 = stub(1).data(0, 0, 0, 0)
	unk2 = stub(2).data(0, 0, 0, 0)

@register('pm:bm')
class PmBmService(IPCService):
	@command(0)
	def Init(self, message):
		return IPCMessage().data(0, 0)

	EnableMaintenanceMode = stub(1)

@register('pm:shell')
class PmShellService(IPCService):
	@command(0)
	def LaunchTitle(self, message):
		print 'Launched title %016X' % message.data[1]
		return IPCMessage().data(0x0)

	@command(3)
	def Unknown3(self, message):
		print 'pm:shell(3) unknown'
		return IPCMessage().copyHandle(Waitable())

@register('psc:m')
class PscMService(IPCService):
	@command(0)
	def Unknown0(self, message):
		return IPCMessage().moveHandle(PscMSubService(self.ipc))

class PscMSubService(IPCService):
	@command(0)
	def Unknown0(self, message):
		print 'psc:m#sub(0)', message
		addr, size, perm = message.aDescriptors[0]
		if addr != 0x0:
			self.ctu.dumpmem(addr, size)
		return IPCMessage(0x0).copyHandle(Waitable())
		#return IPCMessage().copyHandle(Waitable())

@partial(ISystemSettingsServer)
class SetSysService:
	def __setup__(self):
		self.settings = yaml.load(file('systemsettings.yaml'))

	def GetSettingsItemValue(self, message):
		a, b = message.xDescriptors
		scls, snam = self.ctu.readmem(a[0], a[1]).split('\0', 1)[0], self.ctu.readmem(b[0], b[1]).split('\0', 1)[0]
		baddr, bsize, _ = message.bDescriptors[0]
		setting = scls + '!' + snam
		print 'Getting setting', setting
		if setting in self.settings:
			data = self.settings[setting]
			if bsize == 1:
				self.ctu.write8(baddr, data)
			elif bsize == 4:
				self.ctu.write32(baddr, data)
			elif bsize == 8:
				self.ctu.write64(baddr, data)
			else:
				print 'Unknown setting size', bsize
			return IPCMessage().data(bsize)
		else:
			print 'Unknown setting'
			return IPCMessage().data(0)

@register('spl:')
class SplService(IPCService):
	@command(0)
	def GetConfig(self, message):
		configId = message.data[0]
		print 'spl:GetConfig(0x%x)' % configId

		if configId == 5: # HardwareType (0=Icosa, 1=Copper)
			return IPCMessage(0).data(1)
		else:
			return IPCMessage(0).data(0)

	@command(11)
	def GetDevunitFlag(self, message):
		return IPCMessage().data(0)

@register('wlan:lcl')
class WlanLclService(IPCService):
	class WlanLcl17Service(IPCService):
		pass

	unk17 = stub(17).moveHandle(WlanLcl17Service)

@register('wlan:lg')
class WlanLgService(IPCService):
	pass

@register('wlan:lga')
class WlanLgaService(IPCService):
	pass
