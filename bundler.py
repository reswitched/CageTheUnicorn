import struct
from glob import glob

mainaddr = raw_input('Enter main module address: ')
if mainaddr.startswith('0x'):
	mainaddr = mainaddr[2:]
mainaddr = int(mainaddr, 16)
print 'Main at 0x%016x' % mainaddr
wkcaddr = raw_input('Enter wkc module address: ')
if wkcaddr.startswith('0x'):
	wkcaddr = wkcaddr[2:]
wkcaddr = int(wkcaddr, 16)
print 'WKC at 0x%016x' % wkcaddr

with file('membundle.bin', 'wb') as fp:
	files = glob('memdumps/*.bin')
	fp.write(struct.pack('<IQQ', len(files), mainaddr, wkcaddr))
	for fn in files:
		addr = int(fn[11:].split(' ')[0], 16)
		data = file(fn, 'rb').read()
		fp.write(struct.pack('<QI', addr, len(data)))
		fp.write(data)
