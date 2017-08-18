import struct, sys
from glob import glob

def main(dumpdir, mainaddr, wkcaddr):
	mainaddr = int(mainaddr.replace('0x', ''), 16)
	wkcaddr = int(wkcaddr.replace('0x', ''), 16)

	with file('membundle.bin', 'wb') as fp:
		files = glob('%s/*.bin' % dumpdir)
		fp.write(struct.pack('<IQQ', len(files), mainaddr, wkcaddr))
		for fn in files:
			addr = int(fn[11:].rsplit('/', 1)[-1].split(' ', 1)[0], 16)
			end = int(fn[11:].rsplit('/', 1)[-1].split(' - ')[1], 16)
			data = file(fn, 'rb').read()
			print '%x size %x -- real %x' % (addr, end - addr, len(data))
			if end - addr != len(data):
				print 'MISMATCHED SIZE!  CORRUPT DUMP'
				raw_input()
			fp.write(struct.pack('<QI', addr, len(data)))
			fp.write(data)

if __name__=='__main__':
	main(*sys.argv[1:])
