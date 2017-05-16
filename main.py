from ctu import *
from util import *
from ceval import ceval

@run
@debug
def main(ctu):
	fPath = ctu.malloc(36)
	ctu.writemem(fPath, 'blacklist:/blacklist.txt\0')
	fOption = ctu.malloc(16)
	ctu.writemem(fOption, 'rb\0')
	print '%016x' % ctu.call(MainAddress(0x43ddb4), fPath, fOption)

	#ctu.dumpmem(WKCAddress(0x887828), 0x1000)
	#ctu.call(WKCAddress(0x397B3C))

	"""sbuf = ctu.malloc(32)
	ctu.writemem(sbuf + 4, struct.pack('<I', 0xAABCDDEF))
	obuf = ctu.malloc(0x1000)

	print 'obuf at %x' % obuf
	ctu.call(MainAddress(0x397c68), sbuf, obuf, 0xDEADBEEF01234567, 0xCAFEBABE)"""

	"""dname = ctu.malloc(64)
	ctu.writemem(dname, '/dev/nvmap')
	print '%016x' % ctu.call(MainAddress(0x1a49c4), dname)"""
	#print '%016x' % ctu.call(MainAddress(0x1a4b10), 0xdeadbeef, 0xcafebabe, 0x0123456789, 0xf0e0d0c0)
	#print '%016x' % ctu.call(MainAddress(0x1a4ae8), 0x6b0001)
