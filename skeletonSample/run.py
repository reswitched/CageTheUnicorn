import sys
sys.path.append('.')
from ctu import *

#@run#(TRACE_FUNCTION)
@debug(TRACE_MEMCHECK)
def main(ctu):
	ctu.load('skeletonSample')

	#@ctu.replaceFunction(MainAddress(unknown))
	def memset(ctu, addr, val, size):
		ctu.writemem(addr, chr(val) * size, check=False)

	ctu.call(MainAddress(0x0), _start=True)
