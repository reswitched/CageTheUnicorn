import sys
sys.path.append('.')
import struct, sys
from ipcclient import *

c = Client(*sys.argv[1:]) # Optional hostname -- otherwise defaults to localhost
svcTarget = 'pl:u'

print c.ipcMsg(0).data(0xf00, 5).copyHandle(0x012345678).moveHandle(0xCAFEBABE).aDescriptor('data here', 1).sendTo(svcTarget)

