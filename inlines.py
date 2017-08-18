from util import *

magicBase = 1 << 62
functions = {}
reverse = {}

def register(func, override=False):
	global magicBase
	def sub(ctu):
		args = (ctu.reg(i) for i in xrange(func.__code__.co_argcount - 1))
		ret = func(ctu, *args)
		if ret is None:
			return
		elif isinstance(ret, tuple):
			for i, v in enumerate(ret):
				ctu.reg(i, native(v))
		else:
			ctu.reg(0, native(ret))
	functions[func.func_name] = sub, magicBase + 8 * len(reverse), override
	reverse[magicBase + 8 * len(reverse)] = sub
	return sub

def registerOverride(func):
	return register(func, override=True)

@register
def malloc(ctu, size):
	return ctu.malloc(size)

@register
def free(ctu, ptr):
	return ctu.free(ptr)

@register
def calloc(ctu, num, size):
	ptr = ctu.malloc(num * size)
	ctu.writemem(ptr, '\0' * (num * size))
	return ptr

@registerOverride
def _ZN2nn4diag6detail9AbortImplEPKcS3_S3_iPKNS_6ResultES3_z(ctu, x0, x1, x2, x3, x4, x5):
	print '!!!Abort!!!'
	print formatString(ctu, ctu.readstring(x5), 6)
	ctu.debugbreak()
