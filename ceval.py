from pycparser.c_parser import CParser
from pycparser.c_ast import *
import struct

class AstTranslator(object):
	def process(self, ast):
		node = ast.__class__.__name__
		
		if hasattr(self, node):
			func = getattr(self, node)
			fcode = func.im_func.func_code
			argnames = fcode.co_varnames[1:fcode.co_argcount]
			args = [getattr(ast, name) for name in argnames]
			return func(*args)
		else:
			print 'Unhandled AST node:'
			ast.show()
			return '?unknown?'

	def UnaryOp(self, op, expr):
		opmap = {'*' : 'deref', '-' : 'neg', '!' : 'not', '~' : 'bnot'}
		return opmap[op], self.process(expr)

	def BinaryOp(self, op, left, right):
		return op, self.process(left), self.process(right)

	def Cast(self, to_type, expr):
		return 'cast', self.process(to_type), self.process(expr)

	def ID(self, name):
		return 'register', name

	def Typename(self, type):
		return self.process(type)

	def TypeDecl(self, type):
		return self.process(type)

	def IdentifierType(self, names):
		return ' '.join(names)

	def PtrDecl(self, type):
		return 'ptr', self.process(type)

	def ArrayRef(self, name, subscript):
		return '[]', self.process(name), self.process(subscript)

	def Constant(self, type, value):
		if type == 'int':
			if value.startswith('0x'):
				return int(value[2:], 16)
			elif value.startswith('0b'):
				return int(value[2:], 2)
			elif value.startswith('0'):
				return int(value, 8)
			else:
				return int(value)
		elif type == 'float':
			return float(value)
		else:
			print 'Unknown constant type:', type, `value`
			return '?unkconst?'

	def Assignment(self, op, lvalue, rvalue):
		lvalue = self.process(lvalue)
		rvalue = self.process(rvalue)

		if op != '=':
			rvalue = op[0], lvalue, rvalue

		return '=', lvalue, rvalue

dispatchers = {}

def ddp(name):
	def sub(func):
		dispatchers[name] = func
		return func
	if callable(name):
		dispatchers[name.func_name] = name
		return name
	return sub

class Register(object):
	def __init__(self, name):
		self.name = name

	def __repr__(self):
		return self.name

class TypedValue(object):
	def __init__(self, type, value):
		self.type, self.value = type, value
		while isinstance(self.value, TypedValue):
			self.value = self.value.value

	def __repr__(self):
		return '%s:%r' % (self.type, self.value)

	@property
	def stride(self):
		return int(self.type[1:].rstrip('*')) / 8

	@property
	def pointer(self):
		return '*' in self.type

def bare(value):
	if isinstance(value, TypedValue):
		return value.value
	else:
		return value

def autotype(value):
	if isinstance(value, TypedValue):
		return value
	elif isinstance(value, float):
		return TypedValue('f64', value)
	elif isinstance(value, str):
		return value
	else:
		return TypedValue('i64', value)

class SexpRunner(object):
	def __init__(self, ctu):
		self.ctu = ctu

	def run(self, sexp, rvalue=None):
		if not isinstance(sexp, tuple):
			return autotype(sexp)

		if sexp[0] in dispatchers:
			if rvalue is None:
				return dispatchers[sexp[0]](self, *sexp[1:])
			else:
				return dispatchers[sexp[0]](self, *tuple(list(sexp[1:]) + [rvalue]))
		else:
			print 'Unhandled S-exp:', sexp
			return None

	@ddp('=')
	def assign(self, left, right):
		return self.run(left, self.run(right))

	@ddp('[]')
	def subscript(self, base, sub, ass=None):
		base, sub = self.run(base), self.run(sub)

		addr = bare(base) + bare(sub) * base.stride

		return self.deref(TypedValue(base.type, addr), ass)

	@ddp
	def deref(self, ptr, ass=None):
		ptr = self.run(ptr)

		assert ptr.pointer

		fmtmap = dict(u8='B', i8='b', u16='H', i16='h', u32='I', i32='i', u64='L', i64='l', f32='f', f64='d')
		fmt = fmtmap[ptr.type.rstrip('*')]
		size = struct.calcsize(fmt)

		if ass is None:
			data = self.ctu.readmem(bare(ptr), size)
			return TypedValue(ptr.type[:-1], struct.unpack(fmt, data)[0])
		else:
			self.ctu.writemem(bare(ptr), struct.pack(fmt, bare(ass)))

	@ddp
	def register(self, name, ass=None):
		name = name.upper()
		if name == 'PC':
			if ass is None:
				return TypedValue('u64', self.ctu.pc)
			else:
				self.ctu.pc = bare(ass)
		else:
			typemap = dict(X='u64', W='u32', D='f64', Q='f128')
			assert name[0] in 'XW' # XXX: Add float support
			if ass is None:
				type = typemap[name[0]]
				value = self.ctu.reg(int(name[1:]))
				if type == 'u32':
					value &= 0xFFFFFFFF
				return TypedValue(type, value)
			else:
				self.ctu.reg(int(name[1:]), bare(ass))

	@ddp
	def cast(self, type, value):
		return TypedValue(self.run(type), self.run(value))

	@ddp
	def ptr(self, type):
		return self.run(type) + '*'

	@ddp('+')
	def add(self, a, b):
		a, b = self.run(a), self.run(b)
		if b.pointer and not a.pointer:
			a, b = b, a
		if a.pointer and not b.pointer:
			return TypedValue(a.type, bare(a) + bare(b) * a.stride)
		return TypedValue(a.type, bare(a) + bare(b))

	@ddp('-')
	def sub(self, a, b):
		a, b = self.run(a), self.run(b)
		if b.pointer and not a.pointer:
			return TypedValue(b.type, bare(a) * b.stride - bare(b))
		elif a.pointer and not b.pointer:
			return TypedValue(a.type, bare(a) - bare(b) * a.stride)
		return TypedValue(a.type, bare(a) + bare(b))

	@ddp('*')
	def mul(self, a, b):
		a, b = self.run(a), self.run(b)
		return TypedValue(a.type, bare(a) * bare(b))

	@ddp('/')
	def div(self, a, b):
		a, b = self.run(a), self.run(b)
		return TypedValue(a.type, bare(a) / bare(b))

	@ddp('==')
	def eq(self, a, b):
		a, b = self.run(a), self.run(b)
		return TypedValue('i64', 1 if a.value == b.value else 0)

	@ddp('!=')
	def ne(self, a, b):
		a, b = self.run(a), self.run(b)
		return TypedValue('i64', 1 if a.value != b.value else 0)

	@ddp('>')
	def gt(self, a, b):
		a, b = self.run(a), self.run(b)
		return TypedValue('i64', 1 if a.value > b.value else 0)

	@ddp('>=')
	def ge(self, a, b):
		a, b = self.run(a), self.run(b)
		return TypedValue('i64', 1 if a.value >= b.value else 0)

	@ddp('<')
	def lt(self, a, b):
		a, b = self.run(a), self.run(b)
		return TypedValue('i64', 1 if a.value < b.value else 0)

	@ddp('<=')
	def le(self, a, b):
		a, b = self.run(a), self.run(b)
		return TypedValue('i64', 1 if a.value <= b.value else 0)

	@ddp('&&')
	def booland(self, a, b):
		a, b = self.run(a), self.run(b)
		return TypedValue('i64', 1 if bool(a.value) and bool(b.value) else 0)

	@ddp('||')
	def boolor(self, a, b):
		a, b = self.run(a), self.run(b)
		return TypedValue('i64', 1 if bool(a.value) or bool(b.value) else 0)

def compile(code):
	parser = CParser()

	stypes = 'u8 i8 u16 i16 u32 i32 u64 i64 f32 f64 f128'
	code = 'void runner() { ' + code + ' ; }'
	for type in stypes.split(' '):
		code = 'typedef void %s; %s' % (type, code)

	ast = parser.parse(code)
	found = None
	for _, child in ast.children():
		if isinstance(child, FuncDef):
			found = child
			break

	assert found is not None
	assert len(found.body.children()) == 1

	ast = found.body.children()[0][1]
	sexp = AstTranslator().process(ast)

	def run(ctu):
		return bare(SexpRunner(ctu).run(sexp))
	return run

def ceval(code, ctu):
	return compile(code)(ctu)
