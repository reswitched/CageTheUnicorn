#!/usr/bin/python
from sys import argv

def get_header_len(syms):
    for i in xrange(len(syms)):
        if "Publics by Value" in syms[i]:
			return i+1

def get_header(symsfile):
    with open(symsfile, "rb") as f: mainsyms = f.read().split("\n")
    return "\n".join(mainsyms[:get_header_len(mainsyms)]) + "\n\n"

def parse_syms(symsfile):
	with open(symsfile, "rb") as f:
		syms = f.read().split("\n")
	return filter(None, syms[get_header_len(syms):])

def dedupe_syms(syms):
	i = 0
	while i < len(syms)-1:
		if syms[i].split(" ")[1] == syms[i+1].split(" ")[1]:
			print syms[i], "  |  ", syms[i+1]
			idx = 1 if (raw_input() == "") else 0
			print "==>", syms[i+(idx^1)], "\n------------------\n"
			syms = syms[:idx] + syms[idx+1:]
		i += 1
	return syms

assert len(argv) >= 3
res = dedupe_syms(sorted(list(set(parse_syms(argv[1]))|set(parse_syms(argv[2])))))
with open("merged.map", "wb") as f: f.write(get_header(argv[1]) + "\n".join(res))

