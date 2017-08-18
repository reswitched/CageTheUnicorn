Cage The Unicorn
================

CTU is a debugging emulator for the Nintendo Switch.  That means that it **does not and will not** play games.  In fact, it has no support for graphics, sound, input, or any kind of even remotely performant processing.  This is all by design.

With CTU, you can run entire Switch sysmodules or applications, trace and debug the code, test exploits, fuzz, and more.

Installation
============

Install [Unicorn from git](https://github.com/unicorn-engine/unicorn) and make sure that you have Python 2.7.x installed.

Create a directory called `SwitchFS/archives` and copy all the system archive `.bin` files into that, if a sysmodule needs them to run.

Usage
=====

The simplest case is running a sysmodule.  To set this up, run:

	./addtitle.sh target source

Where `target` is the name of the directory (we generally recommend you include the sysmodule name and system version, e.g. `pctl30`) to create for this, and `source` is the directory containing the binaries.

The target directory will be created along with a `run.py` and `load.yaml` file, and the source binaries will be copied in.  To run it, simply run `python target/run.py`

You can see an empty skeleton in the `skeletonSample` directory.

`load.yaml`
===========

The `load.yaml` file defines what all should be loaded into a process.  It is a dictionary with the following keys allowable:

- `nxo`/`nro`/`nso` -- Single filename (string) or array of filenames to load.  Don't include a file extension.
- `mod` -- Single filename (string) to load.
- `bundle` -- Filename of a memory bundle to load.  If `filename.gz` exists and `filename` does not, CTU will automatically decompress the file on first load.
- `maps` -- Dictionary of address class -> map files.
	- Each entry should be the `Titlecase` version of the binary the map is for, e.g. `main` becomes `Main`.  The value of the entry takes the form `[0xf00b, "something.map"]`, where the address is the loadbase of the map.

API
===

This is the core API off the `CTU` object, usable from `run.py`.

- `call(pc, [X0, [X1, ...]], _start=False)` -- Call a given native function on a newly created thread.  Any number of arguments can be passed; return value is X0 on exit.  If `_start` is True, X0 is 0 and X1 is the handle of the newly created thread.
- `debugbreak()` -- Breaks into debugger.
- `malloc(size)` -- Allocates `size` bytes inside the guest address space.
- `free(addr)` -- No-op!
- `reg(i, [val])` -- Reads or assigns a register by number or name (`X0`-`X31`, `LR`, and `SP`).
- `pc` -- Property allowing you to read/write the PC value for the current thread.
- `dumpregs()` -- Display all registers.
- `dumpmem(addr, size, check=False)` -- Hexdump a block of memory. If `check` is True and memcheck is enabled, you'll be warned for unmapped memory reads.
- `readmem(addr, size)` and `writemem(addr, value)` -- Reads or writes memory as a byte string.
- `read8/16/32/64(addr)` and `write8/16/32/64(addr, value)` -- Reads or writes memory as an unsigned integer of a given size.
- `readS8/16/32/64(addr)` -- Reads memory as a signed integer of a given size.
- `readstring(addr)` -- Reads a string until null terminator or unmapped memory.
- `newHandle(obj)` -- Assign a new handle to `obj` and returns that handle ID.
- `closeHandle(handle)` -- Closes a handle.
- `map(base, size)` -- Maps a block of memory.  If not page aligned, that will happen automatically.  Memory will be unmapped if execution restarts.
- `unmap(base, size)` -- Unmaps a block of memory.
- `getmap(addr)` -- Returns the tuple `base, size` for a given address, or `-1, -1` if that memory is unmapped.
- `memregions()` -- Returns a generator providing tuples of `(begin, end, perms)` for all mapped and unmapped regions; unmapped regions have `perms == -1`.
- `hookinsn(insn)` -- Decorator allowing you to hook a given instruction value (as an integer).  Decorated function should have arguments `ctu, addr` where addr is the address of the instruction.  Hook happens before execution.
- `hookfetch(addr)` -- Decorator allowing you to hook a given instruction address prior to execution.  Decorated function takes no arguments.
- `hookread(addr)` and `hookwrite(addr)` -- Decorators allowing you to hook memory read/writes to an address.  Decorator should have arguments `ctu, size` or `ctu, addr, size, value` respectively.  Read hooks may return a replacement value.  If writehook returns non-`None`/`False`, it is deleted.
- `replaceFunction(addr)` -- Decorator allowing you to replace a function in native code at the given address.  The decorated function gets `ctu` as its first argument, but may take any number of arguments beyond that (mapped from X0...X30 automatically) and return any number of values (mapped to X0...X30 automatically).  The original function will not execute.

IPC Client
==========

Sysmodules expose their IPC interface over the network.  The details of that wire protocol are documented in `wireprotocol.txt`, but a Python client is included.

Example usage is in `skeletonSample/client.py`.  You create a `Client` object and connect to a CTU instance, then create and send `IPCMessage`s back and forth.

Debugger Reference
==================

The debugger in CTU is roughly based on gdb but has some key differences that will really irritate GDB fans.

- `exit` -- Exit.
- `s/start` -- Start or restart execution.
- `t/trace (i/instruction | b/block | f/function | m/memory)` -- Toggles tracing.
- `mc/memcheck` -- Toggles memory access violation tracking.
- `b/break [name]` -- Without `name`, list breakpoints; otherwise toggle breakpoint for symbol name or address.
- `bt` -- Print the call stack.
- `sym <name>` -- Print the address of a given symbol.
- `c/continue` -- Continues execution.
- `n/next` -- Single step.
- `r/reg/regs [reg [value]]`
	- No parameters: Display all registers.
	- Reg parameter: Display one register.
	- Reg and value: Assign a value (always hex, or a symbol name) to a register.
- `x/exec <code>` -- Evaluates a given line of C.
- `dump <address> [size=0x100]` -- Dumps `size` bytes of memory at an address.  If address takes the form `*register` (e.g. `*X1`) then the value of that register will be used.
- `save <address> <size> <fn>` -- Writes `size` bytes of memory to a file.  If address or size take the form `*register` (e.g. `*X1`) then the value of that register will be used.
- `ad` -- Toggle address display specialization
- `w/watch [expression]` -- Breaks when expression evaluates to true.  Without an expression, list existing watchpoints.
- `mr/memregions` -- Display mapped memory regions