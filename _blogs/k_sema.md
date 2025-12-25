---
layout: blog
title: "Redoing Scheduler & Bug City"
date: 2025-12-23
tags: [kernel]
description: "Rewriting scheduler with dynamic memory, multitask sync, creating debugging tools with GDB, and fixing wonky bugs"
---

## Redoing the scheduler
So now that I have a dynamic allocator (or so I thought, it was actually broken as seen later LOL) I am going to redo all of the scheduler, make it cleaner code, and create semaphores so I can have syncronyzation. 

This part was ezpz, all I did was have a ready queue that I would cycle over and then if a semaphore was hit, it would go to that queue and get out of the ready queue if the num was below 0. I will say, the timer ISR was well refactored and now it is SO NICE to look at (it started looking shitty the more I kept adding to it, as it usually goes):
```
void _mk_timer_int_handler(uint64_t* stack) {

  mk_working_thread = mk_get_working_thread();

  if (mk_working_thread->time_slice > 0) {

    mk_working_thread->time_slice--;
    return;
  }

  if (!mk_working_thread->started) {

    t_init(stack);
    return;
  }

  if (!t_dis_by_state(stack)) {
      mk_thread_ctx_switch();

      mk_working_thread = mk_get_working_thread();
      t_res_state(stack);
  }
}
```

Outside of that the issues came later which I will talk about, I spent a decent amount of time staring at GDB lol. Luckily pwndbg makes it a lot nicer.

I dont usually talk about bugs I come across because there are always bugs, but I got some good things out of these that I want to note.

## Bug one
So to recap I am running this on `x86_64`, now with this in mind I want to give you a snippet of code and see if you  can spot the bug. Keep in mind ctx is an object that is used for saving and restoring context, also the stack variable is a pointer to the stack right before calling the handler function:
```
void mk_thread_ctx_save_from_stack(struct regs_context* ctx, uint64_t* stack) {
    ctx->rax = stack[0];
    ctx->rbx = stack[1];
    ctx->rcx = stack[2];
    ctx->rdx = stack[3];
    ctx->rbp = stack[4];
    ctx->rdi = stack[5];
    ctx->rsi = stack[6];
    ctx->r8  = stack[7];
    ctx->r9  = stack[8];
    ctx->r10 = stack[9];
    ctx->r11 = stack[10];
    ctx->r12 = stack[11];
    ctx->r13 = stack[12];
    ctx->r14 = stack[13];
    ctx->r15 = stack[14];
    
    // Interrupt frame
    ctx->rip    = stack[15];
    ctx->cs     = stack[16];
    ctx->rflags = stack[17];

    // CS & 3 gives us the RPL (requested privilege level)
    if ((ctx->cs & 0x3) != 0) {
        ctx->rsp = stack[18];
        ctx->ss  = stack[19];
    } else {
        ctx->rsp = (uint64_t)(&stack[15]);
        
        uint64_t current_ss;
        asm volatile("mov %%ss, %0" : "=r"(current_ss));
        ctx->ss = current_ss;
    }
}
```

Got it? The problem was that after every timer interrupt the stack seemed to not go back to what it was supposed to be (offset -0x30 bytes). I have not implemented user space at all on this and the CPL is always 0, or so I thought. The context save handler checks the lower two bits of the CS register that was pushed into the stack by the timer interrupt and then handles RSP and SS accordingly if one of the two lower CS bits are set. 

The problem is that never happens, and to my understanding it shouldnt. But from debugging for some reason I saw that the interrupt and IRETQ are goning to both push and pop all 5 interrupt registers into the stack as if it were a user interrupt. Is there somethign I dont understand with the PIC or PIT? because when I made it handle RSP and SS no matter what, my kernel stopped having issues.

This was quite a bit of GDBing to figure out, and after doing some research, the thing is that this is designed for 32 bit systems!!! 64 bit systems push all 5 `RIP` `CS` `RFLAGS` `RSP` `SS` on interrupts no matter if it is coming from privilaged space or not, while on 32 bit systems it will only push the first three if it is coming from kernel space and all 5 if its coming from user. here is the fixed code:
```
void mk_thread_ctx_save_from_stack(struct regs_context* ctx, uint64_t* stack) {
    ctx->rax = stack[0];
    ctx->rbx = stack[1];
    ctx->rcx = stack[2];
    ctx->rdx = stack[3];
    ctx->rbp = stack[4];
    ctx->rdi = stack[5];
    ctx->rsi = stack[6];
    ctx->r8  = stack[7];
    ctx->r9  = stack[8];
    ctx->r10 = stack[9];
    ctx->r11 = stack[10];
    ctx->r12 = stack[11];
    ctx->r13 = stack[12];
    ctx->r14 = stack[13];
    ctx->r15 = stack[14];
    
    ctx->rip    = stack[15];
    ctx->cs     = stack[16];
    ctx->rflags = stack[17];
    ctx->rsp = stack[18];
    ctx->ss  = stack[19];
}
```

## Bug two

This one is not much about the bug, but just the fact that it was in my slab allocator because it motivated me to make a GDB plugin and it came out to be really nice!!! It has colors and everything. take a peek!
```
pwndbg> slabs
================================================================================
SLAB ALLOCATOR STATE
================================================================================

[Bucket 2] Size: 32 bytes
--------------------------------------------------------------------------------
  Slab #0 @ 0xffffffff80208000
    ID: 2
    Size: 32 bytes
    Usage: 1/127 (0.8%)
    Free: 126
    Freelist: 0xffffffff80208040

  Total slabs in bucket: 1

[Bucket 3] Size: 64 bytes
--------------------------------------------------------------------------------
  Slab #0 @ 0xffffffff80200000
    ID: 3
    Size: 64 bytes
    Usage: 2/63 (3.2%)
    Free: 61
    Freelist: 0xffffffff802000a0

  Slab #1 @ 0x2001003
    ID: 0
    Size: 0 bytes
    Usage: 0/0 (0.0%)
    Free: 0
    Freelist: 0x0

  Total slabs in bucket: 2

[Bucket 5] Size: 256 bytes
--------------------------------------------------------------------------------
  Slab #0 @ 0xffffffff80202000
    ID: 5
    Size: 256 bytes
    Usage: 1/15 (6.7%)
    Free: 14
    Freelist: 0xffffffff80202120

  Total slabs in bucket: 1
================================================================================
Total slabs: 4
================================================================================
pwndbg> vslabs
Undefined command: "vslabs".  Try "help".
pwndbg> vslab 0xffffffff80200000

================================================================================
SLAB INSPECTION @ 0xffffffff80200000
================================================================================
ID:           3
Object Size:  64 bytes
Max Objects:  63
Used:         2 (3.2%)
Free:         61
Next Slab:    0x0000000002001003
Freelist:     0xffffffff802000a0

================================================================================
MEMORY DUMP (Page @ 0xffffffff80200000)
================================================================================
0xffffffff80200000  0000004002000003 0000003f0000003d  ....@...=...?...
0xffffffff80200010  0000000002001003 ffffffff802000a0  .......... .....
0xffffffff80200020  00000000010093f8 00000000010093ea  ................
0xffffffff80200030  ffffffff8100ab50 0000000002002003  P........ ......
0xffffffff80200040  0000000002003003 0000000000000000  .0..............
0xffffffff80200050  0000000000000000 0000000000000000  ................
0xffffffff80200060  000000000100940a 00000000010093fd  ................
0xffffffff80200070  ffffffff8100a750 0000000000000001  P...............
0xffffffff80200080  ffffffff80200020 0000000000000000   . .............
0xffffffff80200090  0000000000000000 0000000000000000  ................
0xffffffff802000a0  ffffffff802000e0 0000000000000000  .. .............  <=== isfree
0xffffffff802000b0  0000000000000000 0000000000000000  ................
0xffffffff802000c0  0000000000000000 0000000000000000  ................
0xffffffff802000d0  0000000000000000 0000000000000000  ................
0xffffffff802000e0  ffffffff80200120 0000000000000000   . .............  <=== isfree
0xffffffff802000f0  0000000000000000 0000000000000000  ................
0xffffffff80200100  0000000000000000 0000000000000000  ................
0xffffffff80200110  0000000000000000 0000000000000000  ................
0xffffffff80200120  ffffffff80200160 0000000000000000  `. .............  <=== isfree
0xffffffff80200130  0000000000000000 0000000000000000  ................
0xffffffff80200140  0000000000000000 0000000000000000  ................
0xffffffff80200150  0000000000000000 0000000000000000  ................
... more ...
pwndbg> pagewalk 0xffffffff80200000

================================================================================
PAGE TABLE WALK FOR VIRTUAL ADDRESS: 0xffffffff80200000
================================================================================
CR3 Register: 0x0000000001001000
PML4 Base:    0x0000000001001000
================================================================================

Virtual Address Breakdown:
  PML4 Index: 511 (0x1ff)
  PDPT Index: 510 (0x1fe)
  PD Index:   1 (0x001)
  PT Index:   0 (0x000)
  Offset:     0 (0x000)

================================================================================

[1] PML4 Entry
    Address: 0x0000000001001ff8
    Value:   0x0000000001002023
    Flags: P | RW | A
    PDPT Base: 0x0000000001002000

[2] PDPT Entry
    Address: 0x0000000001002ff0
    Value:   0x0000000001003023
    Flags: P | RW | A
    PD Base: 0x0000000001003000

[3] PD Entry
    Address: 0x0000000001003008
    Value:   0x00000000002000e3
    Flags: P | RW | A | D | PS
    [2MB HUGE PAGE]

Final Physical Address: 0x0000000000200000
================================================================================
```

The colors probably wont show on md but whatever!!! 

Anyways, if you read the debug logs, I acutally left the bug as part of these logs to see if you can find it. Do you notice anything odd?

If you didnt that is fine, look at Bucket 3 of the `slabs` command, that does not look like a valid address because it isnt. The problem is that my virtual memory mapper was not taking into account HUGE page flags when determining if a page table entry existed... that is it. So it would treat valid memory that was being used as a page table hehe. 

