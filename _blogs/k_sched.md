---
layout: blog
title: "Tasks and Scheduler"
date: 2025-10-21
tags: [kernel]
description: "Created a round robin scheduler for multiple tasks"
---

## Initial
Alright so I have been very busy this past month with midterms and work going like crazy, but we are so back. Now that I have interrupts working I can program the Programmable Interval Timer (PIT) to fire timer interrupts so that I can have a round robin scheduler! Lets gooo multitasking!!!!

First I set up a temporary page allocator with a large buffer in global memory because I am going to have to learn about that and page tables and such... so I am pushing it off until after this. It is nothing crazy, just got something working loosely based on the fact that I have good understanding of how the GLIBC heap and the Linux Kernel slabs work thanks to my exploitation background.

Alright cool lets get started

## Scheduler
Before I get started, I want to say that everything named in my code is under the name of "thread". I will be vulnerable and say I did not understand (or honestly cared about) the difference between "task" and "thread" until not too long ago that I looked it up. 

Since I am only using one CPU core for the time being until I decide to implement Symmetric Multi-Processing (SMP), the implementation I made is technically using tasks and not threads... and for that I will tell you to respectfully fuck off!!!

### Context save + restore
So obviously the most important part of a scheduler is the fact that it must be able to save the whole state of a task at the time of an interrupt before switching to a new task, and then restoring it once it is that task's turn again. This is the struct I am using for ctx save and restore:
```
struct regs_context {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rsi, rdi, rbp, rdx, rcx, rbx, rax;
    uint64_t rip, cs, rflags, rsp, ss;
};
```

So for that I want to tell you something very silly, at first I MANUALLY calculated all offsets in the stack and wrote it to the other MANUALLY calculated offset in the `regs_context` struct HAHAHA:
```
void mk_thread_ctx_save(struct regs_context* ctx) {

    asm volatile (
        ".intel_syntax noprefix\n\t"
        "push rax\n\t"  

        "mov rax, qword ptr [rsp + 0xa0]\n\t"  // r15
        "mov qword ptr [rdi + 0x00], rax\n\t"

        "mov rax, qword ptr [rsp + 0x98]\n\t"  // r14
        "mov qword ptr [rdi + 0x08], rax\n\t"

        "mov rax, qword ptr [rsp + 0x90]\n\t"  // r13
        "mov qword ptr [rdi + 0x10], rax\n\t"

	... MORE OF THIS ...

        "mov rax, qword ptr [rsp + 0xb8]\n\t"  // rflags
        "mov qword ptr [rdi + 0x88], rax\n\t"

        "pop rax\n\t"  // rax
        "mov qword ptr [rdi + 0x70], rax\n\t"

       ".att_syntax prefix\n\t"
        :
        : "D"(ctx)
        : "rax", "memory"
    );
}
```

Not only is this horribly disgusting and awful to debug, but also it made it so that if I EVER pushed anything to the stack inside of the timer handler function I would have to also change those offsets!!! It wasn't until a bit later that I got the epiphany to move the value of RSP into RDI before calling the timer handler function in C and then using that as a stack pointer parameter for the state before the function call!!! Here is the same function but now nicer:
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

So much nicer!!!

### Scheduler
I don't want this blog to be crazy long so I will only go over the important things, things like thread create, thread kill, etc are self explanatory so I will disregard. I will say in thread create I use the temporary page allocator I talked about earlier to allocate a new stack for each task.

In here, I will talk about two main important functions: the timer ISR and the context switch function. Here is the thread object structure:
```
struct mk_thread_obj {
    enum ThreadState state;
    struct regs_context regs;

    uint8_t started;
    uint32_t time_slice;

    void* entry;

    uint8_t* stack_base;
};
```

All the timer ISR function does is time slicing, initializing tasks that havent ran yet, and also switch context in between tasks if needed. This is the code:
```
void mk_timer_int_handler(uint64_t* stack) {
    
    mk_working_thread = mk_get_working_thread();
    
    if (mk_working_thread->time_slice > 0) {
        mk_working_thread->time_slice -= 1;

        mk_pic_send_eoi(0);

        return;
    }
        
    if (!mk_working_thread->started) {
        mk_pic_send_eoi(0);
        mk_working_thread->started = 1;

        mk_thread_ctx_restore_from_stack(&mk_working_thread->regs, stack);

        return;
    }
    
    mk_thread_ctx_save_from_stack(&mk_working_thread->regs, stack);

    mk_pic_send_eoi(0);

    if (!mk_thread_ctx_switch()) {
        mk_working_thread = mk_get_working_thread();

        mk_thread_ctx_restore_from_stack(&mk_working_thread->regs, stack);
    }
}
```

The context switch function will find the next ready thread in the ready queue, which is currently a set array in global memory, but once I have a slab allocator set up I will refactor all of this to use a linked list structure so there is unlimited tasks. 

Outside of that it works!! A lot of debugging but that is part of the process.

