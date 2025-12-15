---
layout: blog
title: "Introduction and Setup"
date: 2025-09-02
tags: [kernel]
description: "Backstory, build environment, and booting 64 bit mode into kernel_main() in C"
---

## Intro
Alright Luis from the future (2025-12-14) wants to give a backstory as to why I started doing this, and what my motivation is going forward. So at the time of starting this project I was (and still am) a second year Computer Science student as well as working as a part time Junior Vulnerability Researcher (around 24 hours a week). 

Over the summer at work I volunteered myself to be put on a full-system emulation task because it looked challenging and fun, not realizing how little I knew about how OS's actually worked. Because of this I had to really work hard to learn a lot of new hardware and OS concepts to even get the RTOS that I was emulating in QEMU started. 

Finding out that I had such a gap of knowledge made me really look forward to my OS class in university, but when I saw the syllabus, I realized that the class was more about UNIX programming than actual OS internals. So then I started this.

Since I had a job plus I was a full time college student, I didn't have much time to work on this outside of short couple hour bursts every few months/weeks. But as time has gone on I have really fallen in love working on this, so enjoy the progress and hopefully I continue working on this as years go on. 

Anyways that was the very lame story, this is more for myself to look back on (as well as these blogs tbh) so don't dog on me. Anyways now to the cool stuff!!

## Setting up the environment
### Finding a starting point
So the plan for this project is for it to run on QEMU so I can work on this wherever I want, in comparison if I were to put this on hardware. Since I have already worked on something relating to RTOSs in ARM, I have decided to do this in `x86_64` to have both CISC and RISC experience. Yippeee. 

Honestly, getting started is pretty daunting since I do not know everything that I need so decided I was going to take a mulligan and watch [this youtube video](https://www.youtube.com/watch?v=FkrpUaGThTQ). The good thing is that the guy that made this only has two videos, so after this I will be officially on my own.

PLUS I am not a slacker that copy pastes code, so I will explain every bit of code this guy wrote on this video to show that.

### Bootloader and linker script
So for the bootloader, we are going to go with `grub`. This means that I am putting a file in `targets/x86_64/iso/boot/grub/` called `grub.cfg` that will specify the following:
```
set timeout=0
set default=0

menuentry "idk the kernel name yet" {
  multiboot2 /boot/kernel.bin
  boot
}
```

This basically states that grub is not going to wait at all in the booting stage (timeout=0) and then that it will load the file in `targets/x86_64/iso/boot/kernel.bin`. 

As for the linker script, this is fairly straight forward as well since all I am doing is stating that the multiboot header and then my code will start in `0x1000000` since that is what is mapped out in the QEMU machine:
```
ENTRY(start)

SECTIONS
{
  /* the operating system starts one megabyte in */
  . = 0x1000000;

  .boot :
  {
    KEEP(*(.multiboot_header))
  }

  .text :
  {
    *(.text)
  }
}
```

This can be found in this MMIO table (I will be continually referencing this as time goes on):
```
0x00000000 – 0x0009FFFF : Conventional RAM (usable)
0x000A0000 – 0x000BFFFF : Video memory / VGA text mode
0x000C0000 – 0x000FFFFF : BIOS ROM / system ROM
0x00100000 – 0x07FFFFFF : Extended RAM (default 128 MB, configurable with -m)
0x08000000 – 0x3FFFFFFF : Extended RAM continuation (depends on -m size)
0x40000000 – 0xBFFFFFFF : PCI hole / MMIO for PCI devices
0xC0000000 – 0xCFFFFFFF : PCI device MMIO regions
0xD0000000 – 0xDFFFFFFF : Optional MMIO / device regions
0xE0000000 – 0xEFFFFFFF : VGA MMIO / other device regions
0xF0000000 – 0xFFFFFFFF : BIOS / reserved legacy system space
```

### Docker build environment and Makefile
So the guy in the video has an ARM machine so he needs to use a docker container to build things for intel, which is not my problem. Nonetheless I liked the idea of having a Dockerfile for easing the setup and build environment so I made my own. It is basic and can be found in `build/Dockerfile`.

This it so that way when starting on any new machine all you have to do is build the docker environemnt to get all dependencies, mount the current directory into the image, and then run the Makefile from there. Super ez.

Now for the Makefile, I got lazy and copied and pasted what he wrote. I know how to do this I just didnt really want to do it and was glad someone did it for me hahahhaa. 

All it does is it compiles all of the files in `src/impl/kernel/` and uses the files in `src/intf` as include files. Also it will assemble all of the `src/impl/x86_64` files when `build-x86_64` is used. Then it will link all of the object files into `kernel.bin`

From here we are ready to write our boot code in the `x86_64` directory and get started.

## booting
### multiboot header
First we need to set up the multiboot header specified in the linker file. This is fairly straightforward, just write the following as 32 bit values:
 - a multiboot2 magic number of `0xe85250d6`
 - NULL to specify protected mode
 - header length
 - a checksum calculated like so: `0x100000000 - (0xe85250d6 + (_end_header - _start_header))`
 - 5x NULL values for the end tag

Now we are ready to work on boot.asm

### boot.asm
Alright to boot into 64 bit long mode, we are going to need to make these checks are supported:
 - multiboot is good
 - cpuid flag
 - long mode

Then from there we need to set up a very basic page table layout, which I have no idea how it works, but I will learn when I get to that part for sure. 

Also I need to set up a Global Descriptor Table. I had never heard of this but I looked it up, and it has to do with the segment registers. This seems like it is just a weird feature that is not needed anymore honestly, I have worked with segment registers in my Microcomputer Systems class when we worked with 16-bit intel on the 8086 Microprocessor. It seems like it is just an evolution thing, I can explain it right here:
 - In 16 bit MPs, there were 20 address lines but a 16 line data bus and registers. So to be able to control and use those higher 4 address lines, they would grab whatever segment register you are using for the memory access (Stack, Data, Code, etc) and then multiply it by 0x10 and then add it to the current pointer used. 
 - Then when 32 bit processors came around, the GDT came. This time around it turned the segment registers to ignify an offset into that table which would then hold info about the region of memory accessed as well as its offset.
 - Now in 64 bit, the GDT and CS registers are really only used to signify the protections and flags for whatever segment is being used in the same way as 32 bit.

This took a second to understand because I was like "... huh?? thats it???", but I guess that's neat!

Anyways I did all of this, filling up all L2 page table entries with an address, setting up a stack, setting up the code segment GDT entry, and then loading all of the initialized segments with their respective registers that needed to be used. 

From there I called `long_mode_start` in `main64.asm` which would clear all segment registers and then call `kernel_main()`. BOOM!!!
