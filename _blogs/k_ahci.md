---
layout: blog
title: "Persistent Storage!!"
date: 2026-01-14
tags: [kernel]
description: "PCI HAL and AHCI Driver"
---

## We are fully virtual now
Alright so for the time being I still had the physical memory mappings in the virtual page layout, so both the last index and the first index of my L4 page table pointed to the same thing. This was because when I wanted to modify a page table, I would just access its "physical memory" instead of finding its virtual address when I crawl through the page tables. 

This obviously ruins the whole purpose of virtual memory, plus it is unmaintainable. So I fixed that.

The way I fixed it was just that I mapped out another region an index above the current L3 entry and made it be the page tables entries region, and then when I allocate a new page as a page table, I will write it somewhere in that region. Then when walking through the page tables I would have to read a page table entry, get its virtual address, and then walk through the next one again. I then removed the index 0 copy from the L4 and L3 page tables.

I also am going to be working with MMIO, so I need to map out its memory region. 
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

As you can see here, addresses `0x40000000-0xEFFFFFFF` are MMIO regions, so I wanted to leave a virtual memory address for it all. Now in startup I have this virtual page layout:
```
CR3 ->  [511] L3    -> [1:3] MMIO
                    -> [509] Tables map
                    -> [510:511] Kernel addr map
```

## Working with PCI
[osdev pci resource](https://wiki.osdev.org/PCI)

Alright so now I want to get persistent storage, that is the main goal for todays blog. Now before we start writing disk drivers, we need to find the device! 

The machine I chose has a device that has SATA drives, which communicate with a device called AHCI, which is hooked up to a PCI bus. So we gotta start from there. 

Now there is a lot of resources out there on how it works, but the main idea is this:
```
 - There is a PCI controller
 - The PCI controller has 8 PCI buses
 - Each bus has 32 devices
 - Each device has 8 functions
```

The way you speak to it is by writing to the port `0xCF8` and reading from port `0xCFC`.

### PCI Enumeration
So now that we know how PCI works, we need to figure out what vendor and what device ID we are looking for. We do it by looking at these sites:
[vendor IDs](https://pcisig.com/membership/member-companies)
[device IDs](https://devicehunt.com/view/type/pci/vendor/8086)

Now that you have the device ID and vendor ID, you can enumerate PCI to find the correct device. From there it becomes a device specific issue.

## AHCI
### Device initialazion
So when I first started I wanted to do this on my own without looking at anything outside of the datasheet. I initialized the device, and then got impatient and started looking at online resources. But for now here is the [datasheet](https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/serial-ata-ahci-spec-rev1-3-1.pdf)

So first in the initialization process I would get the devices memory mapped IO address. Which was located in register ABAR5 in offset 24-27 in the PCI port. From there we could interact with the device.

So now that we have the MMIO address, we need to initialize any AHCI port available. AHCI itself has availability for 32 ports, but the device that I am using only has access for 6 ports. This can be read in the PI (ports implemented) register in the device. 

From here we enumerate the AHCI ports, checking to see if the respective PI bit is set, and then checking to see if it is on and active by checking the SSTS register. 

From there I checked the SIG register which states the connected device's signature. In our case we are looking for `0x101` which states that it is a SATA drive. 

Then, I set the FRE and ST bits in the CMD register and got the device initialized.

After this, I got tired from looking at the data sheet. Not because I cant do it, but because this takes too long and I am doing this as a hobby.

### Reading and writing from disk
From here on out, I am reading off of the [osdev ahci resource](https://wiki.osdev.org/AHCI). 

So now to read and write from the device, you need to initialize the CLB, CTB, and FISB in the port. CLB (command list buffer) holds multiple CTBs (command table buffers) which will be used to communicate with the device. Then the FISB (FIS buffer) is then used to communicate between host and device, doing DMA for you without any crazy overhead.

Outside of that it becomes a lot of device specific register stuff that I dont wanna explain, but I finally got it working. 

I actually had an issue where the device was returning back that the transfer was fine, but yet I would not get the data in my read buffer. This happened because I did not stop the device before configuring it at the beginning... but after that everything was fine!! 

