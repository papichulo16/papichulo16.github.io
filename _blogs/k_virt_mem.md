---
layout: blog
title: "Virtual Memory and Slab Allocator"
date: 2025-11-17
tags: [kernel]
description: "Page table and virtual memory chronicles!!! Also personal kmalloc() implementation"
---

## Intro
Alright this was another month of being busy later. Also this was indeed the scariest and most daunting topic yet, since I had NO IDEA about anything relating to page tables, virtual memory, TLBs, etc. Even though I was not able to write code on here very often, I did spend a decent amount of time on my phone researching about this every now and then. 

Now looking back, this is not so bad after all and I was being a scaredy cat.

## Virtual Memory
The way virtual memory works is by the OS setting up a page table structure and then the MMU in the CPU doing a page walk after every memory access to find the physical memory address. Obviously this is lengthy which is why the TLB exists. I am not going to explain this in grave detail since there are a lot of resources out there but I will make sure to at least show I understand.

So the way that the MMU does the page walk is by reading the physical memory address in the `CR3` register and using that as the L4 page table, then it will use the higher 9 bits of the 48 bit virtual address to index into that table and then use the next entry as the L3 table. Then it will use the next 9 bits and so on until reaching L1 which will be the actual physical address accessed, and the last 12 bits will offset into that page. 

Also keep in mind (not knowing this wasted like 2 hours of my time debugging) that if the most significant bit of the 48 bit addr is set, so will all other higher order bits in the 64 bit address. This is because they want to add forward compatibility whenever they increase memory addressing or something. 

### Changing the virtual kernel base address
First step to virtual memory was not creating a `vmmap()` implementation yet, but rather just messing around in the `boot.asm` file to understand how this works as well as to map the kernel vmmap in address `0xfffffff800000000` or something like that. I basically just made it so that the last index of the L4 table is what is being used rather than the first.

For that I also had to change the linker so that it uses the virtual memory addresses I want. Also in boot mode I had to create a trampoline that will switch to 64 bit mode and THEN call `long_mode_start`. But then after that I had my kernel using virtual addresses rather than physical.

### Creating the page allocator and vmmap
The page allocator was really easy, honestly easier than my temp page allocator implementation. All I had to do was return a pointer to an unused page and then set it to being used somewhere else. The remainder would be done by the vmmap.

The way I made my vmmap function is by just recursively walking through a set path in the page tables until it finds a free L1 entry, if it doesn't, then it will create a new L1, L2, or L3 to then allocate an L1 page table and then create a new entry. 

As of now physical memory still exists since I haven't created a way to translate the read physical page table entry address and then find its virtual memory to modify. My plan is to just do some AVL tree or something to have to translate but as of now I just want to get THIS working and then later I will do it. 

This is the code:
```

uint8_t* kern_get_next_free_l1_addr(uint8_t* p){
    
    // they wont allocate if the index already exists
    alloc_l3_table((uint64_t) p);
    alloc_l2_table((uint64_t) p);
    alloc_l1_table((uint64_t) p);
    
    uint64_t* l1 = get_l1_table((uint64_t) p);
    
    for (; L1_INDEX((uint64_t) p) < 512; p += (1 << 12)) {
        if (get_l1_idx((uint64_t) p) == 0)
            return p;
    }

    // try again with a new l1 table index
    return kern_get_next_free_l1_addr(p + (1 << 12));
}

uint8_t* mk_vmmap_l1(uint8_t flags) {
    uint8_t* p = kern_get_next_free_l1_addr((uint8_t *) KERNEL_DATA_VMA);
    
    if (!map_l1((uint64_t) p))
        return p;
    
    return 0;
}
```

Obviously I created the respective vmunmap function.

## Slab allocator
The way that I structured my slab allocator is very similar to the way the Linux Kernel does it. Since I have worked with it a decent amount when writing Linux Kernel exploits during CTFs, I was actually was actually able to this in a plane with no interwebz in an hour or so. 

Since for now I can only create one page and I don't have a buddy allocator, I can only create objects of up to 4K divided by 2 because the objects still need metadata inside them, so 2K objects max. The way it is structured is I have cache nodes that have an array of buckets for different sizes and then they will hold linked lists with the slabs for that specific size, and each slab will hold as many objects as possible of that size. 

It is a very simple implementation that you can discern from these structure definitions alone:
```
// 8, 16, 32, 64, 128, 256, 512, 1024, 2048
#define NUM_BUCKETS 9

struct mk_slab_t {
    uint8_t id;
    uint32_t size;
    uint32_t free_count;
    uint32_t max;

    struct mk_slab_t* next;
    void* freelist_head;
};

struct mk_cache_node_t {
    struct mk_slab_t* buckets[NUM_BUCKETS];
};
```

Anyways now that I have dynamic allocation in the kernel... the world is my oyster!!

