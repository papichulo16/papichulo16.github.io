---
layout: blog
title: "Poking Holes in the AVF"
date: 2026-10-14
tags: [pkvmi]
description: "Developing the initial VMI from hypervisor space"
---

### Preface 

Before I get started talking about what I have been doing, I want to talk about the goal for this project so we are on the same boat. In the end, I would like to have a pVM have the ko that performs the hypercalls to my own pKVM hypervisor module, then that module will have introspecion on all pVM's and the host kernel, and lastly I would like instrumentation like pausing and modifying them. 

For this month I mainly spent it reading pKVM code, understanding how the architecture works, how everything is split up, and developing a plan for my implementation. Obviously I have been running into issues where I needed to learn specific things that I wasn't expecting, but I wanted to learn enough to have a plan. On top of that, I have been reading the book [Hardware and Software Support for Virtualization](https://kartikgopalan.github.io/680v/books/HSSV.pdf) to make sure I am not missing any base knowledge. I strongly recommend this book, it is a little over 150 pages, is very understandable, straight forward, and covers only the core fundamental concepts like: `the popek goldberg theorem` (the requirements for an ISA to be able to be handled by a VMM), Intel VT-x & ARM hardware virtualization support, `virtio` (this one was like the biggest chunk, I learned the most from this chapter), performance stuff (i skipped this), and more foundational things. In the preface of the book, the intended audience is "new graduate students looking to gain foundational understanding before reading research papers in niche problems within these big topics." What I said wasn't bar for bar, but it's practically what it said.

Anyways, for now the goal is to read EL2 pmem/regs and ping pong to read EL1 pmem/regs. The reason why is if you are able to read the `TTBR` pairs and read physical memory, you have virtual memory too. Also for now I am making the host kernel have the ko module that will interact with the hypervisor module, which basically makes what we are doing right now just reading the kernel memory and registers with extra unnecessary steps, but the ability to do this will be appreciated when I migrate things to a separate pVM in the future.

### pKVM overview

As I was doing research, I started to learn that there is actually quite a weird separation of responsabilities between the host EL1 and the hypervisor EL2 space. Firstly (and this was a weird discovery), the host kernel is NOT acually a VM and is treated differently compared to all of the other pVM's like if you were to spin off a Microdroid pVM. This will be important later on. 

Another thing is what actually happens in EL2 is actually just the bare minimum to keep confidentiality between pVM's and the host kernel. Everything else is actually an interaction between the hypervisor and the host kernel. For example: if a pVM needs a page, the hypervisor will ask the kernel for one, then it will allocate a page, and then donate it to the hypervisor. This was really funky to figure out, other responsabilities include:
 - Kernel:
   - the `/dev/kvm` interface (obviously)
   - creating/destroying VM's, it actually can see which VM's are alive, it just can't see their registers and memory
   - vCPU scheduling
   - device emulation (virtio, PCIe, MMIO, etc)
   - the actual KVM stuff
 - Hypervisor:
   - the stage 2 page tables/EPTs (`TTBR0_EL2`, it does not use `TTBR1` ever)
   - hyp mempool
   - page management/page faults
   - vCPU states
   - timer, GIC, etc
   - trap handling
   - DMA/IOMMU, I will speak more about this later

### Issue one

So with this in mind, there are a couple hurdles we have to go through, and they are all dealing with what we have access to as an EL2 vendor module lmao. First of all, vendor modules do not have access to any of the pKVM symbols. The only thing that vendor modules have access to is the `pkvm_module_ops` object, which holds very useful functions we will use:
``` c
struct pkvm_module_ops {
	int (*create_private_mapping)(phys_addr_t phys, size_t size,
				      enum kvm_pgtable_prot prot,
				      unsigned long *haddr);
	void *(*alloc_module_va)(u64 nr_pages);
	int (*map_module_page)(u64 pfn, void *va, enum kvm_pgtable_prot prot, bool is_protected);
	int (*register_serial_driver)(void (*hyp_putc_cb)(char));
	void (*puts)(const char *str);
	void (*putx64)(u64 num);
	void *(*fixmap_map)(phys_addr_t phys);
	void (*fixmap_unmap)(void);
	void *(*linear_map_early)(phys_addr_t phys, size_t size, enum kvm_pgtable_prot prot);
	void (*linear_unmap_early)(void *addr, size_t size);
	void (*flush_dcache_to_poc)(void *addr, size_t size);
	void (*update_hcr_el2)(unsigned long set_mask, unsigned long clear_mask);
	void (*update_hfgwtr_el2)(unsigned long set_mask, unsigned long clear_mask);
	int (*register_host_perm_fault_handler)(int (*cb)(struct kvm_cpu_context *ctxt, u64 esr, u64 addr));
	int (*host_stage2_mod_prot)(u64 pfn, enum kvm_pgtable_prot prot);
	int (*host_stage2_get_leaf)(phys_addr_t phys, kvm_pte_t *ptep, u32 *level);
	int (*register_host_smc_handler)(bool (*cb)(struct kvm_cpu_context *));
	int (*register_default_trap_handler)(bool (*cb)(struct kvm_cpu_context *));
	int (*register_illegal_abt_notifier)(void (*cb)(struct kvm_cpu_context *));
	int (*register_psci_notifier)(void (*cb)(enum pkvm_psci_notification, struct kvm_cpu_context *));
	int (*register_hyp_panic_notifier)(void (*cb)(struct kvm_cpu_context *host_ctxt));
	int (*host_donate_hyp)(u64 pfn, u64 nr_pages);
	int (*hyp_donate_host)(u64 pfn, u64 nr_pages);
	int (*host_share_hyp)(u64 pfn);
	int (*host_unshare_hyp)(u64 pfn);
	int (*pin_shared_mem)(void *from, void *to);
	void (*unpin_shared_mem)(void *from, void *to);
	void* (*memcpy)(void *to, const void *from, size_t count);
	void* (*memset)(void *dst, int c, size_t count);
	phys_addr_t (*hyp_pa)(void *x);
	void* (*hyp_va)(phys_addr_t phys);
	unsigned long (*kern_hyp_va)(unsigned long x);

    // ... snip ...
}
```

This is cool and all, but I really really really want access to this object that looked very important inside the `nvhe/pkvm.c` file called `vm_table`. I remember reading this file and immediately being like "DING DING DING, that HAS to be what I need." Literally the functions that handled loading vCPU's, page management, etc would spinlock `vm_table_lock`. it is a `pkvm_hyp_vm **`, which is basically an array of size 255 `pkvm_hyp_vm`'s. This is how the struct looks like:

``` c

/* EDIT: this comment literally verifies what I was thinking:
 * Holds the relevant data for running a protected vm.
 */
struct pkvm_hyp_vm {
	struct kvm kvm;

	/* Backpointer to the host's (untrusted) KVM instance. */
	struct kvm *host_kvm;

	/* The guest's stage-2 page-table managed by the hypervisor. */
	struct kvm_pgtable pgt;
	struct kvm_pgtable_mm_ops mm_ops;
	struct hyp_pool pool;
	hyp_spinlock_t lock;

	/* Primary vCPU pending entry to the pvmfw */
	struct pkvm_hyp_vcpu *pvmfw_entry_vcpu;

	/*
	 * The number of vcpus initialized and ready to run.
	 * Modifying this is protected by 'vm_table_lock'.
	 */
	unsigned int nr_vcpus;

	/*
	 * True when the guest is being torn down. When in this state, the
	 * guest's vCPUs can't be loaded anymore, but its pages can be
	 * reclaimed by the host.
	 */
	bool is_dying;

	/* Array of the hyp vCPU structures for this VM. */
	struct pkvm_hyp_vcpu *vcpus[];
};
```

Anyways that is hurdle one, the object is still mapped at the time of the module running so this is a linker thing. I could very easily modify pKVM to allow my module to access it, but that would ruin the whole point of keeping it to vendor module only.

### Getting access to the `vm_table`

Now that the problem is understood, now I need to find a way to get the `vm_table` object. My first thinking was to first try to use the `pkvm_module_ops` functions given, because maybe some of them can help me. But lowkey that was very stupid, I didn't give it too much thought.

Next I tried to just straight up read bytes and eventually profile my way into finding the object, tideous and unreliable i know. I decided to see what was in the call stack for when an `hvc trap` is handled. The call stack looked something like this:
```
pkvmi_module() -> (lr) -> handle_host_dynamic_hcall() -> *(sp + 8) -> handle_host_hcall()
```

As I was just debugging in gdb, working in the BALL CRUSHING FACTORY, I was like "damn, there has to be a better way." I started to think maybe some part of the relationship between the host kernel and the hypervisor would allow me to find it. That it did, and honestly I was not expecting it to be such a good solution.

So what was it? Well in the AVF documentation it tells you that your vendor module symbols you want accessed by the kernel for initialization would have `__kvm_nvhe_` attached to them. This is what I mean:

`hyp/pkvmi.c`:
``` c

void pkvmi_hvc(struct kvm_cpu_context *ctx) {

    // ... snip ...
}

int pkvmi_init(struct pkvm_module_ops* _ops) {

  ops = _ops;

  return 0;
}
```

`kern/ioctl.c`:
``` c

int __kvm_nvhe_pkvmi_init(const struct pkvm_module_ops *ops);
void __kvm_nvhe_pkvmi_hvc(struct kvm_cpu_context *ctx);

int pkvm_driver_init(void) {

  unsigned long token;
  int ret;

  ret = pkvm_load_el2_module(__kvm_nvhe_pkvmi_init, &token);

  if (ret)
    return ret;

  ret = pkvm_register_el2_mod_call(__kvm_nvhe_pkvmi_hvc, token);

  if (ret < 0)
    return ret;

  pkvmi_hvc = ret;

  return 0;
}
```

And if I were to look at `kallsyms`: 
``` 
~ # cat /proc/kallsyms | grep pkvmi_hvc
ffffffc000fca000 b pkvmi_hvc	[pkvmi]
ffffffc000fc1448 t __kvm_nvhe_pkvmi_hvc	[pkvmi]
```

Well anyways, as a hail mary I tried the same for the `vm_table` and to my surprise:
```
~ # cat /proc/kallsyms | grep vm_table
ffffffc008fa6394 T __kvm_nvhe_pkvm_hyp_vm_table_init
ffffffc0097bece8 d vm_table
ffffffc0099881d8 b __kvm_nvhe_vm_table_base
ffffffc00998c248 b __kvm_nvhe_vm_table
ffffffc00998c250 b __kvm_nvhe_vm_table_lock
```

Which honestly makes sense!!! As stated in the last blog post: the kernel and hypervisor get built and linked together (the linker is what adds the `__kvm_nvhe`) and during early boot the kernel is in EL2, sets up the hypervisor, and then deprivilages itself. So it would kind of make sense that `kallsyms` has it. I still dont understand why it stays there on purpose, but I am not complaining. I am not a linker pro, but if anyone wants to explain to me why I'd be happy to learn. Anyways that is my assumption as to why this works.

Well since the kernel and hypervisor are contiguous in physical memory, this means that I can treat the `__kvm_nvhe_vm_table` kernel VA as any other one and turn it into an `immediate physical address (IPA)` by getting `kimage_voffset` and subtracting from it. Then I pass the IPA to the hypervisor and use the `ops->hyp_va(pa)` function to turn that IPA, which is the REAL physical address, into a hypervisor virtual address. AND IT WORKED!!!!11!111!11!1! 

### Trying something cheeky

Now when I first found this, I decided "well, if I can find the PA of hypervisor symbols, why can't I just change them from kernel space by mapping them to the EL1 page table?" 

It didn't work. The part I forgot about was that an IPA has to go through an IPA -> PA translation through `VTTBR_EL2`. It will create a page fault, then it will check to see who owns that PFN, and boom crash.

But then I thought about writing it to an IOMMU entry so that DMA writes to it, but that is also locked down by the hypervisor (as stated earlier). 

Womp womp. Worth the try.

### pKVM reg/mem read

This was really easy, I set up a page to be shared between the hypervisor and kernel by having the kernel allocate a page, send over the PFN, and then use `ops->share_hyp(pfn)` like so:
``` c
static int share_page(int pfn) {

  int ret = 0;
  void * page;

  if (shared_page)
    return -EFAULT;

  ret = ops->host_share_hyp(pfn);
  if (ret)
    goto end;

  page = ops->hyp_va(pfn << PAGE_SHIFT);
  ret = ops->pin_shared_mem(page, page + PAGE_SIZE);

  if (ret) {
		ops->host_unshare_hyp(pfn);
		goto end;
	}

  shared_page = page;
  shared_pfn = pfn;

end:
  return ret;
}
```

Also you will see, I use `EFAULT` for almost everything because I dont feel like learning all of the fault codes lmao. Anyways this is how I send data back and forth. There is a `read_sysreg()` function that allows me to easily get system registers, and pmem is literally jsut a vmem translation and then memcpy. Make sure you dont crash the device though (I didnt implement security yet, maybe I wont if I'm too lazy).

### Reading regs/mem from the host kernel

For this I had a cool idea: I would copy a L3PT entry (`TCR_EL1`'s lower bits specify only 30 VA bits instead of 39) from `TTBR1_EL1` (higher order page table) and paste it into `TTBR0_EL2` and access it regularly. 

The way I did that was I took the root table PA from `TTBR1_EL1`, and lazily mapped it into whatever first empty entry I found in the hypervisor L3PT. Made sure it was treated as a HUGE page, but not access anything past the regular L1 page size (4K):
``` c
static void* el2_tmp_map_phys(phys_addr_t pa) {

  phys_addr_t root_pa = read_sysreg(ttbr0_el2) & ADDR_MASK_47_12;
  unsigned long* root = ops->hyp_va(root_pa);
  void* va = NULL;
  int i;

  for (i = L1_NR_ENTRIES - 1; i >= 0; i--)
    if (!(root[i] & DESC_VALID))
      break;

  if (i < 0)
    goto out;

  root[i] = (pa & L1_ADDR_MASK) | DESC_VALID | DESC_ATTR_NORMAL
          | DESC_SH_INNER | DESC_AF | DESC_XN;

  g_root_pa = root_pa;
  g_idx = i;

  va = (void *) (((unsigned long) i << L1_SHIFT) | (pa & (L1_BLOCK_SIZE - 1)));
  el2_tlb_flush();
out:
  return va;
}
```

Then from there, I would just do what I said I would do. For now I just take the first 1GB entry pointed to by `kimage_voffset`, but I will make it better later:
``` c
// temporarily maps the ttbr1_el1 in the el2 memory space,
// reads the top kbase_pt entry
// maps it into ttbr0_el2 so we can access kernel memory in the pKVM module 
// dont forget to unmap
void* host_el1_map_va(unsigned long va) {

  unsigned long* ttbr0_root = (unsigned long *) ops->hyp_va((phys_addr_t) (read_sysreg(ttbr0_el2) & ADDR_MASK_47_12));
  unsigned long ttbr1_pa = read_sysreg(ttbr1_el1);
  unsigned long* ttbr1_va = el2_tmp_map_phys(ttbr1_pa & ADDR_MASK_47_12);
  unsigned long kbase_pt_pa = 0;

  if (!ttbr1_va)
    return NULL;

  // i lowkey dont understand why its + 1, but when looking at gdb
  // i was one off??? I thought the logic was sound 
  g_kimage_idx = PGD_IDX((unsigned long) kimage_voff) + 1;
  kbase_pt_pa = ttbr1_va[g_kimage_idx];

  host_el1_tmp_unmap();

  // bad map base
  if (ttbr0_root[PGD_IDX(va)] & DESC_VALID)
    return NULL;

  ttbr0_root[PGD_IDX(va)] = kbase_pt_pa;

  return (void *) va;
}
```

And just like that it worked!!:
```
pkvmi> regdump
hcr_el2   0x0000000080080001
sctlr_el2 0x0000000030ed183d
tcr_el2   0x0000000080823519
ttbr0_el2 0x00000000bec01001
mair_el2  0x0000f4040044ffff
vbar_el2  0x000000490119b000
esr_el2   0x000000005a000000
elr_el2   0xffffffc000fc2254
spsr_el2  0x0000000060400005
tpidr_el2 0x0000000001799000
vttbr_el2 0x00000000bf81c001
vtcr_el2  0x00000000802a3558
pkvmi> readpa 0x00000000bec01000
0x00000000bec01000  0x0000000000000000 0x00000000bec02003 
0x00000000bec01010  0x0000000000000000 0x0000000000000000 
0x00000000bec01020  0x0000000000000000 0x0000000000000000 
... snip ...
0x00000000bec01400  0x00000000bec15003 0x0000000000000000 

===== TRIGGER THE REMAPPING =====

pkvmi> readpa 0x00000000bec01000
0x00000000bec01000  0x0000000000000000 0x00000000bec02003 
0x00000000bec01010  0x0000000000000000 0x0000000000000000 
0x00000000bec01020  0x0000000000000000 0x0000000000000000 
0x00000000bec01030  0x0000000000000000 0x0000000000000000 
... snip ...
0x00000000bec01400  0x00000000bec15003 0x10000000bffff003 
```

Anyways, if you didn't realize. For reading physical memory this is an overkill and I could of definitely just use the lazy HUGE page method for reading a host kernel's PA. I was really tired and didn't realize it until my tests kept failing if the physical address I was looking for was NOT part of that mapping, but then when I found it out I was like bruh:
``` c
int host_el1_read_pa(void* dst_page, void* pa) {

  void* va = el2_tmp_map_phys((phys_addr_t) pa);

  if (!va)
    return -EFAULT;

  ops->memcpy(dst_page, va, PAGE_SIZE);

  host_el1_tmp_unmap();
  return 0;
}
```

Either way what I did is going to be useful if I want to scan through virtual that is scattered around in physical memory space. Just not right now.

