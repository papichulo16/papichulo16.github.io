This challenge was pretty fun, and definitely learned a good lesson. 

So this challenge is basically just custom instructions sent to a drone and eventually you will be able to find a bug somewhere. At first (and for quite a while) I tried to to it in Ghidra, the problem is that it had a problem with the jumptable and it became a pain.

```
/* WARNING: Could not recover jumptable at 0x0040139a. Too many branches */
```

Also here is the command I ran to get all the commands:

```bash
strings drone.bin | rg "^[A-Z]{4}$" > commands_list
```

For a while I did try to go through it statically, and I actually learned quite a bit about dealing with this kind of problem. But after a bit, I just decided to run ltrace on the binary, play with the binary, and see when I would find something interesting.

It wasn't that long after when I found that if you turn `SAFE` mode off, and then call `CAMO`, you can actually overflow into the stack. Here is the overflow code.

```c
void deprecated_feedback(void)

{
  undefined local_108 [256];
  
  if (DAT_004067e8 == '\0') {
    puts("<<< Feedback only available in unSAFE state");
  }
  else {
    printf("Leave feedback comments for the developers >>> ");
    read(0,local_108,0x200);
  }
  return;
}
```

With this you can just do `ret2system` and win.

After this challenge I would like to make a shirt that says `UNRECOVERED_JUMPTABLE` and then a Ghidra logo, because I think it would be funny.
