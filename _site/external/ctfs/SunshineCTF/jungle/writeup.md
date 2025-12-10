This challenge was really fun. Ran through some trouble at the end but I learned from it.

So this challenge is a tcache exploitation challenge where you can only have up to 6 allocated chunks at the same time. The bug is found with the fact that there are two arrays: one for holding chunk pointers and one with a bunch of boolean values that state whether or not the chunk is in use. This allows for the `remove()` function to have some interesting functionality where you can call it twice on the same chunk and it will allow for a UAF since the second time you call it, the chunk will not be freed again, but in fact the program will flip the `in_use` variable for the corresponding chunk to `true`.

```c
void remove(uint param_1)

{
  if ((*(long *)(knapsack + (long)(int)param_1 * 8) == 0) ||
     (*(int *)(used + (long)(int)param_1 * 4) != 1)) {
    printf("<<< Pocket %d is already empty.\n",(ulong)param_1);
  }
  else {
    free(*(void **)(knapsack + (long)(int)param_1 * 8));
    printf("<<< Removed item from pocket %d.\n",(ulong)param_1);
  }
  *(uint *)(used + (long)(int)param_1 * 4) = 
    (uint)(*(int *)(used + (long)(int)param_1 * 4) == 0); <=== this line is the bug
  return;
}
```

With this, we can create a tcache poisoning attack. Here is the exploit strategy.

```
PLAN:
         - freeing twice allows for UAF
         - get heap leak through UAF
         - use genie for libc leak
         - get stack leak through environ
         - ret2libc!!
```

The rest you can see through my exploit, just know that when creating a chunk, the first `0x18` bytes will be set to null so that is why my environ leak is a little far back.

Another thing was that my local exploit worked locally but not remotely, and I really struggled on figuring out why. Spent over an hour trying to figure out why but nothing. It wasn't until I got my friend (the man, the myth, the legend) [Alex](https://github.com/SolarDebris) that he saw that I was handling IO not very carefully. This caused the remote version (where things will take a little longer to send/recieve) to not work. So lesson learned, be more careful taking care of IO.
