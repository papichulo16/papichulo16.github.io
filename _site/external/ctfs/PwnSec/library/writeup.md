This challenge was really cool. I don't know if this was the intended solution since my solution required libc and we weren't given one, but I think my solution was cool.

So the challenge gives you 4 options: `create`, `edit`, `print`, and `remove`. Now what is interesting here is the functionality of the `create` and `edit` functions.

The `create` function will create two chunks, something I'd like to call a `mediary chunk` and the chunk that holds your data (title). What the program will do is store the pointer to the real chunk, the rating on the chunk/book/movie, and a pointer to either the `print_movie()` or `print_book()` function inside the `mediary chunk`. Then, it would write the address of the `mediary chunk` to the hash table and when using it, it would just double dereference it. A model would somehow look like this:

```
mediary chunk:
          --------------
          | size field |
------------------------
|chnk ptr | rating     |
------------------------
|func ptr | 
----------- 

pointers: 
Hash table => mediary chunk => chunk with data
```

Now if you think that this was interesting behavior, wait until you see the behavior for the `edit` function. This function will first free the double dereference of the chunk you are editing (the one with the data), then allocate the `mediary chunk` for this new value (which will use the recently freed chunk), and then it will allocate the chunk with the new data. So technically it will use the previous chunk A and use that as a mediary for the new chunk B. The only problem is that it will not remove chunk A's mediary pointer from the hash table and would just create a now entry in the hash table. It will look something like this:

```
Hash table => mediary chunk => chunk A
Hash table => chunk A => chunk B
```

With this, I was able to call the `print()` function and get a `heap leak` since the program would treat chunk A (which stores a pointer to chunk B) as a chunk that is in use.

Also with this in mind, I was able to do this misalignment with chunks A and B, then free chunk A, and when I create a new chunk, I would be able to overwrite the pointer to chunk B to be wherever in the heap I wanted. So what I did was create a new chunk, chunk C, and then I would overwrite the pointer in chunk A to point to chunk C's mediary chunk + 0x10 bytes so when I would call `print()`, I would get the address of `print_____()` and get a PIE leak.

After doing that, I would repeat that same process but instead I would make the pointer point to the GOT table to get a libc leak, which for some reason would only work 33% of the time since the chunks would get printed in different orders sometimes, but all I needed it to do was to work once. Now all I needed to do was replace a mediary chunk's `print______()` function with `system()` and make the chunk's data be `/bin/sh\x00` so that it would give me a shell, and this was a challenge. The reason why is because the program would always add a newline character to the end and if I wasn't careful, my data would be 0x19 bytes long and it would create a 0x30 sized chunk which would not let the exploit work.

So what I did, with a clean slate and a new set of chunks, was make a chunk be a mediary chunk to another chunk's mediary chunk. Then I would perform the same process that I did previously but this time I would make the program misalign the chunks by 16 bytes, and when it would do that I would be able to write the address of `system()` inside the chunk's `print_____()` function pointer. Then I would make the data of that chunk be `/bin/sh\x00` and when I would call `print`, it would call `system("/bin/sh")`.

Now as a last hurdle I had to pull the `libc.so.6` file out of the Docker container, which I found to be funny since there was no way that this was the intended way to do things (or maybe it was, I don't know hahahahaha). For future reference, this is what my friend [Alex](https://github.com/SolarDebris) told me to do:

``` 
build the docker container with docker build
open it in one terminal with docker run -ti ... /bin/sh
on another terminal, get the processes and the name so I can run docker cp name:file location
```

Anyways, this was a really fun challenge to map out on a white board and figure out the maneuvers that would let me do whatever I wanted to the program. Overall I had a blast solving this and I highly encourage checking out the solve script. Pretty cool.

