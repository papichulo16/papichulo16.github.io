This challenge was my first ever heap challenge on a live CTF. I did HeapLab 1 and 2 and I figured that it wouldn't be crazy compared to the challenges inside those courses. 

Anyways the whole challenge is just the fact that you are only allowed 8 active chunks at a time but if you free one you open another spot in the chunk pointers array (aka scripts in the binary). Not just that, but we had no way of viewing chunks so that means no leaks. Also the weirdest part, in my opinion, was that the only data we could write was the 0x18 bytes after the chunk pointer, and only 8 bytes. So I found that if we create a 0x20 sized chunk then we can overwrite the next chunk's size field.

Now the attack angle that [we](https://github.com/Dylan-Jessee) thought of was to set chunks to the unsorted bins, and then unlink an address to the chunk pointers array so we can overwrite data to wherever with the edit function. Then try to overwrite the `loglen` buffer so we can ROP. The only roadblock stopping us will have to be how do we get to write into a chunk's bk pointer. 

The way that I thought of was to first create a 0x20 sized chunk for the overwriting of a size field, and then two large sized chunks so that way they don't go to the tcache bins. Next change the size field of the upper large chunk to overlap both and then free it. Next create a chunk that is 0x10 size smaller than the original upper large chunk and then another chunk to make it overlap both original chunks. This will get us to write to the bk pointer. 

```python
# create initial chunks
create(io, 0x18, p64(0x20d71)) # 0
create(io, 0x438, b"A") # 1 a
create(io, 0x418, b"A") # 2 (target chunk)
create(io, 0x28, b"A") # 3

# free to unsorted bins and change size
edit(io, 0, p64(0x861)) # a
delete(io, 1)

create(io, 0x428, b"A") # 1 a
create(io, 0x28, b"AAAA") # 4
   
# this edits target chunk's bk
edit(io, 4, b"AAAA")
```

Next theoretically we should be able to unlink to the chunk pointers since that array will hold the address of our target chunk. The only problem is that we got an error with a mismatching prev_size field. Luckily if we find out how to change the target chunk's size field we can align it to this old prev_size later down in the heap. So same process again basically. 

```python
# change back target chunk's size field so it works
edit(io, 0, p64(0x461)) # a
#delete(io, 1)
create(io, 0x418, b"A") # 5 a
delete(io, 1)
create(io, 0x418, b"A") # 1 a
create(io, 0x18, p64(0x421)) # 6

# edit bk
edit(io, 5, p64(0x4040f0))
#edit(io, 5, p64(0x4040e0))
``` 

Now we have the main arena's address in the `scripts` array, only problem is that we can't malloc any more chunks because it will fail a size check. Also we can't edit anything in the main arena because the edit function uses a completely different array called `savedTags` and we didn't realize it until after we did all of this work. So only the `scripts` array is used when allocating a new chunk but after that it is it. Also we can't unlink to the `savedTags` because it stores the chunk pointers + 0x18 so all of them end with an 8, which will make it all have a misalignment issue.

This is where we got stuck, after a bit I decided to go to bed since I had work the next day and we didn't end up finishing this challenge once the CTF was over. After checking out the writeup, I found that we completely forgot that we could of done a large bins attack to overwrite the `loglen` variable and then we ROP. So basically we just took a lot of extra steps we did not need, sadly. This is all we had to do heap related to then get into a simple ROP.

```python
# create initial chunks
create(io, 0x428, b"A") # 0
create(io, 0x28, b"A") # 1 this chunk stops consolidation
create(io, 0x418, b"A") # 2

# sort to the large bins
delete(io, 0)
create(io, 0x438, b"A") # 3

# large bins attack
edit(io, 0, p64(e.symbols["loglen"] - 0x20))
delete(io, 2)
create(io, 0x438, b"A") # 4
```
So tragic. Anyways I decided to solve it on my own with the knowledge of the large bins attack so if you want to see the rest of the ROP, the script will be in the directory.

