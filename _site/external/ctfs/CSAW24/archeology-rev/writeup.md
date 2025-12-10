Alright so this challenge just started off as an escape from continuing to do the headache that was the challenge vip-blacklist (reasons why are on that writeup, the pain was self inflicted) but it ended up being a really fun challenge and I really enjoyed it.

What this challenge basically does is take your input and then performs a series of operations to then turn your input into hieroglyphs. After reversing the program through Ghidra you'll see that the flow goes something like this:

```
input -> washing_mashine() -> <adds a series of bytes per character> -> runnnn() -> washing_machine() -> output 
```

So first of all lets talk about the washing machine function, all it does is XOR each character by the character in front of it and then flips it through a procedure (whose name I coined) called a palindromic swap. The Ghidra code looks like this:

```c
void washing_machine(byte *string,ulong length)

{
  byte current_char;
  ulong i;
  ulong x;
  byte tmp;
  
  current_char = *string;
  for (i = 1; i < length; i = i + 1) {
    current_char = string[i] ^ current_char;
    string[i] = current_char;
  }
  for (x = 0; x < length >> 1; x = x + 1) {
    tmp = string[x];
    string[x] = string[(length - x) + -1];
    string[(length - x) + -1] = tmp;
  }
  return;
}
```

So creating a function that does the opposite looks like this:

```python
def unwash(string):
    length = len(string)

    # palindromic swap (patent pending)
    for i in range(length >> 1):
        temp = string[i]
        string[i] = string[length - i - 1]
        string[length - i - 1] = temp

    # unXOR them
    for i in range(length - 1):
        string[length - i - 1] ^= string[length - i - 2]

    return string
```

Now that that is out of the way it is time to look at what kind of weird byte procedures the program does. So for each character, the program will create a string of 146 bytes that are used to perform assembly instructions (but I didn't know that at the time). It looks something like this:

```
arr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee]

\x00\x01\x<input[idx]> | \x00\x00\x<arr[x % 5]>\x08\x01\x03\x03\x01\x01\x01\x00\x02\x01\x03 | \x04\x01\x<idx>
```

This string set will be created in a nested for loop where the bytes in between the `|` are repeated 10 times through the count variable `x` and `idx` is the count variable from the outside.

Now when I first started looking at the `runnnn()` function it all looked so confusing so I decided to take a gamble and tried to dynamically debug it through GDB to see if each value was mapped to another, for some reason it showed me it wasn't (when it technically was, I have no clue what went wrong but it's whatever).

Anyways I then had my [friend](https://github.com/Dylan-Jessee) come and join me and after a little bit he came to the realization that the bytes per character were assembly instructions and the `runnnn()` function was kind of like an interpreter. So with that in mind we mapped everything out on a whiteboard and figured out that what it was doing was something similar to this:

```python
# runnnn function from binary
def run(string):
    bob = [0xaa, 0xbb, 0xcc, 0xdd, 0xee]
    memory = b""

    for char in string:
        reg = [0, char]

        for i in range(10):
            reg[0] = bob[i % 5]
            reg[1] = ((reg[1] >> 3) | reg[1] << 5) & 0xff

            reg[1] = sbox[reg[1]]
            #print(chr(reg[1]).encode("utf-8"))

            reg[1] ^= reg[0]
            reg[1] = ((reg[1] << 3) | reg[1] >> 5) & 0xff

        memory += reg[1].to_bytes(1,"little")

    return memory
```

Now with that being figured out, we then reversed that function and ended up with this:

```python
def unrun(string):
    bob = [0xaa, 0xbb, 0xcc, 0xdd, 0xee]
    memory = b""

    for char in string:
        reg = [0, char]

        for i in range(10):
            reg[0] = bob[4 - (i % 5)]

            reg[1] = ((reg[1] >> 3) | reg[1] << 5) & 0xff
            reg[1] ^= reg[0]

            reg[1] = sbox.index(reg[1])
            reg[1] = ((reg[1] << 3) | reg[1] >> 5) & 0xff

        memory += reg[1].to_bytes(1, "little")

    return memory
```

And now with all of the functions used reversed, we can now decode the message.

```python
table = ""
with open("./hieroglyphs.txt", "r") as file:
    table += file.read()

table = table.split("\n")

message = "𓁡𓆓𓅥𓀺𓃛𓆉𓃣𓁊𓀴𓅜𓀒𓃗𓆂𓄆𓃾𓀠𓅊𓃚𓃧𓄂𓁷𓁻𓅒𓅠𓁡𓀆𓁠𓁿𓅊𓆏𓆃𓁄𓆑𓅅𓆍𓅌𓄄𓆅𓁷𓅡𓆞𓆊𓁺𓁇𓁱𓆝𓁮𓆜𓀚𓅷𓀰𓆝𓅁𓆅𓃣𓁆𓀤𓃔𓅅𓀯𓁏𓃚𓄉𓆄𓀼𓀏𓃻𓁧𓅩𓅳𓀯𓀇𓀛𓀙"

mapped = b""
for i in message:
    mapped += table.index(i).to_bytes(1, "little")

mapped = unwash(bytearray(mapped))
mapped = unrun(mapped)
mapped = unwash(bytearray(mapped))
print(mapped)
```

And when we run it

```
╭─papichulo@luis-20an0069us in ~/Desktop/ExploitDev/LiveCTF/CSAW24/archeology-rev 
╰$ python3 solve.py
bytearray(b'csawctf{w41t_1_54w_7h353_5ymb0l5_47_7h3_m3t_71m3_70_r34d_b00k_0f_7h3_d34d}')
```

Overall I really enjoyed this challenge and learned to look out for these assembly instructions in the future.
