## REV - Paranoia

#### Ghidra disassembler code

``` c
undefined8 main(void)

{
  char cVar1;
  int iVar2;
  time_t tVar3;
  ulong local_20;
  
  tVar3 = time((time_t *)0x0);
  srand((uint)tVar3);
  for (local_20 = 0; local_20 < 0x12; local_20 = local_20 + 1) {
    cVar1 = flag[local_20];
    iVar2 = rand();
    printf("%i ",(ulong)(uint)(iVar2 % 0x100 ^ (int)cVar1));
  }
  putchar(10);
  return 0;
}
```

#### Python script

``` python
from pwn import *
from ctypes import CDLL
from datetime import datetime

d = datetime.now()

timestamp = int(d.timestamp())

libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(timestamp)

io = process("./paranoia")

encoded = io.recvuntil(b"\n")
encoded = encoded[:-1].split(b" ")
encoded.remove(b"")

flag = ""

for byte in encoded:
    cur = int(byte)
    rand = libc.rand()

    flag += chr( rand % 0x100 ^ cur )

print(flag)
```
