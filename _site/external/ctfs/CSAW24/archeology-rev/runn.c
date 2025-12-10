#include <stdio.h>
#include <stdbool.h>

void runnnn(char* str_addr)

{
  byte bVar1;
  byte bVar2;
  int count;
  int count_plus1;
  int count_plus2;
  bool run;
  
  count = 0;
  run = true;
  while (run) {
    count_plus1 = count + 1;
    switch(*(undefined *)(str_addr + count)) {
    case 0:
      count_plus2 = count + 2;
      count = count + 3;
      *(undefined *)((long)&regs + (long)(int)(uint)*(byte *)(str_addr + count_plus1)) =
           *(undefined *)(count_plus2 + str_addr);
      break;
    case 1:
      count_plus2 = count + 2;
      count = count + 3;
      *(byte *)((long)&regs + (long)(int)(uint)*(byte *)(str_addr + count_plus1)) =
           *(byte *)((long)&regs + (long)(int)(uint)*(byte *)(str_addr + count_plus1)) ^
           *(byte *)((long)&regs + (long)(int)(uint)*(byte *)(str_addr + count_plus2));
      break;
    case 2:
      count_plus2 = count + 2;
      bVar1 = *(byte *)(str_addr + count_plus1);
      count = count + 3;
      bVar2 = *(byte *)(str_addr + count_plus2);
      *(byte *)((long)&regs + (long)(int)(uint)bVar1) =
           *(char *)((long)&regs + (long)(int)(uint)bVar1) << (bVar2 & 0x1f) |
           (byte)((int)(uint)*(byte *)((long)&regs + (long)(int)(uint)bVar1) >> (8 - bVar2 & 0x1f));
      break;
    case 3:
      count = count + 2;
      *(undefined1 *)((long)&regs + (long)(int)(uint)*(byte *)(str_addr + count_plus1)) =
           sbox[(int)(uint)*(byte *)((long)&regs +
                                    (long)(int)(uint)*(byte *)(str_addr + count_plus1))];
      break;
    case 4:
      count_plus2 = count + 2;
      count = count + 3;
      memory[(int)(uint)*(byte *)(str_addr + count_plus2)] =
           *(undefined *)((long)&regs + (long)(int)(uint)*(byte *)(str_addr + count_plus1));
      break;
    case 5:
      count_plus2 = count + 2;
      count = count + 3;
      *(undefined1 *)((long)&regs + (long)(int)(uint)*(byte *)(str_addr + count_plus1)) =
           memory[(int)(uint)*(byte *)(str_addr + count_plus2)];
      break;
    case 6:
      count = count + 2;
      putchar((uint)*(byte *)((long)&regs + (long)(int)(uint)*(byte *)(str_addr + count_plus1)));
      break;
    case 7:
      run = false;
      count = count_plus1;
      break;
    case 8:
      bVar1 = *(byte *)(str_addr + count_plus1);
      bVar2 = *(byte *)(str_addr + (count + 2));
      *(byte *)((long)&regs + (long)(int)(uint)bVar1) =
           (byte)((int)(uint)*(byte *)((long)&regs + (long)(int)(uint)bVar1) >> (bVar2 & 0x1f)) |
           *(char *)((long)&regs + (long)(int)(uint)bVar1) << (8 - bVar2 & 0x1f);
      count = count + 3;
      break;
    default:
      puts("Invalid instruction");
      run = false;
      count = count_plus1;
    }
  }
  return;
}

int main() {
	char mock_str[] = ""; 

	return 0;
}
