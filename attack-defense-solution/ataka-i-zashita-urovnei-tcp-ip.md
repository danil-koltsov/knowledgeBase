# Атака и защита уровней TCP/IP

## **Канальный уровень TCP/IP**

| Атака | Защита |
| :---: | :---: |
| Переполнение CAM-таблицы | Включить защиту port-security |
| VLAN Hopping | Не оставлять порты на которых нет тэгов, закрывать их или вывести в другой vlan |
| Атаки на STP | Запрет BDPU пакетов с порты на которых нету камутаторов. Перевести все порты в режим portfast |
| MAC-спуфинг | Поставить ARP-timeout и включить защиту port-security |
| Атаки на PVLAN | На устройстве L3 создать специальный Acrss List, в котором запрещается прямая передача данных между сегменатами сети |
| Атаки на DHCP | DHCP Snooping |
| ARP-spoofing | Использовать статический ARP. Использовать VLAN |

## **Сетевой уровень TCP/IP**

| Атака | Защита |
| :---: | :---: |
| Изменение статической маршрутизации | Физическая защита. Нельзя использовать сервер-маршрутизатор для других целей \(например использовать для хранения баз данных\). Не давать пользователям права администратора. |
| Атаки на RIP. Dos \(запросы GET\), SYN-flood. Ложные маршруты RIP. Понижение версии RIP. Взлом MD5 для RIP | Проверка подлинности RIP версии 2, задание равных маршрутизаторов, фильтры маршрутов, соседи \(ограничить обмен информации только с соседними маршрутизаторами\). Использовать MD5-аутентификацию. |
| Атаки на OSPF. Изменение метрики маршрутизатора  чтобы трафик шел через маршрутизатор злоумышленника. Вывести из строя Designated router \(центральный роутер в топологии ring\) с целью подключить бэкап роутер злоумышленника. Взлом OSPF MD5 | Использовать MD5-аутентификацию. Проверка подлинности пароля OSPF. Фильтр внешних маршрутов на граничных маршрутизаторах автономной системы. Защита от затопления LSA-пакетами |
| Атаки на BGP. BGP Router Masquerading. Взлом MD5 для BGP.DOS на BGP \(SYN-flood на порт tcp 179 с md5 сигнатурами\). Атака confidentiality, replay, message insertion, message deletion, message modification, man-in-the-middle, denial of service. | Следить за потеряй пакетов, перегрузкой сети, черными дырами, задержками, петлями, перехватами, разделениями сети, отключениями, волнами скорости, нестабильностью маршрутов, перегрузами, истощениями пространства таблиц, обманными адресами. Использовать MD5-аутентификацию. Использовать IPsec ESP. |
| Атака на IS-IS. Ложные маршруты. DOS \(HELLO-пакетами\) | Использовать аутентификацию. Следить за заголовками. |
| Атаки на MPLS | Применить средства аутентификации и шифрования, установленные в сетях клиентов |

## **Транспортный уровень TCP/IP**

| Атака | Защита |
| :---: | :---: |
| IP-spoofing | Шифрование TCP-потока криптографически стойким алгоритмом генерации псевдослучайных чисел для генерации squence number |
| TCP hijacking |  |
| Десинхронизация нулевым днем | Контролировать переход в десинхронизованное состояние, обмениваясь информацией о sequence number, acknowledgement number. Отслеживание ACK-бурь. Применение криптографически стойкого алгоритма для шифрования TCP-потока |
| Сканирование сети |  |
| SYN-флуд | TCP Intercept |
| Teardrop | Средства предотвращения вторжений |
| UDP Storm | Средства межсетевого экранирования, средства предотвращения вторжений и IPSec |
| ICMP атаки для снижения скорости обмена данными или для разрыва | Средства межсетевого экранирования, средства предотвращения вторжений и IPSec. Ограничить ping flood |

## **Прикладной уровень TCP/IP**

| Атака | Защита |
| :---: | :---: |
| Вторжение в syslog | Запретить пересылку UPD-пакетов по 514 порту.  Средства межсетевого экранирования, средства предотвращения вторжений |
| DOS на DNS, Отравление кэша DNS \(атака Каминского\) | Обновит ПО, использовать случайные UDP порты для выполнения dns запросов, DNSSEC \(построение доверия\) |
| Session Hijacking, XSS-атаки, Session Fixation, кража cookie с использованием HTTP-заголовка ответа, Session Poisoning | Привязать идентификатор сессии к браузеру пользователя. Запрет использования методов GET и POST для передачи идентификатора сессии. Для передачи идентификатора нужно использовать cookies.Не использовать cookies чтобы не ворвалась сессия. Регенерация идентификатора сессии. |
| SQL-инъекции | Не допускать ошибки в коде, фильтрация целочисленных параметров, усечение входных параметров, использование параметризованных запросов |

