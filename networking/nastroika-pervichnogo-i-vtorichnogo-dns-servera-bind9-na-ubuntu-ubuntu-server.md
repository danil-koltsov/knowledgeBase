# Настройка первичного и вторичного DNS-сервера \(BIND9 на Ubuntu/Ubuntu Server\)

IP-адрес первичного сервера: `172.16.14.1`

IP-адрес вторичного сервера: `172.16.14.2`

## Установка и конфигурация bind9 на первичном сервере

Устанавливаем bind9 используя команду:

```text
apt-get install -y bind9 bind9utils bind9-doc dnsutils
```

Создаем прямую и обратную зону, для этого будем редактировать файл `/etc/bind/named.conf.local`. Запись прямой зоны и обратной зоны будет иметь следующий вид:

* ```text
  zone "d1.local" {
    type master;
    file "/var/lib/bind/forward.bind";
    allow-update { none; };
    };
  zone "14.16.172.in-addr.arpa" {
    type master;
    file "/var/lib/bind/reverse.bind";
    allow-update { none; };
    };
  ```

  Далее настраиваем файл прямой зоны, для этого будем редактировать файл `/var/lib/bind/forward.bind`. Файл будет иметь следующий вид:

* ```text
  $TTL    604800
  @       IN      SOA     danil.d1.local.     root.danil.d1.local.(
                                2           ; Serial
                                604800      ; Refresh
                                86400       ; Retry
                                2419200     ; Expire
                                604800 )    ; Negative Cache TTL
  ;
  @       IN      NS      danil.d1.local.
  @       IN      A       127.0.0.1
  @       IN      AAAA    ::1
  ;Name Server Information
        IN      NS      d1.local.
  ;IP Address of Name Server
  danil   IN      A       172.16.14.1
  danil   IN      A       172.16.14.2
  ;Mail Exchanger
  d1.local.       IN      MX      10      mail.d1.local.
  ;A - Record HostName To IP Address
  www     IN      A       172.16.14.3
  mail    IN      A       172.16.14.4
  ```

  Далее настраиваем файл обратной зоны, для этого будем редактировать файл `/var/lib/bind/reverse.bind`. Файл будет иметь следующий вид:

* ```text
  $TTL    604800
  @       IN      SOA     danil.d1.local.     root.danil.d1.local.(
                                2           ; Serial
                                604800      ; Refresh
                                86400       ; Retry
                                2419200     ; Expire
                                604800 )    ; Negative Cache TTL
  ;
  @       IN      NS      danil.d1.local.
  1.0.0   IN      NS      danil.d1.local.
  ;Name Server Infomation
        IN      NS      danil.d1.local.
        IN      NS      danil.d1.local.
  ;Reverse Lookup For Name Server
  10      IN      PTR     danil.d1.local.
  20      IN      PTR     danil.d1.local.
  ;PTR Record IP Addres To HostName
  3       IN      PTR     www.d1.local.
  4       IN      PTR     mail.d1.local.
  ```

Перезапускает Bind9:

```text
sudo service bind9 restart
```

Проверяем статус настроенного первичного сервера с помощью команды:

```text
sudo service bind9 status
```

## Конфигурация bind9 на вторичном сервере

Настраиваем вторичный сервер конфигурирования файл `/etc/bind/named.conf.local`:

* ```text
  zone "d1.local" {
    type slave;
    file "/var/lib/bind/forward.bind";
    master { 172.16.14.1; };
    };
  zone "14.16.172.in-addr.arpa" {
    type slave;
    file "/var/lib/bind/reverse.bind";
     master { 172.16.14.1; };
    };
  ```

Файлы прямой и обратной зоны вторичного такие же как на первичном сервере. Проверяем статус bind9 вторичного сервера:

```text
sudo service bind9 status
```

## Настройка клиента на Ubuntu

Подключаем клиента, меняя на клиентском интерфейсе файл `/etc/resolv.conf`:

* ```text
  nameserver 172.16.14.1
  options edns0
  ```

Теперь с помощью команды nslookup проверим работу сервера:

```text
nslookup www.d1.local
```

