# crypto_lab_1

Лабораторная работа lab01-fundamentals: консольная программа `crypto` на C11 с классическими
шифрами (Цезарь, Цезарь с ключевым словом, Виженер), арифметикой в GF(2^8), модульным
возведением в степень, обратным по модулю, дискретным логарифмом и разборами 2.6, 3.8, 4.1.

Только стандартная библиотека. Модули EXPMOD, INVMOD и LOGDIS собираются как статические
библиотеки (`libexpmod.a`, `libinvmod.a`, `liblogdis.a`), задание 3.7.

## Сборка

Нужны gcc (MinGW-w64), cmake и ninja. Ниже пути к тем, что идут в комплекте с CLion 2025.3.2;
если инструменты есть в PATH, полные пути не нужны.

PowerShell, из корня проекта:

```powershell
$b = "C:\Program Files\JetBrains\CLion 2025.3.2\bin"
$env:PATH = "$b\mingw\bin;$b\cmake\win\x64\bin;$b\ninja\win\x64;" + $env:PATH
cmake -S . -B build -G Ninja -DCMAKE_C_COMPILER=gcc "-DCMAKE_MAKE_PROGRAM=$b\ninja\win\x64\ninja.exe"
cmake --build build
```

Без явного `-DCMAKE_BUILD_TYPE` собирается Release (`-O3`), чтобы `-BENCH` мерил
оптимизированный код. Флаги `-Wall -Wextra`, сборка проходит без предупреждений.

Результат в `build/`:

| файл | что это |
|---|---|
| `crypto.exe` | основная программа |
| `libutil.a` | общие функции: mod, поиск в алфавите, разбор чисел, простые, факторизация |
| `libexpmod.a` | возведение в степень по модулю |
| `libinvmod.a` | обратный по модулю (зависит от expmod) |
| `liblogdis.a` | дискретный логарифм (зависит от invmod, expmod) |

Если в `examples/` лежат `expmod_orig.c`, `invmod_orig.c`, `logdis_orig.c` (примеры 3.5.1-3.5.3
из методички), они собираются отдельными программами. Сейчас методички в `docs/` нет, поэтому
и примеров нет.

## Структура

```
include/   заголовки модулей (vars, util, csr, csk, vgn, vgb, gf, expmod, invmod, logdis, attack)
src/       реализация, main.c - разбор аргументов, сообщения об ошибках, -BENCH
docs/      notes.md - материал для отчёта
```

## Как задаются ключи

Ключ и seed не передаются в командной строке. После проверки опции программа печатает
`key: ` (и `seed: `, если нужен) и читает строку из stdin. Поэтому ключ можно подать через pipe:

```
echo 7 | crypto -Ecsr IWILLBEHEREONMONDAY
```

Работает в cmd, PowerShell и Git Bash. Если stdin не терминал, прочитанное значение
печатается после приглашения, чтобы вывод выглядел так же, как при ручном вводе. Для двух
значений (ключ и seed) в PowerShell: `"MTIME", "1644485555" | crypto ...`, в bash:
`printf 'MTIME\n1644485555\n' | crypto ...`.

- ключ Цезаря - целое число, берётся по модулю 26;
- ключ CSK/VGN - слово из символов используемого алфавита;
- seed - целое без знака; при шифровании пустая строка означает текущее время `time(NULL)`,
  использованный seed печатается строкой `seed: N`.

Символы сообщения, которых нет в алфавите, копируются без изменений.

Алфавиты:

| имя | где | состав |
|---|---|---|
| `letters` | `vars.c` | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
| `letters2` | `csk.c`, static | `A-Z a-z 0-9`, 62 символа |
| `letters3` | `vgn.c`, static | `letters2` + `!@#$%^&*()-_=+[]{};:,.<>/?`, 88 символов |

## Опции

Все примеры ниже проверены, вывод приведён как есть (при подаче ключа через pipe).

### Цезарь, CSR

```
> echo 7 | crypto -Ecsr IWILLBEHEREONMONDAY
key: 7
enc: PDPSSILOLYLVUTVUKHF

> echo 7 | crypto -Dcsr PDPSSILOLYLVUTVUKHF
key: 7
dec: IWILLBEHEREONMONDAY
```

`-Ecsrm` / `-Dcsrm` - то же через формулу `(m +- k) mod 26`, результат совпадает.

### Цезарь с ключевым словом, CSK

```
> echo MEETINGTIME | crypto -Ecsk IWILLBEHEREONMONDAY
key: MEETINGTIME
enc: CWCHHENBNQNLKJLKIMY

> echo MEETINGTIME | crypto -Dcsk CWCHHENBNQNLKJLKIMY
key: MEETINGTIME
dec: IWILLBEHEREONMONDAY
```

Алфавит шифра для `MEETINGTIME`: `METINGABCDFHJKLOPQRSUVWXYZ`.
`-Ecskx` / `-Dcskx` работают с `letters2`:

```
> echo Key9 | crypto -Ecskx "Hello World 2026"
key: Key9
enc: Dbjjm Tmpja 1z15
```

### Виженер, VGN

```
> echo MTIME | crypto -Evgn IWILLBEHEREONMONDAY
key: MTIME
enc: UPQXPNXPQVQHVYSZWIK

> echo MTIME | crypto -Dvgn UPQXPNXPQVQHVYSZWIK
key: MTIME
dec: IWILLBEHEREONMONDAY
```

`-Evgnx` / `-Dvgnx` - с `letters3`:

```
> echo k3y! | crypto -Evgnx "Hi, Bob! 42?"
key: k3y!
enc: rBs @[,Y eC2
```

### Виженер с seed (разбор 2.6)

Каждая буква ключа дополнительно сдвигается на `seed mod 26`.

```
> printf 'MTIME\n1644485555\n' | crypto -Evgns IWILLBEHEREONMONDAY
key: MTIME
seed: 1644485555
enc: FABIAYIABGBSGJDKHTV

> printf 'MTIME\n1644485555\n' | crypto -Dvgns FABIAYIABGBSGJDKHTV
key: MTIME
seed: 1644485555
dec: IWILLBEHEREONMONDAY
```

### Виженер с XOR, VGB (часть 4)

`c_i = m_i XOR k_(i mod |k|) XOR r_i`, `r_i` - байт генератора xorshift32, заведённого от seed.
Шифротекст выводится в hex. Ключ - любая непустая строка.

```
> printf 'KEY\n12345\n' | crypto -Evgb "HELLO WORLD"
key: KEY
seed: 12345
enc: C565B27320BAE3D187852D

> printf 'KEY\n12345\n' | crypto -Dvgb C565B27320BAE3D187852D
key: KEY
seed: 12345
dec: HELLO WORLD
```

Файлы, двоичный режим. В начало зашифрованного файла пишется 8 байт seed, поэтому для
расшифровки нужен только ключ:

```
> printf 'secret key\n777\n' | crypto -Efvgb report.pdf report.enc
key: secret key
seed: 777
result: report.pdf -> report.enc (encrypted)

> echo secret key | crypto -Dfvgb report.enc report.out
key: secret key
result: report.enc -> report.out (decrypted)
```

### GF(2^8)

Модуль `x^8 + x^4 + x^3 + x + 1` (0x11B), числа в hex, `57` или `0x57`.
Методы: `pm` - русское крестьянское умножение, `poly` - произведение многочленов и деление
на 0x11B, `tbl` - таблицы логарифмов по генератору 0x03.

```
> crypto -GF pm 57 83
result: 0xC1

> crypto -GF inv 53
result: 0xCA
check: 0x53 * 0xCA = 0x01
```

### Возведение в степень по модулю, -ME

Методы: `rlbe` - справа налево, `lrbe` - слева направо, `ml` - лесенка Монтгомери,
`swe` - скользящее окно (ширина 4).

```
> crypto -ME rlbe 15 4947 31
result: 23
> crypto -ME swe 7181 2953 9286
result: 9247
```

### Обратный по модулю, -MI

Методы: `eea` - расширенный Евклид (печатает таблицу хода), `ferma` - `b^(n-2) mod n`, только
для простого n, `gcd` - бинарный алгоритм, только для нечётного n.

```
> crypto -MI eea 7 11
n0           b0           q            r            t0           t            temp
11           7            1            4            0            1            10
7            4            1            3            1            10           2
4            3            1            1            10           2            8
3            1            3            0            2            8            -
result: 8
7 * 8 === 1 (mod 11)

> crypto -MI gcd 1777 2699
result: 1853
1777 * 1853 === 1 (mod 2699)

> crypto -MI ferma 1182 578
crypto: inverse does not exist (gcd != 1)
```

### Дискретный логарифм, -DL (или -Dl)

Ищется наименьшее `x >= 0` с `A^x = B (mod P)`, P простое. Методы: `br` - перебор,
`bsgs` - шаг младенца / шаг великана, `pollard` - ро-метод Полларда, `ph` - Полиг-Хеллман,
`ic` - исчисление индексов (A должен быть первообразным корнем).

```
> crypto -DL bsgs 31 3 29
result: 5
31 ^ 5 === 3 (mod 29)

> crypto -DL ic 2 22 29
result: 26
2 ^ 26 === 22 (mod 29)
```

### Атаки на Виженер с seed (разбор 3.8)

Известный открытый текст - восстанавливается эффективный ключ и период; печатаются все
26 пар (ключ, seed mod 26), которые дают тот же шифротекст:

```
> crypto -ATK kpa IWILLBEHEREONMONDAY FABIAYIABGBSGJDKHTV
period: 5
effective key: XETXP
effective key = key + (seed mod 26), every pair below gives the same ciphertext:
  seed mod 26 =  0 -> key XETXP
  ...
  seed mod 26 = 11 -> key MTIME
  ...
```

Перебор seed при известном ключе (всего 26 вариантов, ранжирование по chi^2):

```
> echo MTIME | crypto -ATK seed FABIAYIABGBSGJDKHTV
key: MTIME
rank 1: seed mod 26 = 11, chi2 =     13.1, plain: IWILLBEHEREONMONDAY
rank 2: seed mod 26 =  4, chi2 =     52.2, plain: PDPSSILOLYLVUTVUKHF
rank 3: seed mod 26 =  7, chi2 =     82.6, plain: MAMPPFILIVISRQSRHEC
result: 11
```

Только шифротекст - период по индексу совпадений (и Касиски, если есть повторы), сдвиги по
chi^2. На 19 буквах статистики нет, поэтому после разбора введённого текста программа
повторяет атаку на встроенном английском тексте (831 буква), зашифрованном с ключом MTIME
и seed 1644485555:

```
> crypto -ATK coa FABIAYIABGBSGJDKHTV
letters: 19
kasiski: no repeated trigrams
period (ioc): 3, ioc = 0.1206
effective key: CWQ
plain: DELGEIGELEFCENNILDT
note: 19 letters is too short for reliable statistics, the result is a guess

demo: built-in English sample, key MTIME, seed 1644485555 (expected effective key XETXP)
cipher: QLX EXPXHON LJ LBROIM TGFXBKV FW TP DIH TP LOMMFCD MMPTIJ TKS CSK JDPX...
letters: 831
kasiski: period 5
period (ioc): 5, ioc = 0.0730
effective key: XETXP
plain: THE HISTORY OF SECRET WRITING IS AS OLD AS WRITING ITSELF AND FOR MOST...
```

### Замер времени

```
> crypto -BENCH
module   method     iterations   total_ms  ns_per_call
GF       pm           33554432      108.0          3.2
...
```

Каждый метод гоняется на векторах из задания, число повторов удваивается, пока замер не
займёт не меньше 100 мс. Таблица с результатами - в `docs/notes.md`.

### Справка

`crypto -h` или `crypto --help`.

## Ошибки и коды возврата

Ошибки печатаются в stderr в виде `crypto: <сообщение>`.

| ситуация | пример | сообщение | код |
|---|---|---|---|
| нет аргументов | `crypto` | `no option and message` | 3 |
| только опция | `crypto -Ecsr` | `no message` | 2 |
| нет опции | `crypto message` | `no option` | 2 |
| неизвестная опция | `crypto -Egdf message` | `illegal option: -Egdf` | 1 |
| лишние строки | `crypto -Ecsr message1 message2` | `to many strings` | 4 |
| не то число аргументов у -GF, -ME, -MI, -DL, -ATK, файловых | `crypto -ME rlbe 15 4947` | `wrong number of arguments for -ME` + подсказка | 4 |
| не число, неверный ключ, неверный hex | `crypto -ME rlbe 1 x 5` | `invalid number: x` | 5 |
| алгоритм не дал ответа | `crypto -MI eea 1182 578` | `inverse does not exist (gcd != 1)` | 6 |

Опции сравниваются целиком через `strcmp`, поэтому `-Dcsr` и `-DL` не путаются.
