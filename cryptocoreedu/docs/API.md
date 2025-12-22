# API.md - Полная документация API криптографической библиотеки


# CryptoCoreEdu API Documentation

Полная документация программного интерфейса криптографической библиотеки CryptoCoreEdu.

## Содержание

- [Обзор](#обзор)
- [Хэш-функции](#хэш-функции)
  - [SHA-256](#sha-256)
  - [SHA3-256](#sha3-256)
- [Коды аутентификации сообщений (MAC)](#коды-аутентификации-сообщений-mac)
  - [HMAC-SHA256](#hmac-sha256)
- [Функции деривации ключей (KDF)](#функции-деривации-ключей-kdf)
  - [PBKDF2](#pbkdf2)
  - [HKDF](#hkdf)
- [Симметричное шифрование](#симметричное-шифрование)
  - [Режим CBC](#режим-cbc)
  - [Режим CFB](#режим-cfb)
  - [Режим CTR](#режим-ctr)
  - [Режим ECB](#режим-ecb)
  - [Режим OFB](#режим-ofb)
  - [Режим GCM](#режим-gcm)
- [Утилиты](#утилиты)
  - [PKCS7 Padding](#pkcs7-padding)
  - [CSPRNG](#csprng)
- [Исключения](#исключения)
- [Примеры использования](#примеры-использования)
- [Рекомендации по безопасности](#рекомендации-по-безопасности)

---

## Обзор

### Структура библиотеки

```
CryptoCoreEdu/
├── cryptocoreedu/         # Исходный код
│   ├── main.py            # Точка входа
│   └── hash/
│       ├──sha3-256.py     # Хэш-функция sha3-256
│       └──sha256.py       # Хэш-функция sha256
│   └── mac/
│       └──hmac.py     # HMAC функция
│   └── kdf/
│       ├──pbkdf2.py   # PBKDF2 реализация
│       └──hkdf.py     # HKDF реализация
│   └── utils/
│       ├── padding.py     # Реализация паддинга по стандрату PKCS7
│       └── validators.py  # Валидаторы для ключей, IV и файлов
│   └── modes/             # Реализации режимов шифрования
│       ├── ECBMode.py        # Режим ECB
│       ├── CBCMode.py        # Режим CBC
│       ├── CFBMode.py        # Режим CFB
│       ├── OFBMode.py        # Режим OFB
│       ├── GCMMode.py        # Режим GCM
│       ├── ETMMode.py        # Режим ETM
│       └── CTRMode.py        # Режим CTR
│   ├── cli_parser.py     # Парсинг аргументов
│   ├── csprng.py         # КСГПСЧ
│   ├── file_io.py        # Работа с файлами и IV
│   ├── exceptions.py     # Кастомные исключения для ошибок
│   └── main.py           # Точка входа в приложение
├── sts-2.1.2/            # Папка с тестами NIST (STS)
├── tests/                # Тесты
│   ├── aead/             # Папка с файлами .txt/.bin
│   ├── plain.txt         # Файл plaintext'а
│   ├── test.txt          # Файл для хэша
│   ├── message.txt       # Файл для HMAC
│   └── test_csprng.py    # Файл для теста уникальности ключа и IV
├── extract_iv.py         # Функция выжимки IV из файлов (для удобства)
├── setup.py              # Файл сборки проекта
├── pyproject.toml        # Файл сборки
└── README.md             # Документация
```

```

### Поддерживаемые алгоритмы

| Категория | Алгоритм | Стандарт |
|-----------|----------|----------|
| Хэширование | SHA-256 | NIST FIPS 180-4 |
| Хэширование | SHA3-256 | NIST FIPS 202 |
| MAC | HMAC-SHA256 | RFC 2104, RFC 4231 |
| KDF | PBKDF2-HMAC-SHA256 | RFC 8018, RFC 6070 |
| KDF | HKDF | RFC 5869 |
| Шифрование | AES-128/192/256 | NIST FIPS 197 |
| Режимы | ECB, CBC, CFB, OFB, CTR | NIST SP 800-38A |
| AEAD | GCM | NIST SP 800-38D |

---

## Хэш-функции

### SHA-256

**Модуль:** `hash.sha256`

**Стандарт:** NIST FIPS 180-4

**Размер выхода:** 256 бит (32 байта)

#### Класс `SHA256`

Реализация хэш-функции SHA-256.

##### Конструктор

```python
SHA256()
```

Создаёт новый объект хэш-функции SHA-256 с начальным состоянием.

##### Атрибуты класса

| Атрибут | Тип | Описание |
|---------|-----|----------|
| `_H0` | `np.ndarray` | Начальные значения хэша (8 × 32-bit слов) |
| `_K` | `np.ndarray` | Константы SHA-256 (64 × 32-bit слов) |

##### Атрибуты экземпляра

| Атрибут | Тип | Описание |
|---------|-----|----------|
| `h` | `np.ndarray` | Текущее хэш-значение |
| `buffer` | `bytearray` | Буфер необработанных данных |
| `total_length` | `int` | Общая длина обработанных данных |
| `finalized` | `bool` | Флаг финализации |

##### Методы

###### `reset()`

```python
def reset(self) -> None
```

Сбрасывает состояние хэш-функции в начальное.

**Пример:**
```python
sha = SHA256()
sha.update(b"data")
sha.reset()  # Состояние сброшено
```

---

###### `update(data)`

```python
def update(self, data: bytes) -> None
```

Добавляет данные для хэширования.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `data` | `bytes` | Данные для добавления в хэш |

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `RuntimeError` | Вызов после финализации (`digest()`) |

**Пример:**
```python
sha = SHA256()
sha.update(b"Hello, ")
sha.update(b"World!")
# Эквивалентно sha.update(b"Hello, World!")
```

---

###### `digest()`

```python
def digest(self) -> bytes
```

Возвращает хэш в виде байтовой строки.

**Возвращает:**

| Тип | Описание |
|-----|----------|
| `bytes` | 32-байтовый хэш SHA-256 |

**Пример:**
```python
sha = SHA256()
sha.update(b"abc")
hash_bytes = sha.digest()
# b'\xbax\x16\xbf\x8f\x01\xcf\xeaAA@\xde]\xae"#...'
```

---

###### `hexdigest()`

```python
def hexdigest(self) -> str
```

Возвращает хэш в виде шестнадцатеричной строки.

**Возвращает:**

| Тип | Описание |
|-----|----------|
| `str` | 64-символьная hex-строка |

**Пример:**
```python
sha = SHA256()
sha.update(b"abc")
hash_hex = sha.hexdigest()
# "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
```

---

#### Функция `sha256_data`

```python
def sha256_data(data: Union[bytes, str]) -> str
```

Вычисляет SHA-256 хэш данных.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `data` | `bytes` или `str` | Данные для хэширования. Строки кодируются в UTF-8 |

**Возвращает:**

| Тип | Описание |
|-----|----------|
| `str` | 64-символьная hex-строка хэша |

**Пример:**
```python
from cryptocoreedu.hash.sha256 import sha256_data

# С байтами
hash1 = sha256_data(b"Hello, World!")

# Со строкой
hash2 = sha256_data("Hello, World!")

# С Unicode
hash3 = sha256_data("Привет, мир!")
```

---

#### Функция `sha256_file`

```python
def sha256_file(filename: str, chunk_size: int = 8192) -> str
```

Вычисляет SHA-256 хэш файла.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `filename` | `str` | — | Путь к файлу |
| `chunk_size` | `int` | `8192` | Размер чанка для чтения (байт) |

**Возвращает:**

| Тип | Описание |
|-----|----------|
| `str` | 64-символьная hex-строка хэша |

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `FileNotFoundError` | Файл не существует |
| `PermissionError` | Нет прав на чтение |
| `IOError` | Ошибка ввода-вывода |

**Пример:**
```python
from cryptocoreedu.hash.sha256 import sha256_file

# Стандартный размер чанка
hash1 = sha256_file("document.pdf")

# Большой размер чанка для больших файлов
hash2 = sha256_file("large_file.iso", chunk_size=1048576)  # 1 MB
```

---

### SHA3-256

**Модуль:** `hash.sha3_256`

**Стандарт:** NIST FIPS 202

**Размер выхода:** 256 бит (32 байта)

**Конструкция:** Keccak sponge (rate=1088 бит, capacity=512 бит)

#### Класс `SHA3_256`

Реализация хэш-функции SHA3-256.

##### Конструктор

```python
SHA3_256()
```

##### Константы класса

| Константа | Значение | Описание |
|-----------|----------|----------|
| `RATE_BITS` | `1088` | Размер rate в битах |
| `RATE_BYTES` | `136` | Размер rate в байтах |
| `CAPACITY_BITS` | `512` | Размер capacity в битах |
| `OUTPUT_BYTES` | `32` | Размер выхода в байтах |
| `DOMAIN_SUFFIX` | `0x06` | Суффикс домена SHA-3 |

##### Атрибуты экземпляра

| Атрибут | Тип | Описание |
|---------|-----|----------|
| `state` | `np.ndarray` | Состояние Keccak (5×5 матрица 64-bit слов) |
| `buffer` | `bytearray` | Буфер необработанных данных |
| `finalized` | `bool` | Флаг финализации |

##### Методы

###### `reset()`

```python
def reset(self) -> None
```

Сбрасывает состояние в начальное (нулевое).

---

###### `update(data)`

```python
def update(self, data: Union[bytes, str]) -> None
```

Добавляет данные для хэширования.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `data` | `bytes` или `str` | Данные. Строки кодируются в UTF-8 |

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `RuntimeError` | Вызов после финализации |

---

###### `digest()`

```python
def digest(self) -> bytes
```

Возвращает хэш в виде байтовой строки.

**Возвращает:** `bytes` — 32-байтовый хэш

---

###### `hexdigest()`

```python
def hexdigest(self) -> str
```

Возвращает хэш в виде hex-строки.

**Возвращает:** `str` — 64-символьная hex-строка

---

###### `copy()`

```python
def copy(self) -> SHA3_256
```

Создаёт копию объекта с текущим состоянием.

**Возвращает:** `SHA3_256` — независимая копия

**Пример:**
```python
sha = SHA3_256()
sha.update(b"Hello")
sha_copy = sha.copy()

sha.update(b" World")
sha_copy.update(b" Python")

# Разные хэши
hash1 = sha.hexdigest()      # SHA3-256("Hello World")
hash2 = sha_copy.hexdigest() # SHA3-256("Hello Python")
```

---

#### Функция `sha3_256_data`

```python
def sha3_256_data(data: Union[bytes, str]) -> str
```

Вычисляет SHA3-256 хэш данных.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `data` | `bytes` или `str` | Данные для хэширования |

**Возвращает:** `str` — 64-символьная hex-строка

**Пример:**
```python
from cryptocoreedu.hash.sha3_256 import sha3_256_data

hash_value = sha3_256_data(b"abc")
# "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
```

---

#### Функция `sha3_256_file`

```python
def sha3_256_file(filename: str, chunk_size: int = 8192) -> str
```

Вычисляет SHA3-256 хэш файла.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `filename` | `str` | — | Путь к файлу |
| `chunk_size` | `int` | `8192` | Размер чанка |

**Возвращает:** `str` — 64-символьная hex-строка

---

## Коды аутентификации сообщений (MAC)

### HMAC-SHA256

**Модуль:** `mac.hmac`

**Стандарт:** RFC 2104, RFC 4231

**Размер выхода:** 256 бит (32 байта)

#### Класс `HMAC`

Реализация HMAC-SHA256.

##### Конструктор

```python
HMAC(key: bytes, hash_class=None)
```

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `key` | `bytes` или `str` | — | Секретный ключ |
| `hash_class` | `class` | `SHA256` | Класс хэш-функции |

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `TypeError` | Ключ не bytes/str |

##### Константы класса

| Константа | Значение | Описание |
|-----------|----------|----------|
| `BLOCK_SIZE` | `64` | Размер блока (байт) |
| `OUTPUT_SIZE` | `32` | Размер выхода (байт) |
| `IPAD_BYTE` | `0x36` | Байт внутреннего padding |
| `OPAD_BYTE` | `0x5c` | Байт внешнего padding |

##### Методы

###### `update(data)`

```python
def update(self, data: bytes) -> HMAC
```

Добавляет данные для аутентификации.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `data` | `bytes`, `bytearray`, `memoryview` или `str` | Данные |

**Возвращает:** `HMAC` — self (для цепочки вызовов)

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `RuntimeError` | Вызов после `digest()` |
| `TypeError` | Неверный тип данных |

**Пример:**
```python
mac = HMAC(b"secret_key")
mac.update(b"message part 1").update(b"message part 2")
```

---

###### `digest()`

```python
def digest(self) -> bytes
```

Возвращает HMAC в виде байтов.

**Возвращает:** `bytes` — 32-байтовый HMAC

---

###### `hexdigest()`

```python
def hexdigest(self) -> str
```

Возвращает HMAC в виде hex-строки.

**Возвращает:** `str` — 64-символьная hex-строка

---

#### Функция `hmac_data`

```python
def hmac_data(key: bytes, data: bytes) -> str
```

Вычисляет HMAC-SHA256 для данных.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `key` | `bytes` или `str` | Секретный ключ |
| `data` | `bytes` или `str` | Данные |

**Возвращает:** `str` — 64-символьная hex-строка

**Пример:**
```python
from cryptocoreedu.mac.hmac import hmac_data

mac = hmac_data(b"key", b"message")
```

---

#### Функция `hmac_file`

```python
def hmac_file(key: bytes, filename: str, chunk_size: int = 8096) -> str
```

Вычисляет HMAC-SHA256 для файла.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `key` | `bytes` или `str` | — | Секретный ключ |
| `filename` | `str` | — | Путь к файлу |
| `chunk_size` | `int` | `8096` | Размер чанка |

**Возвращает:** `str` — 64-символьная hex-строка

---

#### Функция `verify_hmac`

```python
def verify_hmac(expected_hmac: str, computed_hmac: str) -> bool
```

Проверяет HMAC с защитой от timing-атак.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `expected_hmac` | `str` | Ожидаемый HMAC |
| `computed_hmac` | `str` | Вычисленный HMAC |

**Возвращает:** `bool` — `True` если совпадают

**Примечание:** Использует сравнение с постоянным временем (constant-time comparison).

**Пример:**
```python
from cryptocoreedu.mac.hmac import hmac_data, verify_hmac

expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
computed = hmac_data(b"Jefe", b"what do ya want for nothing?")

if verify_hmac(expected, computed):
    print("HMAC valid")
else:
    print("HMAC invalid - data may be tampered")
```

---

#### Функция `parse_hmac_file`

```python
def parse_hmac_file(filepath: str) -> Tuple[str, Optional[str]]
```

Парсит файл с HMAC.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `filepath` | `str` | Путь к файлу с HMAC |

**Возвращает:** `Tuple[str, Optional[str]]` — (hmac_value, filename или None)

**Формат файла:**
```
<hmac_hex> [filename]
```

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `ValueError` | Пустой файл или неверный формат |

---

## Функции деривации ключей (KDF)

### PBKDF2

**Модуль:** `kdf.pbkdf2`

**Стандарт:** RFC 8018, RFC 6070

**PRF:** HMAC-SHA256

#### Функция `pbkdf2_hmac_sha256`

```python
def pbkdf2_hmac_sha256(
    password: Union[bytes, str],
    salt: Union[bytes, str],
    iterations: int,
    dklen: int
) -> bytes
```

Реализация PBKDF2 с HMAC-SHA256.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `password` | `bytes` или `str` | Пароль |
| `salt` | `bytes` или `str` | Соль (hex-строка или UTF-8) |
| `iterations` | `int` | Количество итераций (≥ 1) |
| `dklen` | `int` | Длина выходного ключа (байт) |

**Возвращает:** `bytes` — Производный ключ

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `ValueError` | `iterations < 1` или `dklen < 1` |
| `ValueError` | `dklen > (2^32 - 1) * 32` |

**Пример:**
```python
from cryptocoreedu.kdf.pbkdf2 import pbkdf2_hmac_sha256

# RFC 7914 тест-вектор
key = pbkdf2_hmac_sha256(
    password=b"passwd",
    salt=b"salt",
    iterations=1,
    dklen=64
)
```

**Рекомендации:**
- Минимум 100,000 итераций для паролей
- Уникальная соль (минимум 16 байт) для каждого пароля
- Используйте CSPRNG для генерации соли

---

#### Класс `PBKDF2`

Объектно-ориентированный интерфейс для PBKDF2.

##### Конструктор

```python
PBKDF2(
    password: Union[bytes, str],
    salt: bytes = None,
    iterations: int = None
)
```

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `password` | `bytes` или `str` | — | Пароль |
| `salt` | `bytes` | Случайные 16 байт | Соль |
| `iterations` | `int` | `100000` | Количество итераций |

##### Константы класса

| Константа | Значение | Описание |
|-----------|----------|----------|
| `DEFAULT_ITERATIONS` | `100000` | Итерации по умолчанию |
| `DEFAULT_KEY_LENGTH` | `32` | Длина ключа по умолчанию |
| `HASH_OUTPUT_SIZE` | `32` | Размер выхода SHA-256 |

##### Методы

###### `derive(length)`

```python
def derive(self, length: int = None) -> bytes
```

Деривирует ключ из пароля.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `length` | `int` | `32` | Длина ключа |

**Возвращает:** `bytes` — Производный ключ

---

###### `derive_hex(length)`

```python
def derive_hex(self, length: int = None) -> str
```

Деривирует ключ и возвращает в hex-формате.

**Возвращает:** `str` — Hex-строка ключа

---

**Пример:**
```python
from cryptocoreedu.kdf.pbkdf2 import PBKDF2

# Автоматическая генерация соли
pbkdf = PBKDF2("my_password")
key = pbkdf.derive(32)
salt = pbkdf.salt  # Сохраните для последующей верификации

# С явной солью
pbkdf2 = PBKDF2("password", salt=stored_salt, iterations=150000)
key2 = pbkdf2.derive()
```

---

### HKDF

**Модуль:** `kdf.hkdf`

**Стандарт:** RFC 5869 (упрощённая версия)

**PRF:** HMAC-SHA256

#### Функция `derive_key`

```python
def derive_key(
    master_key: bytes,
    context: str,
    length: int = 32
) -> bytes
```

Деривирует ключ из мастер-ключа с использованием контекста.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `master_key` | `bytes` | — | Мастер-ключ |
| `context` | `str` | — | Контекст/метка |
| `length` | `int` | `32` | Длина выходного ключа |

**Возвращает:** `bytes` — Производный ключ

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `ValueError` | Пустой мастер-ключ или `length < 1` |

**Пример:**
```python
from cryptocoreedu.kdf.hkdf import derive_key

master = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")

encryption_key = derive_key(master, "encryption", 32)
mac_key = derive_key(master, "authentication", 32)
```

---

#### Класс `KeyHierarchy`

Иерархическая деривация ключей с кэшированием.

##### Конструктор

```python
KeyHierarchy(master_key: bytes)
```

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `master_key` | `bytes` или `str` | Мастер-ключ (hex или UTF-8) |

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `ValueError` | Пустой мастер-ключ |

##### Константы класса

| Константа | Значение | Описание |
|-----------|----------|----------|
| `DEFAULT_KEY_LENGTH` | `32` | Длина ключа по умолчанию |

##### Методы

###### `derive(context, length, cache)`

```python
def derive(
    self,
    context: str,
    length: int = None,
    cache: bool = True
) -> bytes
```

Деривирует ключ по контексту.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `context` | `str` | — | Контекст/метка |
| `length` | `int` | `32` | Длина ключа |
| `cache` | `bool` | `True` | Кэшировать результат |

**Возвращает:** `bytes` — Производный ключ

---

###### `derive_hex(context, length)`

```python
def derive_hex(self, context: str, length: int = None) -> str
```

Деривирует ключ и возвращает в hex-формате.

---

###### `clear_cache()`

```python
def clear_cache(self) -> None
```

Очищает кэш производных ключей.

**Примечание по безопасности:** Вызывайте после использования для очистки чувствительных данных из памяти.

---

**Пример:**
```python
from cryptocoreedu.kdf.hkdf import KeyHierarchy

# Создание иерархии
hierarchy = KeyHierarchy(b"master_secret_key_256_bits_long!")

# Деривация разных ключей
file_encryption_key = hierarchy.derive("file_encryption")
database_key = hierarchy.derive("database_encryption")
api_key = hierarchy.derive("api_authentication", length=64)

# Hex-формат для конфигурации
config_key = hierarchy.derive_hex("config")

# Очистка после использования
hierarchy.clear_cache()
```

---

## Симметричное шифрование

### Общие сведения

Все режимы шифрования используют AES (Advanced Encryption Standard) согласно NIST FIPS 197.

**Поддерживаемые размеры ключей:**
- AES-128: 16 байт (128 бит)
- AES-192: 24 байта (192 бита)
- AES-256: 32 байта (256 бит)

**Размер блока:** 16 байт (128 бит)

---

### Режим CBC

**Модуль:** `symmetric.modes.CBCMode`

**Стандарт:** NIST SP 800-38A

**Padding:** PKCS#7

#### Класс `CBCMode`

Cipher Block Chaining — режим сцепления блоков.

##### Конструктор

```python
    CBCMode(key: bytes)
```

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `key` | `bytes` | Ключ AES (16, 24 или 32 байта) |

##### Константы

| Константа | Значение | Описание |
|-----------|----------|----------|
| `BLOCK_SIZE` | `16` | Размер блока AES |

##### Методы

###### `encrypt_file(input_file, output_file)`

```python
def encrypt_file(self, input_file: Path, output_file: Path) -> None
```

Шифрует файл в режиме CBC.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `input_file` | `Path` | Путь к исходному файлу |
| `output_file` | `Path` | Путь к зашифрованному файлу |

**Формат выходного файла:**
```
[IV: 16 байт][Зашифрованные данные с PKCS7 padding]
```

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `CryptoOperationError` | Ошибка ввода-вывода или шифрования |

---

###### `decrypt_file(input_file, output_file, iv)`

```python
    def decrypt_file(
        self,
        input_file: Path,
        output_file: Path,
        iv: bytes = None
    ) -> None
```

Дешифрует файл в режиме CBC.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `input_file` | `Path` | — | Зашифрованный файл |
| `output_file` | `Path` | — | Выходной файл |
| `iv` | `bytes` | `None` | IV (если `None`, извлекается из файла) |

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `CryptoOperationError` | Файл слишком короткий |
| `CryptoOperationError` | Некорректный размер шифртекста |
| `CryptoOperationError` | Ошибка padding (возможно неверный ключ) |

---

**Пример:**
```python
from cryptocoreedu.modes.CBCMode import CBCMode
from pathlib import Path

key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
cbc = CBCMode(key)

# Шифрование
cbc.encrypt_file(Path("secret.txt"), Path("secret.enc"))

# Дешифрование (IV из файла)
cbc.decrypt_file(Path("secret.enc"), Path("secret_decrypted.txt"), iv=None)

# Дешифрование с явным IV
iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
cbc.decrypt_file(Path("data.enc"), Path("data.txt"), iv=iv)
```

---

### Режим CFB

**Модуль:** `symmetric.modes.CFBMode`

**Стандарт:** NIST SP 800-38A (CFB-128)

**Padding:** Не требуется (потоковый режим)

#### Класс `CFBMode`

Cipher Feedback — режим обратной связи по шифртексту.

##### Конструктор

```python
    CFBMode(key: bytes)
```

##### Методы

###### `encrypt_file(input_file, output_file)`

```python
def encrypt_file(self, input_file: Path, output_file: Path) -> None
```

Шифрует файл в режиме CFB.

**Формат выхода:**
```
[IV: 16 байт][Шифртекст (той же длины, что и открытый текст)]
```

---

###### `decrypt_file(input_file, output_file, iv)`

```python
    def decrypt_file(
        self,
        input_file: Path,
        output_file: Path,
        iv: bytes = None
    ) -> None
```

Дешифрует файл в режиме CFB.

---

**Особенности CFB:**
- Потоковый режим — выход той же длины, что и вход
- Ошибка в одном бите шифртекста влияет на текущий и следующий блоки
- Самосинхронизирующийся (после повреждения восстанавливается через 1 блок)

**Пример:**
```python
from cryptocoreedu.modes.CFBMode import CFBMode
from pathlib import Path

key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
cfb = CFBMode(key)

cfb.encrypt_file(Path("data.bin"), Path("data.enc"))
cfb.decrypt_file(Path("data.enc"), Path("data_dec.bin"), iv=None)
```

---

### Режим CTR

**Модуль:** `symmetric.modes.CTRMode`

**Стандарт:** NIST SP 800-38A

**Padding:** Не требуется (потоковый режим)

#### Класс `CTRMode`

Counter Mode — режим счётчика.

##### Конструктор

```python
    CTRMode(key: bytes)
```

##### Методы

###### `_increment_counter(counter)`

```python
def _increment_counter(self, counter: bytes) -> bytes
```

Инкрементирует 128-битный счётчик.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `counter` | `bytes` | 16-байтный счётчик |

**Возвращает:** `bytes` — Увеличенный счётчик

---

###### `encrypt_file(input_file, output_file)`

```python
def encrypt_file(self, input_file: Path, output_file: Path) -> None
```

**Формат выхода:**
```
[Nonce/IV: 16 байт][Шифртекст]
```

---

###### `decrypt_file(input_file, output_file, iv)`

```python
    def decrypt_file(
        self,
        input_file: Path,
        output_file: Path,
        iv: bytes = None
    ) -> None
```

---

**Особенности CTR:**
- Потоковый режим — шифрование = дешифрование (XOR с keystream)
- Параллелизуемый (блоки независимы)
- Ошибка в одном бите влияет только на этот бит
- **КРИТИЧНО:** Никогда не используйте один nonce дважды с одним ключом!

**Пример:**
```python
from cryptocoreedu.modes.CTRMode import CTRMode
from pathlib import Path

key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
ctr = CTRMode(key)

ctr.encrypt_file(Path("video.mp4"), Path("video.enc"))
ctr.decrypt_file(Path("video.enc"), Path("video_dec.mp4"), iv=None)
```

---

### Режим ECB

**Модуль:** `symmetric.modes.ECBMode`

**Стандарт:** NIST SP 800-38A

**Padding:** PKCS#7

#### Класс `ECBMode`

Electronic Codebook — режим электронной кодовой книги.

##### Конструктор

```python
    ECBMode(key: bytes)
```

##### Методы

###### `encrypt_file(input_file, output_file)`

```python
def encrypt_file(self, input_file: Path, output_file: Path) -> None
```

###### `decrypt_file(input_file, output_file)`

```python
def decrypt_file(self, input_file: Path, output_file: Path) -> None
```

---

**ПРЕДУПРЕЖДЕНИЕ О БЕЗОПАСНОСТИ:**

ECB режим **НЕ РЕКОМЕНДУЕТСЯ** для шифрования данных:
- Одинаковые блоки открытого текста дают одинаковые блоки шифртекста
- Утечка паттернов данных
- Подвержен атакам с подменой блоков

**Используйте только для:**
- Шифрования одиночных блоков (например, ключей)
- Образовательных целей
- Тестирования

**Пример (только для демонстрации):**
```python
from cryptocoreedu..modes.ECBMode import ECBMode
from pathlib import Path

# НЕ ИСПОЛЬЗУЙТЕ ДЛЯ РЕАЛЬНЫХ ДАННЫХ!
key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
ecb = ECBMode(key)

ecb.encrypt_file(Path("test.txt"), Path("test.enc"))
ecb.decrypt_file(Path("test.enc"), Path("test_dec.txt"))
```

---

### Режим OFB

**Модуль:** `symmetric.modes.OFBMode`

**Стандарт:** NIST SP 800-38A

**Padding:** Не требуется (потоковый режим)

#### Класс `OFBMode`

Output Feedback — режим обратной связи по выходу.

##### Конструктор

```python
    OFBMode(key: bytes)
```

##### Методы

###### `encrypt_file(input_file, output_file)`

```python
def encrypt_file(self, input_file: Path, output_file: Path) -> None
```

**Формат выхода:**
```
[IV: 16 байт][Шифртекст]
```

###### `decrypt_file(input_file, output_file, iv)`

```python
    def decrypt_file(
        self,
        input_file: Path,
        output_file: Path,
        iv: bytes = None
    ) -> None
```

---

**Особенности OFB:**
- Потоковый режим
- Keystream можно предвычислить (до получения данных)
- Ошибка в одном бите влияет только на этот бит
- Не самосинхронизирующийся

---

### Режим GCM

**Модуль:** `symmetric.modes.GCMMode`

**Стандарт:** NIST SP 800-38D

**Тип:** AEAD (Authenticated Encryption with Associated Data)

#### Класс `GCMMode`

Galois/Counter Mode — режим с аутентификацией.

##### Конструктор

```python
    GCMMode(key: bytes)
```

##### Константы

| Константа | Значение | Описание |
|-----------|----------|----------|
| `BLOCK_SIZE` | `16` | Размер блока |
| `NONCE_SIZE` | `12` | Рекомендуемый размер nonce |
| `TAG_SIZE` | `16` | Размер тега аутентификации |

##### Методы

###### `encrypt_file(input_file, output_file, aad)`

```python
    def encrypt_file(
        self,
        input_file: Path,
        output_file: Path,
        aad: bytes = None
    ) -> None
```

Шифрует файл с аутентификацией.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `input_file` | `Path` | — | Исходный файл |
| `output_file` | `Path` | — | Зашифрованный файл |
| `aad` | `bytes` | `None` | Additional Authenticated Data |

**Формат выхода:**
```
[Nonce: 12 байт][Шифртекст][Tag: 16 байт]
```

---

###### `decrypt_file(input_file, output_file, aad, nonce)`

```python
    def decrypt_file(
        self,
        input_file: Path,
        output_file: Path,
        aad: bytes = None,
        nonce: bytes = None
    ) -> None
```

Дешифрует и проверяет аутентичность.

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `CryptoOperationError` | Ошибка аутентификации (тег не совпадает) |
| `CryptoOperationError` | Неверный AAD |

---

**Особенности GCM:**
- Обеспечивает конфиденциальность И целостность
- AAD аутентифицируется, но не шифруется
- Параллелизуемый
- **КРИТИЧНО:** Уникальный nonce для каждого сообщения!

**Пример:**
```python
from cryptocoreedu.modes.GCMMode import GCMMode
from pathlib import Path

key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
gcm = GCMMode(key)

# Шифрование с AAD
aad = b"file_id:12345,timestamp:1699999999"
gcm.encrypt_file(Path("secret.doc"), Path("secret.enc"), aad=aad)

# Дешифрование (должен быть тот же AAD!)
try:
    gcm.decrypt_file(Path("secret.enc"), Path("secret_dec.doc"), aad=aad)
    print("Decryption successful, data authenticated")
except CryptoOperationError as e:
    print(f"Authentication failed: {e}")
```

---

## Утилиты

### PKCS7 Padding

**Модуль:** `utils`

**Стандарт:** RFC 5652

#### Класс `PKCS7Padding`

Реализация PKCS#7 padding для блочных шифров.

##### Методы класса

###### `pad(data, block_size)`

```python
@staticmethod
def pad(data: bytes, block_size: int = 16) -> bytes
```

Добавляет PKCS#7 padding.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `data` | `bytes` | — | Данные |
| `block_size` | `int` | `16` | Размер блока (1-255) |

**Возвращает:** `bytes` — Данные с padding

**Алгоритм:**
- Если длина кратна block_size, добавляется полный блок padding
- Каждый байт padding = количество добавленных байт

**Пример:**
```python
from cryptocoreedu.utils import PKCS7Padding

# 11 байт -> добавляется 5 байт (0x05)
padded = PKCS7Padding.pad(b"Hello World", 16)
# b'Hello World\x05\x05\x05\x05\x05'

# 16 байт -> добавляется 16 байт (0x10)
padded = PKCS7Padding.pad(b"0123456789ABCDEF", 16)
# b'0123456789ABCDEF\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
```

---

###### `unpad(data, block_size)`

```python
@staticmethod
def unpad(data: bytes, block_size: int = 16) -> bytes
```

Удаляет PKCS#7 padding.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `data` | `bytes` | — | Данные с padding |
| `block_size` | `int` | `16` | Размер блока |

**Возвращает:** `bytes` — Данные без padding

**Исключения:**

| Исключение | Условие |
|------------|---------|
| `ValueError` | Пустые данные |
| `ValueError` | Длина не кратна block_size |
| `ValueError` | Некорректный padding |

---

### CSPRNG

**Модуль:** `csprng`

Криптографически стойкий генератор псевдослучайных чисел.

#### Функция `generate_random_bytes`

```python
def generate_random_bytes(length: int) -> bytes
```

Генерирует криптографически стойкие случайные байты.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `length` | `int` | Количество байт |

**Возвращает:** `bytes` — Случайные байты

**Использует:** `os.urandom()` (системный CSPRNG)

**Пример:**
```python
from cryptocoreedu.csprng import generate_random_bytes

# 256-битный ключ
key = generate_random_bytes(32)

# 128-битный IV
iv = generate_random_bytes(16)

# 128-битная соль для PBKDF2
salt = generate_random_bytes(16)
```

---

## Исключения

### CryptoOperationError

**Модуль:** `exceptions`

```python
class CryptoOperationError(Exception):
    """Исключение для криптографических операций."""
    pass
```

Базовое исключение для всех ошибок криптографических операций.

**Когда возникает:**
- Ошибки ввода-вывода при работе с файлами
- Некорректные параметры (длина ключа, IV)
- Ошибки padding
- Ошибки аутентификации (GCM)
- Файл слишком короткий

**Пример обработки:**
```python
from cryptocoreedu.exceptions import CryptoOperationError
from cryptocoreedu.modes.GCMMode import GCMMode

try:
    gcm = GCMMode(key)
    gcm.decrypt_file(encrypted_file, output_file, aad=aad)
except CryptoOperationError as e:
    if "аутентификац" in str(e).lower():
        print("Данные повреждены или подделаны!")
    elif "короткий" in str(e).lower():
        print("Файл повреждён или неполный")
    else:
        print(f"Ошибка: {e}")
```

---

## Примеры использования

### Шифрование файла с аутентификацией

```python
from cryptocoreedu.modes.GCMMode import GCMMode
from cryptocoreedu.kdf.pbkdf2 import PBKDF2
from cryptocoreedu.csprng import generate_random_bytes
from pathlib import Path

def encrypt_file_with_password(input_path: str, output_path: str, password: str):
    """Шифрует файл с использованием пароля."""
    
    # Генерируем соль
    salt = generate_random_bytes(16)
    
    # Деривируем ключ из пароля
    pbkdf = PBKDF2(password, salt=salt, iterations=100000)
    key = pbkdf.derive(32)  # AES-256
    
    # Шифруем
    gcm = GCMMode(key)
    
    # Добавляем метаданные в AAD
    aad = f"encrypted_by:CryptoCoreEdu,version:1.0".encode()
    
    # Временный файл для шифрования
    temp_encrypted = Path(output_path + ".tmp")
    gcm.encrypt_file(Path(input_path), temp_encrypted, aad=aad)
    
    # Записываем финальный файл: [salt][encrypted_data]
    with open(temp_encrypted, 'rb') as f:
        encrypted_data = f.read()
    
    with open(output_path, 'wb') as f:
        f.write(salt)
        f.write(encrypted_data)
    
    temp_encrypted.unlink()
    print(f"Файл зашифрован: {output_path}")


def decrypt_file_with_password(input_path: str, output_path: str, password: str):
    """Дешифрует файл с использованием пароля."""
    
    with open(input_path, 'rb') as f:
        salt = f.read(16)
        encrypted_data = f.read()
    
    # Деривируем ключ
    pbkdf = PBKDF2(password, salt=salt, iterations=100000)
    key = pbkdf.derive(32)
    
    # Записываем временный файл
    temp_encrypted = Path(input_path + ".tmp")
    with open(temp_encrypted, 'wb') as f:
        f.write(encrypted_data)
    
    # Дешифруем
    gcm = GCMMode(key)
    aad = f"encrypted_by:CryptoCoreEdu,version:1.0".encode()
    
    try:
        gcm.decrypt_file(temp_encrypted, Path(output_path), aad=aad)
        print(f"Файл расшифрован: {output_path}")
    finally:
        temp_encrypted.unlink()
```

---

### Безопасное хранение паролей

```python
from cryptocoreedu.kdf.pbkdf2 import pbkdf2_hmac_sha256
from cryptocoreedu.csprng import generate_random_bytes
from cryptocoreedu.mac.hmac import verify_hmac

def hash_password(password: str) -> dict:
    """Создаёт безопасный хэш пароля."""
    salt = generate_random_bytes(16)
    iterations = 150000
    
    hash_bytes = pbkdf2_hmac_sha256(
        password=password,
        salt=salt,
        iterations=iterations,
        dklen=32
    )
    
    return {
        "salt": salt.hex(),
        "iterations": iterations,
        "hash": hash_bytes.hex()
    }


def verify_password(password: str, stored: dict) -> bool:
    """Проверяет пароль против сохранённого хэша."""
    salt = bytes.fromhex(stored["salt"])
    iterations = stored["iterations"]
    expected_hash = stored["hash"]
    
    computed_hash = pbkdf2_hmac_sha256(
        password=password,
        salt=salt,
        iterations=iterations,
        dklen=32
    ).hex()
    
    # Используем timing-safe сравнение
    return verify_hmac(expected_hash, computed_hash)


# Использование
stored_password = hash_password("my_secret_password")
# Сохраняем stored_password в базу данных

# При входе пользователя
if verify_password("my_secret_password", stored_password):
    print("Пароль верный!")
else:
    print("Неверный пароль!")
```

---

### Иерархия ключей для приложения

```python
from cryptocoreedu.kdf.hkdf import KeyHierarchy
from cryptocoreedu.csprng import generate_random_bytes

class ApplicationKeys:
    """Управление ключами приложения."""
    
    def __init__(self, master_secret: bytes):
        self.hierarchy = KeyHierarchy(master_secret)
    
    def get_database_key(self) -> bytes:
        """Ключ для шифрования базы данных."""
        return self.hierarchy.derive("database_encryption", length=32)
    
    def get_session_key(self, session_id: str) -> bytes:
        """Ключ для конкретной сессии."""
        return self.hierarchy.derive(f"session:{session_id}", length=32, cache=False)
    
    def get_file_encryption_key(self) -> bytes:
        """Ключ для шифрования файлов."""
        return self.hierarchy.derive("file_encryption", length=32)
    
    def get_api_signing_key(self) -> bytes:
        """Ключ для подписи API запросов."""
        return self.hierarchy.derive("api_signing", length=64)
    
    def cleanup(self):
        """Очистка ключей из памяти."""
        self.hierarchy.clear_cache()


# Использование
master = generate_random_bytes(32)  # Хранится безопасно!
app_keys = ApplicationKeys(master)

db_key = app_keys.get_database_key()
session_key = app_keys.get_session_key("user123_1699999999")

# После использования
app_keys.cleanup()
```

---

## Рекомендации по безопасности

### Общие рекомендации

1. **Ключи:**
   - Генерируйте ключи с помощью CSPRNG
   - Используйте ключи достаточной длины (минимум 128 бит)
   - Храните ключи безопасно
   - Регулярно ротируйте ключи

2. **IV/Nonce:**
   - Всегда генерируйте случайный IV для каждого шифрования
   - НИКОГДА не используйте один nonce дважды с одним ключом в CTR/GCM
   - Для GCM: используйте 12-байтный nonce

3. **Пароли:**
   - Используйте PBKDF2 с минимум 100,000 итераций
   - Уникальная соль для каждого пароля
   - Увеличивайте итерации по мере роста производительности оборудования

4. **Режимы шифрования:**
   - Не используйте ECB для данных длиннее одного блока
   - Предпочитайте GCM для конфиденциальности + целостности
   - При использовании CBC/CFB/CTR добавляйте HMAC для аутентификации

5. **Обработка ошибок:**
   - Не раскрывайте детали криптографических ошибок
   - Используйте generic сообщения об ошибках
   - Логируйте ошибки безопасно

### Уязвимости и защита

| Уязвимость | Защита |
|------------|--------|
| Timing attacks | Constant-time сравнение (verify_hmac) |
| Padding oracle | Используйте AEAD (GCM) |
| Nonce reuse | Случайный nonce для каждого сообщения |
| Weak passwords | PBKDF2 с высоким числом итераций |
| Key leakage | Очистка памяти (clear_cache) |

### Соответствие стандартам

| Компонент | Стандарт           |
|-----------|--------------------|
| AES | NIST FIPS 197      |
| SHA-256 | NIST FIPS 180-4    |
| SHA3-256 | NIST FIPS 202      |
| HMAC | RFC 2104, RFC 4231 |
| PBKDF2 | RFC 6070-SHA256    |
| CBC/CTR/GCM | NIST SP 800-38A/D  |

---

## Changelog

### Version 1.0.0
- Initial release
- SHA-256, SHA3-256 hash functions
- HMAC-SHA256
- PBKDF2-HMAC-SHA256
- HKDF
- AES modes: ECB, CBC, CFB, OFB, CTR, GCM
- PKCS7 padding
- CSPRNG

---

```

Этот API.md содержит:
- Полное описание всех модулей и классов
- Параметры и типы для каждого метода
- Возвращаемые значения и исключения
- Примеры использования
- Рекомендации по безопасности
- Таблицы соответствия стандартам