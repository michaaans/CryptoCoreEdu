# CryptoCoreEdu

**CryptoCoreEdu** — утилита командной строки для блочного шифрования файлов с использованием AES-128 в различных режимах работы. Проект разработан в образовательных целях для демонстрации принципов работы блочных шифров.

## Установка

### Способ 1: Установка из PyPI (рекомендуется)
```bash
# Установите пакет
pip install cryptocoreedu

# Или конкретной версии
pip install cryptocoreedu==0.2.3
```

### Способ 2: Установка из исходного кода
```bash
# Клонируйте репозиторий
git clone https://github.com/michaaans/CryptoCoreEdu.git
cd CryptoCoreEdu

# Установите в режиме разработки
pip install -e .
```

## Проверка установки
### Windows (PowerShell)

```shell
# Проверьте что пакет установился (Windows)
pip list | findstr cryptocoreedu

# Проверьте работу утилиты
crypto --help 
# или 
crypto -h
```

### Linux/macOS/WSL (Bash)

```bash
# Проверьте что пакет установился
pip list | grep cryptocoreedu

# Проверьте работу утилиты
crypto --help
```

## Использование

### Поддерживаемые режимы
* ECB (Electronic Codebook) - базовый режим, требует паддинг

* CBC (Cipher Block Chaining) - блочный режим с цепочкой, требует паддинг

* CFB (Cipher Feedback) - потоковый режим, без паддинга

* OFB (Output Feedback) - потоковый режим, без паддинга

* CTR (Counter) - потоковый режим, без паддинга

### Базовые команды шифрования

```shell
# ECB режим (без IV)
crypto -alg aes -m ecb -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# CBC режим (IV генерируется автоматически)
crypto -alg aes -m cbc -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# CFB режим (потоковый)
crypto -alg aes -m cfb -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# OFB режим (потоковый)  
crypto -alg aes -m ofb -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# CTR режим (потоковый)
crypto -alg aes -m ctr -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc
```

```bash
# ECB режим (без IV)
crypto -alg aes -m ecb -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# CBC режим (IV генерируется автоматически)
crypto -alg aes -m cbc -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# CFB режим (потоковый)
crypto -alg aes -m cfb -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# OFB режим (потоковый)
crypto -alg aes -m ofb -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# CTR режим (потоковый)
crypto -alg aes -m ctr -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc
```

### Базовые команды дешифрования

```shell
# ECB режим (без IV)
crypto -alg aes -m ecb -dec -k 000102030405060708090a0b0c0d0e0f -i tests/document.enc -o tests/document_decrypted.txt

# CBC режим (IV извлекается из файла)
crypto -alg aes -m cbc -dec -k 000102030405060708090a0b0c0d0e0f -i tests/document.enc -o tests/document_decrypted.txt

# CBC режим (IV передается явно)
crypto -alg aes -m cbc -dec -k 000102030405060708090a0b0c0d0e0f --iv AABBCCDDEEFF00112233445566778899 -i tests/document.enc -o tests/document_decrypted.txt

# Потоковые режимы (CFB, OFB, CTR) - аналогично CBC
crypto -alg aes -m cfb -dec -k 000102030405060708090a0b0c0d0e0f -i tests/document.enc -o tests/document_decrypted.txt
```

```bash
# ECB режим (без IV)
crypto -alg aes -m ecb -dec -k 000102030405060708090a0b0c0d0e0f -i tests/document.enc -o tests/document_decrypted.txt

# CBC режим (IV извлекается из файла)
crypto -alg aes -m cbc -dec -k 000102030405060708090a0b0c0d0e0f -i tests/document.enc -o tests/document_decrypted.txt

# CBC режим (IV передается явно)
crypto -alg aes -m cbc -dec -k 000102030405060708090a0b0c0d0e0f --iv AABBCCDDEEFF00112233445566778899 -i tests/document.enc -o tests/document_decrypted.txt

# Потоковые режимы (CFB, OFB, CTR) - аналогично CBC
crypto -alg aes -m cfb -dec -k 000102030405060708090a0b0c0d0e0f -i tests/document.enc -o tests/document_decrypted.txt
```

### Параметры командной строки
- `--algorithm (-alg)`: Алгоритм шифрования (`aes`)
- `--mode (-m)`: Режим работы (`ecb`, `cbc`, `cfb`, `ofb`, `ctr`)  
- `--encrypt (-enc)`: Режим шифрования
- `--decrypt (-dec)`: Режим дешифрования
- `--key (-k)`: Ключ шифрования (16 байт в hex-формате)
- `--iv`: Вектор инициализации (16 байт в hex-формате; только в режиме дешифрования)
- `--input (-i)`: Входной файл
- `--output (-o)`: Выходной файл

### Тестирование совместимости с OpenSSL

```bash
# 1. Шифруем своим инструментом
crypto -alg aes -m cbc -enc -k 000102030405060708090a0b0c0d0e0f -i tests/plain.txt -o tests/cipher.bin

# 2. Извлекаем IV и ciphertext
dd if=tests/cipher.bin of=tests/iv.bin bs=16 count=1
dd if=tests/cipher.bin of=tests/ciphertext_only.bin bs=16 skip=1
tests/
# 3. Дешифруем с OpenSSL
openssl enc -aes-128-cbc -d -K 000102030405060708090A0B0C0D0E0F -iv $(xxd -p tests/iv.bin | tr -d '\n') -in tests/ciphertext_only.bin -out tests/decrypted.txt

# 4. Проверяем
diff -s tests/plain.txt tests/decrypted.txt

# В выводе увидим: Files tests/plain.txt and tests/decrypted.txt are identical
```

```bash
# 1. Шифруем с OpenSSL
openssl enc -aes-128-cbc -K 000102030405060708090A0B0C0D0E0F -iv AABBCCDDEEFF00112233445566778899 -in tests/plain.txt -out tests/openssl_cipher.bin

# 2. Дешифруем своим инструментом
crypto -alg aes -m cbc -dec -k 000102030405060708090a0b0c0d0e0f --iv AABBCCDDEEFF00112233445566778899 -i tests/openssl_cipher.bin -o tests/decrypted.txt

# 3. Проверяем
diff -s tests/plain.txt tests/decrypted.txt

# В выводе увидим: Files tests/plain.txt and tests/decrypted.txt are identical
```

### Команды OpenSSL для разных режимов
* #### CBC: openssl enc -aes-128-ecb

* #### CBC: openssl enc -aes-128-cbc

* #### CFB: openssl enc -aes-128-cfb

* #### OFB: openssl enc -aes-128-ofb

* #### CTR: openssl enc -aes-128-ctr


## Структура проекта

```
CryptoCoreEdu/
├── cryptocoreedu/                  # Исходный код
│   ├── main.py           # Точка входа
│   └── utils/
│       ├── padding.py     # Реализация паддинга по стандрату PKCS7
│       ├── validators.py  # Валидаторы для ключей, IV и файлов
│   └── modes/            # Реализации режимов шифрования
│       ├── ECBMode.py        # Режим ECB
│       ├── CBCMode.py        # Режим CBC
│       ├── CFBMode.py        # Режим CFB
│       ├── OFBMode.py        # Режим OFB
│       └── CTRMode.py        # Режим CTR
│   ├── cli_parser.py     # Парсинг аргументов
│   ├── file_io.py        # Работа с файлами и IV
│   ├── exceptions.py     # Кастомные исключения для ошибок
│   ├── main.py           # Точка входа в приложение
├── tests/                # Тесты
│   └── plain.txt         # Файл plaintext'а
├── extract_iv.py         # Функция выжимки IV из файлов (для удобства)
├── setup.py              # Файл сборки проекта
├── pyproject.toml        # Файл сборки
└── README.md             # Документация
```

## Требования

### Зависимости
- **Python** 3.8 или выше
- **pycryptodome** 3.23.0 или выше
- **OpenSSL** (для тестирования совместимости)

### Размер ключа и IV
Ключ должен быть ровно **16 байт** (32 hex-символа):
```
Правильно: 000102030405060708090a0b0c0d0e0f
Неправильно: mykey123 (8 байт)
```
IV должен быть ровно **16 байт** (32 hex-символа):
```
Правильно: AABBCCDDEEFF00112233445566778899
Неправильно: ASFSAFSA909DAS9DA99129129DNNBN
```


## Проверка целостности

Для проверки корректности работы утилиты:

```bash
diff -s tests/plain.txt tests/decrypted.txt

# Вывод при успешной работе утилиты: Files tests/plain.txt and tests/decrypted.txt are identical
```

### Коды ошибок
* 101: Ошибка валидации ключа

* 102: Ошибка валидации IV

* 103: Проблема с входным файлом

* 104: Проблема с выходным файлом

* 105: Входной и выходной файлы одинаковые

* 106: Неподдерживаемый режим

* 107: Ошибка инициализации режима шифрования

* 108: Ошибка выполнения операции

* 109: Неизвестная ошибка операции

* 110: Критическая ошибка

* 130: Прерывание пользователем (Ctrl+C)


## Важные заметки

- Проект разработан для **образовательных целей**
- Режим ECB не рекомендуется для защиты реальных данных
- Всегда используйте надежные случайные ключи
- Сохраняйте ключи в безопасном месте


---

*Разработано для демонстрации принципов криптографии. Не используйте для защиты конфиденциальных данных.*