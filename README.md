# CryptoCoreEdu

**CryptoCoreEdu** — утилита командной строки для блочного шифрования файлов с использованием AES-128 в различных режимах работы. Проект разработан в образовательных целях для демонстрации принципов работы блочных шифров.

## Установка

### Способ 1: Установка из PyPI (рекомендуется)
```bash
# Установите пакет
pip install cryptocoreedu

# Или конкретной версии
pip install cryptocoreedu==0.2.4
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

**Вектор инициализации (IV) генерируется автоматически с помощью криптографически стойкого генератора псевдослучайных чисел**

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
- `--key (-k)`: Ключ шифрования (16 байт в hex-формате, необязателен при шифровании)
- `--iv`: Вектор инициализации (16 байт в hex-формате; только в режиме дешифрования)
- `--input (-i)`: Входной файл
- `--output (-o)`: Выходной файл

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

### Автоматическая генерация ключей
**При шифровании без указания ключа утилита автоматически генерирует криптографически стойкий ключ:**

```bash
    # Выполняем шифрование без указания ключа в параметре
    crypto -alg aes -m ctr -enc -i tests/plain.txt -o tests/cipher.bin
    # Вывод в консоли: 
    [INFO] Сгенерирован случайный ключ: 5fae09f459b9b496cf00c3c5f1f0b613
    [INFO] Файл успешно зашифрован в режиме CFB                            
    [INFO] Входной файл: tests\plain.txt -> Выходной файл: tests\cipher.bin
    
    # или

    # Выполняем шифрование с указанием ключа в параметре
    crypto -alg aes -m ctr -enc -k 000102030405060708090a0b0c0d0e0f -i tests/plain.txt -o tests/cipher.bin
    # Вывод в консоли: 
    [INFO] Файл успешно зашифрован в режиме CTR
    [INFO] Входной файл: tests\plain.txt -> Выходной файл: tests\cipher.bin
```

**При дешифровании параметр --key (-k) все также является обязательным:**
```bash
    # Выполняем дешифрование с указанием ключа 
    crypto -alg aes -m ctr -dec -k 5fae09f459b9b496cf00c3c5f1f0b613 -i tests/cipher.bin -o tests/plain.txt
    # Вывод в консоли: 
    [WARNING] Для режима CTR IV будет извлечен из файла
    [INFO] Файл успешно расшифрован в режиме CTR
    [INFO] Входной файл: tests\cipher.bin -> Выходной файл: tests\plain.txt
```

# Тестирование

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


### Тестирование CSPRNG на уникальность
    
```shell
    # 1. Переходим в корень проекта (для Windows)
    cd C:/Users/user/PycharmProjects/CryptoCoreEdu/
    # 2. Запускаем тест на проверку уникальности генерации ключей и векторов инициализации
    python -m tests.test_csprng.python
    # Ожидаемый вывод: Успешно сгенерировано 1000 уникальных ключей.
``` 

```bash
    # 1. Переходим в корень проекта (для Linux/Mac/WSL)
    cd /mnt/c/Users/user/PycharmProjects/CryptoCoreEdu
    # 2. Запускаем тест на проверку уникальности генерации ключей и векторов инициализации
    python -m tests.test_csprng.python
    # Ожидаемый вывод: Успешно сгенерировано 1000 уникальных ключей.
```

### Тестирование CSPRNG с помощью NIST Statistical Test Suite

#### Пошаговая инструкция запуска тестов:

1. **Переходим в корневую папку проекта:**
    ```bash
    cd /mnt/c/Users/user/PycharmProjects/CryptoCoreEdu
    ```
2. **Переходим в папку NIST STS:**
    ```bash
    cd sts-2.1.2/sts-2.1.2/
    ```
   
3. **Собираем тесты:**

    ```bash
    make
    ```
4. **Создаем тестовые данные (10 МБ):**
    ```bash
    python3 -c "
    from cryptocoreedu.csprng import generate_random_bytes
    data = generate_random_bytes(10000000)
    open('random_test_data.bin', 'wb').write(data)
    print('Сгенерирован файл random_test_data.bin размером 10 МБ')
    "
    ```
5. **Запускаем тесты:**
    ```bash
    ./assess 10000000
    ```

6. **Вводим параметры тестирования:**

* #### Enter Choice: 0 (Input File)

* #### User Prescribed Input File: ../../random_test_data.bin

* #### Enter Choice: 1 (All statistical tests)

* #### Select Test (0 to continue): 0 (Default parameters)

* #### How many bitstreams? 10 (Для точной оценки)

* #### Select input mode: 1 (Binary mode)

7. **Ждем выполнения тестов (5-7 минут)**


8. **Просматриваем результаты:**
    ```bash
    # (Linux/Mac/WSL)
    cat experiments/AlgorithmTesting/finalAnalysisReport.txt
    ```
9. **Ожимаемый вывод:**
    ```
    Все 15 статистических тестов NIST должны быть пройдены с показателем 10/10 и p-value ≥ 0.01
    
    ------------------------------------------------------------------------------
    RESULTS FOR THE UNIFORMITY OF P-VALUES AND THE PROPORTION OF PASSING SEQUENCES
    ------------------------------------------------------------------------------
    generator is <../../random_test_data.bin>
    ------------------------------------------------------------------------------
     C1  C2  C3  C4  C5  C6  C7  C8  C9 C10  P-VALUE  PROPORTION  STATISTICAL TEST
    ------------------------------------------------------------------------------
      0   1   1   3   3   0   1   1   0   0  0.213309     10/10      Frequency
      1   0   2   2   0   1   0   0   4   0  0.066882     10/10      BlockFrequency
      0   0   3   1   1   3   1   0   1   0  0.213309     10/10      CumulativeSums
      0   2   0   0   3   3   1   0   1   0  0.122325     10/10      CumulativeSums
      0   0   1   3   1   1   0   2   0   2  0.350485     10/10      Runs
      0   0   2   2   0   2   0   4   0   0  0.035174     10/10      LongestRun
      0   0   2   1   1   1   4   0   0   1  0.122325     10/10      Rank
      1   1   0   3   0   1   1   0   3   0  0.213309     10/10      FFT
      0   0   0   0   1   1   0   1   2   5  0.008879     10/10      NonOverlappingTemplate
      0   0   2   1   0   0   1   3   0   3  0.122325     10/10      NonOverlappingTemplate
      0   1   2   0   2   1   1   0   0   3  0.350485     10/10      NonOverlappingTemplate
      .....
    ```

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
│   ├── csprng.py         # КСГПСЧ
│   ├── file_io.py        # Работа с файлами и IV
│   ├── exceptions.py     # Кастомные исключения для ошибок
│   ├── main.py           # Точка входа в приложение
├── sts-2.1.2/            # Папка с тестами NIST (STS)
├── tests/                # Тесты
│   └── plain.txt         # Файл plaintext'а
│   └── test_csprng.py    # Файл для теста уникальности ключа и IV
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

* 111: Ошибка отсутствия ключа как обязательного параметра

* 112: Ошибка КСГПСЧ


## Важные заметки

- Проект разработан для **образовательных целей**
- Режим ECB не рекомендуется для защиты реальных данных
- Всегда используйте надежные случайные ключи
- Сохраняйте ключи в безопасном месте
- Для генерации криктостойких ключей и IV используется системный источник энтропии (os.urandom()); гарантирует уникальность и непредсказуемость генерируемых значений

---

*Разработано для демонстрации принципов криптографии. Не используйте для защиты конфиденциальных данных.*