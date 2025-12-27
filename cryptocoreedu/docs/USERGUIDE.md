
## Пользовательские инструкции по использованию утилиты
### Установка проекта
### Способ 1: Установка из PyPI (рекомендуется)
```bash
# Установите пакет
pip install cryptocoreedu

# Или конкретной версии
pip install cryptocoreedu==2.0.2
```

### Способ 2: Установка из исходного кода
```bash
# Клонируйте репозиторий
git clone https://github.com/michaaans/CryptoCoreEdu.git
cd CryptoCoreEdu
# Установите виртуальное окружение
python3 -m venv vevn
# Активируйте виртуальное окружение
source venv/bin/activate
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

## Важные заметки

- Проект разработан для **образовательных целей**
- Режим ECB не рекомендуется для защиты реальных данных, лучше использовать GCM
- Никогда не используйте один nonce дважды с одним ключом в GCM!
- При ошибке аутентификации AEAD выходной файл не создаётся
- Сохраняйте ключи в безопасном месте
- Для генерации криктостойких ключей и IV используется системный источник энтропии (os.urandom()); гарантирует уникальность и непредсказуемость генерируемых значений
- Скорость хэш-функций может быть гораздо ниже, чем в проверенных реализациях (hashlib, sha256sum и т.д.)
- Для выделения ключей используя не менее 100000 итераций и длину ключа не ниже 32 байт.

### Шифрование/Дешифрование всеми режимами

### Поддерживаемые режимы
* ECB (Electronic Codebook) - базовый режим, требует паддинг

* CBC (Cipher Block Chaining) - блочный режим с цепочкой, требует паддинг

* CFB (Cipher Feedback) - потоковый режим, без паддинга

* OFB (Output Feedback) - потоковый режим, без паддинга

* CTR (Counter) - потоковый режим, без паддинга

* GCM (Galois/Counter Mode) - аутентифицированное шифрование по стандарту NIST SP 800-38D

* ETM (Encrypt-then-MAC) - составной режим CTR + HMAC-SHA256


### ECB Mode
```bash
# ECB режим шифрование (без IV)
crypto -alg aes -m ecb -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc
# ECB режим дешифрование (без IV)
crypto -alg aes -m ecb -dec -k 000102030405060708090a0b0c0d0e0f -i tests/document.enc -o tests/document_decrypted.txt
```

### CBC Mode
```bash
# CBC режим шифрование (IV генерируется автоматически)
crypto -alg aes -m cbc -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# CBC режим шифрование (IV пишем сами)
crypto -alg aes -m cbc -enc -k 000102030405060708090a0b0c0d0e0f --iv AABBCCDDEEFF00112233445566778899 -i tests/document.txt -o tests/document.enc

# CBC режим дешифрование
crypto -alg aes -m cbc -dec -k 000102030405060708090a0b0c0d0e0f -i tests/document.enc -o tests/document_decrypted.txt
```

### CFB Mode
```bash
# CFB режим шифрование (IV генерируется автоматически)
crypto -alg aes -m cfb -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# CFB режим шифрование (IV пишем сами)
crypto -alg aes -m cfb -enc -k 000102030405060708090a0b0c0d0e0f --iv AABBCCDDEEFF00112233445566778899 -i tests/document.txt -o tests/document.enc

# CFB режим дешифрование
crypto -alg aes -m cfb -dec -k 000102030405060708090a0b0c0d0e0f -i tests/document.enc -o tests/document_decrypted.txt
```

### OFB Mode
```bash
# OFB режим шифрование (IV генерируется автоматически)
crypto -alg aes -m ofb -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# OFB режим шифрование (IV пишем сами)
crypto -alg aes -m ofb -enc -k 000102030405060708090a0b0c0d0e0f --iv AABBCCDDEEFF00112233445566778899 -i tests/document.txt -o tests/document.enc

# OFB режим дешифрование
crypto -alg aes -m ofb -dec -k 000102030405060708090a0b0c0d0e0f -i tests/document.enc -o tests/document_decrypted.txt
```

### CTR Mode
```bash
# CTR режим шифрование (IV генерируется автоматически)
crypto -alg aes -m ctr -enc -k 000102030405060708090a0b0c0d0e0f -i tests/document.txt -o tests/document.enc

# CTR режим шифрование (IV пишем сами)
crypto -alg aes -m ctr -enc -k 000102030405060708090a0b0c0d0e0f --iv AABBCCDDEEFF00112233445566778899 -i tests/document.txt -o tests/document.enc

# CTR режим дешифрование
crypto -alg aes -m ctr -dec -k 000102030405060708090a0b0c0d0e0f -i tests/document.enc -o tests/document_decrypted.txt
```

### GCM Mode
```bash
# Шифрование с AAD
   crypto -alg aes -m gcm -enc \
       -k 00112233445566778899aabbccddeeff \
       --aad 48656c6c6f576f726c64 \
       -i tests/plain.txt \
       -o tests/cipher.bin
   
   # Шифрование без AAD
   crypto -alg aes -m gcm -enc \
       -k 00112233445566778899aabbccddeeff \
       -i tests/plain.txt \
       -o tests/cipher.bin
   
   # Расшифрование (nonce читается из файла автоматически)
   crypto -alg aes -m gcm -dec \
       -k 00112233445566778899aabbccddeeff \
       --aad 48656c6c6f576f726c64 \
       -i tests/cipher.bin \
       -o tests/decrypted.txt
   
   # Расшифрование с внешним nonce (через --nonce или --iv)
   crypto -alg aes -m gcm -dec \
       -k 00112233445566778899aabbccddeeff \
       --nonce 000102030405060708090a0b \
       --aad 48656c6c6f576f726c64 \
       -i tests/ciphertext_without_nonce.bin \
       -o tests/decrypted.txt
```

### ETM Mode
```bash
# Шифрование с AAD
   crypto -alg aes -m etm -enc \
       -k 00112233445566778899aabbccddeeff \
       --aad 616263 \
       -i tests/plain.txt \
       -o tests/cipher.bin
   
   # Шифрование без AAD
   crypto -a aes -m etm -enc \
       -k 00112233445566778899aabbccddeeff \
       -i tests/plain.txt \
       -o tests/cipher.bin
   
   # Расшифрование
   crypto -alg aes -m etm -dec \
       -k 00112233445566778899aabbccddeeff \
       --aad 616263 \
       -i tests/cipher.bin \
       -o tests/decrypted.txt
```

### Параметры командной строки
- `--algorithm (-alg)`: Алгоритм шифрования (`aes`)
- `--mode (-m)`: Режим работы (`ecb`, `cbc`, `cfb`, `ofb`, `ctr`, `gcm`, `etm`)  
- `--encrypt (-enc)`: Режим шифрования
- `--decrypt (-dec)`: Режим дешифрования
- `--key (-k)`: Ключ шифрования (16 байт в hex-формате, необязателен при шифровании)
- `--iv`: Вектор инициализации (16 байт в hex-формате; только в режиме дешифрования)
- `--nonce (-n)`: Nonce для GCM (12 байт в hex; алиас для --iv)
- `--aad`: Associated Authenticated Data в hex (для GCM/ETM)
- `--input (-i)`: Входной файл
- `--output (-o)`: Выходной файл

### Вычисление HMAC и хэш-сумм разными алгоритмами

```bash
   # Хэширование без указания выходного файла (Linux/MacOS/WSL)
  crypto dgst -alg sha256 -i document.pdf
  #5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b0b5  document.pdf
  # Хэширование с указанием выходного файла
  crypto dgst -alg sha3-256 -i backup.tar -o backup.sha3
```

```bash
   # HMAC без указания выходного файла (Linux/MacOS/WSL)
  crypto dgst -alg sha256 --hmac -k 00112233445566778899aabbccddeeff -i tests/message.txt
  # HMAC с указанием выходного файла
  crypto dgst -alg sha256 --hmac -k 00112233445566778899aabbccddeeff -i tests/message.txt -o tests/hmac.txt
  # HMAC с указанием флага для верификации
  crypto dgst -alg sha256 --hmac -k 00112233445566778899aabbccddeeff -i tests/message.txt -v tests/hmac.txt
  #Вывод: [OK] Проверка HMAC успешна
```
### Параметры хэш-функций и их особенности
#### Параметры хэширования:
- `--algorithm (-alg)`: Алгоритм хэширования (`sha256`, `sha3-256`)
- `--input (-i)`: Входной файл
- `--output (-o)`: Выходной файл (опционально)
#### Параметры HMAC:
- `--algorithm (-alg)`: Алгоритм хэширования (`sha256`, `sha3-256`)
- `--hmac`: Флаг для вычисления HMAC
- `--key (-k)`: Ключ для вычисления HMAC (обязателен для флага --hmac; может быть любой длины от 1 байта)
- `--input (-i)`: Входной файл
- `--output (-o)`: Выходной файл (опционально)
- `--verify (-v)`: Флаг для проверки сообщения

**Формат вывода хэша и HMAC**:
#### 5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b0b5  document.pdf

#### Особенности:

1. **Алгоритм SHA256**:
   - Реализован в соответствии со стандартом NIST FIPS 180-4
   - Использует конструкцию Меркля-Дамгарда
   - корретно реализует схему дополнения
   - реализует все константы SHA-256 и функции раундов.
   - Размер чанка 8192 байт.
   - Обработка больщих файлов (>1gb)

2. **Алгоритм SHA3-256**:
   - Реализован в соответствии со стандартом NIST FIPS 202
   - Использует губчатую конструкцию Keccak
   - Размер чанка 8192 байт.
   - Обработка больщих файлов (>1gb)

3. **Алгоритм HMAC-SHA-256**:
   - Реализован в соответствии со стандартом RFC 2104
   - Использует HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))
   - Обработка больщих файлов (>1gb)
   - Полностью соответствует RFC 4231
   - constant-time сравнение для верификации
   - ключи любой длины

### Команды PBKDF2 и HKDF
#### PBKDF2 (Password-Based Key Derivation Function 2):
PBKDF2 используется для безопасного выведения криптографических ключей из паролей.

- **Назначение**: Безопасное преобразование паролей в криптографические ключи
- **Стойкость к brute-force**: Большое количество итераций замедляет атаки
- **Уникальность ключей**: Использование соли гарантирует разные ключи для одинаковых паролей
- **Рекомендации по безопасности**:
    - Минимум 100,000 итераций для современных систем
    - Использование уникальной соли для каждого ключа
    - Длина ключа не менее 32 байт (256 бит)

#### Особенности реализации:
- **Алгоритм**: PBKDF2-HMAC-SHA256
- **Стандарт**: RFC 2898
- **Функция псевдослучайности**: HMAC-SHA256
- **Соль**: 16 байт (генерируется случайно если не указана)
- **Итерации**: По умолчанию 100,000 (настраивается)
- **Длина ключа**: Произвольная (по умолчанию 32 байта)

#### Формула PBKDF2:
```
DK = PBKDF2(PRF, Password, Salt, c, dkLen)
где:
  DK = derived key (выведенный ключ)
  PRF = HMAC-SHA256
  Password = пароль
  Salt = соль
  c = количество итераций
  dkLen = длина ключа в байтах

Для каждого блока i (от 1 до l, где l = ceil(dkLen / hLen)):
  U1 = PRF(Password, Salt || INT_32_BE(i))
  U2 = PRF(Password, U1)
  ...
  Uc = PRF(Password, Uc-1)
  Ti = U1 ⊕ U2 ⊕ ... ⊕ Uc

DK = T1 || T2 || ... || Tl (обрезается до dkLen байт)
```

#### HKDF (Hierarchical Key Derivation Function):
HKDF используется для детерминированного выведения множества ключей из одного мастер-ключа.

- **Назначение**: Создание множества безопасных ключей из одного мастер-ключа
- **Использование контекста**: Уникальные идентификаторы для разных применений
- **Примеры контекстов**: `"encryption"`, `"authentication"`, `"user:michan"`
- **Преимущества**:
    - Изоляция ключей: компрометация одного ключа не затрагивает другие
    - Детерминизм: одинаковые входные данные дают одинаковые ключи
    - Гибкость: произвольная длина ключей

#### Особенности реализации:
- **Основа**: HMAC-SHA256
- **Контекст**: Уникальная строка для каждого производного ключа
- **Детерминизм**: Одинаковые входные данные дают одинаковый ключ
- **Разделение**: Разные контексты дают статистически независимые ключи

#### Формула HKDF:
```
T1 = HMAC(master_key, context || INT_32_BE(1))
T2 = HMAC(master_key, context || INT_32_BE(2))
...
Tn = HMAC(master_key, context || INT_32_BE(n))

DerivedKey = T1 || T2 || ... || Tn (обрезается до нужной длины)
```


#### Базовое выведение ключа с PBKDF2:

```bash
   # Примеры использования
   
   # Базовое получение ключа с указанием соли
    crypto derive --password "MySecurePassword123!" \
    --salt a1b2c3d4e5f601234567890123456789 \
    --iterations 100000 \
    --length 32
  # Вывод: <KEY_HEX>  a1b2c3d4e5f601234567890123456789

  # Получение ключа с автоматической генерацией соли
   crypto derive --password "AnotherPassword" \
    --iterations 500000 \
    --length 16
  # Вывод: [INFO] Сгенерирована случайная соль: <SALT_HEX>
  #        <KEY_HEX>  <SALT_HEX>
  
  # Запись ключа в файл
  crypto derive --password "app_key" \
    --salt 0123456789abcdef0123456789abcdef \
    --iterations 100000 \
    --length 32 \
    --output tests/derived_key.bin
  # Вывод: [INFO] Ключ (32 байт) записан в файл: derived_key.bin
  #        <KEY_HEX>  0123456789abcdef0123456789abcdef
  
  # С минимальными итерациями (для тестирования RFC 6070 PBKDF2-HMAC-SHA256)
  crypto derive -p "password" -s 73616c74 -c 1 -l 20
  # Вывод: 120fb6cffcf8b32c43e7225256c4f837a86548c9  73616c74
```

#### Параметры команды derive (PBKDF2):
- `--password (-p)`: Пароль для выведения ключа в виде строки
- `--salt (-s)`: Соль в формате hex-строки
- `--iterations (-c)`: Количество итераций PBKDF2
- `--length (-l)`: Длина выведенного ключа в байтах
- `--algorithm (-alg)`: Алгоритм KDF
- `--output (-o)`: Выходной файл для сохранения ключа в бинарном виде

#### Формат вывода для команды derive:
* KEY_HEX SALT_HEX (оба в hex, разделены пробелом)
* Ключ: запрошенной длины в hex
* Соль: использованная соль в hex (предоставленная или сгенерированная)
* При --output: ключ сохраняется как бинарные байты, соль не записывается

#### Иерархическое выведение ключей (HKDF):

```bash
   # Используем master_key для выделения ключей из мастер-ключа
   
python3 -c "
from cryptocoreedu.kdf.hkdf import derive_key

master = b'master_secret_key_for_testing'

key1 = derive_key(master, 'encryption', 32)
key2 = derive_key(master, 'authentication', 32)
key3 = derive_key(master, 'encryption', 32)  # Same as key1
key4 = derive_key(master, 'user:michan', 64)

print(f'Encryption key:     {key1.hex()}')
print(f'Authentication key: {key2.hex()}')
print(f'Encryption key (2): {key3.hex()}')
print(f'User key: {key4.hex()}')
print(f'Deterministic: {key1 == key3}')
print(f'Different contexts produce different keys: {key1 != key2}')
"
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

### Ошибки и решения

* Неверный формат ключа
* Неверный размер ключа или IV
* Неверный порядок флагов в CLI

### Возможные подсказки по форматам
### Размер ключа, IV и Nonce

| Параметр           | Размер            | Режимы                       |
|--------------------|-------------------|------------------------------|
| Ключ               | 16 байт (32 hex)  | Все режимы                   |
| IV                 | 16 байт (32 hex)  | ECB, CBC, CFB, OFB, CTR, ETM |
| Nonce              | 12 байт (24 hex)  | GCM                          |


```
Правильный ключ: 000102030405060708090a0b0c0d0e0f (32 символа)
Неправильно: mykey123 (8 байт)
```
```
Правильный IV: AABBCCDDEEFF00112233445566778899 (32 символа)
Неправильно: ASFSAFSA909DAS9DA99129129DNNBN
```
```
Правильный Nonce: 000102030405060708090a0b (24 символа)
```

