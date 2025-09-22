# CryptoCoreEdu

**CryptoCoreEdu** — утилита командной строки для блочного шифрования файлов с использованием AES-128 в режиме ECB. Проект разработан в образовательных целях для демонстрации принципов работы блочных шифров.

## Установка

### Способ 1: Установка из PyPI (рекомендуется)
```bash
# Установите пакет
pip install cryptocoreedu

# Или конкретной версии
pip install cryptocoreedu==0.2.2
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
```bash
# Проверьте что пакет установился (Windows)
pip list | findstr cryptocoreedu

# Проверьте работу утилиты
crypto --help или crypto -h
```

## Использование

### Базовые команды
```bash
# Шифрование файла
crypto --algorithm aes --mode ecb --encrypt \
       --key 000102030405060708090a0b0c0d0e0f \
       --input document.txt \
       --output document.enc

# Дешифрование файла  
crypto -alg aes -m ecb -dec \
       -k "000102030405060708090a0b0c0d0e0f" \
       -i document.enc \
       -o document_decrypted.txt
```

### Параметры командной строки
- `--algorithm (-alg)`: Алгоритм шифрования (только `aes`)
- `--mode (-m)`: Режим работы (только `ecb`)  
- `--encrypt (-enc)`: Режим шифрования
- `--decrypt (-dec)`: Режим дешифрования
- `--key (-k)`: Ключ шифрования (16 байт в hex-формате)
- `--input (-i)`: Входной файл
- `--output (-o)`: Выходной файл

## Требования

### Зависимости
- **Python** 3.8 или выше
- **pycryptodome** 3.23.0 или выше

### Размер ключа
Ключ должен быть ровно **16 байт** (32 hex-символа):
```
Правильно: 000102030405060708090a0b0c0d0e0f
Неправильно: mykey123 (8 байт)
```

## Проверка целостности

Для проверки корректности шифрования/дешифрования используйте скрипт сравнения:

```bash
# Из директории проекта C:\Users\YourName\PyCharmProjects\CryptoCoreEdu > 
python tests/compare.py original.txt decrypted.txt
```

**Вывод:** `Файлы идентичны!` или `Файлы различны!`

## Пример работы 
- Из директории проекта:
```bash
# Шифрование
crypto -alg aes -m ecb -enc -k 00112233445566778899aabbccddeeff -i secret.txt -o secret.enc
# Файл зашифрован: secret.txt -> secret.enc

# Дешифрование  
crypto -alg aes -m ecb -dec -k 00112233445566778899aabbccddeeff -i secret.enc -o secret_decrypted.txt
# Файл дешифрован: secret.enc -> secret_decrypted.txt

# Проверка 
python tests/compare.py secret.txt secret_decrypted.txt
# Files are identical ✓
```

## Важные заметки

- Проект разработан для **образовательных целей**
- Режим ECB не рекомендуется для защиты реальных данных
- Всегда используйте надежные случайные ключи
- Сохраняйте ключи в безопасном месте

## Планы развития

- Добавление новых алгоритмов шифрования
- Поддержка дополнительных режимов работы (CBC, CFB, OFB, CTR)
- Интеграция скрипта проверки в основную утилиту

---

*Разработано для демонстрации принципов криптографии. Не используйте для защиты конфиденциальных данных.*