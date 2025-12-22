## Структура проекта

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
│   ├── unit/             # Папка с unit-тестами
│   ├── integration/      # Папка с интеграционными тестами
│   ├── plain.txt         # Файл plaintext'а
├── setup.py              # Файл сборки проекта
├── pyproject.toml        # Файл сборки
└── README.md             # Документация
```

## Требования

### Зависимости
- **Python** 3.8 или выше
- **pycryptodome** 3.23.0 или выше
- **OpenSSL** (для тестирования совместимости)
- **numba** 0.62.1 или выше (для оптимизации вычислений хэш-функций)
- **numpy** 2.2.6 или выше (для оптимизации вычислений хэш-функций)