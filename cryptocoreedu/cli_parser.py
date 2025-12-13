import argparse
from pathlib import Path


def create_parser():
    parser = argparse.ArgumentParser(
        description='CryptoCore - Cryptographic Tool',
        prog='crypto',
        allow_abbrev=False
    )

    subparsers = parser.add_subparsers(
        dest='command',
        help='Команды',
        title='subcommands',
        description='valid subcommands',
        metavar='{dgst}'
    )

    # Основная команда crypto для шифрования/дешифрования (все аргументы необязательные)
    parser.add_argument('--algorithm', '-alg', choices=['aes'],
                        help='Алгоритм шифрования')
    parser.add_argument('--mode', '-m', choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'gcm', 'etm'],
                        help='Режим работы')

    mode_group = parser.add_mutually_exclusive_group(required=False)
    mode_group.add_argument('--encrypt', '-enc', action='store_true',
                            help='Режим шифрования')
    mode_group.add_argument('--decrypt', '-dec', action='store_true',
                            help='Режим дешифрования')

    parser.add_argument('--key', '-k', help='Ключ шифрования (128-бит)')

    # CLI-4: --iv используется для nonce в GCM (сохраняем для обратной совместимости)
    parser.add_argument(
        '--iv',
        help='Вектор инициализации / Nonce в hex формате (12 байт для GCM, 16 байт для других)'
    )

    # Дополнительный алиас --nonce для GCM (CLI-4)
    parser.add_argument(
        '--nonce',
        help='Nonce для режима GCM (алиас для --iv, 12 байт в hex)'
    )

    parser.add_argument('--aad', type=str, default='',
                        help='Ассоциированные аутентификационные данные в hex формате (для режима GCM)')

    parser.add_argument('--input', '-i', type=Path, help='Входной файл')
    parser.add_argument('--output', '-o', type=Path, help='Выходной файл')

    # Подкоманда dgst для хеширования
    dgst_parser = subparsers.add_parser('dgst', help='Вычисление хеш-сумм')

    dgst_parser.add_argument('--algorithm', '-alg',
                             choices=['sha256', 'sha3-256'],
                             required=True,
                             help='Алгоритм хеширования')

    dgst_parser.add_argument('--input', '-i', type=Path, required=True,
                             help='Входной файл')

    dgst_parser.add_argument('--output', '-o', type=Path,
                             help='Выходной файл для записи хеша')
    # hmac
    dgst_parser.add_argument(
        '--hmac',
        action='store_true',
        help='Включить режим HMAC (требует --key)'
    )

    dgst_parser.add_argument(
        '--key', '-k',
        type=str,
        help='Секретный ключ в hex формате (обязателен для --hmac)'
    )

    # verify
    dgst_parser.add_argument(
        '--verify', '-v',
        type=Path,
        help='Файл с ожидаемым HMAC для верификации'
    )

    return parser