import argparse
from pathlib import Path


def create_parser():
    parser = argparse.ArgumentParser(
        description='CryptoCore - Cryptographic Tool',
        prog='crypto'
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
    parser.add_argument('--mode', '-m', choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
                        help='Режим работы')

    mode_group = parser.add_mutually_exclusive_group(required=False)
    mode_group.add_argument('--encrypt', '-enc', action='store_true',
                            help='Режим шифрования')
    mode_group.add_argument('--decrypt', '-dec', action='store_true',
                            help='Режим дешифрования')

    parser.add_argument('--key', '-k', help='Ключ шифрования (128-бит)')
    parser.add_argument('--iv', help='Вектор инициализации')

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

    return parser