import argparse
from pathlib import Path


def create_parser():

    parser = argparse.ArgumentParser(description='Crypto Tool')

    parser.add_argument('--algorithm', '-alg', choices=['aes'], required=True, help='Алгоритм шифрования')
    parser.add_argument('--mode', '-m', choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'], required=True, help='Режим работы')

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--encrypt', '-enc', action='store_true', help='Режим шифрования')
    mode_group.add_argument('--decrypt', '-dec', action='store_true', help='Режим дешифрования')

    parser.add_argument('--key', '-k', required=True, help='Ключ шифрования (128-бит)')

    parser.add_argument('--iv', help='Вектор инициализации (обязателен при дешифровании)')

    parser.add_argument('--input', '-i', type=Path, required=True, help='Входной файл')
    parser.add_argument('--output', '-o', type=Path, required=True, help='Выходной файл')

    return parser
