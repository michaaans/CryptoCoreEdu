from .modes.ECBMode import ECBMode
from pathlib import Path

import argparse
import os
import sys


def validate_hex_key(key_str: str) -> bytes:
    try:
        key_str = key_str.strip().lower()

        if not key_str:
            raise ValueError('Ошибка: ключ не может быть пустым')

        if key_str.startswith('0x'):
            key_str = key_str[2:]

        if not all(c in '0123456789abcdef' for c in key_str):
            raise ValueError("Ошибка: ключ должен представлять собой шестнадцатеричную строку")

        if len(key_str) != 32:
            raise ValueError(f"Ошибка: ключ должен состоять из 32 шестнадцатеричных символов (16 байт), получено - {len(key_str)}")

        key_bytes = bytes.fromhex(key_str)
        return key_bytes

    except ValueError as e:
        raise ValueError(f"Ошибка: неверный ключ. {e}")


def validate_file_path(path: Path, for_reading: bool = True) -> Path:
    if for_reading:
        if not path.exists():
            raise FileNotFoundError(f"Ошибка: входной файл {path} не существует.")
        if not path.is_file():
            raise ValueError(f"Ошибка: входной путь {path} не является файлом.")
        if not os.access(path, os.R_OK):
            raise PermissionError(f"Ошибка: нет прав на чтение файла {path}")
    else:
        parent_dir = path.parent
        if parent_dir and not parent_dir.exists():
            raise FileNotFoundError(f"Ошибка: выходная директория {parent_dir} не существует.")
        if not os.access(parent_dir, os.W_OK):
            raise PermissionError(f"Ошибка: нет прав на запись в директорию {parent_dir}")
        if path.exists() and not os.access(path, os.W_OK):
            raise PermissionError(f"Ошибка: нет прав на запись в файл {path}")
    return path


def main():

    parser = argparse.ArgumentParser(description='Crypto Tool')
    parser.add_argument('--algorithm', '-alg', choices=['aes'], required=True, help='Algorithm')
    parser.add_argument('--mode', '-m', choices=['ecb'], required=True, help='Mode')

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--encrypt', '-enc', action='store_true', help='Encrypt mode')
    mode_group.add_argument('--decrypt', '-dec', action='store_true', help='Decrypt mode')

    parser.add_argument('--key', '-k', required=True, help='Encryption key')
    parser.add_argument('--input', '-i', type=Path, required=True, help='Input file path')
    parser.add_argument('--output', '-o', type=Path, required=True, help='Output file path')

    args = parser.parse_args()

    try:

        key = validate_hex_key(args.key)

        input_path = validate_file_path(args.input, for_reading=True)
        output_path = validate_file_path(args.output, for_reading=False)

        if input_path.resolve() == output_path.resolve():
            raise ValueError('Ошибка: входные и выходные файлы не могут быть одинаковыми')

        if args.algorithm == 'aes' and args.mode == 'ecb':
            cipher = ECBMode(key)

            if args.encrypt:
                cipher.encrypt_file(input_path, output_path)
                print(f"Файл зашифрован: {input_path} -> {output_path}")
            else:
                cipher.decrypt_file(input_path, output_path)
                print(f"Файл расшифрован: {input_path} -> {output_path}")

    except Exception as error:
        parser.error(f'Ошибка операции: {error}')
        sys.exit(1)


if __name__ == "__main__":
    main()