from .modes.ECBMode import ECBMode
from .modes.CBCMode import CBCMode
# from .modes.CFBMode import CFBMode
# from .modes.OFBMode import OFBMode
# from .modes.CTRMode import CTRMode

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


def validate_hex_iv(iv_str: str) -> bytes:
    try:
        iv_str = iv_str.strip().lower()

        if not iv_str:
            raise ValueError('Ошибка: IV не может быть пустым')

        if iv_str.startswith('0x'):
            iv_str = iv_str[2:]

        if not all(c in '0123456789abcdef' for c in iv_str):
            raise ValueError("Ошибка: IV должен представлять собой шестнадцатеричную строку")

        if len(iv_str) != 32:
            raise ValueError(f"Ошибка: IV должен состоять из 32 шестнадцатеричных символов (16 байт), получено - {len(iv_str)}")

        iv_bytes = bytes.fromhex(iv_str)
        return iv_bytes

    except ValueError as e:
        raise ValueError(f"Ошибка: неверный IV. {e}")


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
    parser.add_argument('--mode', '-m', choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'], required=True, help='Mode')

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--encrypt', '-enc', action='store_true', help='Encrypt mode')
    mode_group.add_argument('--decrypt', '-dec', action='store_true', help='Decrypt mode')

    parser.add_argument('--key', '-k', required=True, help='Encryption key')

    parser.add_argument('--iv', help='Инициализирующий вектор (обязателен при дешифровании)')

    parser.add_argument('--input', '-i', type=Path, required=True, help='Input file path')
    parser.add_argument('--output', '-o', type=Path, required=True, help='Output file path')
    args = parser.parse_args()
    try:
        # CLI-2: Проверка корректности использования IV
        if args.encrypt and args.iv:
            if args.mode == 'ecb':
                print("Предупреждение: IV игнорируется для режима ECB")
            else:
                print("Предупреждение: Переданный IV нельзя использовать при шифровании, он генерируется автоматически")

        if args.decrypt and not args.iv:
            if args.mode != 'ecb':
                print(f"Предупреждение: Для режима {args.mode.upper()} IV будет извлечен из файла")

        key = validate_hex_key(args.key)

        iv = None
        if args.iv:
            iv = validate_hex_iv(args.iv)

        input_path = validate_file_path(args.input, for_reading=True)
        output_path = validate_file_path(args.output, for_reading=False)

        if input_path.resolve() == output_path.resolve():
            raise ValueError('Ошибка: входные и выходные файлы не могут быть одинаковыми')

            # Создание соответствующего объекта режима
        if args.algorithm == 'aes':
            if args.mode == 'ecb':
                cipher = ECBMode(key)
            elif args.mode == 'cbc':
                cipher = CBCMode(key)
            # elif args.mode == 'cfb':
            #     cipher = CFBMode(key)
            # elif args.mode == 'ofb':
            #     cipher = OFBMode(key)
            # elif args.mode == 'ctr':
            #     cipher = CTRMode(key)
            else:
                raise ValueError(f"Неподдерживаемый режим: {args.mode}")

            if args.encrypt:
                iv = os.urandom(16) if args.mode != 'ecb' else None
                cipher.encrypt_file(input_path, output_path, iv)
                print(f"Файл зашифрован в режиме {args.mode.upper()}: {input_path} -> {output_path}")
            else:
                # Передача IV для дешифрования (если предоставлен)
                cipher.decrypt_file(input_path, output_path, iv)
                print(f"Файл расшифрован в режиме {args.mode.upper()}: {input_path} -> {output_path}")

    except Exception as error:
        parser.error(f'Ошибка операции: {error}')
        sys.exit(1)


if __name__ == "__main__":
    main()