from Crypto.Cipher import AES
from pathlib import Path

from ..file_io import read_file, write_file
import sys


class ECBMode:
    ''' Реализация режима ECB для AES-128 и реализация паддинга по стандарту PKCS7'''

    BLOCK_SIZE = 16

    def __init__(self, key: bytes):

        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        if len(a) != len(b):
            return False

        result = 0

        for x, y in zip(a, b):
            result |= x ^ y

        return result == 0

    def pad(self, data: bytes) -> bytes:
        # Паддинг по PKCS#7.
        if len(data) % self.BLOCK_SIZE == 0:
            pad_len = self.BLOCK_SIZE
        else:
            pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    def unpad(self, data: bytes) -> bytes:
        # Удаление паддинга по PKCS#7.
        if not data:
            return data
        pad_len = data[-1]

        # Проверка корректности дополнения
        if pad_len > self.BLOCK_SIZE or pad_len == 0:
            raise ValueError("Ошибка: Некорректное дополнение")

        expected_padding = bytes([pad_len] * pad_len)
        actual_padding = data[-pad_len:]

        if not self.constant_time_compare(expected_padding, actual_padding):
            raise ValueError("Ошибка: Некорректное дополнение")

        return data[:-pad_len]

    def encrypt_file(self, input_file: Path, output_file: Path) -> None:

        try:
            plaintext = read_file(input_file)
            padded_data = self.pad(plaintext)

            encrypted_blocks = []
            for i in range(0, len(padded_data), self.BLOCK_SIZE):
                block = padded_data[i:i + self.BLOCK_SIZE]
                encrypted_block = self.cipher.encrypt(block)
                encrypted_blocks.append(encrypted_block)

            write_file(output_file, b''.join(encrypted_blocks))

        except (FileNotFoundError, ValueError, IOError) as error:
            print(f'Ошибка при работе с файлами или данными: {error}')
            sys.exit(1)
        except Exception as error:
            print(f'Неизвестная ошибка: {error}')
            sys.exit(1)

    def decrypt_file(self, input_file: Path, output_file: Path) -> None:

        try:
            ciphertext = read_file(input_file)

            if len(ciphertext) % self.BLOCK_SIZE != 0:
                raise ValueError("Ошибка: Некорректный размер шифртекста")

            decrypted_blocks = []
            for i in range(0, len(ciphertext), self.BLOCK_SIZE):
                block = ciphertext[i:i + self.BLOCK_SIZE]
                decrypted_block = self.cipher.decrypt(block)
                decrypted_blocks.append(decrypted_block)
            decrypted_data = b''.join(decrypted_blocks)
            unpadded_data = self.unpad(decrypted_data)

            write_file(output_file, unpadded_data)

        except (FileNotFoundError, ValueError, IOError) as error:
            print(f'Ошибка при работе с файлами или данными: {error}')
            sys.exit(1)
        except Exception as error:
            print(f'Неизвестная ошибка: {error}')
            sys.exit(1)