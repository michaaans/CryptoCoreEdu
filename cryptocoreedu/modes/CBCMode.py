from Crypto.Cipher import AES
from pathlib import Path

import os
from ..file_io import read_file, write_file
import sys


class CBCMode:
    ''' Реализация режима CBC для AES-128 и реализация паддинга по стандарту PKCS7'''

    BLOCK_SIZE = 16

    def __init__(self, key: bytes):
        self.key = key
        # Создаем базовый cipher для шифрования/дешифрования отдельных блоков
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

    def encrypt_file(self, input_file: Path, output_file: Path, iv: bytes) -> None:
        try:
            plaintext = read_file(input_file)
            padded_data = self.pad(plaintext)

            # Генерируем случайный IV если не предоставлен
            if iv is None:
                iv = os.urandom(self.BLOCK_SIZE)

            # Проверяем корректность IV
            if len(iv) != self.BLOCK_SIZE:
                raise ValueError(f"Ошибка: IV должен быть длиной {self.BLOCK_SIZE} байт")

            encrypted_blocks = []
            previous_block = iv

            # Шифруем блоки в режиме CBC
            for i in range(0, len(padded_data), self.BLOCK_SIZE):
                block = padded_data[i:i + self.BLOCK_SIZE]

                # XOR с предыдущим зашифрованным блоком (или IV для первого блока)
                xor_block = bytes(a ^ b for a, b in zip(block, previous_block))

                # Шифруем результат XOR
                encrypted_block = self.cipher.encrypt(xor_block)
                encrypted_blocks.append(encrypted_block)
                previous_block = encrypted_block

            # Записываем IV и зашифрованные данные
            write_file(output_file, iv + b''.join(encrypted_blocks))

        except (FileNotFoundError, ValueError, IOError) as error:
            print(f'Ошибка при работе с файлами или данными: {error}')
            sys.exit(1)
        except Exception as error:
            print(f'Неизвестная ошибка: {error}')
            sys.exit(1)

    def decrypt_file(self, input_file: Path, output_file: Path, iv: bytes) -> None:
        try:
            ciphertext = read_file(input_file)

            # Проверяем минимальный размер данных
            if len(ciphertext) < self.BLOCK_SIZE:
                raise ValueError("Ошибка: файл слишком короткий для CBC режима")

            # Извлекаем IV из начала файла или используем предоставленный
            if iv is None:
                # Если IV не предоставлен, извлекаем из файла
                file_iv = ciphertext[:self.BLOCK_SIZE]
                ciphertext_blocks = ciphertext[self.BLOCK_SIZE:]
            else:
                # Используем предоставленный IV
                file_iv = iv
                ciphertext_blocks = ciphertext[self.BLOCK_SIZE:]

            # Проверяем корректность размера данных
            if len(ciphertext_blocks) % self.BLOCK_SIZE != 0:
                raise ValueError("Ошибка: Некорректный размер шифртекста")

            decrypted_blocks = []
            previous_block = file_iv

            # Дешифруем блоки в режиме CBC
            for i in range(0, len(ciphertext_blocks), self.BLOCK_SIZE):
                block = ciphertext_blocks[i:i + self.BLOCK_SIZE]

                # Дешифруем блок
                decrypted_block = self.cipher.decrypt(block)

                # XOR с предыдущим зашифрованным блоком (или IV для первого блока)
                plain_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
                decrypted_blocks.append(plain_block)
                previous_block = block

            # Объединяем и удаляем паддинг
            decrypted_data = b''.join(decrypted_blocks)
            unpadded_data = self.unpad(decrypted_data)

            write_file(output_file, unpadded_data)

        except (FileNotFoundError, ValueError, IOError) as error:
            print(f'Ошибка при работе с файлами или данными: {error}')
            sys.exit(1)
        except Exception as error:
            print(f'Неизвестная ошибка: {error}')
            sys.exit(1)