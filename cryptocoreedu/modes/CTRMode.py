from Crypto.Cipher import AES
from pathlib import Path

from ..file_io import read_file, write_file
from ..exceptions import CryptoOperationError

import os

class CTRMode:
    '''Реализация режима CTR (Counter) для AES-128 как потокового шифра'''

    BLOCK_SIZE = 16

    def __init__(self, key: bytes):
        self.key = key
        # Создаем базовый cipher для шифрования отдельных блоков
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def _increment_counter(self, counter: bytes) -> bytes:

        counter_int = int.from_bytes(counter, byteorder='big')
        counter_int = (counter_int + 1) & ((1 << 128) - 1)
        return counter_int.to_bytes(16, byteorder='big')

    def encrypt_file(self, input_file: Path, output_file: Path) -> None:

        try:
            plaintext = read_file(input_file)

            iv = os.urandom(self.BLOCK_SIZE)

            # Проверяем корректность IV
            if len(iv) != self.BLOCK_SIZE:
                raise CryptoOperationError(f"IV должен быть длиной {self.BLOCK_SIZE} байт")

            encrypted_blocks = []
            counter = iv

            # Обрабатываем данные блоками
            for i in range(0, len(plaintext), self.BLOCK_SIZE):
                block = plaintext[i:i + self.BLOCK_SIZE]

                # Шифруем текущее значение счетчика для получения keystream
                keystream = self.cipher.encrypt(counter)

                # XOR plaintext с keystream для получения ciphertext
                ciphertext_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
                encrypted_blocks.append(ciphertext_block)

                # Инкрементируем счетчик для следующего блока
                counter = self._increment_counter(counter)

            # Записываем IV (nonce) и зашифрованные данные
            write_file(output_file, iv + b''.join(encrypted_blocks))

        except (FileNotFoundError, ValueError, IOError) as error:
            raise CryptoOperationError(f"Ошибка при шифровании режимом CTR: {error}")
        except Exception as error:
            raise CryptoOperationError(f"Неизвестная ошибка при шифровании CTR: {error}")

    def decrypt_file(self, input_file: Path, output_file: Path, iv: bytes) -> None:

        try:
            ciphertext = read_file(input_file)

            # Проверяем минимальный размер данных
            if len(ciphertext) < self.BLOCK_SIZE:
                raise CryptoOperationError("Файл слишком короткий для CTR режима")

            if iv is None:
                file_iv = ciphertext[:self.BLOCK_SIZE]
                ciphertext_blocks = ciphertext[self.BLOCK_SIZE:]
            else:
                file_iv = iv
                ciphertext_blocks = ciphertext

            # Проверяем что после извлечения IV остались данные
            if len(ciphertext_blocks) == 0:
                raise CryptoOperationError("Файл не содержит данных для дешифрования")

            decrypted_blocks = []
            counter = file_iv

            # Обрабатываем данные блоками
            for i in range(0, len(ciphertext_blocks), self.BLOCK_SIZE):
                block = ciphertext_blocks[i:i + self.BLOCK_SIZE]

                # Шифруем текущее значение счетчика для получения keystream
                keystream = self.cipher.encrypt(counter)

                # XOR ciphertext с keystream для получения plaintext
                plaintext_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
                decrypted_blocks.append(plaintext_block)

                # Инкрементируем счетчик для следующего блока
                counter = self._increment_counter(counter)

            # Объединяем расшифрованные блоки (без паддинга в CTR)
            decrypted_data = b''.join(decrypted_blocks)
            write_file(output_file, decrypted_data)

        except (FileNotFoundError, ValueError, IOError) as error:
            raise CryptoOperationError(f"Ошибка при дешифровании режимом CTR: {error}")
        except Exception as error:
            raise CryptoOperationError(f"Неизвестная ошибка при дешифровании CTR: {error}")