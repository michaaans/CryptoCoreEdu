
import os
import sys
from pathlib import Path

from Crypto.Cipher import AES

from ..mac.hmac import HMAC
from ..exceptions import AuthenticationError, CryptoOperationError
from ..csprng import generate_random_bytes


class ETMMode:

    BLOCK_SIZE = 16
    IV_SIZE = 16
    TAG_SIZE = 32  # HMAC-SHA256 output size

    def __init__(self, key: bytes, iv: bytes = None):

        if len(key) not in (16, 24, 32):
            raise ValueError(f"Ключ должен быть 16, 24 или 32 байта, получено: {len(key)}")

        self.master_key = key

        self.enc_key, self.mac_key = self._derive_keys(key)

        self.aes = AES.new(self.enc_key, AES.MODE_ECB)

        self.iv = iv if iv else generate_random_bytes(self.IV_SIZE)

        if len(self.iv) != self.IV_SIZE:
            raise ValueError(f"IV должен быть {self.IV_SIZE} байт, получено {len(self.iv)}")

    def _derive_keys(self, master_key: bytes) -> tuple:

        hmac_enc = HMAC(master_key)
        hmac_enc.update(b"etm-encryption-key-derivation")
        enc_key = hmac_enc.digest()[:16]  # 128-bit encryption key

        hmac_mac = HMAC(master_key)
        hmac_mac.update(b"etm-authentication-key-derivation")
        mac_key = hmac_mac.digest()  # 256-bit MAC key

        return enc_key, mac_key

    def _increment_counter(self, counter: bytes) -> bytes:

        counter_int = int.from_bytes(counter, 'big')
        counter_int = (counter_int + 1) & ((1 << 128) - 1)
        return counter_int.to_bytes(16, 'big')

    def _ctr_process(self, data: bytes, iv: bytes) -> bytes:

        result = bytearray()
        counter = iv

        for i in range(0, len(data), self.BLOCK_SIZE):
            block = data[i:i + self.BLOCK_SIZE]

            keystream = self.aes.encrypt(counter)

            for j, byte in enumerate(block):
                result.append(byte ^ keystream[j])

            counter = self._increment_counter(counter)

        return bytes(result)

    def _compute_mac(self, ciphertext: bytes, aad: bytes) -> bytes:

        hmac = HMAC(self.mac_key)

        hmac.update(aad)
        hmac.update(len(aad).to_bytes(8, 'big'))

        hmac.update(ciphertext)
        hmac.update(len(ciphertext).to_bytes(8, 'big'))

        return hmac.digest()

    @staticmethod
    def _constant_time_compare(a: bytes, b: bytes) -> bool:

        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:

        ciphertext = self._ctr_process(plaintext, self.iv)

        tag = self._compute_mac(ciphertext, aad)

        return self.iv + ciphertext + tag

    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:

        min_size = self.IV_SIZE + self.TAG_SIZE
        if len(data) < min_size:
            raise ValueError(f"Данные слишком маленькие: {len(data)} байт, минимум {min_size}")

        iv = data[:self.IV_SIZE]
        tag = data[-self.TAG_SIZE:]
        ciphertext = data[self.IV_SIZE:-self.TAG_SIZE]

        expected_tag = self._compute_mac(ciphertext, aad)

        if not self._constant_time_compare(tag, expected_tag):
            raise AuthenticationError(
                "Authentication failed: AAD mismatch or ciphertext tampered"
            )

        plaintext = self._ctr_process(ciphertext, iv)

        return plaintext

    def encrypt_file(self, input_path, output_path, aad: bytes = b""):

        try:
            with open(input_path, 'rb') as f:
                plaintext = f.read()

            result = self.encrypt(plaintext, aad)

            with open(output_path, 'wb') as f:
                f.write(result)

        except (IOError, OSError) as e:
            raise CryptoOperationError(f"File I/O error: {e}")

    def decrypt_file(self, input_path, output_path, aad: bytes = b"", iv: bytes = None):

        try:
            with open(input_path, 'rb') as f:
                data = f.read()

            try:
                plaintext = self.decrypt(data, aad)
            except AuthenticationError:
                output_file = Path(output_path)
                if output_file.exists():
                    output_file.unlink()
                raise

            with open(output_path, 'wb') as f:
                f.write(plaintext)

        except (IOError, OSError) as e:
            raise CryptoOperationError(f"File I/O error: {e}")
