
from ..hash.sha256 import SHA256


class HMAC:
    """
        Реализация HMAC-SHA256 по стандарту RFC 2104
    """
    BLOCK_SIZE = 64

    OUTPUT_SIZE = 32

    IPAD_BYTE = 0x36
    OPAD_BYTE = 0x5c

    def __init__(self, key: bytes, hash_class=None):

        if hash_class is None:
            hash_class = SHA256

        self.hash_class = hash_class
        self.block_size = self.BLOCK_SIZE

        if isinstance(key, str):
            key = key.encode('utf-8')
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Ключ должен быть в формате байтов")

        self._processed_key = self._process_key(bytes(key))

        self._ipad_key = self._xor_bytes(
            self._processed_key,
            bytes([self.IPAD_BYTE] * self.block_size)
        )
        self._opad_key = self._xor_bytes(
            self._processed_key,
            bytes([self.OPAD_BYTE] * self.block_size)
        )

        self._inner_hash = self.hash_class()
        self._inner_hash.update(self._ipad_key)

        self._finalized = False
        self._result_cache = None

    def _process_key(self, key: bytes) -> bytes:

        if len(key) > self.block_size:
            hasher = self.hash_class()
            hasher.update(key)
            key = hasher.digest()

        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))

        return key

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:

        return bytes(x ^ y for x, y in zip(a, b))

    def update(self, data: bytes) -> 'HMAC':

        if self._finalized:
            raise RuntimeError("HMAC уже завершен. Создайте новый экземпляр.")

        if isinstance(data, str):
            data = data.encode('utf-8')

        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Данные должны быть в формате байтов")

        self._inner_hash.update(data)
        return self

    def digest(self) -> bytes:

        if self._finalized:
            return self._result_cache

        inner_digest = self._inner_hash.digest()

        outer_hash = self.hash_class()
        outer_hash.update(self._opad_key)
        outer_hash.update(inner_digest)

        self._result_cache = outer_hash.digest()
        self._finalized = True

        return self._result_cache

    def hexdigest(self) -> str:

        return self.digest().hex()


def hmac_data(key: bytes, data: bytes) -> str:

    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')

    mac = HMAC(key)
    mac.update(data)
    return mac.hexdigest()


def hmac_file(key: bytes, filename: str, chunk_size: int = 8096) -> str: #131072

    if isinstance(key, str):
        key = key.encode('utf-8')

    mac = HMAC(key)

    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            mac.update(chunk)

    return mac.hexdigest()


def verify_hmac(expected_hmac: str, computed_hmac: str) -> bool:

    expected_hmac = expected_hmac.lower().strip()
    computed_hmac = computed_hmac.lower().strip()

    if len(expected_hmac) != len(computed_hmac):
        return False

    result = 0
    for a, b in zip(expected_hmac, computed_hmac):
        result |= ord(a) ^ ord(b)

    return result == 0


def parse_hmac_file(filepath: str) -> tuple:

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read().strip()

    if not content:
        raise ValueError(f"Файл для проверки пустой: {filepath}")

    parts = content.split()

    if len(parts) >= 1:
        hmac_value = parts[0].lower()

        if not all(c in '0123456789abcdef' for c in hmac_value):
            raise ValueError(f"Неверный формат HMAC: {hmac_value[:20]}...")

        filename = parts[1] if len(parts) > 1 else None
        return hmac_value, filename

    raise ValueError(f"Неверный формат файла HMAC: {filepath}")

