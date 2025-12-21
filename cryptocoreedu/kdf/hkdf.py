
import sys
from pathlib import Path

try:
    from ..mac.hmac import HMAC
except ImportError:
    _current_dir = Path(__file__).resolve().parent
    _project_root = _current_dir.parent
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))
    from mac.hmac import HMAC


def hmac_sha256(key: bytes, message: bytes) -> bytes:

    mac = HMAC(key)
    mac.update(message)
    return mac.digest()


def derive_key(master_key: bytes, context: str, length: int = 32) -> bytes:

    if not master_key:
        raise ValueError("Master key cannot be empty")
    if length < 1:
        raise ValueError("Key length must be at least 1")

    if isinstance(context, str):
        context = context.encode('utf-8')

    hash_len = 32

    blocks_needed = (length + hash_len - 1) // hash_len

    derived = b''

    for counter in range(1, blocks_needed + 1):
        block = hmac_sha256(master_key, context + counter.to_bytes(4, 'big'))
        derived += block

    return derived[:length]


class KeyHierarchy:

    DEFAULT_KEY_LENGTH = 32

    def __init__(self, master_key: bytes):

        if not master_key:
            raise ValueError("Master key cannot be empty")

        if isinstance(master_key, str):
            try:
                master_key = bytes.fromhex(master_key)
            except ValueError:
                master_key = master_key.encode('utf-8')

        self.master_key = bytes(master_key)
        self._cache = {}

    def derive(self, context: str, length: int = None, cache: bool = True) -> bytes:

        length = length or self.DEFAULT_KEY_LENGTH
        cache_key = (context, length)

        if cache and cache_key in self._cache:
            return self._cache[cache_key]

        derived = derive_key(self.master_key, context, length)

        if cache:
            self._cache[cache_key] = derived

        return derived

    def derive_hex(self, context: str, length: int = None) -> str:

        return self.derive(context, length).hex()

    def clear_cache(self):
        self._cache.clear()

