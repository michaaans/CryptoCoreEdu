import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from cryptocoreedu.csprng import generate_random_bytes


def test_key_uniqueness():
    key_set = set()
    num_keys = 1000
    for _ in range(num_keys):
        key = generate_random_bytes(16)
        key_hex = key.hex()
        # Проверка на уникальность
        assert key_hex not in key_set, f"Найден дубликат ключа: {key_hex}"
        key_set.add(key_hex)
    print(f"Успешно сгенерировано {len(key_set)} уникальных ключей.")


if __name__ == "__main__":
    test_key_uniqueness()
