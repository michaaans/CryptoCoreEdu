from Crypto.Cipher import AES

BLOCK_SIZE = 16 # 128 bit


def pad(data: bytes) -> bytes:
    # Паддинг по PKCS#7.
    if len(data) % BLOCK_SIZE == 0:
        pad_len = BLOCK_SIZE
    else:
        pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    # Удаление паддинга по PKCS#7.
    if not data:
        return data
    pad_len = data[-1]
    # Проверка корректности дополнения
    if pad_len > BLOCK_SIZE or pad_len == 0 or data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Некорректное дополнение")
    return data[:-pad_len]


def encrypt_file_ecb(input_file: str, output_file: str, key: bytes) -> bytes:

    try:
        with open(input_file, "r", encoding="utf-8") as plaintext:
            return ...

    except Exception as e:
        print(f"Ошибка: {e}")
        exit(1)


def main():
    pass


if __name__ == "__main__":
    pass