from Crypto.Cipher import AES


BLOCK_SIZE = 16 # 128 bit


''' Реализация режима ECB для AES-128 и реализация паддинга по стандарту PKCS7'''


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


def encrypt_file_ecb(input_file: str, output_file: str, key_text: str):
    key = key_text.encode()
    if len(key) != 16:
        raise ValueError("Неверная длина ключа, ключ должен быть 128 бит (16 байт)")

    cipher = AES.new(key, AES.MODE_ECB)

    try:
        with open(input_file, "rb",) as file_in, open(output_file, "wb") as file_out:

            plaintext = file_in.read()
            padded_data = pad(plaintext)

            encrypted_blocks = []
            for i in range(0, len(padded_data), BLOCK_SIZE):
                block = padded_data[i:i+BLOCK_SIZE]
                encrypted_block = cipher.encrypt(block)
                encrypted_blocks.append(encrypted_block)

            file_out.write(b''.join(encrypted_blocks))

    except Exception as e:
        print(f"Ошибка: {e}")
        exit(1)


def decrypt_file_ecb(input_file: str, output_file: str,  key_text: str):
    key = key_text.encode()

    if len(key) != 16:
        raise ValueError("Неверная длина ключа, ключ должен быть 128 бит (16 байт)")

    cipher = AES.new(key, AES.MODE_ECB)

    try:
        with open(input_file, 'rb') as file_in, open(output_file, "wb") as file_out:
            ciphertext = file_in.read()

            if len(ciphertext) % BLOCK_SIZE != 0:
                raise ValueError("Некорректный размер шифртекста!")

            decrypted_blocks = []
            for i in range(0, len(ciphertext), BLOCK_SIZE):
                block = ciphertext[i:i+BLOCK_SIZE]
                decrypted_block = cipher.decrypt(block)
                decrypted_blocks.append(decrypted_block)

            decrypted_data = b''.join(decrypted_blocks)
            unpadded_data = unpad(decrypted_data)

            file_out.write(unpadded_data)

    except Exception as e:
        print(f"Ошибка: {e}")
        exit(1)