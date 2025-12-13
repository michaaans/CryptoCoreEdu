import sys
import os
from pathlib import Path

from .cli_parser import create_parser
from .exceptions import (
    KeyValidationError, IVValidationError, FileValidationError,
    CryptoOperationError, ModeNotImplementedError, UnsupportedAlgorithmError,
    AuthenticationError
)

from .utils.validators import validate_hex_key, validate_hex_iv, validate_file_path

from .file_io import print_error, print_warning, print_success, print_info
from .csprng import generate_random_bytes
from .modes.ECBMode import ECBMode
from .modes.CBCMode import CBCMode
from .modes.CFBMode import CFBMode
from .modes.OFBMode import OFBMode
from .modes.CTRMode import CTRMode
from .modes.GCMMode import GCMMode
from .modes.ETMMode import ETMMode

from .hash.sha256 import sha256_file
from .hash.sha3_256 import sha3_256_file

from .mac.hmac import HMAC, hmac_file, verify_hmac, parse_hmac_file


class CryptoApp:
    """
    Основной класс приложения, управляющий всей логикой
    """

    # Коды ошибок
    ERROR_CODES = {
        'key_validation': 101,
        'iv_validation': 102,
        'input_file': 103,
        'output_file': 104,
        'same_files': 105,
        'mode_not_implemented': 106,
        'mode_initialization': 107,
        'operation': 108,
        'unknown_operation': 109,
        'critical': 110,
        'key_required': 111,
        'rng_error': 112,
        'hash_algorithm_error': 113,
        'hash_operation_error': 114,
        'crypto_args_required': 115,
        'hmac_key_required': 116,
        'hmac_key_invalid': 117,
        'hmac_verification_failed': 118,
        'verify_file_error': 119,
        'aad_validation': 120,
        'authentication_failed': 121,
        'nonce_validation': 122,
    }

    # AEAD режимы (authenticated encryption)
    AEAD_MODES = {'gcm', 'etm'}

    def __init__(self):
        self.parser = create_parser()

    def validate_aad(self, aad_hex: str) -> bytes:
        """
        Валидация и преобразование AAD из hex строки.
        """
        if not aad_hex:
            return b''

        aad_hex = aad_hex.strip()

        if len(aad_hex) == 0:
            return b''

        if len(aad_hex) % 2 != 0:
            print_error(
                "Некорректная длина AAD",
                f"Hex строка должна иметь чётное количество символов. Получено: {len(aad_hex)}"
            )
            sys.exit(self.ERROR_CODES['aad_validation'])

        valid_hex_chars = set('0123456789abcdefABCDEF')
        invalid_chars = set(aad_hex) - valid_hex_chars
        if invalid_chars:
            print_error(
                "Некорректные символы в AAD",
                f"Допустимы только hex символы: 0-9, a-f, A-F. Найдены: {invalid_chars}"
            )
            sys.exit(self.ERROR_CODES['aad_validation'])

        try:
            return bytes.fromhex(aad_hex)
        except ValueError as e:
            print_error("Ошибка преобразования AAD", str(e))
            sys.exit(self.ERROR_CODES['aad_validation'])

    def validate_nonce(self, nonce_hex: str, mode: str) -> bytes:

        if not nonce_hex:
            return None

        nonce_hex = nonce_hex.strip()

        # Проверка hex формата
        if len(nonce_hex) % 2 != 0:
            print_error(
                "Некорректная длина nonce/IV",
                f"Hex строка должна иметь чётное количество символов. Получено: {len(nonce_hex)}"
            )
            sys.exit(self.ERROR_CODES['nonce_validation'])

        valid_hex_chars = set('0123456789abcdefABCDEF')
        invalid_chars = set(nonce_hex) - valid_hex_chars
        if invalid_chars:
            print_error(
                "Некорректные символы в nonce/IV",
                f"Допустимы только hex символы. Найдены: {invalid_chars}"
            )
            sys.exit(self.ERROR_CODES['nonce_validation'])

        try:
            nonce_bytes = bytes.fromhex(nonce_hex)
        except ValueError as e:
            print_error("Ошибка преобразования nonce/IV", str(e))
            sys.exit(self.ERROR_CODES['nonce_validation'])

        # Проверка длины в зависимости от режима
        if mode == 'gcm':
            if len(nonce_bytes) != 12:
                print_error(
                    "Некорректная длина nonce для GCM",
                    f"Nonce должен быть 12 байт (24 hex символа). Получено: {len(nonce_bytes)} байт"
                )
                sys.exit(self.ERROR_CODES['nonce_validation'])
        elif mode == 'etm':
            if len(nonce_bytes) != 16:
                print_error(
                    "Некорректная длина IV для ETM",
                    f"IV должен быть 16 байт (32 hex символа). Получено: {len(nonce_bytes)} байт"
                )
                sys.exit(self.ERROR_CODES['nonce_validation'])
        else:
            # Для других режимов - 16 байт
            if len(nonce_bytes) != 16:
                print_error(
                    "Некорректная длина IV",
                    f"IV должен быть 16 байт (32 hex символа). Получено: {len(nonce_bytes)} байт"
                )
                sys.exit(self.ERROR_CODES['iv_validation'])

        return nonce_bytes

    def validate_crypto_arguments(self, args):
        """
        Валидация аргументов для криптографических операций.
        """
        key = self.validate_key_argument(args)

        # Получаем nonce/iv (--nonce имеет приоритет над --iv для GCM)
        nonce_hex = None
        if args.mode == 'gcm' and hasattr(args, 'nonce') and args.nonce:
            nonce_hex = args.nonce
        elif hasattr(args, 'iv') and args.iv:
            nonce_hex = args.iv

        # Специальная обработка для AEAD режимов
        if args.mode in self.AEAD_MODES:
            if args.encrypt and nonce_hex:
                print_warning(
                    f"Переданный nonce/IV игнорируется при шифровании в режиме {args.mode.upper()}. "
                    "Используется случайно сгенерированный nonce"
                )
                nonce_hex = None

            if args.decrypt and nonce_hex:
                print_info(f"Используется nonce/IV из командной строки для режима {args.mode.upper()}")
        else:
            # Обычная обработка для других режимов
            if args.encrypt and nonce_hex:
                if args.mode == 'ecb':
                    print_warning("IV игнорируется для режима ECB")
                else:
                    print_warning("Переданный IV игнорируется при шифровании. Используется случайно сгенерированный IV")
                nonce_hex = None

            if args.decrypt and not nonce_hex:
                if args.mode != 'ecb':
                    print_warning(f"Для режима {args.mode.upper()} IV будет извлечен из файла")

        # Валидация nonce/IV
        iv = self.validate_nonce(nonce_hex, args.mode) if nonce_hex else None

        # Валидация путей к файлам
        try:
            input_path = validate_file_path(args.input, for_reading=True)
        except FileValidationError as e:
            print_error("Проблема с входным файлом", str(e))
            sys.exit(self.ERROR_CODES['input_file'])

        try:
            output_path = validate_file_path(args.output, for_reading=False)
        except FileValidationError as e:
            print_error("Проблема с выходным файлом", str(e))
            sys.exit(self.ERROR_CODES['output_file'])

        if input_path.resolve() == output_path.resolve():
            print_error("Входной и выходной файлы не могут быть одинаковыми")
            sys.exit(self.ERROR_CODES['same_files'])

        # Валидация AAD для AEAD режимов
        aad = b''
        if hasattr(args, 'aad') and args.aad:
            aad = self.validate_aad(args.aad)

        return key, iv, input_path, output_path, aad

    def validate_hash_arguments(self, args):
        try:
            input_path = validate_file_path(args.input, for_reading=True)
        except FileValidationError as e:
            print_error("Проблема с входным файлом", str(e))
            sys.exit(self.ERROR_CODES['input_file'])

        output_path = None
        if args.output:
            try:
                output_path = validate_file_path(args.output, for_reading=False)
            except FileValidationError as e:
                print_error("Проблема с выходным файлом", str(e))
                sys.exit(self.ERROR_CODES['output_file'])

        return input_path, output_path

    def validate_hmac_arguments(self, args):
        if not args.key:
            print_error(
                "Ключ обязателен для HMAC",
                "Укажите --key с hex-строкой ключа"
            )
            sys.exit(self.ERROR_CODES['hmac_key_required'])

        key_hex = args.key.strip().lower()

        if len(key_hex) == 0:
            print_error("Ключ не может быть пустым")
            sys.exit(self.ERROR_CODES['hmac_key_invalid'])

        if len(key_hex) % 2 != 0:
            print_error(
                "Некорректная длина ключа",
                f"Hex строка должна иметь чётное количество символов. Получено: {len(key_hex)}"
            )
            sys.exit(self.ERROR_CODES['hmac_key_invalid'])

        valid_hex_chars = set('0123456789abcdef')
        invalid_chars = set(key_hex) - valid_hex_chars
        if invalid_chars:
            print_error(
                "Некорректные символы в ключе",
                f"Допустимы только hex символы. Найдены: {invalid_chars}"
            )
            sys.exit(self.ERROR_CODES['hmac_key_invalid'])

        try:
            key_bytes = bytes.fromhex(key_hex)
        except ValueError as e:
            print_error("Ошибка преобразования ключа", str(e))
            sys.exit(self.ERROR_CODES['hmac_key_invalid'])

        try:
            input_path = validate_file_path(args.input, for_reading=True)
        except FileValidationError as e:
            print_error("Проблема с входным файлом", str(e))
            sys.exit(self.ERROR_CODES['input_file'])

        output_path = None
        if args.output:
            try:
                output_path = validate_file_path(args.output, for_reading=False)
            except FileValidationError as e:
                print_error("Проблема с выходным файлом", str(e))
                sys.exit(self.ERROR_CODES['output_file'])

        verify_path = None
        if args.verify:
            try:
                verify_path = validate_file_path(args.verify, for_reading=True)
            except FileValidationError as e:
                print_error("Проблема с файлом верификации", str(e))
                sys.exit(self.ERROR_CODES['verify_file_error'])

        return key_bytes, input_path, output_path, verify_path

    def validate_key_argument(self, args):
        if args.decrypt and not args.key:
            print_error("Ключ обязателен для дешифрования")
            sys.exit(self.ERROR_CODES['key_required'])

        if args.encrypt and not args.key:
            try:
                generated_key_bytes = generate_random_bytes(16)
                generated_key_hex = generated_key_bytes.hex()
                print_info(f"Сгенерирован случайный ключ: {generated_key_hex}")
                return generated_key_bytes
            except Exception as e:
                print_error("Ошибка генерации ключа", str(e))
                sys.exit(self.ERROR_CODES['rng_error'])

        if args.key:
            try:
                return validate_hex_key(args.key)
            except KeyValidationError as e:
                print_error("Некорректный ключ", str(e))
                sys.exit(self.ERROR_CODES['key_validation'])

    def create_cipher(self, algorithm: str, mode: str, key: bytes):
        try:
            if algorithm == 'aes':
                if mode == 'ecb':
                    return ECBMode(key)
                elif mode == 'cbc':
                    return CBCMode(key)
                elif mode == 'cfb':
                    return CFBMode(key)
                elif mode == 'ofb':
                    return OFBMode(key)
                elif mode == 'ctr':
                    return CTRMode(key)
                elif mode == 'gcm':
                    return GCMMode(key)
                elif mode == 'etm':
                    return ETMMode(key)
                else:
                    raise ModeNotImplementedError(f"Режим {mode} пока не реализован")
            else:
                raise ModeNotImplementedError(f"Алгоритм {algorithm} не поддерживается")

        except ModeNotImplementedError as e:
            print_error("Неподдерживаемый режим", str(e))
            sys.exit(self.ERROR_CODES['mode_not_implemented'])

        except Exception as e:
            print_error("Ошибка инициализации режима шифрования", str(e))
            sys.exit(self.ERROR_CODES['mode_initialization'])

    def execute_crypto_operation(self, cipher, operation: str, input_path: Path,
                                 output_path: Path, iv: bytes, mode: str, aad: bytes = b""):
        """
        Выполнение криптографической операции.
        """
        try:
            if operation == 'encrypt':
                if mode in self.AEAD_MODES:
                    cipher.encrypt_file(input_path, output_path, aad)
                    mode_name = "GCM" if mode == "gcm" else "ETM (CTR+HMAC)"
                    print_success(f"зашифрован ({mode_name} authenticated)", input_path, output_path, mode)
                    if aad:
                        print_info(f"AAD: {aad.hex()}")
                else:
                    cipher.encrypt_file(input_path, output_path)
                    print_success("зашифрован", input_path, output_path, mode)

            else:  # decrypt
                if mode in self.AEAD_MODES:
                    try:
                        cipher.decrypt_file(input_path, output_path, aad, iv)
                        mode_name = "GCM" if mode == "gcm" else "ETM (CTR+HMAC)"
                        print_success(f"расшифрован ({mode_name} аутентификация успешна)", input_path, output_path,
                                      mode)

                    except AuthenticationError as e:
                        if output_path.exists():
                            output_path.unlink()

                        print_error(
                            "Ошибка аутентификации",
                            str(e) + "\n         Возможные причины:\n"
                                     "         - Неверный AAD\n"
                                     "         - Повреждённые данные\n"
                                     "         - Неверный ключ"
                        )
                        sys.exit(self.ERROR_CODES['authentication_failed'])
                else:
                    cipher.decrypt_file(input_path, output_path, iv)
                    print_success("расшифрован", input_path, output_path, mode)

        except AuthenticationError as e:
            if output_path.exists():
                output_path.unlink()
            print_error("Ошибка аутентификации", str(e))
            sys.exit(self.ERROR_CODES['authentication_failed'])

        except CryptoOperationError as e:
            print_error("Ошибка выполнения операции", str(e))
            sys.exit(self.ERROR_CODES['operation'])

        except Exception as e:
            print_error("Неизвестная ошибка при выполнении операции", str(e))
            sys.exit(self.ERROR_CODES['unknown_operation'])

    def execute_hash_operation(self, algorithm: str, input_path: Path, output_path: Path = None):
        try:
            if algorithm == 'sha256':
                hash_result = sha256_file(str(input_path))
            elif algorithm == 'sha3-256':
                hash_result = sha3_256_file(str(input_path))
            else:
                raise UnsupportedAlgorithmError(f"Неподдерживаемый алгоритм: {algorithm}")

            output_line = f"{hash_result}  {input_path}\n"

            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(output_line)
                print_info(f"Хеш {algorithm.upper()} записан в файл: {output_path}")
            else:
                print(output_line, end='')

        except UnsupportedAlgorithmError as e:
            print_error("Неподдерживаемый алгоритм хеширования", str(e))
            sys.exit(self.ERROR_CODES['hash_algorithm_error'])
        except Exception as e:
            print_error("Ошибка при вычислении хеша", str(e))
            sys.exit(self.ERROR_CODES['hash_operation_error'])

    def execute_hmac_operation(self, key: bytes, input_path: Path,
                               output_path: Path = None, verify_path: Path = None):
        try:
            computed_hmac = hmac_file(key, str(input_path), chunk_size=131072)

            if verify_path:
                try:
                    expected_hmac, _ = parse_hmac_file(str(verify_path))
                except ValueError as e:
                    print_error("Ошибка парсинга файла верификации", str(e))
                    sys.exit(self.ERROR_CODES['verify_file_error'])

                if verify_hmac(expected_hmac, computed_hmac):
                    print("[OK] HMAC verification successful")
                    sys.exit(0)
                else:
                    print("[ERROR] HMAC verification failed", file=sys.stderr)
                    sys.exit(self.ERROR_CODES['hmac_verification_failed'])

            output_line = f"{computed_hmac}  {input_path}\n"

            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(output_line)
                print_info(f"HMAC-SHA256 записан в файл: {output_path}")
            else:
                print(output_line, end='')

        except Exception as e:
            print_error("Ошибка при вычислении HMAC", str(e))
            sys.exit(self.ERROR_CODES['hash_operation_error'])

    def run(self):
        """Главный метод запуска приложения"""
        try:
            args = self.parser.parse_args()

            if args.command == 'dgst':
                if args.hmac:
                    key, input_path, output_path, verify_path = self.validate_hmac_arguments(args)
                    self.execute_hmac_operation(key, input_path, output_path, verify_path)
                else:
                    input_path, output_path = self.validate_hash_arguments(args)
                    self.execute_hash_operation(args.algorithm, input_path, output_path)

            elif args.command is None:
                if not args.algorithm or not args.mode or not args.input or not args.output:
                    self.parser.error("Для шифрования требуются: --algorithm, --mode, --input, --output")

                if not args.encrypt and not args.decrypt:
                    self.parser.error("Необходимо указать --encrypt или --decrypt")

                key, iv, input_path, output_path, aad = self.validate_crypto_arguments(args)
                cipher = self.create_cipher(args.algorithm, args.mode, key)
                operation = 'encrypt' if args.encrypt else 'decrypt'

                self.execute_crypto_operation(
                    cipher, operation, input_path, output_path, iv, args.mode, aad
                )

            else:
                self.parser.error(f"Неизвестная команда: {args.command}")

        except KeyboardInterrupt:
            print("\n\n[INFO] Операция прервана пользователем")
            sys.exit(130)
        except Exception as e:
            print_error("Критическая ошибка", str(e))
            sys.exit(self.ERROR_CODES['critical'])


def main():
    app = CryptoApp()
    app.run()


if __name__ == "__main__":
    main()