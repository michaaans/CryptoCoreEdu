import sys
from pathlib import Path

from .cli_parser import create_parser
from .exceptions import KeyValidationError, IVValidationError, FileValidationError, CryptoOperationError, \
    ModeNotImplementedError, UnsupportedAlgorithmError


from .utils.validators import validate_hex_key, validate_hex_iv, validate_file_path

from .file_io import print_error, print_warning, print_success, print_info
from .csprng import generate_random_bytes
from .modes.ECBMode import ECBMode
from .modes.CBCMode import CBCMode
from .modes.CFBMode import CFBMode
from .modes.OFBMode import OFBMode
from .modes.CTRMode import CTRMode

from .hash.sha256 import sha256_file
from .hash.sha3_256 import sha3_256_file


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
        'crypto_args_required': 115
    }

    def __init__(self):
        self.parser = create_parser()

    def validate_crypto_arguments(self, args):

        key = self.validate_key_argument(args)

        # Проверка корректности использования IV
        if args.encrypt and args.iv:
            if args.mode == 'ecb':
                print_warning("IV игнорируется для режима ECB")
            else:
                print_warning("Переданный IV игнорируется при шифровании. Используется случайно сгенерированный IV")

        if args.decrypt and not args.iv:
            if args.mode != 'ecb':
                print_warning(f"Для режима {args.mode.upper()} IV будет извлечен из файла")

        # Валидация IV если передан
        iv = None
        if args.iv:
            try:
                iv = validate_hex_iv(args.iv)

            except IVValidationError as e:

                print_error("Некорректный IV", str(e))
                sys.exit(self.ERROR_CODES['iv_validation'])

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

        # Проверка что файлы не одинаковые
        if input_path.resolve() == output_path.resolve():
            print_error("Входной и выходной файлы не могут быть одинаковыми")
            sys.exit(self.ERROR_CODES['same_files'])

        return key, iv, input_path, output_path

    def validate_hash_arguments(self, args):

        try:
            input_path = validate_file_path(args.input, for_reading=True)
        except FileValidationError as e:
            print_error("Проблема с входным файлом", str(e))
            sys.exit(self.ERROR_CODES['input_file'])

        # Валидация выходного файла (если указан)
        output_path = None
        if args.output:
            try:
                output_path = validate_file_path(args.output, for_reading=False)
            except FileValidationError as e:
                print_error("Проблема с выходным файлом", str(e))
                sys.exit(self.ERROR_CODES['output_file'])

        return input_path, output_path

    def validate_key_argument(self, args):

        # Для дешифрования ключ обязателен
        if args.decrypt and not args.key:
            print_error("Ключ обязателен для дешифрования")
            sys.exit(self.ERROR_CODES['key_required'])

        # Для шифрования ключ может быть сгенерирован автоматически
        if args.encrypt and not args.key:
            try:
                # Генерация случайного 16-байтного ключа
                generated_key_bytes = generate_random_bytes(16)
                generated_key_hex = generated_key_bytes.hex()

                # Вывод сгенерированного ключа
                print_info(f"Сгенерирован случайный ключ: {generated_key_hex}")

                return generated_key_bytes

            except Exception as e:
                print_error("Ошибка генерации ключа", str(e))
                sys.exit(self.ERROR_CODES['rng_error'])

        # Если ключ предоставлен пользователем
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

    def execute_crypto_operation(self, cipher, operation: str, input_path: Path, output_path: Path, iv: bytes, mode: str):

        try:
            if operation == 'encrypt':
                cipher.encrypt_file(input_path, output_path)
                print_success("зашифрован", input_path, output_path, mode)
            else:  # decrypt
                cipher.decrypt_file(input_path, output_path, iv)
                print_success("расшифрован", input_path, output_path, mode)

        except CryptoOperationError as e:
            print_error("Ошибка выполнения операции", str(e))
            sys.exit(self.ERROR_CODES['operation'])
        except Exception as e:
            print_error("Неизвестная ошибка при выполнении операции", str(e))
            sys.exit(self.ERROR_CODES['unknown_operation'])

    def execute_hash_operation(self, algorithm: str, input_path: Path, output_path: Path = None):

        try:
            # Преобразуем строку алгоритма в enum
            if algorithm == 'sha256':
                hash_result = sha256_file(str(input_path))
            elif algorithm == 'sha3-256':
                hash_result = sha3_256_file(str(input_path))

            # Формируем вывод в формате: HASH_VALUE INPUT_FILE_PATH
            output_line = f"{hash_result}  {input_path}\n"

            if output_path:
                # Записываем в файл
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(output_line)
                print_info(f"Хеш {algorithm} записан в файл: {output_path}")
            else:
                # Выводим в stdout
                print(output_line, end='')

        except UnsupportedAlgorithmError as e:
            print_error("Неподдерживаемый алгоритм хеширования", str(e))
            sys.exit(self.ERROR_CODES['hash_algorithm_error'])
        except FileValidationError as e:
            print_error("Ошибка ввода-вывода при хешировании", str(e))
            sys.exit(self.ERROR_CODES['hash_operation_error'])
        except PermissionError as e:
            print_error("Ошибка доступа к файлу", str(e))
            sys.exit(self.ERROR_CODES['input_file'])
        except FileNotFoundError as e:
            print_error("Файл не найден", str(e))
            sys.exit(self.ERROR_CODES['input_file'])
        except Exception as e:
            print_error("Неизвестная ошибка при вычислении хеша", str(e))
            sys.exit(self.ERROR_CODES['hash_operation_error'])

    def run(self):
        """
        Главный метод запуска приложения
        """
        try:
            # Парсинг аргументов
            args = self.parser.parse_args()

            # Если вызвана подкоманда dgst
            if args.command == 'dgst':
                # Обработка команд хеширования
                input_path, output_path = self.validate_hash_arguments(args)
                self.execute_hash_operation(args.algorithm, input_path, output_path)

            elif args.command is None:
                # Проверяем что переданы необходимые аргументы для шифрования
                if not args.algorithm or not args.mode or not args.input or not args.output:
                    self.parser.error("Для основной команды crypto требуются: --algorithm, --mode, --input, --output")

                if not args.encrypt and not args.decrypt:
                    self.parser.error("Необходимо указать --encrypt или --decrypt")

                # Обработка основной команды crypto (шифрование/дешифрование)
                key, iv, input_path, output_path = self.validate_crypto_arguments(args)
                cipher = self.create_cipher(args.algorithm, args.mode, key)
                operation = 'encrypt' if args.encrypt else 'decrypt'
                self.execute_crypto_operation(cipher, operation, input_path, output_path, iv, args.mode)

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