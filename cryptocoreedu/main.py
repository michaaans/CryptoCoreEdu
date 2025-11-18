
from pathlib import Path

from .cli_parser import create_parser
from .exceptions import KeyValidationError, \
    IVValidationError, \
    FileValidationError, \
    CryptoOperationError, \
    ModeNotImplementedError

from .utils.validators import validate_hex_key, validate_hex_iv, validate_file_path

from .file_io import print_error, print_warning, print_success
from .modes.ECBMode import ECBMode
from .modes.CBCMode import CBCMode
from .modes.CFBMode import CFBMode
from .modes.OFBMode import OFBMode
from .modes.CTRMode import CTRMode

import sys


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
        'critical': 110
    }

    def __init__(self):
        self.parser = create_parser()

    def validate_arguments(self, args):
        """
        Валидация аргументов командной строки
        """
        # Проверка корректности использования IV
        if args.encrypt and args.iv:
            if args.mode == 'ecb':
                print_warning("IV игнорируется для режима ECB")
            else:
                print_warning("Переданный IV игнорируется при шифровании. Используется случайно сгенерированный IV")

        if args.decrypt and not args.iv:
            if args.mode != 'ecb':
                print_warning(f"Для режима {args.mode.upper()} IV будет извлечен из файла")

        # Валидация ключа
        try:
            key = validate_hex_key(args.key)

        except KeyValidationError as e:

            print_error("Некорректный ключ", str(e))
            sys.exit(self.ERROR_CODES['key_validation'])

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

    def create_cipher(self, algorithm: str, mode: str, key: bytes):
        """
        Создает объект шифрования для указанного алгоритма и режима
        """
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

    def execute_operation(self, cipher, operation: str, input_path: Path, output_path: Path, iv: bytes, mode: str):
        """
        Выполняет операцию шифрования или дешифрования
        """
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

    def run(self):
        """
        Главный метод запуска приложения
        """
        try:
            # Парсинг аргументов
            args = self.parser.parse_args()

            # Валидация аргументов
            key, iv, input_path, output_path = self.validate_arguments(args)

            # Создание объекта шифрования
            cipher = self.create_cipher(args.algorithm, args.mode, key)

            # Определение операции
            operation = 'encrypt' if args.encrypt else 'decrypt'

            # Выполнение операции
            self.execute_operation(cipher, operation, input_path, output_path, iv, args.mode)

        except KeyboardInterrupt:
            print("\n\n [INFO]  Операция прервана пользователем")
            sys.exit(130)
        except Exception as e:
            print_error("Критическая ошибка", str(e))
            sys.exit(self.ERROR_CODES['critical'])


def main():

    app = CryptoApp()
    app.run()


if __name__ == "__main__":
    main()