
class CryptoError(Exception):
    """Базовое исключение для ошибок криптобиблиотеки"""
    pass


class KeyValidationError(CryptoError):
    """Ошибка валидации ключа"""
    pass


class IVValidationError(CryptoError):
    """Ошибка валидации IV"""
    pass


class FileValidationError(CryptoError):
    """Ошибка валидации файлов"""
    pass


class CryptoOperationError(CryptoError):
    """Ошибка выполнения криптооперации"""
    pass


class ModeNotImplementedError(CryptoError):
    """Ошибка неподдерживаемого режима"""
    pass
