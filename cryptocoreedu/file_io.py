from pathlib import Path


def read_file(file_path: Path) -> bytes:
    try:
        with open(file_path, "rb") as file:
            return file.read()
    except IOError as error:
        raise IOError(f"Failed to read file {file_path}: {error}")


def write_file(file_path: Path, data: bytes) -> None:
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "wb") as file:
            file.write(data)

    except IOError as error:
        raise IOError(f"Failed to write file {file_path}: {error}")