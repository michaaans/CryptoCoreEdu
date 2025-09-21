import sys


def compare_files(file1, file2):
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        content1 = f1.read()
        content2 = f2.read()

    if content1 == content2:
        print("Файлы идентичны!")
        return True
    else:
        print("Файлы различны!")
        return False


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python tests/compare.py <file1> <file2>")
        sys.exit(1)

    compare_files(sys.argv[1], sys.argv[2])