import sys


def extract_iv(filename):
    with open(filename, 'rb') as f:
        iv = f.read(16)
        print("IV в hex формате:")
        print(iv.hex())
        print("\nIV для команды:")
        print(f"--iv {iv.hex()}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python extract_iv.py <файл>")
        sys.exit(1)

    extract_iv(sys.argv[1])