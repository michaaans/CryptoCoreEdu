from Crypto.Cipher import AES
from pathlib import Path

from ..file_io import read_file, write_file
import sys


class OFBMode:
    ...