import unittest
import ctypes
from aes import *

rijndael = ctypes.CDLL('./rijndael.so')

class AesTestMethods(unittest.TestCase):

    def test_sample_test(self):


        block = ctypes.create_string_buffer(1024)

        rijndael.sub_bytes(block)

        stringValue = str(block.raw)

        print(stringValue)

        self.assertTrue(stringValue.startswith("b'Hello, world"))

if __name__ == '__main__':
    unittest.main()