import unittest
import ctypes
import random
from aes import sub_bytes, sub_bytes_ld, shift_rows_ld, bytes2matrix, matrix2bytes, mix_columns_ld

rijndael = ctypes.CDLL('./rijndael.so')

def generate_random_plaintext(length):
    return bytearray([random.randint(0, 255) for _ in range(length)])

class AesTestMethods(unittest.TestCase):

    ############################################################################################################
    # sub_bytes #
    ############################################################################################################
    #@unittest.skip("LD SKIP test_sub_bytes")
    def test_sub_bytes(self):
        plaintext = bytearray([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]) #LD using same input
        #LD need to convert because expecting an int or an immutable sequence of bytes
        block = ctypes.create_string_buffer(bytes(plaintext)) #LD creating a buffer here
        rijndael.sub_bytes(block)
        expected_output = bytearray([0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA])
        self.assertEqual(block.raw[:-1], expected_output)#LD Asserting the match. I did exclude the null terminator "[:-1]". 

        print("--- UT PASSED  test_sub_bytes")

    #@unittest.skip("LD SKIP")
    def test_both_sub_bytes(self):
        num_attempts = 0
        for _ in range(3):
            num_attempts += 1     

            plaintext = generate_random_plaintext(16) 
            #plaintext = bytearray([1, 14, 3, 4, 5, 6, 7, 8, 9, 21, 11, 12, 13, 21, 15, 16])

            block = ctypes.create_string_buffer(bytes(plaintext))
            rijndael.sub_bytes(block)#LD will call the sub_bytes function from C implementation

            expected_output_c = bytes2matrix(block.raw[:-1])#LD Convert the result to a matrix because the method in python gets and returns a matrix
            #LD looks like print by default display bytes in decimal
            #for row in expected_output_c:
                #print([hex(byte) for byte in row])
            
            #LD test id same function in python behave the same
            plaintext_matrix = bytes2matrix(plaintext) #LD convert same input plaintext to a matrix
            expected_output_python = sub_bytes_ld(plaintext_matrix)  #LD now call sub_bytes from aes.py
            #print("sub_bytes P:", expected_output_python)
            #for row in expected_output_python:
                #print([hex(byte) for byte in row])

            print(f"--- LOOP n. {num_attempts} with hexadecimal: {[hex(byte) for byte in plaintext]}")
            self.assertEqual(expected_output_c, expected_output_python)

        # Asserting the match between C and Python results
        #self.assertEqual(expected_output_c, expected_output_python)

        print(f"--- UT PASSED test_both_sub_bytes with {num_attempts} attempts")
        print(f"")

    ############################################################################################################
    # shift_rows #
    ############################################################################################################

    #@unittest.skip("LD SKIP test_shift_rows")
    def test_shift_rows(self):
        plaintext = bytearray([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]) 
        #LD need to convert because expecting an int or an immutable sequence of bytes
        block = ctypes.create_string_buffer(bytes(plaintext)) #LD creating a buffer here
        rijndael.shift_rows(block)
        expected_output = bytearray([0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x05, 0x0B, 0x0C, 0x09, 0x0A, 0x10, 0x0D, 0x0E, 0x0F])
        self.assertEqual(block.raw[:-1], expected_output)#LD Asserting the match. I did exclude the null terminator "[:-1]". 
        print("--- UT PASSED  test_shift_rows")

    def transpose(self, s):
        new_s = [row[:] for row in s]

        for i in range(len(s)):
            for j in range(len(s[0])):
                new_s[i][j] = s[j][i]

        return new_s

    def test_both_shift_rows(self):
        print("--- test")
        num_attempts = 0
        for _ in range(3):
            num_attempts += 1     

            plaintext = generate_random_plaintext(16) 

            block = ctypes.create_string_buffer(bytes(plaintext))
            rijndael.shift_rows(block)#LD will call the shift_rows function from C implementation

            expected_output_c = bytes2matrix(block.raw[:-1])#LD Convert the result to a matrix because the method in python gets and returns a matrix
            #LD looks like print by default display bytes in decimal
            print(f"C return")
            for row in expected_output_c:
                print([hex(byte) for byte in row])
            
            #LD test id same function in python behave the same
            #Eoin explanation:  shift columns instead of a shift rows: the blocks are being stored column-wise rather than row-wise
            plaintext_matrix = bytes2matrix(plaintext)
            expected_matrix = self.transpose(plaintext_matrix)
            output_python = shift_rows_ld(expected_matrix)
            expected_output_python = self.transpose(output_python)

            print(f"P return")
            for row in expected_output_python:
                print([hex(byte) for byte in row])

            print(f"--- LOOP n. {num_attempts} with hexadecimal: {[hex(byte) for byte in plaintext]}")
            self.assertEqual(expected_output_c, expected_output_python)

        print(f"--- UT PASSED test_both_sub_bytes with {num_attempts} attempts")
        print(f"")

    ############################################################################################################
    # mix_columns #
    ############################################################################################################

    #@unittest.skip("LD SKIP mix_columns")
    def test_mix_columns(self):
        plaintext = bytearray([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]) 
        #LD need to convert because expecting an int or an immutable sequence of bytes
        block = ctypes.create_string_buffer(bytes(plaintext)) #LD creating a buffer here
        rijndael.mix_columns(block)
        expected_output = bytearray([0x03, 0x04, 0x09, 0x0A, 0x0F, 0x08, 0x15, 0x1E, 0x0B, 0x0C, 0x01, 0x02, 0x17, 0x10, 0x2D, 0x36])
        self.assertEqual(block.raw[:-1], expected_output)#LD Asserting the match. I did exclude the null terminator "[:-1]". 
        print("--- UT PASSED  test_mix_columns")

    #@unittest.skip("LD SKIP test_both_mix_columns")
    def test_both_mix_columns(self):
        num_attempts = 0
        for _ in range(3):
            num_attempts += 1     

            plaintext = generate_random_plaintext(16) 

            block = ctypes.create_string_buffer(bytes(plaintext))
            rijndael.mix_columns(block)#LD C implementation

            expected_output_c = bytes2matrix(block.raw[:-1])#LD Convert the result to a matrix because the method in python gets and returns a matrix
            print(f"C return")
            for row in expected_output_c:
                print([hex(byte) for byte in row])
            
            #LD test id same function in python behave the same
            plaintext_matrix = bytes2matrix(plaintext) #LD convert same input plaintext to a matrix
            expected_output_python = mix_columns_ld(plaintext_matrix)  #LD now call sub_bytes from aes.py
            print(f"P return")
            for row in expected_output_python:
                print([hex(byte) for byte in row])

            print(f"--- LOOP n. {num_attempts} with hexadecimal: {[hex(byte) for byte in plaintext]}")
            self.assertEqual(expected_output_c, expected_output_python)

        print(f"--- UT PASSED test_both_sub_bytes with {num_attempts} attempts")
        print(f"")

if __name__ == '__main__':
    unittest.main()