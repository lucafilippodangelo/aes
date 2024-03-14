import unittest
import ctypes
import random
from aes import sub_bytes, sub_bytes_ld, shift_rows_ld, bytes2matrix, matrix2bytes, mix_columns_ld
from ctypes import CDLL
libc = CDLL("libc.so.6")  

rijndael = ctypes.CDLL('./rijndael.so')
#LD this define argument and return types for "expand_key"
rijndael.expand_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)

def generate_random_plaintext(length):
    return bytearray([random.randint(0, 255) for _ in range(length)])

class AesTestMethods(unittest.TestCase):

    ############################################################################################################
    # sub_bytes # tested in both
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
    # shift_rows # tested in both
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

    #@unittest.skip("LD SKIP test_both_shift_rows")
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
    # mix_columns # tested in both
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


    ############################################################################################################
    # KEY SCHEDULE
    ############################################################################################################
   


    def test_expand_key(self): 
        cipher_key = bytearray([0x2b, 0x28, 0xab, 0x09,
                                0x7e, 0xae, 0xf7, 0xcf,
                                0x15, 0xd2, 0x15, 0x4f,
                                0x16, 0xa6, 0x88, 0x3c])

        
        cipher_key_buffer = ctypes.create_string_buffer(bytes(cipher_key), len(cipher_key))#LD Converting bytearray -> ctypes object
        expanded_key_ptr = rijndael.expand_key(ctypes.cast(cipher_key_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        expanded_key_bytes = bytearray(ctypes.cast(expanded_key_ptr, ctypes.POINTER(ctypes.c_ubyte * 176)).contents)

        expected_output = bytearray([0x2b, 0x28, 0xab, 0x9, 0x7e, 0xae, 0xf7, 0xcf, 0x15, 0xd2, 0x15, 0x4f, 0x16, 0xa6, 0x88, 0x3c, 
                                        0xa0, 0x88, 0x23, 0x2a, 0xfa, 0x54, 0xa3, 0x6c, 0xfe, 0x2c, 0x39, 0x76, 0x17, 0xb1, 0x39, 0x5, 
                                        0xf2, 0x7a, 0x59, 0x73, 0xc2, 0x96, 0x35, 0x59, 0x95, 0xb9, 0x80, 0xf6, 0xf2, 0x43, 0x7a, 0x7f, 
                                        0x3d, 0x47, 0x1e, 0x6d, 0x80, 0x16, 0x23, 0x7a, 0x47, 0xfe, 0x7e, 0x88, 0x7d, 0x3e, 0x44, 0x3b, 
                                        0xef, 0xa8, 0xb6, 0xdb, 0x44, 0x52, 0x71, 0xb, 0xa5, 0x5b, 0x25, 0xad, 0x41, 0x7f, 0x3b, 0x0, 
                                        0xd4, 0x7c, 0xca, 0x11, 0xd1, 0x83, 0xf2, 0xf9, 0xc6, 0x9d, 0xb8, 0x15, 0xf8, 0x87, 0xbc, 0xbc, 
                                        0x6d, 0x11, 0xdb, 0xca, 0x88, 0xb, 0xf9, 0x0, 0xa3, 0x3e, 0x86, 0x93, 0x7a, 0xfd, 0x41, 0xfd, 
                                        0x4e, 0x5f, 0x84, 0x4e, 0x54, 0x5f, 0xa6, 0xa6, 0xf7, 0xc9, 0x4f, 0xdc, 0xe, 0xf3, 0xb2, 0x4f, 
                                        0xea, 0xb5, 0x31, 0x7f, 0xd2, 0x8d, 0x2b, 0x8d, 0x73, 0xba, 0xf5, 0x29, 0x21, 0xd2, 0x60, 0x2f, 
                                        0xac, 0x19, 0x28, 0x57, 0x77, 0xfa, 0xd1, 0x5c, 0x66, 0xdc, 0x29, 0x0, 0xf3, 0x21, 0x41, 0x6e, 
                                        0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63, 0xf9, 0x25, 0xc, 0xc, 0xa8, 0x89, 0xc8, 0xa6])
        self.assertEqual(expanded_key_bytes, expected_output) 

        #expanded_key = [hex(byte) for byte in expanded_key_bytes]
        #print(expanded_key)



    #@unittest.skip("LD SKIP test_RotWord")
    def test_RotWord(self):
        expanded_key = [0x2b, 0x28, 0xab, 0x09,
                        0x7e, 0xae, 0xf7, 0xcf,
                        0x15, 0xd2, 0x15, 0x4f,
                        0x16, 0xa6, 0x88, 0x3c,

                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00]
        expanded_key_array = ctypes.create_string_buffer(bytes(bytearray(expanded_key)))
        column = [0x00, 
                  0x00, 
                  0x00, 
                  0x00]
        column_array = ctypes.create_string_buffer(bytes(bytearray(column)))
        rijndael.RotWord(column_array, expanded_key_array, 0)
        expected_rot_column_array = bytearray([0xcf, 0x4f, 0x3c, 0x09])
        print("111")
        self.assertEqual(column_array.raw[:-1], expected_rot_column_array)
        print("111d")

    #@unittest.skip("")
    def test_RotWord2(self):
        expanded_key = [0x2b, 0x28, 0xab, 0x09,
                        0x7e, 0xae, 0xf7, 0xcf,
                        0x15, 0xd2, 0x15, 0x4f,
                        0x16, 0xa6, 0x88, 0x3c,

                        0xa0, 0x88, 0x23, 0x2a,
                        0xfa, 0x54, 0xa3, 0x6c,
                        0xfe, 0x2c, 0x39, 0x76,
                        0x17, 0xb1, 0x39, 0x05,
                         
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00]
        expanded_key_array = ctypes.create_string_buffer(bytes(bytearray(expanded_key)))
        column = [0x00, 
                  0x00, 
                  0x00, 
                  0x00]
        column_array = ctypes.create_string_buffer(bytes(bytearray(column)))
        rijndael.RotWord(column_array, expanded_key_array, 1)
        expected_rot_column_array = bytearray([0x6c, 0x76, 0x05, 0x2a])
        print("222 clean up")
        self.assertEqual(column_array.raw[:-1], expected_rot_column_array)
        print("222d")

    #@unittest.skip("LD SKIP test_SubBytes")
    def test_SubBytes(self):
        column = [0xcf, 
                  0x4f, 
                  0x3c, 
                  0x09]
        column_array = ctypes.create_string_buffer(bytes(bytearray(column)))
        rijndael.SubBytes(column_array)
        expected_sub_column_array = bytearray([0x8a, 0x84, 0xeb, 0x01])
        print("333 clean up")
        self.assertEqual(column_array.raw[:-1], expected_sub_column_array)
        print("333 clean up")

    #@unittest.skip("LD SKIP test_SubBytes2")
    def test_SubBytes2(self):
        column = [0x6c, 0x76, 0x05, 0x2a]
        column_array = ctypes.create_string_buffer(bytes(bytearray(column)))
        rijndael.SubBytes(column_array)
        expected_sub_column_array = bytearray([0x50, 0x38, 0x6b, 0xe5])
        print("444 clean up")
        self.assertEqual(column_array.raw[:-1], expected_sub_column_array)
        print("444 clean up")

    #@unittest.skip("LD SKIP test_ldExtractColumnFromKey")
    def test_ldExtractColumnFromKey(self):
        expanded_key = [0x2b, 0x28, 0xab, 0x09,
                        0x7e, 0xae, 0xf7, 0xcf,
                        0x15, 0xd2, 0x15, 0x4f,
                        0x16, 0xa6, 0x88, 0x3c,

                        0xa0, 0x88, 0x23, 0x2a,
                        0xfa, 0x54, 0xa3, 0x6c,
                        0xfe, 0x2c, 0x39, 0x76,
                        0x17, 0xb1, 0x39, 0x05,
                         
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00]
        expanded_key_array = ctypes.create_string_buffer(bytes(bytearray(expanded_key)))
        column = [0x00, 
                  0x00, 
                  0x00, 
                  0x00]
        column_array = ctypes.create_string_buffer(bytes(bytearray(column)))
        rijndael.ldExtractColumnFromKey(2, expanded_key_array, 1, column_array)
        expected_rot_column_array = bytearray([0x88, 0x54, 0x2c, 0xb1])
        print("555 clean up")
        self.assertEqual(column_array.raw[:-1], expected_rot_column_array)
        print("555 clean up")

if __name__ == '__main__':
    unittest.main()