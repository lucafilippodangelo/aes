import unittest
import ctypes
import random
import copy
from aes.aes import sub_bytes, shift_rows, bytes2matrix, matrix2bytes, mix_columns, inv_mix_columns, inv_shift_rows, add_round_key, AES
from ctypes import CDLL
libc = CDLL("libc.so.6")

rijndael = ctypes.CDLL('./rijndael.so')
#LD this define argument and return types for "expand_key"
rijndael.expand_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)

rijndael.aes_encrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

rijndael.aes_decrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

def generate_random_plaintext(length):
    return bytearray([random.randint(0, 255) for _ in range(length)])

def turnMatrixLd(plaintext):
    #ogni 4 bytes e' una colonna(visualizzata) ruotata in senso antiorario di 90 gradi
    indices = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15] #LD switch of indexes to turn current ROW_1 to COL_1 etc..
    plaintext_turned = bytearray(plaintext[i] for i in indices) #LD going to create new array based on indices
    return plaintext_turned

def turnMatrixLd_reverse(plaintext_turned):
    indices_reverse = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    plaintext_original = bytearray(0 for _ in range(len(plaintext_turned)))
    for i, idx in enumerate(indices_reverse):
        plaintext_original[idx] = plaintext_turned[i] # Reverting the order
    return plaintext_original

class AesTestMethods(unittest.TestCase):

    ############################################################################################################
    ### sub_bytes ### 
    # CONTENT:
    # "test_sub_bytes" -> testing the C function
    # "test_both_sub_bytes" -> testing both C and Python with 3 random input and asserting on equal results
    #TO UNCOMMENT
    ############################################################################################################

    def test_sub_bytes(self):
        plaintext = bytearray([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]) #LD using same input
        #LD need to convert because expecting an int or an immutable sequence of bytes
        block = ctypes.create_string_buffer(bytes(plaintext)) 
        rijndael.sub_bytes(block)
        expected_output = bytearray([0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA])
        self.assertEqual(block.raw[:-1], expected_output)#LD Asserting the match. I did exclude the null terminator "[:-1]".

    def test_both_sub_bytes(self):
        num_attempts = 0
        for _ in range(3):
            num_attempts += 1

            plaintext = generate_random_plaintext(16)

            block = ctypes.create_string_buffer(bytes(plaintext))
            rijndael.sub_bytes(block)#LD will call the sub_bytes function from C implementation
            expected_output_c = bytes2matrix(block.raw[:-1])#LD Convert the result to a matrix because the method in python gets and returns a matrix

            plaintext_matrix = bytes2matrix(plaintext) #LD convert same input plaintext to a matrix
            sub_bytes(plaintext_matrix)  #LD now call sub_bytes from aes.py
            #print("sub_bytes P:", expected_output_python)
            #for row in expected_output_python:
                #print([hex(byte) for byte in row])

            #TO UNCOMMENT print(f"--- LOOP n. {num_attempts} with hexadecimal: {[hex(byte) for byte in plaintext]}")
            self.assertEqual(expected_output_c, plaintext_matrix)


    ############################################################################################################
    ### invert_sub_bytes ###
    # CONTENT:  
    # "test_invert_sub_bytes" -> testing the C function
    # "test_both_invert_sub_bytes" -> testing both C and Python with 3 random input and asserting on equal results    
    #TO UNCOMMENT    
    ############################################################################################################

    def test_invert_sub_bytes(self):
        #LD using inverted "bytearray" used in "test_sub_bytes"
        plaintext = bytearray([0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA])
        block = ctypes.create_string_buffer(bytes(plaintext))
        rijndael.invert_sub_bytes(block)
        expected_output = bytearray([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
        self.assertEqual(block.raw[:-1], expected_output)

    def test_both_invert_sub_bytes(self):
        num_attempts = 0
        for _ in range(3):
            num_attempts += 1

            plaintext = generate_random_plaintext(16)

            block = ctypes.create_string_buffer(bytes(plaintext))
            rijndael.sub_bytes(block)#LD will call the sub_bytes function from C implementation
            expected_output_c = bytes2matrix(block.raw[:-1])#LD Convert the result to a matrix because the method in python gets and returns a matrix
           
            plaintext_matrix = bytes2matrix(plaintext) #LD convert same input plaintext to a matrix
            sub_bytes(plaintext_matrix)  #LD now call sub_bytes from aes.py
            #print("sub_bytes P:", expected_output_python)
            #for row in expected_output_python:
                #print([hex(byte) for byte in row])

            #TO UNCOMMENT print(f"--- LOOP invert sub bytes both n. {num_attempts} with hexadecimal: {[hex(byte) for byte in plaintext]}")
            self.assertEqual(expected_output_c, plaintext_matrix)


    ############################################################################################################
    ### shift_rows ### 
    # CONTENT:  
    # "test_shift_rows" -> testing the C function
    # "transpose" -> In python shift columns instead of a shift rows, the blocks are being stored column-wise rather than row-wise
    # "test_both_shift_rows" -> testing both C and Python with 3 random input and asserting on equal results    
    #TO UNCOMMENT 
    ############################################################################################################

    def test_shift_rows(self):
        plaintext = bytearray([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        block = ctypes.create_string_buffer(bytes(plaintext)) 
        rijndael.shift_rows(block)
        expected_output = bytearray([0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x05, 0x0B, 0x0C, 0x09, 0x0A, 0x10, 0x0D, 0x0E, 0x0F])
        self.assertEqual(block.raw[:-1], expected_output)#LD Asserting the match. I did exclude the null terminator "[:-1]".

    def transpose(self, s):
        new_s = [row[:] for row in s]
        for i in range(len(s)):
            for j in range(len(s[0])):
                new_s[i][j] = s[j][i]
        return new_s

    def test_both_shift_rows(self):
        num_attempts = 0
        for _ in range(3):
            num_attempts += 1

            plaintext = generate_random_plaintext(16)

            block = ctypes.create_string_buffer(bytes(plaintext))
            rijndael.shift_rows(block)#LD will call the shift_rows function from C implementation
            expected_output_c = bytes2matrix(block.raw[:-1])#LD Convert the result to a matrix because the method in python gets and returns a matrix
            #LD looks like print by default display bytes in decimal
            # print(f"C return")
            # for row in expected_output_c:
            #     print([hex(byte) for byte in row])

            #LD test id same function in python behave the same
            #Eoin explanation:  shift columns instead of a shift rows: the blocks are being stored column-wise rather than row-wise
            plaintext_matrix = bytes2matrix(plaintext)
            expected_matrix = self.transpose(plaintext_matrix)
            shift_rows(expected_matrix)
            expected_output_python = self.transpose(expected_matrix)

            # print(f"P return")
            # for row in expected_output_python:
            #     print([hex(byte) for byte in row])

            #TO UNCOMMENT print(f"--- LOOP test_both_shift_rows n. {num_attempts} with hexadecimal: {[hex(byte) for byte in plaintext]}")
            self.assertEqual(expected_output_c, expected_output_python)

    ############################################################################################################
    ### invert_shift_rows ### 
    # CONTENT:  
    # "test_invert_shift_rows" -> testing the C function
    # "transpose" -> In python shift columns instead of a shift rows, the blocks are being stored column-wise rather than row-wise
    # "test_invert_shift_rows" -> testing both C and Python with 3 random input and asserting on equal results     
    ############################################################################################################


    def test_invert_shift_rows(self):
        plaintext = bytearray([0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x05, 0x0B, 0x0C, 0x09, 0x0A, 0x10, 0x0D, 0x0E, 0x0F])
        block = ctypes.create_string_buffer(bytes(plaintext))
        rijndael.invert_shift_rows(block)
        expected_output = bytearray([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
        self.assertEqual(block.raw[:-1], expected_output)
        
    def test_invert_both_shift_rows(self):
        num_attempts = 0
        for _ in range(3):
            num_attempts += 1

            plaintext = generate_random_plaintext(16)

            block = ctypes.create_string_buffer(bytes(plaintext))
            rijndael.invert_shift_rows(block)
            expected_output_c = bytes2matrix(block.raw[:-1])
 
            plaintext_matrix = bytes2matrix(plaintext)
            expected_matrix = self.transpose(plaintext_matrix)
            inv_shift_rows(expected_matrix)
            expected_output_python = self.transpose(expected_matrix)

            #print(f"--- LOOP inv_shift_rows n. {num_attempts} with hexadecimal: {[hex(byte) for byte in plaintext]}")
            self.assertEqual(expected_output_c, expected_output_python)

   
    ############################################################################################################
    ### test_mix_columns ### 
    # CONTENT:  
    # "test_mix_columns" -> testing the C function in isulation. Assert against a valid expected output
    # "test_mix_columns_python" -> testing the Python function in isulation. Assert against a valid expected output
    # "test_both_mix_columns" -> Now that with the above two tests it's ensured that the methos assert are correct,
    #                            a third test is testing both C and Python with 3 random input and asserting on equal returns 
    ############################################################################################################

    def test_mix_columns(self):
        plaintext = bytearray([0xd4, 0xe0, 0xb8, 0x1e,
                                0xbf, 0xb4, 0x41, 0x27,
                                0x5d, 0x52, 0x11, 0x98,
                                0x30, 0xae, 0xf1, 0xe5])

        block = ctypes.create_string_buffer(bytes(plaintext)) 
        rijndael.mix_columns(block)

        expected_output = bytearray([0x04, 0xe0, 0x48, 0x28,
                                    0x66, 0xcb, 0xf8, 0x06,
                                    0x81, 0x19, 0xd3, 0x26,
                                    0xe5, 0x9a, 0x7a, 0x4c])
        
        self.assertEqual(block.raw[:-1], expected_output)#LD Asserting the match. I did exclude the null terminator "[:-1]".


    def test_mix_columns_python(self):
        plaintext = bytearray([0xd4, 0xe0, 0xb8, 0x1e,
                                0xbf, 0xb4, 0x41, 0x27,
                                0x5d, 0x52, 0x11, 0x98,
                                0x30, 0xae, 0xf1, 0xe5])
        
        expected_output = bytearray([0x04, 0xe0, 0x48, 0x28,
                                    0x66, 0xcb, 0xf8, 0x06,
                                    0x81, 0x19, 0xd3, 0x26,
                                    0xe5, 0x9a, 0x7a, 0x4c])

        flipped = turnMatrixLd(plaintext)
        bytesListToMatrix = bytes2matrix(flipped)
        mix_columns(bytesListToMatrix)
        self.assertEqual(expected_output, turnMatrixLd_reverse(matrix2bytes(bytesListToMatrix)))


    def test_both_mix_columns(self):
        num_attempts = 0
        for _ in range(3):
            num_attempts += 1

            plaintext = generate_random_plaintext(16)

            block = ctypes.create_string_buffer(bytes(plaintext))
            rijndael.mix_columns(block)#LD C implementation

            expected_output_c = block.raw[:-1]
            # print(f"C return")
            # for row in expected_output_c:
            #     print([hex(byte) for byte in row])

            #LD test id same function in python behave the same
            flipped = turnMatrixLd(plaintext)
            bytesListToMatrix = bytes2matrix(flipped)
            mix_columns(bytesListToMatrix)
            self.assertEqual(expected_output_c, turnMatrixLd_reverse(matrix2bytes(bytesListToMatrix)))

            #TO UNCOMMENT print(f"--- LOOP n. {num_attempts} with hexadecimal: {[hex(byte) for byte in plaintext]}")


    ############################################################################################################
    ### test_invert_mix_columns ###
    # CONTENT:  
    # "test_invert_mix_columns" -> testing the C function in isulation. Assert against a valid expected output
    # "test_invert_mix_columns_python" -> testing the Python function in isulation. Assert against a valid expected output
    # "test_invert_both_mix_columns" -> Now that with the above two tests it's ensured that the methos assert are correct,
    #                                   a third test is testing both C and Python with 3 random input and asserting on equal returns             
    ############################################################################################################


    def test_invert_mix_columns(self):
        plaintext = bytearray([0x04, 0xe0, 0x48, 0x28,
                                0x66, 0xcb, 0xf8, 0x06,
                                0x81, 0x19, 0xd3, 0x26,
                                0xe5, 0x9a, 0x7a, 0x4c])
        
        block = ctypes.create_string_buffer(bytes(plaintext))
        rijndael.invert_mix_columns(block)

        expected_output = bytearray([0xd4, 0xe0, 0xb8, 0x1e,
                                    0xbf, 0xb4, 0x41, 0x27,
                                    0x5d, 0x52, 0x11, 0x98,
                                    0x30, 0xae, 0xf1, 0xe5])
        self.assertEqual(block.raw[:-1], expected_output)


    def test_invert_mix_columns_python(self):
        plaintext = bytearray([0x04, 0xe0, 0x48, 0x28,
                                0x66, 0xcb, 0xf8, 0x06,
                                0x81, 0x19, 0xd3, 0x26,
                                0xe5, 0x9a, 0x7a, 0x4c])
        
        expected_output = bytearray([0xd4, 0xe0, 0xb8, 0x1e,
                                    0xbf, 0xb4, 0x41, 0x27,
                                    0x5d, 0x52, 0x11, 0x98,
                                    0x30, 0xae, 0xf1, 0xe5])

        flipped = turnMatrixLd(plaintext)
        bytesListToMatrix = bytes2matrix(flipped)
        inv_mix_columns(bytesListToMatrix)
        self.assertEqual(expected_output, turnMatrixLd_reverse(matrix2bytes(bytesListToMatrix)))

        
    def test_invert_both_mix_columns(self):
        num_attempts = 0
        for _ in range(3):
            num_attempts += 1

            plaintext = generate_random_plaintext(16)

            block = ctypes.create_string_buffer(bytes(plaintext))
            rijndael.invert_mix_columns(block)#LD C implementation

            expected_output_c = block.raw[:-1]

            #LD test id same function in python behave the same
            flipped = turnMatrixLd(plaintext)
            bytesListToMatrix = bytes2matrix(flipped)
            inv_mix_columns(bytesListToMatrix)
            self.assertEqual(expected_output_c, turnMatrixLd_reverse(matrix2bytes(bytesListToMatrix)))


    ############################################################################################################
    ### test_expand_key ###
    # CONTENT:  
    # "test_expand_key" -> testing the C function in isulation. Assert against a valid expected output(same content as animation)
    # "test_expand_key_python" ->   
    # "test_expand_key_both" ->       
    ############################################################################################################

    def test_expand_key(self):
        cipher_key = bytearray([0x2b, 0x28, 0xab, 0x09,
                                0x7e, 0xae, 0xf7, 0xcf,
                                0x15, 0xd2, 0x15, 0x4f,
                                0x16, 0xa6, 0x88, 0x3c])


        cipher_key_buffer = ctypes.create_string_buffer(bytes(cipher_key), len(cipher_key))#LD Converting bytearray -> ctypes object
        expanded_key_ptr = rijndael.expand_key(ctypes.cast(cipher_key_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        expanded_key_bytes = bytearray(ctypes.cast(expanded_key_ptr, ctypes.POINTER(ctypes.c_ubyte * 176)).contents)

        # expanded_key = [hex(byte) for byte in expanded_key_bytes]
        # print(expanded_key)

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


    def test_expand_key_python(self):

        master_key = bytearray([0x2b, 0x28, 0xab, 0x09,
                                0x7e, 0xae, 0xf7, 0xcf,
                                0x15, 0xd2, 0x15, 0x4f,
                                0x16, 0xa6, 0x88, 0x3c])
        aes = AES(turnMatrixLd(master_key))

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


        concatenated_bytes_formatted = bytearray()  #LD I will store here the formatted bytes
        concatenated_bytes = bytearray()
        byte_count = 0  

        for idx, matrix in enumerate(aes._key_matrices):
            for row in matrix:
                for byte in row:
                    concatenated_bytes.append(byte)  
                    byte_count += 1 
                    if byte_count == 16:  #LD I get here when I have a chunk of 16 appended
                        #print(f"LD number of current group: {idx}:")
                        #print("LD current group of 16 bytes:", end=' ')
                        formatted_bytes = turnMatrixLd(concatenated_bytes)  #LD going to turn the current 16 bytes using "turnMatrixLd"
                        for b in formatted_bytes:
                            concatenated_bytes_formatted.append(b)  #LD append byte by byte what is returned by "turnMatrixLd"
                            #print(hex(b), end=' ')  
                        #print()  #LD just adding a line for reading better this thing
                        #Ld need to reset both
                        byte_count = 0  
                        concatenated_bytes = bytearray()  

        # LD final test on flat
        # for byte in concatenated_bytes_formatted:
        #     print(hex(byte), end=' ')
 
        self.assertEqual(concatenated_bytes_formatted, expected_output)


    def test_expand_key_both(self):
            num_attempts = 0
            for _ in range(3):
                num_attempts += 1

                cipher_key = generate_random_plaintext(16)

                #LD C part
                cipher_key_buffer = ctypes.create_string_buffer(bytes(cipher_key), len(cipher_key))#LD Converting bytearray -> ctypes object
                expanded_key_ptr = rijndael.expand_key(ctypes.cast(cipher_key_buffer, ctypes.POINTER(ctypes.c_ubyte)))
                expanded_key_bytes = bytearray(ctypes.cast(expanded_key_ptr, ctypes.POINTER(ctypes.c_ubyte * 176)).contents)

                #LD Python part
                aes = AES(turnMatrixLd(cipher_key))

                concatenated_bytes_formatted = bytearray()  #LD I will store here the formatted bytes
                concatenated_bytes = bytearray()
                byte_count = 0  

                for idx, matrix in enumerate(aes._key_matrices):
                    for row in matrix:
                        for byte in row:
                            concatenated_bytes.append(byte)  
                            byte_count += 1 
                            if byte_count == 16:  #LD I get here when I have a chunk of 16 appended
                                #print(f"LD number of current group: {idx}:")
                                #print("LD current group of 16 bytes:", end=' ')
                                formatted_bytes = turnMatrixLd(concatenated_bytes)  #LD going to turn the current 16 bytes using "turnMatrixLd"
                                for b in formatted_bytes:
                                    concatenated_bytes_formatted.append(b)  #LD append byte by byte what is returned by "turnMatrixLd"
                                    #print(hex(b), end=' ')  
                                #print()  #LD just adding a line for reading better this thing
                                #Ld need to reset both
                                byte_count = 0  
                                concatenated_bytes = bytearray()  

                self.assertEqual(expanded_key_bytes, concatenated_bytes_formatted)


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

        self.assertEqual(column_array.raw[:-1], expected_rot_column_array)


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
      
        self.assertEqual(column_array.raw[:-1], expected_rot_column_array)
       

    def test_SubBytes(self):
        column = [0xcf,
                  0x4f,
                  0x3c,
                  0x09]
        column_array = ctypes.create_string_buffer(bytes(bytearray(column)))
        rijndael.SubBytes(column_array)
        expected_sub_column_array = bytearray([0x8a, 0x84, 0xeb, 0x01])
        
        self.assertEqual(column_array.raw[:-1], expected_sub_column_array)
        

    def test_SubBytes2(self):
        column = [0x6c, 0x76, 0x05, 0x2a]
        column_array = ctypes.create_string_buffer(bytes(bytearray(column)))
        rijndael.SubBytes(column_array)
        expected_sub_column_array = bytearray([0x50, 0x38, 0x6b, 0xe5])
       
        self.assertEqual(column_array.raw[:-1], expected_sub_column_array)
        

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
        
        self.assertEqual(column_array.raw[:-1], expected_rot_column_array)
        

    ############################################################################################################
    ### add_round_key ###
    ############################################################################################################

    #LD using same values in animation
    def test_add_round_key(self):
        inputToProcessText = bytearray([0x04, 0xe0, 0x48, 0x28,
                                        0x66, 0xcb, 0xf8, 0x06,
                                        0x81, 0x19, 0xd3, 0x26,
                                        0xe5, 0x9a, 0x7a, 0x4c])
        inputToProcessTextBuffer = ctypes.create_string_buffer(bytes(inputToProcessText))

        cipher_key = bytearray([0xa0, 0x88, 0x23, 0x2a,
                                0xfa, 0x54, 0xa3, 0x6c,
                                0xfe, 0x2c, 0x39, 0x76,
                                0x17, 0xb1, 0x39, 0x05])
        cipher_key_buffer = ctypes.create_string_buffer(bytes(cipher_key))#LD Converting bytearray -> ctypes object


        rijndael.add_round_key(inputToProcessTextBuffer, cipher_key_buffer)

        expected_output = bytearray([0xa4, 0x68, 0x6b, 0x02, 0x9c, 0x9f, 0x5b, 0x6a, 0x7f, 0x35, 0xea, 0x50, 0xf2, 0x2b, 0x43, 0x49])
        self.assertEqual(inputToProcessTextBuffer.raw[:-1], expected_output)
        

    def test_add_round_key_python(self):
        inputToProcessText = bytearray([0x04, 0xe0, 0x48, 0x28,
                                        0x66, 0xcb, 0xf8, 0x06,
                                        0x81, 0x19, 0xd3, 0x26,
                                        0xe5, 0x9a, 0x7a, 0x4c])

        cipher_key = bytearray([0xa0, 0x88, 0x23, 0x2a,
                                0xfa, 0x54, 0xa3, 0x6c,
                                0xfe, 0x2c, 0x39, 0x76,
                                0x17, 0xb1, 0x39, 0x05])

        # Assuming turnMatrixLd and turnMatrixLd_reverse are defined elsewhere
        input_status = bytes2matrix(turnMatrixLd(inputToProcessText))
        input_key =  bytes2matrix(turnMatrixLd(cipher_key))
        add_round_key(input_status, input_key)

        expected_output = bytearray([0xa4, 0x68, 0x6b, 0x02, 0x9c, 0x9f, 0x5b, 0x6a, 0x7f, 0x35, 0xea, 0x50, 0xf2, 0x2b, 0x43, 0x49])
        self.assertEqual(expected_output, turnMatrixLd_reverse(matrix2bytes(input_status)))


    def test_add_round_key_both(self):
            num_attempts = 0
            for _ in range(3):
                num_attempts += 1

                text = generate_random_plaintext(16)
                key = generate_random_plaintext(16)

                text_c = ctypes.create_string_buffer(bytes(text))
                key_c = ctypes.create_string_buffer(bytes(key))

                #LD C part
                rijndael.add_round_key(text_c, key_c)

                #LD python part
                text_p = bytes2matrix(turnMatrixLd(text))
                input_key =  bytes2matrix(turnMatrixLd(key))
                add_round_key(text_p, input_key)

                self.assertEqual(text_c.raw[:-1], turnMatrixLd_reverse(matrix2bytes(text_p)))
                #print(f"--- LOOP test_add_round_key_both n. {num_attempts} with hexadecimal: {[hex(byte) for byte in text_c.raw[:-1]]}")
                
    ############################################################################################################
    ### Full encription in C ###
    # CONTENT:
    # the two tests are doing exact same thing but with different values
    ############################################################################################################

    def test_aes_encrypt_block(self):
        plaintext = bytearray([0x32, 0x88, 0x31, 0xe0,
                               0x43, 0x5a, 0x31, 0x37,
                               0xf6, 0x30, 0x98, 0x07,
                               0xa8, 0x8d, 0xa2, 0x34])
        plaintext_buffer = ctypes.create_string_buffer(bytes(plaintext))

        key = bytearray([0x2b, 0x28, 0xab, 0x09,
                        0x7e, 0xae, 0xf7, 0xcf,
                        0x15, 0xd2, 0x15, 0x4f,
                        0x16, 0xa6, 0x88, 0x3c])
        key_buffer = ctypes.create_string_buffer(bytes(key))

        ld_encripted_block_ptr = rijndael.aes_encrypt_block(ctypes.cast(plaintext_buffer, ctypes.POINTER(ctypes.c_ubyte)),ctypes.cast(key_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        ld_encripted_block_bytes = bytearray(ctypes.cast(ld_encripted_block_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)

        expected_output = bytearray([0x39, 0x02, 0xdc, 0x19,
                                    0x25, 0xdc, 0x11, 0x6a,
                                    0x84, 0x09, 0x85, 0x0b,
                                    0x1d, 0xfb, 0x97, 0x32])

        self.assertEqual(ld_encripted_block_bytes, expected_output)
        #print("--- UT PASSED aes_encrypt_block")

    # test with other parms I got from internet https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf
    # I have flipped the values
    def test_aes_encrypt_block_Numner_two(self):
        plaintext = bytearray([0x54, 0x4f, 0x4e, 0x20,
                               0x77, 0x6E, 0x69, 0x54,
                               0x6f, 0x65, 0x6e, 0x77,
                               0x20, 0x20, 0x65, 0x6F])
        plaintext_buffer = ctypes.create_string_buffer(bytes(plaintext))

        key = bytearray([0x54, 0x73, 0x20, 0x67,
                        0x68, 0x20, 0x4b, 0x20,
                        0x61, 0x6d, 0x75, 0x46,
                        0x74, 0x79, 0x6e, 0x75])
        key_buffer = ctypes.create_string_buffer(bytes(key))

        ld_encripted_block_ptr = rijndael.aes_encrypt_block(ctypes.cast(plaintext_buffer, ctypes.POINTER(ctypes.c_ubyte)),ctypes.cast(key_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        ld_encripted_block_bytes = bytearray(ctypes.cast(ld_encripted_block_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)


        # sss = [hex(byte) for byte in ld_encripted_block_bytes]
        # print(sss)

        expected_output = bytearray([0x29, 0x57, 0x40, 0x1a,
                                     0xc3, 0x14, 0x22, 0x02,
                                     0x50, 0x20, 0x99, 0xD7,
                                     0x5f, 0xf6, 0xb3, 0x3A])

        self.assertEqual(ld_encripted_block_bytes, expected_output)
        #print("--- UT PASSED aes_encrypt_block")

    ############################################################################################################
    ### Full decription in C ###
    ############################################################################################################

    def test_aes_decrypt_block(self):
        ciphertext = bytearray([0x39, 0x02, 0xdc, 0x19,
                                0x25, 0xdc, 0x11, 0x6a,
                                0x84, 0x09, 0x85, 0x0b,
                                0x1d, 0xfb, 0x97, 0x32])
        ciphertext_buffer = ctypes.create_string_buffer(bytes(ciphertext))

        key = bytearray([0x2b, 0x28, 0xab, 0x09,
                        0x7e, 0xae, 0xf7, 0xcf,
                        0x15, 0xd2, 0x15, 0x4f,
                        0x16, 0xa6, 0x88, 0x3c,])
        key_buffer = ctypes.create_string_buffer(bytes(key))

        ld_dencripted_block_ptr = rijndael.aes_decrypt_block(ctypes.cast(ciphertext_buffer, ctypes.POINTER(ctypes.c_ubyte)),ctypes.cast(key_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        ld_dencripted_block_bytes = bytearray(ctypes.cast(ld_dencripted_block_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)

        expected_output = bytearray([0x32, 0x88, 0x31, 0xe0,
                                    0x43, 0x5a, 0x31, 0x37,
                                    0xf6, 0x30, 0x98, 0x07,
                                    0xa8, 0x8d, 0xa2, 0x34])

        self.assertEqual(ld_dencripted_block_bytes, expected_output)
        #print("--- UT PASSED test_aes_decrypt_block")


    ############################################################################################################
    ### Full encription->decription in python
    ############################################################################################################

    #LD test end to end with main values
    def test_python_encription_decription(self):

        integer_list = [1, 2,  3,  4,  5,  6,  7,  8, 9, 10, 11, 12, 13, 14, 15, 16]
        plaintext = bytearray(integer_list)

        integer_list2 = [50, 20, 46, 86, 67, 9, 70, 27, 75, 17, 51, 17, 4, 8, 6, 99]
        master_key = bytearray(integer_list2)

        aes = AES(turnMatrixLd(master_key))

        ciphertext = aes.encrypt_block(turnMatrixLd(plaintext)) #LD ogni 4 bytes e' una colonna(visualizzata) ruotata in senso antiorario di 90 gradi
        decrypted_plaintext = aes.decrypt_block(ciphertext)

        # print("---")
        # print("plaintext:")
        # print([hex(byte) for byte in plaintext])

        # print("ciphertext:")
        # print([hex(byte) for byte in turnMatrixLd_reverse(ciphertext)])

        # print("decrypted_plaintext:")
        # print([hex(byte) for byte in turnMatrixLd_reverse(decrypted_plaintext)])
        # print("---")
        # print("---")

        self.assertEqual(plaintext, turnMatrixLd_reverse(decrypted_plaintext))

    #LD test end to end correct inversion, calling python with same values in UT for C(I have above)
    def test_python_encription_decription_two(self):

        plaintext = bytearray([0x32, 0x88, 0x31, 0xe0,
                               0x43, 0x5a, 0x31, 0x37,
                               0xf6, 0x30, 0x98, 0x07,
                               0xa8, 0x8d, 0xa2, 0x34])

        master_key = bytearray([0x2b, 0x28, 0xab, 0x09,
                                0x7e, 0xae, 0xf7, 0xcf,
                                0x15, 0xd2, 0x15, 0x4f,
                                0x16, 0xa6, 0x88, 0x3c])

        aes = AES(turnMatrixLd(master_key))#LD ogni 4 bytes e' una colonna(visualizzata) ruotata in senso antiorario di 90 gradi

        ciphertext = aes.encrypt_block(turnMatrixLd(plaintext)) #LD ogni 4 bytes e' una colonna(visualizzata) ruotata in senso antiorario di 90 gradi

        decrypted_plaintext = aes.decrypt_block(ciphertext)

        # print("plaintext:")
        # print([hex(byte) for byte in plaintext])

        # print("ciphertext:")
        # print([hex(byte) for byte in turnMatrixLd_reverse(ciphertext)])

        # print("decrypted_plaintext:")
        # print([hex(byte) for byte in turnMatrixLd_reverse(decrypted_plaintext)])

        self.assertEqual(plaintext, turnMatrixLd_reverse(decrypted_plaintext))

    #***********************************************************************************************************
    ############################################################################################################
    ### FINAL MEGA TEST: 3 rounds of encription->decription in C&python with comparison test at each step
    ############################################################################################################
    #***********************************************************************************************************

    def test_full_encryption_decryption_both(self):
            num_attempts = 0
            for _ in range(3):
                num_attempts += 1

                plaintext = generate_random_plaintext(16)
                key_1 = generate_random_plaintext(16)

                # integer_list = [1, 2,  3,  4,  5,  6,  7,  8, 9, 10, 11, 12, 13, 14, 15, 16]
                # plaintext = bytearray(integer_list)

                # integer_list2 = [50, 20, 46, 86, 67, 9, 70, 27, 75, 17, 51, 17, 4, 8, 6, 99]
                # key_1 = bytearray(integer_list2) # byte interpretation of integers
    
                #print(f"--- LOOP ENCRIPTION n. {num_attempts} key:")
                #hex_list = [hex(byte) for byte in plaintext] #LD just convert each integer or ascii if reading bytearray to hexadecimal directly
                #print(hex_list)


                #LD ENCRIPTION C 
                plaintext_buffer = ctypes.create_string_buffer(bytes(plaintext))
                key_buffer = ctypes.create_string_buffer(bytes(key_1))
                ld_encripted_block_ptr = rijndael.aes_encrypt_block(ctypes.cast(plaintext_buffer, ctypes.POINTER(ctypes.c_ubyte)),ctypes.cast(key_buffer, ctypes.POINTER(ctypes.c_ubyte)))
                ciphertext_c = bytearray(ctypes.cast(ld_encripted_block_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)

                #LD ENCRIPTION Python 
                aes = AES(turnMatrixLd(key_1))
                ciphertext_p = aes.encrypt_block(turnMatrixLd(plaintext)) 

                #LD ENCRIPTION ciphertext match test
                self.assertEqual(ciphertext_c, turnMatrixLd_reverse(ciphertext_p))
                #print(f"--- LOOP ENCRIPTION test_full_encryption_decryption_both n. {num_attempts} matched: {[hex(byte) for byte in ciphertext_c]}")
                
                #LD DECRIPTION C
                ciphertext_buffer = ctypes.create_string_buffer(bytes(ciphertext_c))
                key_buffer_two = ctypes.create_string_buffer(bytes(key_1))
                ld_dencripted_block_ptr = rijndael.aes_decrypt_block(ctypes.cast(ciphertext_buffer, ctypes.POINTER(ctypes.c_ubyte)),ctypes.cast(key_buffer_two, ctypes.POINTER(ctypes.c_ubyte)))
                ld_dencripted_block_bytes = bytearray(ctypes.cast(ld_dencripted_block_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)

                #LD DECRIPTION Python
                decrypted_plaintext = aes.decrypt_block(ciphertext_p)

                #LD DECRIPTION match test
                self.assertEqual(ld_dencripted_block_bytes, turnMatrixLd_reverse(decrypted_plaintext))
                #print(f"--- LOOP DECRIPTION test_full_encryption_decryption_both n. {num_attempts} decripted:")
                hex_list_two = [hex(byte) for byte in ld_dencripted_block_bytes] #LD just convert each integer to hexadecimal directly
                #print(hex_list_two)
                # print(" - - - ")
                # print(" - - - ")

if __name__ == '__main__':
    unittest.main()