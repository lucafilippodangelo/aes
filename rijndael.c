/*
 * Luca Filippo D'Angelo - D23125106
 * 
 * This code performs AES, a symmetric encryption/decription, core steps for those explained below.
 * Encryption gets in input plaintext and encryption/decription key, steps below:
 * "expand_key": the method operates on 128-bit(for this CA) blocks of data and uses a key of 128-bit. The logic implemented expands the original key into a key schedule(11 chunks of 16bytes),
 * so several round keys are created using key expansion algorithm.
 * Initial Round: perform "add_round_key", it's a xor between input data and the first round key(first 16 bytes of the expanded key, matching input cipher key).
 * 9 Rounds: for each round perform a series of transformations ("sub_bytes", "shift_rows", "mix_columns", and "add_round_key") to the data using a different round key generated from "expand_key".
 * Final Round: perform a series of transformations ("sub_bytes", "shift_rows", and "add_round_key"). We skipping  "mix_columns"
 * Decription gets in input ciphertext and encryption/decription key, steps below:
 * "expand_key": same as described in encryption.
 * Initial Round: perform a series of transformations ("add_round_key", "invert_shift_row", "invert_sub_bytes"). 
 * So here the logic is performing the exact reverse of what happened in the final round of encryption and using "invert" methods to do that.
 * 9 Rounds: for each round perform a series of transformations ("add_round_key", "invert_mix_columns", "invert_shift_rows", "invert_sub_bytes")
 * to the data using a different round key generated from "expand_key". Note: logic perform inverse operations and as per initial round the logis
 * uses "inverse" methods.
 * Final Round: perform "add_round_key". Note: very last round for decription is very first round for encryption. 
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rijndael.h"


const unsigned char s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char inv_s_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};

const unsigned char r_con[40] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * Operations used when encrypting a block
 */

/**
 * Description:
 * This function covers the sub byte transformation step of the AES algorithm
 * Getting in input a pointer to a 4x4 matrix(in the case of this C implementation 
 * it is an array where rows are represented sequentially).
 * Iterate through each byte in a for loop. For each byte in block 
 * gets the value of the byte "i" and assign to “index”, 
 * then look for that value in s_box(substitution box), then just replace the 
 * original byte in the input “block” with the value from the s_box.
 * 
 * It’s a substitution to add confusion to the data, as I understand it should be 
 * harder to reverse engineer.
 * 
 * Inputs:
 * this function is getting a pointer to an "unsigned char"
 * 
 * Outputs:
 * there is no return, the function access and modify the memory location of 
 * "block"(memory pointed by the pointer passed as input parm) 
 */
void sub_bytes(unsigned char *block) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        unsigned char index = block[i]; 
        block[i] = s_box[index];//LD swap original byte with value from the s_box
    }
}

/**
 * Description:
 * this function gets in input a pointer to a 4x4 matrix(in the case of this C implementation 
 * it is an array where rows are represented sequentially)and does a circular shift of bytes.
 * The pattern is to unchange row one, row two does left shift of one byte,  row three does 
 * left shift of two bytes, , row four does left shift of three bytes.
 * In the code below I did simply use indexes of the input block to implement the assignments.
 * “ In this way, each column of the output state of the ShiftRows step is composed of bytes from each column of the input state. “ 
 * source: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 * 
 * The scope of this step is then to create “diffusion”, spreading each byte in input to the 
 * entire block in output.

 * Inputs:
 * this function is getting a pointer to an "unsigned char"
 * 
 * Outputs:
 * there is no return, the function access and modify the memory location of 
 * "block"(memory pointed by the pointer passed as input parm) 
 */
void shift_rows(unsigned char *block) {
    
    unsigned char temp;
    //LD there is a fancy implementation here https://github.com/m3y54m/aes-in-c#aes-operations-subbytes-shiftrow-mixcolumn-and-addroundkey

    //LD Row 2: Circular shift to the left by 1 byte
    temp = block[4];
    block[4] = block[5];
    block[5] = block[6];
    block[6] = block[7];
    block[7] = temp;

    //LD Row 3: Circular shift to the left by 2 bytes
    temp = block[8];
    block[8] = block[10];
    block[10] = temp;
    temp = block[9];
    block[9] = block[11];
    block[11] = temp;

    //LD Row 4: Circular shift to the left by 3 bytes
    temp = block[12];
    block[12] = block[15];
    block[15] = block[14];
    block[14] = block[13];
    block[13] = temp;
}

//LD "mix columns" general description
/**
 * Description:
 * for the "mix columns" part I have used the resources:
 * - https://github.com/m3y54m/aes-in-c/tree/main/src
 * - https://en.wikipedia.org/wiki/Rijndael_MixColumns
 * 
 * the mix of the columns is one of the steps of encryption(entry point mix_columns)/decription(entry point invert_mix_columns). 
 * What this step basically does is to multiply each column of the input block(getting in input a pointer to an unsigned char) 
 * with a fixed matrix(Gailos field). 
 * The goal of this step is diffusion. There is a great explanation here https://en.wikipedia.org/wiki/Confusion_and_diffusion, 
 * I guess the most important part to get is the fact that diffusion hide the statistical relationship between the ciphertext and the plain text.
 * From Wikipedia: “Diffusion means that if we change a single bit of the plaintext, then about half of the bits in the ciphertext should change, 
 * and similarly, if we change one bit of the ciphertext, then about half of the plaintext bits should change.[5] This is equivalent to the 
 * expectation that encryption schemes exhibit an avalanche effect.
 * The purpose of diffusion is to hide the statistical relationship between the ciphertext and the plain text. For example, diffusion ensures 
 * that any patterns in the plaintext, such as redundant bits, are not apparent in the ciphertext.[3] Block ciphers achieve this by "diffusing" 
 * the information about the plaintext's structure across the rows and columns of the cipher. ”
 */

void mixColumn(unsigned char *column);
void invMixColumn(unsigned char *column);
unsigned char galois_multiplication(unsigned char a, unsigned char b);

/**
 * Description:
 * multiplication of 2 bytes(in input) in the Gailos field. It's a bit by bit operation
 * 
 */
unsigned char galois_multiplication(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    unsigned char counter;
    unsigned char hi_bit_set;
    for (counter = 0; counter < 8; counter++)
    {
        if ((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/**
 * Description:
 * the function is taking in input a pointer to an unsigned char(as for any methods in this CA it’s a 16 byte buffer) 
 * representing a matrix and applying “mixColumn(column);” to it. 
 * Looking at the implementation, this piece of logic iterates over each column of the state matrix, constructs a column, 
 * applies mixColumn(column);” function to it, and the updates the state matrix with the result.
 * 
 */
void mix_columns(unsigned char *state)
{
    int i, j;
    unsigned char column[4];

    // iterate over the 4 columns
    for (i = 0; i < 4; i++)
    {
        // construct one column by iterating over the 4 rows
        for (j = 0; j < 4; j++)
        {
            column[j] = state[(j * 4) + i];
        }

        // apply the mixColumn on one column
        mixColumn(column);

        // put the values back into the state
        for (j = 0; j < 4; j++)
        {
            state[(j * 4) + i] = column[j];
        }
    }
}

/**
 * Description:
 * this function is called from "mix_columns", goal of this logic is to operate on the column in input(passing a pointer to an unsigned char).
 * so to the column is applied a series of Galois multiplications and XOR operations 
 * to each element in the column, then updates the column with the result.
 * 
 */
void mixColumn(unsigned char *column)
{
    unsigned char cpy[4];
    int i;
    for (i = 0; i < 4; i++)
    {
        cpy[i] = column[i];
    }
    column[0] = galois_multiplication(cpy[0], 2) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 3);

    column[1] = galois_multiplication(cpy[1], 2) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 3);

    column[2] = galois_multiplication(cpy[2], 2) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 3);

    column[3] = galois_multiplication(cpy[3], 2) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 3);
}


/*
 * Operations used when decrypting a block
 */

/**
 * Description:
 * what is happening here is the inverse transformation of "sub_bytes" by using a different substitution table -> "inv_s_box".
 * This method is used in the decryption method.
 * Eoin please refer to "sub_bytes" function description for more details :) , just avoiding to copy pasting same content.
 *
 */
void invert_sub_bytes(unsigned char *block)
{
    for (int i = 0; i < BLOCK_SIZE; i++) {
        unsigned char index = block[i]; 
        block[i] = inv_s_box[index];
    }
}

/**
 * Description:
 * this function perform the inverse transformation of "shift_rows". rotation this time is to the right. Same rows interested(n.2,n.3,n.4).
 * In terms of code and logic it is pretty basic and static, used same approach as described in "shift_rows".
 * 
 * Eoin, I know that this code is not prone for extension but for this CA I did focus on making things working
 * without thinking to handle in a second time matrix 6x6 etc..
 */
void invert_shift_rows(unsigned char *block) {
      unsigned char temp;

    //LD Row 2: Shift to the right 1 byte (undoing what was done in shift_rows)
    temp = block[7];
    block[7] = block[6];
    block[6] = block[5];
    block[5] = block[4];
    block[4] = temp;

    //LD Row 3: Shift to the right 2 byte 
    temp = block[8];
    block[8] = block[10];
    block[10] = temp;
    temp = block[9];
    block[9] = block[11];
    block[11] = temp;

    //LD Row 4: Shift to the right 3 byte 
    temp = block[13];
    block[13] = block[14];
    block[14] = block[15];
    block[15] = block[12];
    block[12] = temp;
}

/**
 * Description:
 * similarly to any methods in this "decriptiong" methods section, "invert_mix_columns" perform exactly the opposite of
 * "mix_columns". It's the inverse process.
 * Iterative processes are pretty similar if not identical to what described in summary of function "mix_columns"
 */
void invert_mix_columns(unsigned char *block) {

    int i, j;
    unsigned char column[4];

    // iterate over the 4 columns
    for (i = 0; i < 4; i++)
    {
        // construct one column by iterating over the 4 rows
        for (j = 0; j < 4; j++)
        {
            column[j] = block[(j * 4) + i];
        }

        // apply the invMixColumn on one column
        invMixColumn(column);

        // put the values back into the state
        for (j = 0; j < 4; j++)
        {
            block[(j * 4) + i] = column[j];
        }
    }
}

/**
 * Description:
 * this function is called from "invert_mix_columns", goal of this logic is to operate on the column in input(passing a pointer to an unsigned char).
 * so to the column is applied a series of Galois multiplications and XOR operations 
 * to each element in the column, then updates the column with the result.
 * 
 */
void invMixColumn(unsigned char *column)
{
    unsigned char cpy[4];
    int i;
    for (i = 0; i < 4; i++)
    {
        cpy[i] = column[i];
    }
    column[0] = galois_multiplication(cpy[0], 14) ^
                galois_multiplication(cpy[3], 9) ^
                galois_multiplication(cpy[2], 13) ^
                galois_multiplication(cpy[1], 11);
    column[1] = galois_multiplication(cpy[1], 14) ^
                galois_multiplication(cpy[0], 9) ^
                galois_multiplication(cpy[3], 13) ^
                galois_multiplication(cpy[2], 11);
    column[2] = galois_multiplication(cpy[2], 14) ^
                galois_multiplication(cpy[1], 9) ^
                galois_multiplication(cpy[0], 13) ^
                galois_multiplication(cpy[3], 11);
    column[3] = galois_multiplication(cpy[3], 14) ^
                galois_multiplication(cpy[2], 9) ^
                galois_multiplication(cpy[1], 13) ^
                galois_multiplication(cpy[0], 11);
}


/*
 * This operation is shared between encryption and decryption
 */
/**
 * Description:
 * the logic does an itaration byte by byte of the block and apply a xor with the corresponding byte from round_key.
 * This is why it is called "add round key" step.
 * At high level, the logic is considering a 4x4 matrix and doing a column by column xor, first of the block with first of the round key,
 * second of the block with second of the round key... etc..
 * 
 * External resource https://crypto.stackexchange.com/questions/22360/what-is-the-importance-of-adding-round-key-in-aes
 * explain the idea of keyed permutation, so the block cipher depends on the round key.
 * This method "add_round_key" is called at every round of encryption/decryption, adding security etc..

 * Inputs:
 * this function is getting a pointer to an "unsigned char", the 16 bytes matrix the logic is boing to transform
 * and a round_key
 * 
 * Outputs:
 * there is no return, the function access and modify the memory location of 
 * "block"(memory pointed by the pointer passed as input parm) 
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
    
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] ^= round_key[i];
    }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */

/**
 * Description:
 * this method is called in the body of "expand_key".
 * The input "block"(unsigned char of 4 bytes) will store the result of the rotation, where the rotation consists in move from first to last position 
 * + rotate all the other bytes of the LAST column of one of the matrix contained in the "expanded_key[]". 
 * As an example if the last column of the considered matrix is [1,2,3,4] output will be [2,3,4,1].
 * As well, as an example of the direct assignments to "block", "block[0]" will get the value of 
 * the "expanded_key" at index 7 + the number of bytes to consider to extract the right matrix("expanded_key_number"(one of the 11) multiplied the block size(16 bytes)). 
 * Do this math is necessary because expanded key is 176 bytes long and for each 
 * execution of "rot_word" is necessary to consider the right chunk of 16bytes, and for each chunk, indexes 3,7,11,15(representing last column of the matrix in a flat array representation).
 * 
 * 
 * Inputs:
 * this function is getting a pointer to a "block", an "unsigned char" 4 byes long, the "expanded_key" (176 bytes long), and the
 * "expanded_key_number". For the last parm values go from 0 to 9, so considering from the 1th matrix to 10th to do rotation and in father method to build subsequent keys.
 * 
 * Outputs:
 * there is no return, the function access and modify the memory location of 
 * "block"(memory pointed by the pointer passed as input parm) 
 */
void rot_word(unsigned char *block, const unsigned char expanded_key[], int expanded_key_number)
{
    block[0] = expanded_key[7 + (expanded_key_number * BLOCK_SIZE)];
    block[1] = expanded_key[11 + (expanded_key_number * BLOCK_SIZE)];
    block[2] = expanded_key[15 + (expanded_key_number * BLOCK_SIZE)];
    block[3] = expanded_key[3 + (expanded_key_number * BLOCK_SIZE)];
}

/**
 * Description:
 * this helper method get's in input the column number to extract from "r_con", an unsigned char of 40 bytes
 */
void ldExtractColumnFromRcon(int columnNumber, unsigned char *ret_column) 
{
    for (int i = 0; i < 4; i++) {
        ret_column[i] = r_con[(columnNumber) + i * 10];
    }
}

/**
 * Description:
 * this helper is called in the body of "expand_key", it extracts and save in "ret_column" the x "columnNumber" from "expanded_key". 
 * The column number is calculated considering the input "Key_number" and the block size
 */
void ldExtractColumnFromKey(int columnNumber, unsigned char *expanded_key, int key_number, unsigned char *ret_column)
{
    for (int i = 0; i < 4; i++)
    {
        ret_column[i] = expanded_key[(columnNumber - 1) + i * 4 + (key_number * BLOCK_SIZE)];
    }
}


/**
 * Description:
 * this helper method is performing a column by column XOR for the three columns in input represented by three unsigned char 4 bytes long.
 */
void XOR(unsigned char *result, unsigned char *a, unsigned char *b, unsigned char *c) {
    for (int i = 0; i < 4; i++) {
        result[i] = a[i] ^ b[i] ^ c[i];
    }
}

//LD XOR in isulation (between 2 inputs)
void XOR_2(unsigned char *result, unsigned char *a, unsigned char *b) {
    for (int i = 0; i < 4; i++) {
        result[i] = a[i] ^ b[i];
    }
}

//LD for now making working the generation of the first KEY SCHEDULE
//------
//- calculation column 1
//create a temp temp_calc_1 of size 4 char and save there the Rotword of column 4(index 3,7,11,15) of the 
//CHEAPERKEY, do subbytes and update same temp_calc_1.
//------
//get column 1(index 0,4,8,12) of the CHEAPERKEY and save in temp_calc_2
//get column ONE of Rcon(index 0,11,21,31) and save in temp_calc_3
//XOR of temp_calc_1-temp_calc_2-temp_calc_3 and save in temp_calc_4
//col 1 of FIRST KEY will be temp_calc_4
//------
//-  calculation column 2
//col 2 is the xor of col2 of current input with col 1 just calculated
//-  calculation column 3
//col 3 is the xor of col3 of current input with col 2 just calculated
//-  calculation column 4
//col 4 is the xor of col4 of current input with col 3 just calculated
//------
//LD added logic to generate the whole array to return
unsigned char *expand_key(unsigned char *cipher_key)
{
    //LD calloc allocate memory and initialise to zero by default. No need to use malloc and then initialise to zero 
    //in a second step.
    unsigned char *expanded_key = (unsigned char *)calloc(BLOCK_SIZE * 11, sizeof(unsigned char));
    
    //LD cipher_key first key of expanded_key
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        expanded_key[i] = cipher_key[i];
    }

    //LD moved declaration outside for to avoid repeated declaration
    unsigned char temp_calc_1[4];
    unsigned char temp_calc_2[4];
    unsigned char temp_calc_3[4];
    unsigned char temp_calc_4[4];
    unsigned char temp_col2[4];
    unsigned char temp_col3[4];
    unsigned char temp_col4[4];
    unsigned char temp_columnExtractedFromKey[4];

    for (int i = 0; i < 10; i++)
    {
        // LD ROTWORD
        printf("ROT WORD: %d\n", i);
       
        rot_word(temp_calc_1, expanded_key, i);

        sub_bytes(temp_calc_1);

        // LD extract the first column form the key
        ldExtractColumnFromKey(1, expanded_key, i, temp_calc_2);

        // LD extracting the X number column. 
        ldExtractColumnFromRcon(i, temp_calc_3);

        XOR(temp_calc_4, temp_calc_1, temp_calc_2, temp_calc_3);
        
		// LD MAKING OF COL 2. COL 2 is the XOR of col2 of key in input with col 1 just calculated
        ldExtractColumnFromKey(2, expanded_key, i, temp_columnExtractedFromKey);

        XOR_2(temp_col2, temp_columnExtractedFromKey, temp_calc_4);
        
		// LD MAKING OF COL 3. COL 3 is the XOR of col3 of key in input with col 2 just calculated
        ldExtractColumnFromKey(3, expanded_key, i, temp_columnExtractedFromKey);
        XOR_2(temp_col3, temp_columnExtractedFromKey, temp_col2);
        
		// LD MAKING OF COL 4. COL 4 is the XOR of col4 of key in input with col 3 just calculated
        ldExtractColumnFromKey(4, expanded_key, i, temp_columnExtractedFromKey);
        XOR_2(temp_col4, temp_columnExtractedFromKey, temp_col3);
			

        //LD some optinization.. same logic above where "z" is the base index. Moving everything under same FOR
        for (int j = 0; j < 4; j++) {
            int z = ((i + 1) * BLOCK_SIZE) + (j * 4);
            expanded_key[z] = temp_calc_4[j];
            expanded_key[z + 1] = temp_col2[j];
            expanded_key[z + 2] = temp_col3[j];
            expanded_key[z + 3] = temp_col4[j];
        }
    }

    //printf("Expanded Keys:\n");
    //print_hex_array(expanded_key, 176);
    return expanded_key;
}


/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {

    //LD doing a copy of plaintext otherwise due to the current structure of main, I will end up  
    //printing ciphertext values instead of plaintext
    unsigned char *temp_plaintext = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
    if (temp_plaintext == NULL) {
        fprintf(stderr, "LD temp_plaintext memory allocation issues\n");
        return NULL;
    }
    memcpy(temp_plaintext, plaintext, BLOCK_SIZE);

    // printf("--- \n");
    // printf("--- LD PLAINTEXT aes_encrypt_block:\n");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", temp_plaintext[i]); 
    //     if ((i + 1) % 4 == 0)
    //         printf("\n");
    // }

    unsigned char *round_keys = expand_key(key);
    if (round_keys == NULL) {
        fprintf(stderr, "LD round_keys memory allocation issues\n");
        return NULL;
    }

    add_round_key(temp_plaintext, round_keys);

    for (int round = 1; round < 10; ++round) {
        sub_bytes(temp_plaintext);
        shift_rows(temp_plaintext);
        mix_columns(temp_plaintext);
        add_round_key(temp_plaintext, round_keys + round * BLOCK_SIZE); //LD advancing the pointer by blocksize
    }

    sub_bytes(temp_plaintext);
    shift_rows(temp_plaintext);
    add_round_key(temp_plaintext, round_keys + 10 * BLOCK_SIZE);

    free(round_keys); //LD release allocated memory

    // printf("--- \n");
    // printf("--- LD ENCRIPTED aes_encrypt_block:\n");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", temp_plaintext[i]); 
    //     if ((i + 1) % 4 == 0)
    //         printf("\n");
    // }
    
    //printf("LD EXECUTED aes_encrypt_block \n");
    return temp_plaintext;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key) {

    //LD allocating a slot of memory for the ciphertext generation. The pointer to ciphertext in
    //input to this function. Since ciphertext is modified during decryption in main, 
    //once the eoin's code in printing ciphertext after decryption, the sequence will print the decrypted plaintext, not the ciphertext.
    // so to output the expected behaviour without touching main I needed to do a copy before decription.
    unsigned char *temp_ciphertext = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
    if (temp_ciphertext == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    memcpy(temp_ciphertext, ciphertext, BLOCK_SIZE);

    // printf("--- \n");
    // printf("--- LD CIPHERTEXT aes_decrypt_block:\n");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", temp_ciphertext[i]); 
    //     if ((i + 1) % 4 == 0)
    //         printf("\n");
    // }

    //LD it's exactly all the way around!

    unsigned char *round_keys = expand_key(key);
        if (round_keys == NULL) {
        //LD free memory
        free(temp_ciphertext);
        return NULL;
    }

    add_round_key(temp_ciphertext, round_keys + 10 * BLOCK_SIZE);
    invert_shift_rows(temp_ciphertext);
    invert_sub_bytes(temp_ciphertext);

    for (int round = 9; round > 0; --round) {
        add_round_key(temp_ciphertext, round_keys + round * BLOCK_SIZE);
        invert_mix_columns(temp_ciphertext);
        invert_shift_rows(temp_ciphertext);
        invert_sub_bytes(temp_ciphertext);
    }

    add_round_key(temp_ciphertext, round_keys);

    free(round_keys);

    // printf("--- \n");
    // printf("--- LD DECRIPTED aes_decrypt_block:\n");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", ciphertext_cpy[i]); 
    //     if ((i + 1) % 4 == 0)
    //         printf("\n");
    // }

    // printf("--- \n");
    // printf("--- LD EXECUTED aes_decrypt_block \n");
    // printf("--- \n");
    
    return temp_ciphertext;
}