/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// TODO: Any other files you need to include should go here
#include "rijndael.h"

#define xtime(a) ((((a) << 1) ^ (((a) & 0x80) ? 0x1B : 0x00)) & 0xFF)

// LD will be used across this CA
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

//LD using exact same round constants in "aes.py"
const unsigned char r_con[40] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block) {
    //strcpy(block, "Hello, world");

    // printf("--- \n");
    // printf("--- LD sub_bytes hexadecimal of the input:\n");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", block[i]); 
    //     if ((i + 1) % 4 == 0)//LD I print 4 per line instead of 16 https://stackoverflow.com/questions/49242874/how-to-print-contents-of-buffer-in-c
    //         printf("\n");
    // }

        for (int i = 0; i < 16; i++) {
        unsigned char index = block[i]; //LD getting index of s_box for byte "i" I'm looping on
        block[i] = s_box[index];//LD swap original byte with value from the s_box
    }

    // printf("--- \n");
    // printf("--- LD sub_bytes hexadecimal of returned from sub_bytes:\n");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", block[i]);
    //     if ((i + 1) % 4 == 0)
    //         printf("\n");
    // }
}

void shift_rows(unsigned char *block) {
    
    // printf("--- \n");
    // printf("--- LD shift_rows hexadecimal of the input:\n");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", block[i]); 
    //     if ((i + 1) % 4 == 0)//LD I print 4 per line instead of 16 https://stackoverflow.com/questions/49242874/how-to-print-contents-of-buffer-in-c
    //         printf("\n");
    // }

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

    // printf("--- \n");
    // printf("--- LD shift_rows hexadecimal of return:\n");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", block[i]);
    //     if ((i + 1) % 4 == 0)
    //         printf("\n");
    // }
}

//LD trying to use exact same approach of aes.py
void mix_single_column(unsigned char *a) {
    unsigned char t = a[0] ^ a[1] ^ a[2] ^ a[3];
    unsigned char u = a[0];

    a[0] ^= t ^ xtime(a[0] ^ a[1]);
    a[1] ^= t ^ xtime(a[1] ^ a[2]);
    a[2] ^= t ^ xtime(a[2] ^ a[3]);
    a[3] ^= t ^ xtime(a[3] ^ u);
}

void mix_columns(unsigned char *block) {
  //LD resource: https://github.com/m3y54m/aes-in-c#aes-operations-subbytes-shiftrow-mixcolumn-and-addroundkey
  //LD resource: https://cnj.atu.edu.iq/wp-content/uploads/2019/10/8.pdf

    printf("--- \n");
    printf("--- LD mix_columns hexadecimal of the input:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", block[i]); 
        if ((i + 1) % 4 == 0)//LD I print 4 per line instead of 16 https://stackoverflow.com/questions/49242874/how-to-print-contents-of-buffer-in-c
            printf("\n");
    }

      for (int i = 0; i < 4; i++) {
        mix_single_column(block + 4 * i);
    }

    printf("--- \n");
    printf("--- LD mix_columns OUTPUT hexadecimal\n");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", block[i]); 
        if ((i + 1) % 4 == 0)//LD I print 4 per line instead of 16 https://stackoverflow.com/questions/49242874/how-to-print-contents-of-buffer-in-c
            printf("\n");
    }

}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
  // TODO: Implement me!
}

void invert_shift_rows(unsigned char *block) {
  // TODO: Implement me!
}

void invert_mix_columns(unsigned char *block) {
  // TODO: Implement me!
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  // TODO: Implement me!
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
/*
* LD I will take a different approach than in "aes.py". What probably done there is a "RotWord" left shift.
* instead I want to implement it exactly as explained in lecture by Eoin. End result of UT I will implement must be same
*/

#include <stdio.h>
#include <stdlib.h>

//LD perform RotWord on cipherKey and update word
void RotWord(unsigned char *word, const unsigned char cipherKey[]) {
    word[2] = cipherKey[15];
    word[3] = cipherKey[3];
    word[0] = cipherKey[7];
    word[1] = cipherKey[11];
}

//LD subbites on the column in isulation
void SubBytes(unsigned char *word) {
            for (int i = 0; i < 4; i += 1) {
                printf("here-> ");
                printf("%02x ", word[i]);

                unsigned char index = word[i]; //LD getting index of s_box for byte "i" I'm looping on
                word[i] = s_box[index];//LD swap original byte with value from the s_box
            }
}

//LD get's in input the column to extract
void ldExtractColumnFromRcon(int columnNumber, unsigned char *word) {
    for (int i = 0; i < 4; i++) {
        word[i] = r_con[(columnNumber - 1) + i * 10];
    }
}

void ldExtractColumnFromKey(int columnNumber, unsigned char *key, unsigned char *word) {
    for (int i = 0; i < 4; i++) {
        word[i] = key[(columnNumber - 1) + i * 4];
    }
}

//LD XOR in isulation (between 3 inputs)
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

unsigned char *generateFirstKey(unsigned char *cipher_key) {   

    unsigned char *expanded_key = malloc(176 * sizeof(unsigned char));

    unsigned char temp_calc_1[4]; //LD will contain Rotword of column 4 of cipher_key (index 3,7,11,15), then the subbytes
    unsigned char temp_calc_2[4];
    unsigned char temp_calc_3[4];
    unsigned char temp_calc_4[4];
    
    //LD ROTWORD
    RotWord(temp_calc_1, cipher_key); //LD expected result 3c 09 cf af
    printf("After rotation and stored in temp_calc_1:\n");
    for (int i = 0; i < 4; i++) {
        printf("%02x ", temp_calc_1[i]);
    }
    printf("\n");

    //LD SUBBYTES
    SubBytes(temp_calc_1); //LD expected result 8a 84 eb 01
    printf("After subbytes in temp_calc_1:\n");
    for (int i = 0; i < 4; i++) {
        printf("%02x ", temp_calc_1[i]);
    }
    printf("\n");

    //LD extract the first column form the key
    ldExtractColumnFromKey(1, cipher_key, temp_calc_2); 
    printf("Column 1 of the cipher key: ");
    for (int i = 0; i < 4; i++) {
        printf("%02x ", temp_calc_2[i]);
    }
    printf("\n");

    //LD extracting the X number column. Can be reused. At the moment extracting column number one
    ldExtractColumnFromRcon(1, temp_calc_3); 
    printf("Column %d of the r_con array: ", 1);
    for (int i = 0; i < 4; i++) {
        printf("%02x ", temp_calc_3[i]);
    }
    printf("\n");

    XOR(temp_calc_4, temp_calc_1, temp_calc_2, temp_calc_3);//LD expected a0 fa fe 17 

        printf("Result of XOR FOR COLUMN ONE: ");
        for (int i = 0; i < 4; i++) {
            printf("%02x ", temp_calc_4[i]);
        }
        printf("\n");

    //LD MAKING OF COL 2. COL 2 is the XOR of col2 of key in input with col 1 just calculated
    unsigned char temp_columnExtractedFromKey[4];
    ldExtractColumnFromKey(2, cipher_key, temp_columnExtractedFromKey); //LD extract column one
    unsigned char temp_col2[4];
    XOR_2(temp_col2, temp_columnExtractedFromKey, temp_calc_4);
    printf("Result of XOR FOR COLUMN TWO: ");
    for (int i = 0; i < 4; i++) { printf("%02x ", temp_col2[i]); } printf("\n"); //LD expected 88 54 2c b1 

    //LD MAKING OF COL 3. COL 3 is the XOR of col3 of key in input with col 2 just calculated
    ldExtractColumnFromKey(3, cipher_key, temp_columnExtractedFromKey); //LD extract column one
    unsigned char temp_col3[4];
    XOR_2(temp_col3, temp_columnExtractedFromKey, temp_col2);
    printf("Result of XOR FOR COLUMN THREE: ");
    for (int i = 0; i < 4; i++) { printf("%02x ", temp_col3[i]); } printf("\n"); //LD expected


    //LD MAKING OF COL 4. COL 4 is the XOR of col4 of key in input with col 3 just calculated
    ldExtractColumnFromKey(4, cipher_key, temp_columnExtractedFromKey); //LD extract column one
    unsigned char temp_col4[4];
    XOR_2(temp_col4, temp_columnExtractedFromKey, temp_col3);
    printf("Result of XOR FOR COLUMN FOUR: ");
    for (int i = 0; i < 4; i++) { printf("%02x ", temp_col4[i]); } printf("\n"); //LD expected


    return expanded_key;
}




//Eoin complete one
// unsigned char *expand_key(unsigned char *cipher_key) {   
//     return expanded_key;
// }

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  // TODO: Implement me!

	// int x = 2;
	// int* y = &x;
  // int c = addNumbers();

  // printf("%d\n", c);

  //LD call sub_bytes
  sub_bytes(plaintext);

  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);

  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  return output;
}
