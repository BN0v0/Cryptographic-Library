/*
Copyright 2020 Bruno Novo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#ifndef AES_H
#define AES_H

// Needed included files
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <data.h>
#include <avr/pgmspace.h>
#include <cstdlib>


//defining 
#define row_numbers 4
#define column_numbers 4
#define block_numbers (row_numbers * column_numbers)
#define number_max_rounds 14
#define key_schedule_bytes ((number_max_rounds +1) * block_numbers)
#define WPOLY 0x011B
#define DPOLY 0x008D

#define ECB 0
#define CBC 1

//Galloir Field Operations -> times 2 -> GF(2*8)
#define f2(x)  ((x) & 0x80 ? (x << 1) ^ WPOLY : x << 1)
#define d2(x)  (((x) >> 1) ^ ((x) & 1 ? DPOLY : 0))

class AES
{
public:
        /* Initializing the AES algorithm 
         * @param mode is the pretended encryption mode - ECB or CBC
         * @param user_key is the user key to use in the encryption and decryption
         * @param IV is only used in the CBC encryption mode -> In ECB use nullptr
        */
        void Initialize(int mode, byte* user_key, byte* IV);

        /* Encryption AES
        * @param output of the encryption operation
        * @param input, input byte array wich is pretended to be encrypted
        * @return is ERROR (-1) if is something wrong, SUCCESS (0) if the encryption is successfull or FAIL (1) if it Fails 
        */
        int Encryption(byte* output, byte* input);

        /* Encryption AES
        * @param output of the decryption operation
        * @param input, input byte array wich is pretended to be encrypted
        * @return is ERROR (-1) if is something wrong, SUCCESS (0) if the encryption is successfull or FAIL (1) if it Fails 
        */
        int Decryption(byte* output, byte* input);
       
private:

    //Initialize Variables
    int Mode;
    byte round ;
    byte key_sched [key_schedule_bytes] ;
    byte iv_cbc_enc[16];
    byte iv_cbc_dec[16];
    int pad;
    int size;
    byte arr_pad[15] ={0x82,0x84,0x88,0x9f,0x92,0x94,0x98,0x9f,0xa2,0xa4,0xa8,0xaf,0xb2,0xb4,0xb8} ;
    byte* Key;
    byte iv_ecb_enc[16];//16bytes
    byte iv_ecb_dec[16];//16bytes
    byte* IVE;
    byte* IVD;


    //Key & IV Operations 
    byte set_key(byte key[], size_t key_size);
    void set_IV(byte* iv);
    void increment_IV();
    void get_IV(byte* out);
    void clean();

    //operations 
    void copy_n_bytes(byte* AESt, byte* src, byte n);
    int get_size();
    void set_size(int size);
    int get_pad_len(int p_size);
    void calc_PlainAndPathSize(int size);
    void padPlaintext(void* in,byte* out);

    // Encryptions
    bool encrypt(byte plain[block_numbers], byte cipher[block_numbers]);
    bool decrypt(byte plain[block_numbers], byte cipher[block_numbers]);
 
    bool Encryption(byte *plain,int size_p,byte *cipher,byte *key, int bits, byte* iv);
    bool Decryption(byte *cipher,int size_c,byte *plain,byte *key, int bits, byte* iv);
};





#endif