#ifndef _HMAC_
#define _HMAC_

#include <data.h>
#include <MD5Builder.h>
#include <sha256.h>
#include <Arduino.h>

#define MD5 0
#define SHA_256 1
#define blocksize 64
#define Length_MD5 16
#define Length_SHA256 32 
#define OutterPad 0x5C
#define InnerPad 0x36


class HMAC{

    public:
        void hmac(int HashFunction , byte* data ,size_t data_size, byte* key, size_t key_size, byte* result );
        void printHash(byte*  result, int algorithm);
    private:
        byte* MD5_HMAC( byte* data ,size_t data_size, byte* key, size_t key_size);
        byte* SHA256_HMAC( byte* data ,size_t data_size, byte* key, size_t key_size );

};
#endif