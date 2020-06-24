/*
Copyright 2020 Bruno Novo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

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