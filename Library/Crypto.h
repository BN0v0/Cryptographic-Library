#include <stdio.h>
#include <Crypto_Help.cpp>


class Crypto
{

public:
    //ECB
    bool Initialize(int EncryptionAlg);
    //CBC
    bool Initialize(int EncryptionAlg, byte* IV);

    bool KeySchedule(byte *key);
    int Encryption(byte *in, byte *out);
    int Decryption(byte *in, byte *out);

    void PrintArray_byte(uint8_t array[], int LENGTH);

private:
    int EncAlg;
};