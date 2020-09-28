#ifndef Des_h
#define Des_h

#include <avr/pgmspace.h>
#include <stdint.h>
#include <string.h>
#include <Print.h>
#include <Crypto_Help.cpp>

#define rottable 0x7EFC
#define rottable_inv 0x3F7E

#define block_size 8

#define R (data.v32[1])
#define L (data.v32[0])

#define des 0
#define t_des 1

#define ECB 0
#define CBC 1

struct Key
{
    byte one[8];
    byte two[8];
    byte three[8];
};

class DES_Alg
{

public:
    void Initialize(int algorithm, int mode, byte *IV);
    bool KeySchedule(byte* user_key);
    int Encryption( byte *input,byte *output);
    int Decryption( byte *input,byte *output );

private:
    /* Variables Initialization */
    Key key;  /**< holds the key for the encryption */
    int pad;  /**< holds the size of the padding. */
    int size; /**< hold the size of the plaintext to be ciphered */
    byte arr_pad[7] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    int Algorithm;
    int Mode;
    byte iv_cbc_enc[8];
    byte iv_cbc_dec[8];
    byte *IVE;
    byte*IVE2;
    byte *IVD;
    byte* IVD2;

    //DES & 3DES Operations
    inline void shiftkey(uint8_t *key);
    inline void shiftkey_inv(uint8_t *key);
    void setKey(byte *m_key);
    inline uint64_t splitin6bitwords(uint64_t a);
    void permute(const uint8_t *ptable, const uint8_t *in, uint8_t *out);
    void changeendian32(uint32_t *a);
    inline byte substitute(uint8_t a, uint8_t *sbp);
    uint32_t des_f(uint32_t r, uint8_t *kr);

    /* Encryption Operations  */
    void encrypt(void *output, const void *input, byte *key);
    void decrypt(void *output, const void *input, byte *key);
    void tripleEncrypt(byte *output, byte *input, Key key);
    void tripleDecrypt(byte *output, byte *input, Key key);

    void tripleXORedEncrypt(byte *output, byte *input, Key key);
    void tripleXORedDecrypt(byte *output, byte *input, Key key);
};
#endif