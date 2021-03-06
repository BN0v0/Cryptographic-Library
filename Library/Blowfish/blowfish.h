#ifndef Blowfish_h
#define Blowfish_h

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <Crypto_Help.cpp>
#include <avr/pgmspace.h>

struct blowfish_key
{
    Word p[18];
    Word s[4][256];
};

#define block_size 8
#define ECB 0
#define CBC 1

#define SwL(l, in) l = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | (in[3]);
#define SwR(r, in) r = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | (in[7])

#define F(x, t)                               \
    t = keystruct->s[0][(x) >> 24];           \
    t += keystruct->s[1][((x) >> 16) & 0xff]; \
    t ^= keystruct->s[2][((x) >> 8) & 0xff];  \
    t += keystruct->s[3][(x)&0xff];
#define swap(r, l, t) \
    t = l;            \
    l = r;            \
    r = t;
#define ITERATION(l, r, t, pval) \
    l ^= keystruct->p[pval];     \
    F(l, t);                     \
    r ^= t;                      \
    swap(r, l, t);

class Blowfish_Alg
{

public:
    void Initialize(int mode, byte *iv_user);
    bool KeySchedule(byte *key);
    int Encryption(byte in[], byte out[]);
    int Decryption(byte in[], byte out[]);

private:
    size_t length;
    int Mode;
    byte *IVE;
    byte *IVD;
    byte iv_enc[16];
    byte iv_dec[16];
    blowfish_key *keystruct;
    void key_setup(byte *user_key, blowfish_key *keystruct, size_t size);
    void encrypt(byte input[], byte output[], blowfish_key *keystruct);
    void decrypt(byte input[], byte output[], blowfish_key *keystruct);
};
#endif