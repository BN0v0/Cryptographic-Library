#include <DES/des.h>

/* DES Operations */

/* Sbox Operations */
const byte sbox[256] PROGMEM = {
    /* S-box 1 */
    0xE4, 0xD1, 0x2F, 0xB8, 0x3A, 0x6C, 0x59, 0x07,
    0x0F, 0x74, 0xE2, 0xD1, 0xA6, 0xCB, 0x95, 0x38,
    0x41, 0xE8, 0xD6, 0x2B, 0xFC, 0x97, 0x3A, 0x50,
    0xFC, 0x82, 0x49, 0x17, 0x5B, 0x3E, 0xA0, 0x6D,
    /* S-box 2 */
    0xF1, 0x8E, 0x6B, 0x34, 0x97, 0x2D, 0xC0, 0x5A,
    0x3D, 0x47, 0xF2, 0x8E, 0xC0, 0x1A, 0x69, 0xB5,
    0x0E, 0x7B, 0xA4, 0xD1, 0x58, 0xC6, 0x93, 0x2F,
    0xD8, 0xA1, 0x3F, 0x42, 0xB6, 0x7C, 0x05, 0xE9,
    /* S-box 3 */
    0xA0, 0x9E, 0x63, 0xF5, 0x1D, 0xC7, 0xB4, 0x28,
    0xD7, 0x09, 0x34, 0x6A, 0x28, 0x5E, 0xCB, 0xF1,
    0xD6, 0x49, 0x8F, 0x30, 0xB1, 0x2C, 0x5A, 0xE7,
    0x1A, 0xD0, 0x69, 0x87, 0x4F, 0xE3, 0xB5, 0x2C,
    /* S-box 4 */
    0x7D, 0xE3, 0x06, 0x9A, 0x12, 0x85, 0xBC, 0x4F,
    0xD8, 0xB5, 0x6F, 0x03, 0x47, 0x2C, 0x1A, 0xE9,
    0xA6, 0x90, 0xCB, 0x7D, 0xF1, 0x3E, 0x52, 0x84,
    0x3F, 0x06, 0xA1, 0xD8, 0x94, 0x5B, 0xC7, 0x2E,
    /* S-box 5 */
    0x2C, 0x41, 0x7A, 0xB6, 0x85, 0x3F, 0xD0, 0xE9,
    0xEB, 0x2C, 0x47, 0xD1, 0x50, 0xFA, 0x39, 0x86,
    0x42, 0x1B, 0xAD, 0x78, 0xF9, 0xC5, 0x63, 0x0E,
    0xB8, 0xC7, 0x1E, 0x2D, 0x6F, 0x09, 0xA4, 0x53,
    /* S-box 6 */
    0xC1, 0xAF, 0x92, 0x68, 0x0D, 0x34, 0xE7, 0x5B,
    0xAF, 0x42, 0x7C, 0x95, 0x61, 0xDE, 0x0B, 0x38,
    0x9E, 0xF5, 0x28, 0xC3, 0x70, 0x4A, 0x1D, 0xB6,
    0x43, 0x2C, 0x95, 0xFA, 0xBE, 0x17, 0x60, 0x8D,
    /* S-box 7 */
    0x4B, 0x2E, 0xF0, 0x8D, 0x3C, 0x97, 0x5A, 0x61,
    0xD0, 0xB7, 0x49, 0x1A, 0xE3, 0x5C, 0x2F, 0x86,
    0x14, 0xBD, 0xC3, 0x7E, 0xAF, 0x68, 0x05, 0x92,
    0x6B, 0xD8, 0x14, 0xA7, 0x95, 0x0F, 0xE2, 0x3C,
    /* S-box 8 */
    0xD2, 0x84, 0x6F, 0xB1, 0xA9, 0x3E, 0x50, 0xC7,
    0x1F, 0xD8, 0xA3, 0x74, 0xC5, 0x6B, 0x0E, 0x92,
    0x7B, 0x41, 0x9C, 0xE2, 0x06, 0xAD, 0xF3, 0x58,
    0x21, 0xE7, 0x4A, 0x8D, 0xFC, 0x90, 0x35, 0x6B};

// Permutations Operations
const byte e_permtab[] PROGMEM = {
    4, 6, /* 4 bytes in 6 bytes out*/
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1};

const byte p_permtab[] PROGMEM = {
    4, 4, /* 32 bit -> 32 bit */
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25};

const byte ip_permtab[] PROGMEM = {
    8, 8, /* 64 bit -> 64 bit */
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7};

const byte inv_ip_permtab[] PROGMEM = {
    8, 8, /* 64 bit -> 64 bit */
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25};

const byte pc1_permtab[] PROGMEM = {
    8, 7, /* 64 bit -> 56 bit*/
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4};

const byte pc2_permtab[] PROGMEM = {
    7, 6, /* 56 bit -> 48 bit */
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32};

const byte splitin6bitword_permtab[] PROGMEM = {
    8, 8, /* 64 bit -> 64 bit */
    64, 64, 1, 6, 2, 3, 4, 5,
    64, 64, 7, 12, 8, 9, 10, 11,
    64, 64, 13, 18, 14, 15, 16, 17,
    64, 64, 19, 24, 20, 21, 22, 23,
    64, 64, 25, 30, 26, 27, 28, 29,
    64, 64, 31, 36, 32, 33, 34, 35,
    64, 64, 37, 42, 38, 39, 40, 41,
    64, 64, 43, 48, 44, 45, 46, 47};

const byte shiftkey_permtab[] PROGMEM = {
    7, 7, /* 56 bit -> 56 bit */
    2, 3, 4, 5, 6, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 1,
    30, 31, 32, 33, 34, 35, 36, 37,
    38, 39, 40, 41, 42, 43, 44, 45,
    46, 47, 48, 49, 50, 51, 52, 53,
    54, 55, 56, 29};

const byte shiftkeyinv_permtab[] PROGMEM = {
    7, 7,
    28, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27,
    56, 29, 30, 31, 32, 33, 34, 35,
    36, 37, 38, 39, 40, 41, 42, 43,
    44, 45, 46, 47, 48, 49, 50, 51,
    52, 53, 54, 55};

//XOR Operations
static void xor_block(byte *d, byte *s)
{

    for (byte i = 0; i < block_size; i++)
    {
        d[i] = d[i] ^ s[i];
    }
}

/* End of DES operations */

/*Key Scheduling */
void DES_Alg::setKey(byte *user_key)
{

    if (Algorithm == des)
    {
        for (size_t i = 0; i < 8; i++)
        {
            /* code */
            key.one[i] = user_key[i];
        }
    }
    else if (Algorithm == t_des)
    {
        for (size_t i = 0; i < 8; i++)
        {
            key.one[i] = user_key[i];
            key.two[i] = user_key[i + 8];
            key.three[i] = user_key[i + 16];
        }
    }
}

/*  Key Operations */
//Shift Key
void DES_Alg::shiftkey(byte *key)
{
    byte k[7];
    memcpy(k, key, 7);
    permute((byte *)shiftkey_permtab, k, key);
}

// Inverse Shift Key
void DES_Alg::shiftkey_inv(byte *key)
{
    byte k[7];
    memcpy(k, key, 7);
    permute((byte *)shiftkeyinv_permtab, k, key);
}

/*DES_Alg permutation*/
void DES_Alg::permute(const byte *ptable, const byte *in, byte *out)
{
    uint8_t ob;        /* in-bytes and out-bytes */
    uint8_t byte, bit; /* counter for bit and byte */
    ob = pgm_read_byte(&ptable[1]);
    ptable = &(ptable[2]);
    for (byte = 0; byte < ob; ++byte)
    {
        uint8_t x, t = 0;
        for (bit = 0; bit < 8; ++bit)
        {
            x = pgm_read_byte(ptable++) - 1;
            t <<= 1;
            if ((in[x / 8]) & (0x80 >> (x % 8)))
            {
                t |= 0x01;
            }
        }
        out[byte] = t;
    }
}

/*Change Endian*/
void DES_Alg::changeendian32(uint32_t *a)
{
    *a = (*a & 0x000000FF) << 24 |
         (*a & 0x0000FF00) << 8 |
         (*a & 0x00FF0000) >> 8 |
         (*a & 0xFF000000) >> 24;
}
/* Split bit words */
uint64_t DES_Alg::splitin6bitwords(uint64_t a)
{
    uint64_t ret = 0;
    a &= 0x0000ffffffffffffLL;
    permute((uint8_t *)splitin6bitword_permtab, (uint8_t *)&a, (uint8_t *)&ret);
    return ret;
}
// Substitution Operations
uint8_t DES_Alg::substitute(uint8_t a, uint8_t *sbp)
{
    uint8_t x;
    x = pgm_read_byte(&sbp[a >> 1]);
    x = (a & 1) ? x & 0x0F : x >> 4;
    return x;
}

//DES_Alg F
uint32_t DES_Alg::des_f(uint32_t r, uint8_t *kr)
{
    uint8_t i;
    uint32_t t = 0, ret;
    uint64_t data;
    uint8_t *sbp; /* sboxpointer */
    permute((uint8_t *)e_permtab, (uint8_t *)&r, (uint8_t *)&data);
    for (i = 0; i < 7; ++i)
        ((uint8_t *)&data)[i] ^= kr[i];

    /* Sbox substitution */
    data = splitin6bitwords(data);
    sbp = (uint8_t *)sbox;
    for (i = 0; i < 8; ++i)
    {
        uint8_t x;
        x = substitute(((uint8_t *)&data)[i], sbp);
        t <<= 4;
        t |= x;
        sbp += 32;
    }
    changeendian32(&t);

    permute((uint8_t *)p_permtab, (uint8_t *)&t, (uint8_t *)&ret);

    return ret;
}

/* Encryption and Decryption Operations */

/* DES_Alg Encryption Operation*/
void DES_Alg::encrypt(void *out, const void *in, byte *key)
{
    uint8_t kr[6], k[7];
    uint8_t i;
    union
    {
        uint8_t v8[8];
        uint32_t v32[2];
    } data;

    permute((uint8_t *)ip_permtab, (uint8_t *)in, data.v8);
    permute((uint8_t *)pc1_permtab, (const uint8_t *)key, k);
    for (i = 0; i < 8; ++i)
    {
        shiftkey(k);
        if (rottable & ((1 << ((i << 1) + 0))))
            shiftkey(k);
        permute((uint8_t *)pc2_permtab, k, kr);
        L ^= des_f(R, kr);

        shiftkey(k);
        if (rottable & ((1 << ((i << 1) + 1))))
            shiftkey(k);
        permute((uint8_t *)pc2_permtab, k, kr);
        R ^= des_f(L, kr);
    }
    /* L <-> R*/
    R ^= L;
    L ^= R;
    R ^= L;
    permute((uint8_t *)inv_ip_permtab, data.v8, (uint8_t *)out);
}

/* DES_Alg Decryption Operation */
void DES_Alg::decrypt(void *out, const void *in, byte *key)
{
    uint8_t kr[6], k[7];
    union
    {
        uint8_t v8[8];
        uint32_t v32[2];
    } data;
    int8_t i;
    permute((uint8_t *)ip_permtab, (uint8_t *)in, data.v8);
    permute((uint8_t *)pc1_permtab, (const uint8_t *)key, k);
    for (i = 7; i >= 0; --i)
    {

        permute((uint8_t *)pc2_permtab, k, kr);
        L ^= des_f(R, kr);
        shiftkey_inv(k);
        if (rottable & ((1 << ((i << 1) + 1))))
        {
            shiftkey_inv(k);
        }

        permute((uint8_t *)pc2_permtab, k, kr);
        R ^= des_f(L, kr);
        shiftkey_inv(k);
        if (rottable & ((1 << ((i << 1) + 0))))
        {
            shiftkey_inv(k);
        }
    }
    /* L <-> R*/
    R ^= L;
    L ^= R;
    R ^= L;
    permute((uint8_t *)inv_ip_permtab, data.v8, (uint8_t *)out);
}

/* Triple DES_Alg Encryption Operation */
void DES_Alg::tripleEncrypt(byte *out, byte *in, Key key)
{

    encrypt(out, in, key.one);
    encrypt(&out[8], &in[8], key.one);
    decrypt(out, out, key.two);
    decrypt(&out[8], &out[8], key.two);
    encrypt(out, out, key.three);
    encrypt(&out[8], &out[8], key.three);
}
/* Triple DES_Alg Decryption Operation */
void DES_Alg::tripleDecrypt(byte *out, byte *in, Key key)
{
    decrypt(out, in, key.three);
    decrypt(&out[8], &in[8], key.three);
    encrypt(out, out, key.two);
    encrypt(&out[8], &out[8], key.two);
    decrypt(out, out, key.one);
    decrypt(&out[8], &out[8], key.one);
}

/* Triple DES_Alg Encryption Operation */
void DES_Alg::tripleXORedEncrypt(byte *out, byte *in, Key key)
{

    xor_block(in, IVE);
    encrypt(out, in, key.one);
    decrypt(out, out, key.two);
    encrypt(out, out, key.three);
    xor_block(&in[8], out);
    encrypt(&out[8], &in[8], key.one);
    decrypt(&out[8], &out[8], key.two);
    encrypt(&out[8], &out[8], key.three);

}
/* Triple DES_Alg Decryption Operation */
void DES_Alg::tripleXORedDecrypt(byte *out, byte *in, Key key)
{
    decrypt(out, in, key.three);
    encrypt(out, out, key.two);   
    decrypt(out, out, key.one);
    xor_block(out, IVD);

    decrypt(&out[8], &in[8], key.three);
    encrypt(&out[8], &out[8], key.two);
    decrypt(&out[8], &out[8], key.one);
    xor_block(&out[8], in);
}

/* Public Functions */

void DES_Alg::Initialize(int algorithm, int mode, byte *user_iv)
{

    Algorithm = algorithm;
    Mode = mode;

    if (Mode == CBC)
    {
        IVE = user_iv;
        IVE2 = user_iv;
        IVD = user_iv;
        IVD2 = user_iv;
    }
}

bool DES_Alg::KeySchedule(byte *user_key)
{

    setKey(user_key);
}

int DES_Alg::Encryption(byte *input, byte *output)
{

    if (Algorithm == des)
    {
        switch (Mode)
        {
        case ECB:
            /* code */
            encrypt(output, input, key.one);
            encrypt(&output[8], &input[8], key.one);
            break;

        case CBC:
            xor_block(input, IVE);
            encrypt(output, input, key.one);
            xor_block(&input[8], output);
            encrypt(&output[8], &input[8], key.one);
            break;

        default:

            return ERROR;
            break;
        }
    }
    else if (Algorithm == t_des)
    {
        switch (Mode)
        {
        case ECB:
            /* code */
            tripleEncrypt(output, input, key);
            break;

        case CBC:

            tripleXORedEncrypt(output, input, key);
            break;

        default:

            return ERROR;
            break;
        }
    }
    else
    {
        return ERROR;
    }
}

int DES_Alg::Decryption(byte *input, byte *output)
{

    if (Algorithm == des)
    {
        switch (Mode)
        {
        case ECB:
            /* code */
            decrypt(output, input, key.one);
            decrypt(&output[8], &input[8], key.one);
            break;

        case CBC:
            decrypt(output, input, key.one);
            xor_block(output, IVD);
            decrypt(&output[8], &input[8], key.one);
            xor_block(&output[8], input);

            break;

        default:

            return ERROR;
            break;
        }
    }
    else if (Algorithm == t_des)
    {
        switch (Mode)
        {
        case ECB:
            /* code */
            tripleDecrypt(output, input, key);
            break;

        case CBC:
            tripleXORedDecrypt(output, input, key);
            break;

        default:

            return ERROR;
            break;
        }
    }
    else
    {
        return ERROR;
    }
}
