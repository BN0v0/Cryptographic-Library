#include <Crypto.h>
#include <Arduino.h>
#include <AES/aes.h>
#include <DES/des.h>
#include <Blowfish/blowfish.h>

Blowfish_Alg blw;
AES_Alg aes;
DES_Alg Des;

bool Crypto::Initialize(int Alg)
{
    EncAlg = Alg;
    switch (Alg)
    {
    case AES:
        aes = AES_Alg();
        aes.Initialize(ECB,nullptr);
        break;
    case DES:
        Des = DES_Alg();
        Des.Initialize(des, ECB,nullptr);
        break;
    case TDES:
        Des = DES_Alg();
        Des.Initialize(t_des, ECB, nullptr);
        break;
    case Blowfish:
        blw = Blowfish_Alg();
        blw.Initialize(ECB,nullptr);
        break;
    default:
        return ERROR;
        break;
    }

    return Success;
}

bool Crypto::Initialize(int Alg, byte* IV)
{
    EncAlg = Alg;
    switch (Alg)
    {
    case AES:
        aes = AES_Alg();
        aes.Initialize(CBC,IV);
        break;
    case DES:
        Des = DES_Alg();
        Des.Initialize(des,CBC,IV);
        break;
    case TDES:
        Des = DES_Alg();
        Des.Initialize(t_des, CBC, IV);
        break;
    case Blowfish:
        blw = Blowfish_Alg();
        blw.Initialize(CBC, IV);
        break;
    default:
        return ERROR;
        break;
    }

    return Success;
}

bool Crypto::KeySchedule(byte *key)
{
    switch (EncAlg)
    {
    case AES:
        aes.KeySetup(key);
        break;
    case DES:
        Des.KeySchedule(key);
        break;
    case TDES:
        Des.KeySchedule(key);
        break;
    case Blowfish:
        blw.KeySchedule(key);
        break;
    default:
        return ERROR;
        break;
    }

    return Success;
}

int Crypto::Encryption(byte *in, byte *out)
{

    switch (EncAlg)
    {
    case AES:
        return aes.Encryption(in, out);
        break;
    case DES:
        return Des.Encryption(in, out);
        break;
    case TDES:
        return Des.Encryption(in, out);
        break;
    case Blowfish:
        return blw.Encryption(in, out);
        break;
    default:
        return ERROR;
        break;
    }

    return Fail;
}

int Crypto::Decryption(byte* in, byte* out){

switch (EncAlg)
    {
    case AES:
        return aes.Decryption(in, out);
        break;
    case DES:
        return Des.Decryption(in, out);
        break;
    case TDES:
        return Des.Decryption(in, out);
        break;
    case Blowfish:
        return blw.Decryption(in, out);
        break;
    default:
        return ERROR;
        break;
    }

    return Fail;
}

void Crypto::PrintArray_byte(uint8_t array[],int LENGTH){
    for(int i = 0; i < LENGTH;i++){
      Serial.print(array[i],HEX);
      Serial.print("  ");
    }
}

