#include <Arduino.h>

//Inclusions
#include <AES.h>
#include <Printing.h>

#define KEY_LENGTH 32
#define IV_LENGTH 16
#define LENGTH 16

AES aes;
    //Initialization
    byte key[KEY_LENGTH] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};//16bytes
    byte iv[IV_LENGTH] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};//16bytes
    byte msg[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    byte cipher[LENGTH];//128 bits = 16 bytes
    byte plainText[LENGTH];

void setup()
{
    Serial.begin(9600);
    
    //Initialization
    aes.Initialize(CBC,key,iv );

    //Encryption
    aes.Encryption(cipher,msg);
    PrintArray_byte(cipher,LENGTH); // use to print the outputs

    Serial.println();

    //Decryption
    aes.Decryption(plainText,cipher);
    PrintArray_byte(plainText,LENGTH);// use to print the outputs

}

void loop(){

}
