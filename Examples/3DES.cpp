#include <Arduino.h>

//Inclusions
#include <DES.h>
#include <Printing.h>

#define KEY_LENGTH 32
#define IV_LENGTH 16
#define LENGTAESH 16

DES Des;
    //Initialization
    byte key[] = {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
    byte msg[]={0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    byte iv[] ={0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    byte cipher[8];//128 bits = 16 bytes
    byte plainText[8];

void setup()
{
    Serial.begin(9600);
    Serial.println();
    //Initialization
    Des.Initialize(t_des,CBC,key,iv);

    //Encryption
    Des.Encryption(cipher,msg);
    PrintArray_byte(cipher,8); // use to print the outputs

    Serial.println();

    //Decryption
    Des.Decryption(plainText,cipher);
    PrintArray_byte(plainText,8);// use to print the outputs

}

void loop(){

}
