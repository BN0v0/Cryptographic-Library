#include <Arduino.h>
#include <blowfish.h>
#include <time.h>
#include <Printing.h>

Blowfish bl;

void setup() {
  Serial.begin(9600);
  Serial.println();

    byte userkey[block_size]={0x00,0x00, 0x00,0x00 ,0x00,0x00,0x00,0x00};
    blowfish_key key;

    byte iv[block_size]={0x10,0x10, 0x10,0x10 ,0x10,0x10,0x10,0x10};

    //In Message -> to Encrypt
    byte mIn[block_size] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    //Encrypted Message -> to Decrypt
    byte mEnc[block_size];
    //Decrypted Message
    byte mOut[block_size];



    bl.Initialize(CBC,userkey,&key,block_size,iv);
    Serial.println("----------");
    bl.Encryption(mIn,mEnc,&key);
    PrintArray_byte(mEnc,block_size);

    Serial.println("----------");
    bl.Decryption(mEnc,mOut,&key);
    PrintArray_byte(mOut,block_size);
    Serial.println("---END---");

    Serial.println();
    Serial.println();
    

    delay(500);
  

  
}

void loop() {
  // put your main code here, to run repeatedly:
}