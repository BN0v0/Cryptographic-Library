#include <Arduino.h>
#include <unity.h>
#include <blowfish.h>

Blowfish bl;

void Test_First_case(){
    byte key[]={
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    };
    blowfish_key keystruct;
    byte msg[] ={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    byte cipher[8];
    byte decipher[8];

    byte CipherExpected []= {0x1b,0xfe,0xd9,0x3f,0xc7,0xd9,0x9b,0x9e};

    bl.Initialize(ECB,key,&keystruct,8,nullptr);
    bl.Encryption(msg,cipher,&keystruct);
    int EncryResult =   memcmp(cipher,CipherExpected,8);
    TEST_ASSERT(EncryResult == 0);

    bl.Decryption(cipher,decipher,&keystruct);
    int DecrResult =   memcmp(decipher,msg,8);
    TEST_ASSERT(DecrResult == 0);
}



void Test_Second_case(){
    byte key[]={
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    };
    blowfish_key keystruct;
    byte msg[] ={0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xa0,0xb0};
    byte cipher[8];
    byte decipher[8];

    byte CipherExpected []= {0x7b,0x0b,0x29,0x8d,0xc2,0x71,0xbe,0x2c};

    bl.Initialize(ECB,key,&keystruct,8,nullptr);
    bl.Encryption(msg,cipher,&keystruct);
    int EncryResult =   memcmp(cipher,CipherExpected,8);
    TEST_ASSERT(EncryResult == 0);

    bl.Decryption(cipher,decipher,&keystruct);
    int DecrResult =   memcmp(decipher,msg,8);
    TEST_ASSERT(DecrResult == 0);
}



void Test_First_case_CBC(){
    byte key[]={
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    };
    blowfish_key keystruct;
    byte msg[] ={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    byte iv[]={0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11};
    byte cipher[8];
    byte decipher[8];

    byte CipherExpected []= {0x4c,0x88,0x54,0xc1,0x35,0x7e,0xac,0xaa};
    byte msgExpected[] ={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    bl.Initialize(CBC,key,&keystruct,8,iv);
    bl.Encryption(msg,cipher,&keystruct);
    int EncryResult =   memcmp(cipher,CipherExpected,8);
    TEST_ASSERT(EncryResult == 0);

    bl.Decryption(cipher,decipher,&keystruct);
    int DecrResult =   memcmp(decipher,msgExpected,8);
    TEST_ASSERT(DecrResult == 0);
}



void Test_Second_case_CBC(){
    byte key[]={
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    };
    blowfish_key keystruct;
    byte msg[] ={0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xa0,0xb0};
    byte iv[]={0xab,0xcd,0xef,0x12,0x34,0x56,0x78,0x90};
    byte cipher[8];
    byte decipher[8];

    byte CipherExpected []= {0x60,0x13,0x50,0xc5,0x54,0x9c,0xb9,0x9f};
    byte msgExpected[] ={0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xa0,0xb0};

    bl.Initialize(CBC,key,&keystruct,8,iv);
    bl.Encryption(msg,cipher,&keystruct);
    int EncryResult =   memcmp(cipher,CipherExpected,8);
    TEST_ASSERT(EncryResult == 0);

    bl.Decryption(cipher,decipher,&keystruct);
    int DecrResult =   memcmp(decipher,msgExpected,8);
    TEST_ASSERT(DecrResult == 0);
}


void setup(){
    delay(2000);
    UNITY_BEGIN();

    RUN_TEST(Test_First_case);
    RUN_TEST(Test_Second_case);

     RUN_TEST(Test_First_case_CBC);
    RUN_TEST(Test_Second_case_CBC);
 
    UNITY_END();
}

void loop(){

}