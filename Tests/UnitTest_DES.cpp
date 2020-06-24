#include <des.h>
#include <Arduino.h>
#include <unity.h>

#define LENGTH 8

DES Des;

void Test_First_case(){
     //Initialization
    byte Key[] = {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
    byte Plain1[]={0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    byte Cipher1[LENGTH];
    byte Decipher1[LENGTH];
    //Expected
    byte CipherExpected[]={0x95 ,0xf8,0xa5,0xe5,0xdd,0x31,0xd9,0x00};

    Des.Initialize(des,ECB,Key,nullptr);

    Des.Encryption(Cipher1,Plain1);
    int EncryResult =   memcmp(Cipher1,CipherExpected,LENGTH);
    TEST_ASSERT(EncryResult == 0);
    Des.Decryption(Decipher1,Cipher1);
    int DecryResult =   memcmp(Decipher1,Plain1,LENGTH);
    TEST_ASSERT(DecryResult == 0);
}

void Test_Second_case(){
     //Initialization
    byte Key[] = {0x75,0x28,0x78,0x39,0x74,0x93,0xCB,0x70};
    byte Plain1[]={0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    byte Cipher1[16];
    byte Decipher1[16];
    //Expected
    byte CipherExpected[]={0xB5 ,0x21,0x9E,0xE8,0x1A,0xA7,0x49,0x9d};

    Des.Initialize(des,ECB,Key,nullptr);

    Des.Encryption(Cipher1,Plain1);
    int EncryResult =   memcmp(Cipher1,CipherExpected,LENGTH);
    TEST_ASSERT(EncryResult == 0);
    Des.Decryption(Decipher1,Cipher1);
    int DecryResult =   memcmp(Decipher1,Plain1,LENGTH);
    TEST_ASSERT(DecryResult == 0);
}



// CBC MODE

void Test_First_case_CBC(){
     //Initialization
    byte Key[] = {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
    byte Plain1[]={0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    byte iv[] ={0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    byte Cipher1[LENGTH];
    byte Decipher1[LENGTH];
    //Expected
    byte CipherExpected[]={0x64,0xb0,0x99,0xb6,0xa6,0x96,0x67,0x52};

    Des.Initialize(des,CBC,Key,iv);

    Des.Encryption(Cipher1,Plain1);
    int EncryResult =   memcmp(Cipher1,CipherExpected,LENGTH);
    TEST_ASSERT(EncryResult == 0);
    Des.Decryption(Decipher1,Cipher1);
    int DecryResult =   memcmp(Decipher1,Plain1,LENGTH);
    TEST_ASSERT(DecryResult == 0);
}

void Test_Second_case_CBC(){
     //Initialization
    byte Key[] = {0x75,0x28,0x78,0x39,0x74,0x93,0xCB,0x70};
    byte Plain1[]={0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    byte iv[] ={0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    byte Cipher1[16];
    byte Decipher1[16];
    //Expected
    byte CipherExpected[]={0x56,0x72,0x1e,0x40,0xa6,0x99,0x14,0xae};

    Des.Initialize(des,CBC,Key,iv);

    Des.Encryption(Cipher1,Plain1);
    int EncryResult =   memcmp(Cipher1,CipherExpected,LENGTH);
    TEST_ASSERT(EncryResult == 0);
    Des.Decryption(Decipher1,Cipher1);
    int DecryResult =   memcmp(Decipher1,Plain1,LENGTH);
    TEST_ASSERT(DecryResult == 0);
}



void setup(){

    delay(2000);

    UNITY_BEGIN();    // IMPORTANT LINE!
    
    RUN_TEST(Test_First_case);
    RUN_TEST(Test_Second_case);

    RUN_TEST(Test_First_case_CBC);
    RUN_TEST(Test_Second_case_CBC);
    UNITY_END();

}

void loop(){

}