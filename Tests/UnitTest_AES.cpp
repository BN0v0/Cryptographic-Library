#include <aes.h>
#include <Arduino.h>
#include <unity.h>

AES aes;
#define LENGTH 16

void Test_First_case(){
     //Initialization
    byte Key[] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81
    };
    byte Plain1[]={0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    byte Cipher1[16];
    byte Decipher1[16];
    //Expected
    byte CipherExpected[]={0x8d,0x91,0x58,0x9b,0xea,0x81,0x10,0x5c,0xdd,0x0c,0x45,0x15,0x45,0xd0,0x63,0x0c};

    aes.Initialize(ECB,Key,nullptr);
    aes.Encryption(Cipher1,Plain1);
    int EncryResult =   memcmp(Cipher1,CipherExpected,LENGTH);
    TEST_ASSERT(EncryResult == 0);
    aes.Decryption(Decipher1,Cipher1);
    int DecryResult =   memcmp(Decipher1,Plain1,LENGTH);
    TEST_ASSERT(DecryResult == 0);
}


void Test_Second_case(){
       //Initialization
    byte Key2[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    byte Plain2[]={0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    byte Cipher2[16];
    byte Decipher2[16];
    //Expected
    byte CipherExpected2[]={0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97};

    aes.Initialize(ECB,Key2,nullptr);
    aes.Encryption(Cipher2,Plain2);
    int EncryResult2 =   memcmp(Cipher2,CipherExpected2,LENGTH);
    TEST_ASSERT(EncryResult2 == 0);
    aes.Decryption(Decipher2,Cipher2);
    int DecryResult2 =   memcmp(Decipher2,Plain2,LENGTH);
    TEST_ASSERT(DecryResult2 == 0);
}

void Test_Third_case(){
       //Initialization
    byte Key3[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    byte Plain3[]={0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
    byte Cipher3[16];
    byte Decipher3[16];
    //Expected
    byte CipherExpected3[]={0xf5,0xd3,0xd5,0x85,0x03,0xb9,0x69,0x9d,0xe7,0x85,0x89,0x5a,0x96,0xfd,0xba,0xaf};

    aes.Initialize(ECB,Key3,nullptr);
    aes.Encryption(Cipher3,Plain3);
    int EncryResult3 =   memcmp(Cipher3,CipherExpected3,LENGTH);
    TEST_ASSERT(EncryResult3 == 0);
    aes.Decryption(Decipher3,Cipher3);
    int DecryResult3 =   memcmp(Decipher3,Plain3,LENGTH);
    TEST_ASSERT(DecryResult3 == 0);
}


// CBC Mode
void Test_First_case_CBC(){
     //Initialization
    byte Key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    byte Plain1[]={0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    byte iv[] ={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    byte Cipher1[16];
    byte Decipher1[16];
    //Expected
    byte CipherExpected[]={0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d};

    aes.Initialize(CBC,Key,iv);
    aes.Encryption(Cipher1,Plain1);
    int EncryResult =   memcmp(Cipher1,CipherExpected,LENGTH);
    TEST_ASSERT(EncryResult == 0);
    aes.Decryption(Decipher1,Cipher1);
    int DecryResult =   memcmp(Decipher1,Plain1,LENGTH);
    TEST_ASSERT(DecryResult == 0);
}


void Test_Second_case_CBC(){
       //Initialization
    byte Key2[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    byte Plain2[]={0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    byte iv2[]={0x76,0x49,0xAB,0xAC,0x81,0x19,0xB2,0x46,0xCE,0xE9,0x8E,0x9B,0x12,0xE9,0x19,0x7D};
    byte Cipher2[16];
    byte Decipher2[16];
    //Expected
    byte CipherExpected2[]={0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2};

    aes.Initialize(CBC,Key2,iv2);
    aes.Encryption(Cipher2,Plain2);
    int EncryResult2 =   memcmp(Cipher2,CipherExpected2,LENGTH);
    TEST_ASSERT(EncryResult2 == 0);
    aes.Decryption(Decipher2,Cipher2);
    int DecryResult2 =   memcmp(Decipher2,Plain2,LENGTH);
    TEST_ASSERT(DecryResult2 == 0);
}

void Test_Third_case_CBC(){
       //Initialization
    byte Key3[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    byte Plain3[]={0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
    byte iv3[] ={0x50,0x86,0xCB,0x9B,0x50,0x72,0x19,0xEE,0x95,0xDB,0x11,0x3A,0x91,0x76,0x78,0xB2};
    byte Cipher3[16];
    byte Decipher3[16];
    //Expected
    byte CipherExpected3[]={0x73,0xbe,0xd6,0xb8,0xe3,0xc1,0x74,0x3b,0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16};

    aes.Initialize(CBC,Key3,iv3);
    aes.Encryption(Cipher3,Plain3);
    int EncryResult3 =   memcmp(Cipher3,CipherExpected3,LENGTH);
    TEST_ASSERT(EncryResult3 == 0);
    aes.Decryption(Decipher3,Cipher3);
    int DecryResult3 =   memcmp(Decipher3,Plain3,LENGTH);
    TEST_ASSERT(DecryResult3 == 0);
}


void setup(){
    delay(2000);

    UNITY_BEGIN();    // IMPORTANT LINE!
    
    RUN_TEST(Test_First_case);
     delay(500);
    RUN_TEST(Test_Second_case);
     delay(500);
     RUN_TEST(Test_Third_case);
    delay(500);
    RUN_TEST(Test_First_case_CBC);
     delay(500);
    RUN_TEST(Test_Second_case_CBC);
     delay(500);
     RUN_TEST(Test_Third_case_CBC);

    UNITY_END();

}

void loop(){

}