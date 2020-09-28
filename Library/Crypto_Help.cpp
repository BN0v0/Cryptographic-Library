typedef unsigned char byte;     //8-bit
typedef long unsigned int Word; //32-bit word -> change to "long for 16-bit machines"

#define AES 1
#define Blowfish 2
#define DES 3
#define TDES 4

#define ECB 0
#define CBC 1

#define Success 1
#define Fail 0
#define ERROR (-1)