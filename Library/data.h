#ifndef Data_H
#define Data_H


#define SUCCESS 0
#define FAILURE 1
#define ERROR (-1)

typedef unsigned char byte; //8-bit 
typedef unsigned int Word;  //32-bit word -> change to "long for 16-bit machines"

struct blowfish_key{
    Word p[18];
    Word s[4][256];
};

#endif