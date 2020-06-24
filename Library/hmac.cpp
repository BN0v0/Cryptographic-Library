/*
Copyright 2020 Bruno Novo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#include <hmac.h>

MD5Builder md5;
Sha_256 sha256;


void HMAC::printHash(byte*  result,int algorithm){
    int size=0;
    switch (algorithm)
    {
    case MD5:
         size=Length_MD5;
        break;
    case SHA_256:
        size = Length_SHA256;
    }
    for(int i = 0; i < size; i++) {
		byte b = result[i];
		if(b < 0x10) Serial.print('0');
		Serial.print(b, HEX); 
        Serial.print(' ');
	}
}


byte* HMAC::MD5_HMAC( byte* data ,size_t data_size, byte* key, size_t key_size){
     byte result[Length_MD5];
     byte tempHash[Length_MD5];
     byte OuterKeyPadded[blocksize];
     byte InnerKeyPadded[blocksize];
     byte padd_Key[]= { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        if(key_size < blocksize){
            for(size_t i = 0; i < key_size; i++) {
                        padd_Key[i] = key[i];
                }
        }else{
            md5.begin();
            md5.add(key, key_size);
            md5.calculate();
            md5.getBytes(padd_Key);
        }

      for (int i = 0; i < blocksize; i++) {
		OuterKeyPadded[i] = padd_Key[i] ^ OutterPad;
		InnerKeyPadded[i] = padd_Key[i] ^ InnerPad;
	}
   
    
    md5.begin();
	md5.add(InnerKeyPadded, blocksize);
	md5.add(data, data_size);
	md5.calculate();
	md5.getBytes(tempHash);

	md5.begin();
	md5.add(OuterKeyPadded, blocksize);
	md5.add(tempHash, Length_MD5);
	md5.calculate();
	md5.getBytes(result);

    return result;
}


byte* HMAC::SHA256_HMAC( byte* data ,size_t data_size, byte* key, size_t key_size ){
    uint8_t i ;
    byte keyBuffer[blockLength]; // K0 in FIPS-198a
    byte innerHash[outputLength];
   
    memset(keyBuffer,0,blockLength);
    if (key_size > blockLength) {
        // Hash long keys
        sha256.init();
        while(key_size--) sha256.write(*key++);
        memcpy(keyBuffer,sha256.result(),outputLength);
    } else {
        // Block length keys are used as is
        memcpy(keyBuffer,key,key_size);
    }

    // Start inner hash
    sha256.init();
    
    for (i=0; i<blockLength; i++) {
        sha256.Add(keyBuffer[i] ^ InnerPad);
    }

    for (size_t i = 0; i < data_size; i++)
    {
        sha256.Add(data[i]);
    }
    
    memcpy(innerHash,sha256.result(),outputLength);
    // Calculate outer hash
    sha256.init();
    for (i=0; i<blockLength; i++)
        sha256.Add(keyBuffer[i] ^ OutterPad);
    for (i=0; i<outputLength; i++) 
        sha256.Add(innerHash[i]);

    return sha256.result();
}


void HMAC::hmac(int HashFunction , byte* data ,size_t data_size, byte* key, size_t key_size,byte* result ){
  
    switch (HashFunction)
    {
    case MD5:
          
          memcpy(result,MD5_HMAC(data,data_size,key,key_size),Length_MD5);    

        break;
    case SHA_256:

        memcpy(result,SHA256_HMAC(data,data_size,key,key_size),Length_SHA256);    

        break;
    }

}
