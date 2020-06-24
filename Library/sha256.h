/*
Copyright 2020 Bruno Novo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#ifndef Sha256_h
#define Sha256_h

#define memcpy_P memcpy
#define pgm_read_dword(p) (*(p))

#include <inttypes.h>
#include <string.h>
#include <data.h>

#define outputLength 32
#define blockLength 64
#define bufferLength 64


class Sha_256
{
  public:
	union _buffer {
		uint8_t b[blockLength];
		uint32_t w[blockLength/4];
	};
	union _state {
		uint8_t b[outputLength];
		uint32_t w[outputLength/4];
	};
   
    void init(void);

	uint8_t* result(void);

	size_t write(uint8_t);

	void Add(byte content);

  private:
  	_buffer buffer;/**< hold the buffer for the hashing process */
    uint8_t bufferOffset;/**< indicates the position on the buffer */
    _state state;/**< identical structure with buffer */
    uint32_t byteCount;/**< Byte counter in order to initialize the hash process for a block */
   	
	
    void Padding();
	
	
    void addUncounted(uint8_t data);
	

    void hashBlock();

	
    uint32_t rot32(uint32_t number, uint8_t bits);
    
};

#endif
