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
