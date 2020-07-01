/*
Copyright 2020 Bruno Novo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#include <blowfish.h>
#include <blowfish_operations.cpp>



void Blowfish::encrypt( byte in[], byte out[],  blowfish_key *keystruct)
{
    Word l,r,t; 

    SwL(l,in);
    SwR(r,in);

    ITERATION(l,r,t,0);
    ITERATION(l,r,t,1);
    ITERATION(l,r,t,2);
    ITERATION(l,r,t,3);
    ITERATION(l,r,t,4);
    ITERATION(l,r,t,5);
    ITERATION(l,r,t,6);
    ITERATION(l,r,t,7);
    ITERATION(l,r,t,8);
    ITERATION(l,r,t,9);
    ITERATION(l,r,t,10);
    ITERATION(l,r,t,11);
    ITERATION(l,r,t,12);
    ITERATION(l,r,t,13);
    ITERATION(l,r,t,14);
    l ^= keystruct->p[15]; 
    F(l,t); 
    r^= t; //Last iteration has no swap()
    r ^= keystruct->p[16];
    l ^= keystruct->p[17];

    out[0] = l >> 24;
    out[1] = l >> 16;
    out[2] = l >> 8;
    out[3] = l;
    out[4] = r >> 24;
    out[5] = r >> 16;
    out[6] = r >> 8;
    out[7] = r;
}

void Blowfish::decrypt( byte in[], byte out[],  blowfish_key *keystruct)
{
    Word l,r,t; 

    SwL(l,in);
    SwR(r,in);;

    ITERATION(l,r,t,17);
    ITERATION(l,r,t,16);
    ITERATION(l,r,t,15);
    ITERATION(l,r,t,14);
    ITERATION(l,r,t,13);
    ITERATION(l,r,t,12);
    ITERATION(l,r,t,11);
    ITERATION(l,r,t,10);
    ITERATION(l,r,t,9);
    ITERATION(l,r,t,8);
    ITERATION(l,r,t,7);
    ITERATION(l,r,t,6);
    ITERATION(l,r,t,5);
    ITERATION(l,r,t,4);
    ITERATION(l,r,t,3);
    l ^= keystruct->p[2]; 
    F(l,t); 
    r^= t; //Last iteration has no swap()
    r ^= keystruct->p[1];
    l ^= keystruct->p[0];

    out[0] = l >> 24;
    out[1] = l >> 16;
    out[2] = l >> 8;
    out[3] = l;
    out[4] = r >> 24;
    out[5] = r >> 16;
    out[6] = r >> 8;
    out[7] = r;
}

void Blowfish::key_setup( byte* user_key, blowfish_key *keystruct, size_t len)
{
    byte block[8];
    int idx,idx2;

    // Copy over the constant init array vals (so the originals aren't destroyed).
    memcpy(keystruct->p,p_perm,sizeof(Word) * 18);
    memcpy(keystruct->s,s_perm,sizeof(Word) * 1024);

    // Combine the key with the P box. Assume key is standard 448 bits (56 bytes) or less.
    for (idx = 0, idx2 = 0; idx < 18; ++idx, idx2 += 4)
        keystruct->p[idx] ^= (user_key[idx2 % len] << 24) | (user_key[(idx2+1) % len] << 16)
                             | (user_key[(idx2+2) % len] << 8) | (user_key[(idx2+3) % len]);
    // Re-calculate the P box.
    memset(block, 0, 8);
    for (idx = 0; idx < 18; idx += 2) {
        encrypt(block,block,keystruct);
        keystruct->p[idx] = (block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3];
        keystruct->p[idx+1]=(block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7];
    }
    // Recalculate the S-boxes.
    for (idx = 0; idx < 4; ++idx) {
        for (idx2 = 0; idx2 < 256; idx2 += 2) {
            encrypt(block,block,keystruct);
            keystruct->s[idx][idx2] = (block[0] << 24) | (block[1] << 16) |
                                      (block[2] << 8) | block[3];
            keystruct->s[idx][idx2+1] = (block[4] << 24) | (block[5] << 16) |
                                        (block[6] << 8) | block[7];
        }
    }
}

//XOR Operations
static void xor_block (byte * d, byte * s)
{
        
  for (byte i = 0 ; i < block_size ; i ++)
    {
       d[i] = d[i] ^ s[i];
    }
}


void Blowfish::Initialize(int mode, byte* user_key, size_t len, byte* iv_user){

    Mode = mode;
    keystruct = new blowfish_key();
    key_setup(user_key,keystruct,len);
    
    
    if(Mode == CBC){
        memcpy(iv_enc,iv_user,8);
        memcpy(iv_dec,iv_user,8);
        IVE = iv_enc;;
        IVD =iv_dec;
      
    }
}


int Blowfish::Encryption(byte in[], byte out[]){

    switch (Mode)
    {
        case ECB:
            /* code */
            encrypt(in,out,keystruct);
            break;
        case CBC:
            /* code */
            xor_block(in,IVE);
            encrypt(in,out,keystruct);
        break;
        
        default:
        return ERROR;
            break;
    }

}

int Blowfish::Decryption(byte in[], byte out[]){

    switch (Mode)
    {
        case ECB:
            /* code */
            decrypt(in,out,keystruct);
            break;
        case CBC:
            /* code */
            decrypt(in,out,keystruct);
            xor_block(out,IVE);
        break;
        
        default:
        return ERROR;
            break;
    }

}