#include <des.h>
#include <des_operations.cpp>
 

/*Key Scheduling */
void DES::setKey(byte* user_key){
    
    if(Algorithm == des){
        for (size_t i = 0; i < 8; i++)
            {
                /* code */
                key.one[i] = user_key[i];
            }
    }else if(Algorithm == t_des){
        for (size_t i = 0; i < 8; i++)
        {
            key.one[i] = user_key[i];
            key.two[i] = user_key[i+8];
            key.three[i] = user_key[i+16];
        }    
    }
  
}




/*  Key Operations */
//Shift Key 
void DES::shiftkey(byte* key){
    byte k[7];
    memcpy(k,key,7);
    permute((byte*)shiftkey_permtab,k,key);
}

// Inverse Shift Key
void DES::shiftkey_inv(byte* key){
    byte k[7];
    memcpy(k,key,7);
    permute((byte*)shiftkeyinv_permtab,k,key);
}

/*DES permutation*/
void DES::permute(const byte *ptable, const byte *in, byte *out){
        uint8_t ob; /* in-bytes and out-bytes */
        uint8_t byte, bit; /* counter for bit and byte */
        ob = pgm_read_byte(&ptable[1]);
        ptable = &(ptable[2]);
        for(byte=0; byte<ob; ++byte){
                uint8_t x,t=0;
                for(bit=0; bit<8; ++bit){
                        x = pgm_read_byte(ptable++) -1 ;
                                t <<= 1;
                        if((in[x/8]) & (0x80>>(x%8)) ){
                                t|=0x01;
                        }
                }
                out[byte]=t;
        }
}


/*Change Endian*/
void DES::changeendian32(uint32_t * a){
        *a = (*a & 0x000000FF) << 24 |
                 (*a & 0x0000FF00) <<  8 |
                 (*a & 0x00FF0000) >>  8 |
                 (*a & 0xFF000000) >> 24;
}
/* Split bit words */ 
uint64_t DES::splitin6bitwords(uint64_t a){
        uint64_t ret=0;
        a &= 0x0000ffffffffffffLL;
        permute((uint8_t*)splitin6bitword_permtab, (uint8_t*)&a, (uint8_t*)&ret);       
        return ret;
}
// Substitution Operations
uint8_t DES::substitute(uint8_t a, uint8_t * sbp){
        uint8_t x;      
        x = pgm_read_byte(&sbp[a>>1]);
        x = (a&1)?x&0x0F:x>>4;
        return x;
        
}

//DES F
uint32_t DES::des_f(uint32_t r, uint8_t* kr){
        uint8_t i;
        uint32_t t=0,ret;
        uint64_t data;
        uint8_t *sbp; /* sboxpointer */ 
        permute((uint8_t*)e_permtab, (uint8_t*)&r, (uint8_t*)&data);
        for(i=0; i<7; ++i)
                ((uint8_t*)&data)[i] ^= kr[i];
        
        /* Sbox substitution */
        data = splitin6bitwords(data);
        sbp=(uint8_t*)sbox;
        for(i=0; i<8; ++i){
                uint8_t x;
                x = substitute(((uint8_t*)&data)[i], sbp);
                t <<= 4;
                t |= x;
                sbp += 32;
        }
        changeendian32(&t);
                
        permute((uint8_t*)p_permtab,(uint8_t*)&t, (uint8_t*)&ret);

        return ret;
}



/* Encryption and Decryption Operations */ 

/* DES Encryption Operation*/
void DES::encrypt(void* out, const void* in, byte* key){
        uint8_t kr[6],k[7];
        uint8_t i;
        union {
                uint8_t v8[8];
                uint32_t v32[2];
        } data;
        
        permute((uint8_t*)ip_permtab, (uint8_t*)in, data.v8);
        permute((uint8_t*)pc1_permtab, (const uint8_t*)key, k);
        for(i=0; i<8; ++i){
                shiftkey(k);
                if(rottable&((1<<((i<<1)+0))) )
                        shiftkey(k);
                permute((uint8_t*)pc2_permtab, k, kr);
                L ^= des_f(R, kr);
                
                shiftkey(k);
                if(rottable&((1<<((i<<1)+1))) )
                        shiftkey(k);
                permute((uint8_t*)pc2_permtab, k, kr);
                R ^= des_f(L, kr);

        }
        /* L <-> R*/
        R ^= L;
        L ^= R;
        R ^= L;
        permute((uint8_t*)inv_ip_permtab, data.v8, (uint8_t*)out);
}

/* DES Decryption Operation */
void DES::decrypt(void* out, const void* in, byte* key){
        uint8_t kr[6],k[7];
        union {
                uint8_t v8[8];
                uint32_t v32[2];
        } data;
        int8_t i;
        permute((uint8_t*)ip_permtab, (uint8_t*)in, data.v8);
        permute((uint8_t*)pc1_permtab, (const uint8_t*)key, k);
        for(i=7; i>=0; --i){
                
                permute((uint8_t*)pc2_permtab, k, kr);
                L ^= des_f(R, kr);
                shiftkey_inv(k);
                if(rottable&((1<<((i<<1)+1))) ){
                        shiftkey_inv(k);
                }

                permute((uint8_t*)pc2_permtab, k, kr);
                R ^= des_f(L, kr);
                shiftkey_inv(k);
                if(rottable&((1<<((i<<1)+0))) ){
                        shiftkey_inv(k);
                }

        }
        /* L <-> R*/
        R ^= L;
        L ^= R;
        R ^= L;
        permute((uint8_t*)inv_ip_permtab, data.v8, (uint8_t*)out);
}


/* Triple DES Encryption Operation */
void DES::tripleEncrypt(byte* out, byte* in, Key key){
  
        encrypt(out,  in, key.one);
        decrypt(out, out, key.two);
        encrypt(out, out, key.three);
       
}
/* Triple DES Decryption Operation */
void DES::tripleDecrypt(byte* out, byte* in, Key key){
        decrypt(out,  in, key.three);
        encrypt(out, out, key.two);
        decrypt(out, out, key.one);
}


/* Public Functions */

void DES::Initialize(int algorithm, int mode ,byte* user_key, byte* user_iv){
        byte defaultIV[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        Algorithm = algorithm;
        Mode =mode;
        
         setKey(user_key);

        if(Mode == CBC){
          IVE = user_iv;
          IVD = user_iv;
          memcpy(iv_cbc_enc,&user_iv,8);
          memcpy(iv_cbc_dec,&user_iv,8);
        }
}

int DES::Encryption(byte* output, byte* input){

    if(Algorithm == des){
        switch (Mode)
        {
        case ECB:
            /* code */
            encrypt(output,input, key.one);
            break;
        
        case CBC:
            xor_block(input,IVE);
            encrypt(output,input, key.one);
            break;

        default:

            return ERROR;
            break;
        }
        

    }else if(Algorithm == t_des){
        switch (Mode)
                {
                case ECB:
                    /* code */
                    tripleEncrypt(output,input,key);
                    break;
                
                case CBC:
                    xor_block(input,IVE);
                    tripleEncrypt(output,input,key);
                    break;

                default:

                    return ERROR;
                    break;
                }
    }else{
        return ERROR;
    }

}

int DES::Decryption(byte* output, byte* input){

    if(Algorithm == des){
        switch (Mode)
        {
        case ECB:
            /* code */
            decrypt(output,input, key.one);
            break;
        
        case CBC:
            decrypt(output,input, key.one);
            xor_block(output,IVD);
            
            break;

        default:

            return ERROR;
            break;
        }
        

    }else if(Algorithm == t_des){
        switch (Mode)
                {
                case ECB:
                    /* code */
                    tripleDecrypt(output,input,key);
                    break;
                
                case CBC:
                    tripleDecrypt(output,input,key);
                    xor_block(output,IVD);
                    break;

                default:

                    return ERROR;
                    break;
                }
    }else{
        return ERROR;
    }

}
