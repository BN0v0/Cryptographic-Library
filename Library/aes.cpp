#include <aes.h>
#include <aes_operations.cpp>
#include <Arduino.h>


void AES::calc_PlainAndPathSize(int p_size){
    int s_of_p = p_size;
      if ( s_of_p % block_numbers == 0){ 
                size = s_of_p;
            }else{
            size = s_of_p +  (block_numbers-(s_of_p % block_numbers));
            }
            pad = size - s_of_p;
}

void AES::padPlaintext(void* in,byte* out)
{
  memcpy(out,in,size);
  for (int i = size-pad; i < size; i++){
    out[i] = arr_pad[pad - 1];
  }
}

/*Key Schedule*/
byte AES::set_key (byte key [], size_t keylen)
    {
        byte hi ;
        switch (keylen)
            {
            case 16:
            case 128:
            keylen = 16; // 10 rounds
            round = 10 ;
            break;
            case 24:
            case 192:
            keylen = 24; // 12 rounds
            round = 12 ;
            break;
            case 32:
            case 256:
            keylen = 32; // 14 rounds
            round = 14 ;
            break;
            default:
            round = 0;
            return FAILURE;
            }
        hi = (round + 1) << 4 ;
        copy_n_bytes (key_sched, key, keylen) ;
        byte t[4] ;
        byte next = keylen ;
        for (byte cc = keylen, rc = 1 ; cc < hi ; cc += column_numbers)
            {
            for (byte i = 0 ; i < column_numbers ; i++)
                t[i] = key_sched [cc-4+i] ;
            if (cc == next)
                {
                next += keylen ;
                byte ttt = t[0] ;
                t[0] = s_box (t[1]) ^ rc ;
                t[1] = s_box (t[2]) ;
                t[2] = s_box (t[3]) ;
                t[3] = s_box (ttt) ;
                rc = f2 (rc) ;
                }
            else if (keylen == 32 && (cc & 31) == 16)
                {
                for (byte i = 0 ; i < 4 ; i++)
                    t[i] = s_box (t[i]) ;
                }
            byte tt = cc - keylen ;
            for (byte i = 0 ; i < column_numbers ; i++)
                key_sched [cc + i] = key_sched [tt + i] ^ t[i] ;
            }
        return SUCCESS ;
    }

/* Cleanning */
void AES::clean ()
{
  for (byte i = 0 ; i < key_schedule_bytes ; i++)
    key_sched [i] = 0 ;
  round = 0 ;
}

/* Copying bytes */
void AES::copy_n_bytes (byte * d, byte * s, byte nn)
{
  while (nn >= 4)
    {
      *d++ = *s++ ;  // some unrolling
      *d++ = *s++ ;
      *d++ = *s++ ;
      *d++ = *s++ ;
      nn -= 4 ;
    }
  while (nn--)
    *d++ = *s++ ;
}

/* Size Operations */
/* Get Size */
int AES::get_size(){
  return size;
}
/*  Set Size */
void AES::set_size(int sizel){
  size = sizel;
}



/* AES Encryption */
//Encryption Operation
bool AES::encrypt(byte plain [block_numbers], byte cipher [block_numbers]){
  if (round)
    {
      byte s1 [block_numbers], r ;
      copy_and_key (s1, plain, (byte*) (key_sched)) ;

      for (r = 1 ; r < round ; r++)
        {
          byte s2 [block_numbers] ;
          mix_sub_columns (s2, s1) ;
          copy_and_key (s1, s2, (byte*) (key_sched + r * block_numbers)) ;
        }
      shift_sub_rows (s1) ;
      copy_and_key (cipher, s1, (byte*) (key_sched + r * block_numbers)) ;
    }
  else
    return FAILURE ;
  return SUCCESS ;
}
//Decryption Operation
bool AES::decrypt (byte plain [block_numbers], byte cipher [block_numbers])
{
  if (round)
    {
      byte s1 [block_numbers] ;
      copy_and_key (s1, plain, (byte*) (key_sched + round * block_numbers)) ;
      inv_shift_sub_rows (s1) ;

      for (byte r = round ; --r ; )
       {
         byte s2 [block_numbers] ;
         copy_and_key (s2, s1, (byte*) (key_sched + r * block_numbers)) ;
         inv_mix_sub_columns (s1, s2) ;
       }
      copy_and_key (cipher, s1, (byte*) (key_sched)) ;
    }
  else
    return FAILURE ;
  return SUCCESS ;
}

bool AES::Encryption(byte *plain,int size_p,byte *cipher,byte *key, int bits, byte* iv){
  calc_PlainAndPathSize(size_p);
  byte plain_p[get_size()];
  padPlaintext(plain,plain_p);
  int blocks = get_size() / block_numbers;
  set_key (key, bits) ;
  
  
  while (blocks--)
    {
      xor_block (iv, plain) ;
      if (encrypt(iv, iv) != SUCCESS)
        return FAILURE ;
      copy_n_bytes(cipher, iv, block_numbers) ;
      plain  += block_numbers ;
      cipher += block_numbers ;
    }
  return SUCCESS ;
}

bool AES::Decryption(byte *cipher,int size_c,byte *plain,byte *key, int bits, byte* iv){
    set_size(size_c);
    int blocks = size_c / block_numbers;
    set_key (key, bits);
    
     while (blocks--)
    {
      byte tmp [block_numbers] ;
      copy_n_bytes (tmp, cipher, block_numbers) ;
      if (decrypt (cipher, plain) != SUCCESS)
        return FAILURE ;
      xor_block (plain, iv) ;
      copy_n_bytes (iv, tmp, block_numbers) ;
      plain  += block_numbers ;
      cipher += block_numbers;
    }
    return SUCCESS ;
   
}


/* Public Functions */

void AES::Initialize(int mode ,byte* user_key , int key_size, byte* user_iv){
         
        byte defaultIV[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        Mode =mode;
        Key=user_key;
        KeySize = key_size;
        
        if(Mode == CBC){
          IVE = user_iv;
          IVD = user_iv;
          memcpy(iv_ecb_enc,defaultIV,16);
          memcpy(iv_ecb_dec,defaultIV,16);
          memcpy(iv_cbc_enc,defaultIV,16);
          memcpy(iv_cbc_dec,defaultIV,16);
          memcpy(iv_cbc_enc,&user_iv,16);
          memcpy(iv_cbc_dec,&user_iv,16);
       
           
        }else if(Mode == ECB){
       
          memcpy(iv_ecb_enc,defaultIV,16);
          memcpy(iv_ecb_dec,defaultIV,16);
        }
}

int AES::Encryption(byte* output, byte* input){
      bool result;
  switch (Mode)
  {
    case ECB:
        result = Encryption(input,16,output,Key,KeySize,iv_ecb_enc);
        return result;
      break;
    case CBC: 
        xor_block(input,IVE);
        result = Encryption(input,16,output,Key,KeySize,iv_ecb_enc);
        return result;
      break;
    
    default:
        return ERROR;
      break;
  }

}



int AES::Decryption(byte* output, byte* input){
  bool result;
  
 switch (Mode)
  {
  case ECB:
      result =Decryption(input,16,output,Key,KeySize,iv_ecb_dec);
      return result;
    break;
  
  case CBC:
  
      result = Decryption(input,16,output,Key,KeySize,iv_ecb_dec);
      xor_block(output,IVD);
      return result;
    break; 
  
  default:
    return ERROR;
    break;
  }

}


