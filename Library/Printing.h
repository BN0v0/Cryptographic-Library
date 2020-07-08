 #include <stdio.h>      
 
void PrintArray_byte(uint8_t array[],int LENGTH){
    for(int i = 0; i < LENGTH;i++){
      Serial.print(array[i],HEX);
      Serial.print("  ");
    }
}

