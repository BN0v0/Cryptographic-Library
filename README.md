#Cryptographic Library 

Simple and user friendly C++ library built to embedded systems and IoT devices. This library was primarly idealized to work with resource contrained IoT devices. 

Included Cryptographic Algorithms:
- AES 
- DES 
- 3DES 
- Blowfish
- RSA 

Every Algorithm is composed by two encryption modes: ECB (Electronic CodeBook) and CBC (Cipher-block chaining), except RSA.


Some Examples of how to use the library are in the Examples folder.
Unit Tests in the Tests folder. 


This library was developed in the Platform IO, therefore there is -> #include <Arduino.h>.


#TO-DO

- Rest of Unit Tests
- DES and 3DES working with blocks bigger than 8-bit
- AES CBC mode not working correctly
