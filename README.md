# Cryptographic Library 

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

Working on Arduino and WEMOS/ESP.

This library was developed in the Platform IO, therefore there is -> #include <Arduino.h>.

### Copyright 2020 Bruno Novo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
