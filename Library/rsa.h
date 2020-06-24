/*
Copyright 2020 Bruno Novo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#ifndef RSA_H
#define RSA_H


class RSA{
    
    private:
    
        int reduce_mod(int x, int m);
        bool rabin_miller(int n);
        int gdc_Euclid(int a, int b);
        int log_power(int n, int p, int mod);
        int GenerateNumber(int bits);
        int GeneratePrime(int bits);
        int Generate_e(int phi_n);
        int Generate_d(int e, int phi_n);
        int ExtendedEuclid(int e, int phi_n);
        int multMod(int a, int b, int m);
        int powMod(int a, int b, int m);

    public:
    
        void KeyGeneration(int &e,int &d,int &n);
        int RSA_encrypt(char c,int d, int n);
        int RSA_decrypt(int x, int e,int m);
        bool VerifyKeyGeneration(int e, int d, int n);
};
#endif