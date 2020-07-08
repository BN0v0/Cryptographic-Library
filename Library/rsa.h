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