/*
Copyright 2020 Bruno Novo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

// Inclusions
#include <Arduino.h>
#include <rsa.h>
//Definitions 
#define Limit 10000 ;

   int RSA::log_power(int n, int p, int mod)
    {
        int result = 1;
        for (; p; p >>= 1)
        {
            if (p & 1)
                result = (1LL * result * n) % mod;
            n = (1LL * n * n) % mod;
        }
        return result;
    }

    // Given an integer x, possibly negative, return an integer
    // in the range 0..m-1 that is congruent to x (mod m)
    int RSA::reduce_mod(int x, int m) {
        int rem = x % m;
        if (rem < 0) {
            rem += m;
        }
        return rem;
    }

/*
Rabin Miller Test is an algorithm wich determines whether a given number is prime
*/
    bool RSA:: rabin_miller(int n)
    {
        bool ok = true;

        for (int i = 1; i <= 5 && ok; i++) {
            int a = rand() + 1;
            int result = log_power(a, n - 1, n);
            ok &= (result == 1);
        }

        return ok;
    }


    int RSA:: gdc_Euclid(int a, int b) {
    while (b > 0) {
        a %= b;

        // now swap them
        int tmp = a;
        a = b;
        b = tmp;
    }
    return a; // b is 0
    }


// Random number generator
int RSA:: GenerateNumber(int bits) {
    int val, random_num = 0;
    // Loop to read from A1, to generate bit and multiply by pow(2,  bit position)
    for (int i = 0; i < bits; ++i) {
        val = random(0,9999999999999999);
        if (val&1) {
          random_num += pow(2, i);
        }
        delay(5);
    }
    random_num += pow(2, bits);
    return random_num;
}

// Key schedule
    //Generate prime number
int RSA:: GeneratePrime(int bits){
    int generated =rand() % Limit;
    while(!rabin_miller(generated)){
        generated = rand()% Limit;
    }
    return generated;
}

int RSA::Generate_e(int phi_n){
    int e;

    while(gdc_Euclid(e,phi_n)!=1){
        e = GenerateNumber(14);
    }

    return e;
}

int RSA:: ExtendedEuclid(int e, int phi_n){
// Find an integer d such that (e*d) == 1 (mod phi_n)
        int q, r[40], s[40], t[40];
        r[0] = e; r[1] = phi_n;
        s[0] = 1; s[1] = 0;
        t[0] = 0; t[1] = 1;
        
        int i = 1;
        while (r[i] > 0) {
            q = r[i-1] / r[i];
            r[i+1] = r[i-1] - q*r[i];
            s[i+1] = s[i-1] - q*s[i];
            t[i+1] = t[i-1] - q*t[i];
            ++i;
        }
        int d = s[i-1];
        
        if (d < 0 || d >= phi_n) {
            d = reduce_mod(d, phi_n);
        }

        return d;
}

// Find a d such that e·d ≡ 1 (mod φ(n)) or declares fail
int RSA::Generate_d(int e, int phi_n){
    
    if(gdc_Euclid(e,phi_n)!=1){
        return FAIL;
    }else{
        int d = ExtendedEuclid (e,phi_n);
        return d;
    }
}

void RSA::KeyGeneration(int &e,int &d,int &n){
    //1º Gerar 2 numeros aleatórios primos
    int p = GeneratePrime(14);
    int q = GeneratePrime(15);

    //calculate n => n = p*q
    n= p*q;

    //calculate Totiente de Euler -> n: phi(n) = (p-1)(q-1)
    int phi_n = (p-1)*(q-1);

    //Calculate e 
    e = Generate_e(phi_n);
    d= Generate_d(e,phi_n);
}

/*
    Compute and return (a*b)%m
    Note: m must be less than 2^31
    Arguments:
        a (int): The first multiplicant
        b (int): The second multiplicant
        m (int): The mod value
    Returns:
        result (uint32_t): (a*b)%m
*/
int RSA:: multMod(int a, int b, int m) {
    int result = 0;
    int dblVal = a%m;
    int newB = b;

    // This is the result of working through the worksheet.
    // Notice the extreme similarity with powmod.
    while (newB > 0) {
        if (newB & 1) {
            result = (result + dblVal) % m;
        }
        dblVal = (dblVal << 1) % m;
        newB = (newB >> 1);
    }

    return result;
}

/*
    NOTE: This was modified using our multMod function, but is otherwise the
    function powModFast.
    Compute and return (a to the power of b) mod m.
      Example: powMod(2, 5, 13) should return 6.
*/
int RSA:: powMod(int a, int b, int m) {
    
    int result = 1 % m;
    int sqrVal = a % m;  // stores a^{2^i} values, initially 2^{2^0}
    int newB = b;
    
    // See the lecture notes for a description of why this works.
    while (newB > 0) {
        if (newB & 1) {  // evalutates to true iff i'th bit of b is 1 in the i'th iteration
            result = multMod(result, sqrVal, m);
        }
        sqrVal = multMod(sqrVal, sqrVal, m);
        newB = (newB >> 1);
    }

    return result;
}


/*
    Encrypts using RSA encryption.
    Arguments:
        c (char): The character to be encrypted
        e (int): The partner's public key
        m (int): The partner's modulus
    Return:
        The encrypted character (int)
*/
int RSA:: RSA_encrypt(char c, int e, int m){
    return powMod(c,e,m);
}

 
/*
    Decrypts using RSA encryption.
    Arguments:
        x (int): The communicated integer
        d (int): The Arduino's private key
        n (int): The Arduino's modulus
    Returns:
        The decrypted character (char)
*/
int RSA:: RSA_decrypt(int x,int d, int n){
    return powMod(x,d,n);
}


//Verify Generation key errors IF false -> error
bool RSA:: VerifyKeyGeneration(int e, int d,int n){
    if(e == 1 || d==1 || n==1){
        return false;
    }else{
        return true;
    }
}