#ifndef RSA_H   
#define RSA_H

#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include "../InfInt/InfInt.h"


using namespace std;


// Conversion functions
InfInt exp(InfInt base, InfInt exp);                                    // Calculate power of a large interger

// Other functions for RSA
InfInt gcd(InfInt a, InfInt b);                                         // Find greatest common divisor of two numbers (GCD) 
InfInt modular_exponentiation(InfInt base, InfInt exp, InfInt modulo);  // Modular exponentiation using Square and Multiply algorithm
bool miller_primality(InfInt n, int k);                                 // Prime check using Miller–Rabin algorithm
InfInt generate_number(int bitsize);                                    // Random number generator given bitsize
InfInt generate_prime_number(int bitsize);                              // Random prime number generator given bitsize
InfInt rsa(int bitsize);                                                // Perform RSA




InfInt rsa(int bitsize){

    // Generate p and q
    InfInt p = generate_prime_number(bitsize);
    InfInt q = generate_prime_number(bitsize);
    //InfInt p = "101";
    //InfInt q = "347";



    // Calculate n - product of p and q
    InfInt n = p*q;

    // Calculate phi
    InfInt phi = (p-1)*(q-1);

    // Generate random e (1 < e < phi) such that gcd(e,phi) = 1
    srand((int)time(0));
    InfInt e = ((InfInt)rand() % (phi)) + 1;
    while (gcd(e,phi) != 1){
        e = ((InfInt)rand() % (phi)) + 1;
    }



    // Generate d (1 < d < phi) such that e*d = 1 (mod phi)
    InfInt d = ((InfInt)rand() % (phi)) + 1;
    while ((e*d)%phi != 1){
        d = ((InfInt)rand() % (phi)) + 1;
    }
    

    cout << "p is " << p << "\n";
    cout << "q is " << q << "\n";
    cout << "n is " << n << "\n";
    cout << "phi is " << phi << "\n";
    cout << "e is " << e << "\n";
    cout << "d (private) is " << d << "\n";
    
    // Generate random session_key
    //InfInt session_key = generate_number(56);       // session_key = plaintext
    //InfInt session_key = 12;
    InfInt session_key = generate_number(10);       // session_key = plaintext

        



    // Encrypt the session key 
    InfInt m_e = exp(session_key,e);
    InfInt ciphertext = modular_exponentiation(m_e, 1, n);

    
    // Decrypt the session key
    InfInt ciphertext_d = exp(ciphertext,d);
    InfInt plaintext = modular_exponentiation(ciphertext_d, 1, n);


    cout << "\nCiphertext is " << ciphertext << "\n";
    cout << "Plaintext is " << plaintext << "\n";
    cout << "Session key (m) is " << session_key << "\n";


    return session_key;

}




#endif