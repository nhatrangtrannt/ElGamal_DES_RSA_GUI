#ifndef ELGAMAL_H   
#define ELGAMAL_H

#include <iostream>
#include <string>
#include <bitset>
#include "../InfInt/InfInt.h"

using namespace std;

// Conversion functions
string decimal2binary(InfInt decimal);  // Decimal to Binary
InfInt binary2decimal(string binary);   // Binary to Decimal
string text2binary(string text);        // Text to Binary
string binary2text(string binary);      // Binary to Text
InfInt exp(InfInt base, InfInt exp);    // Calculate power of a large interger


// Other Functions for ELGamal

InfInt gcd(InfInt a, InfInt b);                                         // Find greatest common divisor of two numbers (GCD) 
InfInt modular_exponentiation(InfInt base, InfInt exp, InfInt modulo);  // Modular exponentiation using Square and Multiply algorithm
bool miller_primality(InfInt n, int k);                                 // Prime check using Miller–Rabin algorithm
InfInt generate_number(int bitsize);                                    // Random number generator given bitsize
InfInt generate_prime_number(int bitsize);                              // Random prime number generator given bitsize
InfInt generate_alpha(InfInt p);                                        // Alpha generator (primitive root of p)
InfInt el_gamal(int bitsize);                                           // Perform El Gamal (return session key)


// Conversion functions
// Find greatest common divisor of two numbers (GCD) 
InfInt gcd(InfInt a, InfInt b){
    if (a < b){
        return gcd(b,a);
    }else if (a % b == 0){
        return b;
    }else{
        return gcd(b, a % b);
    }
}

// Modular exponentiation using Square and Multiply algorithm
InfInt modular_exponentiation(InfInt base, InfInt exp, InfInt modulo){
    InfInt result = 1;
    string exp_binary = decimal2binary(exp);
    string exp_binary_reverse = "";
    // Reverse the binary string
    for(int i = exp_binary.length() - 1; i >= 0; i--){
        exp_binary_reverse = exp_binary_reverse + exp_binary[i];
    }
    
    base = base % modulo;
    if (exp == 0){
        return result;
    }
    InfInt A = base;
    if (exp_binary_reverse[0] == '1'){
        result = base;
    }

    for (string::size_type i = 1; i < exp_binary_reverse.length(); i++){
        A = (A*A) % modulo;
        if (exp_binary_reverse[i] == '1'){
            result = (A*result) % modulo;
        }
    }
    return result;
}

// Prime check using Miller–Rabin algorithm
bool miller_primality(InfInt n, int k){
    // Special cases
    if ((n == 2) || (n == 3)){
        return true;
    }
    if ((n <= 1) || (n % 2 == 0)){
        return false;
    }
    // Find r and s
    InfInt s = 0;
    InfInt r = n - 1;
    InfInt a, y;
    // Iterate k times
    for (int i = 0; i < k; i++){
        srand((int)time(0));

        a = ((InfInt)rand() % (n-2)) + 2; // Genrate random number in range (2,n-2)
        y = modular_exponentiation(a, r, n); // Perform modular exponentiation
        if ((y != 1) && (y != n - 1)){
            InfInt j = 1;
            while ((j <= s - 1) && (y != n - 1)){
                y = modular_exponentiation(y, 2, n);
                if (y == 1){
                    return false;
                }
                j = j + 1;
            }
            if (y != n - 1){
                return false;
            }
        }

    }
    return true;
}

// Random number generator given bitsize
InfInt generate_number(int bitsize){
    string stringbinary = "";
    InfInt decimal;
    srand((int)time(0));

    for (int i = 0; i < bitsize; i++ ){
        stringbinary = stringbinary + to_string((rand() % 2));
    }
    // Convert back to decimal
    decimal = binary2decimal(stringbinary);
    return decimal;
}

// Prime random number generator given bitsize
InfInt generate_prime_number(int bitsize){
    InfInt p = generate_number(bitsize);
    // Prime check
    if (miller_primality(p,20) == 0){
        return generate_prime_number(bitsize);
    }else{
        return p;
    }
}

// Alpha generator (primitive root of p)
InfInt generate_alpha(InfInt p){
    InfInt alpha = ((InfInt)rand() % (p)) + 1;
    while ((gcd(alpha,p) != 1) || (miller_primality(alpha,20) == 0)){
        alpha = ((InfInt)rand() % (p)) + 1;
    }
    return alpha;

}

 // Perform El Gamal (return session key)
InfInt el_gamal(int bitsize){
    // Generate random session_key which is plaintext of ElGamal needed to be encrypted
    InfInt session_key = generate_number(56);       // session_key = plaintext

    // Generate p (Public information)
    //InfInt p = "106425110575092743505343838583518627969794251421244929413004096333268351897071"; // hard-coded b/c it takes some time to find p. However, if you want to generate one, there is a function to find prime number.
    InfInt p = generate_prime_number(bitsize);

    // Generate alpha which is a primitive root of p (Public information)
    InfInt alpha = generate_alpha(p);

    // Generate private key in range (1,p-2) (Private information)
    InfInt a = ((InfInt)rand() % (p-2)) + 1;

    // Calculate alpha^a mod p 
    InfInt alpha_a = modular_exponentiation(alpha, a, p);

    // Generate random k to encrypt the message
    InfInt k = ((InfInt)rand() % (p-2)) + 1;

    // Generate gamma (Public information)
    InfInt gamma = modular_exponentiation(alpha, k, p); // gamma = (alpha^a)^k mod p
    
    // Generate (alpha^a)^k mod p
    InfInt alpha_a_k = modular_exponentiation(alpha_a, k, p);

    // Generate delta (Public information)
    InfInt delta = (session_key * alpha_a_k) % p;

    // Decrypt message
    InfInt message = (delta * modular_exponentiation(gamma, p-1-a, p)) % p;

    cout << "\nPublic Information\n";
    cout << "Prime number - p: " << p << "\n";
    cout << "Alpha - α: " << alpha << "\n";
    cout << "Alpha^a - α^a: " << alpha_a << "\n";

    cout << "\nPrivate Information\n";
    cout << "Session key - m: " << session_key << "\n";
    cout << "Private key - a: " << a << "\n";

    cout << "\nCiphertext\n";
    cout << "Gamma - γ: " << gamma << "\n";
    cout << "Delta - δ: " << delta << "\n";

    cout << "\nDecryption:\n";
    cout << "Message after decrypting - m: " << message << "\n";

    return session_key;

}


#endif