# Implementation of a hybrid cryptographic scheme using El Gamal and DES

Hybrid Encryption combines the efficiency of symmetric encryption with the convenience of asymmetric encryption. 

## Source files

```c++

├── InfInt              # Arbitrary-Precision Integer Arithmetic Library
├── hybrid              # Containing algorithm files (DES, RSA, and ElGamal)
│   ├── DES.h           # Data Encryption System (DES)
│   ├── ElGamal.h       # El Gamal
|   ├── RSA.h           # RSA (only works for smaller bit size) 
│   ├── main.cpp        # Run the program
|   └── gui.cpp         # GUI (To run the program, go to the command terminal, run "./get_session_key")
└── README.md           # Document the process

```
## Description 

El Gamal and DES are the two algorithms in this implementation project (RSA is incomplete because it only works for smaller bit size). Here is the process:
- El Gamal/RSA: 
  - Generate public key and private key with a choice of bit size
  - Generate a one-time session key
  - Encrypt and Decrypt the session key
- DES
  - Generate a list of subkeys using the one-time session key as a master key
  - Encrypt and Decrypt the message 

## Functions used

| El Gamal/RSA                                                            | DES            | 
|    :---:                                                                |     :---:      |  
| InfInt gcd(InfInt a, InfInt b);                                         | string permute(string block, int table, int n);    | 
| InfInt modular_exponentiation(InfInt base, InfInt exp, InfInt modulo);  | string shift_left(string block, int n);     | 
| bool miller_primality(InfInt n, int k);                                 | string shift_right(string block, int n);         | 
| InfInt generate_number(int bitsize);                                    | string xor_func(string x, string y);    | 
| InfInt generate_prime_number(int bitsize);                              | void generate_key_encrypt(string session_key);    | 
| InfInt generate_alpha(InfInt p);                                        | void generate_key_decrypt(string session_key);    | 
| InfInt el_gamal(int bitsize);                                           | string des(string plain_text, string key_list[], string enc_or_dec);    | 

Conversion Functions:
- string decimal2binary(InfInt decimal);
- InfInt binary2decimal(string binary);
- string text2binary(string text);
- string binary2text(string binary);

Calculate power of a number (large intergers):
- InfInt exp(InfInt base, InfInt exp);

