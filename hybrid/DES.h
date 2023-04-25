#ifndef DES_H    
#define DES_H

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


// Other Functions for DES
string permute(string block, int table, int n);                         // Permutation generator
string shift_left(string block, int n);                                 // Shift n bits to the left
string shift_right(string block, int n);                                // Shift n bits to the right
string xor_func(string x, string y);                                    // XOR function
void generate_key_encrypt(string session_key);                          // Generate a list of subkeys (encryption)
void generate_key_decrypt(InfInt session_key);                          // Generate a list of subkeys (decryption)
string des(string plain_text, string key_list[], string enc_or_dec);    // Perform DES (return ciphertext/plaintext)


// Permutation tables
int ip[64] = {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
            };

int pc1[56] = {
                57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
            };

int pc2[48] = {
                14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
            };

int expand[48] = {
                    32, 1, 2, 3, 4, 5, 4, 5,
                    6, 7, 8, 9, 8, 9, 10, 11,
                    12, 13, 12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21, 20, 21,
                    22, 23, 24, 25, 24, 25, 26, 27,
                    28, 29, 28, 29, 30, 31, 32, 1
            };
int perm[32] = {
                    16,  7, 20, 21,
                    29, 12, 28, 17,
                    1, 15, 23, 26,
                    5, 18, 31, 10,
                    2,  8, 24, 14,
                    32, 27,  3,  9,
                    19, 13, 30,  6,
                    22, 11,  4, 25
	};

int fp[64] = {
                40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25
            };

// S-box
int s_box[8][4][16] = {
                    {
                        14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,
                        9,  0,  7,  0, 15, 7,  4,  14, 2,  13, 1,  10, 6,
                        12, 11, 9,  5, 3,  8,  4,  1,  14, 8,  13, 6,  2,
                        11, 15, 12, 9, 7,  3,  10, 5,  0,  15, 12, 8,  2,
                        4,  9,  1,  7, 5,  11, 3,  14, 10, 0,  6,  13 
                    },
                    { 
                        15, 1,  8,  14, 6,  11, 3, 4,  9,  7,  2,  13, 12,
                        0,  5,  10, 3,  13, 4,  7, 15, 2,  8,  14, 12, 0,
                        1,  10, 6,  9,  11, 5,  0, 14, 7,  11, 10, 4,  13,
                        1,  5,  8,  12, 6,  9,  3, 2,  15, 13, 8,  10, 1,
                        3,  15, 4,  2,  11, 6,  7, 12, 0,  5,  14, 9 
                    },

                    { 
                        10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12,
                        7,  11, 4,  2,  8,  13, 7,  0,  9,  3,  4,
                        6,  10, 2,  8,  5,  14, 12, 11, 15, 1,  13,
                        6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12,
                        5,  10, 14, 7,  1,  10, 13, 0,  6,  9,  8,
                        7,  4,  15, 14, 3,  11, 5,  2,  12 
                    },
                    { 
                        7,  13, 14, 3,  0,  6,  9,  10, 1,  2, 8,  5,  11,
                        12, 4,  15, 13, 8,  11, 5,  6,  15, 0, 3,  4,  7,
                        2,  12, 1,  10, 14, 9,  10, 6,  9,  0, 12, 11, 7,
                        13, 15, 1,  3,  14, 5,  2,  8,  4,  3, 15, 0,  6,
                        10, 1,  13, 8,  9,  4,  5,  11, 12, 7, 2,  14 
                    },
                    { 
                        2,  12, 4, 1,  7,  10, 11, 6, 8,  5,  3,  15, 13,
                        0,  14, 9, 14, 11, 2,  12, 4, 7,  13, 1,  5,  0,
                        15, 10, 3, 9,  8,  6,  4,  2, 1,  11, 10, 13, 7,
                        8,  15, 9, 12, 5,  6,  3,  0, 14, 11, 8,  12, 7,
                        1,  14, 2, 13, 6,  15, 0,  9, 10, 4,  5,  3 
                    },
                    { 
                        12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3, 4, 14,
                        7,  5,  11, 10, 15, 4,  2,  7,  12, 9,  5, 6, 1,
                        13, 14, 0,  11, 3,  8,  9,  14, 15, 5,  2, 8, 12,
                        3,  7,  0,  4,  10, 1,  13, 11, 6,  4,  3, 2, 12,
                        9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8, 13 
                    },
                    { 
                        4,  11, 2,  14, 15, 0,  8, 13, 3,  12, 9,  7,  5,
                        10, 6,  1,  13, 0,  11, 7, 4,  9,  1,  10, 14, 3,
                        5,  12, 2,  15, 8,  6,  1, 4,  11, 13, 12, 3,  7,
                        14, 10, 15, 6,  8,  0,  5, 9,  2,  6,  11, 13, 8,
                        1,  4,  10, 7,  9,  5,  0, 15, 14, 2,  3,  12 
                    },
                    { 
                        13, 2,  8, 4,  6,  15, 11, 1,  10, 9, 3, 14, 5,
                        0,  12, 7, 1,  15, 13, 8,  10, 3,  7, 4, 12, 5,
                        6,  11, 0, 14, 9,  2,  7,  11, 4,  1, 9, 12, 14,
                        2,  0,  6, 10, 13, 15, 3,  5,  8,  2, 1, 14, 7,
                        4,  10, 8, 13, 15, 12, 9,  0,  3,  5, 6, 11 
                    }
                };

// Conversion Functions 

// Decimal to Binary
string decimal2binary(InfInt decimal){
    string binary = "";
    while (decimal != 0){
        if (decimal % 2 == 0){
            binary = '0' + binary;
        }else{
            binary = '1' + binary;
        }
        decimal = decimal/2;
    }
    while(binary.length() < 4){
		binary = "0" + binary;
	}
    return binary;
}

// Binary to Decimal
InfInt binary2decimal(string binary){
    InfInt decimal = 0;
    int count = 0;
    int binary_length = binary.length();
    // Iterate through the binary array 
    for (int i = binary_length - 1; i >= 0; i--){
        if (binary[i] == '1'){
            decimal = decimal + exp(2,count);
        }
        count = count + 1;
    }
    return decimal;
}

// Text to Binary
string text2binary(string text) {
    string binary = "";
    // Limit in 8 bits
    for(int i = 0; i < text.length(); i++){
        binary = binary + bitset<8>(text[i]).to_string();
    }
    return binary;
}

// Binary to Text
string binary2text(string binary){
    //Converts binary string to ASCII text using Bitset
    bitset<8> bits;
    string text;
    for (int i = 0; i < binary.length(); i = i + 8){
        bits = bitset<8>(binary.substr(i, 8));
        char c = char(bits.to_ulong());
        text = text + c;
    }
    return text;
}

// Others Functions for DES

// Calculate power of a large interger
InfInt exp(InfInt base, InfInt exp){
    InfInt result = 1;
    for (InfInt i = 0; i < exp; i++){
        result = result*base;
    }
    return result;
}

// Permutation generator
string permute(string block, int table[], int n){
    string permutation = "";
    for (int i = 0; i < n; i++){
        permutation = permutation + block[table[i] - 1];
    }
    return permutation;
}

// Shift bits to the left n time
string shift_left(string block, int n){
    string string_to_be_moved = block.substr(0,n);
    string final_str = block.substr(n,block.length()-1) + string_to_be_moved;
    return final_str;
}

// Shift bits to the right n time
string shift_right(string block, int n){
    string string_to_be_moved = block.substr(block.length()-n,n);
    string final_str = string_to_be_moved + block.substr(0,block.length()-n);
    return final_str;
}

// XOR function
string xor_func(string x, string y){
    string result = "";
    for(int i =0; i < x.length(); i++){
        if(x[i] == y[i]){
            result = result + "0";
        }else{
            result = result + "1";
        }
    }
    return result;
}

// Generate a list of subkeys
string subkeys_list[16] = {};
void generate_key_encrypt(InfInt session_key){
    // Convert session key from decimal to binary
    string binary_session_key = decimal2binary(session_key);

    // Zero padding
    int padding = 64 - (binary_session_key.length() % 64);
    if(padding < 64){
        binary_session_key = binary_session_key + string(padding, '0');
    }else if (padding > 64){
        cout << "Key must be in 64 bits" << endl;
    }

    string key_permute = "";
    // Compress to 56 bits - PC-1
    for (int i = 0; i < 56; i++){
        key_permute = key_permute + binary_session_key[pc1[i]-1]; 
    }

    // Split the block into 28
    string left_key = key_permute.substr(0,28);
    string right_key = key_permute.substr(28,28);

    // Create list of subkeys
    for (int j = 0; j < 16; j++){
        
        if (j == 0 || j == 1 || j == 8 || j == 15){
            left_key = shift_left(left_key, 1); // Rotate 1 bit to the left (0,1,8,15). Otherwise, rotate 2 bit to the left
            right_key = shift_left(right_key, 1); 
        }else{
            left_key = shift_left(left_key, 2); // Rotate 1 bit to the left (0,1,8,15). Otherwise, rotate 2 bit to the left
            right_key = shift_left(right_key, 2); 
        }
        string combined_key = left_key + right_key; // Combine left and right
        //cout << "Combined key: " << combined_key << "\n";
        
        // Compress to 48 bits
        string key_permute_48 = "";
        for (int k = 0; k < 48; k++){
            key_permute_48 = key_permute_48 + combined_key[pc2[k] - 1];
        }
        subkeys_list[j] = key_permute_48;
        //cout << "Round " << j << ": " << key_permute_48 << endl;
    }

}

// Generate keys for decryption
void generate_key_decrypt(InfInt session_key){
    // Convert session key from decimal to binary
    string binary_session_key = decimal2binary(session_key);

    // Zero padding
    int padding = 64 - (binary_session_key.length() % 64);
    if(padding < 64){
        binary_session_key = binary_session_key + string(padding, '0');
    }else if (padding > 64){
        cout << "Key must be in 64 bits" << endl;
    }

    string key_permute = "";
    // Compress to 56 bits - PC-1
    for (int i = 0; i < 56; i++){
        key_permute = key_permute + binary_session_key[pc1[i]-1]; 
    }

    // Split the block into 28
    string left_key = key_permute.substr(0,28);
    string right_key = key_permute.substr(28,28);

    // No rotation for first round
    string combined_key = left_key + right_key; // Combine left and right

    // Compress to 48 bits
    string key_permute_48 = "";
    for (int k = 0; k < 48; k++){
        key_permute_48 = key_permute_48 + combined_key[pc2[k] - 1];
    }
    subkeys_list[0] = key_permute_48;

    // Create list of subkeys
    for (int j = 1; j < 16; j++){
        if (j == 1 || j == 8 || j == 15){
            left_key = shift_right(left_key, 1); // Rotate 1 bit to the left (0,1,8,15). Otherwise, rotate 2 bit to the left
            right_key = shift_right(right_key, 1); 
        }else{
            left_key = shift_right(left_key, 2); // Rotate 1 bit to the left (0,1,8,15). Otherwise, rotate 2 bit to the left
            right_key = shift_right(right_key, 2); 
        }
        combined_key = left_key + right_key; // Combine left and right
        //cout << "Combined key: " << combined_key << "\n";

        key_permute_48 = ""; // clear the string
        // Compress to 48 bits
        for (int k = 0; k < 48; k++){
            key_permute_48 = key_permute_48 + combined_key[pc2[k] - 1];
        }
        subkeys_list[j] = key_permute_48;
        //cout << "Round " << j << ": " << key_permute_48 << endl;
    }

}

// Perform DES (return ciphertext/plaintext)
string des(string plain_text, string key_list[], string enc_or_dec){
    // Convert text to binary
    string binary = text2binary(plain_text);
    string cipher_text = "";
    //cout << "Length of original string: " << binary.length() << endl;

    // Zero Padding
    int padding = 64 - (binary.length() % 64);
    if(padding != 64){
        binary = binary + string(padding, '0');
    }
    //cout << "Text2binary after padding: " << binary << endl;
    //cout << "Number of zero needed: " << padding << endl;
    //cout << "Number of final string: " << binary.length() << endl;

    // Initialize block count for message
    int block_count = 0;

    // Divide by 64 bit block
    for (int i = 0; i < binary.length(); i = i + 64){

        // Take 64 bits block
        string block = binary.substr(i,64);

        // Permute 
        string block_permuted = permute(block, ip, 64);

        // Split the block into half
        string left = block_permuted.substr(0, 32);
        string right = block_permuted.substr(32, 32);
        //cout << "Block: " << block << endl;
        string temp = "";

        // Iterate 16 subkeys
        for (int j = 0; j < 16; j++){
            temp = right; 
            string output_f = "";
            string right_expanded = permute(right, expand, 48);     // Expand 32bits to 48bits
            string xor_48 = xor_func(right_expanded, key_list[j]);  // Using XOR function 
            
            // Iterate through sboxes
            for (int k = 0; k < 8; k++){
                string rowStr = xor_48.substr(k*6,1) + xor_48.substr(k*6 +5,1);     // Get first and last bit 
                string colStr = xor_48.substr(k*6 + 1,1) + xor_48.substr(k*6 + 2,1) + xor_48.substr(k*6 + 3,1) + xor_48.substr(k*6 + 4,1);  // Get elements between the first and last
                InfInt dec_row = binary2decimal(rowStr);        // Convert binary to decimal to find index
                InfInt dec_col = binary2decimal(colStr);        // Convert binary to decimal to find index
                //cout << "k: " << k << " -- " << "col:  " << dec_col << " -- "<< "row: " << dec_row << endl;
                
                InfInt s_box_dec = s_box[k][dec_row.toInt()][dec_col.toInt()];
                output_f = output_f + decimal2binary(s_box_dec);
                //cout << "Output f: " << output_f <<endl;
                //cout << " s_box_dec: " << s_box_dec << endl;
            }

            // Compress to 32 bits
            output_f = permute(output_f, perm, 32);

            // XOR left and f function and Swapping
            right = xor_func(left, output_f);
            left = temp;
        }
        // Combine right and left
        string combine_block = right + left;

        // Final permutation
        cipher_text = cipher_text + permute(combine_block, fp, 64);
        block_count = block_count + 1;
        //cout << "Block " << block_count << ": " << permute(combine_block, fp, 64) << endl;
    }

    cout << "Ciphertext in decimal: " << binary2decimal(cipher_text) << endl;
    
    if (enc_or_dec == "enc"){
        //cout << "Ciphertext in text: " << binary2text(cipher_text);
        return binary2text(cipher_text);
    }else{
       // cout << "Original text: " << binary2text(cipher_text);
        return binary2text(cipher_text);
    }
}


#endif