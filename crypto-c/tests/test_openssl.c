// File: /miniProject/dev/crypto-wasm-test/tests/test_openssl.c

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h> // Include OpenSSL SHA header

int main() {
    // Input string to hash
    const char *input_string = "Hello Wasm Crypto!";
    unsigned char hash[SHA256_DIGEST_LENGTH]; // Buffer for the hash output

    // Calculate SHA256 hash
    SHA256((const unsigned char *)input_string, strlen(input_string), hash);

    // Print the resulting hash in hexadecimal format
    printf("Input String: \"%s\"\n", input_string);
    printf("SHA256 Hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]); // Print each byte as a 2-digit hex number
    }
    printf("\n");

    printf("OpenSSL SHA256 Wasm test: Success!\n");

    return 0;
}
