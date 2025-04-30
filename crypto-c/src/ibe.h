#ifndef IBE_H
#define IBE_H

#include <pbc/pbc.h>
#include <openssl/sha.h>
#include <string.h> // Add missing include

// Define the length of the symmetric key (SHA-256 output)
#define KEY_LEN 32 // Should match SHA256_DIGEST_LENGTH? Yes.

// Function declarations (Ensure signatures match the actual implementation
// and the intended logic based on g, P_pub=g^msk, d=Q^msk)

// No need for Setup/KeyGen here if using setup.c/keygen.c

// Encrypts a message for a given identity.
// Input: pairing, g (generator), P_pub (g^msk), id (recipient),
//        message, message_len
// Output: U (g^r), V (message XOR KDF(e(H(id), P_pub)^r))
void Encrypt(pairing_t pairing, element_t g, element_t P_pub, const char *id,
             const unsigned char *message, size_t message_len, // Use size_t
             element_t U, unsigned char *V); // V needs allocation outside

// Decrypts a ciphertext using the private key d.
// Input: pairing, d (recipient's private key H(id)^msk), U (from ciphertext),
//        V (from ciphertext), message_len (length of V)
// Output: decrypted_message (buffer provided by caller)
void Decrypt(pairing_t pairing, element_t d, element_t U,
             const unsigned char *V, size_t message_len, // Use size_t
             unsigned char *decrypted_message);

// Derives a key of 'derived_key_len' bytes from g_bytes.
// (Keep this as it seems okay for KDF)
void DeriveKey(const unsigned char *g_bytes, int g_len, int derived_key_len, // Changed arg name
               unsigned char *derived_key);

#endif // IBE_H