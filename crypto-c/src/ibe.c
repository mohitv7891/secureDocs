#include "ibe.h"
#include "bls_ibe_util.h" // For hash_id_to_G1 if needed, and error handling
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h> // For htonl
// #include <string.h> // Already included via ibe.h or bls_ibe_util.h

// DeriveKey function remains the same as provided in the question
void DeriveKey(const unsigned char *g_bytes, int g_len, int derived_key_len, unsigned char *derived_key) {
    int hash_size = SHA256_DIGEST_LENGTH;
    int generated = 0;
    unsigned int counter = 0;
    unsigned char hash_output[hash_size];
    unsigned char *input_buffer = malloc(g_len + sizeof(counter));
    if (!input_buffer) DIE("Memory allocation failed in DeriveKey");

    while (generated < derived_key_len) {
        memcpy(input_buffer, g_bytes, g_len);
        // Ensure portable counter encoding (e.g., network byte order if needed, but simple memcpy might be ok here)
        uint32_t counter_net = htonl(counter); // Use network byte order for portability
        memcpy(input_buffer + g_len, &counter_net, sizeof(counter_net));

        SHA256(input_buffer, g_len + sizeof(counter_net), hash_output);
        int copy_size = (generated + hash_size > derived_key_len) ? (derived_key_len - generated) : hash_size;
        memcpy(derived_key + generated, hash_output, copy_size);
        generated += copy_size;
        counter++;
    }
    free(input_buffer);
}


// Encrypt: Matches g, P_pub=g^msk
void Encrypt(pairing_t pairing, element_t g_gen, element_t P_pub, const char *id,
             const unsigned char *message, size_t message_len,
             element_t U, unsigned char *V) { // g_gen to avoid conflict with GT element g below
    element_t Q, r, g_T; // Use g_T for the GT element

    // Hash identity into Q (member of G1)
    hash_id_to_G1(Q, id, pairing); // Use helper

    element_init_Zr(r, pairing);
    element_random(r);

    // U = g_gen^r (ephemeral value)
    element_init_G1(U, pairing);
    element_pow_zn(U, g_gen, r); // Use pow_zn for g^r

    // Compute shared secret: g_T = e(Q, P_pub)^r in GT
    element_init_GT(g_T, pairing);
    pairing_apply(g_T, Q, P_pub, pairing); // g_T = e(Q, P_pub)
    element_pow_zn(g_T, g_T, r);          // g_T = g_T^r

    // Convert shared secret to bytes
    int g_T_len = element_length_in_bytes(g_T);
    unsigned char *g_T_bytes = malloc(g_T_len);
    if (!g_T_bytes) DIE("malloc failed for g_T bytes");
    element_to_bytes(g_T_bytes, g_T);

    // Derive a full-length mask (same length as message) from g_T_bytes
    unsigned char *mask = malloc(message_len);
    if (!mask) { free(g_T_bytes); DIE("malloc failed for mask"); }
    DeriveKey(g_T_bytes, g_T_len, message_len, mask);
    free(g_T_bytes);

    // XOR the message with the mask to form ciphertext V
    for (size_t i = 0; i < message_len; i++) {
        V[i] = message[i] ^ mask[i];
    }
    free(mask);

    element_clear(Q);
    element_clear(r);
    element_clear(g_T);
}

// Decrypt: Matches d=Q^msk, U=g^r
void Decrypt(pairing_t pairing, element_t d, element_t U,
             const unsigned char *V, size_t message_len,
             unsigned char *decrypted_message) {
    element_t g_T; // Use g_T for the GT element

    // Recompute shared secret: g_T = e(U, d) = e(g^r, Q^msk)
    element_init_GT(g_T, pairing);
    pairing_apply(g_T, U, d, pairing);

    // Convert shared secret to bytes
    int g_T_len = element_length_in_bytes(g_T);
    unsigned char *g_T_bytes = malloc(g_T_len);
    if (!g_T_bytes) DIE("malloc failed for g_T bytes in Decrypt");
    element_to_bytes(g_T_bytes, g_T);

    // Derive the same mask
    unsigned char *mask = malloc(message_len);
    if (!mask) { free(g_T_bytes); DIE("malloc failed for mask in Decrypt"); }
    DeriveKey(g_T_bytes, g_T_len, message_len, mask);
    free(g_T_bytes);

    // XOR the ciphertext V with the mask to recover the message
    for (size_t i = 0; i < message_len; i++) {
        decrypted_message[i] = V[i] ^ mask[i];
    }
    free(mask);
    element_clear(g_T);
}
