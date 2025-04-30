/* === File: bls_ibe_util.h === */
#ifndef BLS_IBE_UTIL_H
#define BLS_IBE_UTIL_H

#include <pbc/pbc.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // Make sure string.h is included

// --- Error Handling ---
// Consider replacing exit(EXIT_FAILURE) with return codes in a real application
// for better error handling within the Wasm module.
#define DIE(msg) \
    do { perror(msg); fprintf(stderr, "Fatal error: %s\n", msg); exit(EXIT_FAILURE); } while (0)

// --- File Operations (Mainly for Native/Server-Side Code or Testing) ---

// Reads the entire content of a file into a buffer.
// Remember to free the returned buffer. Returns NULL on error.
unsigned char* read_file_content(const char *filename, size_t *len);

// Writes data to a file. Exits on failure via DIE().
void write_file_content(const char *filename, const unsigned char *data, size_t len);

// --- PBC Initialization and Loading ---

// Initializes pairing from a parameter file. Exits on failure via DIE().
// For Wasm: Assumes 'param_file' exists in the virtual filesystem (e.g., MEMFS).
void initialize_pairing(pairing_t pairing, const char *param_file);

// Loads public parameters (g, P_pub) from a file. Exits on failure via DIE().
// Primarily for native code/testing.
void load_public_params(pairing_t pairing, element_t g, element_t P_pub, const char *filename);

// Loads master secret key from a file. Exits on failure via DIE().
// SERVER-SIDE ONLY.
void load_master_secret(pairing_t pairing, element_t msk, const char *filename);

// Loads user private key from a file. Exits on failure via DIE().
// Primarily for native code/testing.
void load_user_private_key(pairing_t pairing, element_t user_sk, const char *filename);

// Saves user private key to a file. Exits on failure via DIE().
// SERVER-SIDE ONLY (used by keygen).
void save_user_private_key(element_t user_sk, const char *filename);


// --- Buffer Deserialization Functions (for Wasm Wrappers) ---

// Deserializes public parameters (g, P_pub) from a buffer.
// Assumes buffer contains compressed g followed by compressed P_pub.
// Returns 0 on success, non-zero on error.
int deserialize_public_params_from_buffer(pairing_t pairing, element_t g, element_t P_pub, const unsigned char *param_data, size_t param_len);

// Deserializes a user private key (G1 element, compressed) from a buffer.
// Returns 0 on success, non-zero on error.
int deserialize_private_key_from_buffer(pairing_t pairing, element_t user_sk, const unsigned char *key_data, size_t key_len);

// Deserializes a signature (G1 element, compressed) from a buffer.
// Returns 0 on success, non-zero on error.
int deserialize_signature_from_buffer(pairing_t pairing, element_t sigma, const unsigned char *sig_data, size_t sig_len);

// Deserializes the 'U' part of a ciphertext (G1 element, compressed) from a buffer.
// Returns 0 on success, non-zero on error.
int deserialize_ciphertext_u_from_buffer(pairing_t pairing, element_t U, const unsigned char* u_data, size_t u_len);


// --- Hashing (Used by both Native and Wasm) ---

// Hashes an ID string into an element of G1 using PBC's element_from_hash.
void hash_id_to_G1(element_t Q, const char *id, pairing_t pairing);

// Hashes a message buffer into an element of Zr using SHA256 + PBC's element_from_hash.
void hash_message_to_Zr(element_t h, const unsigned char *msg, size_t msg_len, pairing_t pairing);

#endif // BLS_IBE_UTIL_H
