#include <stdlib.h>
#include <stdio.h>
#include <string.h> // For memcpy
#include <pbc/pbc.h>
#include "bls_ibe_util.h" // For utilities including buffer deserializers
#include "ibe.h"          // For IBE Encrypt/Decrypt

// Define the path where pairing parameters are expected in the Wasm virtual filesystem
#define WASM_PARAM_FILE "/a.param"

// --- Helper Function ---
// Initializes pairing for Wasm environment. Returns 0 on success, 1 on error.
// Assumes WASM_PARAM_FILE exists in Emscripten's virtual FS (MEMFS).
static int initialize_wasm_pairing(pairing_t pairing) {
    // Check if the file exists using fopen, as pbc_pairing_init_set_str might not give clear errors
    // if the file content is invalid but *does* exist. We primarily care if it's accessible.
    FILE *fp = fopen(WASM_PARAM_FILE, "rb");
    if (!fp) {
        fprintf(stderr, "Wasm Error: Pairing parameter file '%s' not found or inaccessible in virtual filesystem.\n", WASM_PARAM_FILE);
        return 1; // Indicate error: file not found
    }
    fclose(fp); // Close the file handle, we just needed to check existence.

    // Now, initialize pairing using the file path passed to PBC
    // Note: PBC's internal file reading might still fail if the content is bad,
    // potentially leading to an abort (depending on PBC error handling).
    // initialize_pairing should handle calling pbc_pairing_init_set_str or similar
    initialize_pairing(pairing, WASM_PARAM_FILE);

    // We might not reach here if initialize_pairing uses DIE on error.
    // If initialize_pairing were modified to return errors, we'd check its return value here.
    // A basic check after init:
    if (!pairing_is_symmetric(pairing)) {
         // Or some other check relevant to the expected pairing type
         fprintf(stderr, "Wasm Error: Pairing initialization seems to have failed or produced unexpected type.\n");
         // pairing_clear(pairing); // Maybe clear if failed? Depends on initialize_pairing's state.
         // return 1; // Indicate error
         // For now, assume initialize_pairing handles fatal errors.
    }

    return 0; // Success (assuming initialize_pairing didn't exit)
}


// --- Exported Wasm Functions ---

/**
 * @brief Signs a message using a provided private key.
 *
 * Allocates memory for the signature which must be freed by the caller
 * using wasm_free_buffer().
 *
 * @param private_key_data Buffer containing the compressed private key (G1 element).
 * @param private_key_len Length of the private key buffer.
 * @param message_data Buffer containing the message to sign.
 * @param message_len Length of the message buffer.
 * @param output_sig_len Pointer to a size_t where the length of the returned signature buffer will be written.
 * @return Pointer to the allocated signature buffer (compressed G1 element), or NULL on error.
 */
unsigned char* wasm_sign_buffer(
    const unsigned char* private_key_data, size_t private_key_len,
    const unsigned char* message_data, size_t message_len,
    size_t* output_sig_len
) {
    // Check output pointer
    if (!output_sig_len) {
        fprintf(stderr, "Wasm Sign Error: output_sig_len pointer is NULL.\n");
        return NULL;
    }
    *output_sig_len = 0; // Initialize

    pairing_t pairing;
    element_t d;       // User's private key
    element_t h;       // Hash of message
    element_t sigma;   // Signature
    unsigned char *sig_bytes_out = NULL; // Pointer to return

    // 1. Initialize Pairing
    if (initialize_wasm_pairing(pairing) != 0) {
        return NULL; // Failed to initialize pairing
    }

    // Initialize elements that need clearing even on early exit
    element_init_G1(d, pairing);
    element_init_Zr(h, pairing);
    element_init_G1(sigma, pairing);

    // 2. Load private key from buffer
    if (deserialize_private_key_from_buffer(pairing, d, private_key_data, private_key_len) != 0) {
        fprintf(stderr, "Wasm Sign Error: Failed to load private key from buffer.\n");
        element_clear(d); element_clear(h); element_clear(sigma);
        pairing_clear(pairing);
        return NULL;
    }

    // 3. Hash message buffer to Zr
    // Assuming hash_message_to_Zr handles message_len == 0 correctly.
    hash_message_to_Zr(h, message_data, message_len, pairing);

    // 4. Compute signature: sigma = d^h
    element_pow_zn(sigma, d, h); // sigma = d ^ h

    // 5. Serialize signature (compressed) and allocate memory for output
    int sig_len = element_length_in_bytes_compressed(sigma);
    if (sig_len <= 0) {
         fprintf(stderr, "Wasm Sign Error: Failed to get signature length (maybe element is zero?).\n");
         element_clear(d); element_clear(h); element_clear(sigma);
         pairing_clear(pairing);
         return NULL;
    }

    *output_sig_len = (size_t)sig_len; // Set the output length

    sig_bytes_out = (unsigned char *)malloc(*output_sig_len);
    if (!sig_bytes_out) {
        fprintf(stderr, "Wasm Sign Error: Malloc failed for signature buffer.\n");
        *output_sig_len = 0; // Reset length on error
        element_clear(d); element_clear(h); element_clear(sigma);
        pairing_clear(pairing);
        return NULL;
    }
    // Check return value? pbc docs say element_to_bytes_compressed returns bytes written
    int bytes_written = element_to_bytes_compressed(sig_bytes_out, sigma);
     if (bytes_written != sig_len) {
        fprintf(stderr, "Wasm Sign Error: Mismatch writing signature bytes (expected %d, wrote %d).\n", sig_len, bytes_written);
        free(sig_bytes_out);
        *output_sig_len = 0;
        element_clear(d); element_clear(h); element_clear(sigma);
        pairing_clear(pairing);
        return NULL;
    }

    // 6. Cleanup PBC elements and pairing
    element_clear(d);
    element_clear(h);
    element_clear(sigma);
    pairing_clear(pairing);

    // 7. Return the allocated buffer containing the signature
    return sig_bytes_out;
}

/**
 * @brief Encrypts a message and signature for a recipient ID using IBE.
 *
 * This function follows the logic of concatenating message and signature before encryption.
 * Allocates memory for the ciphertext (compressed_U || V) which must be freed by the caller
 * using wasm_free_buffer().
 *
 * @param pub_params_data Buffer containing public parameters (compressed g || compressed P_pub).
 * @param pub_params_len Length of the public parameters buffer.
 * @param receiver_id Null-terminated string containing the recipient's identity.
 * @param message_data Buffer containing the original message.
 * @param message_len Length of the message buffer.
 * @param signature_data Buffer containing the signature (compressed G1 element).
 * @param signature_len Length of the signature buffer.
 * @param output_u_len Pointer to size_t where length of compressed U part will be written.
 * @param output_total_len Pointer to a size_t where the total length of the returned ciphertext buffer (compressed_U || V) will be written.
 * @return Pointer to the allocated ciphertext buffer (compressed_U || V), or NULL on error.
 */
unsigned char* wasm_encrypt_buffer(
    const unsigned char* pub_params_data, size_t pub_params_len,
    const char* receiver_id,
    const unsigned char* message_data, size_t message_len,
    const unsigned char* signature_data, size_t signature_len,
    size_t* output_u_len, // Output param for U length
    size_t* output_total_len // Output param for Total length
) {
    // Add null checks for output pointers at the beginning
    if (!output_u_len || !output_total_len) {
        fprintf(stderr, "Wasm Encrypt Error: Output length pointers cannot be NULL.\n");
        return NULL;
    }
    // Initialize output lengths to 0 in case of early error return
    *output_u_len = 0;
    *output_total_len = 0;

     // Check for NULL receiver_id
    if (!receiver_id) {
        fprintf(stderr, "Wasm Encrypt Error: receiver_id cannot be NULL.\n");
        return NULL;
    }
    // Check for NULL message/signature data if lengths > 0
    if ((message_len > 0 && !message_data) || (signature_len > 0 && !signature_data)) {
        fprintf(stderr, "Wasm Encrypt Error: message_data or signature_data is NULL despite non-zero length.\n");
        return NULL;
    }

    pairing_t pairing;
    element_t g, P_pub, U;
    unsigned char *plaintext_buffer = NULL;
    unsigned char *V = NULL;
    unsigned char *output_buffer = NULL;

    // 1. Initialize Pairing
    if (initialize_wasm_pairing(pairing) != 0) {
        return NULL;
    }

    // Initialize elements to ensure they are cleared
    element_init_G1(g, pairing);
    element_init_G2(P_pub, pairing); // Assuming P_pub is G2 based on typical BLS IBE
    element_init_G1(U, pairing);     // U is G1 in standard IBE

    // 2. Deserialize Public Parameters
    if (deserialize_public_params_from_buffer(pairing, g, P_pub, pub_params_data, pub_params_len) != 0) {
        fprintf(stderr, "Wasm Encrypt Error: Failed to load public params from buffer.\n");
        element_clear(g); element_clear(P_pub); element_clear(U);
        pairing_clear(pairing);
        return NULL;
    }

    // 3. Concatenate message and signature = plaintext
    size_t plaintext_len = message_len + signature_len;
    // Check for potential overflow if lengths are huge (size_t might wrap)
    if (plaintext_len < message_len || plaintext_len < signature_len) {
         fprintf(stderr, "Wasm Encrypt Error: Plaintext length calculation overflow.\n");
         element_clear(g); element_clear(P_pub); element_clear(U); pairing_clear(pairing);
         return NULL;
    }
    // Handle case where both inputs are empty
    if (plaintext_len == 0) {
         // Allow encrypting empty message? Let's proceed, Encrypt should handle it.
         fprintf(stderr, "Wasm Encrypt Info: Plaintext length is zero (empty message and signature).\n");
         // V will have size 0, U will be computed.
    }

    // Allocate even if plaintext_len is 0 (malloc(0) is valid)
    plaintext_buffer = (unsigned char *)malloc(plaintext_len);
    if (!plaintext_buffer) {
        fprintf(stderr, "Wasm Encrypt Error: Malloc failed for plaintext buffer (size %zu).\n", plaintext_len);
        element_clear(g); element_clear(P_pub); element_clear(U); pairing_clear(pairing);
        return NULL;
    }
    if (message_len > 0) {
        memcpy(plaintext_buffer, message_data, message_len);
    }
    if (signature_len > 0) {
        memcpy(plaintext_buffer + message_len, signature_data, signature_len);
    }

    // 4. Prepare for IBE Encryption
    // V buffer needs to be allocated with plaintext_len
    V = (unsigned char *)malloc(plaintext_len);
    if (!V) {
        fprintf(stderr, "Wasm Encrypt Error: Malloc failed for ciphertext V buffer (size %zu).\n", plaintext_len);
        free(plaintext_buffer); element_clear(g); element_clear(P_pub); element_clear(U); pairing_clear(pairing);
        return NULL;
    }

    // 5. Call IBE Encrypt function (from ibe.c)
    // Encrypt computes U and fills V
    Encrypt(pairing, g, P_pub, receiver_id, plaintext_buffer, plaintext_len, U, V);

    // 6. Prepare output buffer (U_compressed || V)
    int U_len_comp = element_length_in_bytes_compressed(U);
    if (U_len_comp <= 0) {
         fprintf(stderr, "Wasm Encrypt Error: Failed to get compressed U length (maybe element is zero?).\n");
         free(plaintext_buffer); free(V); element_clear(g); element_clear(P_pub); element_clear(U); pairing_clear(pairing);
         return NULL;
     }

    size_t total_len_calc = (size_t)U_len_comp + plaintext_len;
    // Check for overflow again
    if (total_len_calc < (size_t)U_len_comp || total_len_calc < plaintext_len) {
         fprintf(stderr, "Wasm Encrypt Error: Total output length calculation overflow.\n");
         free(plaintext_buffer); free(V); element_clear(g); element_clear(P_pub); element_clear(U); pairing_clear(pairing);
         return NULL;
    }

    // --- Assign output lengths ---
    *output_u_len = (size_t)U_len_comp;
    *output_total_len = total_len_calc;

    output_buffer = (unsigned char *)malloc(*output_total_len);
    if (!output_buffer) {
        fprintf(stderr, "Wasm Encrypt Error: Malloc failed for output buffer (size %zu).\n", *output_total_len);
        *output_u_len = 0; // Reset lengths on error
        *output_total_len = 0;
        free(plaintext_buffer); free(V); element_clear(g); element_clear(P_pub); element_clear(U); pairing_clear(pairing);
        return NULL;
    }

    // Serialize compressed U into the start of output_buffer
    int bytes_written_u = element_to_bytes_compressed(output_buffer, U);
     if (bytes_written_u != U_len_comp) {
        fprintf(stderr, "Wasm Encrypt Error: Mismatch writing U bytes (expected %d, wrote %d).\n", U_len_comp, bytes_written_u);
        free(output_buffer); free(plaintext_buffer); free(V);
        *output_u_len = 0; *output_total_len = 0;
        element_clear(g); element_clear(P_pub); element_clear(U); pairing_clear(pairing);
        return NULL;
    }

    // Copy V into output_buffer after U
    if (plaintext_len > 0) {
        memcpy(output_buffer + U_len_comp, V, plaintext_len);
    }

    // 7. Cleanup
    free(plaintext_buffer);
    free(V);
    element_clear(g);
    element_clear(P_pub);
    element_clear(U);
    pairing_clear(pairing);

    // 8. Return combined ciphertext
    return output_buffer;
}


/**
 * @brief Decrypts an IBE ciphertext (compressed_U || V) using the recipient's private key.
 * Calculates U length internally based on pairing parameters.
 *
 * Allocates memory for the combined plaintext (message || signature) which must be freed
 * by the caller using wasm_free_buffer(). Also provides the length of the signature
 * part so the caller can split the combined buffer.
 *
 * @param private_key_data Buffer containing the compressed private key (G1 element).
 * @param private_key_len Length of the private key buffer.
 * @param ciphertext_data Buffer containing the full ciphertext (compressed U || V).
 * @param ciphertext_len Total length of the ciphertext buffer.
 * -- REMOVED: size_t u_len input parameter --
 * @param output_plaintext_len Pointer to size_t where the length of the returned combined plaintext (message || signature) will be written.
 * @param output_sig_len Pointer to size_t where the length of the signature part within the plaintext will be written.
 * @return Pointer to the allocated combined plaintext buffer (message || signature), or NULL on error.
 */
unsigned char* wasm_decrypt_buffer(
    const unsigned char* private_key_data, size_t private_key_len,
    const unsigned char* ciphertext_data, size_t ciphertext_len, // Combined U||V
    // REMOVED size_t u_len, // Length of the U part NO LONGER AN INPUT
    size_t* output_plaintext_len, // Length of the decrypted combined data (V part length)
    size_t* output_sig_len        // Length of the signature part within the decrypted data
) {
     // Add null checks for output pointers
    if (!output_plaintext_len || !output_sig_len) {
        fprintf(stderr, "Wasm Decrypt Error: Output length pointers cannot be NULL.\n");
        return NULL;
    }
    *output_plaintext_len = 0; // Initialize
    *output_sig_len = 0;       // Initialize

     // Basic validation of input pointers/lengths
     if (!ciphertext_data && ciphertext_len > 0) {
         fprintf(stderr, "Wasm Decrypt Error: ciphertext_data is NULL but ciphertext_len is %zu.\n", ciphertext_len);
         return NULL;
     }
     if (!private_key_data && private_key_len > 0) {
          fprintf(stderr, "Wasm Decrypt Error: private_key_data is NULL but private_key_len is %zu.\n", private_key_len);
         return NULL;
     }

    pairing_t pairing;
    element_t d_receiver; // Receiver's private key
    element_t U;          // Ephemeral key from ciphertext U
    unsigned char *plaintext_buffer = NULL;

    // 1. Initialize Pairing
    if (initialize_wasm_pairing(pairing) != 0) {
        return NULL;
    }

    // Initialize elements (needed for calculating lengths and for cleanup)
    element_init_G1(d_receiver, pairing);
    element_init_G1(U, pairing);

    // --- Calculate expected U length dynamically ---
    int u_len_comp = element_length_in_bytes_compressed(U);
    if (u_len_comp <= 0) {
        fprintf(stderr, "Wasm Decrypt Error: Failed to get expected compressed U length.\n");
        element_clear(d_receiver); element_clear(U); pairing_clear(pairing);
        return NULL;
    }
    size_t u_len = (size_t)u_len_comp; // Use this calculated length
    // --- End U length calculation ---

    // --- Validate total ciphertext length against calculated U length ---
    if (u_len > ciphertext_len) {
        fprintf(stderr, "Wasm Decrypt Error: Calculated u_len (%zu) is greater than total ciphertext_len (%zu).\n", u_len, ciphertext_len);
        element_clear(d_receiver); element_clear(U); pairing_clear(pairing);
        return NULL;
    }
    // --- End validation ---

    // --- Define pointers to U and V within the combined ciphertext ---
    const unsigned char* u_data = ciphertext_data;
    const unsigned char* v_data = ciphertext_data + u_len;
    size_t v_len = ciphertext_len - u_len; // This is the length of the encrypted (msg||sig) blob
    // --- End split definition ---

    // 2. Deserialize private key
    if (deserialize_private_key_from_buffer(pairing, d_receiver, private_key_data, private_key_len) != 0) {
        fprintf(stderr, "Wasm Decrypt Error: Failed to load private key from buffer.\n");
        element_clear(d_receiver); element_clear(U);
        pairing_clear(pairing);
        return NULL;
    }

    // --- Calculate expected signature length ---
    // (We use the loaded private key element type (G1) to get the standard compressed size)
    int sig_len_expected = element_length_in_bytes_compressed(d_receiver);
    if (sig_len_expected <= 0) {
        fprintf(stderr, "Wasm Decrypt Error: Failed to determine expected signature length.\n");
        element_clear(d_receiver); element_clear(U); pairing_clear(pairing);
        return NULL;
    }
    // --- End signature length calculation ---


    // 3. Deserialize ciphertext component U from the input buffer segment
    if (u_len == 0) { // Should not happen if u_len_comp > 0 check passed
         fprintf(stderr, "Wasm Decrypt Error: Calculated length of U component (u_len) is zero.\n");
         element_clear(d_receiver); element_clear(U); pairing_clear(pairing);
         return NULL;
    }
    // Use element_from_bytes_compressed directly on the u_data segment
    if (element_from_bytes_compressed(U, (unsigned char *)u_data) != (int)u_len) { // Use calculated u_len
        fprintf(stderr, "Wasm Decrypt Error: Failed to load U from buffer (length mismatch or invalid data).\n");
        element_clear(d_receiver); element_clear(U); pairing_clear(pairing);
        return NULL;
    }

    // 4. Allocate buffer for decrypted plaintext (size is v_len)
    // Validate v_len against expected signature length
    if (v_len < (size_t)sig_len_expected) {
         fprintf(stderr, "Wasm Decrypt Error: Encrypted data length V (%zu) is less than expected signature length (%d).\n", v_len, sig_len_expected);
         element_clear(d_receiver); element_clear(U); pairing_clear(pairing);
         return NULL;
    }
     if (v_len == 0) {
         fprintf(stderr, "Wasm Decrypt Info: Ciphertext V part has zero length. Decrypting to empty buffer.\n");
         // Allow decrypting empty message/signature? Let's assume malloc(0) and Decrypt(..., 0, ...) work.
     }

    plaintext_buffer = (unsigned char *)malloc(v_len);
    if (!plaintext_buffer) {
        fprintf(stderr, "Wasm Decrypt Error: Malloc failed for plaintext buffer (size %zu).\n", v_len);
        element_clear(d_receiver); element_clear(U); pairing_clear(pairing);
        return NULL;
    }

    // 5. Call IBE Decrypt function (from ibe.c)
    // Decrypt modifies plaintext_buffer in place. Assumes Decrypt handles v_len=0 case.
    Decrypt(pairing, d_receiver, U, v_data, v_len, plaintext_buffer);

    // 6. Set output lengths and cleanup
    *output_plaintext_len = v_len;           // Total combined length = V length
    *output_sig_len = (size_t)sig_len_expected; // Signature part length

    element_clear(d_receiver);
    element_clear(U);
    pairing_clear(pairing);

    // 7. Return allocated combined plaintext buffer (contains message || signature)
    return plaintext_buffer;
}

/**
 * @brief Verifies a signature against a message and signer's identity.
 *
 * @param pub_params_data Buffer containing public parameters (compressed g || compressed P_pub).
 * @param pub_params_len Length of the public parameters buffer.
 * @param signer_id Null-terminated string containing the signer's identity.
 * @param message_data Buffer containing the message.
 * @param message_len Length of the message buffer.
 * @param signature_data Buffer containing the signature (compressed G1 element).
 * @param signature_len Length of the signature buffer.
 * @return 0 if signature is VALID, 1 if signature is INVALID, -1 on error.
 */
int wasm_verify_buffer(
    const unsigned char* pub_params_data, size_t pub_params_len,
    const char* signer_id,
    const unsigned char* message_data, size_t message_len,
    const unsigned char* signature_data, size_t signature_len
) {
     // Check for NULL signer_id first
    if (!signer_id) {
         fprintf(stderr, "Wasm Verify Error: Signer ID is NULL.\n");
         return -1;
    }
     // Check for NULL data pointers if corresponding length is non-zero
    if ((pub_params_len > 0 && !pub_params_data) ||
        (message_len > 0 && !message_data) ||
        (signature_len > 0 && !signature_data)) {
         fprintf(stderr, "Wasm Verify Error: Data pointer is NULL for non-zero length input.\n");
         return -1;
    }


    pairing_t pairing;
    element_t g, P_pub;     // Public parameters
    element_t Q_signer;     // H(signer_id)
    element_t h;            // H(message)
    element_t sigma;        // Signature
    element_t temp_G1, lhs_GT, rhs_GT; // Temporaries
    int result = -1; // Default to error

    // 1. Initialize Pairing
    if (initialize_wasm_pairing(pairing) != 0) {
        return -1; // Error
    }

    // Initialize elements for proper clearing
    element_init_G1(g, pairing);
    element_init_G2(P_pub, pairing); // Assume G2
    element_init_G1(Q_signer, pairing);
    element_init_Zr(h, pairing);
    element_init_G1(sigma, pairing);
    element_init_G1(temp_G1, pairing);
    element_init_GT(lhs_GT, pairing);
    element_init_GT(rhs_GT, pairing);


    // 2. Deserialize Public Parameters
    if (deserialize_public_params_from_buffer(pairing, g, P_pub, pub_params_data, pub_params_len) != 0) {
        fprintf(stderr, "Wasm Verify Error: Failed to load public params from buffer.\n");
        // Clear all initialized elements
        element_clear(g); element_clear(P_pub); element_clear(Q_signer); element_clear(h);
        element_clear(sigma); element_clear(temp_G1); element_clear(lhs_GT); element_clear(rhs_GT);
        pairing_clear(pairing);
        return -1; // Error
    }

    // 3. Deserialize Signature
    // Check if signature_len is 0
    if (signature_len == 0) {
        fprintf(stderr, "Wasm Verify Error: Signature length is zero.\n");
        element_clear(g); element_clear(P_pub); element_clear(Q_signer); element_clear(h);
        element_clear(sigma); element_clear(temp_G1); element_clear(lhs_GT); element_clear(rhs_GT);
        pairing_clear(pairing);
        return -1;
    }
    if (deserialize_signature_from_buffer(pairing, sigma, signature_data, signature_len) != 0) {
        fprintf(stderr, "Wasm Verify Error: Failed to load signature from buffer.\n");
        element_clear(g); element_clear(P_pub); element_clear(Q_signer); element_clear(h);
        element_clear(sigma); element_clear(temp_G1); element_clear(lhs_GT); element_clear(rhs_GT);
        pairing_clear(pairing);
        return -1; // Error
    }

    // 4. Hash signer ID to G1
    // Check for empty signer_id string
    if (strlen(signer_id) == 0) {
         fprintf(stderr, "Wasm Verify Error: Signer ID is empty.\n");
         element_clear(g); element_clear(P_pub); element_clear(Q_signer); element_clear(h);
         element_clear(sigma); element_clear(temp_G1); element_clear(lhs_GT); element_clear(rhs_GT);
         pairing_clear(pairing);
         return -1;
    }
    hash_id_to_G1(Q_signer, signer_id, pairing);

    // 5. Hash message to Zr
    // Allow empty message? hash_message_to_Zr should handle it.
    hash_message_to_Zr(h, message_data, message_len, pairing);

    // 6. Verification check: e(sigma, g) == e(Q_signer^h, P_pub)
    // LHS = e(sigma, g)
    pairing_apply(lhs_GT, sigma, g, pairing);

    // temp_G1 = Q_signer^h
    element_pow_zn(temp_G1, Q_signer, h);

    // RHS = e(temp_G1, P_pub)
    pairing_apply(rhs_GT, temp_G1, P_pub, pairing);

    // Compare LHS and RHS
    if (!element_cmp(lhs_GT, rhs_GT)) {
        result = 0; // VALID
    } else {
        result = 1; // INVALID
    }

    // 7. Cleanup
    element_clear(g);
    element_clear(P_pub);
    element_clear(Q_signer);
    element_clear(h);
    element_clear(sigma);
    element_clear(temp_G1);
    element_clear(lhs_GT);
    element_clear(rhs_GT);
    pairing_clear(pairing);

    return result;
}


/**
 * @brief Frees memory allocated by Wasm functions (like wasm_sign_buffer).
 *
 * Should be called from JavaScript to free the pointers returned by functions
 * that allocate memory internally via malloc.
 *
 * @param ptr Pointer to the memory buffer to free.
 */
void wasm_free_buffer(void* ptr) {
    // Check for NULL before freeing is good practice although free(NULL) is standardly a no-op.
    if (ptr != NULL) {
        free(ptr);
    }
}

