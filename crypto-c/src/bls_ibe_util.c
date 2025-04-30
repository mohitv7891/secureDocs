/* === File: bls_ibe_util.c === */
#include "bls_ibe_util.h"

/* --- File Operations Implementation (Keep for Native/Testing) --- */

unsigned char* read_file_content(const char *filename, size_t *len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error opening file for reading: %s\n", filename);
        perror("read_file_content");
        return NULL; // Let caller handle error
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
     if (file_size < 0) { // Check for ftell error
        fclose(fp);
        perror("ftell");
        return NULL;
    }
    *len = (size_t)file_size;
    rewind(fp);

    // Handle zero-length file case
    if (*len == 0) {
        fclose(fp);
        // Return a non-NULL pointer for zero-length data if needed, or NULL
        // Let's return NULL for simplicity, caller should check len.
        return NULL;
    }

    unsigned char *buffer = malloc(*len);
    if (!buffer) {
        fclose(fp);
        fprintf(stderr, "Malloc failed in read_file_content for size %zu\n", *len);
        return NULL; // Let caller handle error
    }

    if (fread(buffer, 1, *len, fp) != *len) {
        fclose(fp);
        free(buffer);
         fprintf(stderr, "Read error in read_file_content from file: %s\n", filename);
        perror("fread");
        return NULL; // Let caller handle error
    }

    fclose(fp);
    return buffer;
}

void write_file_content(const char *filename, const unsigned char *data, size_t len) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) DIE("Failed to open file for writing"); // Using DIE for simplicity here

    if (len > 0 && fwrite(data, 1, len, fp) != len) {
        fclose(fp);
        DIE("Failed to write complete data to file");
    }
    fclose(fp);
}

/* --- PBC Initialization and Loading Implementation --- */

// Kept as is - Wasm wrappers will assume param file exists in virtual FS
void initialize_pairing(pairing_t pairing, const char *param_file) {
    size_t param_len;
    unsigned char *param_buf = read_file_content(param_file, &param_len);
    // Check if read_file_content returned NULL (error or zero length)
    if (!param_buf || param_len == 0) {
         fprintf(stderr, "Failed to read pairing parameters from: %s\n", param_file);
         exit(EXIT_FAILURE); // Or use DIE macro
    }

    // Use pairing_init_set_buf as before
    if (pairing_init_set_buf(pairing, (const char *)param_buf, param_len)) {
        free(param_buf);
        fprintf(stderr, "Pairing initialization failed\n");
        exit(EXIT_FAILURE);
    }
    free(param_buf);

    // Check symmetry
    if (!pairing_is_symmetric(pairing)) {
        fprintf(stderr, "Error: Pairing must be symmetric (Type A) for this scheme.\n");
        exit(EXIT_FAILURE);
    }
}

// Kept for native/testing
void load_public_params(pairing_t pairing, element_t g, element_t P_pub, const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) DIE("Failed to open public parameters file");

    element_init_G1(g, pairing);
    element_init_G1(P_pub, pairing);

    int g_len_expected = element_length_in_bytes_compressed(g);
    int p_pub_len_expected = element_length_in_bytes_compressed(P_pub);
    size_t total_len_expected = g_len_expected + p_pub_len_expected;

    unsigned char *buf = malloc(total_len_expected);
    if (!buf) { fclose(fp); DIE("Malloc failed for public params buffer"); }

    if (fread(buf, 1, total_len_expected, fp) != total_len_expected) {
         free(buf); fclose(fp); DIE("Failed to read expected bytes for public parameters");
    }
    fclose(fp); // Close file after reading

    // Deserialize g
    if (element_from_bytes_compressed(g, buf) == 0) {
        free(buf); DIE("Failed to deserialize g from public params file");
    }
    // Deserialize P_pub (from the correct offset)
    if (element_from_bytes_compressed(P_pub, buf + g_len_expected) == 0) {
         free(buf); DIE("Failed to deserialize P_pub from public params file");
    }

    free(buf);
}

// Kept for server-side
void load_master_secret(pairing_t pairing, element_t msk, const char *filename) {
     FILE *fp = fopen(filename, "rb");
    if (!fp) DIE("Failed to open master secret key file");

    element_init_Zr(msk, pairing);
    int msk_len = element_length_in_bytes(msk);
    unsigned char *buf = malloc(msk_len);
     if (!buf) { fclose(fp); DIE("Malloc failed for msk buffer"); }

    if(fread(buf, 1, msk_len, fp) != (size_t)msk_len) {
        free(buf); fclose(fp); DIE("Failed to read msk from file");
    }
    fclose(fp);

    element_from_bytes(msk, buf); // No check needed? element_from_bytes returns void

    free(buf);
}

// Kept for native/testing
void load_user_private_key(pairing_t pairing, element_t user_sk, const char *filename) {
     FILE *fp = fopen(filename, "rb");
    if (!fp) DIE("Failed to open user private key file");

    element_init_G1(user_sk, pairing); // IBE key is in G1
    int sk_len = element_length_in_bytes_compressed(user_sk); // Use compressed
    unsigned char *buf = malloc(sk_len);
    if (!buf) { fclose(fp); DIE("Malloc failed for user sk buffer"); }

    if(fread(buf, 1, sk_len, fp) != (size_t)sk_len) {
         free(buf); fclose(fp); DIE("Failed to read user sk from file");
    }
     fclose(fp);

    if (element_from_bytes_compressed(user_sk, buf) == 0) { // Use compressed
        free(buf); DIE("Failed to deserialize user private key");
    }

    free(buf);
}

// Kept for server-side (keygen)
void save_user_private_key(element_t user_sk, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) DIE("Failed to open private key file for writing");

    int sk_len = element_length_in_bytes_compressed(user_sk); // Use compressed
    unsigned char *buf = malloc(sk_len);
    if (!buf) { fclose(fp); DIE("Malloc failed for user sk save buffer"); }

    element_to_bytes_compressed(buf, user_sk);
    if (fwrite(buf, 1, sk_len, fp) != (size_t)sk_len) {
        free(buf);
        fclose(fp);
        DIE("Failed to write user private key");
    }
    free(buf);
    fclose(fp);
}


/* --- Buffer Deserialization Implementations (for Wasm) --- */

int deserialize_public_params_from_buffer(pairing_t pairing, element_t g, element_t P_pub, const unsigned char *param_data, size_t param_len) {
    element_init_G1(g, pairing);
    element_init_G1(P_pub, pairing);

    int g_len_expected = element_length_in_bytes_compressed(g);
    int p_pub_len_expected = element_length_in_bytes_compressed(P_pub);
    size_t total_len_expected = g_len_expected + p_pub_len_expected;

    if (param_len != total_len_expected) {
        fprintf(stderr, "Error: Public param buffer length (%zu) does not match expected length (%zu)\n", param_len, total_len_expected);
        return 1;
    }

    // Deserialize g
    if (element_from_bytes_compressed(g, (unsigned char*)param_data) == 0) {
        fprintf(stderr, "Error: Failed to deserialize g from public param buffer.\n");
        return 1;
    }
    // Deserialize P_pub (from the correct offset)
    if (element_from_bytes_compressed(P_pub, (unsigned char*)param_data + g_len_expected) == 0) {
         fprintf(stderr, "Error: Failed to deserialize P_pub from public param buffer.\n");
         // Consider clearing 'g' if P_pub fails?
         return 1;
    }
    return 0; // Success
}

// Included from previous step
int deserialize_private_key_from_buffer(pairing_t pairing, element_t user_sk, const unsigned char *key_data, size_t key_len) {
    element_init_G1(user_sk, pairing);
    int expected_len = element_length_in_bytes_compressed(user_sk);

    // Optional: Check length if it's guaranteed fixed. Otherwise, rely on element_from_bytes.
    // if (key_len != (size_t)expected_len) {
    //      fprintf(stderr, "Warning: Private key length (%zu) differs from expected (%d)\n", key_len, expected_len);
    // }

    if (element_from_bytes_compressed(user_sk, (unsigned char *)key_data) == 0) {
         fprintf(stderr, "Error: Failed to deserialize private key from buffer.\n");
         return 1; // Indicate error
    }
    return 0; // Success
}

int deserialize_signature_from_buffer(pairing_t pairing, element_t sigma, const unsigned char *sig_data, size_t sig_len) {
    element_init_G1(sigma, pairing);
    int expected_len = element_length_in_bytes_compressed(sigma);
    // Optional length check
    // if (sig_len != (size_t)expected_len) { ... }

    if (element_from_bytes_compressed(sigma, (unsigned char*)sig_data) == 0) {
         fprintf(stderr, "Error: Failed to deserialize signature from buffer.\n");
         return 1;
    }
    return 0; // Success
}

int deserialize_ciphertext_u_from_buffer(pairing_t pairing, element_t U, const unsigned char* u_data, size_t u_len) {
    element_init_G1(U, pairing);
    int expected_len = element_length_in_bytes_compressed(U);
     // Optional length check
    // if (u_len != (size_t)expected_len) { ... }

    if (element_from_bytes_compressed(U, (unsigned char*)u_data) == 0) {
         fprintf(stderr, "Error: Failed to deserialize ciphertext U from buffer.\n");
         return 1;
    }
    return 0; // Success
}


/* --- Hashing Implementation (Keep as is) --- */

void hash_id_to_G1(element_t Q, const char *id, pairing_t pairing) {
    // Ensure Q is initialized before use
    element_init_G1(Q, pairing);
    // Use the standard PBC hash function
    // Note: Check PBC documentation if specific domain separation is needed.
    element_from_hash(Q, (void*)id, strlen(id));
}

void hash_message_to_Zr(element_t h, const unsigned char *msg, size_t msg_len, pairing_t pairing) {
    // Ensure h is initialized before use
    element_init_Zr(h, pairing);
    // Use SHA256 of the message, then map bytes to element
    unsigned char hash_buf[SHA256_DIGEST_LENGTH];
    SHA256(msg, msg_len, hash_buf);
    element_from_hash(h, hash_buf, SHA256_DIGEST_LENGTH); // PBC's way to map hash to Zr
}
