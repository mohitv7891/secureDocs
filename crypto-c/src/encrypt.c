#include "ibe.h"
#include "bls_ibe_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h> // For PATH_MAX (alternative to FILENAME_MAX)

#define PARAM_FILE "a.param"
#define PP_FILE "public_params.dat"
#define MAX_FILENAME_LEN 512 // Use a consistent definition

int main(int argc, char *argv[]) {
    // Updated Usage: remove output_encrypted_file argument
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <receiver_identity> <message_file> <signature_file>\n", argv[0]);
        return 1;
    }

    const char *receiver_id = argv[1];
    const char *message_file = argv[2];
    const char *signature_file = argv[3];
    // char encrypted_file[FILENAME_MAX]; // Output filename generated internally
    char encrypted_file[MAX_FILENAME_LEN];

    pairing_t pairing;
    element_t g, P_pub, U;

    // Generate output encrypted filename: <message_file>.<receiver_id>.enc
    int len_written = snprintf(encrypted_file, sizeof(encrypted_file), "%s.%s.enc", message_file, receiver_id);
     if (len_written < 0 || (size_t)len_written >= sizeof(encrypted_file)) {
        fprintf(stderr, "Error: Filenames/ID ('%s', '%s') too long to generate encrypted filename.\n", message_file, receiver_id);
        exit(EXIT_FAILURE);
    }

    // Initialize pairing and load public parameters
    initialize_pairing(pairing, PARAM_FILE);
    load_public_params(pairing, g, P_pub, PP_FILE);

    // Read message file
    size_t msg_len;
    unsigned char *msg_content = read_file_content(message_file, &msg_len);
    if (!msg_content) DIE("Failed to read message file");

    // Read signature file
    size_t sig_len;
    unsigned char *sig_content = read_file_content(signature_file, &sig_len);
    if (!sig_content) { free(msg_content); DIE("Failed to read signature file"); }

    // Concatenate message and signature = plaintext
    size_t plaintext_len = msg_len + sig_len;
    unsigned char *plaintext_buffer = malloc(plaintext_len);
    if (!plaintext_buffer) { free(msg_content); free(sig_content); DIE("Malloc failed for plaintext buffer"); }
    memcpy(plaintext_buffer, msg_content, msg_len);
    memcpy(plaintext_buffer + msg_len, sig_content, sig_len);
    free(msg_content);
    free(sig_content);

    // Prepare for encryption
    element_init_G1(U, pairing); // U will be computed by Encrypt
    unsigned char *V = malloc(plaintext_len); // Ciphertext part V
    if (!V) { free(plaintext_buffer); DIE("Malloc failed for ciphertext V buffer"); }

    // Encrypt the combined plaintext
    Encrypt(pairing, g, P_pub, receiver_id, plaintext_buffer, plaintext_len, U, V);

    // Save U and V to the generated encrypted file
    // Format: U (compressed) | V
    FILE *fp_out = fopen(encrypted_file, "wb"); // Use generated filename
    if (!fp_out) { free(plaintext_buffer); free(V); DIE("Error opening output file"); }

    int U_len_comp = element_length_in_bytes_compressed(U);
    unsigned char *U_buf_comp = malloc(U_len_comp);
    if (!U_buf_comp) { free(plaintext_buffer); free(V); fclose(fp_out); DIE("Malloc U buffer failed"); }
    element_to_bytes_compressed(U_buf_comp, U);

    // Write compressed U
    if (fwrite(U_buf_comp, 1, U_len_comp, fp_out) != (size_t)U_len_comp) {
        free(plaintext_buffer); free(V); free(U_buf_comp); fclose(fp_out); DIE("Error writing U to file");
    }
    // Write V
    if (fwrite(V, 1, plaintext_len, fp_out) != plaintext_len) {
         free(plaintext_buffer); free(V); free(U_buf_comp); fclose(fp_out); DIE("Error writing V to file");
    }

    fclose(fp_out);
    // Updated printf
    printf("Encryption complete. Encrypted data saved as %s\n", encrypted_file);

    // Cleanup
    free(plaintext_buffer);
    free(V);
    free(U_buf_comp);
    element_clear(g);
    element_clear(P_pub);
    element_clear(U);
    pairing_clear(pairing);

    return 0;
}
