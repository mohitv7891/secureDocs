#include "ibe.h"
#include "bls_ibe_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h> // For PATH_MAX

#define PARAM_FILE "a.param"
#define MAX_FILENAME_LEN 512 // Use a consistent definition

// Helper function to extract base filename from the ".<userid>.enc" format
// Returns a newly allocated string (must be freed by caller) or NULL on error.
char* extract_base_filename(const char* enc_filename) {
    const char* last_dot = strrchr(enc_filename, '.');
    if (!last_dot || strcmp(last_dot, ".enc") != 0) {
        fprintf(stderr, "Error: Encrypted filename '%s' does not end with '.enc'\n", enc_filename);
        return NULL; // Doesn't end with .enc
    }

    // Temporarily replace the last dot with null to find the second last dot
    // size_t enc_len = strlen(enc_filename); // <--- REMOVE THIS LINE
    char* temp_name = strdup(enc_filename); // Create a mutable copy
    if (!temp_name) return NULL; // strdup failed
    temp_name[last_dot - enc_filename] = '\0'; // Cut off ".enc"

    const char* second_last_dot = strrchr(temp_name, '.');
    if (!second_last_dot) {
        fprintf(stderr, "Error: Encrypted filename '%s' does not match format '<base>.<userid>.enc'\n", enc_filename);
        free(temp_name);
        return NULL; // No second dot found (missing userid part)
    }

    // The base name is the part before the second last dot
    size_t base_len = second_last_dot - temp_name;
    char* base_filename = (char*) malloc(base_len + 1);
    if (!base_filename) {
        free(temp_name);
        return NULL; // malloc failed
    }
    strncpy(base_filename, temp_name, base_len);
    base_filename[base_len] = '\0';

    free(temp_name); // Free the temporary copy
    return base_filename;
}


int main(int argc, char *argv[]) {
    // Updated Usage: remove output filename arguments
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <private_key_file> <encrypted_file>\n", argv[0]);
        return 1;
    }

    const char *keyfile = argv[1];
    const char *enc_file = argv[2];
    // Output filenames generated internally
    // char output_msg_file[FILENAME_MAX];
    // char output_sig_file[FILENAME_MAX];
    char output_msg_file[MAX_FILENAME_LEN];
    char output_sig_file[MAX_FILENAME_LEN];


    pairing_t pairing;
    element_t d_receiver; // Receiver's private key
    element_t U;          // Ephemeral key from ciphertext

    // --- Derive output filenames from encrypted filename ---
    char *base_name = extract_base_filename(enc_file);
    if (!base_name) {
        // Error message already printed by helper function
        return 1;
    }

    int len_msg = snprintf(output_msg_file, sizeof(output_msg_file), "%s", base_name);
    int len_sig = snprintf(output_sig_file, sizeof(output_sig_file), "%s.sig", base_name);

    if (len_msg < 0 || (size_t)len_msg >= sizeof(output_msg_file) ||
        len_sig < 0 || (size_t)len_sig >= sizeof(output_sig_file)) {
        fprintf(stderr, "Error: Base filename '%s' derived from '%s' is too long for output buffers.\n", base_name, enc_file);
        free(base_name);
        exit(EXIT_FAILURE);
    }
    free(base_name); // Free the extracted base name, we have the full names now
    // --- End filename derivation ---


    // Initialize pairing
    initialize_pairing(pairing, PARAM_FILE);

    // Load receiver's private key
    load_user_private_key(pairing, d_receiver, keyfile);

    // Load encrypted file (U | V)
    FILE *fp_in = fopen(enc_file, "rb");
    if (!fp_in) DIE("Error opening encrypted file");

    // Determine size of compressed U and read it
    element_init_G1(U, pairing); // Initialize U to get its compressed size context
    int U_len_comp = element_length_in_bytes_compressed(U);
    unsigned char *U_buf_comp = malloc(U_len_comp);
    if (!U_buf_comp) { fclose(fp_in); DIE("Malloc U buffer failed"); }

    if (fread(U_buf_comp, 1, U_len_comp, fp_in) != (size_t)U_len_comp) {
        free(U_buf_comp); fclose(fp_in); DIE("Error reading U from encrypted file");
    }
    if (element_from_bytes_compressed(U, U_buf_comp) != U_len_comp) {
         free(U_buf_comp); fclose(fp_in); DIE("Error decompressing U");
    }
    free(U_buf_comp);

    // Determine size of V (rest of the file) and read it
    long current_pos = ftell(fp_in);
    fseek(fp_in, 0, SEEK_END);
    long total_len = ftell(fp_in);
    size_t V_len = total_len - current_pos;
    if (V_len <= 0 && total_len > 0) { // Check if V_len calculation makes sense
       fclose(fp_in);
       fprintf(stderr, "Error: Calculated ciphertext V length (%zu) is invalid.\n", V_len);
       exit(EXIT_FAILURE);
    }
    rewind(fp_in);
    fseek(fp_in, current_pos, SEEK_SET); // Seek back to start of V

    unsigned char *V = malloc(V_len);
    if (!V) { fclose(fp_in); DIE("Malloc V buffer failed"); }
    // Only read if V_len is positive
    if (V_len > 0 && fread(V, 1, V_len, fp_in) != V_len) {
        free(V); fclose(fp_in); DIE("Error reading V from encrypted file");
    }
    fclose(fp_in);

    // Allocate buffer for decrypted plaintext
    unsigned char *plaintext_buffer = malloc(V_len); // V_len is also plaintext_len
    if (!plaintext_buffer) { free(V); DIE("Malloc plaintext buffer failed"); }

    // Decrypt V only if V_len > 0 (handle empty message case)
     if (V_len > 0) {
        Decrypt(pairing, d_receiver, U, V, V_len, plaintext_buffer);
    }
    // If V_len is 0, plaintext_buffer remains allocated but empty, which is fine.
    free(V); // V is no longer needed

    // --- Split plaintext into message and signature ---
    int sig_len_expected = element_length_in_bytes_compressed(d_receiver);

    if (V_len < (size_t)sig_len_expected) {
        free(plaintext_buffer);
        fprintf(stderr, "Error: Decrypted data length (%zu) is too short to contain the expected signature (%d bytes).\n", V_len, sig_len_expected);
        exit(1);
    }

    size_t msg_len = V_len - sig_len_expected;
    unsigned char *msg_data = plaintext_buffer;
    unsigned char *sig_data = plaintext_buffer + msg_len;

    // Write message to the generated output file
    write_file_content(output_msg_file, msg_data, msg_len); // Use generated name

    // Write signature to the generated output file
    write_file_content(output_sig_file, sig_data, sig_len_expected); // Use generated name

    // Updated printf
    printf("Decryption complete. Message saved to %s, Signature saved to %s\n", output_msg_file, output_sig_file);

    // Cleanup
    free(plaintext_buffer);
    element_clear(U);
    element_clear(d_receiver);
    pairing_clear(pairing);

    return 0;
}
