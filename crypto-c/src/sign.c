#include "bls_ibe_util.h"
#include <pbc/pbc.h>
#include <stdio.h> // For FILENAME_MAX

#define PARAM_FILE "a.param"
#define MAX_FILENAME_LEN 512

int main(int argc, char **argv) {
    // Updated Usage: remove output_signature_file argument
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <private_key_file> <message_file>\n", argv[0]);
        return 1;
    }
    const char *priv_key_file = argv[1];
    const char *message_file = argv[2];
    // char sig_file[FILENAME_MAX]; // Output filename generated internally
    char sig_file[MAX_FILENAME_LEN];


    pairing_t pairing;
    element_t d; // User's private key (H(ID)^msk in G1)
    element_t h; // Hash of message (in Zr)
    element_t sigma; // Signature (in G1)

    // Generate output signature filename: <message_file>.sig
    int len_written = snprintf(sig_file, sizeof(sig_file), "%s.sig", message_file);
    if (len_written < 0 || (size_t)len_written >= sizeof(sig_file)) {
        fprintf(stderr, "Error: Message filename '%s' is too long to generate signature filename.\n", message_file);
        exit(EXIT_FAILURE);
    }


    // Initialize pairing
    initialize_pairing(pairing, PARAM_FILE);

    // Load user's private key (d)
    load_user_private_key(pairing, d, priv_key_file);

    // Read message file content
    size_t msg_len;
    unsigned char *msg_content = read_file_content(message_file, &msg_len);
    if (!msg_content) DIE("Failed to read message file");

    // Hash message to Zr (h = H_Zr(m))
    hash_message_to_Zr(h, msg_content, msg_len, pairing);

    // Compute signature: sigma = d^h
    element_init_G1(sigma, pairing);
    element_pow_zn(sigma, d, h);

    // Save signature to the generated filename (compressed)
    int sig_len = element_length_in_bytes_compressed(sigma);
    unsigned char *sig_bytes = malloc(sig_len);
    if (!sig_bytes) DIE("Malloc failed for signature buffer");
    element_to_bytes_compressed(sig_bytes, sigma);
    write_file_content(sig_file, sig_bytes, sig_len); // Use generated filename

    // Updated printf
    printf("Message '%s' signed successfully. Signature saved to '%s'.\n", message_file, sig_file);

    // Cleanup
    free(msg_content);
    free(sig_bytes);
    element_clear(d);
    element_clear(h);
    element_clear(sigma);
    pairing_clear(pairing);

    return 0;
}
