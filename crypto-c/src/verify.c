#include "bls_ibe_util.h"
#include <pbc/pbc.h>

#define PARAM_FILE "a.param"
#define PP_FILE "public_params.dat"

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <signer_identity> <message_file> <signature_file>\n", argv[0]);
        return 1;
    }
    const char *signer_id = argv[1];
    const char *message_file = argv[2];
    const char *sig_file = argv[3];

    pairing_t pairing;
    element_t g, P_pub; // Public parameters
    element_t Q_signer; // H(signer_id) in G1
    element_t h;        // Hash of message (in Zr)
    element_t sigma;    // Signature read from file (in G1)
    element_t temp_G1, lhs_GT, rhs_GT; // Temporaries for verification

    // Initialize pairing
    initialize_pairing(pairing, PARAM_FILE);

    // Load public parameters
    load_public_params(pairing, g, P_pub, PP_FILE);

    // Load signature from file
    size_t sig_len_read;
    unsigned char *sig_bytes = read_file_content(sig_file, &sig_len_read);
    if (!sig_bytes) DIE("Failed to read signature file");

    element_init_G1(sigma, pairing);
    if (element_from_bytes_compressed(sigma, sig_bytes) != sig_len_read) {
         fprintf(stderr, "Error: Signature size mismatch or decompression failed.\n");
         free(sig_bytes);
         exit(1);
    }
    free(sig_bytes);


    // Read message file content
    size_t msg_len;
    unsigned char *msg_content = read_file_content(message_file, &msg_len);
    if (!msg_content) DIE("Failed to read message file");

    // Compute Q_signer = H(signer_id)
    hash_id_to_G1(Q_signer, signer_id, pairing);

    // Compute h = H_Zr(message)
    hash_message_to_Zr(h, msg_content, msg_len, pairing);

    // Verification check: e(sigma, g) == e(Q_signer^h, P_pub)

    // Compute LHS: e(sigma, g)
    element_init_GT(lhs_GT, pairing);
    pairing_apply(lhs_GT, sigma, g, pairing);

    // Compute RHS: e(Q_signer^h, P_pub)
    element_init_G1(temp_G1, pairing);
    element_pow_zn(temp_G1, Q_signer, h); // temp_G1 = Q_signer^h

    element_init_GT(rhs_GT, pairing);
    pairing_apply(rhs_GT, temp_G1, P_pub, pairing);

    // Compare LHS and RHS
    if (!element_cmp(lhs_GT, rhs_GT)) {
        printf("Signature VALID.\n");
    } else {
        printf("Signature INVALID.\n");
    }

    // Cleanup
    free(msg_content);
    element_clear(g);
    element_clear(P_pub);
    element_clear(Q_signer);
    element_clear(h);
    element_clear(sigma);
    element_clear(temp_G1);
    element_clear(lhs_GT);
    element_clear(rhs_GT);
    pairing_clear(pairing);

    return 0;
}