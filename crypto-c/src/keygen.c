#include "bls_ibe_util.h" // Use the utility header
#include <pbc/pbc.h>
#include <stdio.h> // For FILENAME_MAX if used

#define PARAM_FILE "a.param"
#define MSK_FILE "master_secret_key.dat"
// Define a max path length if FILENAME_MAX is not suitable everywhere
#define MAX_FILENAME_LEN 512

int main(int argc, char **argv) {
    // Usage remains the same
    if (argc != 2) { // Correct check for 1 argument
        fprintf(stderr, "Usage: %s <identity>\n", argv[0]);
        return 1;
    }
    const char *ID = argv[1];

    pairing_t pairing;
    element_t Q_id, msk, private_key; // Q_id = H(ID)

    // Initialize pairing
    initialize_pairing(pairing, PARAM_FILE);

    // Load master secret key
    load_master_secret(pairing, msk, MSK_FILE);

    // Generate private key: d = H(ID)^msk
    hash_id_to_G1(Q_id, ID, pairing); // Q_id = H(ID)

    element_init_G1(private_key, pairing);
    element_pow_zn(private_key, Q_id, msk); // private_key = Q_id ^ msk

    // Save private key to file (e.g., alice_private_key.dat)
    // Filename is generated automatically based on ID
    char private_key_file[MAX_FILENAME_LEN];
    int len_written = snprintf(private_key_file, sizeof(private_key_file), "%s_private_key.dat", ID);
     if (len_written < 0 || (size_t)len_written >= sizeof(private_key_file)) {
        fprintf(stderr, "Error: User ID '%s' is too long for filename buffer.\n", ID);
        exit(EXIT_FAILURE);
    }

    save_user_private_key(private_key, private_key_file); // Use utility

    // Updated printf to show the generated filename
    printf("Private key for identity '%s' generated and saved to '%s'.\n", ID, private_key_file);

    // Clear elements
    element_clear(Q_id);
    element_clear(msk);
    element_clear(private_key);
    pairing_clear(pairing);

    return 0;
}
