#include "bls_ibe_util.h" // Use the utility header
#include <pbc/pbc.h>

// No need for ibe.h here

#define PARAM_FILE "a.param"
#define PP_FILE "public_params.dat"
#define MSK_FILE "master_secret_key.dat"

int main() {
    pairing_t pairing;
    element_t g, P_pub, msk;

    // Initialize pairing using utility function
    initialize_pairing(pairing, PARAM_FILE);

    // Initialize elements
    element_init_G1(g, pairing);
    element_init_G1(P_pub, pairing);
    element_init_Zr(msk, pairing);

    // Generate parameters
    element_random(g);      // Generator g
    element_random(msk);    // Master Secret Key msk
    element_pow_zn(P_pub, g, msk); // Public Key P_pub = g^msk

    // Save public parameters (g, P_pub) - Use compressed format
    FILE *fp = fopen(PP_FILE, "wb");
    if (!fp) DIE("Failed to open public parameters file for writing");

    int g_len = element_length_in_bytes_compressed(g);
    int p_pub_len = element_length_in_bytes_compressed(P_pub);
    unsigned char *buf = malloc(g_len + p_pub_len);
    if (!buf) DIE("Malloc failed for public param save buffer");

    element_to_bytes_compressed(buf, g);
    element_to_bytes_compressed(buf + g_len, P_pub);

    if(fwrite(buf, 1, g_len + p_pub_len, fp) != (size_t)(g_len + p_pub_len)) {
        free(buf);
        fclose(fp);
        DIE("Failed to write public parameters");
    }
    free(buf);
    fclose(fp);

    // Save master secret key (msk) - Cannot compress Zr elements typically
     fp = fopen(MSK_FILE, "wb");
    if (!fp) DIE("Failed to open master secret key file for writing");

    int msk_len = element_length_in_bytes(msk);
    buf = malloc(msk_len);
     if (!buf) DIE("Malloc failed for msk save buffer");

    element_to_bytes(buf, msk);
    if(fwrite(buf, 1, msk_len, fp) != (size_t)msk_len) {
        free(buf);
        fclose(fp);
        DIE("Failed to write master secret key");
    }
    free(buf);
    fclose(fp);


    printf("Setup completed. Public parameters (%s) and master secret key (%s) saved.\n", PP_FILE, MSK_FILE);

    // Clear elements
    element_clear(g);
    element_clear(P_pub);
    element_clear(msk);
    pairing_clear(pairing);

    return 0;
}