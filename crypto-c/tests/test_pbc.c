#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("Testing basic pairing functionality...\n");
    
    // Initialize pairing with complete (but small) Type A parameters
    pairing_t pairing;
    char param[] = 
        "type a\n"
        "q 4025338979\n"          // A small prime
        "h 6279784459\n"          // Group order
        "r 641\n"                 // Subgroup order
        "exp2 159\n"
        "exp1 107\n"
        "sign1 1\n"
        "sign0 1\n";

    if (pairing_init_set_buf(pairing, param, strlen(param))) {
        printf("Error initializing pairing\n");
        return 1;
    }

    // Declare elements
    element_t P, Q, result;
    
    // Initialize elements
    element_init_G1(P, pairing);
    element_init_G2(Q, pairing);
    element_init_GT(result, pairing);

    printf("Generating random points...\n");
    element_random(P);
    element_random(Q);

    printf("Computing pairing...\n");
    pairing_apply(result, P, Q, pairing);
    
    if (!element_is0(result)) {
        printf("SUCCESS: Pairing computation worked (result is non-zero)\n");
    } else {
        printf("WARNING: Pairing returned zero (unexpected)\n");
    }

    // Clean up
    element_clear(P);
    element_clear(Q);
    element_clear(result);
    pairing_clear(pairing);

    return 0;
}
