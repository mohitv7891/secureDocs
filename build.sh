#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e


echo "--- Starting custom build process for KDC Server ---"

# 1. Install Node.js dependencies
echo "--- (1/3) Installing Node.js dependencies for KDC... ---"
(cd kdc && npm install)

# 2. Compile the native 'keygen' executable for the Render (Linux) environment
echo "--- (2/3) Compiling native keygen executable... ---"

# Define source files, output path, and library/include paths
# These paths are relative to the repository root where this script is run.
KEYGEN_SOURCES="crypto-c/src/keygen.c crypto-c/src/ibe.c crypto-c/src/bls_ibe_util.c"
OUTPUT_EXEC="kdc/opt/crypto-native/keygen"
INCLUDE_PATH="crypto-c/wasm-libs/include"
LIBRARY_PATH="crypto-c/wasm-libs/lib"

# The GCC command to compile and link the executable
# -o: specifies the output file
# -I: specifies the include directory for headers (.h files)
# -L: specifies the library directory for linking (.a, .so files)
# -l...: specifies the libraries to link against (crypto, pbc, gmp)
gcc -o $OUTPUT_EXEC $KEYGEN_SOURCES -I$INCLUDE_PATH -L$LIBRARY_PATH -lcrypto -lpbc -lgmp

# 3. Make the newly compiled binary executable
echo "--- (3/3) Setting execute permissions on compiled keygen... ---"
chmod +x $OUTPUT_EXEC

echo "--- Custom build process completed successfully! ---"
