// client/src/utils/cryptoUtilsJS.js

// --- Constants (Should ideally match KDC's cryptoUtils.js exports) ---
// These could potentially be fetched from a config endpoint or duplicated,
// but ensure they match the server implementation EXACTLY.
const KDF_ITERATIONS = 100000;
const KDF_KEYLEN_BITS = 256; // Key length for AES-256 in BITS
const KDF_HASH = 'SHA-512'; // SubtleCrypto uses standard names ('SHA-1', 'SHA-256', 'SHA-384', 'SHA-512')
const SALT_BYTES = 16;
const IV_BYTES = 12; // Standard for GCM
const AUTH_TAG_BYTES = 16; // Standard GCM tag length
const AES_ALGORITHM_NAME = 'AES-GCM';
const PBKDF2_ALG_NAME = 'PBKDF2';
// --- End Constants ---

/**
 * Parses the combined encrypted package.
 * Format: [Salt (16 bytes)][AuthTag (16 bytes)][IV (12 bytes)][Encrypted Data]
 * @param {Uint8Array} encryptedPackage - The combined data buffer.
 * @returns {{salt: Uint8Array, authTag: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array}}
 * @throws {Error} If the package is too short.
 */
const parseEncryptedPackage = (encryptedPackage) => {
    const minLength = SALT_BYTES + AUTH_TAG_BYTES + IV_BYTES;
    if (!encryptedPackage || encryptedPackage.length < minLength) {
        throw new Error(`Encrypted package is too short. Minimum length: ${minLength}, Received: ${encryptedPackage?.length}`);
    }

    let offset = 0;

    const salt = encryptedPackage.slice(offset, offset + SALT_BYTES);
    offset += SALT_BYTES;

    // IMPORTANT: SubtleCrypto's decrypt needs the tag length specified,
    // but it expects the tag to be *appended* to the ciphertext, not prepended.
    // We'll handle this later, but extract the tag now.
    const authTag = encryptedPackage.slice(offset, offset + AUTH_TAG_BYTES);
    offset += AUTH_TAG_BYTES;

    const iv = encryptedPackage.slice(offset, offset + IV_BYTES);
    offset += IV_BYTES;

    const ciphertext = encryptedPackage.slice(offset); // The rest is ciphertext

    console.debug("Parsed Package - Salt:", salt.length, "Tag:", authTag.length, "IV:", iv.length, "Ciphertext:", ciphertext.length);

    return { salt, authTag, iv, ciphertext };
};


/**
 * Decrypts the IBE private key using password and encrypted package.
 * Uses Web Crypto API (SubtleCrypto).
 * @param {string} password - The user's password.
 * @param {ArrayBuffer | Uint8Array} encryptedKeyPackage - The ArrayBuffer/Uint8Array containing the packaged data ([Salt][AuthTag][IV][Data]).
 * @returns {Promise<Uint8Array>} - Resolves with the raw decrypted private key (Uint8Array).
 * @throws {Error} If decryption or KDF fails.
 */
export const decryptKeyWithPasswordJS = async (password, encryptedKeyPackage) => {
    console.log("JS Decrypt: Starting key decryption...");
    const cryptoSubtle = window.crypto?.subtle;
    if (!cryptoSubtle) {
        throw new Error("Web Crypto API (SubtleCrypto) is not available in this browser.");
    }

    const packageUint8Array = (encryptedKeyPackage instanceof Uint8Array)
        ? encryptedKeyPackage
        : new Uint8Array(encryptedKeyPackage);

    // 1. Parse the package
    console.log("JS Decrypt: Parsing encrypted package...");
    const { salt, authTag, iv, ciphertext } = parseEncryptedPackage(packageUint8Array);

    // 2. Derive the AES key using PBKDF2
    console.log("JS Decrypt: Deriving AES key via PBKDF2...");
    let derivedAesKey;
    try {
        // Import the password as a base key material for PBKDF2
        const basePasswordKey = await cryptoSubtle.importKey(
            "raw",
            new TextEncoder().encode(password), // Convert password string to buffer
            { name: PBKDF2_ALG_NAME },
            false, // not extractable
            ["deriveKey"]
        );

        // Derive the AES key
        derivedAesKey = await cryptoSubtle.deriveKey(
            {
                name: PBKDF2_ALG_NAME,
                salt: salt, // Use the extracted salt
                iterations: KDF_ITERATIONS,
                hash: KDF_HASH, // Ensure this matches KDC digest
            },
            basePasswordKey, // Base key derived from password
            { name: AES_ALGORITHM_NAME, length: KDF_KEYLEN_BITS }, // Algorithm and length for the derived key
            true, // Allow export for debugging? Set false usually. true: allow key to be used for encrypt/decrypt
            ["decrypt"] // Key usage
        );
        console.log("JS Decrypt: AES key derived successfully.");
    } catch (kdfError) {
        console.error("JS Decrypt: PBKDF2 key derivation failed:", kdfError);
        throw new Error(`Key derivation failed. Check password or crypto parameters. (${kdfError.message})`);
    }

    // 3. Decrypt using AES-GCM
    console.log("JS Decrypt: Attempting AES-GCM decryption...");
    try {
        // SubtleCrypto AES-GCM implicitly verifies the tag.
        // It expects the tag appended to the ciphertext.
        // We need to concatenate our ciphertext and tag for the API call.
        const ciphertextWithTag = new Uint8Array(ciphertext.length + authTag.length);
        ciphertextWithTag.set(ciphertext, 0);
        ciphertextWithTag.set(authTag, ciphertext.length);

        const decryptedDataBuffer = await cryptoSubtle.decrypt(
            {
                name: AES_ALGORITHM_NAME,
                iv: iv, // Use the extracted IV
                // Optional: additionalAuthenticatedData: new Uint8Array(), // If you used AAD during encryption
                tagLength: AUTH_TAG_BYTES * 8, // tagLength must be in BITS (128 for 16 bytes)
            },
            derivedAesKey, // The key derived via PBKDF2
            ciphertextWithTag // Ciphertext with AuthTag appended
        );

        console.log("JS Decrypt: AES-GCM decryption successful (Tag Verified).");
        return new Uint8Array(decryptedDataBuffer); // Return the raw decrypted bytes

    } catch (decryptError) {
        console.error("JS Decrypt: AES-GCM decryption failed:", decryptError);
        // This error most commonly means the AuthTag verification failed (wrong password, wrong key, tampered data)
        throw new Error(`Decryption failed. Incorrect password or corrupted key file. (${decryptError.message})`);
    }
};