// kdc/utils/cryptoUtils.js
const crypto = require('crypto');

// --- Keep existing constants ---
const KDF_ITERATIONS = 100000;
const KDF_KEYLEN = 32;
const KDF_DIGEST = 'sha512';
const SALT_BYTES = 16;
const IV_BYTES = 12;
const AES_ALGORITHM = 'aes-256-gcm';
const AUTH_TAG_BYTES = 16; // Standard for AES-GCM

/**
 * Derives a key from a password using PBKDF2.
 * @param {string} password - The user's password.
 * @param {Buffer} salt - A unique salt for the user.
 * @returns {Promise<Buffer>} - The derived key.
 */
const deriveKey = (password, salt) => {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, KDF_ITERATIONS, KDF_KEYLEN, KDF_DIGEST, (err, derivedKey) => {
            if (err) return reject(err);
            resolve(derivedKey);
        });
    });
};

/**
 * Encrypts data using AES-256-GCM.
 * @param {Buffer} data - The data to encrypt (e.g., raw private key).
 * @param {Buffer} key - The AES encryption key (derived from password).
 * @returns {{iv: Buffer, encryptedData: Buffer, authTag: Buffer}} - IV, encrypted data, and GCM auth tag.
 */
const encryptAES = (data, key) => {
    const iv = crypto.randomBytes(IV_BYTES);
    const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv);
    const encryptedData = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return { iv, encryptedData, authTag };
};

/**
 * Creates a combined buffer for storage/transmission.
 * Format: [Salt (16 bytes)][AuthTag (16 bytes)][IV (12 bytes)][Encrypted Data]
 * @param {Buffer} salt - The KDF salt used.
 * @param {Buffer} iv - The AES IV used.
 * @param {Buffer} encryptedData - The AES encrypted payload.
 * @param {Buffer} authTag - The AES-GCM authentication tag.
 * @returns {Buffer}
 */
const packageEncryptedData = (salt, iv, encryptedData, authTag) => {
    // Validate inputs (basic length checks)
    if (salt.length !== SALT_BYTES) throw new Error('Invalid salt length for packaging');
    if (iv.length !== IV_BYTES) throw new Error('Invalid IV length for packaging');
    if (authTag.length !== AUTH_TAG_BYTES) throw new Error('Invalid authTag length for packaging');

    // Prepend Salt to the previous format
    return Buffer.concat([salt, authTag, iv, encryptedData]); // Salt first
};

module.exports = {
    deriveKey,
    encryptAES,
    packageEncryptedData,
    SALT_BYTES,
    IV_BYTES,       // Export needed lengths for client constants
    AUTH_TAG_BYTES, // Export needed lengths for client constants
    KDF_ITERATIONS, // Export needed constants for client KDF
    KDF_KEYLEN,     // Export needed constants for client KDF
    KDF_DIGEST,     // Export needed constants for client KDF
    AES_ALGORITHM,  // Export needed constants for client AES
};