// kgs/utils/executeKeygen.js
const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs').promises; // Use fs promises module

// Configuration - Read paths from environment variables set FOR THE KGS SERVER
const NATIVE_CRYPTO_DIR = process.env.NATIVE_CRYPTO_DIR;
const KEYGEN_EXEC = process.env.NATIVE_KEYGEN_EXEC || 'keygen'; // Default name

// Basic validation for required environment variables
if (!NATIVE_CRYPTO_DIR) {
    console.error("FATAL KGS ERROR: NATIVE_CRYPTO_DIR environment variable is not set.");
    // Throwing here will prevent the KGS from starting if the config is bad
    throw new Error("KGS Server configuration error: NATIVE_CRYPTO_DIR not set.");
}

const keygenExecutablePath = path.join(NATIVE_CRYPTO_DIR, KEYGEN_EXEC);

/**
 * Executes the native C keygen program (which writes a temporary file),
 * reads the generated key file content into a Buffer, deletes the key file,
 * and returns the key content Buffer.
 * Intended for use by the KGS server for on-demand key generation.
 *
 * @param {string} emailId - The user's email ID to generate the key for.
 * @returns {Promise<Buffer>} - Resolves with the key content Buffer on success.
 * @throws {Error} - Throws an error if key generation, file reading, or file deletion fails.
 */
async function executeKeygen(emailId) {
    // Validate emailId format briefly before passing to executable
    if (!emailId || typeof emailId !== 'string' || !/^[a-zA-Z0-9@._-]+$/.test(emailId)) {
         console.error(`executeKeygen Error: Invalid emailId format received: ${emailId}`);
        throw new Error("Invalid email format provided for key generation.");
    }

    console.log(`executeKeygen (KGS): Generating temporary key for: ${emailId}`);
    // Determine the expected temporary key filename WITHIN NATIVE_CRYPTO_DIR
    const tempKeyFilename = `${emailId}_private_key.dat`;
    const tempKeyPath = path.join(NATIVE_CRYPTO_DIR, tempKeyFilename);
    console.log(`executeKeygen (KGS): Expecting temporary key file at: ${tempKeyPath}`);

    return new Promise((resolve, reject) => {
        // Execute the C binary within NATIVE_CRYPTO_DIR
        // This assumes keygen needs a.param and master_secret_key.dat in its CWD
        execFile(keygenExecutablePath, [emailId], { cwd: NATIVE_CRYPTO_DIR, timeout: 5000 }, // 5 second timeout
            async (error, stdout, stderr) => {
                // Callback after C process finishes
                if (error) {
                    console.error(`executeKeygen (KGS): Keygen execution failed for ${emailId}. Code: ${error.code}, Signal: ${error.signal}`);
                    if (stderr) console.error(`executeKeygen (KGS): Stderr: ${stderr}`);
                    if (stdout) console.error(`executeKeygen (KGS): Stdout (on error): ${stdout}`);
                    // Attempt cleanup just in case file was partially created
                    try { await fs.unlink(tempKeyPath); } catch (e) { /* ignore cleanup error */ }
                    // Reject with a specific error
                    return reject(new Error(`Key generation C process failed for user ${emailId}.`));
                }

                // Log C process output even on success for debugging
                if (stderr) console.warn(`executeKeygen (KGS): Stderr (on success): ${stderr}`);
                if (stdout) console.log(`executeKeygen (KGS): Stdout (on success): ${stdout}`);
                console.log(`executeKeygen (KGS): Keygen C process completed successfully for ${emailId}.`);

                // Now, read the content of the generated temporary file
                let keyBuffer;
                try {
                    console.log(`executeKeygen (KGS): Reading temporary key file from: ${tempKeyPath}`);
                    keyBuffer = await fs.readFile(tempKeyPath);
                    if (!keyBuffer || keyBuffer.length === 0) {
                         // Throw if file is empty
                         throw new Error("Generated key file is empty.");
                    }
                    console.log(`executeKeygen (KGS): Successfully read key file (length: ${keyBuffer.length})`);

                } catch (readError) {
                    console.error(`executeKeygen (KGS): Failed to read temporary key file ${tempKeyPath} after successful C execution:`, readError);
                    // Attempt cleanup just in case file exists but is unreadable
                    try { await fs.unlink(tempKeyPath); } catch (e) { /* ignore cleanup error */ }
                    // Reject with specific error
                    return reject(new Error(`Failed to read temporary key file for ${emailId}.`));
                }

                // --- IMPORTANT: Delete the temporary key file ---
                try {
                    await fs.unlink(tempKeyPath);
                    console.log(`executeKeygen (KGS): Successfully deleted temporary key file: ${tempKeyPath}`);
                } catch (deleteError) {
                    console.error(`executeKeygen (KGS): CRITICAL - Failed to delete temporary key file ${tempKeyPath}:`, deleteError);
                    // Decide how critical this is. Failing to delete leaks the key file.
                    // Rejecting might prevent key delivery, but highlights a cleanup issue.
                    return reject(new Error(`Failed to clean up temporary key file for ${emailId}.`));
                }
                // --- End Deletion ---

                // If read and delete were successful, resolve with the key content
                resolve(keyBuffer);

            }); // End execFile callback
    }); // End Promise constructor
}

module.exports = executeKeygen;