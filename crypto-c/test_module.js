// File: /miniProject/dev/crypto-wasm-test/test_module.js
// Focus: Decrypt data from MongoDB and verify signature.
const fs = require('fs');
const assert = require('assert');

// Import the factory function created by Emscripten's MODULARIZE flag
const createCryptoModule = require('./crypto_module.js');

// --- Helper Function to Load File as Buffer ---
function loadFileBuffer(filePath) {
    try {
        return fs.readFileSync(filePath);
    } catch (err) {
        console.error(`Error reading file ${filePath}:`, err);
        process.exit(1); // Exit if essential files are missing
    }
}

// --- Helper Function to Manage Wasm Memory for Buffers ---
function passBufferToWasm(Module, jsBuffer) {
    // Ensure input is a Buffer or Uint8Array
    const data = Buffer.isBuffer(jsBuffer) ? jsBuffer : Buffer.from(jsBuffer);
    const bufferPtr = Module._malloc(data.length);
    if (!bufferPtr) throw new Error(`Wasm malloc failed for size ${data.length}`);
    // Module.HEAPU8 is a view into the Wasm memory (Uint8Array)
    Module.HEAPU8.set(data, bufferPtr);
    return bufferPtr;
}

// --- Helper Function to Read Output Buffer from Wasm ---
function getBufferFromWasm(Module, bufferPtr, bufferLen) {
    if (!bufferPtr || bufferLen <= 0) return new Uint8Array(0);
    // Create a Uint8Array view onto the specific part of the Wasm heap
    // slice() creates a copy, so it's safe even after freeing Wasm memory
    return Module.HEAPU8.slice(bufferPtr, bufferPtr + bufferLen);
}

// --- Main Test Logic ---
async function runTests() {
    console.log("Loading Wasm module...");
    const Module = await createCryptoModule(); // Instantiate the module
    console.log("Module loaded.");

    // --- Configuration ---
    const recipientKeyFile = 'moh@iiitb_private_key.dat'; // Key matching recipientId in DB
    const recipientId = "moh@iiitb"; // Matches DB record
    // const senderId_from_db = "test_sender_id"; // ID stored in DB (placeholder)
    const actualSignerId = "mohit@iiita"; // The ID whose key was USED to sign the doc originally
    const originalSourceFile = 'DLL.c'; // The original file to compare against

    // --- Base64 Encrypted Data (from MongoDB) ---
    const encryptedDataB64 = "ZXacqo+9ULuv8/QvMtgrSYkK3YqYM8Myvv0V9Q8v4UxZFQe79IBZQ268zycuxHoENvqdV5vDgIa6BS5EGP0cHwAI6pX/FGV91erXwmiqRLL+NMRL4fEoxuun7JU64jeS5fX2+RCpolPYrZh4gqNpByobIJNzx9+06dwOitdEtVReCgDIutiC1cxR6EL9GhIJwmmNfx2RxOS0zJXMev5IxE5jPcy7VFimQUSUdCjAYS4035mOmFOdFvwQdCFewyloGweWQb9T1WwGiE7HiFbi2FUARlFzEMdxLEeX6Sxss0BgXaL4+OtjrYFivJg7dGvWEfbseYaTeqKF1XKxHuxVXmZsp4i5AaTG+YSE2im4wFUIaW+zCPAsQeD1vLxzofSI+mRkenClf2RIajDxVqxFGqK6gjCUiabyFigIwkDbtOwCUNLw587wGh2KIwMOqbYTMAXJaHey5o8fnmMRUz4+PW1hrmJoPggRp+fXS2GqgfNWzRdvxXO/w0Bz39ryrJkoaoZYlCK859d6E8NmYdGj0uR9FNwun9TOE7Cc5dnsGnMfWtEEnafncHdRwI51gU8j1qJihRkB6uIdsnQxPXi1Gs6os3JwNT0GhhoF6P6iUQWorr4Vo5N60mwy5M4LOmSSoNns3e4UqihvIc0VaMZIoJIC4z6CgvoMnN+IYlA8A1KuzPYR2aiisLR7A6o4gcxuf6vkPj5n2f7i+Ticl6xg3CzZXXmuYakUjbqfdmQZ0i/Dl2GTOrrRgZxjoD/6+5UZdNypwAYTb71fjiNAiCQti4CqeN6OCPCvyJVzNDSm4kPEII/YiylCIwNoL8w2zsA8DaHS21mh6AjbO0Yq88VtwGPZT0eHHrzIqtXqd7n3kIx4r8WEvTzFXgVnPrlGDuZuYr9PFini/vFGc2+x6EA8Wkp4PRkMiQI60FkIHwwRmrateMSMLkP2BP/IkVlNZXDbSnS8utxhQqghRWjpPjt89SAM+JigHwhRlmO0G4Z38G/9AOKp8Lag4SvAnEY6pZQSwMyDmDmNZILBzQWpzYi1tHkv05ACSR0EiPjJOL32olFPHaFOVa0AVytxdEkCtQzb+Q2atQTcJ9qwxutI5BvaNzXM5bppsD3UtvaE0Qp/WURytCOJgBHUCzPv0uxxJ4knUBtqqb8xNO+1YxeXXUaL7+WyJOWCynt5CWCYOFowlTwBgEob1nRQJtnYQraPINxExh0KntVYesErmF8uiOmQyHGWRvTdL6ttWiQrvX1hiFOG9Gpn8UHAa31G0wY7TICoklBcelpFpNvi5r1GE5zhCqwVC12qvDGLwZT2vYRJyry+rp+E2zL0c3WiRcms9gInj/hljiNuIhfeUN8qDtWncbr0ba62/5AOtqW8NcDf0S5Z8RiseSnKbwLFSkWaPF4KpfQyEEsT9VPwpSslm4Q4GS13uuE0GkP2MTNcM8PxMFjIKoLdvmTTIUn4IaZ6qgx/mI0nMIeEGX+s3jSpeRJTk7zDI02M2Qazydz41Kl8Cv1U8kqbNCdpVO3OfpcH4H2df1ReUB7kYG4MXJMo+/djr08RTU/5/0e0VMjIMRaSuprIRPLxHieF";

    // --- Load Necessary Files ---
    console.log("Loading parameters and keys...");
    const pairingParamsBuf = loadFileBuffer('a.param');
    const pubParamsBuf = loadFileBuffer('public_params.dat');
    const recipientPrivKeyBuf = loadFileBuffer(recipientKeyFile);
    const originalFileBuf = loadFileBuffer(originalSourceFile); // Load original DLL.c

    // --- Prepare Wasm Virtual Filesystem ---
    console.log("Creating /a.param in Wasm virtual filesystem...");
    try {
        Module.FS_createDataFile('/', 'a.param', pairingParamsBuf, true, false);
        console.log("/a.param created successfully.");
    } catch(e) {
        console.error("Error creating file in Wasm FS:", e);
    }

    // --- Test Variables ---
    let decPtr = null;
    let decLen = 0;
    let decLenPtr = null;
    let decryptedBuffer = null; // Will hold JS Uint8Array copy of plaintext (Msg||Sig)

    // Pointers for Wasm memory allocated from JS
    let wasmRecipientKeyPtr = null;
    let wasmPubParamsPtr = null;
    let wasmSignerIdPtr = null; // Renamed for clarity in verification step
    let wasmEncUPtr = null;
    let wasmEncVPtr = null;
    let wasmDecMsgPtr = null;
    let wasmDecSigPtr = null;

    try {
        // === Decode Base64 Data ===
        console.log("Decoding Base64 encrypted data...");
        const encryptedBuffer = Buffer.from(encryptedDataB64, 'base64');
        console.log(`Decoded data length: ${encryptedBuffer.length}`);

        // === Allocate memory in Wasm for output length ===
        decLenPtr = Module._malloc(4);
        if (!decLenPtr) throw new Error("Malloc failed for output length pointer");

        // === Split U || V ===
        // Use known/assumed compressed G1 element size
        const uLen = 65; // Hardcoded based on previous observation - IMPROVE THIS LATER!
        console.log(`Using assumed U length: ${uLen}`);

        if (uLen <= 0 || uLen >= encryptedBuffer.length) {
            throw new Error(`Invalid U length assumption or encrypted data length: U len=${uLen}, Total len=${encryptedBuffer.length}`);
        }
        const vLen = encryptedBuffer.length - uLen;
        const uData = encryptedBuffer.slice(0, uLen);
        const vData = encryptedBuffer.slice(uLen);
        console.log(`Split ciphertext: U len=${uLen}, V len=${vLen}`);

        // === Allocate memory in Wasm for inputs and copy data ===
        console.log("Allocating memory and copying data to Wasm heap...");
        wasmRecipientKeyPtr = passBufferToWasm(Module, recipientPrivKeyBuf);
        wasmPubParamsPtr = passBufferToWasm(Module, pubParamsBuf);
        // Allocate sender ID later when needed for verification
        wasmEncUPtr = passBufferToWasm(Module, uData);
        wasmEncVPtr = passBufferToWasm(Module, vData);
        console.log("Data copied.");

        // === 1. Test Decryption ===
        console.log(`\n--- Testing Decryption (as User: ${recipientId}) ---`);
        decPtr = Module.ccall(
            'wasm_decrypt_buffer', 'number',
            ['number', 'number', 'number', 'number', 'number', 'number', 'number'],
            [wasmRecipientKeyPtr, recipientPrivKeyBuf.length, wasmEncUPtr, uLen, wasmEncVPtr, vLen, decLenPtr]
        );

        if (!decPtr) { throw new Error("wasm_decrypt_buffer returned NULL."); }
        decLen = Module.HEAPU32[decLenPtr / 4];
        console.log(`Decryption successful. Plaintext (Msg||Sig) length: ${decLen}`);
        assert(decLen > 0, "Decrypted length should be > 0");
        decryptedBuffer = getBufferFromWasm(Module, decPtr, decLen);

        // === 2. Split Message || Signature ===
        // Use known/assumed compressed G1 element size for signature
        const sigLenExpected = 65; // Hardcoded based on previous observation - IMPROVE THIS LATER!
        console.log(`Using assumed signature length: ${sigLenExpected}`);

         if (sigLenExpected <= 0 || sigLenExpected > decLen) {
            throw new Error(`Invalid Sig length assumption or decrypted length: Sig len=${sigLenExpected}, Total len=${decLen}`);
        }
        const msgLen = decLen - sigLenExpected;
        const messageData = decryptedBuffer.slice(0, msgLen);
        const signatureData = decryptedBuffer.slice(msgLen);
        console.log(`Split plaintext: Msg len=${msgLen}, Sig len=${sigLenExpected}`);

        // === 3. Compare Decrypted Message with Original ===
        console.log(`\n--- Comparing decrypted message with original ${originalSourceFile} ---`);
        assert.deepStrictEqual(Buffer.from(messageData), originalFileBuf, `Decrypted message content does not match original ${originalSourceFile}!`);
        console.log("Decrypted message content MATCHES original file.");

        // === 4. Test Verification ===
        console.log(`\n--- Testing Verification (${recipientId} verifies ${actualSignerId}) ---`); // Log actual signer ID
        // ** Use the ACTUAL SIGNER ID for verification **
        wasmSignerIdPtr = passBufferToWasm(Module, Buffer.from(actualSignerId + '\0', 'utf8'));
        wasmDecMsgPtr = passBufferToWasm(Module, messageData);
        wasmDecSigPtr = passBufferToWasm(Module, signatureData);

        const verifyResult = Module.ccall(
            'wasm_verify_buffer', 'number',
            ['number', 'number', 'number', 'number', 'number', 'number', 'number'],
            // Pass the correct signer ID pointer
            [wasmPubParamsPtr, pubParamsBuf.length, wasmSignerIdPtr, wasmDecMsgPtr, messageData.length, wasmDecSigPtr, signatureData.length]
        );
        console.log(`Verification result (${recipientId} verifies ${actualSignerId}): ${verifyResult}`);
        assert.strictEqual(verifyResult, 0, `Verification by ${recipientId} should be VALID (0)`);

        console.log("\n✅ ✅ ✅ DECRYPTION & VERIFICATION TEST PASSED! ✅ ✅ ✅");

    } catch (error) {
        console.error("\n❌ TEST FAILED:", error);
    } finally {
        // === Cleanup Wasm Memory ===
        console.log("\n--- Cleaning up Wasm memory ---");
        if (decPtr) Module.ccall('wasm_free_buffer', null, ['number'], [decPtr]);
        if (decLenPtr) Module._free(decLenPtr);
        if (wasmRecipientKeyPtr) Module._free(wasmRecipientKeyPtr);
        if (wasmPubParamsPtr) Module._free(wasmPubParamsPtr);
        if (wasmSignerIdPtr) Module._free(wasmSignerIdPtr); // Changed name from wasmSenderIdPtr
        if (wasmEncUPtr) Module._free(wasmEncUPtr);
        if (wasmEncVPtr) Module._free(wasmEncVPtr);
        if (wasmDecMsgPtr) Module._free(wasmDecMsgPtr);
        if (wasmDecSigPtr) Module._free(wasmDecSigPtr);
    }
}

// Run the tests
runTests();

