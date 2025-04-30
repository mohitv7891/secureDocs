// client/src/components/FileUpload.jsx
import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

// --- Helper Functions ---
const readFileAsArrayBuffer = (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (event) => resolve(event.target.result);
        reader.onerror = (error) => reject(error);
        reader.readAsArrayBuffer(file);
    });
};

const passBufferToWasm = (Module, jsBuffer) => {
    if (!Module || typeof Module._malloc !== 'function' || !Module.HEAPU8) {
        throw new Error("Wasm module or its memory functions are not available.");
    }
    const data = (jsBuffer instanceof Uint8Array) ? jsBuffer : new Uint8Array(jsBuffer);
    const bufferPtr = Module._malloc(data.length);
    if (!bufferPtr) throw new Error(`Wasm malloc failed for size ${data.length}`);
    Module.HEAPU8.set(data, bufferPtr);
    return bufferPtr;
};

const getBufferFromWasm = (Module, bufferPtr, bufferLen) => {
    if (!Module || !Module.HEAPU32 || !Module.HEAPU8) {
         throw new Error("Wasm module or its memory functions are not available.");
    }
    if (!bufferPtr || bufferLen <= 0) return new Uint8Array(0);
    // Ensure the requested range is valid within the HEAP buffer
    if (bufferPtr + bufferLen > Module.HEAPU8.length) {
      console.error(`Wasm Memory Read Error: Attempting to read beyond HEAP boundary. Ptr: ${bufferPtr}, Len: ${bufferLen}, Heap Size: ${Module.HEAPU8.length}`);
      throw new Error("Wasm memory read out of bounds.");
    }
    return Module.HEAPU8.slice(bufferPtr, bufferPtr + bufferLen);
};
// --- End Helper Functions ---


// Accept wasmModule, publicParamsBuffer, and DECRYPTED private key buffer
const FileUpload = ({ wasmModule, publicParamsBuffer, decryptedPrivateKeyBuffer, onUploadSuccess }) => {
  const [file, setFile] = useState(null);
  const [recipientId, setRecipientId] = useState("");
  const [statusMessage, setStatusMessage] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const { apiClient, user } = useAuth(); // Get apiClient and user info for filename construction

  const handleFileChange = (e) => {
      setFile(e.target.files[0]);
      setStatusMessage("");
  };
  const handleRecipientChange = (e) => {
      setRecipientId(e.target.value);
      setStatusMessage(""); // Clear message on change
  };

  const handleUploadAndEncrypt = async () => {
    // --- Input Checks ---
    if (!file) { setStatusMessage("Please select a file."); return; }
    if (!recipientId.trim()) { setStatusMessage("Please enter a recipient ID (IIITA email)."); return; }
     if (!recipientId.trim().toLowerCase().endsWith('@iiita.ac.in')) {
       setStatusMessage("Error: Recipient must be a valid IIITA email address.");
       return;
    }
    if (!wasmModule) { setStatusMessage("Wasm module is not loaded yet."); return; }
    if (!publicParamsBuffer) { setStatusMessage("Public parameters are not loaded yet."); return; }
    // --- Check for the DECRYPTED private key buffer ---
    if (!decryptedPrivateKeyBuffer || !(decryptedPrivateKeyBuffer instanceof Uint8Array) || decryptedPrivateKeyBuffer.length === 0) {
         setStatusMessage("Your private key is not loaded or invalid. Please use the key loader first.");
         return;
    }
    // --- End Input Checks ---

    setIsProcessing(true);
    setStatusMessage("Processing file...");

    // Define WASM pointers - Initialize to null
    let wasmPrivKeyPtr = null, wasmMsgPtr = null, wasmSigPtr = null;
    let wasmSigLenPtr = null, wasmPubParamsPtr = null, wasmRecipientIdPtr = null;
    let wasmEncPtr = null, wasmEncULenPtr = null, wasmEncTotalLenPtr = null;

    try {
        setStatusMessage("Preparing signing key...");
        // Key is already a Uint8Array, no decoding needed
        console.log("Using decrypted private key buffer for signing (length):", decryptedPrivateKeyBuffer.length);

        setStatusMessage("Reading file...");
        const messageArrayBuffer = await readFileAsArrayBuffer(file);
        const messageUint8Array = new Uint8Array(messageArrayBuffer);
        console.log(`Read file: ${file.name}, size: ${messageUint8Array.length} bytes`);

        setStatusMessage("Preparing data for Wasm...");
        // Allocate memory for pointers to store output lengths from WASM
        wasmSigLenPtr = wasmModule._malloc(4);
        wasmEncULenPtr = wasmModule._malloc(4);
        wasmEncTotalLenPtr = wasmModule._malloc(4);
        if (!wasmSigLenPtr || !wasmEncULenPtr || !wasmEncTotalLenPtr) throw new Error("Malloc failed for output length pointers");

        // Allocate memory and copy data to WASM heap
        // --- Pass DECRYPTED key buffer to Wasm ---
        wasmPrivKeyPtr = passBufferToWasm(wasmModule, decryptedPrivateKeyBuffer);
        // --- End Pass Key ---
        wasmMsgPtr = passBufferToWasm(wasmModule, messageUint8Array);
        wasmPubParamsPtr = passBufferToWasm(wasmModule, publicParamsBuffer);
        const recipientIdBytes = new TextEncoder().encode(recipientId.trim() + '\0'); // Ensure null-terminated
        wasmRecipientIdPtr = passBufferToWasm(wasmModule, recipientIdBytes);

        // --- Signing ---
        setStatusMessage("Signing document...");
        console.log("Calling wasm_sign_buffer with decrypted key...");
        wasmSigPtr = wasmModule.ccall(
            'wasm_sign_buffer',
            'number', // return type: pointer (number)
            ['number', 'number', 'number', 'number', 'number'], // arg types: ptr, len, ptr, len, ptr_for_len_out
            [wasmPrivKeyPtr, decryptedPrivateKeyBuffer.length, // <-- Use buffer length
             wasmMsgPtr, messageUint8Array.length, wasmSigLenPtr]
        );
        if (!wasmSigPtr) throw new Error("Signing failed: wasm_sign_buffer returned null pointer.");
        const sigLen = wasmModule.HEAPU32[wasmSigLenPtr / 4]; // Get signature length output
        console.log(`Signing successful. Signature length: ${sigLen}`);
        if(sigLen <= 0) throw new Error("WASM signing returned invalid signature length.");
        const signatureUint8Array = getBufferFromWasm(wasmModule, wasmSigPtr, sigLen);

        // --- Encryption ---
        setStatusMessage("Encrypting document...");
        console.log("Calling wasm_encrypt_buffer...");
        wasmEncPtr = wasmModule.ccall(
            'wasm_encrypt_buffer',
            'number', // return type: pointer (number)
            ['number', 'number', 'number', 'number', 'number', 'number', 'number', 'number', 'number'], // arg types
            [wasmPubParamsPtr, publicParamsBuffer.length, wasmRecipientIdPtr, // Public params, recipient
             wasmMsgPtr, messageUint8Array.length, // Message data
             wasmSigPtr, sigLen, // Signature data
             wasmEncULenPtr, wasmEncTotalLenPtr] // Pointers for output lengths
        );
        if (!wasmEncPtr) throw new Error("Encryption failed: wasm_encrypt_buffer returned null pointer.");
        const encULen = wasmModule.HEAPU32[wasmEncULenPtr / 4]; // Get U length output
        const encTotalLen = wasmModule.HEAPU32[wasmEncTotalLenPtr / 4]; // Get total ciphertext length output
        console.log(`Encryption successful. U Len: ${encULen}, Total Ciphertext Len: ${encTotalLen}`);
        if(encULen <= 0 || encTotalLen <= encULen) throw new Error("WASM encryption returned invalid ciphertext lengths.");
        const encryptedUint8Array = getBufferFromWasm(wasmModule, wasmEncPtr, encTotalLen);

        // --- Prepare Upload Data ---
        setStatusMessage("Preparing upload...");
        const encryptedBlob = new Blob([encryptedUint8Array], { type: 'application/octet-stream' });
        const uploadFormData = new FormData();
        // Construct a filename (optional: adjust as needed)
        const senderUsername = user?.email?.split('@')[0] || 'unknown_sender';
        const recipientUsername = recipientId.trim().split('@')[0];
        const uploadFilename = `${senderUsername}_to_${recipientUsername}_${file.name}.enc`;

        uploadFormData.append("encryptedFile", encryptedBlob, uploadFilename);
        uploadFormData.append("recipientId", recipientId.trim());

        // --- Upload using apiClient ---
        setStatusMessage("Uploading encrypted document...");
        console.log("Sending encrypted data to Data Server (port 5006)...");

        // Use the apiClient from AuthContext (already includes Authorization header via interceptor)
        const response = await apiClient.post(
            "/files/upload-encrypted", // Relative path to Data Server API
            uploadFormData,
            { headers: { "Content-Type": "multipart/form-data" } } // Required for FormData
        );

        setStatusMessage(`Upload successful: ${response.data.message}`);
        console.log("Upload response:", response.data);

        // Clear form and optionally notify parent on success
        setFile(null);
        const fileInput = document.getElementById('file-upload'); // Make sure input has this ID
        if (fileInput) fileInput.value = ''; // Clear file input display
        setRecipientId("");
        if (onUploadSuccess) onUploadSuccess();

    } catch (error) {
      console.error("Processing or Upload failed:", error);
      const backendErrorMessage = error.response?.data?.message;
      setStatusMessage(`Error: ${backendErrorMessage || error.message || 'Processing/Upload failed!'}`);
    } finally {
      // --- Cleanup Wasm Memory ---
      console.log("Cleaning up Wasm memory for FileUpload...");
      try { // Wrap cleanup in try/catch
          if (wasmSigPtr && wasmModule) wasmModule.ccall('wasm_free_buffer', null, ['number'], [wasmSigPtr]);
          if (wasmEncPtr && wasmModule) wasmModule.ccall('wasm_free_buffer', null, ['number'], [wasmEncPtr]);
          if (wasmSigLenPtr && wasmModule) wasmModule._free(wasmSigLenPtr);
          if (wasmEncULenPtr && wasmModule) wasmModule._free(wasmEncULenPtr);
          if (wasmEncTotalLenPtr && wasmModule) wasmModule._free(wasmEncTotalLenPtr);
          if (wasmPrivKeyPtr && wasmModule) wasmModule._free(wasmPrivKeyPtr); // Free the key pointer
          if (wasmMsgPtr && wasmModule) wasmModule._free(wasmMsgPtr);
          if (wasmPubParamsPtr && wasmModule) wasmModule._free(wasmPubParamsPtr);
          if (wasmRecipientIdPtr && wasmModule) wasmModule._free(wasmRecipientIdPtr);
      } catch(cleanupError) {
          console.error("Error during WASM memory cleanup:", cleanupError);
      }
      // --- End Cleanup ---
      setIsProcessing(false);
    }
  };

  // --- Render Logic ---
  // Determine button state and text based on prerequisites
  const isButtonDisabled = isProcessing || !wasmModule || !decryptedPrivateKeyBuffer || !file || !recipientId.trim();
  let buttonText = 'Sign, Encrypt & Upload';
  if (isProcessing) buttonText = 'Processing...';
  else if (!wasmModule) buttonText = 'Wasm Loading...';
  else if (!decryptedPrivateKeyBuffer) buttonText = 'Key Unavailable - Load Key First';
  else if (!file) buttonText = 'Select File';
  else if (!recipientId.trim()) buttonText = 'Enter Recipient';

  return (
    <div className="bg-white p-6 rounded-lg shadow-md mb-6"> {/* Added mb-6 */}
      <h2 className="text-lg font-semibold mb-4">Upload & Encrypt Document</h2>
      {/* File Input */}
      <div className="mb-4">
          <label htmlFor="file-upload" className="block text-sm font-medium text-gray-700 mb-1">Select File:</label>
          <input
            id="file-upload"
            type="file"
            onChange={handleFileChange}
            className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 disabled:opacity-50"
            disabled={isProcessing}
           />
      </div>

      {/* Recipient Input */}
       <div className="mb-4">
          <label htmlFor="recipient-id" className="block text-sm font-medium text-gray-700 mb-1">Recipient ID (IIITA Email):</label>
          <input
            id="recipient-id"
            type="email" // Use type email for basic validation
            value={recipientId}
            onChange={handleRecipientChange}
            placeholder="recipient@iiita.ac.in"
            className="border border-gray-300 p-2 rounded w-full focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
            disabled={isProcessing}
           />
      </div>

      {/* Upload Button - Updated disabled logic and text */}
      <button
        onClick={handleUploadAndEncrypt}
        disabled={isButtonDisabled}
        className={`w-full text-white px-4 py-2 rounded transition duration-150 ease-in-out ${isButtonDisabled ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'}`}
      >
        {buttonText}
      </button>

      {/* Status Message */}
      {statusMessage && (
          <p className={`mt-4 text-sm font-medium ${statusMessage.startsWith('Error:') || statusMessage.startsWith('Key Unavailable') ? 'text-red-600' : 'text-green-600'}`}>
              {statusMessage}
          </p>
      )}
    </div>
  );
};

export default FileUpload;