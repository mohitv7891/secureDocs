// client/components/FileList.jsx
import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

// --- Helper Functions ---
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

const base64ToUint8Array = (base64) => {
    try {
        if (base64 === null || typeof base64 === 'undefined') throw new Error("Input is null or undefined.");
        if (typeof base64 !== 'string') throw new Error(`Input must be a string, got ${typeof base64}`);
        const binaryString = window.atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) { bytes[i] = binaryString.charCodeAt(i); }
        return bytes;
    } catch (e) {
        console.error("Error decoding base64:", e);
        throw e; // Re-throw original error
    }
};

const uint8ArrayToString = (buffer) => {
  try {
    // Attempt UTF-8 decoding
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch (e) {
    console.warn("Failed to decode buffer as UTF-8:", e);
    // Fallback for non-text data
    return "[Binary data - Use Download button]";
  }
};

const getBaseFilename = (encryptedFilename) => {
    if (!encryptedFilename) return "downloaded_file";
    let name = encryptedFilename;
    // Try removing a potential recipient ID pattern like '.recipient@email.com.enc'
    // This looks for a dot, then typical email chars, then '.enc' at the end
    const pattern1 = /\.[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\.enc$/;
    if (pattern1.test(name)) {
        name = name.replace(pattern1, '');
    } else {
        // Fallback: just remove .enc if the complex pattern didn't match
        name = name.endsWith('.enc') ? name.slice(0, -4) : name;
    }
    // Further fallback if the name becomes empty (unlikely)
    return name || "decrypted_file";
};
// --- End Helper Functions ---


// Accept wasmModule, publicParamsBuffer, and DECRYPTED key buffer
const FileList = ({ files = [], wasmModule, publicParamsBuffer, decryptedPrivateKeyBuffer }) => {
  const { apiClient } = useAuth(); // Use apiClient for download fetch
  const [selectedFileId, setSelectedFileId] = useState(null); // Track which file is being processed
  const [decryptionStatus, setDecryptionStatus] = useState({}); // Store status per file ID
  const [decryptedContent, setDecryptedContent] = useState({}); // Store preview per file ID
  const [decryptedBuffer, setDecryptedBuffer] = useState({}); // Store raw buffer per file ID
  const [decryptedFilename, setDecryptedFilename] = useState({}); // Store filename per file ID
  const [verificationResult, setVerificationResult] = useState({}); // Store verification per file ID
  const [isProcessing, setIsProcessing] = useState({}); // Track processing state per file ID

  const updateFileState = (fileId, updates) => {
      setDecryptionStatus(prev => ({ ...prev, [fileId]: updates.status ?? prev[fileId] }));
      setVerificationResult(prev => ({ ...prev, [fileId]: updates.verification ?? prev[fileId] }));
      setDecryptedContent(prev => ({ ...prev, [fileId]: updates.content ?? prev[fileId] }));
      setDecryptedBuffer(prev => ({ ...prev, [fileId]: updates.buffer ?? prev[fileId] }));
      setDecryptedFilename(prev => ({ ...prev, [fileId]: updates.filename ?? prev[fileId] }));
      setIsProcessing(prev => ({ ...prev, [fileId]: updates.processing ?? prev[fileId] }));
  };

  const handleDecryptAndVerify = async (documentId, senderId, originalFileName) => {
    setSelectedFileId(documentId); // Track the currently selected file
    // Reset state for this specific file
    updateFileState(documentId, {
        status: `Preparing for ${originalFileName}...`,
        verification: "",
        content: "",
        buffer: null,
        filename: "",
        processing: true
    });

    // --- Prerequisites Check ---
    if (!wasmModule || !publicParamsBuffer) {
        updateFileState(documentId, { status: "Error: Wasm/Params not ready.", processing: false });
        return;
     }
    if (!documentId || !senderId) {
        updateFileState(documentId, { status: "Error: Missing document/sender ID.", processing: false });
        return;
    }
    // --- Check for DECRYPTED Key Buffer ---
    if (!decryptedPrivateKeyBuffer || !(decryptedPrivateKeyBuffer instanceof Uint8Array) || decryptedPrivateKeyBuffer.length === 0) {
        alert("Your private key is not loaded. Please use the key loader form above.");
        updateFileState(documentId, { status: "Error: Private key not loaded.", processing: false });
        return;
    }
    // --- End Prerequisites Check ---

    // Wasm Memory Pointers - Initialize to null
    let wasmPrivKeyPtr = null, wasmCiphertextPtr = null, wasmDecPtr = null;
    let wasmDecLenPtr = null, wasmSigLenPtr = null, wasmPubParamsPtr = null;
    let wasmSenderIdPtr = null, wasmMsgDataPtr = null, wasmSigDataPtr = null;

    try {
        // --- Use the DECRYPTED key buffer ---
        updateFileState(documentId, { status: "Preparing decryption key..." });
        console.log("FileList: Using decrypted private key buffer for decryption (length):", decryptedPrivateKeyBuffer.length);

        // Fetch encrypted data
        updateFileState(documentId, { status: `Fetching ${originalFileName}...` });
        const response = await apiClient.get(`/files/download-encrypted/${documentId}`);
        const { encryptedDataB64 } = response.data;
        if (!encryptedDataB64) throw new Error("Encrypted data not found in server response.");

        updateFileState(documentId, { status: "Decoding encrypted data..." });
        const encryptedUint8Array = base64ToUint8Array(encryptedDataB64);
        const ciphertext_len = encryptedUint8Array.length;

        // Prepare data for Wasm decryption
        updateFileState(documentId, { status: "Preparing data for Wasm decryption..." });
        wasmDecLenPtr = wasmModule._malloc(4);
        wasmSigLenPtr = wasmModule._malloc(4);
        if (!wasmDecLenPtr || !wasmSigLenPtr) throw new Error("Malloc failed for output length pointers");

        // --- Pass DECRYPTED key buffer to Wasm ---
        wasmPrivKeyPtr = passBufferToWasm(wasmModule, decryptedPrivateKeyBuffer);
        // --- End Pass Key ---
        wasmCiphertextPtr = passBufferToWasm(wasmModule, encryptedUint8Array);

        // Call Wasm Decrypt
        updateFileState(documentId, { status: "Decrypting..." });
        console.log(`FileList: Calling wasm_decrypt_buffer with decrypted key for doc ${documentId}...`);
        wasmDecPtr = wasmModule.ccall(
            'wasm_decrypt_buffer', 'number',
            ['number', 'number', 'number', 'number', 'number', 'number'],
            [wasmPrivKeyPtr, decryptedPrivateKeyBuffer.length, // <-- Use buffer length
             wasmCiphertextPtr, ciphertext_len, wasmDecLenPtr, wasmSigLenPtr]
        );
        if (!wasmDecPtr) throw new Error("Decryption failed: wasm_decrypt_buffer returned null pointer.");
        const decLen = wasmModule.HEAPU32[wasmDecLenPtr / 4];
        const actualSigLen = wasmModule.HEAPU32[wasmSigLenPtr / 4];
        if (actualSigLen <= 0 || actualSigLen > decLen) throw new Error(`Invalid Signature length returned by WASM: ${actualSigLen}`);
        console.log(`FileList: Decryption successful. Plaintext (Msg||Sig) length: ${decLen}, Sig part: ${actualSigLen}`);
        const decryptedUint8Array = getBufferFromWasm(wasmModule, wasmDecPtr, decLen);

        // Split Plaintext
        const msgLen = decLen - actualSigLen;
        if (msgLen < 0) throw new Error(`Calculated message length negative.`);
        const messageData = decryptedUint8Array.slice(0, msgLen); // Raw message bytes
        const signatureData = decryptedUint8Array.slice(msgLen);
        console.log(`FileList: Split plaintext: Msg len=${msgLen}, Sig len=${actualSigLen}`);

        // Prepare data for Wasm verification
        updateFileState(documentId, { status: "Preparing data for verification..." });
        wasmPubParamsPtr = passBufferToWasm(wasmModule, publicParamsBuffer);
        wasmSenderIdPtr = passBufferToWasm(wasmModule, new TextEncoder().encode(senderId + '\0')); // Null-terminate C string
        wasmMsgDataPtr = passBufferToWasm(wasmModule, messageData);
        wasmSigDataPtr = passBufferToWasm(wasmModule, signatureData);

        // Call Wasm Verify
        updateFileState(documentId, { status: "Verifying signature..." });
        console.log(`FileList DEBUG Verify: Verifying doc ${documentId} with Sender ID: ${senderId}, Msg Len: ${messageData.length}, Sig Len: ${signatureData.length}`);
        const verifyResultCode = wasmModule.ccall(
          'wasm_verify_buffer', 'number',
          ['number', 'number', 'number', 'number', 'number', 'number', 'number'],
          [wasmPubParamsPtr, publicParamsBuffer.length, wasmSenderIdPtr, wasmMsgDataPtr, messageData.length, wasmSigDataPtr, signatureData.length]
        );

        // Handle Verification Result
        if (verifyResultCode === 0) { // VALID
            console.log(`FileList: Verification VALID for doc ${documentId}.`);
            const baseFilename = getBaseFilename(originalFileName);
            updateFileState(documentId, {
                status: "Decryption and Verification Successful!",
                verification: "VALID",
                content: uint8ArrayToString(messageData), // Attempt text decode for preview
                buffer: messageData, // Store raw buffer
                filename: baseFilename
            });
        } else if (verifyResultCode === 1) { // INVALID
            console.warn(`FileList: Verification INVALID for doc ${documentId}.`);
            updateFileState(documentId, {
                status: "Decryption successful, but signature verification FAILED!",
                verification: "INVALID",
                content: "Cannot display content: Invalid Signature",
                buffer: null, // Clear buffer
                filename: ""
            });
        } else { // ERROR
             console.error(`FileList: Verification function returned error code ${verifyResultCode} for doc ${documentId}`);
             updateFileState(documentId, {
                status: `Verification failed with error code: ${verifyResultCode}`,
                verification: "ERROR",
                content: `Verification Error ${verifyResultCode}`,
                buffer: null, // Clear buffer
                filename: ""
             });
        }

    } catch (error) {
        console.error(`FileList: Decryption/Verification failed for doc ${documentId}:`, error);
        updateFileState(documentId, {
            status: `Error: ${error.message || 'Processing failed!'}`,
            verification: "ERROR",
            buffer: null,
            filename: ""
        });
    } finally {
        // Cleanup Wasm Memory
        console.log(`FileList: Cleaning up Wasm memory for doc ${documentId}...`);
         try { // Wrap cleanup
            if (wasmSigLenPtr && wasmModule) wasmModule._free(wasmSigLenPtr);
            if (wasmDecPtr && wasmModule) wasmModule.ccall('wasm_free_buffer', null, ['number'], [wasmDecPtr]);
            if (wasmPrivKeyPtr && wasmModule) wasmModule._free(wasmPrivKeyPtr); // Free the key pointer
            if (wasmCiphertextPtr && wasmModule) wasmModule._free(wasmCiphertextPtr);
            if (wasmDecLenPtr && wasmModule) wasmModule._free(wasmDecLenPtr);
            if (wasmPubParamsPtr && wasmModule) wasmModule._free(wasmPubParamsPtr);
            if (wasmSenderIdPtr && wasmModule) wasmModule._free(wasmSenderIdPtr);
            if (wasmMsgDataPtr && wasmModule) wasmModule._free(wasmMsgDataPtr);
            if (wasmSigDataPtr && wasmModule) wasmModule._free(wasmSigDataPtr);
         } catch(cleanupError) {
             console.error("Error during WASM memory cleanup:", cleanupError);
         }
        updateFileState(documentId, { processing: false }); // Mark processing finished for this file
    }
  };

  // --- Download Handler ---
  const handleDownloadDecrypted = (documentId) => {
      const bufferToDownload = decryptedBuffer[documentId];
      const filenameToDownload = decryptedFilename[documentId];

      if (!bufferToDownload || !filenameToDownload) {
          console.error(`Download clicked for ${documentId} but decrypted data/filename not available.`);
          alert("Decrypted data is not ready for download.");
          return;
      }
      try {
          const blob = new Blob([bufferToDownload], { type: 'application/octet-stream' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = filenameToDownload; // Use the extracted filename
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          console.log(`Download initiated for: ${filenameToDownload}`);
      } catch (error) {
          console.error("Error creating download link:", error);
          alert("Failed to initiate download.");
      }
  };
  // --- End Download Handler ---

  // --- Render Logic ---
  const isDecryptDisabledGlobally = !decryptedPrivateKeyBuffer; // Check if key is loaded in context

  if (!files || files.length === 0) {
    return <p className="text-gray-600">You have not received any documents yet.</p>;
  }

  return (
    <div className="space-y-4">
       {/* Display global key status info */}
       {isDecryptDisabledGlobally && <p className="text-orange-600 text-sm mb-4 font-medium">⚠️ Private key not loaded. Please use the key loader above to enable decryption.</p>}

       {/* File List Table */}
       <div className="overflow-x-auto bg-white rounded-lg shadow">
           <table className="min-w-full divide-y divide-gray-200">
               <thead className="bg-gray-50">
                   <tr>
                       <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Filename</th>
                       <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Sender</th>
                       <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Received</th>
                       <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                   </tr>
               </thead>
               <tbody className="bg-white divide-y divide-gray-200">
                   {files.map((file) => (
                       <React.Fragment key={file._id}>
                           {/* File Row */}
                            <tr>
                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900" title={file.originalFileName}>
                                    {/* Show base filename, use original on hover */}
                                    {getBaseFilename(file.originalFileName) || file.originalFileName}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{file.senderId}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{new Date(file.createdAt).toLocaleString()}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                    {/* Decrypt Button */}
                                    <button
                                        onClick={() => handleDecryptAndVerify(file._id, file.senderId, file.originalFileName)}
                                        disabled={isDecryptDisabledGlobally || isProcessing[file._id]} // Disable if global key missing OR this file is processing
                                        className={`text-indigo-600 hover:text-indigo-900 disabled:text-gray-400 disabled:cursor-not-allowed transition duration-150 ease-in-out`}
                                        title={isDecryptDisabledGlobally ? "Load your private key first" : ""}
                                    >
                                        {isProcessing[file._id] ? 'Processing...' : 'Decrypt & Verify'}
                                    </button>
                                    {/* Download Button - Show only if valid and buffer exists */}
                                    {verificationResult[file._id] === 'VALID' && decryptedBuffer[file._id] && (
                                         <button
                                            onClick={() => handleDownloadDecrypted(file._id)}
                                            className="ml-4 text-green-600 hover:text-green-900"
                                            title={`Download ${decryptedFilename[file._id]}`}
                                        >
                                            Download
                                        </button>
                                    )}
                                </td>
                           </tr>
                            {/* Results Row (Only shows if this file was selected/processed) */}
                            {selectedFileId === file._id && (
                                <tr>
                                    <td colSpan="4" className="px-6 py-3 bg-gray-50 text-sm text-gray-700">
                                        <div className="flex flex-col space-y-1">
                                             <span>Status: <span className="font-medium">{decryptionStatus[file._id]}</span></span>
                                             {verificationResult[file._id] && (
                                                 <span className={`font-medium ${ verificationResult[file._id] === 'VALID' ? 'text-green-600' : verificationResult[file._id] === 'INVALID' ? 'text-red-600' : 'text-yellow-700' }`}>
                                                     Signature: {verificationResult[file._id]}
                                                 </span>
                                             )}
                                             {/* Optional Preview for text files */}
                                             {verificationResult[file._id] === 'VALID' && decryptedContent[file._id] && decryptedContent[file._id] !== "[Binary data - Use Download button]" && (
                                                <details className="mt-1">
                                                    <summary className="cursor-pointer text-blue-600 text-xs hover:underline">Show Preview</summary>
                                                    <pre className="mt-1 p-2 text-xs bg-white border rounded max-h-32 overflow-auto">{decryptedContent[file._id]}</pre>
                                                </details>
                                             )}
                                        </div>
                                    </td>
                                </tr>
                            )}
                       </React.Fragment>
                   ))}
               </tbody>
           </table>
       </div>
    </div>
  );
};

export default FileList;