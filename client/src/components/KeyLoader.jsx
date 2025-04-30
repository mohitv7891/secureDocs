// client/src/components/KeyLoader.jsx
import React, { useState, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';

const KeyLoader = () => {
    // Get necessary state and functions from AuthContext
    const {
        decryptAndLoadKey,          // Function to call for decryption
        isDecryptingKey,            // Boolean: Is decryption in progress?
        keyDecryptionError,         // String: Holds error message from context if decryption fails
        decryptedPrivateKeyBuffer, // The resulting Uint8Array key buffer, or null
        setEncryptedKeyFileContent, // Function to potentially store the read file buffer in context (optional usage)
        logout                      // Function to log out and clear keys
    } = useAuth();

    // Local state for the form inputs and component-specific feedback
    const [selectedFile, setSelectedFile] = useState(null); // Holds the File object
    const [password, setPassword] = useState('');           // Holds the password input
    const [fileError, setFileError] = useState('');         // Local error for file selection/reading issues
    const [localSuccessMessage, setLocalSuccessMessage] = useState(''); // Optional local success message

    // Handler for file input changes
    const handleFileChange = (event) => {
        const file = event.target.files[0];
        setFileError('');             // Clear local errors
        setLocalSuccessMessage('');
        // NOTE: We intentionally DO NOT clear keyDecryptionError (from context) here.
        // It should only clear when a new decryption attempt starts.

        if (file) {
            // Optional: Basic validation for file type
            if (!file.name.toLowerCase().endsWith('.dat')) {
                setFileError('Invalid file type. Please select your .dat key file.');
                setSelectedFile(null);
                // Optionally clear context buffer if needed: setEncryptedKeyFileContent(null);
                return;
            }
            setSelectedFile(file);
            console.log("Key file selected:", file.name);
            // We don't need to read the buffer here, can do it on submit.
            // If you wanted to store it immediately in context, you would use:
            // const reader = new FileReader();
            // reader.onload = (e) => setEncryptedKeyFileContent(e.target.result);
            // reader.onerror = () => setFileError('Error reading key file.');
            // reader.readAsArrayBuffer(file);

        } else {
            setSelectedFile(null);
            // Optionally clear context buffer: setEncryptedKeyFileContent(null);
        }
    };

    // Handler for password input changes
    const handlePasswordChange = (event) => {
        setPassword(event.target.value);
        setLocalSuccessMessage(''); // Clear local success message
        setFileError('');           // Clear local form errors (e.g., "Password is required")
        // We DO NOT clear keyDecryptionError (from context) here.
    };

    // Handler for form submission
    const handleSubmit = async (event) => {
        event.preventDefault();
        setFileError('');             // Clear local errors before attempt
        setLocalSuccessMessage('');
        // NOTE: decryptAndLoadKey within AuthContext is responsible for clearing
        // the context's keyDecryptionError before starting.

        if (!selectedFile) {
            setFileError('Please select your encrypted key file (.dat).');
            return;
        }
        if (!password) {
            setFileError('Please enter your password.');
            return;
        }

        // Read the file content into an ArrayBuffer just before decrypting
        let fileBuffer;
        try {
            fileBuffer = await selectedFile.arrayBuffer();
            // Optionally store in context if needed elsewhere immediately
            // setEncryptedKeyFileContent(fileBuffer);
        } catch (readError) {
             console.error("Error reading file before decryption:", readError);
             setFileError('Could not read key file content.');
             return;
        }

        // Call the decryption function provided by AuthContext
        await decryptAndLoadKey(password, fileBuffer);

        // Feedback (Success/Error) is primarily handled by observing
        // the keyDecryptionError and decryptedPrivateKeyBuffer states from context,
        // which will cause a re-render. We could set a local success message
        // if the context doesn't provide one implicitly.
    };

    // --- Render Logic ---

    // If key is already successfully loaded, show confirmation and logout option
    if (decryptedPrivateKeyBuffer && !isDecryptingKey && !keyDecryptionError) {
        return (
            <div className="p-4 border rounded-lg bg-green-100 text-center mb-6 shadow-sm">
                <p className="text-green-800 font-semibold">✅ Private key is loaded and ready.</p>
                 <button
                     onClick={logout} // Allow user to explicitly unload key by logging out
                     className="mt-2 text-sm text-red-600 hover:text-red-800 hover:underline"
                 >
                     Logout to unload key
                 </button>
            </div>
        );
    }

    // Otherwise, render the key loading form
    return (
        <div className="p-4 border rounded-lg bg-white shadow-md mb-6">
            <h3 className="text-lg font-semibold mb-3 text-gray-800">Load Your Encrypted Private Key</h3>
            <p className="text-sm text-gray-600 mb-4">
                Select your downloaded <code>.dat</code> key file and enter the password you registered with to enable signing and decryption.
            </p>
            <form onSubmit={handleSubmit} className="space-y-3">
                {/* File Input */}
                <div>
                    <label htmlFor="key-file" className="block text-sm font-medium text-gray-700 mb-1">
                        Select Key File (.dat):<span className="text-red-500">*</span>
                    </label>
                    <input
                        type="file"
                        id="key-file"
                        accept=".dat" // Only allow .dat files
                        onChange={handleFileChange}
                        required
                        className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 disabled:opacity-50 cursor-pointer"
                        disabled={isDecryptingKey}
                    />
                </div>
                {/* Password Input */}
                <div>
                    <label htmlFor="key-password"className="block text-sm font-medium text-gray-700 mb-1">
                        Your Password:<span className="text-red-500">*</span>
                    </label>
                    <input
                        type="password"
                        id="key-password"
                        value={password}
                        onChange={handlePasswordChange} // Use the corrected handler
                        required
                        placeholder="Enter your login password"
                        className="w-full p-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
                        disabled={isDecryptingKey}
                    />
                </div>

                {/* Error/Status Display Area */}
                <div className="min-h-[20px] text-xs"> {/* Reserve space for messages */}
                    {/* Display LOCAL form errors */}
                    {fileError && <p className="text-red-600 font-medium">{fileError}</p>}
                    {/* Display CONTEXT decryption errors */}
                    {keyDecryptionError && <p className="text-red-600 font-medium">Decryption Error: {keyDecryptionError}</p>}
                    {/* Display LOCAL success message (if you choose to implement) */}
                    {localSuccessMessage && <p className="text-green-600 font-medium">{localSuccessMessage}</p>}
                </div>


                <button
                    type="submit"
                    // Disable if processing, or if file/password haven't been entered
                    disabled={isDecryptingKey || !selectedFile || !password}
                    className={`w-full p-2 rounded-md text-white font-semibold transition duration-150 ease-in-out ${isDecryptingKey || !selectedFile || !password ? 'bg-gray-400 cursor-not-allowed' : 'bg-green-600 hover:bg-green-700'}`}
                >
                    {isDecryptingKey ? 'Decrypting Key...' : 'Load & Decrypt Key'}
                </button>
            </form>
        </div>
    );
};

export default KeyLoader;