const Document = require("../models/Document");
const mongoose = require('mongoose'); 


// --- uploadEncryptedFile function (from previous step - ensure senderId uses req.user.id or req.user.email consistently) ---
const uploadEncryptedFile = async (req, res) => {
    console.log("Received encrypted upload request");
    try {
        if (!req.file || !req.file.buffer) {
            return res.status(400).json({ message: "No encrypted file data received." });
        }
        const { recipientId } = req.body;
        // *** Ensure senderId format matches how recipientId is stored (e.g., email) ***
        // *** Or update Document model to use ObjectId for both ***
        const senderId = req.user ? (req.user.email || req.user.id) : "test_sender_id_NEEDS_FIXING"; // Example: prefer email if available
        const originalFileName = req.file.originalname;

        if (!recipientId || !originalFileName) {
             return res.status(400).json({ message: "Recipient ID and filename are required." });
        }
        console.log(`Sender ID being saved: ${senderId} (Type: ${typeof senderId})`); // Log what's saved

        if (req.file?.buffer) {
            console.log(`DEBUG uploadEncryptedFile: req.file.buffer type: ${typeof req.file.buffer}, instanceof Buffer: ${req.file.buffer instanceof Buffer}, length: ${req.file.buffer.length}`);
        } else {
            console.error(`CRITICAL uploadEncryptedFile: req.file.buffer is missing before save!`);
            return res.status(500).json({ message: "Server error: Upload buffer missing before save." });
        }

        const newDocument = new Document({
            originalFileName: originalFileName,
            encryptedData: req.file.buffer,
            senderId: senderId, // Make sure this matches recipientId format
            recipientId: recipientId, // This is an email string from form
        });
        await newDocument.save();

        console.log("✅ Encrypted document saved to database. ID:", newDocument._id);
        res.status(201).json({ message: "Encrypted file uploaded and saved successfully.", documentId: newDocument._id });
    } catch (error) {
        console.error("❌ Encrypted upload error:", error);
        res.status(500).json({ message: "Server error during encrypted file upload.", error: error.message });
    }
};


// --- Controller for Fetching Received Files (UPDATED QUERY) ---
const getReceivedFiles = async (req, res) => {
    console.log("Received request for received files");
    try {
        // Ensure user info (esp. email) is attached by authMiddleware
        if (!req.user || !req.user.email) { // <<< CHECK FOR EMAIL
             console.log("User not authenticated or email missing in getReceivedFiles");
             return res.status(401).json({ message: 'User not authenticated or email missing.' });
        }
        const userEmail = req.user.email; // <<< GET EMAIL FROM req.user

        console.log(`DEBUG: Querying documents where recipientId matches req.user.email = ${userEmail}`);

        // Find documents where the recipientId (string) matches the logged-in user's email (string)
        const documents = await Document.find({ recipientId: userEmail }) // <<< USE EMAIL IN QUERY
                                        .select('-encryptedData')
                                        .sort({ createdAt: -1 });

        console.log(`DEBUG: Found ${documents.length} documents matching query for ${userEmail}.`);
        res.json(documents);

    } catch (error) {
        console.error("Error fetching received files:", error);
        res.status(500).json({ message: "Failed to fetch received documents." });
    }
};

// --- downloadEncryptedFile function ---

const downloadEncryptedFile = async (req, res) => {
    console.log("--- Enter downloadEncryptedFile Controller ---");
    const documentId = req.params.id; // Keep ID definition outside for catch block

    // --- Define userEmail OUTSIDE the try block ---
    const userEmail = req.user?.email; // Get email from middleware result

    try {
        // 1. Check User Info (using variable defined above)
        if (!userEmail) {
            console.log("downloadEncryptedFile: User email not found on req.user.");
            return res.status(403).json({ message: 'User identity not found in token.' });
        }

        // 2. Validate Document ID Format
        if (!mongoose.Types.ObjectId.isValid(documentId)) {
            console.log(`downloadEncryptedFile: Invalid document ID format received: ${documentId}`);
            return res.status(400).json({ message: 'Invalid document ID format.' });
        }
        // This log should now work
        console.log(`downloadEncryptedFile: Request for document ID: ${documentId} by user: ${userEmail}`);

        // 3. Find the specific document by its ID
        const document = await Document.findById(documentId);

        // Check if document exists
        if (!document) {
            console.log(`downloadEncryptedFile: Document not found in DB for ID: ${documentId}`);
            return res.status(404).json({ message: 'Document not found.' });
        }

        // 4. Authorization Check
        if (document.recipientId !== userEmail) { // Uses userEmail defined outside
             console.warn(`downloadEncryptedFile: Authorization FAILED. User ${userEmail} attempted to access document meant for ${document.recipientId}`);
            return res.status(403).json({ message: 'Forbidden: You are not the recipient of this document.' });
        }

        // 5. Check if encrypted data exists AND is a Buffer
        // Add the debug log right before the check for clarity
        if (document.encryptedData) {
             console.log(`DEBUG downloadEncryptedFile: document.encryptedData type: ${typeof document.encryptedData}, instanceof Buffer: ${document.encryptedData instanceof Buffer}, length: ${document.encryptedData?.length}`);
        } else {
             console.log(`DEBUG downloadEncryptedFile: document.encryptedData is null or undefined.`);
        }

        if (!document.encryptedData || !(document.encryptedData instanceof Buffer)) {
             console.error(`downloadEncryptedFile: Encrypted data missing or invalid type check FAILED for document ID: ${documentId}`);
            return res.status(500).json({ message: 'Server error: Encrypted data has invalid type.' });
        }

        // Prepare payload
        console.log(`downloadEncryptedFile: Preparing Base64 payload for document ID: ${documentId}`);
        const base64Data = document.encryptedData.toString('base64');
        const responsePayload = {
            encryptedDataB64: base64Data,
        };
        console.log(`downloadEncryptedFile: Payload ready. Sending 200 OK for document ID: ${documentId}`);

        // Send response
        res.status(200).json(responsePayload);

    } catch (error) {
        // Log error including documentId which is defined outside try
        console.error(`❌ CAUGHT ERROR in downloadEncryptedFile for ID ${documentId}:`, error);
        res.status(500).json({ message: "Server error while fetching encrypted file data." });
    }
};

// --- End Download Controller ---

// Export functions
module.exports = {
    uploadEncryptedFile,
    getReceivedFiles,
    downloadEncryptedFile,
};
