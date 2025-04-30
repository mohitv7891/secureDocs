// kdc/controllers/authController.js
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const crypto = require('crypto'); // For OTP and KDF Salt generation

// KDC Models and Utilities
const User = require('../models/User'); // KDC's User model (stores email, bcrypt hash, kdfSalt)
const PendingRegistration = require('../models/PendingRegistration'); // KDC's Pending model
const executeKeygen = require('../utils/executeKeygen'); // KDC calls native keygen
const sendEmail = require('../utils/sendEmail'); // KDC sends registration/key emails
const {
    deriveKey,
    encryptAES,
    packageEncryptedData,
    SALT_BYTES // Import constant for salt generation
} = require('../utils/cryptoUtils'); // KDC uses these crypto helpers

// Environment Variables (Ensure loaded in kdc_server.js)
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1d';
const IIITA_EMAIL_DOMAIN = '@iiita.ac.in'; // Or load from env if preferred
const OTP_EXPIRY_MINUTES = 10;

// --- Step 1: Initiate Registration (Sends OTP) ---
exports.initiateRegistration = async (req, res) => {
    console.log("KDC: Initiate registration request received:", req.body.email);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;
    const lowerCaseEmail = email.toLowerCase();

    // Validate domain
    if (!lowerCaseEmail.endsWith(IIITA_EMAIL_DOMAIN)) {
        return res.status(400).json({ message: `Registration only allowed for ${IIITA_EMAIL_DOMAIN} emails.` });
    }

    try {
        // Check if user is already fully registered in KDC User model
        let existingUser = await User.findOne({ email: lowerCaseEmail });
        if (existingUser) {
            console.log(`KDC: Initiate registration failed: Email ${lowerCaseEmail} already registered.`);
            return res.status(400).json({ message: 'Email address already registered. Please log in.' });
        }

        // Remove any previous pending registration for this email
        await PendingRegistration.deleteOne({ email: lowerCaseEmail });
        console.log(`KDC: Cleared any previous pending registration for ${lowerCaseEmail}.`);

        // Hash the LOGIN password using bcrypt (this hash is stored in the final User doc)
        const bcryptSalt = await bcrypt.genSalt(10);
        const hashedPasswordForLogin = await bcrypt.hash(password, bcryptSalt);
        console.log(`KDC: Login password hashed (bcrypt) for pending registration: ${lowerCaseEmail}.`);

        // Generate OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        // SECURITY NOTE: Avoid logging OTP in production environments
        console.log(`KDC: Generated OTP for ${lowerCaseEmail}: ${otp}`);

        // Calculate Expiry Time for OTP
        const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

        // Save pending registration details including TEMPORARY plaintext password
        // This password is used ONCE after OTP verification to derive the key, then discarded.
        // This avoids asking the user for their password again on the OTP screen.
        // Ensure cleanup if verification fails or expires.
        const pending = new PendingRegistration({
            email: lowerCaseEmail,
            hashedPassword: hashedPasswordForLogin, // Store bcrypt hash for final user doc
            name,
            otp,
            expiresAt,
            tempPassword: password // Temporarily store plaintext for key derivation
        });
        await pending.save();
        console.log(`KDC: Pending registration saved for ${lowerCaseEmail}, expires at ${expiresAt.toISOString()}`);

        // Send OTP email
        const message = `Your OTP for SecureDocs registration is: ${otp}\n\nIt will expire in ${OTP_EXPIRY_MINUTES} minutes.\n\nIf you did not request this, please ignore this email.`;
        try {
            await sendEmail({
                email: lowerCaseEmail,
                subject: 'Your SecureDocs Registration OTP',
                message,
            });
            console.log(`KDC: OTP email sending initiated for ${lowerCaseEmail}.`);
            // Send success response to frontend
            res.status(200).json({ message: `OTP sent to ${lowerCaseEmail}. Please check your email.` });

        } catch (emailError) {
            console.error(`KDC: Failed to send OTP email to ${lowerCaseEmail}:`, emailError);
            // If email fails, clean up the pending registration to prevent inconsistent state
            await PendingRegistration.deleteOne({ email: lowerCaseEmail }).catch(e => console.error("KDC: Cleanup failed after email error", e));
            return res.status(500).json({ message: 'Failed to send OTP email. Please try initiating registration again.' });
        }

    } catch (error) {
        console.error('KDC Error during initiate registration:', error);
        // General cleanup attempt
        await PendingRegistration.deleteOne({ email: lowerCaseEmail }).catch(e => console.error("KDC: Cleanup failed in general catch block", e));
        res.status(500).json({ message: 'Server error during registration initiation.' });
    }
};

// --- Step 2: Verify OTP, Generate/Encrypt Key, Create Final User, Send Key ---
exports.verifyRegistration = async (req, res) => {
    console.log("KDC: Verify registration request received for:", req.body.email);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log("KDC: Verification validation errors:", errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, otp } = req.body;
    const lowerCaseEmail = email.toLowerCase();
    let pendingDoc; // Define here for broader scope, especially cleanup

    try {
        // Find the pending registration, ensure tempPassword is selected
        pendingDoc = await PendingRegistration.findOne({ email: lowerCaseEmail }).select('+tempPassword');

        // Basic checks for pending doc, expiry, and OTP
        if (!pendingDoc) {
            console.log(`KDC: Verification failed: No pending registration found for ${lowerCaseEmail}`);
            return res.status(400).json({ message: 'Invalid request or registration attempt not found. Please initiate registration again.' });
        }
        if (Date.now() > pendingDoc.expiresAt) {
            console.log(`KDC: Verification failed: OTP expired for ${lowerCaseEmail}`);
            await PendingRegistration.findByIdAndDelete(pendingDoc._id); // Clean up expired record
            console.log(`KDC: Deleted expired pending registration for ${lowerCaseEmail}`);
            return res.status(400).json({ message: 'OTP has expired. Please initiate registration again.' });
        }
        if (otp !== pendingDoc.otp) {
            console.log(`KDC: Verification failed: Invalid OTP submitted for ${lowerCaseEmail}.`);
            // NOTE: Implement attempt limiting in production
            return res.status(400).json({ message: 'Invalid OTP submitted.' });
        }
        // CRITICAL check: Ensure tempPassword was retrieved
        if (!pendingDoc.tempPassword) {
            console.error(`KDC CRITICAL: Temp password missing after OTP check for ${lowerCaseEmail}! PendingDocID: ${pendingDoc._id}`);
            await PendingRegistration.findByIdAndDelete(pendingDoc._id); // Clean up this invalid state
            return res.status(500).json({ message: 'Internal processing error (Ref: TPW). Please initiate registration again.' });
        }

        // --- OTP Correct ---
        console.log(`KDC: OTP verified successfully for ${lowerCaseEmail}`);

        // 1. Generate the raw IBE private key
        let rawPrivateKeyBuffer;
        try {
            console.log(`KDC: Generating IBE private key for ${lowerCaseEmail}...`);
            rawPrivateKeyBuffer = await executeKeygen(lowerCaseEmail); // Call native binary
            if (!rawPrivateKeyBuffer || rawPrivateKeyBuffer.length === 0) {
                throw new Error("executeKeygen returned an empty buffer.");
            }
            console.log(`KDC: Raw IBE key generated (length: ${rawPrivateKeyBuffer.length}) for ${lowerCaseEmail}.`);
        } catch (keygenError) {
            console.error(`KDC: Key generation via executeKeygen failed for ${lowerCaseEmail}:`, keygenError);
            await PendingRegistration.findByIdAndDelete(pendingDoc._id); // Clean pending doc on failure
            return res.status(500).json({ message: 'Failed to generate cryptographic key.' });
        }

        // 2. Encrypt the raw key using password-derived key
        let encryptedKeyPackage; // Buffer: [Salt][AuthTag][IV][EncryptedKey]
        let kdfSalt; // Buffer for the salt used
        try {
            console.log(`KDC: Preparing for AES encryption for ${lowerCaseEmail}...`);
            kdfSalt = crypto.randomBytes(SALT_BYTES); // Generate unique salt PER USER
            console.log(`KDC: Generated KDF Salt (length ${kdfSalt.length})`);

            // Derive AES key from the TEMPORARY plaintext password and the new salt
            const aesKey = await deriveKey(pendingDoc.tempPassword, kdfSalt);
            console.log(`KDC: AES key derived using PBKDF2.`);

            // Encrypt the raw key using the derived AES key
            const { iv, encryptedData, authTag } = encryptAES(rawPrivateKeyBuffer, aesKey);
            console.log(`KDC: Raw private key encrypted using AES-GCM.`);

            // Package the encrypted data along with salt, IV, and tag
            encryptedKeyPackage = packageEncryptedData(kdfSalt, iv, encryptedData, authTag);
            console.log(`KDC: Encrypted key package created (total length: ${encryptedKeyPackage.length}).`);

            // IMPORTANT: Clear sensitive variables from memory as soon as possible
            aesKey.fill(0); // Overwrite derived key buffer
            pendingDoc.tempPassword = undefined; // Remove temp password from doc object
            // Note: rawPrivateKeyBuffer might still be in memory until garbage collected

        } catch (cryptoError) {
            console.error(`KDC: Failed to derive key or encrypt private key for ${lowerCaseEmail}:`, cryptoError);
            await PendingRegistration.findByIdAndDelete(pendingDoc._id); // Clean pending doc
            return res.status(500).json({ message: 'Failed to secure cryptographic key.' });
        }

        // 3. Create the final User record in the KDC database
        try {
            console.log(`KDC: Creating final user record for ${lowerCaseEmail}`);
            const newUser = new User({
                name: pendingDoc.name,
                email: pendingDoc.email,
                password: pendingDoc.hashedPassword, // Store the BCRYPT hash for login
                kdfSalt: kdfSalt,                  // Store the salt used for this user's key encryption
            });
            await newUser.save();
            console.log(`KDC: User record created successfully for ${lowerCaseEmail} with ID: ${newUser._id}`);

        } catch (userSaveError) {
            console.error(`KDC: Error saving final user record for ${lowerCaseEmail}:`, userSaveError);
            // Handle potential duplicate email error (race condition?)
            if (userSaveError.code === 11000) {
                await PendingRegistration.findByIdAndDelete(pendingDoc._id); // Clean pending doc
                console.log(`KDC: Deleted pending registration for ${lowerCaseEmail} due to existing user during save.`);
                return res.status(400).json({ message: 'This email address was already registered. Please try logging in.' });
            }
            // Other save errors indicate an inconsistent state (key generated/encrypted, user not saved)
            // This is hard to recover from automatically. Log it as critical.
            console.error(`KDC CRITICAL: Inconsistent state for ${lowerCaseEmail}. Key generated/encrypted but User save failed.`);
            // Don't delete pendingDoc here, might be needed for manual recovery investigation.
            return res.status(500).json({ message: 'Server error saving user registration details. Please contact support.' });
        }

        // 4. Send the Encrypted Key via Email
        try {
            console.log(`KDC: Preparing to send encrypted key email to ${lowerCaseEmail}...`);
            const filename = `encrypted_private_key_${lowerCaseEmail}.dat`;
            const emailMessage = `Registration successful!\n\nAttached is your encrypted private key file (${filename}).\n\n**IMPORTANT:**\n- Store this file securely.\n- You will need this file AND your password every time you log in to use the service.\n- If you lose this file OR forget your password, you will permanently lose access to your encrypted documents.\n- **DO NOT share this file or your password.**`;

            await sendEmail({
                email: lowerCaseEmail,
                subject: 'Your SecureDocs Encrypted Private Key',
                message: emailMessage,
                attachments: [
                    {
                        filename: filename,
                        content: encryptedKeyPackage, // Attach the buffer containing [Salt][Tag][IV][EncryptedKey]
                        contentType: 'application/octet-stream'
                    }
                ]
            });
            console.log(`KDC: Encrypted key email sending initiated for ${lowerCaseEmail}.`);

        } catch (emailError) {
            console.error(`KDC CRITICAL: Failed to send encrypted key email to ${lowerCaseEmail} AFTER user save:`, emailError);
            // User IS registered, but received no key. Bad state.
            // Log this prominently. Inform user to contact support. Don't delete the user.
            // Keep the pending doc deletion *after* this block, as it's less critical than the user not getting the key.
            return res.status(500).json({ message: 'User registered, but failed to send the encrypted key email. Please contact support immediately.' });
        }

        // 5. Clean up the pending registration document as everything succeeded
        try {
            await PendingRegistration.findByIdAndDelete(pendingDoc._id);
            console.log(`KDC: Pending registration record deleted successfully for ${lowerCaseEmail}`);
        } catch (deleteError) {
            // Log this, but don't fail the request if user+email succeeded
            console.error(`KDC: Error deleting completed pending registration record for ${lowerCaseEmail} (ID: ${pendingDoc._id}):`, deleteError);
        }

        // 6. Respond with success
        res.status(201).json({
            message: 'User registered successfully! Check your email for your encrypted private key file and instructions. Save the file securely!'
            // Optional: Include base64 key package for immediate download trigger
            // encryptedKeyB64: encryptedKeyPackage.toString('base64'),
            // suggestedFilename: `encrypted_private_key_${lowerCaseEmail}.dat`
        });

    } catch (error) {
        console.error('KDC: Unhandled error during verify registration:', error);
        // Attempt cleanup if pendingDoc was fetched
        if (pendingDoc && pendingDoc._id) {
            await PendingRegistration.findByIdAndDelete(pendingDoc._id).catch(e => console.error("KDC: Cleanup failed in final catch block", e));
        }
        res.status(500).json({ message: 'Server error during registration verification.' });
    }
};

// --- Login Controller (Authenticates against KDC, Issues JWT) ---
exports.loginUser = async (req, res) => {
    console.log("KDC: Login request received:", req.body.email);
    const errors = validationResult(req);
    if (!errors.isEmpty()) { return res.status(400).json({ errors: errors.array() }); }

    const { email, password } = req.body;

    if (!JWT_SECRET) {
        console.error("KDC FATAL: JWT_SECRET environment variable is not set!");
        return res.status(500).json({ message: 'Server configuration error [Auth Secret].' });
    }

    try {
        // Find user in KDC database, fetch password hash (+password)
        const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
        if (!user) {
            console.log(`KDC: Login failed for ${email}: User not found.`);
            return res.status(400).json({ message: 'Invalid credentials or user not registered.' });
        }

        // Compare provided password with stored BCRYPT hash
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log(`KDC: Login failed for ${email}: Password mismatch.`);
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        // --- Login successful - Generate JWT ---
        // Payload contains user identity needed by the Data Server
        const payload = {
            user: {
                id: user.id, // KDC User ID (might be useful for logging on data server)
                email: user.email // Primary identifier
            }
        };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

        console.log(`KDC: Login successful for ${email}. Token generated.`);
        // Send ONLY the token back. Client needs to handle key file separately.
        res.json({ token });

    } catch (error) {
        console.error('KDC Login Error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
};