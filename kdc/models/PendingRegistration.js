// kdc/models/PendingRegistration.js
const mongoose = require('mongoose');

const pendingRegistrationSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true, // Only one pending registration per email
        lowercase: true,
        trim: true, // Good practice for emails
    },
    hashedPassword: { // This is the BCRYPT hash of the user's LOGIN password
        type: String,
        required: true,
    },
    name: { // Store name if provided
        type: String,
        required: false,
        trim: true,
    },
    otp: { // Store the plaintext OTP
        type: String,
        required: true,
    },
    // --- ADDED tempPassword FIELD ---
    tempPassword: { // Temporarily store PLAINTEXT password for key derivation AFTER OTP verification
        type: String,
        required: true, // Essential for the verify step to derive the AES key
        select: false, // CRITICAL: Prevent this field from being returned in queries by default
                       // Must use .select('+tempPassword') in the controller when needed.
    },
    // --- End ADDED FIELD ---
    expiresAt: {
        type: Date,
        required: true,
        // Create a TTL index: MongoDB automatically deletes documents
        // 'expiresAfterSeconds' seconds after the 'expiresAt' time.
        // Set to 0 so it deletes right at the specified time.
        index: { expires: '10m' } // Expire after 10 minutes (adjust if needed)
    },
}, {
    // Optional: Add timestamps for creation if needed for debugging
    // timestamps: true
});

// Optional: Create index on email for faster lookups
pendingRegistrationSchema.index({ email: 1 });

module.exports = mongoose.model('PendingRegistration', pendingRegistrationSchema);