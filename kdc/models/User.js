const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String },
  email: {
    type: String,
    required: [true, 'Please provide an email'],
    unique: true,
    lowercase: true,
    match: [/.+@iiita\.ac\.in$/i, 'Please provide a valid IIITA email address'],
  },
  password: { // Stores the BCRYPT HASH of the password for login verification
    type: String,
    required: [true, 'Please provide a password hash'],
    minlength: 6,
    select: false, // Do not send password hash back by default
  },
  // --- NEW FIELDS for Key Encryption ---
  kdfSalt: { // Salt used with password for PBKDF2
      type: Buffer,
      required: true,
      select: false, // Don't send salt back by default
  },
  // We DO NOT store the raw key or the password-derived AES key.
  // The IV used for AES is packaged WITH the encrypted data sent to the user.
  // --- End New Fields ---
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('User', userSchema);