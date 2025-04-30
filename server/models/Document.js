/* === File: models/Document.js === */
const mongoose = require("mongoose");

const documentSchema = new mongoose.Schema({
  // Store the original filename provided by the client
  originalFileName: {
    type: String,
    required: true,
  },
  // Store the encrypted data as a binary buffer
  encryptedData: {
    type: Buffer,
    required: true,
  },
  // Store the ID of the user who uploaded (sender)
  // Assuming you have a User model and authentication sending req.user.id
  senderId: {
    // type: mongoose.Schema.Types.ObjectId,
    // ref: "User", // Uncomment if you have a User model and want to populate
    type: String, // Using String for simplicity if user ID is not ObjectId
    required: true,
  },
  // Store the ID of the intended recipient
  recipientId: {
    // type: mongoose.Schema.Types.ObjectId,
    // ref: "User", // Uncomment if you have a User model and want to populate
    type: String, // Using String for simplicity if user ID is not ObjectId
    required: true,
  },
  // Keep track of upload time
  createdAt: {
    type: Date,
    default: Date.now,
  },
  // Removed 'path' field as we store the data directly
  // Removed 'uploadedBy', replaced with more specific 'senderId'
  // Removed 'sharedWith', recipient is now a single required field for this model
});

// Add index for potential queries
documentSchema.index({ recipientId: 1, createdAt: -1 });
documentSchema.index({ senderId: 1, createdAt: -1 });


module.exports = mongoose.model("Document", documentSchema);