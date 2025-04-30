// data-server/server.js
const express = require("express");
const connectDB = require("./config/db"); // Data server DB config
const cors = require("cors");
require("dotenv").config(); // Load data-server .env

// --- Route Imports ---
const fileRoutes = require("./routes/fileRoutes"); // Only file routes needed

// --- Middleware Imports ---
const authMiddleware = require('./middleware/authMiddleware'); // JWT verification

const app = express();

// --- Core Middleware ---
app.use(cors()); // Enable CORS (configure strictly)
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- Database Connection ---
connectDB(); // Connect to data server DB

// --- API Routes ---
// Mount file routes and PROTECT THEM GLOBALLY with authMiddleware
// Any request to /api/files/* will now require a valid token verified using the shared JWT_SECRET
app.use("/api/files", authMiddleware, fileRoutes);

// Health check
app.get('/health', (req, res) => res.status(200).send('Data Server OK'));

// --- Start Server ---
const PORT = process.env.PORT || 5006; // Data server port
app.listen(PORT, () => console.log(`Data Server running on port ${PORT}`));