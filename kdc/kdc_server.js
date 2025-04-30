// kdc/kdc_server.js
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const connectDB = require('./config/db'); // KDC DB Config

// Load KDC env vars
dotenv.config({ path: './.env' });

// Import KDC routes
const authRoutes = require('./routes/authRoutes');
// We removed the old keyRoutes as key gen is part of registration now

const app = express();

// Middleware
app.use(cors()); // Configure CORS more strictly in production
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Connect KDC Database
connectDB();

// Mount Auth Routes (Registration/Login)
app.use('/api/auth', authRoutes); // Make endpoints consistent with client expectations

// Health check
app.get('/health', (req, res) => res.status(200).send('KDC Authentication Server OK'));

const PORT = process.env.PORT || 5007; // Use KDC port
app.listen(PORT, () => console.log(`KDC Server running on port ${PORT}`));