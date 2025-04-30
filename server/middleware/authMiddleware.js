// server/middleware/authMiddleware.js
const jwt = require('jsonwebtoken');
// const User = require('../models/user'); // Optional: Usually not needed here unless checking if user still exists in DB on every request

module.exports = function (req, res, next) {
    // Log entry point for debugging middleware execution
    console.log(`--- AUTH MIDDLEWARE CHECK --- Path: ${req.originalUrl}, Method: ${req.method} ---`);

    // 1. Check if JWT_SECRET is loaded (crucial)
    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) {
         console.error("FATAL AUTH ERROR: JWT_SECRET environment variable is not set!");
         // Avoid proceeding without a secret, this is a server config issue
         return res.status(500).json({ message: 'Server configuration error (Authentication Secret).' });
    }

    // 2. Get Authorization header
    const authHeader = req.header('Authorization');

    // Check if header exists
    if (!authHeader) {
        console.log("Auth Middleware: No Authorization header found.");
        return res.status(401).json({ message: 'No authentication token provided.' });
    }

    // 3. Check format "Bearer <token>" and extract token
    const tokenParts = authHeader.split(' ');
    if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer' || !tokenParts[1]) {
         console.log("Auth Middleware: Invalid token format (Expected 'Bearer <token>').");
         return res.status(401).json({ message: 'Token format is invalid.' });
    }
    const actualToken = tokenParts[1];

    // 4. Verify token
    try {
        const decoded = jwt.verify(actualToken, JWT_SECRET);

        // 5. Check if the expected user payload exists in the decoded token
        if (!decoded || !decoded.user || !decoded.user.id || !decoded.user.email) {
             console.error('Auth Middleware Error: Token payload is missing expected user data (id/email). Payload:', decoded);
             return res.status(401).json({ message: 'Token payload is invalid.' });
        }

        // 6. Attach user payload to the request object
        req.user = decoded.user; // Contains { id: userId, email: userEmail }
        console.log(`Auth Middleware: Token verified. Attaching user: { id: '${req.user.id}', email: '${req.user.email}' }`);

        next(); // Proceed to the next middleware or route handler

    } catch (err) {
        // 7. Handle verification errors (e.g., expired, invalid signature)
        console.error('Auth Middleware Token Verification Error:', err.name, '-', err.message);
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Authentication token has expired.' });
        }
        // For other errors like JsonWebTokenError (bad signature, malformed)
        return res.status(401).json({ message: 'Authentication token is not valid.' });
    }
};