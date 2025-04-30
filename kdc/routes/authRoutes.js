// kdc/routes/authRoutes.js
const express = require('express');
const { check } = require('express-validator');
const authController = require('../controllers/authController'); // KDC's controller

const router = express.Router();

// Step 1: Initiate Registration & Send OTP (Public)
router.post( '/initiate-registration',
    [ /* Validation rules */
        check('name', 'Name is optional').optional().isString(),
        check('email', 'Please include a valid IIITA email').isEmail().normalizeEmail().matches(/@iiita\.ac\.in$/i),
        check('password', 'Password must be 6 or more characters').isLength({ min: 6 }),
    ], authController.initiateRegistration
);

// Step 2: Verify OTP & Complete Registration (Public)
router.post( '/verify-registration',
    [ /* Validation rules */
         check('email', 'Please include a valid email').isEmail().normalizeEmail(),
         check('otp', 'OTP is required and must be 6 digits').isLength({ min: 6, max: 6 }).isNumeric(),
    ], authController.verifyRegistration
);

// Login Route (Public)
router.post('/login',
    [ /* Validation rules */
        check('email', 'Please include a valid email').isEmail().normalizeEmail(),
        check('password', 'Password is required').exists(),
    ], authController.loginUser
);

module.exports = router;