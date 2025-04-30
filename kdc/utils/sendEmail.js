// server/utils/sendEmail.js
const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
    // 1. Create a transporter object using SMTP transport
    // Ensure environment variables are loaded before this file is imported/used
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT || '587', 10), // Default to 587 if not set
        secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports (uses STARTTLS if available)
        auth: {
            user: process.env.EMAIL_USER, // Your email address
            pass: process.env.EMAIL_PASS, // Your email password or App Password
        },
        // Optional: Add TLS options if needed for specific providers
        // tls: {
        //     ciphers:'SSLv3' // Example for some older servers if needed
        // }
    });

    // 2. Define the email options
    const mailOptions = {
        from: process.env.EMAIL_FROM, // Sender address (e.g., '"MyApp" <no-reply@myapp.com>')
        to: options.email,           // List of receivers from function argument
        subject: options.subject,    // Subject line from function argument
        text: options.message,       // Plain text body from function argument
        attachments: options.attachments,
        // html: '<b>Hello world?</b>' // You can also send HTML body
    };

    // 3. Send the email
    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent: %s', info.messageId);
        // Optional: You could return info or true on success
        return info;
    } catch (error) {
         console.error('Error sending email:', error);
         // Re-throw the error so the calling function knows sending failed
         throw new Error(`Email could not be sent (User: ${options.email}, Subject: ${options.subject})`);
    }
};

module.exports = sendEmail;