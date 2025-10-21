// testEmail.js
const sendEmail = require("./sendEmail");

(async () => {
  try {
    await sendEmail({
      email: "mcl2024016@iiita.ac.in",  // test email
      subject: "Test OTP from MyApp",
      message: "Your OTP is 987654"
    });
    console.log("✅ Email sent successfully!");
  } catch (err) {
    console.error("❌ Error:", err.message);
  }
})();
