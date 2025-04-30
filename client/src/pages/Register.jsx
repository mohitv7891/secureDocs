// client/pages/Register.jsx
import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext'; // Import useAuth
import Navbar from "../components/Navbar";

const Register = () => {
  // Get the kdcClient instance from the Auth context
  const { kdcClient } = useAuth();

  const [stage, setStage] = useState('enterDetails'); // 'enterDetails' or 'enterOtp'
  const [formData, setFormData] = useState({ name: '', email: '', password: '' });
  const [otp, setOtp] = useState('');
  const [submittedEmail, setSubmittedEmail] = useState(''); // Store email for OTP step
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState(''); // For success/info messages
  const [errorMessage, setErrorMessage] = useState(''); // For error messages

  const navigate = useNavigate();
  const { name, email, password } = formData;

  // --- Input Handlers ---
  const onChangeDetails = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    setMessage(''); // Clear messages on input change
    setErrorMessage('');
  };

  const onChangeOtp = (e) => {
    // Allow only digits and max length 6
    const value = e.target.value.replace(/\D/g, '');
    if (value.length <= 6) {
      setOtp(value);
      setMessage(''); // Clear messages on input change
      setErrorMessage('');
    }
  };

  // --- Step 1: Submit Details to Initiate Registration ---
  const handleSubmitDetails = async (e) => {
    e.preventDefault();
    setErrorMessage(''); // Clear previous errors
    setMessage('');

    // Frontend Validations
    if (!email || !password) {
      setErrorMessage('Please enter email and password.');
      return;
    }
    if (!email.toLowerCase().endsWith('@iiita.ac.in')) {
       setErrorMessage('Please use a valid IIITA email address (@iiita.ac.in).');
       return;
    }
    if (password.length < 6) {
       setErrorMessage('Password must be at least 6 characters long.');
       return;
    }

    setIsLoading(true);
    try {
      const body = { name: name.trim(), email: email.trim(), password }; // Send password directly
      console.log("Register: Sending initiate request to KDC:", body.email);

      // Use kdcClient to hit KDC endpoint
      const res = await kdcClient.post(`/auth/initiate-registration`, body);

      setMessage(res.data.message || 'OTP Sent! Please check your email.');
      setSubmittedEmail(email.trim()); // Store the email used
      setStage('enterOtp'); // Move to next stage
      setFormData({ ...formData, password: '' }); // Clear password field for security
      setOtp(''); // Clear any previous OTP attempts

    } catch (err) {
       console.error('Initiate Registration Error:', err.response ? err.response.data : err.message, err);
       const errorMsg = err.response?.data?.message || err.response?.data?.errors?.[0]?.msg || 'Registration initiation failed. Please try again.';
       setErrorMessage(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  // --- Step 2: Submit OTP for Verification ---
  const handleSubmitOtp = async (e) => {
    e.preventDefault();
    setMessage('');
    setErrorMessage('');

    if (!otp || otp.length !== 6) {
       setErrorMessage('Please enter the 6-digit OTP.');
       return;
    }

    setIsLoading(true);
    try {
      const body = { email: submittedEmail, otp }; // Use the stored email
      console.log("Register: Sending verify request to KDC:", body.email);

      // Use kdcClient to hit KDC endpoint
      const res = await kdcClient.post(`/auth/verify-registration`, body);

      setMessage(res.data.message || 'Registration successful! Redirecting to login...');
      // Add a delay so user can see the success message and key instruction
      setTimeout(() => {
        navigate('/login'); // Redirect to login page after success
      }, 3000); // 3 second delay

    } catch (err) {
       console.error('Verify Registration Error:', err.response ? err.response.data : err.message, err);
       const errorMsg = err.response?.data?.message || err.response?.data?.errors?.[0]?.msg || 'OTP verification failed. Please check the code or initiate registration again.';
       setErrorMessage(errorMsg);
       // Optionally clear OTP field on error?
       // setOtp('');
    } finally {
      setIsLoading(false);
    }
  };

  // --- Go Back Handler ---
  const handleGoBack = () => {
      setStage('enterDetails');
      setErrorMessage('');
      setMessage('');
      setOtp('');
      setSubmittedEmail('');
      // Keep name/email fields filled from previous attempt? Optional.
      // setFormData({ name: '', email: '', password: '' });
  };

  // --- Render Logic ---
  return (
    <div>
      <Navbar />
      <div className="flex justify-center items-center min-h-screen pt-16 bg-gray-100">
        <div className="w-full max-w-md p-8 space-y-6 bg-white rounded-lg shadow-md">

          {/* Stage 1: Enter Details */}
          {stage === 'enterDetails' && (
            <>
              <h2 className="text-2xl font-bold text-center text-gray-800">Register</h2>
              {/* Message Area */}
              {message && !errorMessage && ( <div className="p-3 rounded text-center text-sm bg-green-100 text-green-700"> {message} </div> )}
              {errorMessage && ( <div className="p-3 rounded text-center text-sm bg-red-100 text-red-700"> {errorMessage} </div> )}

              <form onSubmit={handleSubmitDetails} className="space-y-4">
                {/* Name Input */}
                <div>
                  <label htmlFor="name" className="block text-sm font-medium text-gray-700">Name (Optional)</label>
                  <input type="text" id="name" placeholder="Your Name" name="name" value={name} onChange={onChangeDetails} className="w-full p-2 mt-1 border rounded-md focus:ring-blue-500 focus:border-blue-500"/>
                </div>
                {/* Email Input */}
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-700">IIITA Email*</label>
                  <input type="email" id="email" placeholder="user@iiita.ac.in" name="email" value={email} onChange={onChangeDetails} required className="w-full p-2 mt-1 border rounded-md focus:ring-blue-500 focus:border-blue-500" />
                </div>
                {/* Password Input */}
                <div>
                  <label htmlFor="password"className="block text-sm font-medium text-gray-700">Password* (min 6 chars)</label>
                  <input type="password" id="password" placeholder="Password" name="password" value={password} onChange={onChangeDetails} required minLength="6" className="w-full p-2 mt-1 border rounded-md focus:ring-blue-500 focus:border-blue-500" />
                </div>
                {/* Submit Button */}
                <button type="submit" disabled={isLoading} className={`w-full p-2 rounded-md text-white font-semibold ${ isLoading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700' }`} >
                  {isLoading ? 'Sending OTP...' : 'Register & Send OTP'}
                </button>
              </form>
               <p className="text-sm text-center text-gray-600">
                   Already have an account?{' '}
                   <Link to="/login" className="font-medium text-blue-600 hover:underline">
                       Log In
                   </Link>
               </p>
            </>
          )}

          {/* Stage 2: Enter OTP */}
          {stage === 'enterOtp' && (
             <>
              <h2 className="text-2xl font-bold text-center text-gray-800">Verify Your Email</h2>
               {/* Message Area */}
              {message && !errorMessage && ( <div className="p-3 rounded text-center text-sm bg-green-100 text-green-700"> {message} </div> )}
              {errorMessage && ( <div className="p-3 rounded text-center text-sm bg-red-100 text-red-700"> {errorMessage} </div> )}

              <p className="text-sm text-center text-gray-600">
                An OTP has been sent to <strong>{submittedEmail}</strong>. Please enter it below. It expires in 10 minutes. Check your spam folder if needed.
              </p>

              <form onSubmit={handleSubmitOtp} className="space-y-4">
                 {/* OTP Input */}
                <div>
                  <label htmlFor="otp" className="block text-sm font-medium text-gray-700">Enter 6-Digit OTP</label>
                  <input type="text" id="otp" placeholder="123456" name="otp" value={otp} onChange={onChangeOtp} maxLength="6" required inputMode="numeric" pattern="\d{6}" className="w-full p-2 mt-1 border rounded-md focus:ring-blue-500 focus:border-blue-500 tracking-widest text-center" />
                </div>
                 {/* Submit Button */}
                <button type="submit" disabled={isLoading} className={`w-full p-2 rounded-md text-white font-semibold ${ isLoading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700' }`} >
                  {isLoading ? 'Verifying...' : 'Verify OTP & Complete Registration'}
                </button>
              </form>
              {/* Go Back Button */}
               <button onClick={handleGoBack} disabled={isLoading} className="w-full text-sm text-center text-gray-600 hover:underline mt-2 disabled:text-gray-400">
                  Go Back / Change Email
               </button>
            </>
          )}

        </div>
      </div>
    </div>
  );
};

export default Register;