// client/pages/Login.jsx
import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom'; // Import Link
import Navbar from "../components/Navbar";
import { useAuth } from '../context/AuthContext'; // Import useAuth

const Login = () => {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const navigate = useNavigate();
  // Get the login function from the context
  const { login } = useAuth();
  const { email, password } = formData;

  // Handle input changes
  const onChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    setErrorMessage(''); // Clear error on change
  };

  // Handle form submission
  const onSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setErrorMessage('');

    if (!email || !password) {
      setErrorMessage('Please enter both email and password.');
      setIsLoading(false);
      return;
    }

    try {
        console.log("Login Page: Calling context login function...");
        // Call the login function from AuthContext
        // It handles the API call to KDC and updates global state
        const loginSuccess = await login(email.trim(), password);

        if (loginSuccess) {
             console.log('Login page: Context login reported success.');
             // Redirect to dashboard ONLY AFTER successful login confirmation
             navigate('/dashboard');
        } else {
             // This case might not happen if login function throws on failure,
             // but included for completeness.
             setErrorMessage('Login process did not complete successfully.');
        }

    } catch (err) {
      // The context login function should throw an error on failure
      // Use the error message from the response if available
      console.error('Login Page: Error during login attempt:', err);
      const errorMsg = err.response?.data?.message || err.message || 'Login failed. Please check credentials or server status.';
      setErrorMessage(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  // --- Render Logic ---
  return (
    <div>
      <Navbar />
      <div className="flex justify-center items-center min-h-screen pt-16 bg-gray-100">
        <div className="w-full max-w-md p-8 space-y-6 bg-white rounded-lg shadow-md">
          <h2 className="text-2xl font-bold text-center text-gray-800">Login</h2>
          {/* Error Message Display */}
          {errorMessage && ( <div className="p-3 rounded text-center text-sm bg-red-100 text-red-700"> {errorMessage} </div> )}

          <form onSubmit={onSubmit} className="space-y-4">
             {/* Email Input */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">IIITA Email</label>
               <input type="email" id="email" placeholder="user@iiita.ac.in" name="email" value={email} onChange={onChange} required className="w-full p-2 mt-1 border rounded-md focus:ring-blue-500 focus:border-blue-500" />
            </div>
            {/* Password Input */}
             <div>
               <label htmlFor="password"className="block text-sm font-medium text-gray-700">Password</label>
               <input type="password" id="password" placeholder="Password" name="password" value={password} onChange={onChange} required className="w-full p-2 mt-1 border rounded-md focus:ring-blue-500 focus:border-blue-500" />
            </div>
            {/* Submit Button */}
            <button type="submit" disabled={isLoading} className={`w-full p-2 rounded-md text-white font-semibold ${ isLoading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700' }`} >
              {isLoading ? 'Logging In...' : 'Login'}
            </button>
          </form>
          {/* Link to Register Page */}
           <p className="text-sm text-center text-gray-600">
                Don't have an account?{' '}
                <Link to="/register" className="font-medium text-blue-600 hover:underline">
                    Sign Up
                </Link>
            </p>
        </div>
      </div>
    </div>
  );
};

export default Login;