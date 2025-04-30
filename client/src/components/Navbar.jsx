import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext'; // Import the useAuth hook

const Navbar = () => {
  const { isAuthenticated, user, logout } = useAuth(); // Get auth state and functions
  const navigate = useNavigate();

  const handleLogout = () => {
    logout(); // Call logout from context
    navigate('/login'); // Redirect to login after logout
  };

  return (
    <nav className="bg-gray-800 text-white p-4 shadow-md">
      <div className="container mx-auto flex justify-between items-center">
        {/* Logo/Brand */}
        <Link to={isAuthenticated ? "/dashboard" : "/"} className="text-xl font-bold">
          SecureDocs
        </Link>

        {/* Navigation Links */}
        <div className="space-x-4">
          {isAuthenticated ? (
            // Links shown when logged IN
            <>
              {/* Display user info if available */}
              {user && user.id && <span className="text-gray-300 text-sm">Welcome! ({user.email})</span>}
              <Link to="/dashboard" className="hover:text-gray-300">Dashboard</Link>
              {/* Add other authenticated links here */}
              <button
                onClick={handleLogout}
                className="bg-red-600 hover:bg-red-700 px-3 py-1 rounded text-sm"
              >
                Logout
              </button>
            </>
          ) : (
            // Links shown when logged OUT
            <>
              <Link to="/login" className="hover:text-gray-300">Login</Link>
              <Link to="/register" className="hover:text-gray-300">Register</Link>
            </>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
