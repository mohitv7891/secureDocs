import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

// This component wraps routes that require authentication.
// It accepts the component to render (as children) if authenticated.
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, token } = useAuth(); // Get authentication status
  const location = useLocation(); // Get the current location

  // Check not just the boolean, but also if the token *actually* exists
  // This helps prevent brief flashes of content if auth state hydration is delayed.
  const hasAccess = isAuthenticated && token;

  if (!hasAccess) {
    // If not authenticated, redirect to the login page.
    // Pass the current location in state, so after login,
    // the user can be redirected back to where they were trying to go.
    console.log(`ProtectedRoute: Not authenticated, redirecting to login from ${location.pathname}`);
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // If authenticated, render the child component (the actual protected page)
  return children;
};

export default ProtectedRoute;