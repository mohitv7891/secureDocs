/* === File: src/main.jsx (Correct Structure Example) === */
import React from 'react';
import ReactDOM from 'react-dom/client';
// Make sure BrowserRouter is imported
import { BrowserRouter as Router } from 'react-router-dom';
import App from './App.jsx';
import { AuthProvider } from './context/AuthContext';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    {/* AuthProvider wraps Router */}
    <AuthProvider>
      {/* Router wraps App */}
      <Router>
        <App /> {/* App component contains <Routes> */}
      </Router>
    </AuthProvider>
  </React.StrictMode>,
);