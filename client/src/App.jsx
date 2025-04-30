 import React from 'react';
 import { Routes, Route } from 'react-router-dom';
 import { AuthProvider } from './context/AuthContext'; // Import here if wrapping Routes
 import Login from './pages/Login';
 import Register from './pages/Register';
 import Dashboard from './pages/Dashboard';
 import Navbar from './components/Navbar';
 import ProtectedRoute from './components/ProtectedRoute';
 import Home from './pages/Home';

 function App() {
   return (
      <AuthProvider>
       <Routes>
       <Route path="/" element={<Home />} />
         <Route path="/login" element={<Login />} />
         <Route path="/register" element={<Register />} />
         <Route
           path="/dashboard"
           element={
             <ProtectedRoute> 
               <Navbar />
               <Dashboard />
             </ProtectedRoute>
           }
         />
        {/* <Route path="*" element={<NotFound />} />   */}
      </Routes>
     </AuthProvider>
   );
   }
 export default App;