import React, { useState, useEffect } from 'react';
import LoginPage from './LoginPage.js';
import Dashboard from './Dashboard.js';
import ResetPasswordPage from './ResetPasswordPage.js';
import RegisterPage from './RegisterPage.js';

function App() {
    const [userData, setUserData] = useState(null);
    const [currentPage, setCurrentPage] = useState('login');
    const [resetToken, setResetToken] = useState(null);
    const [showRegister, setShowRegister] = useState(false);
    
    useEffect(() => {
        // Check for localStorage data
        const storedUserData = localStorage.getItem('userData');
        if (storedUserData) {
            try {
                setUserData(JSON.parse(storedUserData));
            } catch (error) {
                localStorage.removeItem('userData');
                localStorage.removeItem('token');
            }
        }
        
        // Check URL for reset token using query parameter
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        if (token) {
            setCurrentPage('reset');
            setResetToken(token);
        }
    }, []);
    
    const handleLoginSuccess = (data) => {
        setUserData(data);
    };
    
    const handleLogout = () => {
        localStorage.removeItem('userData');
        localStorage.removeItem('token');
        setUserData(null);
    };
    
    const handleResetComplete = () => {
        setCurrentPage('login');
        window.history.pushState({}, '', '/');
    };
    
    const handleRegister = () => {
        setShowRegister(true);
    };

    const handleCancelRegister = () => {
        setShowRegister(false);
    };
    
    if (currentPage === 'reset' && resetToken) {
        return <ResetPasswordPage token={resetToken} onComplete={handleResetComplete} />;
    } else if (showRegister) {
        return <RegisterPage onCancel={handleCancelRegister} />;
    } else if (userData) {
        return <Dashboard userData={userData} onLogout={handleLogout} />;
    } else {
        return <LoginPage onLoginSuccess={handleLoginSuccess} onRegister={handleRegister} />;
    }
}

export default App;
