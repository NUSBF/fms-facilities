import React, { useState } from 'react';
import axios from 'axios';

function LoginPage({ onLoginSuccess, onRegister }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const [resetMessage, setResetMessage] = useState('');
    const [resetLoading, setResetLoading] = useState(false);

    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');
        
        // Simple validation
        if (!username || !password) {
            setError('Username and password are required');
            return;
        }
        
        setIsLoading(true);
        
        try {
            // Restore original API endpoint
            const response = await axios.post('/fms-api/login', {
                username: username.trim(),
                password: password
            });
            
            if (response.data.success) {
                const userData = {
                    user: response.data.user,
                    roles: response.data.roles
                };
                
                // Store in localStorage as it was before
                localStorage.setItem('userData', JSON.stringify(userData));
                localStorage.setItem('token', response.data.user.id);
                
                onLoginSuccess(userData);
            } else {
                setError(response.data.message || 'Login failed');
            }
        } catch (err) {
            setError('Failed to connect to server');
        } finally {
            setIsLoading(false);
        }
   };
    
const handleResetPassword = async () => {
    // Clear previous messages
    setResetMessage('');
    setError('');
    
    console.log('Password reset requested for username:', username);
    
    // Validate username
    if (!username.trim()) {
        console.log('Reset failed: No username entered');
        setError('Please enter your username first');
        return;
    }
    
    setResetLoading(true);
    
    try {
        console.log('Sending reset request to /fms-api/reset-password-request');
        const response = await axios.post('/fms-api/reset-password-request', {
            username: username.trim(),
        });
        
        console.log('Reset response received:', response.data);
        setResetMessage('If your account exists, a password reset link has been sent to your email.');
    } catch (err) {
        console.error('Reset request error:', err);
        // Always display the same message even if the request fails
        // This prevents username enumeration attacks
        setResetMessage('If your account exists, a password reset link has been sent to your email.');
    } finally {
        setResetLoading(false);
    }
};

    return (
        <div style={{ marginTop: '100px', textAlign: 'center' }}>
            <h2>Login to FMS Facilities</h2>
            {error && <div style={{ color: 'red', marginBottom: '10px' }}>{error}</div>}
            {resetMessage && <div style={{ color: 'green', marginBottom: '10px' }}>{resetMessage}</div>}
            <form onSubmit={handleLogin}>
                <div>
                    <input 
                        type="text" 
                        placeholder="Username" 
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        disabled={isLoading || resetLoading}
                        autoComplete="username"
                    />
                </div>
                <div style={{ position: 'relative', display: 'inline-block' }}>
                    <input 
                        type={showPassword ? "text" : "password"}
                        placeholder="Password" 
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        style={{ marginTop: '10px' }}
                        disabled={isLoading || resetLoading}
                        autoComplete="current-password"
                    />
                    <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        style={{
                            position: 'absolute',
                            right: '5px',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            border: 'none',
                            background: 'transparent',
                            cursor: 'pointer',
                            padding: '0 5px',
                            marginTop: '5px'
                        }}
                        disabled={isLoading || resetLoading}
                    >
                        {showPassword ? '👁️' : '👁️‍🗨️'}
                    </button>
                </div>
                <div>
                    <button 
                        type="submit" 
                        style={{ marginTop: '20px' }}
                        disabled={isLoading || resetLoading}
                    >
                        {isLoading ? 'Logging in...' : 'Login'}
                    </button>
                </div>
                <div style={{ marginTop: '10px' }}>
    <a 
        href="#" 
        onClick={(e) => {
            e.preventDefault();
            handleResetPassword();
        }}
        style={{ 
            color: '#0066cc', 
            textDecoration: 'none',
            fontSize: '14px',
            marginRight: '15px'
        }}
        disabled={resetLoading}
    >
        {resetLoading ? 'Processing...' : 'Forgot password?'}
    </a>
    <a 
        href="#" 
        onClick={(e) => {
            e.preventDefault();
            onRegister();
        }}
        style={{ 
            color: '#0066cc', 
            textDecoration: 'none',
            fontSize: '14px'
        }}
    >
        Register
                    </a>
                </div>
            </form>
        </div>
    );
}

export default LoginPage;
