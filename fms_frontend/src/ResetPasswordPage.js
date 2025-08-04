import React, { useState, useEffect } from 'react';
import axios from 'axios';

function ResetPasswordPage({ token, onComplete }) {
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);
    const [loading, setLoading] = useState(false);
    const [tokenValid, setTokenValid] = useState(false);
    const [tokenChecked, setTokenChecked] = useState(false);

    // Verify token validity on page load
    useEffect(() => {
        const verifyToken = async () => {
            if (!token) {
                setError('Invalid reset link.');
                setTokenChecked(true);
                return;
            }

            try {
                setLoading(true);
                const response = await axios.get(`/fms-api/verify-reset-token/${token}`);
                if (response.data.valid) {
                    setTokenValid(true);
                } else {
                    setError('This reset link is invalid or has expired.');
                }
            } catch (err) {
                setError('This reset link is invalid or has expired.');
            } finally {
                setLoading(false);
                setTokenChecked(true);
            }
        };

        verifyToken();
    }, [token]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        // Validate passwords
        if (password !== confirmPassword) {
            setError('Passwords do not match.');
            return;
        }

        if (password.length < 8) {
            setError('Password must be at least 8 characters long.');
            return;
        }

        try {
            setLoading(true);
            const response = await axios.post('/fms-api/reset-password', {
                token,
                password
            });
            
            setSuccess(true);
            setTimeout(() => {
                if (onComplete) onComplete();
            }, 3000);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to reset password.');
        } finally {
            setLoading(false);
        }
    };

    if (!tokenChecked) {
        return <div style={{ marginTop: '100px', textAlign: 'center' }}>Verifying reset link...</div>;
    }

    if (!tokenValid && tokenChecked) {
        return (
            <div style={{ marginTop: '100px', textAlign: 'center' }}>
                <h2>Password Reset Failed</h2>
                <p style={{ color: 'red' }}>{error}</p>
                <p>Please request a new password reset link.</p>
                <button onClick={onComplete}>Return to Login</button>
            </div>
        );
    }

    return (
        <div style={{ marginTop: '100px', textAlign: 'center' }}>
            <h2>Reset Your Password</h2>
            
            {error && <div style={{ color: 'red', marginBottom: '10px' }}>{error}</div>}
            
            {success ? (
                <div style={{ color: 'green', marginBottom: '10px' }}>
                    Password has been successfully reset. Redirecting to login page...
                </div>
            ) : (
                <form onSubmit={handleSubmit}>
                    <div>
                        <input 
                            type="password" 
                            placeholder="New Password" 
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            disabled={loading}
                            style={{ marginBottom: '10px' }}
                            required
                        />
                    </div>
                    <div>
                        <input 
                            type="password" 
                            placeholder="Confirm New Password" 
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            disabled={loading}
                            style={{ marginBottom: '20px' }}
                            required
                        />
                    </div>
                    <div>
                        <button 
                            type="submit" 
                            disabled={loading}
                        >
                            {loading ? 'Processing...' : 'Reset Password'}
                        </button>
                    </div>
                </form>
            )}
        </div>
    );
}

export default ResetPasswordPage;
