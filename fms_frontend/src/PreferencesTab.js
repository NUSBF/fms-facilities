import React, { useState, useEffect } from 'react';
import axios from 'axios';

function PreferencesTab({ userData }) {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [preferences, setPreferences] = useState({
        facility_logo_file_id: null,
        user_image_file_id: null,
        theme: 'light',
        language: 'en',
        notifications: true,
        auto_save: true,
        default_view: 'facilities'
    });

    // Image handling states
    const [facilityLogo, setFacilityLogo] = useState('');
    const [userImage, setUserImage] = useState('');
    const [userFiles, setUserFiles] = useState([]);

    const fetchUserFiles = async () => {
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };

            const response = await axios.get('/fms-api/file-uploads', config);
            // Filter only image files that belong to the current user
            const imageFiles = response.data.filter(file =>
                file.file_category === 'image' &&
                file.file_type && file.file_type.startsWith('image/')
            );
            setUserFiles(imageFiles);
        } catch (err) {
            setError('Failed to load user files');
            console.error('Error fetching user files:', err);
        }
    };

    const fetchUserPreferences = async () => {
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };

            const response = await axios.get('/fms-api/user-preferences', config);
            const prefs = response.data;

            setPreferences({
                facility_logo_file_id: prefs.facility_logo_file_id,
                user_image_file_id: prefs.user_image_file_id,
                theme: prefs.theme || 'light',
                language: prefs.language || 'en',
                notifications: prefs.notifications !== undefined ? prefs.notifications : true,
                auto_save: prefs.auto_save !== undefined ? prefs.auto_save : true,
                default_view: prefs.default_view || 'facilities'
            });

            // Set image paths for display
            if (prefs.facility_logo_path) {
                setFacilityLogo(prefs.facility_logo_path);
                localStorage.setItem('facilityLogo', prefs.facility_logo_path);
            }
            if (prefs.user_image_path) {
                setUserImage(prefs.user_image_path);
                localStorage.setItem('userImage', prefs.user_image_path);
            }
        } catch (err) {
            setError('Failed to load user preferences');
            console.error('Error fetching user preferences:', err);
        }
    };

    const handleFileSelection = async (type, fileId) => {
        const selectedFile = userFiles.find(file => file.id === parseInt(fileId));
        if (selectedFile) {
            const updatedPreferences = { ...preferences };

            if (type === 'facility') {
                updatedPreferences.facility_logo_file_id = parseInt(fileId);
                setFacilityLogo(selectedFile.file_path);
                localStorage.setItem('facilityLogo', selectedFile.file_path);
            } else if (type === 'user') {
                updatedPreferences.user_image_file_id = parseInt(fileId);
                setUserImage(selectedFile.file_path);
                localStorage.setItem('userImage', selectedFile.file_path);
            }

            setPreferences(updatedPreferences);

            // Auto-save the preference
            await savePreferences(updatedPreferences);

            // Trigger a page refresh to update the dashboard
            window.location.reload();
        }
    };

    const handleRemoveImage = async (type) => {
        const updatedPreferences = { ...preferences };

        if (type === 'facility') {
            updatedPreferences.facility_logo_file_id = null;
            setFacilityLogo('');
            localStorage.removeItem('facilityLogo');
        } else if (type === 'user') {
            updatedPreferences.user_image_file_id = null;
            setUserImage('');
            localStorage.removeItem('userImage');
        }

        setPreferences(updatedPreferences);

        // Auto-save the preference
        await savePreferences(updatedPreferences);

        // Trigger a page refresh to update the dashboard
        window.location.reload();
    };

    const savePreferences = async (prefsToSave = preferences) => {
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };

            await axios.put('/fms-api/user-preferences', prefsToSave, config);
            setError('');
            return true;
        } catch (err) {
            setError('Failed to save preferences. Please try again.');
            console.error('Error saving preferences:', err);
            return false;
        }
    };

    useEffect(() => {
        // Fetch user preferences and files on component mount
        fetchUserPreferences();
        fetchUserFiles();
    }, []);

    const handlePreferenceChange = (key, value) => {
        const updatedPreferences = {
            ...preferences,
            [key]: value
        };
        setPreferences(updatedPreferences);
    };

    const handleSavePreferences = async () => {
        setLoading(true);
        const success = await savePreferences();
        if (success) {
            alert('Preferences saved successfully!');
        }
        setLoading(false);
    };

    return (
        <div style={{ padding: '20px' }}>
            <h3>User Preferences</h3>

            {error && <div style={{ color: 'red', marginBottom: '15px' }}>{error}</div>}

            <div style={{ maxWidth: '600px' }}>
                {/* Facility Logo Upload */}
                <div style={{ marginBottom: '30px', padding: '20px', border: '1px solid #ddd', borderRadius: '8px', backgroundColor: '#f9f9f9' }}>
                    <h4 style={{ marginTop: 0, marginBottom: '15px' }}>Facility Logo</h4>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginBottom: '15px' }}>
                        {facilityLogo ? (
                            <img
                                src={facilityLogo}
                                alt="Facility Logo Preview"
                                style={{
                                    height: '60px',
                                    width: 'auto',
                                    maxWidth: '150px',
                                    objectFit: 'contain',
                                    border: '1px solid #ccc',
                                    borderRadius: '4px'
                                }}
                            />
                        ) : (
                            <div style={{
                                height: '60px',
                                width: '60px',
                                backgroundColor: '#007bff',
                                borderRadius: '8px',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                color: 'white',
                                fontSize: '16px',
                                fontWeight: 'bold'
                            }}>
                                FMS
                            </div>
                        )}
                        <div>
                            <p style={{ margin: 0, fontSize: '14px', color: '#666' }}>
                                Select a logo from your uploaded files
                            </p>
                            <small style={{ color: '#888' }}>Choose from files you've uploaded to the system</small>
                        </div>
                    </div>
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                        <select
                            value={preferences.facility_logo_file_id || ''}
                            onChange={(e) => handleFileSelection('facility', e.target.value)}
                            style={{
                                padding: '8px 12px',
                                border: '1px solid #ccc',
                                borderRadius: '4px',
                                backgroundColor: 'white',
                                fontSize: '14px',
                                minWidth: '200px'
                            }}
                        >
                            <option value="">Select a file...</option>
                            {userFiles.map(file => (
                                <option key={file.id} value={file.id}>
                                    {file.original_name}
                                </option>
                            ))}
                        </select>
                        {facilityLogo && (
                            <button
                                onClick={() => handleRemoveImage('facility')}
                                style={{
                                    padding: '8px 16px',
                                    backgroundColor: '#dc3545',
                                    color: 'white',
                                    border: 'none',
                                    borderRadius: '4px',
                                    cursor: 'pointer'
                                }}
                            >
                                Remove
                            </button>
                        )}
                    </div>
                </div>

                {/* User Profile Image Upload */}
                <div style={{ marginBottom: '30px', padding: '20px', border: '1px solid #ddd', borderRadius: '8px', backgroundColor: '#f9f9f9' }}>
                    <h4 style={{ marginTop: 0, marginBottom: '15px' }}>Profile Image</h4>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginBottom: '15px' }}>
                        {userImage ? (
                            <img
                                src={userImage}
                                alt="User Profile Preview"
                                style={{
                                    width: '60px',
                                    height: '60px',
                                    borderRadius: '50%',
                                    objectFit: 'cover',
                                    border: '3px solid #007bff'
                                }}
                            />
                        ) : (
                            <div style={{
                                width: '60px',
                                height: '60px',
                                borderRadius: '50%',
                                backgroundColor: '#007bff',
                                color: 'white',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                fontSize: '20px'
                            }}>
                                {userData.user.first_name ? userData.user.first_name.charAt(0) : ''}
                                {userData.user.last_name ? userData.user.last_name.charAt(0) : ''}
                            </div>
                        )}
                        <div>
                            <p style={{ margin: 0, fontSize: '14px', color: '#666' }}>
                                Select your profile picture from uploaded files
                            </p>
                            <small style={{ color: '#888' }}>Choose from files you've uploaded to the system</small>
                        </div>
                    </div>
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                        <select
                            value={preferences.user_image_file_id || ''}
                            onChange={(e) => handleFileSelection('user', e.target.value)}
                            style={{
                                padding: '8px 12px',
                                border: '1px solid #ccc',
                                borderRadius: '4px',
                                backgroundColor: 'white',
                                fontSize: '14px',
                                minWidth: '200px'
                            }}
                        >
                            <option value="">Select a file...</option>
                            {userFiles.map(file => (
                                <option key={file.id} value={file.id}>
                                    {file.original_name}
                                </option>
                            ))}
                        </select>
                        {userImage && (
                            <button
                                onClick={() => handleRemoveImage('user')}
                                style={{
                                    padding: '8px 16px',
                                    backgroundColor: '#dc3545',
                                    color: 'white',
                                    border: 'none',
                                    borderRadius: '4px',
                                    cursor: 'pointer'
                                }}
                            >
                                Remove
                            </button>
                        )}
                    </div>
                </div>

                {/* Save Button */}
                <button
                    onClick={handleSavePreferences}
                    disabled={loading}
                    style={{
                        padding: '10px 20px',
                        backgroundColor: '#0066cc',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: loading ? 'not-allowed' : 'pointer',
                        opacity: loading ? 0.6 : 1
                    }}
                >
                    {loading ? 'Saving...' : 'Save Preferences'}
                </button>
            </div>
        </div>
    );
}

export default PreferencesTab;
