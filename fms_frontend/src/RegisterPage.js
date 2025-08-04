import React, { useState, useEffect } from 'react';
import axios from 'axios';

function RegisterPage({ onCancel }) {
    // Form data state
    const [formData, setFormData] = useState({
        username: '',
        password: '',
        confirmPassword: '',
        first_name: '',
        last_name: '',
        email: '',
        university: 'Newcastle University',
        company: '',
        faculty: '',
        institute: '',
        building: '',
        room: '',
        phone_number: '',
        profile_link: '',
        photo_link: '',
        linkedin_link: '',
        group_website: '',
        facility_id: 1, // Default to NUSBF
        requested_role: 'facility_user' // Default role
    });

    // State for facilities dropdown
    const [facilities, setFacilities] = useState([]);
    
    // State for form submission
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);

    // Fetch facilities on component mount
    useEffect(() => {
        const fetchFacilities = async () => {
            try {
                const response = await axios.get('/fms-api/facilities-public'); // Using a public endpoint that doesn't require auth
                setFacilities(response.data);
            } catch (err) {
                console.error('Failed to fetch facilities:', err);
                // Default to NUSBF if facilities can't be fetched
                setFacilities([{ id: 1, short_name: 'NUSBF', long_name: 'Newcastle University Structural Biology Facility' }]);
            }
        };

        fetchFacilities();
    }, []);

    // Handle input changes
    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData({
            ...formData,
            [name]: value
        });
    };

    // Handle form submission
    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setIsLoading(true);

        // Validate passwords match
        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match');
            setIsLoading(false);
            return;
        }

        // Validate required fields
        const requiredFields = ['username', 'password', 'first_name', 'last_name', 'email'];
        for (const field of requiredFields) {
            if (!formData[field]) {
                setError(`${field.replace('_', ' ')} is required`);
                setIsLoading(false);
                return;
            }
        }

        try {
            // Submit registration
            const response = await axios.post('/fms-api/register', {
                ...formData,
                // Don't send confirmPassword to server
                confirmPassword: undefined
            });

            if (response.data.success) {
                setSuccess(true);
                window.scrollTo(0, 0); // Scroll to top to show success message
            } else {
                setError(response.data.message || 'Registration failed');
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to register. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div style={{ maxWidth: '600px', margin: '0 auto', padding: '20px' }}>
            <h2>Register for FMS Facilities</h2>
            
            {success ? (
                <div>
                    <div style={{ color: 'green', marginBottom: '20px' }}>
                        Registration submitted successfully! Your request will be reviewed by the facility manager.
                    </div>
                    <button onClick={onCancel}>Return to Login</button>
                </div>
            ) : (
                <form onSubmit={handleSubmit}>
                    {error && <div style={{ color: 'red', marginBottom: '20px' }}>{error}</div>}
                    
                    <h3>Required Information</h3>
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Username *</label>
                        <input
                            type="text"
                            name="username"
                            value={formData.username}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                            required
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>First Name *</label>
                        <input
                            type="text"
                            name="first_name"
                            value={formData.first_name}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                            required
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Last Name *</label>
                        <input
                            type="text"
                            name="last_name"
                            value={formData.last_name}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                            required
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Email *</label>
                        <input
                            type="email"
                            name="email"
                            value={formData.email}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                            required
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Password *</label>
                        <input
                            type="password"
                            name="password"
                            value={formData.password}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                            required
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Confirm Password *</label>
                        <input
                            type="password"
                            name="confirmPassword"
                            value={formData.confirmPassword}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                            required
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Facility *</label>
                        <select
                            name="facility_id"
                            value={formData.facility_id}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                            required
                        >
                            {facilities.map(facility => (
                                <option key={facility.id} value={facility.id}>
                                    {facility.short_name} - {facility.long_name}
                                </option>
                            ))}
                        </select>
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Requested Role *</label>
                        <select
                            name="requested_role"
                            value={formData.requested_role}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                            required
                        >
                            <option value="facility_user">Facility User</option>
                            <option value="facility_staff">Facility Staff</option>
                            <option value="facility_manager">Facility Manager</option>
                            <option value="facility_superuser">Facility Superuser</option>
                        </select>
                    </div>
                    
                    <h3>Optional Information</h3>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>University</label>
                        <input
                            type="text"
                            name="university"
                            value={formData.university}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Company</label>
                        <input
                            type="text"
                            name="company"
                            value={formData.company}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Faculty</label>
                        <input
                            type="text"
                            name="faculty"
                            value={formData.faculty}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Institute</label>
                        <input
                            type="text"
                            name="institute"
                            value={formData.institute}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Building</label>
                        <input
                            type="text"
                            name="building"
                            value={formData.building}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Room</label>
                        <input
                            type="text"
                            name="room"
                            value={formData.room}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Phone Number</label>
                        <input
                            type="text"
                            name="phone_number"
                            value={formData.phone_number}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Profile Link</label>
                        <input
                            type="url"
                            name="profile_link"
                            value={formData.profile_link}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>LinkedIn Link</label>
                        <input
                            type="url"
                            name="linkedin_link"
                            value={formData.linkedin_link}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                        />
                    </div>
                    
                    <div className="form-group" style={{ marginBottom: '15px' }}>
                        <label>Group Website</label>
                        <input
                            type="url"
                            name="group_website"
                            value={formData.group_website}
                            onChange={handleChange}
                            style={{ width: '100%', padding: '8px' }}
                        />
                    </div>
                    
                    <div style={{ marginTop: '20px' }}>
                        <button 
                            type="submit" 
                            disabled={isLoading}
                            style={{ 
                                padding: '10px 20px', 
                                backgroundColor: '#0066cc', 
                                color: 'white', 
                                border: 'none', 
                                borderRadius: '4px',
                                cursor: 'pointer',
                                marginRight: '10px'
                            }}
                        >
                            {isLoading ? 'Submitting...' : 'Register'}
                        </button>
                        <button 
                            type="button" 
                            onClick={onCancel}
                            style={{ 
                                padding: '10px 20px', 
                                backgroundColor: '#f2f2f2', 
                                border: '1px solid #ccc', 
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            Cancel
                        </button>
                    </div>
                </form>
            )}
        </div>
    );
}

export default RegisterPage;
