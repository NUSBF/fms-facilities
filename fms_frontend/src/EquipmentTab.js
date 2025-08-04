import React, { useState } from 'react';
import axios from 'axios';

function EquipmentTab({ equipment, facilities, userData, onEquipmentUpdate }) {
    const [showAddEquipmentModal, setShowAddEquipmentModal] = useState(false);
    const [newEquipment, setNewEquipment] = useState({
        name: '',
        model: '',
        serial_number: '',
        facility_id: '',
        description: '',
        status: 'available',
        price_per_hour: '',
        image: null
    });
    const [imagePreview, setImagePreview] = useState(null);
    const [uploading, setUploading] = useState(false);

    // Function to check if user can manage equipment
    const canManageEquipment = () => {
        // Check if user has developer, facility_manager, or facility_staff role
        if (!userData || !userData.roles) return false;
        return userData.roles.some(role => 
            ['developer', 'facility_manager', 'facility_staff'].includes(role.role)
        );
    };

    // Handle image file selection and preview
    const handleImageChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            // Validate file type
            if (!file.type.startsWith('image/')) {
                alert('Please select a valid image file');
                return;
            }
            
            // Validate file size (5MB limit)
            if (file.size > 5 * 1024 * 1024) {
                alert('Image file size must be less than 5MB');
                return;
            }
            
            // Create preview URL
            const previewUrl = URL.createObjectURL(file);
            setImagePreview(previewUrl);
            
            // Update equipment state with file
            setNewEquipment(prev => ({
                ...prev,
                image: file
            }));
        }
    };

    // Remove selected image and clear preview
    const removeImage = () => {
        setImagePreview(null);
        setNewEquipment(prev => ({
            ...prev,
            image: null
        }));
    };

    // Handle form submission for adding new equipment
    const handleAddEquipment = async (e) => {
        e.preventDefault();
        
        // Validate required fields
        if (!newEquipment.name || !newEquipment.facility_id) {
            alert('Please fill in all required fields');
            return;
        }
        
        try {
            setUploading(true);
            const token = localStorage.getItem('token');
            
            // Create FormData for file upload
            const formData = new FormData();
            formData.append('name', newEquipment.name);
            formData.append('model', newEquipment.model);
            formData.append('serial_number', newEquipment.serial_number);
            formData.append('facility_id', newEquipment.facility_id);
            formData.append('description', newEquipment.description);
            formData.append('status', newEquipment.status);
            formData.append('price_per_hour', newEquipment.price_per_hour);
            
            if (newEquipment.image) {
                formData.append('image', newEquipment.image);
            }
            
            const response = await axios.post('/fms-api/equipment', formData, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'multipart/form-data'
                }
            });
            
            // Update parent component with new equipment
            onEquipmentUpdate(response.data);
            
            // Reset form and close modal
            setNewEquipment({
                name: '',
                model: '',
                serial_number: '',
                facility_id: '',
                description: '',
                status: 'available',
                price_per_hour: '',
                image: null
            });
            setImagePreview(null);
            setShowAddEquipmentModal(false);
            
        } catch (error) {
            console.error('Error adding equipment:', error);
            alert('Failed to add equipment. Please try again.');
        } finally {
            setUploading(false);
        }
    };

    return (
        <>
            <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                    <h2>Equipment</h2>
                    {canManageEquipment() && (
                        <button
                            style={{
                                padding: '10px 20px',
                                backgroundColor: '#007bff',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer',
                                fontSize: '14px',
                                fontWeight: 'bold'
                            }}
                            onMouseEnter={(e) => e.target.style.backgroundColor = '#0056b3'}
                            onMouseLeave={(e) => e.target.style.backgroundColor = '#007bff'}
                            onClick={() => setShowAddEquipmentModal(true)}
                        >
                            Add Equipment
                        </button>
                    )}
                </div>
                {equipment.length === 0 ? (
                    <p>No equipment available.</p>
                ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                            <tr>
                                <th style={{ border: '1px solid #ddd', padding: '8px', textAlign: 'left' }}>Name</th>
                                <th style={{ border: '1px solid #ddd', padding: '8px', textAlign: 'left' }}>Model</th>
                                <th style={{ border: '1px solid #ddd', padding: '8px', textAlign: 'left' }}>Status</th>
                                <th style={{ border: '1px solid #ddd', padding: '8px', textAlign: 'left' }}>Price/Hour</th>
                            </tr>
                        </thead>
                        <tbody>
                            {equipment.map(e => (
                                <tr key={e.id}>
                                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{e.name}</td>
                                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{e.model}</td>
                                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{e.status}</td>
                                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>${e.price_per_hour}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {/* Add Equipment Modal */}
            {showAddEquipmentModal && (
                <div style={{
                    position: 'fixed',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    backgroundColor: 'rgba(0, 0, 0, 0.5)',
                    display: 'flex',
                    justifyContent: 'center',
                    alignItems: 'center',
                    zIndex: 1000
                }}>
                    <div style={{
                        backgroundColor: 'white',
                        padding: '20px',
                        borderRadius: '8px',
                        width: '500px',
                        maxHeight: '80vh',
                        overflow: 'auto'
                    }}>
                        <h3>Add New Equipment</h3>
                        <form onSubmit={handleAddEquipment}>
                            <div style={{ marginBottom: '15px' }}>
                                <label style={{ display: 'block', marginBottom: '5px' }}>Name *</label>
                                <input
                                    type="text"
                                    value={newEquipment.name}
                                    onChange={(e) => setNewEquipment(prev => ({...prev, name: e.target.value}))}
                                    style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px' }}
                                    required
                                />
                            </div>
                            
                            <div style={{ marginBottom: '15px' }}>
                                <label style={{ display: 'block', marginBottom: '5px' }}>Model</label>
                                <input
                                    type="text"
                                    value={newEquipment.model}
                                    onChange={(e) => setNewEquipment(prev => ({...prev, model: e.target.value}))}
                                    style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px' }}
                                />
                            </div>
                            
                            <div style={{ marginBottom: '15px' }}>
                                <label style={{ display: 'block', marginBottom: '5px' }}>Serial Number</label>
                                <input
                                    type="text"
                                    value={newEquipment.serial_number}
                                    onChange={(e) => setNewEquipment(prev => ({...prev, serial_number: e.target.value}))}
                                    style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px' }}
                                />
                            </div>
                            
                            <div style={{ marginBottom: '15px' }}>
                                <label style={{ display: 'block', marginBottom: '5px' }}>Facility *</label>
                                <select
                                    value={newEquipment.facility_id}
                                    onChange={(e) => setNewEquipment(prev => ({...prev, facility_id: e.target.value}))}
                                    style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px' }}
                                    required
                                >
                                    <option value="">Select a facility</option>
                                    {facilities.map(facility => (
                                        <option key={facility.id} value={facility.id}>
                                            {facility.short_name} - {facility.long_name}
                                        </option>
                                    ))}
                                </select>
                            </div>
                            
                            <div style={{ marginBottom: '15px' }}>
                                <label style={{ display: 'block', marginBottom: '5px' }}>Description</label>
                                <textarea
                                    value={newEquipment.description}
                                    onChange={(e) => setNewEquipment(prev => ({...prev, description: e.target.value}))}
                                    style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px', height: '80px' }}
                                />
                            </div>
                            
                            <div style={{ marginBottom: '15px' }}>
                                <label style={{ display: 'block', marginBottom: '5px' }}>Status</label>
                                <select
                                    value={newEquipment.status}
                                    onChange={(e) => setNewEquipment(prev => ({...prev, status: e.target.value}))}
                                    style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px' }}
                                >
                                    <option value="available">Available</option>
                                    <option value="maintenance">Maintenance</option>
                                    <option value="out_of_order">Out of Order</option>
                                </select>
                            </div>
                            
                            <div style={{ marginBottom: '15px' }}>
                                <label style={{ display: 'block', marginBottom: '5px' }}>Price per Hour</label>
                                <input
                                    type="number"
                                    step="0.01"
                                    value={newEquipment.price_per_hour}
                                    onChange={(e) => setNewEquipment(prev => ({...prev, price_per_hour: e.target.value}))}
                                    style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px' }}
                                />
                            </div>
                            
                            <div style={{ marginBottom: '15px' }}>
                                <label style={{ display: 'block', marginBottom: '5px' }}>Equipment Image</label>
                                <input
                                    type="file"
                                    accept="image/*"
                                    onChange={handleImageChange}
                                    style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px' }}
                                />
                                {imagePreview && (
                                    <div style={{ marginTop: '10px' }}>
                                        <img
                                            src={imagePreview}
                                            alt="Preview"
                                            style={{ maxWidth: '200px', maxHeight: '150px', objectFit: 'cover' }}
                                        />
                                        <button
                                            type="button"
                                            onClick={removeImage}
                                            style={{
                                                marginLeft: '10px',
                                                padding: '5px 10px',
                                                backgroundColor: '#dc3545',
                                                color: 'white',
                                                border: 'none',
                                                borderRadius: '4px',
                                                cursor: 'pointer'
                                            }}
                                        >
                                            Remove
                                        </button>
                                    </div>
                                )}
                            </div>
                            
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                <button
                                    type="button"
                                    onClick={() => setShowAddEquipmentModal(false)}
                                    style={{
                                        padding: '10px 20px',
                                        backgroundColor: '#6c757d',
                                        color: 'white',
                                        border: 'none',
                                        borderRadius: '4px',
                                        cursor: 'pointer'
                                    }}
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={uploading}
                                    style={{
                                        padding: '10px 20px',
                                        backgroundColor: uploading ? '#ccc' : '#007bff',
                                        color: 'white',
                                        border: 'none',
                                        borderRadius: '4px',
                                        cursor: uploading ? 'not-allowed' : 'pointer'
                                    }}
                                >
                                    {uploading ? 'Adding...' : 'Add Equipment'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </>
    );
}

export default EquipmentTab;
