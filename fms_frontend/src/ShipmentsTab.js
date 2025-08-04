import React, { useState, useEffect } from 'react';
import axios from 'axios';

function ShipmentsTab({ userData }) {
    const [shipments, setShipments] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [showForm, setShowForm] = useState(false);
    const [editingShipment, setEditingShipment] = useState(null);
    const [activeShipmentsTab, setActiveShipmentsTab] = useState('diamond-light-source');
    const [showNameModal, setShowNameModal] = useState(false);
    const [shipmentName, setShipmentName] = useState('');
    const [editingShipmentName, setEditingShipmentName] = useState(false);
    const [formData, setFormData] = useState({
        courrier: 'DHL', // Default courrier
        tracking_number: '',
        sender: '',
        recipient: '',
        destination: '',
        status: 'pending',
        ship_date: (() => {
            const today = new Date();
            return today.toISOString().split('T')[0];
        })(),
        expected_delivery: (() => {
            const tomorrow = new Date();
            tomorrow.setDate(tomorrow.getDate() + 1);
            return tomorrow.toISOString().split('T')[0];
        })(),
        actual_delivery: '',
        contents: '',
        value: '',
        weight: '',
        dimensions: '',
        notes: ''
    });

    useEffect(() => {
        fetchShipments();
    }, []);

    // Generate suggested shipment name
    const generateSuggestedName = () => {
        const today = new Date();
        const day = String(today.getDate()).padStart(2, '0');
        const month = String(today.getMonth() + 1).padStart(2, '0');
        const year = today.getFullYear();
        return `Newcastle_${day}${month}${year}`;
    };

    // Handle opening the name modal for diamond shipments
    const handleAddNewShipment = () => {
        if (activeShipmentsTab === 'diamond-light-source') {
            setShipmentName(generateSuggestedName());
            setShowNameModal(true);
        } else {
            setShowForm(true);
        }
    };

    // Handle name modal confirmation
    const handleNameModalConfirm = () => {
        setShowNameModal(false);
        setFormData({
            ...formData,
            contents: shipmentName,
            destination: 'diamond-light-source'
        });
        setShowForm(true);
    };

    // Handle name modal cancel
    const handleNameModalCancel = () => {
        setShowNameModal(false);
        setShipmentName('');
    };

    // Handle editing shipment name
    const handleEditShipmentName = () => {
        setEditingShipmentName(true);
    };

    const handleSaveShipmentName = () => {
        setFormData(prev => ({
            ...prev,
            contents: shipmentName
        }));
        setEditingShipmentName(false);
    };

    const handleCancelShipmentNameEdit = () => {
        setShipmentName(formData.contents || '');
        setEditingShipmentName(false);
    };

    const fetchShipments = async () => {
        try {
            setLoading(true);
            const token = localStorage.getItem('token');
            const config = {
                headers: { Authorization: `Bearer ${token}` }
            };
            
            const response = await axios.get('/fms-api/shipments', config);
            // Get all shipments - filtering will be done in the display logic
            setShipments(response.data);
            setError('');
        } catch (error) {
            console.error('Error fetching shipments:', error);
            setError('Failed to load shipments. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const token = localStorage.getItem('token');
            const config = {
                headers: { Authorization: `Bearer ${token}` }
            };

            // Set destination based on active tab
            const submissionData = {
                ...formData,
                destination: activeShipmentsTab
            };

            if (editingShipment) {
                await axios.put(`/fms-api/shipments/${editingShipment.id}`, submissionData, config);
            } else {
                await axios.post('/fms-api/shipments', submissionData, config);
            }

            setShowForm(false);
            setEditingShipment(null);
            setFormData({
                courrier: 'DHL',
                tracking_number: '',
                sender: '',
                recipient: '',
                destination: '',
                status: 'pending',
                ship_date: '',
                expected_delivery: '',
                actual_delivery: '',
                contents: '',
                value: '',
                weight: '',
                dimensions: '',
                notes: ''
            });
            fetchShipments();
        } catch (error) {
            console.error('Error saving shipment:', error);
            setError('Failed to save shipment. Please try again.');
        }
    };

    const handleEdit = (shipment) => {
        setEditingShipment(shipment);
        setFormData({
            courrier: shipment.courrier || 'DHL',
            tracking_number: shipment.tracking_number || '',
            sender: shipment.sender || '',
            recipient: shipment.recipient || '',
            destination: shipment.destination || activeShipmentsTab || '',
            status: shipment.status || 'pending',
            ship_date: shipment.ship_date || '',
            expected_delivery: shipment.expected_delivery || '',
            actual_delivery: shipment.actual_delivery || '',
            contents: shipment.contents || '',
            value: shipment.value || '',
            weight: shipment.weight || '',
            dimensions: shipment.dimensions || '',
            notes: shipment.notes || ''
        });
        setShowForm(true);
    };

    const handleDelete = async (id) => {
        if (window.confirm('Are you sure you want to delete this shipment?')) {
            try {
                const token = localStorage.getItem('token');
                const config = {
                    headers: { Authorization: `Bearer ${token}` }
                };
                
                await axios.delete(`/fms-api/shipments/${id}`, config);
                fetchShipments();
            } catch (error) {
                console.error('Error deleting shipment:', error);
                setError('Failed to delete shipment. Please try again.');
            }
        }
    };

    const getStatusColor = (status) => {
        switch (status) {
            case 'pending':
                return '#ffc107';
            case 'shipped':
                return '#17a2b8';
            case 'in-transit':
                return '#007bff';
            case 'delivered':
                return '#28a745';
            case 'delayed':
                return '#dc3545';
            default:
                return '#6c757d';
        }
    };

    if (loading) {
        return <div style={{ textAlign: 'center', padding: '20px' }}>Loading shipments...</div>;
    }

    return (
        <div>
            <h3>Shipments Management</h3>
            
            {/* Shipments Sub-tabs */}
            <div style={{ 
                display: 'flex', 
                borderBottom: '1px solid #dee2e6',
                marginBottom: '20px',
                backgroundColor: '#f8f9fa'
            }}>
                <div 
                    onClick={() => setActiveShipmentsTab('diamond-light-source')}
                    style={{ 
                        padding: '8px 16px', 
                        cursor: 'pointer',
                        backgroundColor: activeShipmentsTab === 'diamond-light-source' ? '#ffffff' : 'transparent',
                        borderBottom: activeShipmentsTab === 'diamond-light-source' ? '2px solid #007bff' : 'none',
                        fontWeight: activeShipmentsTab === 'diamond-light-source' ? 'bold' : 'normal',
                        border: activeShipmentsTab === 'diamond-light-source' ? '1px solid #dee2e6' : 'none',
                        borderBottom: activeShipmentsTab === 'diamond-light-source' ? 'none' : '1px solid #dee2e6'
                    }}
                >
                    To Diamond Light Source
                </div>
                <div 
                    onClick={() => setActiveShipmentsTab('ebic')}
                    style={{ 
                        padding: '8px 16px', 
                        cursor: 'pointer',
                        backgroundColor: activeShipmentsTab === 'ebic' ? '#ffffff' : 'transparent',
                        borderBottom: activeShipmentsTab === 'ebic' ? '2px solid #007bff' : 'none',
                        fontWeight: activeShipmentsTab === 'ebic' ? 'bold' : 'normal',
                        border: activeShipmentsTab === 'ebic' ? '1px solid #dee2e6' : 'none',
                        borderBottom: activeShipmentsTab === 'ebic' ? 'none' : '1px solid #dee2e6'
                    }}
                >
                    To eBIC
                </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h4>Shipments {activeShipmentsTab === 'diamond-light-source' ? 'to Diamond Light Source' : 'to eBIC'}</h4>
                <button 
                    onClick={handleAddNewShipment}
                    style={{ 
                        padding: '10px 20px', 
                        backgroundColor: '#007bff', 
                        color: 'white', 
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer'
                    }}
                >
                    Add New Shipment
                </button>
            </div>

            {error && (
                <div style={{ 
                    backgroundColor: '#ffeeee', 
                    color: 'red', 
                    padding: '10px', 
                    borderRadius: '4px', 
                    marginBottom: '20px' 
                }}>
                    {error}
                </div>
            )}

            {/* Name Modal for Diamond Shipments */}
            {showNameModal && (
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
                        padding: '30px',
                        borderRadius: '8px',
                        minWidth: '400px',
                        maxWidth: '500px',
                        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.3)'
                    }}>
                        <h3 style={{ marginTop: 0, marginBottom: '20px', color: '#333' }}>
                            Diamond Light Source Shipment
                        </h3>
                        <p style={{ marginBottom: '20px', color: '#666' }}>
                            Please enter a name for this shipment:
                        </p>
                        <input
                            type="text"
                            value={shipmentName}
                            onChange={(e) => setShipmentName(e.target.value)}
                            style={{
                                width: '100%',
                                padding: '10px',
                                borderRadius: '4px',
                                border: '1px solid #ddd',
                                fontSize: '14px',
                                marginBottom: '20px'
                            }}
                            placeholder="Enter shipment name..."
                            autoFocus
                        />
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                            <button
                                onClick={handleNameModalCancel}
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
                                onClick={handleNameModalConfirm}
                                disabled={!shipmentName.trim()}
                                style={{
                                    padding: '10px 20px',
                                    backgroundColor: shipmentName.trim() ? '#007bff' : '#ccc',
                                    color: 'white',
                                    border: 'none',
                                    borderRadius: '4px',
                                    cursor: shipmentName.trim() ? 'pointer' : 'not-allowed'
                                }}
                            >
                                Continue
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {showForm && (
                <div style={{ 
                    backgroundColor: '#f8f9fa', 
                    padding: '20px', 
                    borderRadius: '4px', 
                    marginBottom: '20px' 
                }}>
                    <div style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        marginBottom: '20px',
                        gap: '15px'
                    }}>
                        {formData.contents && formData.contents.trim() ? (
                            editingShipmentName ? (
                                // Editing mode
                                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                    <input
                                        type="text"
                                        value={shipmentName}
                                        onChange={(e) => setShipmentName(e.target.value)}
                                        style={{
                                            fontSize: '18px',
                                            fontWeight: 'bold',
                                            color: '#007bff',
                                            border: '2px solid #007bff',
                                            borderRadius: '4px',
                                            padding: '5px 10px',
                                            minWidth: '200px'
                                        }}
                                        autoFocus
                                        onKeyPress={(e) => {
                                            if (e.key === 'Enter') {
                                                handleSaveShipmentName();
                                            } else if (e.key === 'Escape') {
                                                handleCancelShipmentNameEdit();
                                            }
                                        }}
                                    />
                                    <button
                                        type="button"
                                        onClick={handleSaveShipmentName}
                                        style={{
                                            padding: '5px 10px',
                                            backgroundColor: '#28a745',
                                            color: 'white',
                                            border: 'none',
                                            borderRadius: '4px',
                                            cursor: 'pointer',
                                            fontSize: '12px'
                                        }}
                                    >
                                        Save
                                    </button>
                                    <button
                                        type="button"
                                        onClick={handleCancelShipmentNameEdit}
                                        style={{
                                            padding: '5px 10px',
                                            backgroundColor: '#6c757d',
                                            color: 'white',
                                            border: 'none',
                                            borderRadius: '4px',
                                            cursor: 'pointer',
                                            fontSize: '12px'
                                        }}
                                    >
                                        Cancel
                                    </button>
                                </div>
                            ) : (
                                // Display mode
                                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                    <h4 style={{ 
                                        margin: 0,
                                        color: '#007bff', 
                                        fontWeight: 'bold',
                                        fontSize: '18px'
                                    }}>
                                        {formData.contents}
                                    </h4>
                                    <button
                                        type="button"
                                        onClick={() => {
                                            setShipmentName(formData.contents);
                                            handleEditShipmentName();
                                        }}
                                        style={{
                                            padding: '4px 8px',
                                            backgroundColor: '#007bff',
                                            color: 'white',
                                            border: 'none',
                                            borderRadius: '4px',
                                            cursor: 'pointer',
                                            fontSize: '12px'
                                        }}
                                    >
                                        Edit Name
                                    </button>
                                </div>
                            )
                        ) : (
                            <h4 style={{ margin: 0, color: '#333' }}>
                                {editingShipment ? 'Edit Shipment' : 'New Shipment'}
                            </h4>
                        )}
                    </div>
                    <form onSubmit={handleSubmit}>
                        <div style={{
                            display: 'grid',
                            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                            gap: '24px', // Increased gap for better spacing
                            background: '#fff',
                            borderRadius: '12px',
                            boxShadow: '0 2px 12px rgba(0,0,0,0.08)',
                            padding: '32px',
                            marginBottom: '16px',
                            alignItems: 'start'
                        }}>
                            {/* Courrier dropdown first */}
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Courrier:</label>
                                <select 
                                    value={formData.courrier}
                                    onChange={(e) => setFormData({...formData, courrier: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                    required
                                >
                                    <option value="DHL">DHL</option>
                                    <option value="FedEx">FedEx</option>
                                    <option value="UPS">UPS</option>
                                    <option value="RoyalMail">Royal Mail</option>
                                    <option value="TNT">TNT</option>
                                    <option value="Other">Other</option>
                                </select>
                            </div>
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Sender:</label>
                                <input 
                                    type="text"
                                    value={formData.sender}
                                    onChange={(e) => setFormData({...formData, sender: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                    required
                                />
                            </div>
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Recipient:</label>
                                <input 
                                    type="text"
                                    value={formData.recipient}
                                    onChange={(e) => setFormData({...formData, recipient: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                    required
                                />
                            </div>
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Destination:</label>
                                <select 
                                    value={formData.destination}
                                    onChange={(e) => setFormData({...formData, destination: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                    required
                                    disabled={false}
                                >
                                    <option value="">Select Destination</option>
                                    <option value="diamond-light-source">Diamond Light Source</option>
                                    <option value="ebic">eBIC</option>
                                    <option value="other">Other</option>
                                </select>
                            </div>
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Status:</label>
                                <select 
                                    value={formData.status}
                                    onChange={(e) => setFormData({...formData, status: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                >
                                    <option value="pending">Pending</option>
                                    <option value="shipped">Shipped</option>
                                    <option value="in-transit">In Transit</option>
                                    <option value="delivered">Delivered</option>
                                    <option value="delayed">Delayed</option>
                                </select>
                            </div>
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Ship Date:</label>
                                <input 
                                    type="date"
                                    value={formData.ship_date}
                                    onChange={(e) => setFormData({...formData, ship_date: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                />
                            </div>
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Expected Delivery:</label>
                                <input 
                                    type="date"
                                    value={formData.expected_delivery}
                                    onChange={(e) => setFormData({...formData, expected_delivery: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                />
                            </div>
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Actual Delivery:</label>
                                <input 
                                    type="date"
                                    value={formData.actual_delivery}
                                    onChange={(e) => setFormData({...formData, actual_delivery: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                />
                            </div>
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Value ($):</label>
                                <input 
                                    type="number"
                                    step="0.01"
                                    value={formData.value}
                                    onChange={(e) => setFormData({...formData, value: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                />
                            </div>
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Weight (kg):</label>
                                <input 
                                    type="number"
                                    step="0.01"
                                    value={formData.weight}
                                    onChange={(e) => setFormData({...formData, weight: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                />
                            </div>
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Dimensions (L x W x H):</label>
                                <input 
                                    type="text"
                                    value={formData.dimensions}
                                    onChange={(e) => setFormData({...formData, dimensions: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                    placeholder="e.g., 30cm x 20cm x 10cm"
                                />
                            </div>
                            {/* Tracking Number at the end */}
                            <div>
                                <label style={{ fontWeight: 500, marginBottom: 6, display: 'block' }}>Tracking Number:</label>
                                <input 
                                    type="text"
                                    value={formData.tracking_number}
                                    onChange={(e) => setFormData({...formData, tracking_number: e.target.value})}
                                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #e0e0e0', marginTop: '2px', fontSize: '15px' }}
                                    required
                                />
                            </div>
                        </div>
                        <div style={{ marginTop: '32px', display: 'flex', flexWrap: 'wrap', gap: '16px' }}>
                            <button 
                                type="submit"
                                style={{ 
                                    flex: '1 1 200px',
                                    padding: '12px 0', 
                                    backgroundColor: '#28a745', 
                                    color: 'white',
                                    border: 'none',
                                    borderRadius: '4px',
                                    cursor: 'pointer',
                                    fontSize: '16px',
                                    fontWeight: 'bold'
                                }}
                            >
                                {editingShipment ? 'Update Shipment' : 'Create Shipment'}
                            </button>
                            <button 
                                type="button"
                                onClick={() => {
                                    setShowForm(false);
                                    setEditingShipment(null);
                                    setFormData({
                                        courrier: 'DHL',
                                        tracking_number: '',
                                        sender: '',
                                        recipient: '',
                                        destination: activeShipmentsTab || '',
                                        status: 'pending',
                                        ship_date: '',
                                        expected_delivery: '',
                                        actual_delivery: '',
                                        contents: '',
                                        value: '',
                                        weight: '',
                                        dimensions: '',
                                        notes: ''
                                    });
                                }}
                                style={{ 
                                    flex: '1 1 200px',
                                    padding: '12px 0', 
                                    backgroundColor: '#6c757d', 
                                    color: 'white', 
                                    border: 'none',
                                    borderRadius: '4px',
                                    cursor: 'pointer',
                                    fontSize: '16px'
                                }}
                            >
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>
            )}

            {shipments.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px', color: '#666' }}>
                    <p>No shipments found.</p>
                    <p>Click "Add New Shipment" to create your first shipment record.</p>
                </div>
            ) : (
                <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '800px' }}>
                        <thead>
                            <tr style={{ backgroundColor: '#f8f9fa' }}>
                                <th style={{ border: '1px solid #dee2e6', padding: '12px', textAlign: 'left' }}>Tracking Number</th>
                                <th style={{ border: '1px solid #dee2e6', padding: '12px', textAlign: 'left' }}>Carrier</th>
                                <th style={{ border: '1px solid #dee2e6', padding: '12px', textAlign: 'left' }}>Sender</th>
                                <th style={{ border: '1px solid #dee2e6', padding: '12px', textAlign: 'left' }}>Recipient</th>
                                <th style={{ border: '1px solid #dee2e6', padding: '12px', textAlign: 'left' }}>Destination</th>
                                <th style={{ border: '1px solid #dee2e6', padding: '12px', textAlign: 'left' }}>Status</th>
                                <th style={{ border: '1px solid #dee2e6', padding: '12px', textAlign: 'left' }}>Ship Date</th>
                                <th style={{ border: '1px solid #dee2e6', padding: '12px', textAlign: 'left' }}>Expected Delivery</th>
                                <th style={{ border: '1px solid #dee2e6', padding: '12px', textAlign: 'left' }}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {shipments
                                .filter(shipment => shipment.destination === activeShipmentsTab)
                                .map(shipment => (
                                <tr key={shipment.id} style={{ borderBottom: '1px solid #dee2e6' }}>
                                    <td style={{ border: '1px solid #dee2e6', padding: '12px' }}>
                                        <strong>{shipment.tracking_number}</strong>
                                    </td>
                                    <td style={{ border: '1px solid #dee2e6', padding: '12px' }}>
                                        {shipment.carrier}
                                    </td>
                                    <td style={{ border: '1px solid #dee2e6', padding: '12px' }}>
                                        {shipment.sender}
                                    </td>
                                    <td style={{ border: '1px solid #dee2e6', padding: '12px' }}>
                                        {shipment.recipient}
                                    </td>
                                    <td style={{ border: '1px solid #dee2e6', padding: '12px' }}>
                                        {shipment.destination === 'diamond-light-source' ? 'Diamond Light Source' : 
                                         shipment.destination === 'ebic' ? 'eBIC' : 
                                         shipment.destination || 'Not specified'}
                                    </td>
                                    <td style={{ border: '1px solid #dee2e6', padding: '12px' }}>
                                        <span style={{ 
                                            backgroundColor: getStatusColor(shipment.status), 
                                            color: 'white', 
                                            padding: '4px 8px', 
                                            borderRadius: '12px', 
                                            fontSize: '12px',
                                            fontWeight: 'bold'
                                        }}>
                                            {shipment.status ? shipment.status.toUpperCase() : 'UNKNOWN'}
                                        </span>
                                    </td>
                                    <td style={{ border: '1px solid #dee2e6', padding: '12px' }}>
                                        {shipment.ship_date || 'N/A'}
                                    </td>
                                    <td style={{ border: '1px solid #dee2e6', padding: '12px' }}>
                                        {shipment.expected_delivery || 'N/A'}
                                    </td>
                                    <td style={{ border: '1px solid #dee2e6', padding: '12px' }}>
                                        <button 
                                            onClick={() => handleEdit(shipment)}
                                            style={{ 
                                                padding: '5px 10px', 
                                                backgroundColor: '#007bff', 
                                                color: 'white', 
                                                border: 'none',
                                                borderRadius: '3px',
                                                cursor: 'pointer',
                                                marginRight: '5px',
                                                fontSize: '12px'
                                            }}
                                        >
                                            Edit
                                        </button>
                                        <button 
                                            onClick={() => handleDelete(shipment.id)}
                                            style={{ 
                                                padding: '5px 10px', 
                                                backgroundColor: '#dc3545', 
                                                color: 'white', 
                                                border: 'none',
                                                borderRadius: '3px',
                                                cursor: 'pointer',
                                                fontSize: '12px'
                                            }}
                                        >
                                            Delete
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

export default ShipmentsTab;
