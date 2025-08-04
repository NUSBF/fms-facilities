import React, { useEffect, useState } from 'react';
import axios from 'axios';

const allowedRoles = ['developer', 'administrator', 'facility_manager', 'facility_staff'];

function TrainingPage({ userData }) 
{
    const [trainings, setTrainings] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [formData, setFormData] = useState({ id: null, name: '', validity_months: '' });
    const [editing, setEditing] = useState(false);

    const hasPermission = () => {
        return userData?.roles?.some(role => allowedRoles.includes(role.role));
    };

    useEffect(() => {
        if (!hasPermission()) return;
        fetchTrainings();
    }, []);

    const fetchTrainings = async () => 
    {
        try {
            const config = { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } };
            const response = await axios.get('/fms-api/training-types', config);
            setTrainings(response.data);
        } catch (err) {
            setError('Failed to load training types');
        } finally {
            setLoading(false);
        }
    };

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
    };

    const handleSubmit = async (e) => 
    {
        e.preventDefault();
        const config = { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } };
        try {
            if (editing) {
                await axios.put(`/fms-api/training-types/${formData.id}`, formData, config);
            } else {
                await axios.post('/fms-api/training-types', formData, config);
            }
            setFormData({ id: null, name: '', validity_months: '' });
            setEditing(false);
            fetchTrainings();
        } catch {
            setError('Failed to save training');
        }
    };

    const handleEdit = (training) => {
        setFormData(training);
        setEditing(true);
    };

    const handleDelete = async (id) => 
    {
        if (!window.confirm('Delete this training type?')) return;
        const config = { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } };
        try {
            await axios.delete(`/fms-api/training-types/${id}`, config);
            fetchTrainings();
        } catch {
            setError('Failed to delete training');
        }
    };

    if (!hasPermission()) {
        return <div style={{ padding: '20px', color: 'red' }}>Access denied.</div>;
    }

    return (
        <div style={{ padding: '20px' }}>
            <h2>Training Types</h2>

            {error && <div style={{ color: 'red', marginBottom: '10px' }}>{error}</div>}

            <form onSubmit={handleSubmit} style={{ marginBottom: '20px' }}>
                <input
                    type="text"
                    name="name"
                    placeholder="Training Name"
                    value={formData.name}
                    onChange={handleInputChange}
                    required
                    style={{ marginRight: '10px' }}
                />
                <input
                    type="number"
                    name="validity_months"
                    placeholder="Validity (months)"
                    value={formData.validity_months}
                    onChange={handleInputChange}
                    required
                    style={{ marginRight: '10px' }}
                />
                <button type="submit">{editing ? 'Update' : 'Add'} Training</button>
                {editing && (
                    <button
                        type="button"
                        onClick={() => {
                            setFormData({ id: null, name: '', validity_months: '' });
                            setEditing(false);
                        }}
                        style={{ marginLeft: '10px' }}
                    >
                        Cancel
                    </button>
                )}
            </form>

            {loading ? (
                <p>Loading...</p>
            ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr>
                            <th style={{ padding: '8px', borderBottom: '1px solid #ccc' }}>Name</th>
                            <th style={{ padding: '8px', borderBottom: '1px solid #ccc' }}>Validity (Months)</th>
                            <th style={{ padding: '8px', borderBottom: '1px solid #ccc' }}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {trainings.map(t => (
                            <tr key={t.id}>
                                <td style={{ padding: '8px' }}>{t.name}</td>
                                <td style={{ padding: '8px' }}>{t.validity_months}</td>
                                <td style={{ padding: '8px' }}>
                                    <button onClick={() => handleEdit(t)} style={{ marginRight: '10px' }}>Edit</button>
                                    <button onClick={() => handleDelete(t.id)}>Delete</button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    );
}

export default TrainingPage;
