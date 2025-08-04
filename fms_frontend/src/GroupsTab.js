import React, { useState, useEffect } from 'react';
import axios from 'axios';

function GroupsTab({ userData }) {
    const [groups, setGroups] = useState([]);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(true);
    const [editingGroup, setEditingGroup] = useState(null);
    const [editForm, setEditForm] = useState({});
    const [showCreateForm, setShowCreateForm] = useState(false);
    const [showArchived, setShowArchived] = useState(false);
    const [createForm, setCreateForm] = useState({
        group_name: '',
        pi_name: '',
        pi_email: ''
    });

    useEffect(() => {
        fetchGroups();
    }, []);

    const fetchGroups = async () => {
        setLoading(true);
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            const response = await axios.get('/fms-api/groups', config);
            setGroups(response.data);
        } catch (err) {
            setError('Failed to load groups. Please try again.');
            console.error('Error fetching groups:', err);
        } finally {
            setLoading(false);
        }
    };

    const handleEdit = (group) => {
        setEditingGroup(group);
        setEditForm({
            id: group.id,
            group_name: group.group_name,
            pi_name: group.pi_name,
            pi_email: group.pi_email
        });
    };

    const handleCancelEdit = () => {
        setEditingGroup(null);
        setEditForm({});
    };

    const handleFormChange = (e) => {
        const { name, value } = e.target;
        setEditForm(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleCreateFormChange = (e) => {
        const { name, value } = e.target;
        setCreateForm(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSaveGroup = async () => {
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            await axios.put(`/fms-api/groups/${editForm.id}`, editForm, config);
            
            fetchGroups();
            setEditingGroup(null);
            setEditForm({});
        } catch (err) {
            setError('Failed to update group. Please try again.');
            console.error('Error updating group:', err);
        }
    };

    const handleCreateGroup = async () => {
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            await axios.post('/fms-api/groups', createForm, config);
            
            fetchGroups();
            setShowCreateForm(false);
            setCreateForm({ group_name: '', pi_name: '', pi_email: '' });
        } catch (err) {
            setError('Failed to create group. Please try again.');
            console.error('Error creating group:', err);
        }
    };

    const handleArchiveGroup = async (groupId, groupName) => {
        if (!window.confirm(`Are you sure you want to archive group "${groupName}"?`)) {
            return;
        }
        
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            await axios.patch(`/fms-api/groups/${groupId}/archive`, {}, config);
            fetchGroups();
        } catch (err) {
            setError('Failed to archive group. Please try again.');
            console.error('Error archiving group:', err);
        }
    };

    const handleRestoreGroup = async (groupId, groupName) => {
        if (!window.confirm(`Are you sure you want to restore group "${groupName}"?`)) {
            return;
        }
        
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            await axios.patch(`/fms-api/groups/${groupId}/restore`, {}, config);
            fetchGroups();
        } catch (err) {
            setError('Failed to restore group. Please try again.');
            console.error('Error restoring group:', err);
        }
    };

    const handleDeleteGroup = async (groupId, groupName) => {
        if (!window.confirm(`Are you sure you want to permanently delete group "${groupName}"? This action cannot be undone.`)) {
            return;
        }
        
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            await axios.delete(`/fms-api/groups/${groupId}`, config);
            fetchGroups();
        } catch (err) {
            setError('Failed to delete group. Please try again.');
            console.error('Error deleting group:', err);
        }
    };

    // Helper to check if user has required roles
    const hasRole = (requiredRoles) => {
        if (!userData || !userData.roles) return false;
        
        const exactMatch = userData.roles.some(r => requiredRoles.includes(r.role) || r.role === 'developer');
        const patternMatch = userData.roles.some(r => {
            const baseRole = r.role.split('_').slice(0, 2).join('_');
            return requiredRoles.includes(baseRole) || baseRole === 'developer';
        });
        
        return exactMatch || patternMatch;
    };

    const canManageGroups = hasRole(['developer', 'administrator', 'facility_manager', 'facility_staff']);

    const activeGroups = groups.filter(group => !group.archived_at);
    const archivedGroups = groups.filter(group => group.archived_at);

    if (loading) {
        return <div style={{ textAlign: 'center', padding: '20px' }}>Loading groups...</div>;
    }

    return (
        <div style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h2>Group Management</h2>
                <div style={{ display: 'flex', gap: '10px' }}>
                    <button 
                        onClick={() => setShowArchived(!showArchived)}
                        style={{ 
                            padding: '10px 20px', 
                            backgroundColor: showArchived ? '#6c757d' : '#17a2b8', 
                            color: 'white', 
                            border: 'none',
                            borderRadius: '4px'
                        }}
                    >
                        {showArchived ? 'Show Active' : 'Show Archived'}
                    </button>
                    {canManageGroups && (
                        <button 
                            onClick={() => setShowCreateForm(true)}
                            style={{ padding: '10px 20px', backgroundColor: '#0066cc', color: 'white', border: 'none', borderRadius: '4px' }}
                        >
                            Create New Group
                        </button>
                    )}
                </div>
            </div>

            {error && <div style={{ color: 'red', marginBottom: '15px' }}>{error}</div>}

            {showCreateForm && (
                <div style={{ marginBottom: '30px', padding: '20px', border: '1px solid #ddd', borderRadius: '5px' }}>
                    <h3>Create New Group</h3>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                        <div>
                            <label>Group Name:</label>
                            <input 
                                type="text" 
                                name="group_name" 
                                value={createForm.group_name} 
                                onChange={handleCreateFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                                required
                            />
                        </div>
                        <div>
                            <label>PI Name:</label>
                            <input 
                                type="text" 
                                name="pi_name" 
                                value={createForm.pi_name} 
                                onChange={handleCreateFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                                required
                            />
                        </div>
                        <div style={{ gridColumn: '1 / -1' }}>
                            <label>PI Email:</label>
                            <input 
                                type="email" 
                                name="pi_email" 
                                value={createForm.pi_email} 
                                onChange={handleCreateFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                                required
                            />
                        </div>
                    </div>
                    <div style={{ marginTop: '15px', display: 'flex', gap: '10px' }}>
                        <button 
                            onClick={handleCreateGroup}
                            style={{ padding: '10px 20px', backgroundColor: '#0066cc', color: 'white', border: 'none' }}
                        >
                            Create Group
                        </button>
                        <button 
                            onClick={() => { setShowCreateForm(false); setCreateForm({ group_name: '', pi_name: '', pi_email: '' }); }}
                            style={{ padding: '10px 20px' }}
                        >
                            Cancel
                        </button>
                    </div>
                </div>
            )}

            {editingGroup && (
                <div style={{ marginBottom: '30px', padding: '20px', border: '1px solid #ddd', borderRadius: '5px' }}>
                    <h3>Edit Group</h3>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                        <div>
                            <label>Group Name:</label>
                            <input 
                                type="text" 
                                name="group_name" 
                                value={editForm.group_name} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>PI Name:</label>
                            <input 
                                type="text" 
                                name="pi_name" 
                                value={editForm.pi_name} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div style={{ gridColumn: '1 / -1' }}>
                            <label>PI Email:</label>
                            <input 
                                type="email" 
                                name="pi_email" 
                                value={editForm.pi_email} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                    </div>
                    <div style={{ marginTop: '15px', display: 'flex', gap: '10px' }}>
                        <button 
                            onClick={handleSaveGroup}
                            style={{ padding: '10px 20px', backgroundColor: '#0066cc', color: 'white', border: 'none' }}
                        >
                            Save Changes
                        </button>
                        <button 
                            onClick={handleCancelEdit}
                            style={{ padding: '10px 20px' }}
                        >
                            Cancel
                        </button>
                    </div>
                </div>
            )}

            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                    <tr>
                        <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Group Name</th>
                        <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>PI Name</th>
                        <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>PI Email</th>
                        <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Members</th>
                        <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Created</th>
                        {showArchived && (
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Archived</th>
                        )}
                        <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {(showArchived ? archivedGroups : activeGroups).length === 0 ? (
                        <tr>
                            <td colSpan={showArchived ? "7" : "6"} style={{ textAlign: 'center', padding: '8px' }}>
                                {showArchived ? 'No archived groups found' : 'No active groups found'}
                            </td>
                        </tr>
                    ) : (
                        (showArchived ? archivedGroups : activeGroups).map(group => (
                            <tr key={group.id}>
                                <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{group.group_name}</td>
                                <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{group.pi_name}</td>
                                <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{group.pi_email}</td>
                                <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{group.member_count || 0}</td>
                                <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{new Date(group.created_at).toLocaleDateString()}</td>
                                {showArchived && (
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>
                                        {group.archived_at ? new Date(group.archived_at).toLocaleDateString() : '-'}
                                    </td>
                                )}
                                <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>
                                    {canManageGroups && (
                                        <>
                                            {!showArchived ? (
                                                <>
                                                    <button 
                                                        onClick={() => handleEdit(group)}
                                                        style={{ marginRight: '5px', padding: '5px 10px' }}
                                                    >
                                                        Edit
                                                    </button>
                                                    <button 
                                                        onClick={() => handleArchiveGroup(group.id, group.group_name)}
                                                        style={{ marginRight: '5px', padding: '5px 10px', backgroundColor: '#ffc107', color: 'black', border: 'none' }}
                                                    >
                                                        Archive
                                                    </button>
                                                </>
                                            ) : (
                                                <button 
                                                    onClick={() => handleRestoreGroup(group.id, group.group_name)}
                                                    style={{ marginRight: '5px', padding: '5px 10px', backgroundColor: '#28a745', color: 'white', border: 'none' }}
                                                >
                                                    Restore
                                                </button>
                                            )}
                                            <button 
                                                onClick={() => handleDeleteGroup(group.id, group.group_name)}
                                                style={{ padding: '5px 10px', backgroundColor: '#dc3545', color: 'white', border: 'none' }}
                                            >
                                                Delete
                                            </button>
                                        </>
                                    )}
                                </td>
                            </tr>
                        ))
                    )}
                </tbody>
            </table>
        </div>
    );
}

export default GroupsTab;
