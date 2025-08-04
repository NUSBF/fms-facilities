import React, { useState, useEffect } from 'react';
import axios from 'axios';

const UserStatus = {
    PENDING: 'inactive',
    ACTIVE: 'active',
    ARCHIVED: 'suspended'
};

function UsersManagement({ userData }) {
    const [pendingUsers, setPendingUsers] = useState([]);
    const [activeUsers, setActiveUsers] = useState([]);
    const [archivedUsers, setArchivedUsers] = useState([]);
    const [groups, setGroups] = useState([]);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(true);
    const [editingUser, setEditingUser] = useState(null);
    const [editForm, setEditForm] = useState({});

    useEffect(() => {
        fetchUsers();
        fetchGroups();
    }, []);

    const fetchUsers = async () => {
        setLoading(true);
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            const response = await axios.get('/fms-api/users', config);
            
            // Sort users by status
            const pending = [];
            const active = [];
            const archived = [];
            
            response.data.forEach(user => {
                if (user.status === UserStatus.PENDING) {
                    pending.push(user);
                } else if (user.status === UserStatus.ACTIVE) {
                    active.push(user);
                } else if (user.status === UserStatus.ARCHIVED) {
                    archived.push(user);
                }
            });
            
            setPendingUsers(pending);
            setActiveUsers(active);
            setArchivedUsers(archived);
        } catch (err) {
            setError('Failed to load users. Please try again.');
            console.error('Error fetching users:', err);
        } finally {
            setLoading(false);
        }
    };

    const fetchGroups = async () => {
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            const response = await axios.get('/fms-api/groups', config);
            setGroups(response.data);
        } catch (err) {
            console.error('Error fetching groups:', err);
        }
    };

    const handleEdit = (user) => {
        setEditingUser(user);
        setEditForm({
            id: user.id,
            username: user.username || '',
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email,
            university: user.university || '',
            company: user.company || '',
            faculty: user.faculty || '',
            institute: user.institute || '',
            building: user.building || '',
            room: user.room || '',
            phone_number: user.phone_number || '',
            profile_link: user.profile_link || '',
            linkedin_link: user.linkedin_link || '',
            group_website: user.group_website || '',
            role: user.roles?.[0]?.role || 'facility_user',
            facility_id: user.roles?.[0]?.facility_id || 1,
            group_id: user.group_id || '',
            status: user.status
        });
    };

    const handleCancelEdit = () => {
        setEditingUser(null);
        setEditForm({});
    };

    const handleFormChange = (e) => {
        const { name, value } = e.target;
        setEditForm(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSaveUser = async () => {
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            await axios.put(`/fms-api/users/${editForm.id}`, editForm, config);
            
            fetchUsers();
            setEditingUser(null);
            setEditForm({});
        } catch (err) {
            setError('Failed to update user. Please try again.');
            console.error('Error updating user:', err);
        }
    };

    const handleApproveUser = async (userId) => {
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            await axios.post(`/fms-api/users/${userId}/approve`, {}, config);
            fetchUsers();
        } catch (err) {
            setError('Failed to approve user. Please try again.');
            console.error('Error approving user:', err);
        }
    };

    const handleArchiveUser = async (userId) => {
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            await axios.post(`/fms-api/users/${userId}/archive`, {}, config);
            fetchUsers();
        } catch (err) {
            setError('Failed to archive user. Please try again.');
            console.error('Error archiving user:', err);
        }
    };

    const handleActivateUser = async (userId) => {
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            await axios.post(`/fms-api/users/${userId}/activate`, {}, config);
            fetchUsers();
        } catch (err) {
            setError('Failed to activate user. Please try again.');
            console.error('Error activating user:', err);
        }
    };

    const handleDeleteUser = async (userId, username) => {
        if (!window.confirm(`Are you sure you want to delete user ${username}? This action cannot be undone.`)) {
            return;
        }
        
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            
            await axios.delete(`/fms-api/users/${userId}`, config);
            fetchUsers();
        } catch (err) {
            setError('Failed to delete user. Please try again.');
            console.error('Error deleting user:', err);
        }
    };

    const hasRole = (requiredRoles) => {
        if (!userData || !userData.roles) {
            return false;
        }
        
        const exactMatch = userData.roles.some(r => requiredRoles.includes(r.role) || r.role === 'developer');
        const patternMatch = userData.roles.some(r => {
            const baseRole = r.role.split('_').slice(0, 2).join('_');
            return requiredRoles.includes(baseRole) || baseRole === 'developer';
        });
        
        return exactMatch || patternMatch;
    };

    const canEditUsers = hasRole(['developer', 'administrator', 'facility_manager']);
    const canDeleteUsers = hasRole(['developer', 'facility_manager', 'facility_staff']);

    if (loading) {
        return <div style={{ textAlign: 'center', padding: '20px' }}>Loading user data...</div>;
    }

    if (editingUser) {
        return (
            <div style={{ padding: '20px', maxWidth: '800px', margin: '0 auto' }}>
                <h2>Edit User</h2>
                {error && <div style={{ color: 'red', marginBottom: '15px' }}>{error}</div>}
                
                <form>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                        <div>
                            <label>Username:</label>
                            <input 
                                type="text" 
                                name="username"
                                value={editForm.username} 
                                onChange={handleFormChange}
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Status:</label>
                            <select 
                                name="status" 
                                value={editForm.status} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }}
                            >
                                <option value="inactive">Pending</option>
                                <option value="active">Active</option>
                                <option value="suspended">Archived</option>
                            </select>
                        </div>
                        <div>
                            <label>First Name:</label>
                            <input 
                                type="text" 
                                name="first_name" 
                                value={editForm.first_name} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Last Name:</label>
                            <input 
                                type="text" 
                                name="last_name" 
                                value={editForm.last_name} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Email:</label>
                            <input 
                                type="email" 
                                name="email" 
                                value={editForm.email} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Group:</label>
                            <select 
                                name="group_id" 
                                value={editForm.group_id} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }}
                            >
                                <option value="">No Group</option>
                                {groups.map(group => (
                                    <option key={group.id} value={group.id}>{group.group_name}</option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label>Role:</label>
                            <select 
                                name="role" 
                                value={editForm.role} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }}
                            >
                                <option value="facility_user">Facility User</option>
                                <option value="facility_staff">Facility Staff</option>
                                <option value="facility_manager">Facility Manager</option>
                                <option value="facility_superuser">Facility Superuser</option>
                                {hasRole(['developer', 'administrator']) && (
                                    <option value="administrator">Administrator</option>
                                )}
                                {hasRole(['developer']) && (
                                    <option value="developer">Developer</option>
                                )}
                            </select>
                        </div>
                        <div>
                            <label>University:</label>
                            <input 
                                type="text" 
                                name="university" 
                                value={editForm.university} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Company:</label>
                            <input 
                                type="text" 
                                name="company" 
                                value={editForm.company} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Faculty:</label>
                            <input 
                                type="text" 
                                name="faculty" 
                                value={editForm.faculty} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Institute:</label>
                            <input 
                                type="text" 
                                name="institute" 
                                value={editForm.institute} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Building:</label>
                            <input 
                                type="text" 
                                name="building" 
                                value={editForm.building} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Room:</label>
                            <input 
                                type="text" 
                                name="room" 
                                value={editForm.room} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Phone Number:</label>
                            <input 
                                type="text" 
                                name="phone_number" 
                                value={editForm.phone_number} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Profile Link:</label>
                            <input 
                                type="url" 
                                name="profile_link" 
                                value={editForm.profile_link} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>LinkedIn Link:</label>
                            <input 
                                type="url" 
                                name="linkedin_link" 
                                value={editForm.linkedin_link} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                        <div>
                            <label>Group Website:</label>
                            <input 
                                type="url" 
                                name="group_website" 
                                value={editForm.group_website} 
                                onChange={handleFormChange} 
                                style={{ width: '100%', padding: '8px', marginBottom: '10px' }} 
                            />
                        </div>
                    </div>
                    
                    <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                        <button 
                            type="button" 
                            onClick={handleCancelEdit}
                            style={{ padding: '10px 20px' }}
                        >
                            Cancel
                        </button>
                        <button 
                            type="button" 
                            onClick={handleSaveUser}
                            style={{ padding: '10px 20px', backgroundColor: '#0066cc', color: 'white', border: 'none' }}
                        >
                            Save Changes
                        </button>
                    </div>
                </form>
            </div>
        );
    }

    return (
        <div style={{ padding: '20px' }}>
            <h2>User Management</h2>
            {error && <div style={{ color: 'red', marginBottom: '15px' }}>{error}</div>}
            
            <div style={{ marginBottom: '30px' }}>
                <h3>Pending Approval</h3>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Username</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Name</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Email</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Group</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Requested Role</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Date Registered</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {pendingUsers.length === 0 ? (
                            <tr>
                                <td colSpan="7" style={{ textAlign: 'center', padding: '8px' }}>No pending users</td>
                            </tr>
                        ) : (
                            pendingUsers.map(user => (
                                <tr key={user.id}>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.username}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.first_name} {user.last_name}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.email}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.group_name || 'N/A'}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.roles?.[0]?.role || 'N/A'}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{new Date(user.created_at).toLocaleDateString()}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>
                                        {canEditUsers && (
                                            <>
                                                <button 
                                                    onClick={() => handleApproveUser(user.id)}
                                                    style={{ marginRight: '5px', padding: '5px 10px', backgroundColor: 'green', color: 'white', border: 'none' }}
                                                >
                                                    Approve
                                                </button>
                                                <button 
                                                    onClick={() => handleEdit(user)}
                                                    style={{ marginRight: '5px', padding: '5px 10px' }}
                                                >
                                                    Edit
                                                </button>
                                            </>
                                        )}
                                        {canDeleteUsers && (
                                            <button 
                                                onClick={() => handleDeleteUser(user.id, user.username)}
                                                style={{ padding: '5px 10px', backgroundColor: '#cc0000', color: 'white', border: 'none' }}
                                            >
                                                Delete
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
            
            <div style={{ marginBottom: '30px' }}>
                <h3>Active Users</h3>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Username</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Name</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Email</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Group</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Role</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Last Login</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {activeUsers.length === 0 ? (
                            <tr>
                                <td colSpan="7" style={{ textAlign: 'center', padding: '8px' }}>No active users</td>
                            </tr>
                        ) : (
                            activeUsers.map(user => (
                                <tr key={user.id}>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.username}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.first_name} {user.last_name}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.email}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.group_name || 'N/A'}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.roles?.[0]?.role || 'N/A'}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>
                                        {canEditUsers && (
                                            <>
                                                <button 
                                                    onClick={() => handleEdit(user)}
                                                    style={{ marginRight: '5px', padding: '5px 10px' }}
                                                >
                                                    Edit
                                                </button>
                                                <button 
                                                    onClick={() => handleArchiveUser(user.id)}
                                                    style={{ marginRight: '5px', padding: '5px 10px', backgroundColor: '#999', color: 'white', border: 'none' }}
                                                >
                                                    Archive
                                                </button>
                                            </>
                                        )}
                                        {canDeleteUsers && (
                                            <button 
                                                onClick={() => handleDeleteUser(user.id, user.username)}
                                                style={{ padding: '5px 10px', backgroundColor: '#cc0000', color: 'white', border: 'none' }}
                                            >
                                                Delete
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
            
            <div>
                <h3>Archived Users</h3>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Username</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Name</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Email</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Group</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Role</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Last Login</th>
                            <th style={{ textAlign: 'left', padding: '8px', borderBottom: '1px solid #ddd' }}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {archivedUsers.length === 0 ? (
                            <tr>
                                <td colSpan="7" style={{ textAlign: 'center', padding: '8px' }}>No archived users</td>
                            </tr>
                        ) : (
                            archivedUsers.map(user => (
                                <tr key={user.id}>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.username}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.first_name} {user.last_name}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.email}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.group_name || 'N/A'}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.roles?.[0]?.role || 'N/A'}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>{user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}</td>
                                    <td style={{ padding: '8px', borderBottom: '1px solid #ddd' }}>
                                        {canEditUsers && (
                                            <>
                                                <button 
                                                    onClick={() => handleEdit(user)}
                                                    style={{ marginRight: '5px', padding: '5px 10px' }}
                                                >
                                                    Edit
                                                </button>
                                                <button 
                                                    onClick={() => handleActivateUser(user.id)}
                                                    style={{ marginRight: '5px', padding: '5px 10px', backgroundColor: 'green', color: 'white', border: 'none' }}
                                                >
                                                    Activate
                                                </button>
                                            </>
                                        )}
                                        {canDeleteUsers && (
                                            <button 
                                                onClick={() => handleDeleteUser(user.id, user.username)}
                                                style={{ padding: '5px 10px', backgroundColor: '#cc0000', color: 'white', border: 'none' }}
                                            >
                                                Delete
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

export default UsersManagement;
