import React, { useState, useEffect } from 'react';
import UsersManagement from './UsersManagement';
import GroupsTab from './GroupsTab';

function UserTab({ userData }) {
    const [activeUserTab, setActiveUserTab] = useState(() => {
        return localStorage.getItem('dashboardActiveUserTab') || 'users';
    });

    // Save active user tab to localStorage when it changes
    useEffect(() => {
        localStorage.setItem('dashboardActiveUserTab', activeUserTab);
    }, [activeUserTab]);

    return (
        <div>
            <h2>Users & Groups Management</h2>
            
            {/* Tab Navigation */}
            <div style={{ 
                display: 'flex', 
                borderBottom: '1px solid #dee2e6',
                marginBottom: '20px',
                backgroundColor: '#f8f9fa'
            }}>
                <div 
                    onClick={() => setActiveUserTab('users')}
                    style={{ 
                        padding: '10px 20px', 
                        cursor: 'pointer',
                        backgroundColor: activeUserTab === 'users' ? '#ffffff' : 'transparent',
                        borderBottom: activeUserTab === 'users' ? '2px solid #007bff' : 'none',
                        fontWeight: activeUserTab === 'users' ? 'bold' : 'normal',
                        border: activeUserTab === 'users' ? '1px solid #dee2e6' : 'none',
                        borderBottom: activeUserTab === 'users' ? 'none' : '1px solid #dee2e6'
                    }}
                >
                    Users
                </div>
                <div 
                    onClick={() => setActiveUserTab('groups')}
                    style={{ 
                        padding: '10px 20px', 
                        cursor: 'pointer',
                        backgroundColor: activeUserTab === 'groups' ? '#ffffff' : 'transparent',
                        borderBottom: activeUserTab === 'groups' ? '2px solid #007bff' : 'none',
                        fontWeight: activeUserTab === 'groups' ? 'bold' : 'normal',
                        border: activeUserTab === 'groups' ? '1px solid #dee2e6' : 'none',
                        borderBottom: activeUserTab === 'groups' ? 'none' : '1px solid #dee2e6'
                    }}
                >
                    Groups
                </div>
            </div>

            {/* Tab Content */}
            <div style={{ backgroundColor: '#ffffff', padding: '20px', border: '1px solid #dee2e6', borderRadius: '0 0 4px 4px' }}>
                {activeUserTab === 'users' && (
                    <UsersManagement userData={userData} />
                )}

                {activeUserTab === 'groups' && (
                    <GroupsTab userData={userData} />
                )}
            </div>
        </div>
    );
}

export default UserTab;
