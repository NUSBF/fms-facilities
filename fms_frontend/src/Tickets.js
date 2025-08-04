import React, { useState } from 'react';

function Tickets({ userData }) {
    const [activeTab, setActiveTab] = useState('open');
    const [showNewTicketForm, setShowNewTicketForm] = useState(false);
    const [notification, setNotification] = useState('');
    const [newTicket, setNewTicket] = useState({
        title: '',
        category: 'technical',
        priority: 'medium',
        description: ''
    });

    // Email notification function
    const sendTicketNotification = async (ticket, type = 'created', updateMessage = '') => {
        try {
            const token = localStorage.getItem('token');
            if (!token) return;

            // Get current user's facility for facility staff notifications
            const currentFacility = userData?.roles?.find(role => role.facility_name)?.facility_name || 'Default Facility';
            
            const emailData = {
                ticketId: ticket.id,
                ticketTitle: ticket.title,
                ticketDescription: ticket.description,
                ticketPriority: ticket.priority,
                ticketCategory: ticket.category,
                ticketStatus: ticket.status,
                userEmail: userData?.user?.email || 'user@example.com',
                userName: `${userData?.user?.first_name || 'User'} ${userData?.user?.last_name || ''}`.trim(),
                facilityName: currentFacility,
                notificationType: type, // 'created', 'updated', 'status_changed'
                updateMessage: updateMessage,
                createdDate: ticket.created_date
            };

            const response = await fetch('/fms-api/tickets/notify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(emailData)
            });

            if (!response.ok) {
                console.warn('Failed to send email notification:', await response.text());
                setNotification('⚠️ Ticket created, but email notifications failed to send');
            } else {
                const result = await response.json();
                console.log('Email notification sent successfully', result);
                
                let message = '✅ Email notifications sent successfully!';
                if (result.userNotified) message += ` User notified.`;
                if (result.staffNotified > 0) message += ` ${result.staffNotified} facility staff member(s) notified.`;
                
                setNotification(message);
            }
        } catch (error) {
            console.error('Error sending email notification:', error);
            setNotification('⚠️ Ticket created, but email notifications failed to send');
        }
        
        // Clear notification after 5 seconds
        setTimeout(() => setNotification(''), 5000);
    };

    // Mock tickets data
    const mockTickets = [
        {
            id: 1,
            title: 'Centrifuge not starting',
            category: 'technical',
            priority: 'high',
            status: 'open',
            created_date: '2025-01-20',
            assigned_to: 'Tech Support',
            description: 'The high-speed centrifuge in Lab 2 is not starting. Power light is on but motor won\'t engage.',
            user_name: 'John Doe',
            user_email: 'john.doe@university.ac.uk'
        },
        {
            id: 2,
            title: 'Booking calendar sync issue',
            category: 'software',
            priority: 'medium',
            status: 'in_progress',
            created_date: '2025-01-19',
            assigned_to: 'IT Support',
            description: 'Calendar is not syncing properly with Outlook. Missing some bookings.',
            user_name: 'Jane Smith',
            user_email: 'jane.smith@university.ac.uk'
        },
        {
            id: 3,
            title: 'Access card not working',
            category: 'access',
            priority: 'medium',
            status: 'open',
            created_date: '2025-01-18',
            assigned_to: 'Security',
            description: 'My access card is not working for Lab 3. Need access for project work.',
            user_name: 'Mike Johnson',
            user_email: 'mike.johnson@university.ac.uk'
        },
        {
            id: 4,
            title: 'Equipment manual missing',
            category: 'documentation',
            priority: 'low',
            status: 'resolved',
            created_date: '2025-01-15',
            assigned_to: 'Admin',
            description: 'Cannot find the manual for the new PCR machine.',
            user_name: 'Sarah Wilson',
            user_email: 'sarah.wilson@university.ac.uk'
        }
    ];

    const [tickets, setTickets] = useState(mockTickets);

    const getFilteredTickets = () => {
        switch (activeTab) {
            case 'open':
                return tickets.filter(t => t.status === 'open');
            case 'in_progress':
                return tickets.filter(t => t.status === 'in_progress');
            case 'resolved':
                return tickets.filter(t => t.status === 'resolved');
            default:
                return tickets;
        }
    };

    const getPriorityColor = (priority) => {
        switch (priority) {
            case 'high': return '#dc3545';
            case 'medium': return '#ffc107';
            case 'low': return '#28a745';
            default: return '#6c757d';
        }
    };

    const getStatusColor = (status) => {
        switch (status) {
            case 'open': return '#007bff';
            case 'in_progress': return '#ffc107';
            case 'resolved': return '#28a745';
            default: return '#6c757d';
        }
    };

    const handleSubmitTicket = async (e) => {
        e.preventDefault();
        if (!newTicket.title || !newTicket.description) {
            alert('Please fill in all required fields');
            return;
        }

        const ticket = {
            id: Date.now(),
            ...newTicket,
            status: 'open',
            created_date: new Date().toISOString().split('T')[0],
            assigned_to: 'Pending Assignment',
            user_name: `${userData?.user?.first_name || 'Current'} ${userData?.user?.last_name || 'User'}`.trim(),
            user_email: userData?.user?.email || 'user@example.com'
        };

        setTickets([ticket, ...tickets]);
        setNewTicket({ title: '', category: 'technical', priority: 'medium', description: '' });
        setShowNewTicketForm(false);

        // Send email notification to user and facility staff
        await sendTicketNotification(ticket, 'created');
        
        // Note: Success message is now handled by the notification system
    };

    // Handle ticket status update
    const handleStatusUpdate = async (ticketId, newStatus) => {
        const updatedTickets = tickets.map(ticket => {
            if (ticket.id === ticketId) {
                const updatedTicket = { ...ticket, status: newStatus };
                // Send email notification for status change
                sendTicketNotification(updatedTicket, 'status_changed', `Ticket status changed to: ${newStatus.replace('_', ' ').toUpperCase()}`);
                return updatedTicket;
            }
            return ticket;
        });
        setTickets(updatedTickets);
    };

    // Handle adding response to ticket
    const handleAddResponse = async (ticketId, responseMessage) => {
        const updatedTickets = tickets.map(ticket => {
            if (ticket.id === ticketId) {
                const updatedTicket = { ...ticket, response: responseMessage };
                // Send email notification for response
                sendTicketNotification(updatedTicket, 'updated', `New response added: ${responseMessage}`);
                return updatedTicket;
            }
            return ticket;
        });
        setTickets(updatedTickets);
    };

    const getCategoryIcon = (category) => {
        switch (category) {
            case 'technical': return '🔧';
            case 'software': return '💻';
            case 'access': return '🔑';
            case 'documentation': return '📋';
            default: return '❓';
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h2 style={{ margin: 0, color: '#333' }}>Support Tickets</h2>
                <button
                    onClick={() => setShowNewTicketForm(true)}
                    style={{
                        padding: '10px 20px',
                        backgroundColor: '#007bff',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        fontSize: '14px'
                    }}
                >
                    + New Ticket
                </button>
            </div>

            {/* Notification Display */}
            {notification && (
                <div style={{
                    backgroundColor: notification.includes('⚠️') ? '#fff3cd' : '#d4edda',
                    border: `1px solid ${notification.includes('⚠️') ? '#ffeaa7' : '#c3e6cb'}`,
                    color: notification.includes('⚠️') ? '#856404' : '#155724',
                    padding: '12px 20px',
                    borderRadius: '6px',
                    marginBottom: '20px',
                    display: 'flex',
                    alignItems: 'center',
                    fontSize: '14px'
                }}>
                    {notification}
                </div>
            )}

            {/* Ticket Status Tabs */}
            <div style={{ display: 'flex', marginBottom: '20px', borderBottom: '1px solid #ddd' }}>
                {[
                    { key: 'open', label: 'Open', count: tickets.filter(t => t.status === 'open').length },
                    { key: 'in_progress', label: 'In Progress', count: tickets.filter(t => t.status === 'in_progress').length },
                    { key: 'resolved', label: 'Resolved', count: tickets.filter(t => t.status === 'resolved').length }
                ].map(tab => (
                    <button
                        key={tab.key}
                        onClick={() => setActiveTab(tab.key)}
                        style={{
                            padding: '10px 20px',
                            border: 'none',
                            backgroundColor: activeTab === tab.key ? '#f8f9fa' : 'transparent',
                            borderBottom: activeTab === tab.key ? '2px solid #007bff' : 'none',
                            cursor: 'pointer',
                            fontSize: '14px',
                            fontWeight: activeTab === tab.key ? 'bold' : 'normal'
                        }}
                    >
                        {tab.label} ({tab.count})
                    </button>
                ))}
            </div>

            {/* New Ticket Modal */}
            {showNewTicketForm && (
                <div style={{
                    position: 'fixed',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    backgroundColor: 'rgba(0,0,0,0.5)',
                    display: 'flex',
                    justifyContent: 'center',
                    alignItems: 'center',
                    zIndex: 1000
                }}>
                    <div style={{
                        backgroundColor: 'white',
                        padding: '30px',
                        borderRadius: '8px',
                        width: '90%',
                        maxWidth: '500px',
                        maxHeight: '80vh',
                        overflowY: 'auto'
                    }}>
                        <h3 style={{ marginTop: 0, marginBottom: '20px' }}>Create New Ticket</h3>
                        <form onSubmit={handleSubmitTicket}>
                            <div style={{ marginBottom: '15px' }}>
                                <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                    Title *
                                </label>
                                <input
                                    type="text"
                                    value={newTicket.title}
                                    onChange={(e) => setNewTicket({...newTicket, title: e.target.value})}
                                    style={{
                                        width: '100%',
                                        padding: '8px',
                                        border: '1px solid #ddd',
                                        borderRadius: '4px',
                                        fontSize: '14px'
                                    }}
                                    placeholder="Brief description of the issue"
                                />
                            </div>

                            <div style={{ display: 'flex', gap: '15px', marginBottom: '15px' }}>
                                <div style={{ flex: 1 }}>
                                    <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                        Category
                                    </label>
                                    <select
                                        value={newTicket.category}
                                        onChange={(e) => setNewTicket({...newTicket, category: e.target.value})}
                                        style={{
                                            width: '100%',
                                            padding: '8px',
                                            border: '1px solid #ddd',
                                            borderRadius: '4px',
                                            fontSize: '14px'
                                        }}
                                    >
                                        <option value="technical">Technical Issue</option>
                                        <option value="software">Software/System</option>
                                        <option value="access">Access/Security</option>
                                        <option value="documentation">Documentation</option>
                                    </select>
                                </div>

                                <div style={{ flex: 1 }}>
                                    <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                        Priority
                                    </label>
                                    <select
                                        value={newTicket.priority}
                                        onChange={(e) => setNewTicket({...newTicket, priority: e.target.value})}
                                        style={{
                                            width: '100%',
                                            padding: '8px',
                                            border: '1px solid #ddd',
                                            borderRadius: '4px',
                                            fontSize: '14px'
                                        }}
                                    >
                                        <option value="low">Low</option>
                                        <option value="medium">Medium</option>
                                        <option value="high">High</option>
                                    </select>
                                </div>
                            </div>

                            <div style={{ marginBottom: '20px' }}>
                                <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                    Description *
                                </label>
                                <textarea
                                    value={newTicket.description}
                                    onChange={(e) => setNewTicket({...newTicket, description: e.target.value})}
                                    style={{
                                        width: '100%',
                                        height: '100px',
                                        padding: '8px',
                                        border: '1px solid #ddd',
                                        borderRadius: '4px',
                                        fontSize: '14px',
                                        resize: 'vertical'
                                    }}
                                    placeholder="Detailed description of the issue..."
                                />
                            </div>

                            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
                                <button
                                    type="button"
                                    onClick={() => setShowNewTicketForm(false)}
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
                                    style={{
                                        padding: '10px 20px',
                                        backgroundColor: '#007bff',
                                        color: 'white',
                                        border: 'none',
                                        borderRadius: '4px',
                                        cursor: 'pointer'
                                    }}
                                >
                                    Create Ticket
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Tickets List */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                {getFilteredTickets().length === 0 ? (
                    <div style={{ 
                        textAlign: 'center', 
                        padding: '40px',
                        backgroundColor: '#f8f9fa',
                        borderRadius: '8px',
                        color: '#666'
                    }}>
                        No {activeTab.replace('_', ' ')} tickets found.
                    </div>
                ) : (
                    getFilteredTickets().map(ticket => (
                        <div key={ticket.id} style={{
                            backgroundColor: 'white',
                            border: '1px solid #ddd',
                            borderRadius: '8px',
                            padding: '20px',
                            boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                        }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '10px' }}>
                                <div style={{ flex: 1 }}>
                                    <h3 style={{ margin: '0 0 5px 0', color: '#333' }}>
                                        {getCategoryIcon(ticket.category)} {ticket.title}
                                    </h3>
                                    <div style={{ fontSize: '14px', color: '#666', marginBottom: '10px' }}>
                                        <span>Ticket #{ticket.id}</span>
                                        <span style={{ margin: '0 10px' }}>•</span>
                                        <span>Created: {ticket.created_date}</span>
                                        <span style={{ margin: '0 10px' }}>•</span>
                                        <span>By: {ticket.user_name}</span>
                                    </div>
                                </div>
                                <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                                    <span style={{
                                        padding: '4px 8px',
                                        backgroundColor: getPriorityColor(ticket.priority),
                                        color: 'white',
                                        borderRadius: '12px',
                                        fontSize: '12px',
                                        fontWeight: 'bold'
                                    }}>
                                        {ticket.priority.toUpperCase()}
                                    </span>
                                    <span style={{
                                        padding: '4px 8px',
                                        backgroundColor: getStatusColor(ticket.status),
                                        color: 'white',
                                        borderRadius: '12px',
                                        fontSize: '12px',
                                        fontWeight: 'bold'
                                    }}>
                                        {ticket.status.replace('_', ' ').toUpperCase()}
                                    </span>
                                </div>
                            </div>
                            
                            <p style={{ margin: '0 0 15px 0', color: '#555', lineHeight: '1.5' }}>
                                {ticket.description}
                            </p>
                            
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '14px', color: '#666' }}>
                                <span>Assigned to: <strong>{ticket.assigned_to}</strong></span>
                                <div style={{ display: 'flex', gap: '10px' }}>
                                    <button 
                                        onClick={() => {
                                            // In a real app, this would open a detailed view modal
                                            alert(`Ticket Details:\n\nID: #${ticket.id}\nTitle: ${ticket.title}\nCategory: ${ticket.category}\nPriority: ${ticket.priority}\nStatus: ${ticket.status}\nUser: ${ticket.user_name} (${ticket.user_email})\nCreated: ${ticket.created_date}\nDescription: ${ticket.description}`);
                                        }}
                                        style={{
                                            padding: '5px 10px',
                                            backgroundColor: '#17a2b8',
                                            color: 'white',
                                            border: 'none',
                                            borderRadius: '4px',
                                            cursor: 'pointer',
                                            fontSize: '12px'
                                        }}
                                    >
                                        View Details
                                    </button>
                                    {ticket.status !== 'resolved' && (
                                        <>
                                            <select
                                                onChange={(e) => {
                                                    if (e.target.value && e.target.value !== ticket.status) {
                                                        handleStatusUpdate(ticket.id, e.target.value);
                                                        e.target.value = ticket.status; // Reset select
                                                    }
                                                }}
                                                style={{
                                                    padding: '5px 8px',
                                                    backgroundColor: '#28a745',
                                                    color: 'white',
                                                    border: 'none',
                                                    borderRadius: '4px',
                                                    cursor: 'pointer',
                                                    fontSize: '12px'
                                                }}
                                            >
                                                <option value="">Update Status</option>
                                                {ticket.status !== 'open' && <option value="open">Mark as Open</option>}
                                                {ticket.status !== 'in_progress' && <option value="in_progress">Mark as In Progress</option>}
                                                {ticket.status !== 'resolved' && <option value="resolved">Mark as Resolved</option>}
                                            </select>
                                            <button 
                                                onClick={() => {
                                                    const response = prompt('Enter your response to this ticket:');
                                                    if (response && response.trim()) {
                                                        handleAddResponse(ticket.id, response.trim());
                                                    }
                                                }}
                                                style={{
                                                    padding: '5px 10px',
                                                    backgroundColor: '#ffc107',
                                                    color: 'black',
                                                    border: 'none',
                                                    borderRadius: '4px',
                                                    cursor: 'pointer',
                                                    fontSize: '12px'
                                                }}
                                            >
                                                Add Response
                                            </button>
                                        </>
                                    )}
                                    <button 
                                        onClick={() => {
                                            const emailSubject = `Re: Ticket #${ticket.id} - ${ticket.title}`;
                                            const emailBody = `Dear ${ticket.user_name},\n\nRegarding your ticket #${ticket.id}:\n\n${ticket.description}\n\nBest regards,\nFacility Management Team`;
                                            window.open(`mailto:${ticket.user_email}?subject=${encodeURIComponent(emailSubject)}&body=${encodeURIComponent(emailBody)}`);
                                        }}
                                        style={{
                                            padding: '5px 10px',
                                            backgroundColor: '#6f42c1',
                                            color: 'white',
                                            border: 'none',
                                            borderRadius: '4px',
                                            cursor: 'pointer',
                                            fontSize: '12px'
                                        }}
                                    >
                                        📧 Email User
                                    </button>
                                </div>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}

export default Tickets;