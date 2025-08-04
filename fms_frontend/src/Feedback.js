import React, { useState } from 'react';

function Feedback({ userData }) {
    const [activeTab, setActiveTab] = useState('submit');
    const [showThankYou, setShowThankYou] = useState(false);
    const [notification, setNotification] = useState('');
    const [feedback, setFeedback] = useState({
        type: 'suggestion',
        category: 'general',
        title: '',
        description: '',
        rating: 5,
        anonymous: false
    });

    // Mock feedback data
    const mockFeedbackList = [
        {
            id: 1,
            type: 'suggestion',
            category: 'booking',
            title: 'Improve booking calendar UI',
            description: 'The calendar could be more intuitive with drag-and-drop functionality.',
            rating: 4,
            status: 'under_review',
            date: '2025-01-15',
            user: 'Anonymous',
            response: 'Thank you for the suggestion. We are currently working on improving the booking interface.'
        },
        {
            id: 2,
            type: 'complaint',
            category: 'equipment',
            title: 'Frequent centrifuge breakdowns',
            description: 'The centrifuge in Lab 2 has been breaking down frequently, causing project delays.',
            rating: 2,
            status: 'resolved',
            date: '2025-01-10',
            user: 'John Doe',
            response: 'We have scheduled maintenance for this equipment and added backup equipment.'
        },
        {
            id: 3,
            type: 'compliment',
            category: 'staff',
            title: 'Excellent support from technical team',
            description: 'The technical support team resolved my equipment issue very quickly and professionally.',
            rating: 5,
            status: 'acknowledged',
            date: '2025-01-08',
            user: 'Jane Smith',
            response: 'Thank you for the positive feedback! We will share this with the technical team.'
        },
        {
            id: 4,
            type: 'suggestion',
            category: 'training',
            title: 'More hands-on training sessions',
            description: 'Would like to see more practical training sessions for new equipment.',
            rating: 4,
            status: 'planned',
            date: '2025-01-05',
            user: 'Mike Johnson',
            response: 'We are planning to introduce more hands-on training sessions starting next month.'
        }
    ];

    const [feedbackList, setFeedbackList] = useState(mockFeedbackList);

    const handleSubmitFeedback = (e) => {
        e.preventDefault();
        if (!feedback.title || !feedback.description) {
            alert('Please fill in all required fields');
            return;
        }

        const newFeedback = {
            id: Date.now(),
            ...feedback,
            status: 'submitted',
            date: new Date().toISOString().split('T')[0],
            user: feedback.anonymous ? 'Anonymous' : 'Current User',
            response: null
        };

        setFeedbackList([newFeedback, ...feedbackList]);
        setFeedback({ type: 'suggestion', category: 'general', title: '', description: '', rating: 5, anonymous: false });
        setShowThankYou(true);
        
        setTimeout(() => {
            setShowThankYou(false);
            setActiveTab('view');
        }, 2000);
    };

    const getTypeColor = (type) => {
        switch (type) {
            case 'suggestion': return '#007bff';
            case 'complaint': return '#dc3545';
            case 'compliment': return '#28a745';
            default: return '#6c757d';
        }
    };

    const getStatusColor = (status) => {
        switch (status) {
            case 'submitted': return '#17a2b8';
            case 'under_review': return '#ffc107';
            case 'planned': return '#fd7e14';
            case 'resolved': return '#28a745';
            case 'acknowledged': return '#6f42c1';
            default: return '#6c757d';
        }
    };

    const getTypeIcon = (type) => {
        switch (type) {
            case 'suggestion': return '💡';
            case 'complaint': return '⚠️';
            case 'compliment': return '👍';
            default: return '💬';
        }
    };

    const renderStars = (rating, interactive = false) => {
        return (
            <div style={{ display: 'flex', gap: '2px' }}>
                {[1, 2, 3, 4, 5].map(star => (
                    <span
                        key={star}
                        onClick={interactive ? () => setFeedback({...feedback, rating: star}) : undefined}
                        style={{
                            color: star <= rating ? '#ffc107' : '#e9ecef',
                            fontSize: '20px',
                            cursor: interactive ? 'pointer' : 'default'
                        }}
                    >
                        ★
                    </span>
                ))}
            </div>
        );
    };

    return (
        <div style={{ padding: '20px' }}>
            <h2 style={{ marginBottom: '20px', color: '#333' }}>User Feedback</h2>

            {/* Tab Navigation */}
            <div style={{ display: 'flex', marginBottom: '20px', borderBottom: '1px solid #ddd' }}>
                <button
                    onClick={() => setActiveTab('submit')}
                    style={{
                        padding: '10px 20px',
                        border: 'none',
                        backgroundColor: activeTab === 'submit' ? '#f8f9fa' : 'transparent',
                        borderBottom: activeTab === 'submit' ? '2px solid #007bff' : 'none',
                        cursor: 'pointer',
                        fontSize: '14px',
                        fontWeight: activeTab === 'submit' ? 'bold' : 'normal'
                    }}
                >
                    Submit Feedback
                </button>
                <button
                    onClick={() => setActiveTab('view')}
                    style={{
                        padding: '10px 20px',
                        border: 'none',
                        backgroundColor: activeTab === 'view' ? '#f8f9fa' : 'transparent',
                        borderBottom: activeTab === 'view' ? '2px solid #007bff' : 'none',
                        cursor: 'pointer',
                        fontSize: '14px',
                        fontWeight: activeTab === 'view' ? 'bold' : 'normal'
                    }}
                >
                    View Feedback ({feedbackList.length})
                </button>
            </div>

            {/* Submit Feedback Tab */}
            {activeTab === 'submit' && (
                <div style={{ maxWidth: '600px' }}>
                    {showThankYou ? (
                        <div style={{
                            textAlign: 'center',
                            padding: '40px',
                            backgroundColor: '#d4edda',
                            border: '1px solid #c3e6cb',
                            borderRadius: '8px',
                            color: '#155724'
                        }}>
                            <h3>Thank you for your feedback!</h3>
                            <p>Your feedback has been submitted and will be reviewed by our team.</p>
                        </div>
                    ) : (
                        <form onSubmit={handleSubmitFeedback} style={{
                            backgroundColor: 'white',
                            padding: '30px',
                            border: '1px solid #ddd',
                            borderRadius: '8px'
                        }}>
                            <div style={{ display: 'flex', gap: '20px', marginBottom: '20px' }}>
                                <div style={{ flex: 1 }}>
                                    <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                        Feedback Type
                                    </label>
                                    <select
                                        value={feedback.type}
                                        onChange={(e) => setFeedback({...feedback, type: e.target.value})}
                                        style={{
                                            width: '100%',
                                            padding: '8px',
                                            border: '1px solid #ddd',
                                            borderRadius: '4px',
                                            fontSize: '14px'
                                        }}
                                    >
                                        <option value="suggestion">Suggestion</option>
                                        <option value="complaint">Complaint</option>
                                        <option value="compliment">Compliment</option>
                                    </select>
                                </div>

                                <div style={{ flex: 1 }}>
                                    <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                        Category
                                    </label>
                                    <select
                                        value={feedback.category}
                                        onChange={(e) => setFeedback({...feedback, category: e.target.value})}
                                        style={{
                                            width: '100%',
                                            padding: '8px',
                                            border: '1px solid #ddd',
                                            borderRadius: '4px',
                                            fontSize: '14px'
                                        }}
                                    >
                                        <option value="general">General</option>
                                        <option value="equipment">Equipment</option>
                                        <option value="booking">Booking System</option>
                                        <option value="staff">Staff</option>
                                        <option value="training">Training</option>
                                        <option value="facilities">Facilities</option>
                                    </select>
                                </div>
                            </div>

                            <div style={{ marginBottom: '20px' }}>
                                <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                    Title *
                                </label>
                                <input
                                    type="text"
                                    value={feedback.title}
                                    onChange={(e) => setFeedback({...feedback, title: e.target.value})}
                                    style={{
                                        width: '100%',
                                        padding: '8px',
                                        border: '1px solid #ddd',
                                        borderRadius: '4px',
                                        fontSize: '14px'
                                    }}
                                    placeholder="Brief summary of your feedback"
                                />
                            </div>

                            <div style={{ marginBottom: '20px' }}>
                                <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                    Description *
                                </label>
                                <textarea
                                    value={feedback.description}
                                    onChange={(e) => setFeedback({...feedback, description: e.target.value})}
                                    style={{
                                        width: '100%',
                                        height: '120px',
                                        padding: '8px',
                                        border: '1px solid #ddd',
                                        borderRadius: '4px',
                                        fontSize: '14px',
                                        resize: 'vertical'
                                    }}
                                    placeholder="Please provide detailed feedback..."
                                />
                            </div>

                            <div style={{ marginBottom: '20px' }}>
                                <label style={{ display: 'block', marginBottom: '10px', fontWeight: 'bold' }}>
                                    Overall Rating
                                </label>
                                {renderStars(feedback.rating, true)}
                                <small style={{ color: '#666', display: 'block', marginTop: '5px' }}>
                                    Click on stars to rate (1 = Poor, 5 = Excellent)
                                </small>
                            </div>

                            <div style={{ marginBottom: '20px' }}>
                                <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <input
                                        type="checkbox"
                                        checked={feedback.anonymous}
                                        onChange={(e) => setFeedback({...feedback, anonymous: e.target.checked})}
                                        style={{ margin: 0 }}
                                    />
                                    <span style={{ fontSize: '14px' }}>Submit anonymously</span>
                                </label>
                            </div>

                            <button
                                type="submit"
                                style={{
                                    padding: '12px 30px',
                                    backgroundColor: '#007bff',
                                    color: 'white',
                                    border: 'none',
                                    borderRadius: '4px',
                                    cursor: 'pointer',
                                    fontSize: '16px',
                                    fontWeight: 'bold'
                                }}
                            >
                                Submit Feedback
                            </button>
                        </form>
                    )}
                </div>
            )}

            {/* View Feedback Tab */}
            {activeTab === 'view' && (
                <div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                        {feedbackList.length === 0 ? (
                            <div style={{ 
                                textAlign: 'center', 
                                padding: '40px',
                                backgroundColor: '#f8f9fa',
                                borderRadius: '8px',
                                color: '#666'
                            }}>
                                No feedback submitted yet.
                            </div>
                        ) : (
                            feedbackList.map(item => (
                                <div key={item.id} style={{
                                    backgroundColor: 'white',
                                    border: '1px solid #ddd',
                                    borderRadius: '8px',
                                    padding: '20px',
                                    boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                                }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '10px' }}>
                                        <div style={{ flex: 1 }}>
                                            <h3 style={{ margin: '0 0 5px 0', color: '#333' }}>
                                                {getTypeIcon(item.type)} {item.title}
                                            </h3>
                                            <div style={{ fontSize: '14px', color: '#666', marginBottom: '10px' }}>
                                                <span>#{item.id}</span>
                                                <span style={{ margin: '0 10px' }}>•</span>
                                                <span>{item.date}</span>
                                                <span style={{ margin: '0 10px' }}>•</span>
                                                <span>By: {item.user}</span>
                                                <span style={{ margin: '0 10px' }}>•</span>
                                                <span>Category: {item.category}</span>
                                            </div>
                                        </div>
                                        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                                            <span style={{
                                                padding: '4px 8px',
                                                backgroundColor: getTypeColor(item.type),
                                                color: 'white',
                                                borderRadius: '12px',
                                                fontSize: '12px',
                                                fontWeight: 'bold'
                                            }}>
                                                {item.type.toUpperCase()}
                                            </span>
                                            <span style={{
                                                padding: '4px 8px',
                                                backgroundColor: getStatusColor(item.status),
                                                color: 'white',
                                                borderRadius: '12px',
                                                fontSize: '12px',
                                                fontWeight: 'bold'
                                            }}>
                                                {item.status.replace('_', ' ').toUpperCase()}
                                            </span>
                                        </div>
                                    </div>
                                    
                                    <p style={{ margin: '0 0 15px 0', color: '#555', lineHeight: '1.5' }}>
                                        {item.description}
                                    </p>

                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                                        <div>
                                            <span style={{ fontSize: '14px', color: '#666', marginRight: '10px' }}>Rating:</span>
                                            {renderStars(item.rating)}
                                        </div>
                                    </div>
                                    
                                    {item.response && (
                                        <div style={{
                                            backgroundColor: '#f8f9fa',
                                            border: '1px solid #e9ecef',
                                            borderRadius: '4px',
                                            padding: '15px',
                                            marginTop: '15px'
                                        }}>
                                            <h4 style={{ margin: '0 0 10px 0', color: '#007bff', fontSize: '14px' }}>
                                                Team Response:
                                            </h4>
                                            <p style={{ margin: 0, color: '#555', fontSize: '14px', lineHeight: '1.5' }}>
                                                {item.response}
                                            </p>
                                        </div>
                                    )}
                                </div>
                            ))
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}

export default Feedback;