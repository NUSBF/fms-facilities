import React, { useState } from 'react';

function ResourcesTab({ userData }) {
    const [resources, setResources] = useState([
        {
            id: 1,
            name: 'PCR Machine Service Manual',
            type: 'Documentation',
            category: 'Equipment Manual',
            description: 'Complete service and troubleshooting manual for PCR machines',
            location: 'Digital Library',
            access_level: 'All Users',
            date_added: '2024-01-15',
            added_by: 'John Smith'
        },
        {
            id: 2,
            name: 'Safety Data Sheets Collection',
            type: 'Documentation',
            category: 'Safety',
            description: 'Complete collection of safety data sheets for all chemicals',
            location: 'Safety Cabinet - Room M2.001',
            access_level: 'All Users',
            date_added: '2024-02-20',
            added_by: 'Safety Officer'
        },
        {
            id: 3,
            name: 'Microscopy Training Videos',
            type: 'Training Material',
            category: 'Training',
            description: 'Video tutorials for advanced microscopy techniques',
            location: 'Digital Library',
            access_level: 'Trained Users',
            date_added: '2024-03-10',
            added_by: 'Training Coordinator'
        },
        {
            id: 4,
            name: 'Emergency Contact List',
            type: 'Reference',
            category: 'Emergency',
            description: 'Updated contact information for all emergency situations',
            location: 'Notice Board - All Labs',
            access_level: 'All Users',
            date_added: '2024-01-01',
            added_by: 'Facility Manager'
        },
        {
            id: 5,
            name: 'Standard Operating Procedures',
            type: 'Documentation',
            category: 'Procedures',
            description: 'Collection of SOPs for all facility equipment and processes',
            location: 'Digital Library + Physical Binder',
            access_level: 'All Users',
            date_added: '2024-02-01',
            added_by: 'Quality Assurance'
        }
    ]);

    const [searchTerm, setSearchTerm] = useState('');
    const [selectedCategory, setSelectedCategory] = useState('All');
    const [selectedType, setSelectedType] = useState('All');
    const [showAddForm, setShowAddForm] = useState(false);
    const [newResource, setNewResource] = useState({
        name: '',
        type: 'Documentation',
        category: 'Equipment Manual',
        description: '',
        location: '',
        access_level: 'All Users'
    });

    // Get unique categories and types for filtering
    const categories = ['All', ...new Set(resources.map(resource => resource.category))];
    const types = ['All', ...new Set(resources.map(resource => resource.type))];

    // Filter resources based on search and filters
    const filteredResources = resources.filter(resource => {
        const matchesSearch = resource.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            resource.description.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesCategory = selectedCategory === 'All' || resource.category === selectedCategory;
        const matchesType = selectedType === 'All' || resource.type === selectedType;
        
        return matchesSearch && matchesCategory && matchesType;
    });

    const handleAddResource = () => {
        if (newResource.name && newResource.description) {
            const resource = {
                ...newResource,
                id: Date.now(),
                date_added: new Date().toISOString().split('T')[0],
                added_by: `${userData.user.first_name} ${userData.user.last_name}`
            };
            
            setResources([...resources, resource]);
            setNewResource({
                name: '',
                type: 'Documentation',
                category: 'Equipment Manual',
                description: '',
                location: '',
                access_level: 'All Users'
            });
            setShowAddForm(false);
        }
    };

    const handleDeleteResource = (id) => {
        if (window.confirm('Are you sure you want to delete this resource?')) {
            setResources(resources.filter(resource => resource.id !== id));
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h3 style={{ margin: 0 }}>Resource Library</h3>
                <button
                    onClick={() => setShowAddForm(!showAddForm)}
                    style={{
                        padding: '10px 20px',
                        backgroundColor: '#007bff',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer'
                    }}
                >
                    {showAddForm ? 'Cancel' : 'Add Resource'}
                </button>
            </div>

            {/* Search and Filters */}
            <div style={{ 
                display: 'grid', 
                gridTemplateColumns: '2fr 1fr 1fr', 
                gap: '15px', 
                marginBottom: '20px',
                padding: '15px',
                backgroundColor: '#f8f9fa',
                borderRadius: '4px'
            }}>
                <div>
                    <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                        Search Resources:
                    </label>
                    <input
                        type="text"
                        placeholder="Search by name or description..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        style={{
                            width: '100%',
                            padding: '8px',
                            border: '1px solid #ddd',
                            borderRadius: '4px'
                        }}
                    />
                </div>
                
                <div>
                    <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                        Category:
                    </label>
                    <select
                        value={selectedCategory}
                        onChange={(e) => setSelectedCategory(e.target.value)}
                        style={{
                            width: '100%',
                            padding: '8px',
                            border: '1px solid #ddd',
                            borderRadius: '4px'
                        }}
                    >
                        {categories.map(category => (
                            <option key={category} value={category}>{category}</option>
                        ))}
                    </select>
                </div>
                
                <div>
                    <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                        Type:
                    </label>
                    <select
                        value={selectedType}
                        onChange={(e) => setSelectedType(e.target.value)}
                        style={{
                            width: '100%',
                            padding: '8px',
                            border: '1px solid #ddd',
                            borderRadius: '4px'
                        }}
                    >
                        {types.map(type => (
                            <option key={type} value={type}>{type}</option>
                        ))}
                    </select>
                </div>
            </div>

            {/* Add Resource Form */}
            {showAddForm && (
                <div style={{ 
                    marginBottom: '20px', 
                    padding: '20px', 
                    border: '1px solid #ddd', 
                    borderRadius: '4px',
                    backgroundColor: '#ffffff'
                }}>
                    <h4>Add New Resource</h4>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginBottom: '15px' }}>
                        <div>
                            <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                Resource Name:
                            </label>
                            <input
                                type="text"
                                value={newResource.name}
                                onChange={(e) => setNewResource({...newResource, name: e.target.value})}
                                style={{
                                    width: '100%',
                                    padding: '8px',
                                    border: '1px solid #ddd',
                                    borderRadius: '4px'
                                }}
                                placeholder="Enter resource name"
                            />
                        </div>
                        
                        <div>
                            <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                Type:
                            </label>
                            <select
                                value={newResource.type}
                                onChange={(e) => setNewResource({...newResource, type: e.target.value})}
                                style={{
                                    width: '100%',
                                    padding: '8px',
                                    border: '1px solid #ddd',
                                    borderRadius: '4px'
                                }}
                            >
                                <option value="Documentation">Documentation</option>
                                <option value="Training Material">Training Material</option>
                                <option value="Reference">Reference</option>
                                <option value="Software">Software</option>
                                <option value="Template">Template</option>
                            </select>
                        </div>
                        
                        <div>
                            <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                Category:
                            </label>
                            <select
                                value={newResource.category}
                                onChange={(e) => setNewResource({...newResource, category: e.target.value})}
                                style={{
                                    width: '100%',
                                    padding: '8px',
                                    border: '1px solid #ddd',
                                    borderRadius: '4px'
                                }}
                            >
                                <option value="Equipment Manual">Equipment Manual</option>
                                <option value="Safety">Safety</option>
                                <option value="Training">Training</option>
                                <option value="Emergency">Emergency</option>
                                <option value="Procedures">Procedures</option>
                                <option value="Forms">Forms</option>
                                <option value="Guidelines">Guidelines</option>
                            </select>
                        </div>
                        
                        <div>
                            <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                                Access Level:
                            </label>
                            <select
                                value={newResource.access_level}
                                onChange={(e) => setNewResource({...newResource, access_level: e.target.value})}
                                style={{
                                    width: '100%',
                                    padding: '8px',
                                    border: '1px solid #ddd',
                                    borderRadius: '4px'
                                }}
                            >
                                <option value="All Users">All Users</option>
                                <option value="Trained Users">Trained Users</option>
                                <option value="Staff Only">Staff Only</option>
                                <option value="Managers Only">Managers Only</option>
                            </select>
                        </div>
                    </div>
                    
                    <div style={{ marginBottom: '15px' }}>
                        <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                            Location:
                        </label>
                        <input
                            type="text"
                            value={newResource.location}
                            onChange={(e) => setNewResource({...newResource, location: e.target.value})}
                            style={{
                                width: '100%',
                                padding: '8px',
                                border: '1px solid #ddd',
                                borderRadius: '4px'
                            }}
                            placeholder="Where can this resource be found?"
                        />
                    </div>
                    
                    <div style={{ marginBottom: '15px' }}>
                        <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                            Description:
                        </label>
                        <textarea
                            value={newResource.description}
                            onChange={(e) => setNewResource({...newResource, description: e.target.value})}
                            style={{
                                width: '100%',
                                padding: '8px',
                                border: '1px solid #ddd',
                                borderRadius: '4px',
                                minHeight: '80px',
                                resize: 'vertical'
                            }}
                            placeholder="Describe the resource and its purpose"
                        />
                    </div>
                    
                    <div style={{ display: 'flex', gap: '10px' }}>
                        <button
                            onClick={handleAddResource}
                            style={{
                                padding: '10px 20px',
                                backgroundColor: '#28a745',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            Add Resource
                        </button>
                        <button
                            onClick={() => setShowAddForm(false)}
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
                    </div>
                </div>
            )}

            {/* Resources Summary */}
            <div style={{ 
                display: 'grid', 
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
                gap: '15px', 
                marginBottom: '20px' 
            }}>
                <div style={{ 
                    padding: '15px', 
                    backgroundColor: '#e3f2fd', 
                    borderRadius: '4px', 
                    textAlign: 'center' 
                }}>
                    <h4 style={{ margin: '0 0 5px 0', color: '#1976d2' }}>Total Resources</h4>
                    <p style={{ margin: 0, fontSize: '24px', fontWeight: 'bold' }}>{resources.length}</p>
                </div>
                <div style={{ 
                    padding: '15px', 
                    backgroundColor: '#e8f5e8', 
                    borderRadius: '4px', 
                    textAlign: 'center' 
                }}>
                    <h4 style={{ margin: '0 0 5px 0', color: '#388e3c' }}>Documentation</h4>
                    <p style={{ margin: 0, fontSize: '24px', fontWeight: 'bold' }}>
                        {resources.filter(r => r.type === 'Documentation').length}
                    </p>
                </div>
                <div style={{ 
                    padding: '15px', 
                    backgroundColor: '#fff3e0', 
                    borderRadius: '4px', 
                    textAlign: 'center' 
                }}>
                    <h4 style={{ margin: '0 0 5px 0', color: '#f57c00' }}>Training Materials</h4>
                    <p style={{ margin: 0, fontSize: '24px', fontWeight: 'bold' }}>
                        {resources.filter(r => r.type === 'Training Material').length}
                    </p>
                </div>
                <div style={{ 
                    padding: '15px', 
                    backgroundColor: '#fce4ec', 
                    borderRadius: '4px', 
                    textAlign: 'center' 
                }}>
                    <h4 style={{ margin: '0 0 5px 0', color: '#c2185b' }}>Reference Materials</h4>
                    <p style={{ margin: 0, fontSize: '24px', fontWeight: 'bold' }}>
                        {resources.filter(r => r.type === 'Reference').length}
                    </p>
                </div>
            </div>

            {/* Resources Table */}
            <div style={{ 
                border: '1px solid #ddd', 
                borderRadius: '4px', 
                overflow: 'hidden',
                backgroundColor: 'white'
            }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr style={{ backgroundColor: '#f8f9fa' }}>
                            <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>
                                Resource Name
                            </th>
                            <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>
                                Type
                            </th>
                            <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>
                                Category
                            </th>
                            <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>
                                Location
                            </th>
                            <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>
                                Access Level
                            </th>
                            <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>
                                Added By
                            </th>
                            <th style={{ padding: '12px', textAlign: 'center', borderBottom: '1px solid #ddd' }}>
                                Actions
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredResources.length > 0 ? (
                            filteredResources.map(resource => (
                                <tr key={resource.id} style={{ borderBottom: '1px solid #eee' }}>
                                    <td style={{ padding: '12px' }}>
                                        <div>
                                            <div style={{ fontWeight: 'bold', marginBottom: '4px' }}>
                                                {resource.name}
                                            </div>
                                            <div style={{ fontSize: '14px', color: '#666' }}>
                                                {resource.description}
                                            </div>
                                        </div>
                                    </td>
                                    <td style={{ padding: '12px' }}>
                                        <span style={{
                                            padding: '4px 8px',
                                            borderRadius: '12px',
                                            fontSize: '12px',
                                            backgroundColor: resource.type === 'Documentation' ? '#e3f2fd' : 
                                                           resource.type === 'Training Material' ? '#fff3e0' : 
                                                           resource.type === 'Reference' ? '#fce4ec' : '#f3e5f5',
                                            color: resource.type === 'Documentation' ? '#1976d2' : 
                                                  resource.type === 'Training Material' ? '#f57c00' : 
                                                  resource.type === 'Reference' ? '#c2185b' : '#7b1fa2'
                                        }}>
                                            {resource.type}
                                        </span>
                                    </td>
                                    <td style={{ padding: '12px' }}>{resource.category}</td>
                                    <td style={{ padding: '12px' }}>{resource.location}</td>
                                    <td style={{ padding: '12px' }}>
                                        <span style={{
                                            padding: '4px 8px',
                                            borderRadius: '12px',
                                            fontSize: '12px',
                                            backgroundColor: resource.access_level === 'All Users' ? '#e8f5e8' : 
                                                           resource.access_level === 'Trained Users' ? '#fff3e0' : 
                                                           resource.access_level === 'Staff Only' ? '#ffebee' : '#fce4ec',
                                            color: resource.access_level === 'All Users' ? '#388e3c' : 
                                                  resource.access_level === 'Trained Users' ? '#f57c00' : 
                                                  resource.access_level === 'Staff Only' ? '#d32f2f' : '#c2185b'
                                        }}>
                                            {resource.access_level}
                                        </span>
                                    </td>
                                    <td style={{ padding: '12px' }}>
                                        <div style={{ fontSize: '14px' }}>{resource.added_by}</div>
                                        <div style={{ fontSize: '12px', color: '#666' }}>{resource.date_added}</div>
                                    </td>
                                    <td style={{ padding: '12px', textAlign: 'center' }}>
                                        <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
                                            <button
                                                style={{
                                                    padding: '6px 12px',
                                                    backgroundColor: '#007bff',
                                                    color: 'white',
                                                    border: 'none',
                                                    borderRadius: '4px',
                                                    cursor: 'pointer',
                                                    fontSize: '12px'
                                                }}
                                                onClick={() => alert(`Viewing details for: ${resource.name}`)}
                                            >
                                                View
                                            </button>
                                            <button
                                                style={{
                                                    padding: '6px 12px',
                                                    backgroundColor: '#dc3545',
                                                    color: 'white',
                                                    border: 'none',
                                                    borderRadius: '4px',
                                                    cursor: 'pointer',
                                                    fontSize: '12px'
                                                }}
                                                onClick={() => handleDeleteResource(resource.id)}
                                            >
                                                Delete
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))
                        ) : (
                            <tr>
                                <td colSpan="7" style={{ 
                                    padding: '20px', 
                                    textAlign: 'center', 
                                    color: '#666',
                                    fontStyle: 'italic'
                                }}>
                                    No resources found matching your criteria
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>

            {/* Help Text */}
            <div style={{ 
                marginTop: '20px', 
                padding: '15px', 
                backgroundColor: '#f8f9fa', 
                borderRadius: '4px',
                border: '1px solid #dee2e6'
            }}>
                <h4 style={{ margin: '0 0 10px 0', color: '#495057' }}>About Resources</h4>
                <p style={{ margin: '0', color: '#6c757d', fontSize: '14px' }}>
                    The Resource Library contains important documents, training materials, references, and other resources 
                    that support facility operations. Use the search and filter options above to quickly find what you need. 
                    Resources are categorized by type and access level to help users identify relevant materials.
                </p>
            </div>
        </div>
    );
}

export default ResourcesTab;
