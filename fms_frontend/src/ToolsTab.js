import React, { useState, useEffect, useRef } from 'react';

function ToolsTab({ userData }) {
    const [tools, setTools] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [activeToolCategory, setActiveToolCategory] = useState(() => {
        return localStorage.getItem('toolsTabActiveCategory') || 'xray_puck';
    });
    const [currency, setCurrency] = useState('GBP'); // Default to British Pounds
    const [editingToolId, setEditingToolId] = useState(null);
    const [editingToolData, setEditingToolData] = useState(null);
    const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
    const [validationErrors, setValidationErrors] = useState({});
    const [saveErrorMsg, setSaveErrorMsg] = useState('');
    const [courrier, setCourrier] = useState('DHL'); // Default courrier
    const [trackingNumber, setTrackingNumber] = useState(''); // Tracking number state
    const [shippingDate, setShippingDate] = useState(() => {
        const today = new Date();
        return today.toISOString().split('T')[0];
    });
    const [receivingDate, setReceivingDate] = useState(() => {
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        return tomorrow.toISOString().split('T')[0];
    });
    
    // ALL HOOKS MUST BE AT THE TOP - BEFORE ANY CONDITIONAL RETURNS
    
    // Direct inline editing handlers
    const handleFieldChange = (toolId, field, value) => {
        setEditingToolData(prev => ({
            ...prev,
            [field]: value
        }));
        setHasUnsavedChanges(true);
    };

    const handleStartEdit = (toolId) => {
        const tool = tools.find(t => t.id === toolId);
        if (tool) {
            setEditingToolId(toolId);
            setEditingToolData({ ...tool });
            setHasUnsavedChanges(false);
            setValidationErrors({});
            setSaveErrorMsg('');
        }
    };

    const handleStopEdit = () => {
        setEditingToolId(null);
        setEditingToolData(null);
        setHasUnsavedChanges(false);
    };

    // Required fields for each category
    const requiredFields = {
        xray_puck: ['name', 'barcode', 'cost', 'manufacturer', 'date_of_purchase', 'status'],
        cryoem_puck: ['name', 'barcode', 'cost', 'manufacturer', 'date_of_purchase', 'status'],
        dry_shipper: ['name', 'barcode', 'cost', 'manufacturer', 'date_of_purchase', 'status', 'volume', 'weight', 'holding_time'],
        puck_shelf: ['name', 'barcode', 'cost', 'manufacturer', 'date_of_purchase', 'status']
    };

    // Validate tool data
    const validateToolData = (toolData, category) => {
        const fields = requiredFields[category] || [];
        const errors = {};
        fields.forEach(field => {
            if (!toolData[field] || toolData[field].toString().trim() === '') {
                errors[field] = true;
            }
        });
        return errors;
    };

    const handleSaveEdit = async () => {
        if (editingToolData) {
            const errors = validateToolData(editingToolData, editingToolData.category);
            setValidationErrors(errors);
            if (Object.keys(errors).length > 0) {
                setSaveErrorMsg('Please fill all required fields highlighted in red.');
                return;
            }
            setSaveErrorMsg('');
            try {
                const isNew = editingToolId === 'new';
                const savedTool = await saveTool(editingToolData, isNew);
                if (isNew) {
                    setTools(prevTools => [...prevTools, savedTool]);
                } else {
                    setTools(prevTools =>
                        prevTools.map(tool =>
                            tool.id === editingToolData.id ? editingToolData : tool
                        )
                    );
                }
                handleStopEdit();
            } catch (error) {
                console.error('Error saving tool:', error);
                setSaveErrorMsg('Failed to save. Please try again.');
            }
        }
    };

    const handleCancelEdit = () => {
        setValidationErrors({});
        setSaveErrorMsg('');
        if (hasUnsavedChanges) {
            if (window.confirm('You have unsaved changes. Are you sure you want to cancel?')) {
                handleStopEdit();
            }
        } else {
            handleStopEdit();
        }
    };

    // Tool categories configuration
    const toolCategories = {
        xray_puck: {
            name: 'X-ray PUCK',
            label: 'X-ray PUCK Tools',
            columns: ['name', 'barcode', 'cost', 'manufacturer', 'distributor', 'manufacturer_website', 'date_of_purchase', 'status', 'capacity']
        },
        cryoem_puck: {
            name: 'CryoEM PUCK',
            label: 'CryoEM PUCK Tools',
            columns: ['name', 'barcode', 'cost', 'manufacturer', 'distributor', 'manufacturer_website', 'date_of_purchase', 'status', 'capacity']
        },
        dry_shipper: {
            name: 'Dry Shipper',
            label: 'Dry Shipper Tools',
            columns: ['name', 'barcode', 'cost', 'manufacturer', 'distributor', 'manufacturer_website', 'date_of_purchase', 'status', 'volume', 'weight', 'holding_time', 'retirement_date']
        },
        puck_shelf: {
            name: 'PUCK Shelf',
            label: 'PUCK Shelf Tools',
            columns: ['name', 'barcode', 'cost', 'manufacturer', 'distributor', 'manufacturer_website', 'date_of_purchase', 'status', 'capacity']
        }
    };

    // Column display names
    const getColumnLabels = () => ({
        name: 'Tool Name',
        barcode: 'Barcode',
        cost: `Cost (${currencies[currency]?.symbol || '£'})`,
        manufacturer: 'Manufacturer',
        distributor: 'Distributor',
        manufacturer_website: 'Website',
        date_of_purchase: 'Purchase Date',
        status: 'Status',
        capacity: 'Capacity',
        volume: 'Volume',
        weight: 'Weight',
        holding_time: 'Holding Time',
        retirement_date: 'Retirement Date'
    });

    // Currency configuration
    const currencies = {
        GBP: { symbol: '£', label: 'British Pounds (£)' },
        USD: { symbol: '$', label: 'US Dollars ($)' },
        EUR: { symbol: '€', label: 'Euros (€)' }
    };

    useEffect(() => {
        fetchTools();
    }, []);

    // Save active tool category to localStorage when it changes
    useEffect(() => {
        localStorage.setItem('toolsTabActiveCategory', activeToolCategory);
    }, [activeToolCategory]);

    const fetchTools = async () => {
        try {
            setLoading(true);
            setError('');
            
            const token = localStorage.getItem('token');
            if (!token) {
                setError('No authentication token found');
                setTools([]);
                return;
            }
            
            const config = {
                headers: { Authorization: `Bearer ${token}` }
            };

            // Fetch from API
            const response = await fetch('/fms-api/tools', {
                headers: config.headers
            });
            
            if (response.ok) {
                const data = await response.json();
                setTools(data);
                setError(null);
            } else {
                throw new Error(`Failed to fetch tools: ${response.status}`);
            }
        } catch (err) {
            setError('Failed to fetch tools data. Please check your connection and try again.');
            console.error('Error fetching tools:', err);
            setTools([]); // Set empty array instead of mock data
        } finally {
            setLoading(false);
        }
    };

    // Save tool to database (create or update)
    const saveTool = async (toolData, isNew = false) => {
        try {
            console.log('saveTool called with:', { toolData, isNew });
            
            const token = localStorage.getItem('token');
            console.log('Token from localStorage:', token ? 'exists' : 'missing');
            
            if (!token) {
                throw new Error('No authentication token found');
            }
            
            const config = {
                method: isNew ? 'POST' : 'PUT',
                headers: { 
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(toolData)
            };

            const url = isNew ? '/fms-api/tools' : `/fms-api/tools/${toolData.id}`;
            console.log('Making request to:', url);
            console.log('Request config:', config);
            
            const response = await fetch(url, config);
            console.log('Response status:', response.status);
            console.log('Response ok:', response.ok);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('Error response body:', errorText);
                throw new Error(`Failed to ${isNew ? 'create' : 'update'} tool: ${response.status} - ${errorText}`);
            }
            
            const result = await response.json();
            console.log('Success response:', result);
            return result;
        } catch (error) {
            console.error('Error in saveTool:', error);
            throw error;
        }
    };

    // Calculate retirement date for dry shippers (10 years after purchase)
    const calculateRetirementDate = (purchaseDate, category) => {
        if (category !== 'dry_shipper' || !purchaseDate) return null;
        
        const purchase = new Date(purchaseDate);
        const retirement = new Date(purchase);
        retirement.setFullYear(purchase.getFullYear() + 10);
        
        return retirement.toISOString().split('T')[0]; // Return YYYY-MM-DD format
    };

    // Check if retirement date is overdue
    const isRetirementOverdue = (retirementDate) => {
        if (!retirementDate) return false;
        
        const today = new Date();
        const retirement = new Date(retirementDate);
        
        return today > retirement;
    };

    // Filter tools by category
    const getFilteredTools = () => {
        return tools
            .filter(tool => tool.category === activeToolCategory)
            .sort((a, b) => {
                // Sort alphabetically by tool name (case-insensitive)
                const nameA = (a.name || '').toLowerCase();
                const nameB = (b.name || '').toLowerCase();
                return nameA.localeCompare(nameB);
            });
    };

    // Get dynamic columns for current category, only showing columns with populated values
    const getDynamicColumns = () => {
        const filteredTools = getFilteredTools();
        const categoryConfig = toolCategories[activeToolCategory];
        
        if (!categoryConfig) {
            return [];
        }
        
        // When in edit mode (editing), show all columns for the category
        if (editingToolId) {
            return categoryConfig.columns || [];
        }
        
        if (filteredTools.length === 0) {
            return categoryConfig?.columns || [];
        }

        // Filter columns to only show those with at least one populated value
        return categoryConfig.columns.filter(column => {
            // Always show retirement_date for dry shippers since it's calculated
            if (column === 'retirement_date' && activeToolCategory === 'dry_shipper') {
                return true;
            }
            
            return filteredTools.some(tool => {
                const value = tool[column];
                return value !== undefined && value !== null && value !== '';
            });
        });
    };

    // Format date to human-readable format
    const formatDate = (dateString) => {
        if (!dateString) return '';
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) return dateString; // Return original if invalid
            
            // Format as "15 June 2024"
            return date.toLocaleDateString('en-GB', {
                day: 'numeric',
                month: 'long',
                year: 'numeric'
            });
        } catch (error) {
            return dateString; // Return original if error
        }
    };

    const formatCellValue = (value, column, tool) => {
        // Check if this entire row is being edited (existing or new tool)
        const isEditing = (editingToolId === tool.id) || (editingToolId === 'new' && tool === editingToolData);
        if (isEditing && editingToolData) {
            const editValue = editingToolData[column];
            const isError = validationErrors[column];
            const inputStyle = {
                width: '100%',
                padding: '4px',
                border: isError ? '2px solid #dc3545' : '1px solid #007bff',
                borderRadius: '4px',
                fontSize: '13px',
                backgroundColor: isError ? '#f8d7da' : 'white'
            };

            if (column === 'status') {
                return (
                    <select
                        value={editValue || 'Available'}
                        onChange={(e) => handleFieldChange(tool.id, column, e.target.value)}
                        style={inputStyle}
                    >
                        <option value="Available">Available</option>
                        <option value="In Use">In Use</option>
                        <option value="Maintenance">Maintenance</option>
                        <option value="Archived">Archived</option>
                        <option value="Out of Order">Out of Order</option>
                    </select>
                );
            } else if (column === 'cost') {
                return (
                    <input
                        type="number"
                        step="0.01"
                        min="0"
                        value={editValue || ''}
                        onChange={(e) => handleFieldChange(tool.id, column, e.target.value)}
                        style={inputStyle}
                    />
                );
            } else if (column === 'date_of_purchase') {
                return (
                    <input
                        type="date"
                        value={editValue ? editValue.split('T')[0] : ''}
                        onChange={(e) => handleFieldChange(tool.id, column, e.target.value)}
                        style={inputStyle}
                    />
                );
            } else if (column === 'manufacturer_website') {
                return (
                    <input
                        type="url"
                        value={editValue || ''}
                        onChange={(e) => handleFieldChange(tool.id, column, e.target.value)}
                        placeholder="https://..."
                        style={inputStyle}
                    />
                );
            } else if (column === 'retirement_date') {
                // Don't allow editing calculated retirement date
                const retirementDate = calculateRetirementDate(editingToolData.date_of_purchase, editingToolData.category);
                if (retirementDate) {
                    const isOverdue = isRetirementOverdue(retirementDate);
                    const formattedDate = formatDate(retirementDate);
                    return (
                        <span style={{
                            backgroundColor: isOverdue ? '#ffebee' : 'transparent',
                            color: isOverdue ? '#c62828' : 'inherit',
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontWeight: isOverdue ? 'bold' : 'normal'
                        }}>
                            {formattedDate}
                        </span>
                    );
                }
                return '-';
            } else {
                return (
                    <input
                        type="text"
                        value={editValue || ''}
                        onChange={(e) => handleFieldChange(tool.id, column, e.target.value)}
                        style={inputStyle}
                    />
                );
            }
        }

        // Normal display mode
        if (value === undefined || value === null || value === '') {
            // For retirement_date column, calculate it for dry shippers
            if (column === 'retirement_date' && tool && tool.category === 'dry_shipper') {
                const retirementDate = calculateRetirementDate(tool.date_of_purchase, tool.category);
                if (retirementDate) {
                    const isOverdue = isRetirementOverdue(retirementDate);
                    const formattedDate = formatDate(retirementDate);
                    return (
                        <span style={{
                            backgroundColor: isOverdue ? '#ffebee' : 'transparent',
                            color: isOverdue ? '#c62828' : 'inherit',
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontWeight: isOverdue ? 'bold' : 'normal'
                        }}>
                            {formattedDate}
                        </span>
                    );
                }
            }
            return '-';
        }
        
        if (column === 'cost') {
            const currencySymbol = currencies[currency]?.symbol || '£';
            return `${currencySymbol}${parseFloat(value).toFixed(2)}`;
        }
        
        if (column === 'manufacturer_website') {
            return (
                <a 
                    href={value} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    style={{
                        color: '#007bff',
                        textDecoration: 'underline',
                        fontSize: '12px'
                    }}
                    title="Visit manufacturer website"
                >
                    View Website
                </a>
            );
        }
        
        if (column === 'retirement_date') {
            const isOverdue = isRetirementOverdue(value);
            const formattedDate = formatDate(value);
            return (
                <span style={{
                    backgroundColor: isOverdue ? '#ffebee' : 'transparent',
                    color: isOverdue ? '#c62828' : 'inherit',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontWeight: isOverdue ? 'bold' : 'normal'
                }}>
                    {formattedDate}
                </span>
            );
        }
        
        // Format date fields
        if (column === 'date_of_purchase' || column.includes('date') || column.includes('Date')) {
            return formatDate(value);
        }
        
        return value;
    };

    // Render status with color coding
    const renderStatus = (status) => {
        const statusStyles = {
            'Available': { backgroundColor: '#d4edda', color: '#155724' },
            'In Use': { backgroundColor: '#fff3cd', color: '#856404' },
            'Archived': { backgroundColor: '#e2e3e5', color: '#6c757d' },
            'Out of Order': { backgroundColor: '#f8d7da', color: '#721c24' }
        };
        const style = statusStyles[status] || { backgroundColor: '#f8d7da', color: '#721c24' };
        return (
            <span style={{
                padding: '2px 8px',
                borderRadius: '4px',
                fontSize: '12px',
                ...style
            }}>
                {status}
            </span>
        );
    };

    // Handler functions for tool actions
    const handleAddTool = async () => {
        const defaultTool = {
            category: activeToolCategory,
            name: '', // Empty to force user input
            barcode: '',
            cost: '',
            manufacturer: '',
            distributor: '',
            date_of_purchase: '',
            status: 'Available',
            // Add other fields as needed for category
            volume: '',
            weight: '',
            holding_time: ''
        };
        setEditingToolData(defaultTool);
        setEditingToolId('new'); // Use 'new' as a temporary ID
        setHasUnsavedChanges(true);
        setValidationErrors(validateToolData(defaultTool, activeToolCategory));
        setSaveErrorMsg('Please fill all required fields highlighted in red.');
    };

    const handleEdit = (toolId) => {
        handleStartEdit(toolId);
    };

    const handleCopy = async (toolId) => {
        console.log('handleCopy called with toolId:', toolId);
        const tool = tools.find(t => t.id === toolId);
        console.log('Found tool:', tool);
        
        if (tool) {
            // Create copy with modified name
            const copiedTool = {
                ...tool,
                id: undefined, // No ID means it's a new tool
                name: tool.name + ' (Copy)',
                barcode: '' // Leave barcode empty for user to fill
            };
            console.log('Copied tool data:', copiedTool);
            
            try {
                const savedTool = await saveTool(copiedTool, true);
                setTools(prevTools => [...prevTools, savedTool]);
                // Start editing the copied tool immediately
                setEditingToolId(savedTool.id);
            } catch (error) {
                console.error('Error copying tool:', error);
            }
        } else {
            console.error('Tool not found with ID:', toolId);
        }
    };

    const handleCheckOut = async (toolId) => {
        try {
            const tool = tools.find(t => t.id === toolId);
            if (tool) {
                const updatedTool = { ...tool, status: 'In Use' };
                await saveTool(updatedTool, false);
                setTools(prevTools =>
                    prevTools.map(t =>
                        t.id === toolId ? updatedTool : t
                    )
                );
                // No success popup - silent checkout
            }
        } catch (error) {
            console.error('Error checking out tool:', error);
            // No error popup - silent failure
        }
    };

    const handleCheckIn = async (toolId) => {
        try {
            const tool = tools.find(t => t.id === toolId);
            if (tool) {
                const updatedTool = { ...tool, status: 'Available' };
                await saveTool(updatedTool, false);
                setTools(prevTools =>
                    prevTools.map(t =>
                        t.id === toolId ? updatedTool : t
                    )
                );
                // No success popup - silent checkin
            }
        } catch (error) {
            console.error('Error checking in tool:', error);
            // No error popup - silent failure
        }
    };

    const handleArchive = async (toolId) => {
        try {
            const tool = tools.find(t => t.id === toolId);
            if (tool) {
                const updatedTool = { ...tool, status: 'Archived' };
                await saveTool(updatedTool, false);
                setTools(prevTools =>
                    prevTools.map(t =>
                        t.id === toolId ? updatedTool : t
                    )
                );
                // No success popup - silent archive
            }
        } catch (error) {
            console.error('Error archiving tool:', error);
            // No error popup - silent failure
        }
    };

    const handleDelete = async (toolId) => {
        if (window.confirm('Are you sure you want to delete this tool?')) {
            try {
                const token = localStorage.getItem('token');
                if (!token) {
                    throw new Error('No authentication token found');
                }
                
                const response = await fetch(`/fms-api/tools/${toolId}`, {
                    method: 'DELETE',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                
                if (!response.ok) {
                    throw new Error('Failed to delete tool');
                }
                
                setTools(prevTools => prevTools.filter(tool => tool.id !== toolId));
                // No success popup - silent delete
            } catch (error) {
                console.error('Error deleting tool:', error);
                // No error popup - silent failure
            }
        }
    };

    // Add focus handler
    const handleInputFocus = (e) => {
        e.target.select(); // Optionally select text for better UX
    };

    const filteredTools = getFilteredTools();
    const dynamicColumns = getDynamicColumns();
    const columnLabels = getColumnLabels();

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h3>Tools Management</h3>
                <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                    {/* Currency Selector */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <label htmlFor="currency-select" style={{ fontSize: '14px', fontWeight: '500' }}>
                            Currency:
                        </label>
                        <select
                            id="currency-select"
                            value={currency}
                            onChange={(e) => setCurrency(e.target.value)}
                            style={{
                                padding: '6px 10px',
                                border: '1px solid #ddd',
                                borderRadius: '4px',
                                backgroundColor: 'white',
                                fontSize: '14px',
                                cursor: 'pointer'
                            }}
                        >
                            {Object.entries(currencies).map(([code, config]) => (
                                <option key={code} value={code}>
                                    {config.label}
                                </option>
                            ))}
                        </select>
                    </div>
                    
                    <button 
                        onClick={handleAddTool}
                        style={{ 
                            padding: '8px 16px', 
                            backgroundColor: '#007bff', 
                            color: 'white', 
                            border: 'none',
                            borderRadius: '4px',
                            cursor: 'pointer'
                        }}
                    >
                        Add New Tool
                    </button>
                </div>
            </div>

            {/* Tool Category Tabs */}
            <div style={{ 
                marginBottom: '20px',
                borderBottom: '2px solid #e9ecef'
            }}>
                <div style={{ display: 'flex', gap: '5px' }}>
                    {Object.keys(toolCategories).map(categoryKey => (
                        <button
                            key={categoryKey}
                            onClick={() => setActiveToolCategory(categoryKey)}
                            style={{
                                padding: '10px 20px',
                                border: 'none',
                                borderRadius: '4px 4px 0 0',
                                backgroundColor: activeToolCategory === categoryKey ? '#007bff' : '#f8f9fa',
                                color: activeToolCategory === categoryKey ? 'white' : '#495057',
                                cursor: 'pointer',
                                fontWeight: activeToolCategory === categoryKey ? 'bold' : 'normal',
                                transition: 'all 0.2s'
                            }}
                        >
                            {toolCategories[categoryKey].label}
                        </button>
                    ))}
                </div>
            </div>

            {/* Tools Table */}
            {filteredTools.length === 0 ? (
                <div style={{ 
                    textAlign: 'center', 
                    padding: '40px',
                    backgroundColor: '#f8f9fa',
                    borderRadius: '4px',
                    border: '1px solid #dee2e6'
                }}>
                    <p style={{ margin: '0', color: '#6c757d' }}>
                        No {toolCategories[activeToolCategory]?.name} tools available in this category.
                    </p>
                </div>
            ) : (
                <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '800px' }}>
                        <thead>
                            <tr>
                                {dynamicColumns.map(column => (
                                    <th key={column} style={{ 
                                        border: '1px solid #ddd', 
                                        padding: '12px 8px', 
                                        textAlign: 'left', 
                                        backgroundColor: '#f8f9fa',
                                        fontWeight: 'bold',
                                        fontSize: '14px'
                                    }}>
                                        {columnLabels[column] || column}
                                    </th>
                                ))}
                                <th style={{ 
                                    border: '1px solid #ddd', 
                                    padding: '12px 8px', 
                                    textAlign: 'left', 
                                    backgroundColor: '#f8f9fa',
                                    fontWeight: 'bold',
                                    fontSize: '14px',
                                    minWidth: '200px'
                                }}>
                                    Actions
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {/* Render normal tools */}
                            {filteredTools.map(tool => (
                                <tr key={tool.id}>
                                    {dynamicColumns.map(column => (
                                        <td key={column} style={{ 
                                            border: '1px solid #ddd', 
                                            padding: '8px',
                                            fontSize: '13px'
                                        }}>
                                            {column === 'status' 
                                                ? renderStatus(tool[column])
                                                : formatCellValue(tool[column], column, tool)
                                            }
                                        </td>
                                    ))}
                                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                                            {editingToolId === tool.id ? (
                                                // Save/Cancel buttons when editing
                                                <>
                                                    <button 
                                                        onClick={handleSaveEdit}
                                                        style={{ 
                                                            padding: '4px 8px', 
                                                            backgroundColor: '#28a745', 
                                                            color: 'white', 
                                                            border: 'none',
                                                            borderRadius: '2px',
                                                            cursor: 'pointer',
                                                            fontSize: '12px'
                                                        }}
                                                    >
                                                        Save
                                                    </button>
                                                    <button 
                                                        onClick={handleCancelEdit}
                                                        style={{ 
                                                            padding: '4px 8px', 
                                                            backgroundColor: '#6c757d', 
                                                            color: 'white', 
                                                            border: 'none',
                                                            borderRadius: '2px',
                                                            cursor: 'pointer',
                                                            fontSize: '12px'
                                                        }}
                                                    >
                                                        Cancel
                                                    </button>
                                                </>
                                            ) : (
                                                // Normal action buttons when not editing
                                                <>
                                                    <button 
                                                        onClick={() => handleEdit(tool.id)}
                                                        style={{ 
                                                            padding: '4px 8px', 
                                                            backgroundColor: '#6c757d', 
                                                            color: 'white', 
                                                            border: 'none',
                                                            borderRadius: '2px',
                                                            cursor: 'pointer',
                                                            fontSize: '12px'
                                                        }}
                                                    >
                                                        Edit
                                                    </button>

                                                    <button 
                                                        onClick={() => handleCopy(tool.id)}
                                                        style={{ 
                                                            padding: '4px 8px', 
                                                            backgroundColor: '#17a2b8', 
                                                            color: 'white', 
                                                            border: 'none',
                                                            borderRadius: '2px',
                                                            cursor: 'pointer',
                                                            fontSize: '12px'
                                                        }}
                                                    >
                                                        Copy
                                                    </button>
                                                    
                                                    {tool.status === 'Available' && (
                                                        <button 
                                                            onClick={() => handleCheckOut(tool.id)}
                                                            style={{ 
                                                                padding: '4px 8px', 
                                                                backgroundColor: '#28a745', 
                                                                color: 'white', 
                                                                border: 'none',
                                                                borderRadius: '2px',
                                                                cursor: 'pointer',
                                                                fontSize: '12px'
                                                            }}
                                                        >
                                                            Check Out
                                                        </button>
                                                    )}
                                                    
                                                    {tool.status === 'In Use' && (
                                                        <button 
                                                            onClick={() => handleCheckIn(tool.id)}
                                                            style={{ 
                                                                padding: '4px 8px', 
                                                                backgroundColor: '#20c997', 
                                                                color: 'white', 
                                                                border: 'none',
                                                                borderRadius: '2px',
                                                                cursor: 'pointer',
                                                                fontSize: '12px'
                                                            }}
                                                        >
                                                            Check In
                                                        </button>
                                                    )}
                                                    
                                                    {tool.status !== 'Archived' && (
                                                        <button 
                                                            onClick={() => handleArchive(tool.id)}
                                                            style={{ 
                                                                padding: '4px 8px', 
                                                                backgroundColor: '#ffc107', 
                                                                color: '#212529', 
                                                                border: 'none',
                                                                borderRadius: '2px',
                                                                cursor: 'pointer',
                                                                fontSize: '12px'
                                                            }}
                                                        >
                                                            Archive
                                                        </button>
                                                    )}
                                                    
                                                    <button 
                                                        onClick={() => handleDelete(tool.id)}
                                                        style={{ 
                                                            padding: '4px 8px', 
                                                            backgroundColor: '#dc3545', 
                                                            color: 'white', 
                                                            border: 'none',
                                                            borderRadius: '2px',
                                                            cursor: 'pointer',
                                                            fontSize: '12px'
                                                        }}
                                                    >
                                                        Delete
                                                    </button>
                                                </>
                                            )}
                                        </div>
                                    </td>
                                </tr>
                            ))}
                            {/* Render new tool row if adding */}
                            {editingToolId === 'new' && editingToolData && (
                                <tr>
                                    {dynamicColumns.map(column => (
                                        <td key={column} style={{ 
                                            border: '1px solid #ddd', 
                                            padding: '8px',
                                            fontSize: '13px'
                                        }}>
                                            {formatCellValue(editingToolData[column], column, editingToolData)}
                                        </td>
                                    ))}
                                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                                            <button 
                                                onClick={handleSaveEdit}
                                                style={{ 
                                                    padding: '4px 8px', 
                                                    backgroundColor: '#28a745', 
                                                    color: 'white', 
                                                    border: 'none',
                                                    borderRadius: '2px',
                                                    cursor: 'pointer',
                                                    fontSize: '12px'
                                                }}
                                            >
                                                Save
                                            </button>
                                            <button 
                                                onClick={handleCancelEdit}
                                                style={{
                                                    padding: '4px 8px', 
                                                    backgroundColor: '#6c757d', 
                                                    color: 'white', 
                                                    border: 'none',
                                                    borderRadius: '2px',
                                                    cursor: 'pointer',
                                                    fontSize: '12px'
                                                }}
                                            >
                                                Cancel
                                            </button>
                                            {saveErrorMsg && (
                                                <div style={{ color: '#dc3545', fontSize: '12px', marginTop: '4px' }}>{saveErrorMsg}</div>
                                            )}
                                        </div>
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

export default ToolsTab;
