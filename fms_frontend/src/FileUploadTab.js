import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';

function FileUploadTab({ userData }) {
    const [selectedFiles, setSelectedFiles] = useState([]);
    const [uploading, setUploading] = useState(false);
    const [uploadProgress, setUploadProgress] = useState({});
    const [uploadResults, setUploadResults] = useState([]);
    const [fileUploads, setFileUploads] = useState([]);
    const [facilities, setFacilities] = useState([]);
    const [selectedFacility, setSelectedFacility] = useState('');
    const [fileCategory, setFileCategory] = useState('document');
    const [description, setDescription] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const fileInputRef = useRef(null);

    useEffect(() => {
        fetchFacilities();
        fetchFileUploads();
    }, []);

    const fetchFacilities = async () => {
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            const response = await axios.get('/fms-api/facilities', config);
            setFacilities(response.data);
        } catch (err) {
            console.error('Error fetching facilities:', err);
        }
    };

    const fetchFileUploads = async () => {
        setLoading(true);
        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };
            const response = await axios.get('/fms-api/file-uploads', config);
            setFileUploads(response.data || []);
        } catch (err) {
            setError('Failed to load file uploads');
            setFileUploads([]);
            console.error('Error fetching file uploads:', err);
        } finally {
            setLoading(false);
        }
    };

    const handleFileSelect = (e) => {
        const files = Array.from(e.target.files);
        if (files.length > 0) {
            // Only take the first file
            setSelectedFiles([files[0]]);
            setUploadResults([]);
            setError('');
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        e.stopPropagation();
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        const files = Array.from(e.dataTransfer.files);
        if (files.length > 0) {
            // Only take the first file
            setSelectedFiles([files[0]]);
            setUploadResults([]);
            setError('');
        }
    };

    const formatFileSize = (bytes) => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const removeFile = (index) => {
        const newFiles = selectedFiles.filter((_, i) => i !== index);
        setSelectedFiles(newFiles);
    };

    const uploadFiles = async () => {
        if (selectedFiles.length === 0) {
            setError('Please select files to upload');
            return;
        }

        if (!selectedFacility) {
            setError('Please select a facility');
            return;
        }

        setUploading(true);
        setError('');
        const results = [];

        for (let i = 0; i < selectedFiles.length; i++) {
            const file = selectedFiles[i];

            try {
                // Initialize upload progress
                setUploadProgress(prev => ({
                    ...prev,
                    [file.name]: 0
                }));

                // Create FormData for file upload
                const formData = new FormData();
                formData.append('file', file);
                formData.append('facility_id', selectedFacility);
                formData.append('file_category', fileCategory);
                formData.append('description', description);

                const config = {
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('token')}`
                    },
                    onUploadProgress: (progressEvent) => {
                        const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
                        setUploadProgress(prev => ({
                            ...prev,
                            [file.name]: percentCompleted
                        }));
                    }
                };

                const response = await axios.post('/fms-api/file-uploads', formData, config);

                results.push({
                    fileName: file.name,
                    status: 'success',
                    message: 'File uploaded successfully',
                    size: file.size,
                    uploadedAt: new Date().toISOString(),
                    fileId: response.data.fileId
                });

            } catch (err) {
                results.push({
                    fileName: file.name,
                    status: 'error',
                    message: err.response?.data?.error || 'Upload failed',
                    size: file.size
                });
            }
        }

        setUploadResults(results);
        setUploading(false);
        setSelectedFiles([]);
        setUploadProgress({});
        setDescription('');

        if (fileInputRef.current) {
            fileInputRef.current.value = '';
        }

        // Refresh file uploads list
        fetchFileUploads();
    };

    const handleDeleteFile = async (fileId, fileName) => {
        if (!window.confirm(`Are you sure you want to delete "${fileName}"? This action cannot be undone.`)) {
            return;
        }

        try {
            const config = {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            };

            await axios.delete(`/fms-api/file-uploads/${fileId}`, config);

            // Refresh the file list
            fetchFileUploads();

            // Show success message
            alert('File deleted successfully');
        } catch (err) {
            console.error('Error deleting file:', err);
            alert(err.response?.data?.error || 'Failed to delete file');
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <h3>File Upload Management</h3>

            {error && <div style={{ color: 'red', marginBottom: '15px' }}>{error}</div>}

            {/* Upload Configuration */}
            <div style={{
                marginBottom: '20px',
                padding: '15px',
                border: '1px solid #ddd',
                borderRadius: '4px',
                backgroundColor: '#f8f9fa'
            }}>
                <h4>Upload Configuration</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginBottom: '15px' }}>
                    <div>
                        <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                            Facility:
                        </label>
                        <select
                            value={selectedFacility}
                            onChange={(e) => setSelectedFacility(e.target.value)}
                            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #ccc' }}
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
                    <div>
                        <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                            File Category:
                        </label>
                        <select
                            value={fileCategory}
                            onChange={(e) => setFileCategory(e.target.value)}
                            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #ccc' }}
                        >
                            <option value="certificate">Certificate</option>
                            <option value="document">Document</option>
                            <option value="image">Image</option>
                            <option value="manual">Manual</option>
                            <option value="other">Other</option>
                            <option value="publication">Publication</option>
                            <option value="report">Report</option>
                            <option value="sop">SOP (Standard Operating Procedure)</option>
                        </select>
                    </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '15px' }}>
                    <div>
                        <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                            Description:
                        </label>
                        <input
                            type="text"
                            value={description}
                            onChange={(e) => setDescription(e.target.value)}
                            placeholder="Brief description of the file"
                            style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #ccc' }}
                        />
                    </div>
                </div>
            </div>

            {/* Upload Area and Guidelines Container */}
            <div style={{ display: 'flex', gap: '20px', marginBottom: '20px' }}>
                {/* Upload Area - Half Width */}
                <div style={{ flex: '1' }}>
                    <div
                        onDragOver={handleDragOver}
                        onDrop={handleDrop}
                        style={{
                            border: '2px dashed #ccc',
                            borderRadius: '8px',
                            padding: '40px',
                            textAlign: 'center',
                            backgroundColor: '#fafafa',
                            cursor: 'pointer',
                            height: 'auto',
                            minHeight: '200px',
                            display: 'flex',
                            flexDirection: 'column',
                            justifyContent: 'center'
                        }}
                        onClick={() => fileInputRef.current?.click()}
                    >
                        <div style={{ fontSize: '48px', marginBottom: '10px', color: '#999' }}>📁</div>
                        <p style={{ fontSize: '18px', marginBottom: '10px' }}>
                            Drag and drop a file here, or click to select a file
                        </p>
                        <p style={{ fontSize: '14px', color: '#666' }}>
                            Upload one file at a time to ensure proper categorization
                        </p>
                        <p style={{ fontSize: '12px', color: '#666' }}>
                            Supported formats: Documents, Images, PDFs, Spreadsheets
                        </p>
                        <input
                            ref={fileInputRef}
                            type="file"
                            onChange={handleFileSelect}
                            style={{ display: 'none' }}
                            accept=".pdf,.doc,.docx,.xls,.xlsx,.png,.jpg,.jpeg,.gif,.txt,.csv"
                        />
                    </div>
                </div>

                {/* Guidelines - Half Width */}
                <div style={{ flex: '1' }}>
                    <div style={{
                        padding: '20px',
                        backgroundColor: '#e9ecef',
                        borderRadius: '8px',
                        border: '1px solid #dee2e6',
                        height: 'auto'
                    }}>
                        <h4 style={{ marginTop: '0', marginBottom: '15px', color: '#495057' }}>File Upload Guidelines</h4>
                        <ul style={{ marginBottom: '15px', paddingLeft: '20px' }}>
                            <li style={{ marginBottom: '8px' }}>Maximum file size: 50MB per file</li>
                            <li style={{ marginBottom: '8px' }}>Supported formats: PDF, DOC, DOCX, XLS, XLSX, PNG, JPG, JPEG, GIF, TXT, CSV</li>
                            <li style={{ marginBottom: '8px' }}>Files are automatically scanned for viruses</li>
                            <li style={{ marginBottom: '8px' }}>Uploaded files are stored securely and backed up daily</li>
                            <li style={{ marginBottom: '8px' }}>Only one file can be uploaded at a time</li>
                            <li style={{ marginBottom: '8px' }}>Ensure proper facility and category selection</li>
                        </ul>
                    </div>
                </div>
            </div>

            {/* Selected File */}
            {selectedFiles.length > 0 && (
                <div style={{ marginBottom: '20px' }}>
                    <h4>Selected File</h4>
                    <div style={{ border: '1px solid #ddd', borderRadius: '4px' }}>
                        {selectedFiles.map((file, index) => (
                            <div key={index} style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                padding: '15px'
                            }}>
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontWeight: 'bold', fontSize: '16px' }}>{file.name}</div>
                                    <div style={{ fontSize: '14px', color: '#666', marginTop: '5px' }}>
                                        {formatFileSize(file.size)} • {file.type || 'Unknown type'}
                                    </div>
                                    {uploadProgress[file.name] !== undefined && (
                                        <div style={{ marginTop: '10px' }}>
                                            <div style={{
                                                width: '100%',
                                                height: '6px',
                                                backgroundColor: '#eee',
                                                borderRadius: '3px',
                                                overflow: 'hidden'
                                            }}>
                                                <div style={{
                                                    width: `${uploadProgress[file.name]}%`,
                                                    height: '100%',
                                                    backgroundColor: '#007bff',
                                                    transition: 'width 0.3s ease'
                                                }}></div>
                                            </div>
                                            <div style={{ fontSize: '12px', color: '#666', marginTop: '5px' }}>
                                                Upload Progress: {uploadProgress[file.name]}%
                                            </div>
                                        </div>
                                    )}
                                </div>
                                {!uploading && (
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            removeFile(index);
                                        }}
                                        style={{
                                            backgroundColor: '#dc3545',
                                            color: 'white',
                                            border: 'none',
                                            borderRadius: '4px',
                                            padding: '8px 15px',
                                            cursor: 'pointer',
                                            fontSize: '14px'
                                        }}
                                    >
                                        Remove
                                    </button>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Upload Button */}
            {selectedFiles.length > 0 && (
                <div style={{ marginBottom: '20px' }}>
                    <button
                        onClick={uploadFiles}
                        disabled={uploading}
                        style={{
                            backgroundColor: uploading ? '#6c757d' : '#007bff',
                            color: 'white',
                            border: 'none',
                            borderRadius: '4px',
                            padding: '10px 20px',
                            cursor: uploading ? 'not-allowed' : 'pointer',
                            fontSize: '16px'
                        }}
                    >
                        {uploading ? 'Uploading...' : 'Upload File'}
                    </button>
                </div>
            )}

            {/* Upload Results */}
            {uploadResults.length > 0 && (
                <div style={{ marginBottom: '30px' }}>
                    <h4>Upload Results</h4>
                    <div style={{ border: '1px solid #ddd', borderRadius: '4px' }}>
                        {uploadResults.map((result, index) => (
                            <div key={index} style={{
                                padding: '10px',
                                borderBottom: index < uploadResults.length - 1 ? '1px solid #eee' : 'none',
                                backgroundColor: result.status === 'success' ? '#d4edda' : '#f8d7da'
                            }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div>
                                        <div style={{ fontWeight: 'bold', color: result.status === 'success' ? '#155724' : '#721c24' }}>
                                            {result.fileName}
                                        </div>
                                        <div style={{ fontSize: '12px', color: result.status === 'success' ? '#155724' : '#721c24' }}>
                                            {result.message} • {formatFileSize(result.size)}
                                            {result.uploadedAt && ` • ${new Date(result.uploadedAt).toLocaleString()}`}
                                        </div>
                                    </div>
                                    <div style={{
                                        fontSize: '16px',
                                        color: result.status === 'success' ? '#28a745' : '#dc3545'
                                    }}>
                                        {result.status === 'success' ? '✅' : '❌'}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Uploaded Files List */}
            <div style={{ marginBottom: '30px' }}>
                <h4>Uploaded Files</h4>
                {loading ? (
                    <div style={{ textAlign: 'center', padding: '20px' }}>Loading files...</div>
                ) : (
                    <div style={{ border: '1px solid #ddd', borderRadius: '4px', overflow: 'hidden' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                            <thead style={{ backgroundColor: '#f8f9fa' }}>
                                <tr>
                                    <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>File Name</th>
                                    <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>Facility</th>
                                    <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>Category</th>
                                    <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>Size</th>
                                    <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>Uploaded By</th>
                                    <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>Upload Date</th>
                                    <th style={{ padding: '12px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {fileUploads.length === 0 ? (
                                    <tr>
                                        <td colSpan="7" style={{
                                            padding: '20px',
                                            textAlign: 'center',
                                            color: '#666',
                                            fontStyle: 'italic',
                                            borderBottom: 'none'
                                        }}>
                                            No files uploaded yet
                                        </td>
                                    </tr>
                                ) : (
                                    fileUploads.map((upload, index) => (
                                        <tr key={upload.id} style={{ backgroundColor: index % 2 === 0 ? '#fff' : '#f9f9f9' }}>
                                            <td style={{ padding: '12px', borderBottom: '1px solid #eee' }}>
                                                <div style={{ fontWeight: 'bold' }}>{upload.original_name}</div>
                                                {upload.description && (
                                                    <div style={{ fontSize: '12px', color: '#666' }}>{upload.description}</div>
                                                )}
                                            </td>
                                            <td style={{ padding: '12px', borderBottom: '1px solid #eee' }}>
                                                {upload.facility_name}
                                            </td>
                                            <td style={{ padding: '12px', borderBottom: '1px solid #eee' }}>
                                                <span style={{
                                                    padding: '4px 8px',
                                                    borderRadius: '12px',
                                                    fontSize: '12px',
                                                    backgroundColor: '#e9ecef',
                                                    color: '#495057'
                                                }}>
                                                    {upload.file_category}
                                                </span>
                                            </td>
                                            <td style={{ padding: '12px', borderBottom: '1px solid #eee' }}>
                                                {formatFileSize(upload.file_size)}
                                            </td>
                                            <td style={{ padding: '12px', borderBottom: '1px solid #eee' }}>
                                                {upload.first_name} {upload.last_name}
                                            </td>
                                            <td style={{ padding: '12px', borderBottom: '1px solid #eee' }}>
                                                {new Date(upload.upload_timestamp).toLocaleDateString()}
                                            </td>
                                            <td style={{ padding: '12px', borderBottom: '1px solid #eee' }}>
                                                <button
                                                    onClick={() => handleDeleteFile(upload.id, upload.original_name)}
                                                    style={{
                                                        padding: '6px 12px',
                                                        backgroundColor: '#dc3545',
                                                        color: 'white',
                                                        border: 'none',
                                                        borderRadius: '4px',
                                                        cursor: 'pointer',
                                                        fontSize: '12px'
                                                    }}
                                                    onMouseOver={(e) => e.target.style.backgroundColor = '#c82333'}
                                                    onMouseOut={(e) => e.target.style.backgroundColor = '#dc3545'}
                                                >
                                                    Delete
                                                </button>
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}

export default FileUploadTab;
