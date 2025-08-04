import React, { useState, useEffect } from 'react';
import { displayNetworkScanResults } from './NetworkScanUtils';

function ITTab({ userData }) {
    const [servers, setServers] = useState([]);
    const [workstations, setWorkstations] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [scanStatus, setScanStatus] = useState(null);
    const [isNetworkScanning, setIsNetworkScanning] = useState(false);
    const [isAssetScanning, setIsAssetScanning] = useState(false);
    const [latestScanData, setLatestScanData] = useState(null);
    const [loadingScanData, setLoadingScanData] = useState(false);
    const [showDetailsModal, setShowDetailsModal] = useState(false);
    const [selectedAsset, setSelectedAsset] = useState(null);

    useEffect(() => {
        fetchITAssets();
        fetchLatestScanData();
    }, []);

    const fetchITAssets = async () => {
        try {
            setLoading(true);
            setError(null);
            
            const mockServers = [
                {
                    id: 1,
                    hostname: 'srv-web-01',
                    ip_address: '192.168.1.10',
                    ip: '192.168.1.10',
                    cost: '$2,500',
                    location: 'Data Center A - Rack 1',
                    os: 'Ubuntu 22.04 LTS',
                    status: 'online',
                    last_scan: '2024-01-15 10:30:00',
                    type: 'server',
                    macAddress: '00:1B:44:11:3A:B7',
                    building: 'Main Building',
                    room: 'DC-A-101',
                    rackPosition: 'Rack 1, U10-U12',
                    serialNumber: 'SV2023001',
                    manufacturer: 'Dell',
                    model: 'PowerEdge R740',
                    cpu: 'Intel Xeon Silver 4214R (2x12 cores)',
                    ram: '64GB DDR4',
                    storage: '2x 1TB NVMe SSD RAID 1',
                    networkInterfaces: '2x 1GbE, 2x 10GbE',
                    osVersion: '22.04.3 LTS',
                    kernelVersion: '5.15.0-91-generic',
                    architecture: 'x86_64',
                    lastBoot: '2024-01-15 09:30:00',
                    dnsServer: '8.8.8.8, 8.8.4.4',
                    gateway: '192.168.1.1',
                    subnetMask: '255.255.255.0',
                    dhcpEnabled: false,
                    domain: 'fms.local',
                    purchaseDate: '2023-03-15',
                    vendor: 'Dell Technologies',
                    purchaseOrder: 'PO-2023-0045',
                    assetTag: 'FMS-SRV-001',
                    warrantyStatus: 'Active',
                    warrantyExpiry: '2026-03-15',
                    supportContract: 'ProSupport Plus',
                    serviceLevel: '24x7x4',
                    lastMaintenance: '2024-01-10',
                    nextMaintenance: '2024-07-10',
                    monitoringStatus: 'Active',
                    backupStatus: 'Active',
                    lastBackup: '2024-01-20 02:00:00',
                    securityStatus: 'Compliant',
                    lastSecurityScan: '2024-01-18',
                    antivirusStatus: 'Active',
                    firewallStatus: 'Enabled',
                    complianceStatus: 'SOX Compliant',
                    primaryUser: 'IT Team',
                    department: 'Information Technology',
                    usageType: 'Production Web Server',
                    cpuUsage: '45%',
                    memoryUsage: '68%',
                    diskUsage: '32%',
                    environment: 'Production',
                    businessCriticality: 'High',
                    installedSoftware: 'Apache 2.4, PHP 8.1, MySQL 8.0',
                    notes: 'Primary web server for FMS application',
                    lastUpdated: '2024-01-20 14:30:00'
                },
                {
                    id: 2,
                    hostname: 'srv-db-01',
                    ip_address: '192.168.1.11',
                    ip: '192.168.1.11',
                    cost: '$4,200',
                    location: 'Data Center A - Rack 2',
                    os: 'Debian 12',
                    status: 'online',
                    last_scan: '2024-01-15 09:45:00',
                    type: 'server',
                    macAddress: '00:1B:44:11:3A:B8',
                    building: 'Main Building',
                    room: 'DC-A-101',
                    rackPosition: 'Rack 2, U5-U7',
                    serialNumber: 'SV2023002',
                    manufacturer: 'HPE',
                    model: 'ProLiant DL380 Gen10',
                    cpu: 'Intel Xeon Gold 6226R (2x16 cores)',
                    ram: '128GB DDR4',
                    storage: '4x 2TB SAS HDD RAID 10',
                    networkInterfaces: '2x 1GbE, 2x 10GbE',
                    osVersion: '12.2',
                    kernelVersion: '6.1.0-15-amd64',
                    architecture: 'x86_64',
                    lastBoot: '2024-01-12 08:15:00',
                    dnsServer: '8.8.8.8, 8.8.4.4',
                    gateway: '192.168.1.1',
                    subnetMask: '255.255.255.0',
                    dhcpEnabled: false,
                    domain: 'fms.local',
                    purchaseDate: '2023-04-20',
                    vendor: 'HPE',
                    purchaseOrder: 'PO-2023-0067',
                    assetTag: 'FMS-SRV-002',
                    warrantyStatus: 'Active',
                    warrantyExpiry: '2026-04-20',
                    supportContract: 'Foundation Care',
                    serviceLevel: '24x7x4',
                    lastMaintenance: '2024-01-08',
                    nextMaintenance: '2024-07-08',
                    monitoringStatus: 'Active',
                    backupStatus: 'Active',
                    lastBackup: '2024-01-20 01:00:00',
                    securityStatus: 'Compliant',
                    lastSecurityScan: '2024-01-17',
                    antivirusStatus: 'Active',
                    firewallStatus: 'Enabled',
                    complianceStatus: 'SOX Compliant',
                    primaryUser: 'Database Team',
                    department: 'Information Technology',
                    usageType: 'Production Database Server',
                    cpuUsage: '62%',
                    memoryUsage: '78%',
                    diskUsage: '58%',
                    environment: 'Production',
                    businessCriticality: 'Critical',
                    installedSoftware: 'PostgreSQL 15, Redis 7.0',
                    notes: 'Primary database server for FMS application',
                    lastUpdated: '2024-01-20 14:30:00'
                }
            ];

            const mockWorkstations = [
                {
                    id: 5,
                    hostname: 'ws-dev-01',
                    ip_address: '192.168.1.50',
                    ip: '192.168.1.50',
                    cost: '$1,200',
                    location: 'Office Floor 2 - Room 201',
                    os: 'Ubuntu 22.04 Desktop',
                    status: 'online',
                    last_scan: '2024-01-15 11:00:00',
                    type: 'workstation',
                    macAddress: '00:1B:44:11:3A:C1',
                    building: 'Office Building',
                    room: 'OF-2-201',
                    rackPosition: 'Desk 5',
                    serialNumber: 'WS2023001',
                    manufacturer: 'Dell',
                    model: 'OptiPlex 7090',
                    cpu: 'Intel Core i7-11700 (8 cores)',
                    ram: '32GB DDR4',
                    storage: '512GB NVMe SSD',
                    networkInterfaces: '1x 1GbE, WiFi 6',
                    osVersion: '22.04.3 LTS',
                    kernelVersion: '5.15.0-91-generic',
                    architecture: 'x86_64',
                    lastBoot: '2024-01-15 08:30:00',
                    dnsServer: '192.168.1.1',
                    gateway: '192.168.1.1',
                    subnetMask: '255.255.255.0',
                    dhcpEnabled: true,
                    domain: 'fms.local',
                    purchaseDate: '2023-06-15',
                    vendor: 'Dell Technologies',
                    purchaseOrder: 'PO-2023-0089',
                    assetTag: 'FMS-WS-001',
                    warrantyStatus: 'Active',
                    warrantyExpiry: '2026-06-15',
                    supportContract: 'ProSupport',
                    serviceLevel: '9x5xNBD',
                    lastMaintenance: '2024-01-12',
                    nextMaintenance: '2024-07-12',
                    monitoringStatus: 'Active',
                    backupStatus: 'Active',
                    lastBackup: '2024-01-14 18:00:00',
                    securityStatus: 'Compliant',
                    lastSecurityScan: '2024-01-14',
                    antivirusStatus: 'Active',
                    firewallStatus: 'Enabled',
                    complianceStatus: 'Compliant',
                    primaryUser: 'John Developer',
                    department: 'Development',
                    usageType: 'Development Workstation',
                    cpuUsage: '35%',
                    memoryUsage: '55%',
                    diskUsage: '42%',
                    environment: 'Development',
                    businessCriticality: 'Medium',
                    installedSoftware: 'VS Code, Docker, Node.js, Python',
                    notes: 'Development workstation for software team',
                    lastUpdated: '2024-01-15 11:00:00'
                },
                {
                    id: 6,
                    hostname: 'ws-design-01',
                    ip_address: '192.168.1.51',
                    ip: '192.168.1.51',
                    cost: '$2,800',
                    location: 'Office Floor 3 - Room 305',
                    os: 'Windows 11 Pro',
                    status: 'online',
                    last_scan: '2024-01-15 10:15:00',
                    type: 'workstation',
                    macAddress: '00:1B:44:11:3A:C2',
                    building: 'Office Building',
                    room: 'OF-3-305',
                    rackPosition: 'Desk 12',
                    serialNumber: 'WS2023002',
                    manufacturer: 'HP',
                    model: 'Z6 G5A Workstation',
                    cpu: 'AMD Ryzen Threadripper PRO 5975WX (32 cores)',
                    ram: '128GB DDR4',
                    storage: '2TB NVMe SSD + 4TB HDD',
                    networkInterfaces: '2x 1GbE, WiFi 6E',
                    osVersion: '22H2 (Build 22621.2715)',
                    kernelVersion: 'NT 10.0.22621',
                    architecture: 'x86_64',
                    lastBoot: '2024-01-15 07:45:00',
                    dnsServer: '192.168.1.1',
                    gateway: '192.168.1.1',
                    subnetMask: '255.255.255.0',
                    dhcpEnabled: true,
                    domain: 'fms.local',
                    purchaseDate: '2023-09-20',
                    vendor: 'HP Inc.',
                    purchaseOrder: 'PO-2023-0167',
                    assetTag: 'FMS-WS-002',
                    warrantyStatus: 'Active',
                    warrantyExpiry: '2026-09-20',
                    supportContract: 'Care Pack Plus',
                    serviceLevel: '9x5xNBD',
                    lastMaintenance: '2024-01-10',
                    nextMaintenance: '2024-07-10',
                    monitoringStatus: 'Active',
                    backupStatus: 'Active',
                    lastBackup: '2024-01-14 19:00:00',
                    securityStatus: 'Compliant',
                    lastSecurityScan: '2024-01-14',
                    antivirusStatus: 'Active',
                    firewallStatus: 'Enabled',
                    complianceStatus: 'Compliant',
                    primaryUser: 'Sarah Designer',
                    department: 'Design',
                    usageType: 'CAD/Design Workstation',
                    cpuUsage: '75%',
                    memoryUsage: '82%',
                    diskUsage: '65%',
                    environment: 'Production',
                    businessCriticality: 'High',
                    installedSoftware: 'AutoCAD 2024, SolidWorks, Adobe Creative Suite',
                    notes: 'High-performance workstation for CAD design',
                    lastUpdated: '2024-01-15 10:15:00'
                }
            ];
            
            setServers(mockServers);
            setWorkstations(mockWorkstations);
        } catch (err) {
            setError('Failed to fetch IT assets data. Please try again.');
            console.error('Error fetching IT assets:', err);
        } finally {
            setLoading(false);
        }
    };

    const fetchLatestScanData = async () => {
        try {
            setLoadingScanData(true);
            const token = localStorage.getItem('token');
            
            if (!token) {
                console.log('No auth token found, skipping scan data fetch');
                return;
            }

            const response = await fetch('/fms-api/network-scan-results', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                }
            });

            if (response.ok) {
                const data = await response.json();
                console.log('Fetched scan data:', data);
                
                if (data.length > 0) {
                    const latestScan = data[0];
                    console.log('Setting latest scan data:', latestScan);
                    setLatestScanData(latestScan);
                } else {
                    console.log('No scan data found in response');
                    setLatestScanData(null);
                }
            } else if (response.status === 401) {
                console.log('Unauthorized - user not logged in');
            } else {
                console.error('Failed to fetch scan data:', response.status);
            }
        } catch (error) {
            console.error('Error fetching latest scan data:', error);
        } finally {
            setLoadingScanData(false);
        }
    };

    const formatNetworkStatus = (status) => {
        return status.charAt(0).toUpperCase() + status.slice(1);
    };

    const getNetworkStatusIcon = (status) => {
        switch (status) {
            case 'online':
                return '🟢';
            case 'offline':
                return '🔴';
            case 'unknown':
            default:
                return '🟡';
        }
    };

    const getNetworkStatusStyle = (status) => {
        switch(status) {
            case 'online': 
                return { backgroundColor: '#d4edda', color: '#155724' };
            case 'offline': 
                return { backgroundColor: '#f8d7da', color: '#721c24' };
            case 'unknown': 
                return { backgroundColor: '#e2e3e5', color: '#6c757d' };
            default: 
                return { backgroundColor: '#e2e3e5', color: '#6c757d' };
        }
    };

    const formatDate = (dateString) => {
        if (!dateString) return '';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    const scanLocalIPs = async () => {
        setIsNetworkScanning(true);
        setScanStatus(null);
        
        try {
            const response = await fetch('/fms-api/run-network-scan', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`,
                    'Content-Type': 'application/json',
                }
            });

            if (response.ok) {
                const result = await response.text();
                displayNetworkScanResults(result, setScanStatus);
                setTimeout(() => {
                    fetchLatestScanData();
                }, 1000);
            } else {
                throw new Error(`Network scan failed: ${response.status}`);
            }
        } catch (error) {
            console.error('Network scan error:', error);
            setScanStatus({ 
                type: 'error', 
                message: `Network scan failed: ${error.message}` 
            });
        } finally {
            setIsNetworkScanning(false);
        }
    };

    const runAssetScan = async () => {
        if (!window.confirm('This will run the asset scan script. Continue?')) {
            return;
        }

        setIsAssetScanning(true);
        setScanStatus(null);

        try {
            const response = await fetch('/fms-api/run-asset-scan', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`,
                    'Content-Type': 'application/json',
                }
            });

            if (response.ok) {
                setScanStatus({ type: 'success', message: `Asset scan completed successfully. Found ${servers.length + workstations.length} assets.` });
                await fetchITAssets();
            } else {
                throw new Error('Scan failed');
            }
        } catch (error) {
            console.error('Scan error:', error);
            setScanStatus({ type: 'error', message: 'Asset scan failed. Please check the script and try again.' });
        } finally {
            setIsAssetScanning(false);
        }
    };

    const openDetailsModal = (asset) => {
        setSelectedAsset(asset);
        setShowDetailsModal(true);
    };

    const closeDetailsModal = () => {
        setShowDetailsModal(false);
        setSelectedAsset(null);
    };

    const handleCopyAsset = (asset) => {
        alert(`Copy asset functionality to be implemented for: ${asset.hostname || asset.ip}`);
    };

    const handleEditAsset = (asset) => {
        alert(`Edit asset functionality to be implemented for: ${asset.hostname}`);
    };

    const handleArchiveAsset = (asset) => {
        alert(`Archive asset functionality to be implemented for: ${asset.hostname}`);
    };

    const handleDeleteAsset = (asset) => {
        if (window.confirm(`Are you sure you want to delete ${asset.hostname}?`)) {
            alert(`Delete asset functionality to be implemented for: ${asset.hostname}`);
        }
    };

    const showAddAssetForm = () => {
        alert('Add new asset form');
    };

    const exportAssets = () => {
        alert('Export assets functionality');
    };

    const renderAssetTable = (assets, title, icon) => (
        <div style={{ marginBottom: '40px' }}>
            <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '20px',
                padding: '15px',
                backgroundColor: '#f8f9fa',
                borderRadius: '6px',
                borderLeft: '4px solid #007bff'
            }}>
                <div style={{ fontSize: '18px', fontWeight: '600', color: '#495057' }}>
                    {icon} {title}
                </div>
                <div style={{
                    backgroundColor: '#007bff',
                    color: 'white',
                    padding: '4px 12px',
                    borderRadius: '20px',
                    fontSize: '14px',
                    fontWeight: '500'
                }}>
                    {assets.length} Assets
                </div>
            </div>
            
            {assets.length === 0 ? (
                <div style={{
                    textAlign: 'center',
                    padding: '40px',
                    color: '#6c757d',
                    fontStyle: 'italic'
                }}>
                    No {title.toLowerCase()} found. Run an asset scan to discover devices.
                </div>
            ) : (
                <div style={{
                    overflowX: 'auto',
                    border: '1px solid #dee2e6',
                    borderRadius: '6px'
                }}>
                    <table style={{
                        width: '100%',
                        borderCollapse: 'collapse',
                        minWidth: '1200px'
                    }}>
                        <thead>
                            <tr>
                                <th style={{
                                    backgroundColor: '#f8f9fa',
                                    padding: '12px 8px',
                                    textAlign: 'left',
                                    fontWeight: '600',
                                    fontSize: '14px',
                                    color: '#495057',
                                    borderBottom: '2px solid #dee2e6'
                                }}>Hostname</th>
                                <th style={{
                                    backgroundColor: '#f8f9fa',
                                    padding: '12px 8px',
                                    textAlign: 'left',
                                    fontWeight: '600',
                                    fontSize: '14px',
                                    color: '#495057',
                                    borderBottom: '2px solid #dee2e6'
                                }}>IP Address</th>
                                <th style={{
                                    backgroundColor: '#f8f9fa',
                                    padding: '12px 8px',
                                    textAlign: 'left',
                                    fontWeight: '600',
                                    fontSize: '14px',
                                    color: '#495057',
                                    borderBottom: '2px solid #dee2e6'
                                }}>Cost</th>
                                <th style={{
                                    backgroundColor: '#f8f9fa',
                                    padding: '12px 8px',
                                    textAlign: 'left',
                                    fontWeight: '600',
                                    fontSize: '14px',
                                    color: '#495057',
                                    borderBottom: '2px solid #dee2e6'
                                }}>Location</th>
                                <th style={{
                                    backgroundColor: '#f8f9fa',
                                    padding: '12px 8px',
                                    textAlign: 'left',
                                    fontWeight: '600',
                                    fontSize: '14px',
                                    color: '#495057',
                                    borderBottom: '2px solid #dee2e6'
                                }}>Operating System</th>
                                <th style={{
                                    backgroundColor: '#f8f9fa',
                                    padding: '12px 8px',
                                    textAlign: 'left',
                                    fontWeight: '600',
                                    fontSize: '14px',
                                    color: '#495057',
                                    borderBottom: '2px solid #dee2e6'
                                }}>Status</th>
                                <th style={{
                                    backgroundColor: '#f8f9fa',
                                    padding: '12px 8px',
                                    textAlign: 'left',
                                    fontWeight: '600',
                                    fontSize: '14px',
                                    color: '#495057',
                                    borderBottom: '2px solid #dee2e6'
                                }}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {assets.map(asset => (
                                <tr key={asset.id} style={{ cursor: 'pointer' }} 
                                    onMouseEnter={(e) => e.target.parentElement.style.backgroundColor = '#f8f9fa'}
                                    onMouseLeave={(e) => e.target.parentElement.style.backgroundColor = 'transparent'}>
                                    <td style={{
                                        padding: '10px 8px',
                                        borderBottom: '1px solid #dee2e6',
                                        fontSize: '13px',
                                        verticalAlign: 'middle'
                                    }}><strong>{asset.hostname}</strong></td>
                                    <td style={{
                                        padding: '10px 8px',
                                        borderBottom: '1px solid #dee2e6',
                                        fontSize: '13px',
                                        verticalAlign: 'middle'
                                    }}>
                                        <span style={{
                                            fontFamily: 'Monaco, monospace',
                                            backgroundColor: '#e3f2fd',
                                            color: '#1976d2',
                                            padding: '2px 6px',
                                            borderRadius: '3px',
                                            fontSize: '12px',
                                            fontWeight: '600'
                                        }}>
                                            {asset.ip_address}
                                        </span>
                                    </td>
                                    <td style={{
                                        padding: '10px 8px',
                                        borderBottom: '1px solid #dee2e6',
                                        fontSize: '13px',
                                        verticalAlign: 'middle'
                                    }}>
                                        <span style={{
                                            fontWeight: '600',
                                            color: '#28a745'
                                        }}>
                                            {asset.cost}
                                        </span>
                                    </td>
                                    <td style={{
                                        padding: '10px 8px',
                                        borderBottom: '1px solid #dee2e6',
                                        fontSize: '13px',
                                        verticalAlign: 'middle'
                                    }}>
                                        <span style={{
                                            backgroundColor: '#fff3cd',
                                            color: '#856404',
                                            padding: '2px 6px',
                                            borderRadius: '3px',
                                            fontSize: '12px',
                                            fontWeight: '500'
                                        }}>
                                            {asset.location}
                                        </span>
                                    </td>
                                    <td style={{
                                        padding: '10px 8px',
                                        borderBottom: '1px solid #dee2e6',
                                        fontSize: '13px',
                                        verticalAlign: 'middle'
                                    }}>{asset.os}</td>
                                    <td style={{
                                        padding: '10px 8px',
                                        borderBottom: '1px solid #dee2e6',
                                        fontSize: '13px',
                                        verticalAlign: 'middle'
                                    }}>
                                        <span style={{
                                            padding: '2px 8px',
                                            borderRadius: '12px',
                                            fontSize: '11px',
                                            fontWeight: '500',
                                            textTransform: 'uppercase',
                                            ...getNetworkStatusStyle(asset.status)
                                        }}>
                                            {getNetworkStatusIcon(asset.status)} {formatNetworkStatus(asset.status)}
                                        </span>
                                    </td>
                                    <td style={{
                                        padding: '10px 8px',
                                        borderBottom: '1px solid #dee2e6',
                                        fontSize: '13px',
                                        verticalAlign: 'middle'
                                    }}>
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2px' }}>
                                            <button style={{
                                                padding: '4px 8px',
                                                fontSize: '12px',
                                                margin: '1px',
                                                border: 'none',
                                                borderRadius: '4px',
                                                cursor: 'pointer',
                                                fontWeight: '500',
                                                transition: 'all 0.2s',
                                                backgroundColor: '#17a2b8',
                                                color: 'white'
                                            }} 
                                            onClick={() => openDetailsModal(asset)}>
                                                Details
                                            </button>
                                            <button style={{
                                                padding: '4px 8px',
                                                fontSize: '12px',
                                                margin: '1px',
                                                border: 'none',
                                                borderRadius: '4px',
                                                cursor: 'pointer',
                                                fontWeight: '500',
                                                transition: 'all 0.2s',
                                                backgroundColor: '#6c757d',
                                                color: 'white'
                                            }} 
                                            onClick={() => handleEditAsset(asset)}>
                                                Edit
                                            </button>
                                            <button style={{
                                                padding: '4px 8px',
                                                fontSize: '12px',
                                                margin: '1px',
                                                border: 'none',
                                                borderRadius: '4px',
                                                cursor: 'pointer',
                                                fontWeight: '500',
                                                transition: 'all 0.2s',
                                                backgroundColor: '#17a2b8',
                                                color: 'white'
                                            }} 
                                            onClick={() => handleCopyAsset(asset)}>
                                                Copy
                                            </button>
                                            <button style={{
                                                padding: '4px 8px',
                                                fontSize: '12px',
                                                margin: '1px',
                                                border: 'none',
                                                borderRadius: '4px',
                                                cursor: 'pointer',
                                                fontWeight: '500',
                                                transition: 'all 0.2s',
                                                backgroundColor: '#ffc107',
                                                color: '#212529'
                                            }} 
                                            onClick={() => handleArchiveAsset(asset)}>
                                                Archive
                                            </button>
                                            <button style={{
                                                padding: '4px 8px',
                                                fontSize: '12px',
                                                margin: '1px',
                                                border: 'none',
                                                borderRadius: '4px',
                                                cursor: 'pointer',
                                                fontWeight: '500',
                                                transition: 'all 0.2s',
                                                backgroundColor: '#dc3545',
                                                color: 'white'
                                            }} 
                                            onClick={() => handleDeleteAsset(asset)}>
                                                Delete
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );

    if (loading) {
        return (
            <div style={{ padding: '20px', textAlign: 'center' }}>
                <p>Loading IT assets...</p>
            </div>
        );
    }

    if (error) {
        return (
            <div style={{ padding: '20px', textAlign: 'center', color: 'red' }}>
                <p>{error}</p>
                <button onClick={fetchITAssets} style={{
                    padding: '8px 16px',
                    backgroundColor: '#007bff',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    marginTop: '10px'
                }}>
                    Retry
                </button>
            </div>
        );
    }

    return (
        <>
            <div style={{
                maxWidth: '1400px',
                margin: '0 auto',
                background: 'white',
                borderRadius: '8px',
                boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
                padding: '20px'
            }}>
                {/* Header Section with Buttons */}
            <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '30px',
                paddingBottom: '15px',
                borderBottom: '2px solid #e9ecef'
            }}>
                <h2 style={{ color: '#495057', fontSize: '24px', margin: 0 }}>
                    IT Assets Management
                </h2>
                <div style={{ display: 'flex', gap: '15px', alignItems: 'center' }}>
                    <button 
                        style={{
                            padding: '8px 16px',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: isNetworkScanning ? 'not-allowed' : 'pointer',
                            fontSize: '14px',
                            fontWeight: '500',
                            backgroundColor: isNetworkScanning ? '#6c757d' : '#17a2b8',
                            color: 'white',
                            transition: 'all 0.2s',
                            opacity: isNetworkScanning ? 0.7 : 1
                        }}
                        onClick={scanLocalIPs}
                        disabled={isNetworkScanning || isAssetScanning}
                    >
                        {isNetworkScanning ? '⏳ Scanning Network...' : '🌐 Scan Local IPs'}
                    </button>
                    <button 
                        style={{
                            padding: '8px 16px',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: isAssetScanning ? 'not-allowed' : 'pointer',
                            fontSize: '14px',
                            fontWeight: '500',
                            backgroundColor: isAssetScanning ? '#6c757d' : '#28a745',
                            color: 'white',
                            transition: 'all 0.2s',
                            opacity: isAssetScanning ? 0.7 : 1
                        }}
                        onClick={runAssetScan}
                        disabled={isNetworkScanning || isAssetScanning}
                    >
                        {isAssetScanning ? '⏳ Scanning Assets...' : '🔍 Run Asset Scan'}
                    </button>
                    <button 
                        style={{
                            padding: '8px 16px',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '14px',
                            fontWeight: '500',
                            backgroundColor: '#007bff',
                            color: 'white'
                        }}
                        onClick={showAddAssetForm}
                    >
                        ➕ Add New Asset
                    </button>
                    <button 
                        style={{
                            padding: '8px 16px',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '14px',
                            fontWeight: '500',
                            backgroundColor: '#6c757d',
                            color: 'white'
                        }}
                        onClick={exportAssets}
                    >
                        📊 Export
                    </button>
                </div>
            </div>

            {/* Scan Status Message */}
            {scanStatus && (
                <div style={{
                    padding: '10px',
                    marginBottom: '20px',
                    borderRadius: '6px',
                    fontWeight: '500',
                    backgroundColor: scanStatus.type === 'success' ? '#d4edda' : '#f8d7da',
                    color: scanStatus.type === 'success' ? '#155724' : '#721c24',
                    border: `1px solid ${scanStatus.type === 'success' ? '#c3e6cb' : '#f5c6cb'}`
                }}>
                    {scanStatus.type === 'success' ? '✅' : '❌'} {scanStatus.message}
                </div>
            )}

            {/* Latest Network Scan Results */}
            {latestScanData && (
                <div style={{
                    marginBottom: '30px',
                    padding: '20px',
                    backgroundColor: '#f8f9fa',
                    borderRadius: '8px',
                    border: '1px solid #dee2e6'
                }}>
                    <h3 style={{ 
                        margin: '0 0 15px 0', 
                        color: '#495057',
                        fontSize: '18px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                    }}>
                        🔍 Latest Network Scan Results
                        <span style={{
                            fontSize: '12px',
                            color: '#6c757d',
                            fontWeight: 'normal',
                            marginLeft: '10px'
                        }}>
                            {new Date(latestScanData.scan_timestamp).toLocaleString()}
                        </span>
                    </h3>
                    
                    {loadingScanData ? (
                        <div style={{ textAlign: 'center', padding: '20px', color: '#6c757d' }}>
                            Loading scan data...
                        </div>
                    ) : latestScanData.ips && latestScanData.ips.length > 0 ? (
                        <div style={{ overflowX: 'auto' }}>
                            <table style={{
                                width: '100%',
                                borderCollapse: 'collapse',
                                backgroundColor: 'white',
                                borderRadius: '6px',
                                overflow: 'hidden'
                            }}>
                                <thead>
                                    <tr style={{ backgroundColor: '#e9ecef' }}>
                                        <th style={{
                                            padding: '12px',
                                            textAlign: 'left',
                                            fontWeight: '600',
                                            color: '#495057',
                                            fontSize: '14px',
                                            borderBottom: '1px solid #dee2e6'
                                        }}>#</th>
                                        <th style={{
                                            padding: '12px',
                                            textAlign: 'left',
                                            fontWeight: '600',
                                            color: '#495057',
                                            fontSize: '14px',
                                            borderBottom: '1px solid #dee2e6'
                                        }}>IP Address</th>
                                        <th style={{
                                            padding: '12px',
                                            textAlign: 'left',
                                            fontWeight: '600',
                                            color: '#495057',
                                            fontSize: '14px',
                                            borderBottom: '1px solid #dee2e6'
                                        }}>Hostname</th>
                                        <th style={{
                                            padding: '12px',
                                            textAlign: 'left',
                                            fontWeight: '600',
                                            color: '#495057',
                                            fontSize: '14px',
                                            borderBottom: '1px solid #dee2e6'
                                        }}>Source</th>
                                        <th style={{
                                            padding: '12px',
                                            textAlign: 'left',
                                            fontWeight: '600',
                                            color: '#495057',
                                            fontSize: '14px',
                                            borderBottom: '1px solid #dee2e6'
                                        }}>Status</th>
                                        <th style={{
                                            padding: '12px',
                                            textAlign: 'left',
                                            fontWeight: '600',
                                            color: '#495057',
                                            fontSize: '14px',
                                            borderBottom: '1px solid #dee2e6'
                                        }}>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {latestScanData.ips.map((ip, index) => (
                                        <tr key={index} style={{
                                            borderBottom: index === latestScanData.ips.length - 1 ? 'none' : '1px solid #dee2e6'
                                        }}>
                                            <td style={{
                                                padding: '10px 12px',
                                                fontSize: '13px',
                                                color: '#495057',
                                                fontWeight: '500'
                                            }}>{index + 1}</td>
                                            <td style={{
                                                padding: '10px 12px',
                                                fontSize: '13px'
                                            }}>
                                                <span style={{
                                                    fontFamily: 'Monaco, monospace',
                                                    backgroundColor: '#e3f2fd',
                                                    color: '#1976d2',
                                                    padding: '2px 6px',
                                                    borderRadius: '3px',
                                                    fontSize: '12px',
                                                    fontWeight: '600'
                                                }}>
                                                    {ip.ip_address}
                                                </span>
                                            </td>
                                            <td style={{
                                                padding: '10px 12px',
                                                fontSize: '13px'
                                            }}>
                                                {ip.hostname ? (
                                                    <span style={{
                                                        backgroundColor: '#e8f5e8',
                                                        color: '#2e7d32',
                                                        padding: '2px 6px',
                                                        borderRadius: '3px',
                                                        fontSize: '12px',
                                                        fontWeight: '500'
                                                    }}>
                                                        {ip.hostname}
                                                    </span>
                                                ) : (
                                                    <span style={{ color: '#6c757d', fontStyle: 'italic' }}>N/A</span>
                                                )}
                                            </td>
                                            <td style={{
                                                padding: '10px 12px',
                                                fontSize: '13px'
                                            }}>
                                                <span style={{
                                                    backgroundColor: ip.source === 'DHCP' ? '#fff3cd' : ip.source === 'NFS' ? '#d4edda' : '#f8d7da',
                                                    color: ip.source === 'DHCP' ? '#856404' : ip.source === 'NFS' ? '#155724' : '#721c24',
                                                    padding: '2px 6px',
                                                    borderRadius: '3px',
                                                    fontSize: '11px',
                                                    fontWeight: '500',
                                                    textTransform: 'uppercase'
                                                }}>
                                                    {ip.source}
                                                </span>
                                            </td>
                                            <td style={{
                                                padding: '10px 12px',
                                                fontSize: '13px'
                                            }}>
                                                <span style={{
                                                    backgroundColor: ip.status === 'online' ? '#d4edda' : ip.status === 'offline' ? '#f8d7da' : '#e2e3e5',
                                                    color: ip.status === 'online' ? '#155724' : ip.status === 'offline' ? '#721c24' : '#6c757d',
                                                    padding: '2px 8px',
                                                    borderRadius: '12px',
                                                    fontSize: '11px',
                                                    fontWeight: '500',
                                                    textTransform: 'uppercase'
                                                }}>
                                                    {ip.status === 'online' ? '🟢 Online' : ip.status === 'offline' ? '🔴 Offline' : '❓ Unknown'}
                                                </span>
                                            </td>
                                            <td style={{
                                                padding: '10px 12px',
                                                fontSize: '13px'
                                            }}>
                                                <button 
                                                    style={{
                                                        padding: '4px 8px',
                                                        fontSize: '12px',
                                                        border: 'none',
                                                        borderRadius: '4px',
                                                        cursor: 'pointer',
                                                        fontWeight: '500',
                                                        backgroundColor: '#007bff',
                                                        color: 'white',
                                                        transition: 'all 0.2s'
                                                    }}
                                                    onClick={() => {
                                                        // Do nothing for now
                                                    }}
                                                >
                                                    Copy Asset
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div style={{
                            textAlign: 'center',
                            padding: '40px',
                            color: '#6c757d',
                            fontStyle: 'italic'
                        }}>
                            No network scan data available. Run a network scan to see results here.
                        </div>
                    )}
                </div>
            )}

            {/* Servers Section */}
            {renderAssetTable(servers, 'Servers', '🖥️')}

            {/* Workstations Section */}
            {renderAssetTable(workstations, 'Workstations', '💻')}
        </div>

        {/* Details Modal */}
        {showDetailsModal && selectedAsset && (
                <div style={{
                    position: 'fixed',
                    top: '0',
                    left: '0',
                    right: '0',
                    bottom: '0',
                    backgroundColor: 'rgba(0, 0, 0, 0.7)',
                    display: 'flex',
                    justifyContent: 'center',
                    alignItems: 'center',
                    zIndex: '1000'
                }}>
                    <div style={{
                        backgroundColor: 'white',
                        borderRadius: '8px',
                        padding: '20px',
                        maxWidth: '95vw',
                        width: '1400px',
                        maxHeight: '95vh',
                        overflowY: 'auto',
                        boxShadow: '0 4px 8px rgba(0, 0, 0, 0.2)',
                        position: 'relative'
                    }}>
                        <button onClick={closeDetailsModal} style={{
                            position: 'absolute',
                            top: '15px',
                            right: '15px',
                            backgroundColor: '#dc3545',
                            color: 'white',
                            border: 'none',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontSize: '16px',
                            fontWeight: '600',
                            padding: '10px 15px',
                            boxShadow: '0 2px 4px rgba(0,0,0,0.2)',
                            zIndex: 1002
                        }}>
                            ✕ Close
                        </button>
                        <h3 style={{ margin: '0 0 15px 0', color: '#495057', fontSize: '18px' }}>
                            Asset Details: {selectedAsset.hostname}
                        </h3>
                        <div style={{
                            display: 'grid',
                            gridTemplateColumns: 'repeat(3, 1fr)',
                            gap: '15px'
                        }}>
                            {/* Basic Information */}
                            <div style={{
                                backgroundColor: '#f9f9f9',
                                border: '1px solid #e0e0e0',
                                borderRadius: '6px',
                                padding: '15px'
                            }}>
                                <h4 style={{
                                    margin: '0 0 15px 0',
                                    fontSize: '16px',
                                    color: '#333',
                                    fontWeight: '600',
                                    borderBottom: '2px solid #007bff',
                                    paddingBottom: '5px'
                                }}>Basic Information</h4>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>Hostname:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.hostname}</span>
                                </div>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>IP Address:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.ip_address}</span>
                                </div>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>Type:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.type}</span>
                                </div>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>Status:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{formatNetworkStatus(selectedAsset.status)}</span>
                                </div>
                            </div>

                            {/* Hardware Specifications */}
                            <div style={{
                                backgroundColor: '#f9f9f9',
                                border: '1px solid #e0e0e0',
                                borderRadius: '6px',
                                padding: '15px'
                            }}>
                                <h4 style={{
                                    margin: '0 0 15px 0',
                                    fontSize: '16px',
                                    color: '#333',
                                    fontWeight: '600',
                                    borderBottom: '2px solid #007bff',
                                    paddingBottom: '5px'
                                }}>Hardware</h4>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>Manufacturer:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.manufacturer || 'N/A'}</span>
                                </div>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>Model:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.model || 'N/A'}</span>
                                </div>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>CPU:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.cpu || 'N/A'}</span>
                                </div>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>RAM:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.ram || 'N/A'}</span>
                                </div>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>Storage:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.storage || 'N/A'}</span>
                                </div>
                            </div>

                            {/* Financial Information */}
                            <div style={{
                                backgroundColor: '#f9f9f9',
                                border: '1px solid #e0e0e0',
                                borderRadius: '6px',
                                padding: '15px'
                            }}>
                                <h4 style={{
                                    margin: '0 0 15px 0',
                                    fontSize: '16px',
                                    color: '#333',
                                    fontWeight: '600',
                                    borderBottom: '2px solid #007bff',
                                    paddingBottom: '5px'
                                }}>Financial</h4>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>Cost:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.cost}</span>
                                </div>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>Purchase Date:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.purchaseDate || 'N/A'}</span>
                                </div>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>Vendor:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.vendor || 'N/A'}</span>
                                </div>
                                <div style={{ display: 'flex', marginBottom: '8px', fontSize: '14px' }}>
                                    <span style={{ flex: '0 0 45%', fontWeight: '500', color: '#555' }}>Asset Tag:</span>
                                    <span style={{ flex: '1', color: '#333', wordBreak: 'break-word' }}>{selectedAsset.assetTag || 'N/A'}</span>
                                </div>
                            </div>
                        </div>
                        <div style={{
                            display: 'flex',
                            justifyContent: 'flex-end',
                            gap: '10px',
                            marginTop: '20px',
                            paddingTop: '20px',
                            borderTop: '1px solid #e0e0e0'
                        }}>
                            <button style={{
                                padding: '10px 20px',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer',
                                fontSize: '14px',
                                fontWeight: '500',
                                background: '#6c757d',
                                color: 'white'
                            }} onClick={closeDetailsModal}>Close</button>
                            <button style={{
                                padding: '10px 20px',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer',
                                fontSize: '14px',
                                fontWeight: '500',
                                background: '#007bff',
                                color: 'white'
                            }} onClick={() => handleEditAsset(selectedAsset)}>Edit Asset</button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}

export default ITTab;