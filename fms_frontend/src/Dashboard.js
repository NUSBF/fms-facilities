import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import UserTab from './UserTab.js';
import TrainingPage from './TrainingPage.js';
import EquipmentTab from './EquipmentTab.js';
import BookingTab from './BookingTab.js';
import ProjectTab from './ProjectTab.js';
import ShipmentsTab from './ShipmentsTab.js';
import CommercialTab from './CommercialTab.js';
import GrantsTab from './GrantsTab.js';
import CostingModelTab from './CostingModelTab.js';
import InvoicingTab from './InvoicingTab.js';
import SpendingTab from './SpendingTab.js';
import RiskAssessments from './RiskAssessments.js';
import MSDS from './MSDS.js';
import IncidentReports from './IncidentReports.js';
import SafetyInspectionReports from './SafetyInspectionReports.js';
import EmergencyProcedures from './EmergencyProcedures.js';
import LocalRules from './LocalRules.js';
import WasteDisposalProcedures from './WasteDisposalProcedures.js';
import ChemicalsTab from './ChemicalsTab.js';
import ConsumablesTab from './ConsumablesTab.js';
import StrainsTab from './StrainsTab.js';
import ProteinsTab from './ProteinsTab.js';
import LigandsTab from './LigandsTab.js';
import PlasmidsTab from './PlasmidsTab.js';
import ResourcesTab from './ResourcesTab.js';
import ToolsTab from './ToolsTab.js';
import ITTab from './ITTab.js';
import Tickets from './Tickets.js';
import Feedback from './Feedback.js';
import ReportsStats from './ReportsStats.js';
import PreferencesTab from './PreferencesTab.js';
import FileUploadTab from './FileUploadTab.js';

function Dashboard({ userData, onLogout }) {
    const [activeTab, setActiveTab] = useState(() => {
        return localStorage.getItem('dashboardActiveTab') || 'facilities';
    });
    const [activeInventoryTab, setActiveInventoryTab] = useState(() => {
        return localStorage.getItem('dashboardActiveInventoryTab') || 'assets';
    });
    const [activeAssetsTab, setActiveAssetsTab] = useState(() => {
        return localStorage.getItem('dashboardActiveAssetsTab') || 'equipment';
    });
    const [activeFinanceTab, setActiveFinanceTab] = useState(() => {
        return localStorage.getItem('dashboardActiveFinanceTab') || 'invoicing';
    });
    const [activeComplianceTab, setActiveComplianceTab] = useState(() => {
        return localStorage.getItem('dashboardActiveComplianceTab') || 'training';
    });
    const [activeSupportTab, setActiveSupportTab] = useState(() => {
        return localStorage.getItem('dashboardActiveSupportTab') || 'tickets';
    });
    const [activeResearchTab, setActiveResearchTab] = useState(() => {
        return localStorage.getItem('dashboardActiveResearchTab') || 'projects';
    });
    const [activeSetupTab, setActiveSetupTab] = useState(() => {
        return localStorage.getItem('dashboardActiveSetupTab') || 'preferences';
    });
    const [facilities, setFacilities] = useState([]);
    const [equipment, setEquipment] = useState([]);
    const [bookings, setBookings] = useState([]);
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    // Function to check if user can manage users
    const canManageUsers = () => {
        // Check if user has developer, administrator, facility_manager, or facility_staff role
        if (!userData || !userData.roles) return false;
        return userData.roles.some(role =>
            ['developer', 'administrator', 'facility_manager', 'facility_staff'].includes(role.role)
        );
    };

    // Handle equipment updates from EquipmentTab
    const handleEquipmentUpdate = (newEquipment) => {
        setEquipment(prev => [...prev, newEquipment]);
    };

    useEffect(() => {
        const fetchData = async () => {
            try {
                setLoading(true);
                setError('');

                const token = localStorage.getItem('token');
                if (!token) {
                    onLogout(); // Force logout if no token
                    return;
                }

                const config = {
                    headers: { Authorization: `Bearer ${token}` }
                };

                const [facilitiesRes, equipmentRes, bookingsRes] = await Promise.all([
                    axios.get('/fms-api/facilities', config),
                    axios.get('/fms-api/equipment', config),
                    axios.get('/fms-api/bookings', config)
                ]);

                setFacilities(facilitiesRes.data);
                setEquipment(equipmentRes.data);
                setBookings(bookingsRes.data);

                // Fetch users if the current user can manage users
                if (canManageUsers()) {
                    const usersRes = await axios.get('/fms-api/users', config);
                    setUsers(usersRes.data);
                }
            } catch (error) {
                setError('Failed to load data. Please try again.');
                // If unauthorized, logout
                if (error.response && error.response.status === 401) {
                    onLogout();
                }
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [onLogout]);

    // Save active tab to localStorage when it changes
    useEffect(() => {
        localStorage.setItem('dashboardActiveTab', activeTab);
    }, [activeTab]);

    // Save active sub-tabs to localStorage when they change
    useEffect(() => {
        localStorage.setItem('dashboardActiveInventoryTab', activeInventoryTab);
    }, [activeInventoryTab]);

    useEffect(() => {
        localStorage.setItem('dashboardActiveAssetsTab', activeAssetsTab);
    }, [activeAssetsTab]);

    useEffect(() => {
        localStorage.setItem('dashboardActiveFinanceTab', activeFinanceTab);
    }, [activeFinanceTab]);

    useEffect(() => {
        localStorage.setItem('dashboardActiveComplianceTab', activeComplianceTab);
    }, [activeComplianceTab]);

    useEffect(() => {
        localStorage.setItem('dashboardActiveSupportTab', activeSupportTab);
    }, [activeSupportTab]);

    useEffect(() => {
        localStorage.setItem('dashboardActiveResearchTab', activeResearchTab);
    }, [activeResearchTab]);

    useEffect(() => {
        localStorage.setItem('dashboardActiveSetupTab', activeSetupTab);
    }, [activeSetupTab]);

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
            {/* Header */}
            <header style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '10px 20px',
                backgroundColor: '#f0f0f0',
                borderBottom: '1px solid #ddd'
            }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                    {/* Facility Logo */}
                    {localStorage.getItem('facilityLogo') ? (
                        <img
                            src={localStorage.getItem('facilityLogo')}
                            alt="Facility Logo"
                            style={{
                                height: '50px',
                                width: 'auto',
                                maxWidth: '120px',
                                objectFit: 'contain'
                            }}
                            onError={(e) => {
                                e.target.style.display = 'none';
                            }}
                        />
                    ) : (
                        <div style={{
                            height: '50px',
                            width: '50px',
                            backgroundColor: '#007bff',
                            borderRadius: '8px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            color: 'white',
                            fontSize: '20px',
                            fontWeight: 'bold'
                        }}>
                            FMS
                        </div>
                    )}
                    <h1>FMS Facilities Management System</h1>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <button
                        onClick={onLogout}
                        style={{
                            padding: '8px 16px',
                            backgroundColor: '#dc3545',
                            color: 'white',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: 'pointer'
                        }}
                    >
                        Log Out
                    </button>
                </div>
            </header>

            {/* Main Content */}
            <div style={{ display: 'flex', flex: 1 }}>
                {/* User Panel - Left Side */}
                <div style={{
                    width: '250px',
                    padding: '20px',
                    borderRight: '1px solid #ddd',
                    backgroundColor: '#f8f9fa'
                }}>
                    <div style={{ textAlign: 'center', marginBottom: '20px' }}>
                        {/* User Image */}
                        {localStorage.getItem('userImage') ? (
                            <img
                                src={localStorage.getItem('userImage')}
                                alt="User Profile"
                                style={{
                                    width: '80px',
                                    height: '80px',
                                    borderRadius: '50%',
                                    objectFit: 'cover',
                                    margin: '0 auto 10px',
                                    border: '3px solid #007bff'
                                }}
                                onError={(e) => {
                                    // Fallback to initials if image fails to load
                                    e.target.style.display = 'none';
                                    e.target.nextSibling.style.display = 'flex';
                                }}
                            />
                        ) : null}
                        <div style={{
                            width: '80px',
                            height: '80px',
                            borderRadius: '50%',
                            backgroundColor: '#007bff',
                            color: 'white',
                            display: localStorage.getItem('userImage') ? 'none' : 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: '24px',
                            margin: '0 auto 10px'
                        }}>
                            {userData.user.first_name ? userData.user.first_name.charAt(0) : ''}
                            {userData.user.last_name ? userData.user.last_name.charAt(0) : ''}
                        </div>
                        <h3>{userData.user.first_name} {userData.user.last_name}</h3>
                        <p>{userData.user.email}</p>
                    </div>

                    <div>
                        <h4>Roles:</h4>
                        <ul style={{ listStyleType: 'none', padding: 0 }}>
                            {userData.roles.map((role, index) => (
                                <li key={index} style={{
                                    backgroundColor: '#e9ecef',
                                    padding: '8px 12px',
                                    borderRadius: '4px',
                                    marginBottom: '8px'
                                }}>
                                    {role.role}
                                    {role.facility_name &&
                                        <span style={{ fontSize: '0.8em', display: 'block' }}>
                                            {role.facility_name}
                                        </span>
                                    }
                                </li>
                            ))}
                        </ul>
                    </div>
                </div>

                {/* Tab Content - Right Side */}
                <div style={{ flex: 1, padding: '0', display: 'flex', flexDirection: 'column' }}>
                    {/* Tab Navigation */}
                    <div style={{ display: 'flex', borderBottom: '1px solid #ddd' }}>
                        {/* Alphabetical order: Bookings, Compliance, Facilities, Finance, Inventory, Research Operation, Support, Users */}
                        <div
                            onClick={() => setActiveTab('bookings')}
                            style={{
                                padding: '15px 25px',
                                cursor: 'pointer',
                                backgroundColor: activeTab === 'bookings' ? '#f8f9fa' : 'transparent',
                                borderBottom: activeTab === 'bookings' ? '2px solid #007bff' : 'none',
                                fontWeight: activeTab === 'bookings' ? 'bold' : 'normal'
                            }}
                        >
                            Bookings
                        </div>
                        <div
                            onClick={() => setActiveTab('compliance')}
                            style={{
                                padding: '15px 25px',
                                cursor: 'pointer',
                                backgroundColor: activeTab === 'compliance' ? '#f8f9fa' : 'transparent',
                                borderBottom: activeTab === 'compliance' ? '2px solid #007bff' : 'none',
                                fontWeight: activeTab === 'compliance' ? 'bold' : 'normal'
                            }}
                        >
                            Compliance
                        </div>
                        <div
                            onClick={() => setActiveTab('facilities')}
                            style={{
                                padding: '15px 25px',
                                cursor: 'pointer',
                                backgroundColor: activeTab === 'facilities' ? '#f8f9fa' : 'transparent',
                                borderBottom: activeTab === 'facilities' ? '2px solid #007bff' : 'none',
                                fontWeight: activeTab === 'facilities' ? 'bold' : 'normal'
                            }}
                        >
                            Facilities
                        </div>
                        <div
                            onClick={() => setActiveTab('finance')}
                            style={{
                                padding: '15px 25px',
                                cursor: 'pointer',
                                backgroundColor: activeTab === 'finance' ? '#f8f9fa' : 'transparent',
                                borderBottom: activeTab === 'finance' ? '2px solid #007bff' : 'none',
                                fontWeight: activeTab === 'finance' ? 'bold' : 'normal'
                            }}
                        >
                            Finance
                        </div>
                        <div
                            onClick={() => setActiveTab('inventory')}
                            style={{
                                padding: '15px 25px',
                                cursor: 'pointer',
                                backgroundColor: activeTab === 'inventory' ? '#f8f9fa' : 'transparent',
                                borderBottom: activeTab === 'inventory' ? '2px solid #007bff' : 'none',
                                fontWeight: activeTab === 'inventory' ? 'bold' : 'normal'
                            }}
                        >
                            Inventory
                        </div>
                        {/* New Research Operation tab */}
                        <div
                            onClick={() => setActiveTab('research-operation')}
                            style={{
                                padding: '15px 25px',
                                cursor: 'pointer',
                                backgroundColor: activeTab === 'research-operation' ? '#f8f9fa' : 'transparent',
                                borderBottom: activeTab === 'research-operation' ? '2px solid #007bff' : 'none',
                                fontWeight: activeTab === 'research-operation' ? 'bold' : 'normal'
                            }}
                        >
                            Research Operation
                        </div>
                        <div
                            onClick={() => setActiveTab('setup')}
                            style={{
                                padding: '15px 25px',
                                cursor: 'pointer',
                                backgroundColor: activeTab === 'setup' ? '#f8f9fa' : 'transparent',
                                borderBottom: activeTab === 'setup' ? '2px solid #007bff' : 'none',
                                fontWeight: activeTab === 'setup' ? 'bold' : 'normal'
                            }}
                        >
                            Setup
                        </div>
                        <div
                            onClick={() => setActiveTab('support')}
                            style={{
                                padding: '15px 25px',
                                cursor: 'pointer',
                                backgroundColor: activeTab === 'support' ? '#f8f9fa' : 'transparent',
                                borderBottom: activeTab === 'support' ? '2px solid #007bff' : 'none',
                                fontWeight: activeTab === 'support' ? 'bold' : 'normal'
                            }}
                        >
                            Support
                        </div>
                        {canManageUsers() && (
                            <div
                                onClick={() => setActiveTab('users')}
                                style={{
                                    padding: '15px 25px',
                                    cursor: 'pointer',
                                    backgroundColor: activeTab === 'users' ? '#f8f9fa' : 'transparent',
                                    borderBottom: activeTab === 'users' ? '2px solid #007bff' : 'none',
                                    fontWeight: activeTab === 'users' ? 'bold' : 'normal'
                                }}
                            >
                                Users & Groups
                            </div>
                        )}
                    </div>

                    {/* Tab Content */}
                    <div style={{ padding: '20px', flex: 1, overflowY: 'auto' }}>
                        {loading && (
                            <div style={{ textAlign: 'center', padding: '20px' }}>
                                <p>Loading data...</p>
                            </div>
                        )}

                        {error && (
                            <div style={{
                                textAlign: 'center',
                                padding: '20px',
                                color: 'red',
                                backgroundColor: '#ffeeee',
                                borderRadius: '4px',
                                margin: '10px 0'
                            }}>
                                <p>{error}</p>
                                <button
                                    onClick={() => window.location.reload()}
                                    style={{
                                        padding: '5px 10px',
                                        marginTop: '10px',
                                        backgroundColor: '#f8f9fa',
                                        border: '1px solid #ddd',
                                        borderRadius: '4px',
                                        cursor: 'pointer'
                                    }}
                                >
                                    Retry
                                </button>
                            </div>
                        )}

                        {!loading && !error && activeTab === 'facilities' && (
                            <div>
                                <h2>Facilities</h2>
                                {facilities.length === 0 ? (
                                    <p>No facilities available.</p>
                                ) : (
                                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                                        <thead>
                                            <tr>
                                                <th style={{ border: '1px solid #ddd', padding: '8px', textAlign: 'left' }}>Short Name</th>
                                                <th style={{ border: '1px solid #ddd', padding: '8px', textAlign: 'left' }}>Long Name</th>
                                                <th style={{ border: '1px solid #ddd', padding: '8px', textAlign: 'left' }}>Building</th>
                                                <th style={{ border: '1px solid #ddd', padding: '8px', textAlign: 'left' }}>Room</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {facilities.map(facility => (
                                                <tr key={facility.id}>
                                                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{facility.short_name}</td>
                                                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{facility.long_name}</td>
                                                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{facility.building}</td>
                                                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{facility.room}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                )}
                            </div>
                        )}

                        {!loading && !error && activeTab === 'bookings' && (
                            <BookingTab />
                        )}

                        {!loading && !error && activeTab === 'users' && canManageUsers() && (
                            <div>
                                <UserTab userData={userData} users={users} />
                            </div>
                        )}

                        {!loading && !error && activeTab === 'setup' && (
                            <div>
                                <h2>Setup</h2>
                                <div style={{ display: 'flex', borderBottom: '1px solid #dee2e6', marginBottom: '20px', backgroundColor: '#f8f9fa' }}>
                                    <div
                                        onClick={() => setActiveSetupTab('preferences')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeSetupTab === 'preferences' ? '#ffffff' : 'transparent',
                                            borderBottom: activeSetupTab === 'preferences' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeSetupTab === 'preferences' ? 'bold' : 'normal',
                                            border: activeSetupTab === 'preferences' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeSetupTab === 'preferences' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Preferences
                                    </div>
                                    <div
                                        onClick={() => setActiveSetupTab('file-upload')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeSetupTab === 'file-upload' ? '#ffffff' : 'transparent',
                                            borderBottom: activeSetupTab === 'file-upload' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeSetupTab === 'file-upload' ? 'bold' : 'normal',
                                            border: activeSetupTab === 'file-upload' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeSetupTab === 'file-upload' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        File Upload
                                    </div>
                                </div>
                                <div style={{ backgroundColor: '#ffffff', padding: '20px', border: '1px solid #dee2e6', borderRadius: '0 0 4px 4px' }}>
                                    {activeSetupTab === 'preferences' && (
                                        <PreferencesTab userData={userData} />
                                    )}
                                    {activeSetupTab === 'file-upload' && (
                                        <FileUploadTab userData={userData} />
                                    )}
                                </div>
                            </div>
                        )}                        {!loading && !error && activeTab === 'research-operation' && (
                            <div>
                                <h2>Research Operation</h2>
                                <div style={{ display: 'flex', borderBottom: '1px solid #dee2e6', marginBottom: '20px', backgroundColor: '#f8f9fa' }}>
                                    <div
                                        onClick={() => setActiveResearchTab('projects')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeResearchTab === 'projects' ? '#ffffff' : 'transparent',
                                            borderBottom: activeResearchTab === 'projects' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeResearchTab === 'projects' ? 'bold' : 'normal',
                                            border: activeResearchTab === 'projects' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeResearchTab === 'projects' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Projects
                                    </div>
                                    <div
                                        onClick={() => setActiveResearchTab('shipments')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeResearchTab === 'shipments' ? '#ffffff' : 'transparent',
                                            borderBottom: activeResearchTab === 'shipments' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeResearchTab === 'shipments' ? 'bold' : 'normal',
                                            border: activeResearchTab === 'shipments' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeResearchTab === 'shipments' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Shipments
                                    </div>
                                </div>
                                <div style={{ backgroundColor: '#ffffff', padding: '20px', border: '1px solid #dee2e6', borderRadius: '0 0 4px 4px' }}>
                                    {activeResearchTab === 'projects' && (
                                        <ProjectTab />
                                    )}
                                    {activeResearchTab === 'shipments' && (
                                        <ShipmentsTab userData={userData} />
                                    )}
                                </div>
                            </div>
                        )}

                        {!loading && !error && activeTab === 'inventory' && (
                            <div>
                                <h2>Inventory Management</h2>

                                {/* Inventory Sub-tabs */}
                                <div style={{
                                    display: 'flex',
                                    borderBottom: '1px solid #dee2e6',
                                    marginBottom: '20px',
                                    backgroundColor: '#f8f9fa'
                                }}>
                                    <div
                                        onClick={() => setActiveInventoryTab('assets')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeInventoryTab === 'assets' ? '#ffffff' : 'transparent',
                                            borderBottom: activeInventoryTab === 'assets' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeInventoryTab === 'assets' ? 'bold' : 'normal',
                                            border: activeInventoryTab === 'assets' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeInventoryTab === 'assets' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Assets
                                    </div>
                                    <div
                                        onClick={() => setActiveInventoryTab('chemicals')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeInventoryTab === 'chemicals' ? '#ffffff' : 'transparent',
                                            borderBottom: activeInventoryTab === 'chemicals' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeInventoryTab === 'chemicals' ? 'bold' : 'normal',
                                            border: activeInventoryTab === 'chemicals' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeInventoryTab === 'chemicals' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Chemicals
                                    </div>
                                    <div
                                        onClick={() => setActiveInventoryTab('consumables')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeInventoryTab === 'consumables' ? '#ffffff' : 'transparent',
                                            borderBottom: activeInventoryTab === 'consumables' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeInventoryTab === 'consumables' ? 'bold' : 'normal',
                                            border: activeInventoryTab === 'consumables' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeInventoryTab === 'consumables' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Consumables
                                    </div>
                                    <div
                                        onClick={() => setActiveInventoryTab('ligands')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeInventoryTab === 'ligands' ? '#ffffff' : 'transparent',
                                            borderBottom: activeInventoryTab === 'ligands' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeInventoryTab === 'ligands' ? 'bold' : 'normal',
                                            border: activeInventoryTab === 'ligands' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeInventoryTab === 'ligands' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Ligands
                                    </div>
                                    <div
                                        onClick={() => setActiveInventoryTab('plasmids')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeInventoryTab === 'plasmids' ? '#ffffff' : 'transparent',
                                            borderBottom: activeInventoryTab === 'plasmids' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeInventoryTab === 'plasmids' ? 'bold' : 'normal',
                                            border: activeInventoryTab === 'plasmids' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeInventoryTab === 'plasmids' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Plasmids
                                    </div>
                                    <div
                                        onClick={() => setActiveInventoryTab('proteins')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeInventoryTab === 'proteins' ? '#ffffff' : 'transparent',
                                            borderBottom: activeInventoryTab === 'proteins' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeInventoryTab === 'proteins' ? 'bold' : 'normal',
                                            border: activeInventoryTab === 'proteins' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeInventoryTab === 'proteins' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Proteins
                                    </div>
                                    <div
                                        onClick={() => setActiveInventoryTab('resources')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeInventoryTab === 'resources' ? '#ffffff' : 'transparent',
                                            borderBottom: activeInventoryTab === 'resources' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeInventoryTab === 'resources' ? 'bold' : 'normal',
                                            border: activeInventoryTab === 'resources' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeInventoryTab === 'resources' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Resources
                                    </div>
                                    <div
                                        onClick={() => setActiveInventoryTab('strains')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeInventoryTab === 'strains' ? '#ffffff' : 'transparent',
                                            borderBottom: activeInventoryTab === 'strains' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeInventoryTab === 'strains' ? 'bold' : 'normal',
                                            border: activeInventoryTab === 'strains' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeInventoryTab === 'strains' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Strains
                                    </div>
                                </div>

                                {/* Inventory Sub-tab Content */}
                                <div style={{ backgroundColor: '#ffffff', padding: '20px', border: '1px solid #dee2e6', borderRadius: '0 0 4px 4px' }}>
                                    {activeInventoryTab === 'assets' && (
                                        <div>
                                            <h3>Assets Management</h3>

                                            {/* Assets Sub-tabs */}
                                            <div style={{
                                                display: 'flex',
                                                borderBottom: '1px solid #dee2e6',
                                                marginBottom: '20px',
                                                backgroundColor: '#f8f9fa'
                                            }}>
                                                <div
                                                    onClick={() => setActiveAssetsTab('equipment')}
                                                    style={{
                                                        padding: '8px 16px',
                                                        cursor: 'pointer',
                                                        backgroundColor: activeAssetsTab === 'equipment' ? '#ffffff' : 'transparent',
                                                        borderBottom: activeAssetsTab === 'equipment' ? '2px solid #007bff' : 'none',
                                                        fontWeight: activeAssetsTab === 'equipment' ? 'bold' : 'normal',
                                                        border: activeAssetsTab === 'equipment' ? '1px solid #dee2e6' : 'none',
                                                        borderBottom: activeAssetsTab === 'equipment' ? 'none' : '1px solid #dee2e6'
                                                    }}
                                                >
                                                    Equipment
                                                </div>
                                                <div
                                                    onClick={() => setActiveAssetsTab('it')}
                                                    style={{
                                                        padding: '8px 16px',
                                                        cursor: 'pointer',
                                                        backgroundColor: activeAssetsTab === 'it' ? '#ffffff' : 'transparent',
                                                        borderBottom: activeAssetsTab === 'it' ? '2px solid #007bff' : 'none',
                                                        fontWeight: activeAssetsTab === 'it' ? 'bold' : 'normal',
                                                        border: activeAssetsTab === 'it' ? '1px solid #dee2e6' : 'none',
                                                        borderBottom: activeAssetsTab === 'it' ? 'none' : '1px solid #dee2e6'
                                                    }}
                                                >
                                                    IT
                                                </div>
                                                <div
                                                    onClick={() => setActiveAssetsTab('tools')}
                                                    style={{
                                                        padding: '8px 16px',
                                                        cursor: 'pointer',
                                                        backgroundColor: activeAssetsTab === 'tools' ? '#ffffff' : 'transparent',
                                                        borderBottom: activeAssetsTab === 'tools' ? '2px solid #007bff' : 'none',
                                                        fontWeight: activeAssetsTab === 'tools' ? 'bold' : 'normal',
                                                        border: activeAssetsTab === 'tools' ? '1px solid #dee2e6' : 'none',
                                                        borderBottom: activeAssetsTab === 'tools' ? 'none' : '1px solid #dee2e6'
                                                    }}
                                                >
                                                    Tools
                                                </div>
                                            </div>

                                            {/* Assets Sub-tab Content */}
                                            <div>
                                                {activeAssetsTab === 'equipment' && (
                                                    <EquipmentTab
                                                        equipment={equipment}
                                                        facilities={facilities}
                                                        userData={userData}
                                                        onEquipmentUpdate={handleEquipmentUpdate}
                                                    />
                                                )}

                                                {activeAssetsTab === 'tools' && (
                                                    <ToolsTab userData={userData} />
                                                )}

                                                {activeAssetsTab === 'it' && (
                                                    <ITTab userData={userData} />
                                                )}
                                            </div>
                                        </div>
                                    )}

                                    {activeInventoryTab === 'chemicals' && (
                                        <ChemicalsTab userData={userData} />
                                    )}

                                    {activeInventoryTab === 'consumables' && (
                                        <ConsumablesTab userData={userData} />
                                    )}

                                    {activeInventoryTab === 'ligands' && (
                                        <LigandsTab userData={userData} />
                                    )}

                                    {activeInventoryTab === 'plasmids' && (
                                        <PlasmidsTab userData={userData} />
                                    )}

                                    {activeInventoryTab === 'proteins' && (
                                        <ProteinsTab userData={userData} />
                                    )}

                                    {activeInventoryTab === 'resources' && (
                                        <ResourcesTab userData={userData} />
                                    )}

                                    {activeInventoryTab === 'strains' && (
                                        <StrainsTab userData={userData} />
                                    )}
                                </div>
                            </div>
                        )}

                        {!loading && !error && activeTab === 'finance' && (
                            <div>
                                <h2>Finance & Billing</h2>

                                {/* Finance Sub-tabs */}
                                <div style={{
                                    display: 'flex',
                                    borderBottom: '1px solid #dee2e6',
                                    marginBottom: '20px',
                                    backgroundColor: '#f8f9fa'
                                }}>
                                    <div
                                        onClick={() => setActiveFinanceTab('commercial')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeFinanceTab === 'commercial' ? '#ffffff' : 'transparent',
                                            borderBottom: activeFinanceTab === 'commercial' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeFinanceTab === 'commercial' ? 'bold' : 'normal',
                                            border: activeFinanceTab === 'commercial' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeFinanceTab === 'commercial' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Commercial Contracts
                                    </div>
                                    <div
                                        onClick={() => setActiveFinanceTab('grants')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeFinanceTab === 'grants' ? '#ffffff' : 'transparent',
                                            borderBottom: activeFinanceTab === 'grants' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeFinanceTab === 'grants' ? 'bold' : 'normal',
                                            border: activeFinanceTab === 'grants' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeFinanceTab === 'grants' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Costing Grants
                                    </div>
                                    <div
                                        onClick={() => setActiveFinanceTab('costing-model')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeFinanceTab === 'costing-model' ? '#ffffff' : 'transparent',
                                            borderBottom: activeFinanceTab === 'costing-model' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeFinanceTab === 'costing-model' ? 'bold' : 'normal',
                                            border: activeFinanceTab === 'costing-model' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeFinanceTab === 'costing-model' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Costing Model
                                    </div>
                                    <div
                                        onClick={() => setActiveFinanceTab('invoicing')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeFinanceTab === 'invoicing' ? '#ffffff' : 'transparent',
                                            borderBottom: activeFinanceTab === 'invoicing' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeFinanceTab === 'invoicing' ? 'bold' : 'normal',
                                            border: activeFinanceTab === 'invoicing' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeFinanceTab === 'invoicing' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Invoicing
                                    </div>
                                    <div
                                        onClick={() => setActiveFinanceTab('spending')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeFinanceTab === 'spending' ? '#ffffff' : 'transparent',
                                            borderBottom: activeFinanceTab === 'spending' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeFinanceTab === 'spending' ? 'bold' : 'normal',
                                            border: activeFinanceTab === 'spending' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeFinanceTab === 'spending' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Spending
                                    </div>
                                </div>

                                {/* Finance Sub-tab Content */}
                                <div style={{ backgroundColor: '#ffffff', padding: '20px', border: '1px solid #dee2e6', borderRadius: '0 0 4px 4px' }}>
                                    {activeFinanceTab === 'commercial' && (
                                        <CommercialTab userData={userData} />
                                    )}

                                    {activeFinanceTab === 'grants' && (
                                        <GrantsTab userData={userData} />
                                    )}

                                    {activeFinanceTab === 'costing-model' && (
                                        <CostingModelTab userData={userData} />
                                    )}

                                    {activeFinanceTab === 'invoicing' && (
                                        <InvoicingTab userData={userData} />
                                    )}

                                    {activeFinanceTab === 'spending' && (
                                        <SpendingTab userData={userData} />
                                    )}
                                </div>
                            </div>
                        )}

                        {!loading && !error && activeTab === 'compliance' && (
                            <div>
                                <h2>Compliance Management</h2>

                                {/* Compliance Sub-tabs */}
                                <div style={{
                                    display: 'flex',
                                    borderBottom: '1px solid #dee2e6',
                                    marginBottom: '20px',
                                    backgroundColor: '#f8f9fa',
                                    flexWrap: 'wrap'
                                }}>
                                    <div
                                        onClick={() => setActiveComplianceTab('emergency-procedures')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeComplianceTab === 'emergency-procedures' ? '#ffffff' : 'transparent',
                                            borderBottom: activeComplianceTab === 'emergency-procedures' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeComplianceTab === 'emergency-procedures' ? 'bold' : 'normal',
                                            border: activeComplianceTab === 'emergency-procedures' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeComplianceTab === 'emergency-procedures' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Emergency Procedures
                                    </div>
                                    <div
                                        onClick={() => setActiveComplianceTab('incident-reports')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeComplianceTab === 'incident-reports' ? '#ffffff' : 'transparent',
                                            borderBottom: activeComplianceTab === 'incident-reports' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeComplianceTab === 'incident-reports' ? 'bold' : 'normal',
                                            border: activeComplianceTab === 'incident-reports' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeComplianceTab === 'incident-reports' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Incident Reports
                                    </div>
                                    <div
                                        onClick={() => setActiveComplianceTab('local-rules')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeComplianceTab === 'local-rules' ? '#ffffff' : 'transparent',
                                            borderBottom: activeComplianceTab === 'local-rules' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeComplianceTab === 'local-rules' ? 'bold' : 'normal',
                                            border: activeComplianceTab === 'local-rules' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeComplianceTab === 'local-rules' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Local Rules
                                    </div>
                                    <div
                                        onClick={() => setActiveComplianceTab('msds')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeComplianceTab === 'msds' ? '#ffffff' : 'transparent',
                                            borderBottom: activeComplianceTab === 'msds' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeComplianceTab === 'msds' ? 'bold' : 'normal',
                                            border: activeComplianceTab === 'msds' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeComplianceTab === 'msds' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        MSDS
                                    </div>
                                    <div
                                        onClick={() => setActiveComplianceTab('risk-assessments')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeComplianceTab === 'risk-assessments' ? '#ffffff' : 'transparent',
                                            borderBottom: activeComplianceTab === 'risk-assessments' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeComplianceTab === 'risk-assessments' ? 'bold' : 'normal',
                                            border: activeComplianceTab === 'risk-assessments' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeComplianceTab === 'risk-assessments' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Risk Assessments
                                    </div>
                                    <div
                                        onClick={() => setActiveComplianceTab('safety-inspection-reports')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeComplianceTab === 'safety-inspection-reports' ? '#ffffff' : 'transparent',
                                            borderBottom: activeComplianceTab === 'safety-inspection-reports' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeComplianceTab === 'safety-inspection-reports' ? 'bold' : 'normal',
                                            border: activeComplianceTab === 'safety-inspection-reports' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeComplianceTab === 'safety-inspection-reports' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Safety Inspection Reports
                                    </div>
                                    <div
                                        onClick={() => setActiveComplianceTab('sop')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeComplianceTab === 'sop' ? '#ffffff' : 'transparent',
                                            borderBottom: activeComplianceTab === 'sop' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeComplianceTab === 'sop' ? 'bold' : 'normal',
                                            border: activeComplianceTab === 'sop' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeComplianceTab === 'sop' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        SOP
                                    </div>
                                    <div
                                        onClick={() => setActiveComplianceTab('training')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeComplianceTab === 'training' ? '#ffffff' : 'transparent',
                                            borderBottom: activeComplianceTab === 'training' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeComplianceTab === 'training' ? 'bold' : 'normal',
                                            border: activeComplianceTab === 'training' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeComplianceTab === 'training' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Training
                                    </div>
                                    <div
                                        onClick={() => setActiveComplianceTab('waste-disposal-procedures')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeComplianceTab === 'waste-disposal-procedures' ? '#ffffff' : 'transparent',
                                            borderBottom: activeComplianceTab === 'waste-disposal-procedures' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeComplianceTab === 'waste-disposal-procedures' ? 'bold' : 'normal',
                                            border: activeComplianceTab === 'waste-disposal-procedures' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeComplianceTab === 'waste-disposal-procedures' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Waste Disposal Procedures
                                    </div>
                                </div>

                                {/* Compliance Sub-tab Content */}
                                <div>
                                    {activeComplianceTab === 'training' && (
                                        <TrainingPage userData={userData} />
                                    )}

                                    {activeComplianceTab === 'sop' && (
                                        <div>
                                            <h3>Standard Operating Procedures (SOP)</h3>
                                            <p>SOP management functionality coming soon...</p>
                                            <div style={{
                                                backgroundColor: '#f3e5f5',
                                                padding: '15px',
                                                borderRadius: '4px',
                                                border: '1px solid #e1bee7'
                                            }}>
                                                <h4>Features to be implemented:</h4>
                                                <ul>
                                                    <li>SOP document management</li>
                                                    <li>Version control</li>
                                                    <li>Equipment-specific procedures</li>
                                                    <li>Training material integration</li>
                                                    <li>Approval workflows</li>
                                                    <li>Document distribution and access control</li>
                                                    <li>Compliance tracking and reporting</li>
                                                    <li>Digital signatures and attestation</li>
                                                </ul>
                                            </div>
                                        </div>
                                    )}

                                    {activeComplianceTab === 'risk-assessments' && (
                                        <RiskAssessments userData={userData} />
                                    )}

                                    {activeComplianceTab === 'msds' && (
                                        <MSDS userData={userData} />
                                    )}

                                    {activeComplianceTab === 'incident-reports' && (
                                        <IncidentReports userData={userData} />
                                    )}

                                    {activeComplianceTab === 'safety-inspection-reports' && (
                                        <SafetyInspectionReports userData={userData} />
                                    )}

                                    {activeComplianceTab === 'emergency-procedures' && (
                                        <EmergencyProcedures userData={userData} />
                                    )}

                                    {activeComplianceTab === 'local-rules' && (
                                        <LocalRules userData={userData} />
                                    )}

                                    {activeComplianceTab === 'waste-disposal-procedures' && (
                                        <WasteDisposalProcedures userData={userData} />
                                    )}
                                </div>
                            </div>
                        )}

                        {!loading && !error && activeTab === 'support' && (
                            <div>
                                <h2>Support Center</h2>

                                {/* Support Sub-tabs */}
                                <div style={{
                                    display: 'flex',
                                    borderBottom: '1px solid #dee2e6',
                                    marginBottom: '20px',
                                    backgroundColor: '#f8f9fa'
                                }}>
                                    <div
                                        onClick={() => setActiveSupportTab('feedback')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeSupportTab === 'feedback' ? '#ffffff' : 'transparent',
                                            borderBottom: activeSupportTab === 'feedback' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeSupportTab === 'feedback' ? 'bold' : 'normal',
                                            border: activeSupportTab === 'feedback' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeSupportTab === 'feedback' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Feedback
                                    </div>
                                    <div
                                        onClick={() => setActiveSupportTab('reports-stats')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeSupportTab === 'reports-stats' ? '#ffffff' : 'transparent',
                                            borderBottom: activeSupportTab === 'reports-stats' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeSupportTab === 'reports-stats' ? 'bold' : 'normal',
                                            border: activeSupportTab === 'reports-stats' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeSupportTab === 'reports-stats' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Reports & Stats
                                    </div>
                                    <div
                                        onClick={() => setActiveSupportTab('tickets')}
                                        style={{
                                            padding: '10px 20px',
                                            cursor: 'pointer',
                                            backgroundColor: activeSupportTab === 'tickets' ? '#ffffff' : 'transparent',
                                            borderBottom: activeSupportTab === 'tickets' ? '2px solid #007bff' : 'none',
                                            fontWeight: activeSupportTab === 'tickets' ? 'bold' : 'normal',
                                            border: activeSupportTab === 'tickets' ? '1px solid #dee2e6' : 'none',
                                            borderBottom: activeSupportTab === 'tickets' ? 'none' : '1px solid #dee2e6'
                                        }}
                                    >
                                        Tickets
                                    </div>
                                </div>

                                {/* Support Sub-tab Content */}
                                <div style={{ backgroundColor: '#ffffff', padding: '20px', border: '1px solid #dee2e6', borderRadius: '0 0 4px 4px' }}>
                                    {activeSupportTab === 'tickets' && (
                                        <Tickets userData={userData} />
                                    )}

                                    {activeSupportTab === 'feedback' && (
                                        <Feedback userData={userData} />
                                    )}

                                    {activeSupportTab === 'reports-stats' && (
                                        <ReportsStats userData={userData} />
                                    )}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Dashboard;
