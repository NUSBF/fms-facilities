import React, { useState } from 'react';

function ReportsStats({ userData }) {
    const [selectedPeriod, setSelectedPeriod] = useState('thisMonth');
    const [selectedMetric, setSelectedMetric] = useState('bookings');

    // Mock data for demonstration
    const statsData = {
        bookings: {
            thisMonth: { total: 156, trend: '+12%' },
            lastMonth: { total: 139, trend: '+8%' },
            thisYear: { total: 1847, trend: '+23%' }
        },
        equipment: {
            thisMonth: { total: 42, trend: '+3%' },
            lastMonth: { total: 41, trend: '+2%' },
            thisYear: { total: 42, trend: '+5%' }
        },
        users: {
            thisMonth: { total: 89, trend: '+7%' },
            lastMonth: { total: 83, trend: '+4%' },
            thisYear: { total: 89, trend: '+15%' }
        },
        incidents: {
            thisMonth: { total: 3, trend: '-25%' },
            lastMonth: { total: 4, trend: '-20%' },
            thisYear: { total: 28, trend: '-12%' }
        }
    };

    const getCurrentStats = () => {
        return statsData[selectedMetric]?.[selectedPeriod] || { total: 0, trend: '0%' };
    };

    return (
        <div style={{ padding: '20px' }}>
            <h2 style={{ marginBottom: '20px', color: '#333' }}>Reports & Statistics</h2>
            
            {/* Control Panel */}
            <div style={{ 
                display: 'flex', 
                gap: '20px', 
                marginBottom: '30px',
                padding: '20px',
                backgroundColor: '#f8f9fa',
                borderRadius: '8px',
                border: '1px solid #ddd'
            }}>
                <div>
                    <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                        Time Period:
                    </label>
                    <select 
                        value={selectedPeriod}
                        onChange={(e) => setSelectedPeriod(e.target.value)}
                        style={{ 
                            padding: '8px', 
                            border: '1px solid #ddd', 
                            borderRadius: '4px',
                            fontSize: '14px'
                        }}
                    >
                        <option value="thisMonth">This Month</option>
                        <option value="lastMonth">Last Month</option>
                        <option value="thisYear">This Year</option>
                    </select>
                </div>
                
                <div>
                    <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                        Metric:
                    </label>
                    <select 
                        value={selectedMetric}
                        onChange={(e) => setSelectedMetric(e.target.value)}
                        style={{ 
                            padding: '8px', 
                            border: '1px solid #ddd', 
                            borderRadius: '4px',
                            fontSize: '14px'
                        }}
                    >
                        <option value="bookings">Equipment Bookings</option>
                        <option value="equipment">Equipment Usage</option>
                        <option value="users">Active Users</option>
                        <option value="incidents">Safety Incidents</option>
                    </select>
                </div>
            </div>

            {/* Stats Cards */}
            <div style={{ 
                display: 'grid', 
                gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                gap: '20px',
                marginBottom: '30px'
            }}>
                <div style={{
                    padding: '20px',
                    backgroundColor: 'white',
                    border: '1px solid #ddd',
                    borderRadius: '8px',
                    textAlign: 'center',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                }}>
                    <h3 style={{ color: '#007bff', marginBottom: '10px' }}>Total {selectedMetric.charAt(0).toUpperCase() + selectedMetric.slice(1)}</h3>
                    <div style={{ fontSize: '2.5em', fontWeight: 'bold', color: '#333' }}>
                        {getCurrentStats().total}
                    </div>
                    <div style={{ 
                        color: getCurrentStats().trend.startsWith('+') ? '#28a745' : '#dc3545',
                        fontWeight: 'bold',
                        marginTop: '10px'
                    }}>
                        {getCurrentStats().trend} vs previous period
                    </div>
                </div>

                <div style={{
                    padding: '20px',
                    backgroundColor: 'white',
                    border: '1px solid #ddd',
                    borderRadius: '8px',
                    textAlign: 'center',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                }}>
                    <h3 style={{ color: '#28a745', marginBottom: '10px' }}>Utilization Rate</h3>
                    <div style={{ fontSize: '2.5em', fontWeight: 'bold', color: '#333' }}>
                        73%
                    </div>
                    <div style={{ color: '#28a745', fontWeight: 'bold', marginTop: '10px' }}>
                        +5% vs previous period
                    </div>
                </div>

                <div style={{
                    padding: '20px',
                    backgroundColor: 'white',
                    border: '1px solid #ddd',
                    borderRadius: '8px',
                    textAlign: 'center',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                }}>
                    <h3 style={{ color: '#ffc107', marginBottom: '10px' }}>Peak Hours</h3>
                    <div style={{ fontSize: '2.5em', fontWeight: 'bold', color: '#333' }}>
                        10-14
                    </div>
                    <div style={{ color: '#666', fontWeight: 'bold', marginTop: '10px' }}>
                        Most active period
                    </div>
                </div>
            </div>

            {/* Detailed Reports */}
            <div style={{ 
                backgroundColor: 'white',
                border: '1px solid #ddd',
                borderRadius: '8px',
                padding: '20px'
            }}>
                <h3 style={{ marginBottom: '20px', color: '#333' }}>Detailed Analytics</h3>
                
                <div style={{ 
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '30px'
                }}>
                    {/* Top Equipment */}
                    <div>
                        <h4 style={{ color: '#007bff', marginBottom: '15px' }}>Most Popular Equipment</h4>
                        <div style={{ fontSize: '14px' }}>
                            {[
                                { name: 'M2.020 High speed Centrifuge', bookings: 45 },
                                { name: 'M1077 Tissue Culture Hood', bookings: 38 },
                                { name: 'M2.016 Ultra Centrifuge', bookings: 32 },
                                { name: 'PCR Machine', bookings: 28 },
                                { name: 'Microscope Station', bookings: 25 }
                            ].map((item, index) => (
                                <div key={index} style={{ 
                                    display: 'flex', 
                                    justifyContent: 'space-between',
                                    padding: '8px 0',
                                    borderBottom: '1px solid #eee'
                                }}>
                                    <span>{item.name}</span>
                                    <span style={{ fontWeight: 'bold', color: '#007bff' }}>
                                        {item.bookings} bookings
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Usage by Time */}
                    <div>
                        <h4 style={{ color: '#28a745', marginBottom: '15px' }}>Usage by Time Slot</h4>
                        <div style={{ fontSize: '14px' }}>
                            {[
                                { time: '08:00 - 10:00', usage: 85 },
                                { time: '10:00 - 12:00', usage: 95 },
                                { time: '12:00 - 14:00', usage: 78 },
                                { time: '14:00 - 16:00', usage: 92 },
                                { time: '16:00 - 18:00', usage: 67 }
                            ].map((item, index) => (
                                <div key={index} style={{ 
                                    display: 'flex', 
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    padding: '8px 0',
                                    borderBottom: '1px solid #eee'
                                }}>
                                    <span>{item.time}</span>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                        <div style={{
                                            width: '100px',
                                            height: '8px',
                                            backgroundColor: '#e9ecef',
                                            borderRadius: '4px',
                                            overflow: 'hidden'
                                        }}>
                                            <div style={{
                                                width: `${item.usage}%`,
                                                height: '100%',
                                                backgroundColor: '#28a745',
                                                borderRadius: '4px'
                                            }}></div>
                                        </div>
                                        <span style={{ fontWeight: 'bold', color: '#28a745' }}>
                                            {item.usage}%
                                        </span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Export Options */}
                <div style={{ 
                    marginTop: '30px',
                    paddingTop: '20px',
                    borderTop: '1px solid #eee',
                    textAlign: 'center'
                }}>
                    <h4 style={{ marginBottom: '15px', color: '#333' }}>Export Reports</h4>
                    <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
                        <button style={{
                            padding: '10px 20px',
                            backgroundColor: '#007bff',
                            color: 'white',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '14px'
                        }}>
                            Export PDF
                        </button>
                        <button style={{
                            padding: '10px 20px',
                            backgroundColor: '#28a745',
                            color: 'white',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '14px'
                        }}>
                            Export Excel
                        </button>
                        <button style={{
                            padding: '10px 20px',
                            backgroundColor: '#17a2b8',
                            color: 'white',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '14px'
                        }}>
                            Schedule Report
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default ReportsStats;
