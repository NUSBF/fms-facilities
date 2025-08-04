import React, { useState } from 'react';

function IncidentReports({ userData }) {
    return (
        <div>
            <h3>Incident Reports</h3>
            <p>Report, track, and manage safety incidents and near-miss events.</p>
            <div style={{ 
                backgroundColor: '#fce4ec', 
                padding: '15px', 
                borderRadius: '4px',
                border: '1px solid #f8bbd9'
            }}>
                <h4>Features to be implemented:</h4>
                <ul>
                    <li>Online incident reporting forms</li>
                    <li>Photo and document attachments</li>
                    <li>Witness statement collection</li>
                    <li>Incident classification and severity</li>
                    <li>Investigation workflow management</li>
                    <li>Corrective action tracking</li>
                    <li>Statistical analysis and reporting</li>
                    <li>Regulatory notification requirements</li>
                </ul>
            </div>
        </div>
    );
}

export default IncidentReports;
