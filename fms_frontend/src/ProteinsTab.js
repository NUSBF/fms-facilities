import React, { useState } from 'react';

function ProteinsTab({ userData }) {
    return (
        <div>
            <h3>Proteins Inventory</h3>
            <p>Protein samples and reagents management.</p>
            <div style={{ 
                backgroundColor: '#e8f5e8', 
                padding: '15px', 
                borderRadius: '4px',
                border: '1px solid #c8e6c9'
            }}>
                <h4>Features to be implemented:</h4>
                <ul>
                    <li>Protein catalog and characterization</li>
                    <li>Purity and concentration tracking</li>
                    <li>Storage temperature monitoring</li>
                    <li>Stability and expiration management</li>
                    <li>Lot and batch information</li>
                    <li>Research application history</li>
                    <li>Quality control testing records</li>
                    <li>Collaboration and sharing protocols</li>
                </ul>
            </div>
        </div>
    );
}

export default ProteinsTab;
