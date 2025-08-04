import React, { useState } from 'react';

function StrainsTab({ userData }) {
    return (
        <div>
            <h3>Strains Inventory</h3>
            <p>Biological strain collections and cultures management.</p>
            <div style={{ 
                backgroundColor: '#f3e5f5', 
                padding: '15px', 
                borderRadius: '4px',
                border: '1px solid #e1bee7'
            }}>
                <h4>Features to be implemented:</h4>
                <ul>
                    <li>Strain catalog and classification</li>
                    <li>Genetic information tracking</li>
                    <li>Storage condition monitoring</li>
                    <li>Passage history and genealogy</li>
                    <li>Contamination screening records</li>
                    <li>Research application tracking</li>
                    <li>Sharing and collaboration protocols</li>
                    <li>Regulatory compliance documentation</li>
                </ul>
            </div>
        </div>
    );
}

export default StrainsTab;
