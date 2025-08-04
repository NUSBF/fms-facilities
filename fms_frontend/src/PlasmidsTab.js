import React, { useState } from 'react';

function PlasmidsTab({ userData }) {
    return (
        <div>
            <h3>Plasmids Inventory</h3>
            <p>Plasmid vectors and DNA constructs management.</p>
            <div style={{ 
                backgroundColor: '#fff8e1', 
                padding: '15px', 
                borderRadius: '4px',
                border: '1px solid #ffecb3'
            }}>
                <h4>Features to be implemented:</h4>
                <ul>
                    <li>Plasmid maps and sequence information</li>
                    <li>Gene insert and vector details</li>
                    <li>Antibiotic resistance markers</li>
                    <li>Transformation and propagation protocols</li>
                    <li>Quality control and verification</li>
                    <li>Research project associations</li>
                    <li>Sharing and distribution tracking</li>
                    <li>Biosafety and regulatory compliance</li>
                </ul>
            </div>
        </div>
    );
}

export default PlasmidsTab;
