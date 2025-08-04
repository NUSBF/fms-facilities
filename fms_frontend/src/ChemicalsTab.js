import React, { useState } from 'react';

function ChemicalsTab({ userData }) {
    return (
        <div>
            <h3>Chemicals Inventory</h3>
            <p>Chemical substances and reagents management.</p>
            <div style={{ 
                backgroundColor: '#e3f2fd', 
                padding: '15px', 
                borderRadius: '4px',
                border: '1px solid #bbdefb'
            }}>
                <h4>Features to be implemented:</h4>
                <ul>
                    <li>Chemical inventory tracking</li>
                    <li>Safety data sheet integration</li>
                    <li>Expiration date monitoring</li>
                    <li>Storage condition requirements</li>
                    <li>Usage tracking and consumption</li>
                    <li>Regulatory compliance monitoring</li>
                    <li>Automated reorder notifications</li>
                    <li>Waste disposal tracking</li>
                </ul>
            </div>
        </div>
    );
}

export default ChemicalsTab;
