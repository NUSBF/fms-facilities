import React, { useState } from 'react';

function ConsumablesTab({ userData }) {
    return (
        <div>
            <h3>Consumables Inventory</h3>
            <p>Laboratory consumables and disposable items management.</p>
            <div style={{ 
                backgroundColor: '#fff3e0', 
                padding: '15px', 
                borderRadius: '4px',
                border: '1px solid #ffcc02'
            }}>
                <h4>Features to be implemented:</h4>
                <ul>
                    <li>Consumables stock tracking</li>
                    <li>Usage monitoring and analytics</li>
                    <li>Automated reorder thresholds</li>
                    <li>Supplier management</li>
                    <li>Cost tracking and budgeting</li>
                    <li>Quality control and batch tracking</li>
                    <li>Storage location mapping</li>
                    <li>Procurement workflow integration</li>
                </ul>
            </div>
        </div>
    );
}

export default ConsumablesTab;
