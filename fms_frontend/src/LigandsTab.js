import React, { useState } from 'react';

function LigandsTab({ userData }) {
    return (
        <div>
            <h3>Ligands Inventory</h3>
            <p>Ligand compounds and binding molecules management.</p>
            <div style={{ 
                backgroundColor: '#fce4ec', 
                padding: '15px', 
                borderRadius: '4px',
                border: '1px solid #f8bbd9'
            }}>
                <h4>Features to be implemented:</h4>
                <ul>
                    <li>Ligand structure and properties</li>
                    <li>Binding affinity data</li>
                    <li>Solubility and stability information</li>
                    <li>Storage condition requirements</li>
                    <li>Synthesis and source tracking</li>
                    <li>Biological activity profiles</li>
                    <li>Research application records</li>
                    <li>Chemical safety and handling protocols</li>
                </ul>
            </div>
        </div>
    );
}

export default LigandsTab;
