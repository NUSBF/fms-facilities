// NetworkScanUtils.js - Utility functions for network scan popup windows

import { 
    generateInlineStyledHTML, 
    generateParsingFailedHTML, 
    generateRawOutputHTML 
} from './NetworkScanInlineGenerator';

/**
 * Creates and displays a network scan result popup with export functionality
 * @param {string} result - The raw result from the network scan API
 * @param {Function} setScanStatus - Function to update scan status in parent component
 */
export const displayNetworkScanResults = (result, setScanStatus) => {
    console.log('=== displayNetworkScanResults called ===');
    console.log('Result:', result);
    console.log('Type of result:', typeof result);
    
    try {
        // Try to extract JSON from the output
        const jsonMatch = result.match(/\{[\s\S]*\}/);
        console.log('JSON match found:', !!jsonMatch);
        
        if (jsonMatch) {
            console.log('Found JSON, trying to parse...');
            try {
                const jsonData = JSON.parse(jsonMatch[0]);
                console.log('JSON parsed successfully:', jsonData);
                
                // Save scan results to database
                saveNetworkScanResults(jsonData, result);
                
                // Try blob URL approach first, fallback to document.write
                createSuccessfulScanWindowAlt(result, jsonData, setScanStatus);
            } catch (parseError) {
                console.log('JSON parse failed:', parseError);
                createParsingFailedWindow(result, setScanStatus);
            }
        } else {
            console.log('No JSON found, showing raw output');
            createRawOutputWindow(result, setScanStatus);
        }
    } catch (error) {
        console.log('Main function error:', error);
        // Simple fallback
        alert(`Network scan completed.\n\nRaw result:\n${result?.substring(0, 500) || 'No result data'}${(result?.length || 0) > 500 ? '...' : ''}`);
        setScanStatus({ 
            type: 'info', 
            message: 'Network scan completed - results shown in alert.' 
        });
    }
};

/**
 * Creates the popup window for successful JSON parsing
 */
const createSuccessfulScanWindow = (result, jsonData, setScanStatus) => {
    try {
        console.log('=== createSuccessfulScanWindow called ===');
        console.log('Attempting to open popup window...');
        
        const outputWindow = window.open('', '_blank', 'width=1200,height=800,scrollbars=yes,resizable=yes');
        console.log('window.open returned:', outputWindow);
        console.log('outputWindow type:', typeof outputWindow);
        console.log('outputWindow is null?', outputWindow === null);
        console.log('outputWindow is undefined?', outputWindow === undefined);
        
        if (!outputWindow) {
            console.log('Popup blocked or failed to open');
            throw new Error('popup_blocked');
        }
        
        console.log('Popup window opened successfully');
        console.log('outputWindow.document:', outputWindow.document);
        
        const htmlContent = generateInlineStyledHTML(result, jsonData);
        
        console.log('Writing content to popup...');
        outputWindow.document.write(htmlContent);
        outputWindow.document.close();
        console.log('Content written and document closed');
        
        // Give it a moment then check if content loaded
        setTimeout(() => {
            console.log('Checking popup after 500ms...');
            console.log('outputWindow.document.body:', outputWindow.document.body);
            console.log('outputWindow.document.body.innerHTML length:', outputWindow.document.body?.innerHTML?.length || 'N/A');
        }, 500);
        
        setScanStatus({ 
            type: 'success', 
            message: `Network scan completed. Found ${jsonData.dhcp_fixed_ips?.length || 0} DHCP reservations and ${jsonData.nfs_exports?.length || 0} NFS exports.` 
        });
    } catch (error) {
        console.log('createSuccessfulScanWindow error:', error);
        // Clean fallback alert
        const summary = `Network Scan Results
========================
DHCP reservations: ${jsonData.dhcp_fixed_ips?.length || 0}
NFS exports: ${jsonData.nfs_exports?.length || 0}

Raw output (first 500 chars):
${result.substring(0, 500)}${result.length > 500 ? '...' : ''}`;
        
        alert(summary);
        setScanStatus({ 
            type: 'success', 
            message: `Network scan completed. Found ${jsonData.dhcp_fixed_ips?.length || 0} DHCP reservations and ${jsonData.nfs_exports?.length || 0} NFS exports.` 
        });
    }
};

/**
 * Alternative popup implementation using Blob URL (more secure)
 */
const createSuccessfulScanWindowAlt = (result, jsonData, setScanStatus) => {
    try {
        console.log('=== createSuccessfulScanWindowAlt called ===');
        
        const htmlContent = generateInlineStyledHTML(result, jsonData);
        
        // Create a blob with the HTML content
        const blob = new Blob([htmlContent], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        console.log('Created blob URL:', url);
        
        // Open the blob URL in a new window
        const outputWindow = window.open(url, '_blank', 'width=1200,height=800,scrollbars=yes,resizable=yes');
        console.log('window.open with blob URL returned:', outputWindow);
        
        if (!outputWindow) {
            console.log('Popup with blob URL blocked or failed, trying in-page modal');
            URL.revokeObjectURL(url); // Clean up
            
            // Try in-page modal as fallback
            const modalSuccess = createInPageModal(result, jsonData, setScanStatus);
            if (modalSuccess) {
                return; // Modal created successfully
            }
            
            throw new Error('popup_blocked');
        }
        
        // Clean up the blob URL after a delay (window should have loaded by then)
        setTimeout(() => {
            console.log('Revoking blob URL');
            URL.revokeObjectURL(url);
        }, 5000);
        
        setScanStatus({ 
            type: 'success', 
            message: `Network scan completed. Found ${jsonData.dhcp_fixed_ips?.length || 0} DHCP reservations and ${jsonData.nfs_exports?.length || 0} NFS exports.` 
        });
    } catch (error) {
        console.log('createSuccessfulScanWindowAlt error:', error);
        // Try in-page modal as fallback
        const modalSuccess = createInPageModal(result, jsonData, setScanStatus);
        if (!modalSuccess) {
            // Final fallback to original method with debugging
            createSuccessfulScanWindow(result, jsonData, setScanStatus);
        }
    }
};

/**
 * Creates the popup window when JSON parsing fails
 */
const createParsingFailedWindow = (result, setScanStatus) => {
    try {
        const outputWindow = window.open('', '_blank', 'width=1200,height=800,scrollbars=yes,resizable=yes');
        
        if (!outputWindow) {
            throw new Error('popup_blocked');
        }
        
        const htmlContent = generateParsingFailedHTML(result);
        outputWindow.document.write(htmlContent);
        outputWindow.document.close();
        
        setScanStatus({ 
            type: 'warning', 
            message: 'Network scan completed but JSON parsing failed. Raw output displayed.' 
        });
    } catch (error) {
        const summary = `Network Scan Results (JSON Parsing Failed)
===================================================
Raw output (first 500 chars):
${result.substring(0, 500)}${result.length > 500 ? '...' : ''}`;
        
        alert(summary);
        setScanStatus({ 
            type: 'warning', 
            message: 'Network scan completed but JSON parsing failed.' 
        });
    }
};

/**
 * Creates the popup window for raw output (no JSON found)
 */
const createRawOutputWindow = (result, setScanStatus) => {
    try {
        const outputWindow = window.open('', '_blank', 'width=1200,height=800,scrollbars=yes,resizable=yes');
        
        if (!outputWindow) {
            throw new Error('popup_blocked');
        }
        
        const htmlContent = generateRawOutputHTML(result);
        outputWindow.document.write(htmlContent);
        outputWindow.document.close();
        
        setScanStatus({ 
            type: 'info', 
            message: 'Network scan completed. Raw output displayed.' 
        });
    } catch (error) {
        const summary = `Network Scan Results (Raw Output)
=====================================
Output (first 500 chars):
${result.substring(0, 500)}${result.length > 500 ? '...' : ''}`;
        
        alert(summary);
        setScanStatus({ 
            type: 'info', 
            message: 'Network scan completed.' 
        });
    }
};

/**
 * Creates an in-page modal instead of a popup (most reliable)
 */
const createInPageModal = (result, jsonData, setScanStatus) => {
    try {
        console.log('=== createInPageModal called ===');
        
        // Remove any existing modal
        const existingModal = document.getElementById('network-scan-modal');
        if (existingModal) {
            existingModal.remove();
        }
        
        // Create modal HTML
        const htmlContent = generateInlineStyledHTML(result, jsonData);
        
        // Extract just the body content and script content
        const bodyMatch = htmlContent.match(/<body[^>]*>([\s\S]*)<\/body>/);
        const bodyContent = bodyMatch ? bodyMatch[1] : htmlContent;
        
        // Extract script content for export functionality
        const scriptMatch = htmlContent.match(/<script[^>]*>([\s\S]*?)<\/script>/);
        const scriptContent = scriptMatch ? scriptMatch[1] : '';
        
        // Create modal wrapper
        const modalHTML = `
            <div id="network-scan-modal" style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.8);
                z-index: 10000;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                box-sizing: border-box;
            ">
                <div style="
                    background: white;
                    border-radius: 8px;
                    width: 100%;
                    max-width: 1200px;
                    max-height: 90vh;
                    overflow-y: auto;
                    position: relative;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                ">
                    <div style="
                        position: sticky;
                        top: 0;
                        background: white;
                        border-radius: 8px 8px 0 0;
                        padding: 10px 20px;
                        border-bottom: 1px solid #dee2e6;
                        display: flex;
                        justify-content: flex-end;
                        z-index: 10001;
                    ">
                        <button onclick="document.getElementById('network-scan-modal').remove()" style="
                            background: #dc3545;
                            color: white;
                            border: none;
                            border-radius: 4px;
                            padding: 8px 12px;
                            cursor: pointer;
                            font-size: 14px;
                            font-weight: bold;
                        ">✕ Close</button>
                    </div>
                    <div id="modal-content" style="padding: 0;">
                        ${bodyContent}
                    </div>
                </div>
            </div>
        `;
        
        // Insert modal into the page
        document.body.insertAdjacentHTML('beforeend', modalHTML);
        
        // Add export functionality if script content was found
        if (scriptContent) {
            try {
                // Create a script element and execute it
                const script = document.createElement('script');
                // Modify the script to work within the modal context
                const modifiedScript = scriptContent.replace(
                    /document\.documentElement\.outerHTML/g, 
                    'document.getElementById("modal-content").innerHTML'
                ).replace(
                    /document\.querySelector\('\.container'\)/g,
                    'document.getElementById("modal-content")'
                );
                script.innerHTML = modifiedScript;
                document.head.appendChild(script);
                console.log('Export scripts added to modal');
            } catch (scriptError) {
                console.log('Error adding export scripts:', scriptError);
            }
        }
        
        console.log('In-page modal created successfully');
        
        setScanStatus({ 
            type: 'success', 
            message: `Network scan completed. Found ${jsonData.dhcp_fixed_ips?.length || 0} DHCP reservations and ${jsonData.nfs_exports?.length || 0} NFS exports.` 
        });
        
        return true; // Success
    } catch (error) {
        console.log('createInPageModal error:', error);
        return false; // Failed
    }
};

/**
 * Saves network scan results to the database
 * @param {Object} jsonData - The parsed JSON data from the network scan
 * @param {string} rawResult - The raw output from the scan
 */
const saveNetworkScanResults = async (jsonData, rawResult) => {
    try {
        console.log('=== Saving network scan results to database ===');
        
        // Extract unique IPs and their details
        const uniqueIPs = [];
        const processedIPs = new Set();
        
        // Process DHCP IPs
        if (jsonData.dhcp_fixed_ips) {
            jsonData.dhcp_fixed_ips.forEach(item => {
                if (item.ip_address && !processedIPs.has(item.ip_address)) {
                    processedIPs.add(item.ip_address);
                    uniqueIPs.push({
                        ip_address: item.ip_address,
                        hostname: item.hostname || null,
                        source: 'DHCP',
                        status: 'unknown'
                    });
                }
            });
        }
        
        // Process NFS IPs
        if (jsonData.nfs_exports) {
            jsonData.nfs_exports.forEach(item => {
                if (item.client) {
                    const client = item.client.trim();
                    // Only process valid IP addresses
                    if (client.match(/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]+)?$/)) {
                        const ipMatch = client.match(/^([0-9]{1,3}\.){3}[0-9]{1,3}/);
                        if (ipMatch && !processedIPs.has(ipMatch[0])) {
                            processedIPs.add(ipMatch[0]);
                            
                            // Extract hostname and status from resolved_hostname
                            let hostname = null;
                            let status = 'unknown';
                            
                            if (item.resolved_hostname) {
                                hostname = item.resolved_hostname.replace(/ \((online|offline|unknown)\)/, '');
                                if (item.resolved_hostname.includes('(online)')) {
                                    status = 'online';
                                } else if (item.resolved_hostname.includes('(offline)')) {
                                    status = 'offline';
                                }
                                
                                // Don't save if hostname is just the IP or generic values
                                if (hostname === ipMatch[0] || hostname === 'Unknown' || hostname === 'N/A') {
                                    hostname = null;
                                }
                            }
                            
                            uniqueIPs.push({
                                ip_address: ipMatch[0],
                                hostname: hostname,
                                source: 'NFS',
                                status: status
                            });
                        }
                    }
                }
            });
        }
        
        console.log('Unique IPs to save:', uniqueIPs);
        
        // Prepare the data for the API
        const scanData = {
            scan_timestamp: jsonData.scan_timestamp || new Date().toISOString(),
            dhcp_count: jsonData.dhcp_fixed_ips?.length || 0,
            nfs_count: jsonData.nfs_exports?.length || 0,
            unique_ips: uniqueIPs,
            raw_output: rawResult.substring(0, 10000) // Limit raw output size
        };
        
        // Get auth token from localStorage (matching other components)
        const token = localStorage.getItem('token');
        console.log('Auth token found:', !!token);
        
        // Send to backend API
        const headers = {
            'Content-Type': 'application/json'
        };
        
        // Add auth header if token exists
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        
        const response = await fetch('/fms-api/network-scan-results', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(scanData)
        });
        
        if (response.ok) {
            const result = await response.json();
            console.log('Network scan results saved successfully:', result);
        } else {
            const error = await response.text();
            console.error('Failed to save network scan results:', error);
        }
        
    } catch (error) {
        console.error('Error saving network scan results:', error);
    }
};
