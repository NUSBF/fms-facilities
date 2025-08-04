// NetworkScanInlineGenerator.js - Generates HTML with inline styles for popup windows

/**
 * Generates HTML with all inline styles for better popup compatibility
 */
export const generateInlineStyledHTML = (result, jsonData) => {
    const dhcpTable = generateInlineDHCPTable(jsonData.dhcp_fixed_ips);
    const nfsTable = generateInlineNFSTable(jsonData.nfs_exports);
    const uniqueIPsCount = getUniqueIPs(jsonData).length;
    
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Scan Results</title>
            <meta charset="UTF-8">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
            </style>
        </head>
        <body style="
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            line-height: 1.6;
        ">
            <div style="
                background: white;
                border-radius: 6px;
                border: 1px solid #dee2e6;
                max-width: 1200px;
                margin: 0 auto;
                overflow: hidden;
            ">
                <!-- Header -->
                <div style="
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 15px;
                    background-color: #f8f9fa;
                    border-bottom: 1px solid #dee2e6;
                    border-left: 4px solid #007bff;
                ">
                    <div>
                        <h1 style="
                            margin: 0;
                            font-size: 18px;
                            font-weight: 600;
                            color: #495057;
                        ">🌐 Network Configuration Scan Results</h1>
                        <p style="
                            margin: 5px 0 0 0;
                            font-size: 14px;
                            color: #6c757d;
                        ">Timestamp: ${jsonData.scan_timestamp || new Date().toISOString()}</p>
                    </div>
                    <div>
                        <button onclick="exportAsHTML()" style="
                            padding: 6px 12px;
                            font-size: 12px;
                            margin-left: 4px;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                            font-weight: 500;
                            background-color: #17a2b8;
                            color: white;
                        ">💾 Export HTML</button>
                        <button onclick="exportAsPDF()" style="
                            padding: 6px 12px;
                            font-size: 12px;
                            margin-left: 4px;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                            font-weight: 500;
                            background-color: #17a2b8;
                            color: white;
                        ">📄 Export PDF</button>
                    </div>
                </div>
                
                <!-- Summary Stats -->
                <div style="
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin: 20px;
                    padding: 15px;
                    background-color: #f8f9fa;
                    border-radius: 6px;
                    border-left: 4px solid #007bff;
                ">
                    <div style="
                        font-size: 18px;
                        font-weight: 600;
                        color: #495057;
                    ">Network Scan Summary</div>
                    <div style="display: flex; gap: 20px;">
                        <div style="text-align: center;">
                            <div style="
                                background-color: #007bff;
                                color: white;
                                padding: 4px 12px;
                                border-radius: 20px;
                                font-size: 14px;
                                font-weight: 500;
                            ">${jsonData.dhcp_fixed_ips?.length || 0}</div>
                            <div style="font-size: 12px; color: #6c757d; margin-top: 4px;">DHCP Fixed IPs</div>
                        </div>
                        <div style="text-align: center;">
                            <div style="
                                background-color: #007bff;
                                color: white;
                                padding: 4px 12px;
                                border-radius: 20px;
                                font-size: 14px;
                                font-weight: 500;
                            ">${jsonData.nfs_exports?.length || 0}</div>
                            <div style="font-size: 12px; color: #6c757d; margin-top: 4px;">NFS Exports</div>
                        </div>
                        <div style="text-align: center;">
                            <div style="
                                background-color: #007bff;
                                color: white;
                                padding: 4px 12px;
                                border-radius: 20px;
                                font-size: 14px;
                                font-weight: 500;
                            ">${uniqueIPsCount}</div>
                            <div style="font-size: 12px; color: #6c757d; margin-top: 4px;">Unique IPs</div>
                        </div>
                    </div>
                </div>
                
                <!-- Unique IPs Table Section -->
                <div style="margin: 20px; margin-bottom: 40px;">
                    <div style="
                        padding: 15px;
                        background-color: #f8f9fa;
                        border-radius: 6px;
                        border-left: 4px solid #28a745;
                        font-size: 18px;
                        font-weight: 600;
                        color: #495057;
                        margin-bottom: 20px;
                    ">🔍 Unique IP Addresses Found</div>
                    <div style="
                        overflow-x: auto;
                        border: 1px solid #dee2e6;
                        border-radius: 6px;
                    ">
                        ${generateUniqueIPsTable(jsonData)}
                    </div>
                </div>
                
                <!-- DHCP Section -->
                <div style="margin: 20px; margin-bottom: 40px;">
                    <div style="
                        padding: 15px;
                        background-color: #f8f9fa;
                        border-radius: 6px;
                        border-left: 4px solid #007bff;
                        font-size: 18px;
                        font-weight: 600;
                        color: #495057;
                        margin-bottom: 20px;
                    ">🖥️ DHCP Fixed IP Reservations</div>
                    <div style="
                        overflow-x: auto;
                        border: 1px solid #dee2e6;
                        border-radius: 6px;
                    ">
                        ${dhcpTable}
                    </div>
                </div>
                
                <!-- NFS Section -->
                <div style="margin: 20px; margin-bottom: 40px;">
                    <div style="
                        padding: 15px;
                        background-color: #f8f9fa;
                        border-radius: 6px;
                        border-left: 4px solid #007bff;
                        font-size: 18px;
                        font-weight: 600;
                        color: #495057;
                        margin-bottom: 20px;
                    ">📁 NFS Export Clients (with hostname resolution)</div>
                    <div style="
                        overflow-x: auto;
                        border: 1px solid #dee2e6;
                        border-radius: 6px;
                    ">
                        ${nfsTable}
                    </div>
                </div>
                
                <!-- Raw Output Section -->
                <div style="margin: 20px; margin-bottom: 40px;">
                    <div style="
                        padding: 15px;
                        background-color: #f8f9fa;
                        border-radius: 6px;
                        border-left: 4px solid #007bff;
                        font-size: 18px;
                        font-weight: 600;
                        color: #495057;
                        margin-bottom: 20px;
                    ">📋 Raw Script Output</div>
                    <pre style="
                        background-color: #f8f9fa;
                        padding: 15px;
                        border-radius: 6px;
                        border: 1px solid #dee2e6;
                        overflow-x: auto;
                        font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New', monospace;
                        font-size: 12px;
                        line-height: 1.4;
                        max-height: 400px;
                        overflow-y: auto;
                        white-space: pre-wrap;
                    ">${result.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
                </div>
            </div>
            
            <script>
                function exportAsHTML() {
                    // Create a Blob with the entire HTML content
                    const htmlContent = document.documentElement.outerHTML;
                    const blob = new Blob([htmlContent], { type: 'text/html' });
                    const url = URL.createObjectURL(blob);
                    
                    // Create a download link and trigger download
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'network-scan-' + new Date().toISOString().replace(/[:.]/g, '-') + '.html';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                }
                
                function exportAsPDF() {
                    // Alert the user that we're preparing the PDF
                    alert('Preparing PDF for download. The browser print dialog will open momentarily.');
                    
                    // Small delay to make sure the alert is seen
                    setTimeout(() => {
                        // Add a temporary print-specific style
                        const style = document.createElement('style');
                        style.id = 'print-style';
                        style.innerHTML = \`
                            @media print {
                                body { padding: 10mm; }
                                button { display: none; }
                                pre { max-height: none; }
                                @page { size: A4; margin: 10mm; }
                            }
                        \`;
                        document.head.appendChild(style);
                        
                        // Open print dialog
                        window.print();
                        
                        // Remove the print style after a delay
                        setTimeout(() => {
                            document.getElementById('print-style').remove();
                        }, 1000);
                    }, 500);
                }
            </script>
        </body>
        </html>
    `;
};

/**
 * Generates HTML with inline styles for parsing failed scenario
 */
export const generateParsingFailedHTML = (result) => {
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Scan Results (Raw)</title>
            <meta charset="UTF-8">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
            </style>
        </head>
        <body style="
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            line-height: 1.6;
        ">
            <div style="
                background: white;
                border-radius: 6px;
                border: 1px solid #dee2e6;
                max-width: 1200px;
                margin: 0 auto;
                overflow: hidden;
            ">
                <!-- Warning Header -->
                <div style="
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 15px;
                    background-color: #fff3cd;
                    border-bottom: 1px solid #dee2e6;
                    border-left: 4px solid #ffc107;
                ">
                    <div>
                        <h1 style="
                            margin: 0;
                            font-size: 18px;
                            font-weight: 600;
                            color: #856404;
                        ">⚠️ Network Scan Results (JSON Parsing Failed)</h1>
                        <p style="
                            margin: 5px 0 0 0;
                            font-size: 14px;
                            color: #856404;
                        ">The scan completed but JSON parsing failed. Raw output below:</p>
                    </div>
                    <div>
                        <button onclick="exportAsHTML()" style="
                            padding: 6px 12px;
                            font-size: 12px;
                            margin-left: 4px;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                            font-weight: 500;
                            background-color: #ffc107;
                            color: #212529;
                        ">💾 Export HTML</button>
                        <button onclick="exportAsPDF()" style="
                            padding: 6px 12px;
                            font-size: 12px;
                            margin-left: 4px;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                            font-weight: 500;
                            background-color: #ffc107;
                            color: #212529;
                        ">📄 Export PDF</button>
                    </div>
                </div>
                
                <!-- Raw Output Section -->
                <div style="margin: 20px; margin-bottom: 40px;">
                    <div style="
                        padding: 15px;
                        background-color: #f8f9fa;
                        border-radius: 6px;
                        border-left: 4px solid #ffc107;
                        font-size: 18px;
                        font-weight: 600;
                        color: #495057;
                        margin-bottom: 20px;
                    ">📄 Raw Script Output</div>
                    <pre style="
                        background-color: #f8f9fa;
                        padding: 15px;
                        border-radius: 6px;
                        border: 1px solid #dee2e6;
                        overflow-x: auto;
                        font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New', monospace;
                        font-size: 12px;
                        line-height: 1.4;
                        max-height: 400px;
                        overflow-y: auto;
                        white-space: pre-wrap;
                    ">${result.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
                </div>
            </div>
            
            <script>
                function exportAsHTML() {
                    // Create a Blob with the entire HTML content
                    const htmlContent = document.documentElement.outerHTML;
                    const blob = new Blob([htmlContent], { type: 'text/html' });
                    const url = URL.createObjectURL(blob);
                    
                    // Create a download link and trigger download
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'network-scan-parsing-failed-' + new Date().toISOString().replace(/[:.]/g, '-') + '.html';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                }
                
                function exportAsPDF() {
                    // Alert the user that we're preparing the PDF
                    alert('Preparing PDF for download. The browser print dialog will open momentarily.');
                    
                    // Small delay to make sure the alert is seen
                    setTimeout(() => {
                        // Add a temporary print-specific style
                        const style = document.createElement('style');
                        style.id = 'print-style';
                        style.innerHTML = \`
                            @media print {
                                body { padding: 10mm; }
                                button { display: none; }
                                pre { max-height: none; }
                                @page { size: A4; margin: 10mm; }
                            }
                        \`;
                        document.head.appendChild(style);
                        
                        // Open print dialog
                        window.print();
                        
                        // Remove the print style after a delay
                        setTimeout(() => {
                            document.getElementById('print-style').remove();
                        }, 1000);
                    }, 500);
                }
            </script>
        </body>
        </html>
    `;
};

/**
 * Generates HTML with inline styles for raw output (no JSON found)
 */
export const generateRawOutputHTML = (result) => {
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Scan Results</title>
            <meta charset="UTF-8">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
            </style>
        </head>
        <body style="
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            line-height: 1.6;
        ">
            <div style="
                background: white;
                border-radius: 6px;
                border: 1px solid #dee2e6;
                max-width: 1200px;
                margin: 0 auto;
                overflow: hidden;
            ">
                <!-- Info Header -->
                <div style="
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 15px;
                    background-color: #f8f9fa;
                    border-bottom: 1px solid #dee2e6;
                    border-left: 4px solid #6c757d;
                ">
                    <div>
                        <h1 style="
                            margin: 0;
                            font-size: 18px;
                            font-weight: 600;
                            color: #495057;
                        ">📊 Network Scan Results</h1>
                        <p style="
                            margin: 5px 0 0 0;
                            font-size: 14px;
                            color: #6c757d;
                        ">Raw network scan output (no structured data found):</p>
                    </div>
                    <div>
                        <button onclick="exportAsHTML()" style="
                            padding: 6px 12px;
                            font-size: 12px;
                            margin-left: 4px;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                            font-weight: 500;
                            background-color: #6c757d;
                            color: white;
                        ">💾 Export HTML</button>
                        <button onclick="exportAsPDF()" style="
                            padding: 6px 12px;
                            font-size: 12px;
                            margin-left: 4px;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                            font-weight: 500;
                            background-color: #6c757d;
                            color: white;
                        ">📄 Export PDF</button>
                    </div>
                </div>
                
                <!-- Raw Output Section -->
                <div style="margin: 20px; margin-bottom: 40px;">
                    <div style="
                        padding: 15px;
                        background-color: #f8f9fa;
                        border-radius: 6px;
                        border-left: 4px solid #6c757d;
                        font-size: 18px;
                        font-weight: 600;
                        color: #495057;
                        margin-bottom: 20px;
                    ">📄 Raw Script Output</div>
                    <pre style="
                        background-color: #f8f9fa;
                        padding: 15px;
                        border-radius: 6px;
                        border: 1px solid #dee2e6;
                        overflow-x: auto;
                        font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New', monospace;
                        font-size: 12px;
                        line-height: 1.4;
                        max-height: 400px;
                        overflow-y: auto;
                        white-space: pre-wrap;
                    ">${result.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
                </div>
            </div>
            
            <script>
                function exportAsHTML() {
                    // Create a Blob with the entire HTML content
                    const htmlContent = document.documentElement.outerHTML;
                    const blob = new Blob([htmlContent], { type: 'text/html' });
                    const url = URL.createObjectURL(blob);
                    
                    // Create a download link and trigger download
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'network-scan-raw-' + new Date().toISOString().replace(/[:.]/g, '-') + '.html';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                }
                
                function exportAsPDF() {
                    // Alert the user that we're preparing the PDF
                    alert('Preparing PDF for download. The browser print dialog will open momentarily.');
                    
                    // Small delay to make sure the alert is seen
                    setTimeout(() => {
                        // Add a temporary print-specific style
                        const style = document.createElement('style');
                        style.id = 'print-style';
                        style.innerHTML = \`
                            @media print {
                                body { padding: 10mm; }
                                button { display: none; }
                                pre { max-height: none; }
                                @page { size: A4; margin: 10mm; }
                            }
                        \`;
                        document.head.appendChild(style);
                        
                        // Open print dialog
                        window.print();
                        
                        // Remove the print style after a delay
                        setTimeout(() => {
                            document.getElementById('print-style').remove();
                        }, 1000);
                    }, 500);
                }
            </script>
        </body>
        </html>
    `;
};

const generateInlineDHCPTable = (dhcpData) => {
    if (!dhcpData || dhcpData.length === 0) {
        return `<div style="
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-style: italic;
        ">No DHCP fixed IP reservations found</div>`;
    }

    let tableHTML = `
        <table style="
            width: 100%;
            border-collapse: collapse;
            min-width: 800px;
        ">
            <thead>
                <tr>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                    ">Hostname</th>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                    ">IP Address</th>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                    ">MAC Address</th>
                </tr>
            </thead>
            <tbody>
    `;

    dhcpData.forEach((item, index) => {
        tableHTML += `
                <tr style="transition: background-color 0.2s;">
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === dhcpData.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                    ">
                        <span style="
                            font-weight: 500;
                            color: #28a745;
                            background-color: #d4edda;
                            padding: 2px 6px;
                            border-radius: 3px;
                            font-size: 12px;
                        ">${item.hostname || 'N/A'}</span>
                    </td>
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === dhcpData.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                    ">
                        <span style="
                            font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New', monospace;
                            font-weight: 500;
                            color: #007bff;
                            background-color: #e3f2fd;
                            padding: 2px 6px;
                            border-radius: 3px;
                            font-size: 12px;
                        ">${item.ip_address || 'N/A'}</span>
                    </td>
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === dhcpData.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                    ">
                        <span style="
                            font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New', monospace;
                            color: #6c757d;
                            background-color: #f8f9fa;
                            padding: 2px 6px;
                            border-radius: 3px;
                            font-size: 12px;
                        ">${item.mac_address || 'N/A'}</span>
                    </td>
                </tr>
        `;
    });

    tableHTML += `
            </tbody>
        </table>
    `;

    return tableHTML;
};

const generateInlineNFSTable = (nfsData) => {
    if (!nfsData || nfsData.length === 0) {
        return `<div style="
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-style: italic;
        ">No NFS exports found</div>`;
    }

    let tableHTML = `
        <table style="
            width: 100%;
            border-collapse: collapse;
            min-width: 800px;
        ">
            <thead>
                <tr>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                    ">Export Path</th>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                    ">Client/IP Range</th>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                    ">Resolved Hostname</th>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                    ">Status</th>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                    ">Type</th>
                </tr>
            </thead>
            <tbody>
    `;

    nfsData.forEach((item, index) => {
        let clientType = 'Unknown';
        const client = item.client || 'N/A';
        const resolvedHostname = item.resolved_hostname || 'N/A';
        
        // Determine client type with better validation
        if (client === '*') {
            clientType = 'All hosts';
        } else if (client.match(/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]+)?$/)) {
            clientType = 'IP/Network';
        } else if (client.match(/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)) {
            clientType = 'Hostname';
        } else if (client.match(/^[a-zA-Z0-9.-]+$/)) {
            clientType = 'Hostname';
        } else if (client.includes(',') || client.match(/^(rw|ro|sync|async|no_root_squash|root_squash|all_squash|no_all_squash|secure|insecure)/)) {
            // This looks like NFS mount options, not a client
            clientType = 'Mount Options (Invalid)';
        } else {
            clientType = 'Unknown';
        }

        // Extract status from resolved hostname
        let status = 'unknown';
        let displayHostname = resolvedHostname;
        if (resolvedHostname.includes('(online)')) {
            status = 'online';
            displayHostname = resolvedHostname.replace(' (online)', '');
        } else if (resolvedHostname.includes('(offline)')) {
            status = 'offline';
            displayHostname = resolvedHostname.replace(' (offline)', '');
        }

        // Create status indicator
        let statusBadge = '';
        if (status === 'online') {
            statusBadge = `<span style="
                background-color: #d4edda;
                color: #155724;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 11px;
                font-weight: 500;
                text-transform: uppercase;
            ">🟢 Online</span>`;
        } else if (status === 'offline') {
            statusBadge = `<span style="
                background-color: #f8d7da;
                color: #721c24;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 11px;
                font-weight: 500;
                text-transform: uppercase;
            ">🔴 Offline</span>`;
        } else {
            statusBadge = `<span style="
                color: #6c757d;
                background: #f8f9fa;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 11px;
            ">❓ Unknown</span>`;
        }

        tableHTML += `
                <tr style="transition: background-color 0.2s;">
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === nfsData.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                    ">${item.export_path || 'N/A'}</td>
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === nfsData.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                    ">
                        <span style="
                            font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New', monospace;
                            font-weight: 500;
                            color: ${clientType === 'Mount Options (Invalid)' ? '#dc3545' : '#007bff'};
                            background-color: ${clientType === 'Mount Options (Invalid)' ? '#f8d7da' : '#e3f2fd'};
                            padding: 2px 6px;
                            border-radius: 3px;
                            font-size: 12px;
                        ">${client}</span>
                    </td>
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === nfsData.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                    ">
                        <span style="
                            font-weight: 500;
                            color: #28a745;
                            background-color: #d4edda;
                            padding: 2px 6px;
                            border-radius: 3px;
                            font-size: 12px;
                        ">${displayHostname}</span>
                    </td>
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === nfsData.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                    ">${statusBadge}</td>
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === nfsData.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                    ">${clientType}</td>
                </tr>
        `;
    });

    tableHTML += `
            </tbody>
        </table>
    `;

    return tableHTML;
};

const getUniqueIPs = (jsonData) => {
    const ips = new Set();
    
    if (jsonData.dhcp_fixed_ips) {
        jsonData.dhcp_fixed_ips.forEach(item => {
            if (item.ip_address) ips.add(item.ip_address);
        });
    }
    
    if (jsonData.nfs_exports) {
        jsonData.nfs_exports.forEach(item => {
            if (item.client) {
                const client = item.client.trim();
                // Only add if it's a valid IP address or IP range, not mount options
                if (client.match(/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]+)?$/)) {
                    // Extract just the IP part (remove CIDR if present)
                    const ipMatch = client.match(/^([0-9]{1,3}\.){3}[0-9]{1,3}/);
                    if (ipMatch) {
                        ips.add(ipMatch[0]);
                    }
                }
                // Don't count hostnames, wildcards (*), or mount options as IPs
            }
        });
    }
    
    return Array.from(ips);
};

const generateUniqueIPsTable = (jsonData) => {
    const uniqueIPs = getUniqueIPs(jsonData);
    
    if (uniqueIPs.length === 0) {
        return `<div style="
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-style: italic;
        ">No unique IP addresses found</div>`;
    }

    // Sort IPs numerically
    const sortedIPs = uniqueIPs.sort((a, b) => {
        const aParts = a.split('.').map(num => parseInt(num, 10));
        const bParts = b.split('.').map(num => parseInt(num, 10));
        
        for (let i = 0; i < 4; i++) {
            if (aParts[i] !== bParts[i]) {
                return aParts[i] - bParts[i];
            }
        }
        return 0;
    });

    let tableHTML = `
        <table style="
            width: 100%;
            border-collapse: collapse;
            min-width: 600px;
        ">
            <thead>
                <tr>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                        width: 15%;
                    ">#</th>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                        width: 25%;
                    ">IP Address</th>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                        width: 40%;
                    ">Hostname</th>
                    <th style="
                        background-color: #f8f9fa;
                        padding: 12px 8px;
                        text-align: left;
                        font-weight: 600;
                        font-size: 14px;
                        color: #495057;
                        border-bottom: 2px solid #dee2e6;
                        width: 20%;
                    ">Status</th>
                </tr>
            </thead>
            <tbody>
    `;

    sortedIPs.forEach((ip, index) => {
        // Try to get hostname from NFS data if available
        let hostname = 'N/A';
        if (jsonData.nfs_exports) {
            const nfsEntry = jsonData.nfs_exports.find(item => {
                const client = item.client || '';
                const clientIP = client.split('/')[0];
                return clientIP === ip;
            });
            
            if (nfsEntry && nfsEntry.resolved_hostname) {
                hostname = nfsEntry.resolved_hostname.replace(/ \((online|offline|unknown)\)/, '');
            }
        }
        
        // Also check DHCP for hostname
        if (hostname === 'N/A' && jsonData.dhcp_fixed_ips) {
            const dhcpEntry = jsonData.dhcp_fixed_ips.find(item => item.ip_address === ip);
            if (dhcpEntry && dhcpEntry.hostname) {
                hostname = dhcpEntry.hostname;
            }
        }
        
        // Get status from hostname if available
        let status = 'Unknown';
        if (jsonData.nfs_exports) {
            const nfsEntry = jsonData.nfs_exports.find(item => {
                const client = item.client || '';
                const clientIP = client.split('/')[0];
                return clientIP === ip;
            });
            
            if (nfsEntry && nfsEntry.resolved_hostname) {
                if (nfsEntry.resolved_hostname.includes('(online)')) {
                    status = 'Online';
                } else if (nfsEntry.resolved_hostname.includes('(offline)')) {
                    status = 'Offline';
                }
            }
        }

        let statusBadge = '';
        if (status === 'Online') {
            statusBadge = `<span style="
                background-color: #d4edda;
                color: #155724;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 11px;
                font-weight: 500;
                text-transform: uppercase;
            ">🟢 Online</span>`;
        } else if (status === 'Offline') {
            statusBadge = `<span style="
                background-color: #f8d7da;
                color: #721c24;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 11px;
                font-weight: 500;
                text-transform: uppercase;
            ">🔴 Offline</span>`;
        } else {
            statusBadge = `<span style="
                color: #6c757d;
                background: #f8f9fa;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 11px;
            ">❓ Unknown</span>`;
        }

        tableHTML += `
                <tr style="transition: background-color 0.2s;">
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === sortedIPs.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                        font-weight: 600;
                        color: #495057;
                    ">${index + 1}</td>
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === sortedIPs.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                    ">
                        <span style="
                            font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New', monospace;
                            font-weight: 600;
                            color: #007bff;
                            background-color: #e3f2fd;
                            padding: 2px 6px;
                            border-radius: 3px;
                            font-size: 12px;
                        ">${ip}</span>
                    </td>
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === sortedIPs.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                        color: #495057;
                    ">
                        ${hostname !== 'N/A' ? `<span style="
                            font-weight: 500;
                            color: #28a745;
                            background-color: #d4edda;
                            padding: 2px 6px;
                            border-radius: 3px;
                            font-size: 12px;
                        ">${hostname}</span>` : '<span style="color: #6c757d; font-style: italic;">N/A</span>'}
                    </td>
                    <td style="
                        padding: 10px 8px;
                        border-bottom: ${index === sortedIPs.length - 1 ? 'none' : '1px solid #dee2e6'};
                        font-size: 13px;
                        vertical-align: middle;
                    ">${statusBadge}</td>
                </tr>
        `;
    });

    tableHTML += `
            </tbody>
        </table>
    `;

    return tableHTML;
};
