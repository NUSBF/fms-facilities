// Email template system for FMS notifications

const createEmailTemplate = (type, data) => {
    const baseStyles = `
        <style>
            .email-container { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333; }
            .header { background: linear-gradient(135deg, #007bff, #0056b3); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
            .content { padding: 20px; background: white; }
            .ticket-details { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #007bff; }
            .priority-high { border-left-color: #dc3545 !important; }
            .priority-medium { border-left-color: #ffc107 !important; }
            .priority-low { border-left-color: #28a745 !important; }
            .footer { background: #f8f9fa; padding: 15px; text-align: center; border-radius: 0 0 8px 8px; color: #666; }
            .btn { display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 10px 5px; }
            .status-badge { padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }
            .status-open { background: #007bff; }
            .status-in-progress { background: #ffc107; color: black; }
            .status-resolved { background: #28a745; }
        </style>
    `;

    switch (type) {
        case 'ticket_created_user':
            return `
                ${baseStyles}
                <div class="email-container">
                    <div class="header">
                        <h1>🎫 Support Ticket Created</h1>
                        <p>Your request has been received</p>
                    </div>
                    <div class="content">
                        <p>Dear ${data.userName},</p>
                        <p>Your support ticket has been successfully created and assigned to our facility team. We'll keep you updated on its progress.</p>
                        
                        <div class="ticket-details priority-${data.ticketPriority}">
                            <h3>📋 Ticket Details</h3>
                            <p><strong>Ticket ID:</strong> #${data.ticketId}</p>
                            <p><strong>Title:</strong> ${data.ticketTitle}</p>
                            <p><strong>Category:</strong> ${data.ticketCategory}</p>
                            <p><strong>Priority:</strong> <span class="status-badge priority-${data.ticketPriority}">${data.ticketPriority.toUpperCase()}</span></p>
                            <p><strong>Status:</strong> <span class="status-badge status-${data.ticketStatus}">${data.ticketStatus.replace('_', ' ').toUpperCase()}</span></p>
                            <p><strong>Created:</strong> ${data.createdDate}</p>
                            <p><strong>Description:</strong></p>
                            <div style="background: white; padding: 10px; border-radius: 4px; border: 1px solid #ddd;">
                                ${data.ticketDescription}
                            </div>
                        </div>
                        
                        <div style="text-align: center; margin: 20px 0;">
                            <p><strong>What happens next?</strong></p>
                            <p>Our facility team will review your ticket and respond within:</p>
                            <ul style="text-align: left; display: inline-block;">
                                <li><strong>High Priority:</strong> 2-4 hours</li>
                                <li><strong>Medium Priority:</strong> 4-8 hours</li>
                                <li><strong>Low Priority:</strong> 24-48 hours</li>
                            </ul>
                        </div>
                        
                        <p>You'll receive email notifications when your ticket status changes or when our team adds updates.</p>
                        <p>If you need to add more information, please reply to this email referencing ticket #${data.ticketId}.</p>
                    </div>
                    <div class="footer">
                        <p><strong>FMS Facilities Management System</strong></p>
                        <p>${data.facilityName}</p>
                        <p><small>This is an automated message. Please do not reply directly to this email.</small></p>
                    </div>
                </div>
            `;

        case 'ticket_created_staff':
            return `
                ${baseStyles}
                <div class="email-container">
                    <div class="header">
                        <h1>🚨 New Support Ticket</h1>
                        <p>Requires ${data.ticketPriority} priority attention</p>
                    </div>
                    <div class="content">
                        <p>A new support ticket has been submitted and requires your attention.</p>
                        
                        <div class="ticket-details priority-${data.ticketPriority}">
                            <h3>🔧 Ticket Details</h3>
                            <p><strong>Ticket ID:</strong> #${data.ticketId}</p>
                            <p><strong>Title:</strong> ${data.ticketTitle}</p>
                            <p><strong>Category:</strong> ${data.ticketCategory}</p>
                            <p><strong>Priority:</strong> <span class="status-badge priority-${data.ticketPriority}">${data.ticketPriority.toUpperCase()}</span></p>
                            <p><strong>Status:</strong> <span class="status-badge status-${data.ticketStatus}">${data.ticketStatus.replace('_', ' ').toUpperCase()}</span></p>
                            <p><strong>Submitted by:</strong> ${data.userName} (${data.userEmail})</p>
                            <p><strong>Facility:</strong> ${data.facilityName}</p>
                            <p><strong>Created:</strong> ${data.createdDate}</p>
                            <p><strong>Description:</strong></p>
                            <div style="background: white; padding: 10px; border-radius: 4px; border: 1px solid #ddd;">
                                ${data.ticketDescription}
                            </div>
                        </div>
                        
                        <div style="text-align: center; margin: 20px 0;">
                            <a href="mailto:${data.userEmail}?subject=Re: Ticket #${data.ticketId} - ${data.ticketTitle}" class="btn">📧 Reply to User</a>
                        </div>
                        
                        <div style="background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107;">
                            <p><strong>⏰ Response Time Guidelines:</strong></p>
                            <ul>
                                <li><strong>High Priority:</strong> Respond within 2-4 hours</li>
                                <li><strong>Medium Priority:</strong> Respond within 4-8 hours</li>
                                <li><strong>Low Priority:</strong> Respond within 24-48 hours</li>
                            </ul>
                        </div>
                    </div>
                    <div class="footer">
                        <p><strong>FMS Facilities Management System</strong></p>
                        <p>Facility Staff Notification</p>
                    </div>
                </div>
            `;

        case 'ticket_status_changed':
            return `
                ${baseStyles}
                <div class="email-container">
                    <div class="header">
                        <h1>📈 Ticket Status Updated</h1>
                        <p>Ticket #${data.ticketId}</p>
                    </div>
                    <div class="content">
                        <p>Dear ${data.userName},</p>
                        <p>Your support ticket status has been updated by our facility team.</p>
                        
                        <div class="ticket-details">
                            <h3>📊 Status Update</h3>
                            <p><strong>Ticket ID:</strong> #${data.ticketId}</p>
                            <p><strong>Title:</strong> ${data.ticketTitle}</p>
                            <p><strong>New Status:</strong> <span class="status-badge status-${data.ticketStatus}">${data.ticketStatus.replace('_', ' ').toUpperCase()}</span></p>
                            ${data.updateMessage ? `<p><strong>Update Message:</strong> ${data.updateMessage}</p>` : ''}
                        </div>
                        
                        ${data.ticketStatus === 'resolved' ? `
                            <div style="background: #d4edda; padding: 15px; border-radius: 5px; border-left: 4px solid #28a745; margin: 15px 0;">
                                <h4>✅ Ticket Resolved</h4>
                                <p>Great news! Your ticket has been resolved. If you're satisfied with the resolution, no further action is needed.</p>
                                <p>If you're not satisfied or need additional help, please reply to this email and we'll reopen your ticket.</p>
                            </div>
                        ` : `
                            <div style="background: #cce5ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff; margin: 15px 0;">
                                <p>We're actively working on your ticket and will keep you updated on our progress.</p>
                            </div>
                        `}
                    </div>
                    <div class="footer">
                        <p><strong>FMS Facilities Management System</strong></p>
                        <p>${data.facilityName}</p>
                    </div>
                </div>
            `;

        case 'ticket_response_added':
            return `
                ${baseStyles}
                <div class="email-container">
                    <div class="header">
                        <h1>💬 New Response Added</h1>
                        <p>Ticket #${data.ticketId}</p>
                    </div>
                    <div class="content">
                        <p>Dear ${data.userName},</p>
                        <p>Our facility team has added a response to your support ticket.</p>
                        
                        <div class="ticket-details">
                            <h3>📝 New Response</h3>
                            <p><strong>Ticket ID:</strong> #${data.ticketId}</p>
                            <p><strong>Title:</strong> ${data.ticketTitle}</p>
                            <p><strong>Response:</strong></p>
                            <div style="background: white; padding: 15px; border-radius: 4px; border: 1px solid #ddd; border-left: 4px solid #28a745;">
                                ${data.updateMessage}
                            </div>
                        </div>
                        
                        <div style="text-align: center; margin: 20px 0;">
                            <p>Need to add more information or ask follow-up questions?</p>
                            <a href="mailto:fms-facilities@ncl.ac.uk?subject=Re: Ticket #${data.ticketId} - ${data.ticketTitle}" class="btn">📧 Reply to Team</a>
                        </div>
                    </div>
                    <div class="footer">
                        <p><strong>FMS Facilities Management System</strong></p>
                        <p>${data.facilityName}</p>
                    </div>
                </div>
            `;

        default:
            return `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <p>This is a notification from the FMS Facilities Management System.</p>
                    <p>Details: ${JSON.stringify(data)}</p>
                </div>
            `;
    }
};

module.exports = { createEmailTemplate };
