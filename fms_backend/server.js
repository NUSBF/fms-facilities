const express = require('express');
const mariadb = require('mariadb');
const cors = require('cors');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = mariadb.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectionLimit: process.env.DB_CONNECTION_LIMIT || 5
});

// Email configuration
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '25'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: process.env.SMTP_AUTH === 'true' ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    } : false,
    tls: {
        rejectUnauthorized: process.env.SMTP_REJECT_UNAUTHORIZED !== 'false'
    }
});

// Set frontend URL for links in emails
const FRONTEND_URL = process.env.FRONTEND_URL;

// Middleware to check token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    try {
        // Simple implementation - in production use JWT or other secure token method
        const userId = parseInt(token);
        if (isNaN(userId)) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        req.user = { id: userId };
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Apply authentication to specific routes instead of globally;

// Middleware to check roles
const checkRole = (allowedRoles) => {
    return async (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        
        try {
            const conn = await pool.getConnection();
            const roles = await conn.query(`
                SELECT ur.role, ur.facility_id 
                FROM user_roles ur 
                WHERE ur.user_id = ?
            `, [req.user.id]);
            conn.end();
            
            const hasPermission = roles.some(userRole => {
                if (userRole.role === 'developer') return true;
                return allowedRoles.includes(userRole.role);
            });
            
            if (!hasPermission) {
                return res.status(403).json({ error: 'Insufficient permissions' });
            }
            
            req.userRoles = roles;
            next();
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    };
};

// Test route - disable in production
if (process.env.NODE_ENV !== 'production') {
    app.get('/api/test', authenticateToken, async (req, res) => {
        try {
            const conn = await pool.getConnection();
            const result = await conn.query('SELECT 1');
            conn.release();
            res.json({ message: 'Database connected!' });
        } catch (err) {
            res.status(500).json({ error: 'Database connection failed' });
        }
    });
}

// Public facilities endpoint for registration
app.get('/fms-api/facilities-public', async (req, res) => {
    try {
        const conn = await pool.getConnection();
        const facilities = await conn.query(
            'SELECT id, short_name, long_name FROM facilities'
        );
        conn.release();
        res.json(facilities);
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve facilities data' });
    }
});

// Register endpoint
app.post('/fms-api/register', async (req, res) => {
    const { 
        username, password, first_name, last_name, email, 
        university, company, faculty, institute, building, room, 
        phone_number, profile_link, photo_link, linkedin_link, 
        group_website, facility_id, requested_role 
    } = req.body;
    
    // Validate required fields
    if (!username || !password || !first_name || !last_name || !email) {
        return res.status(400).json({ 
            success: false, 
            message: 'Required fields are missing' 
        });
    }
    
    try {
        const conn = await pool.getConnection();
        
        // Check if username already exists
        const existingUser = await conn.query(
            'SELECT id FROM users WHERE username = ?', 
            [username]
        );
        
        if (existingUser.length > 0) {
            conn.release();
            return res.status(400).json({ 
                success: false, 
                message: 'Username already exists' 
            });
        }
        
        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Insert new user with status 'inactive' (pending approval)
        const result = await conn.query(
            `INSERT INTO users (
                username, password_hash, first_name, last_name, email,
                university, company, faculty, institute, building, room,
                phone_number, profile_link, photo_link, linkedin_link,
                group_website, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                username, hashedPassword, first_name, last_name, email,
                university || null, company || null, faculty || null, 
                institute || null, building || null, room || null,
                phone_number || null, profile_link || null, photo_link || null, 
                linkedin_link || null, group_website || null, 'inactive'
            ]
        );
        
        const userId = result.insertId;
        
        // Insert user role
        await conn.query(
            'INSERT INTO user_roles (user_id, role, facility_id) VALUES (?, ?, ?)',
            [userId, requested_role, facility_id || 1]
        );
        
        // Find facility managers to notify
        const managers = await conn.query(
            `SELECT u.email 
            FROM users u
            JOIN user_roles ur ON u.id = ur.user_id
            WHERE ur.role = 'facility_manager' AND ur.facility_id = ?`,
            [facility_id || 1]
        );
        
        // Get facility name
        const facilityResult = await conn.query(
            'SELECT short_name FROM facilities WHERE id = ?',
            [facility_id || 1]
        );
        
        const facilityName = facilityResult.length > 0 ? facilityResult[0].short_name : 'Unknown Facility';
        
        // Send email to facility managers
        if (managers.length > 0) {
            // Build comma-separated list of manager emails
            const managerEmails = managers.map(m => m.email).join(',');
            
            // Send notification email
            await transporter.sendMail({
                from: 'fms-facilities@ncl.ac.uk',
                to: managerEmails,
                subject: `New User Registration: ${first_name} ${last_name} for ${facilityName}`,
                html: `
                    <p>A new user has registered for ${facilityName} and is awaiting approval:</p>
                    <p><strong>Name:</strong> ${first_name} ${last_name}<br>
                    <strong>Username:</strong> ${username}<br>
                    <strong>Email:</strong> ${email}<br>
                    <strong>Requested Role:</strong> ${requested_role}</p>
                    <p>Please <a href="${FRONTEND_URL}/users">click here</a> to review and approve this request.</p>
                `
            });
        }

        // Send confirmation email to the user
await transporter.sendMail({
    from: 'fms-facilities@ncl.ac.uk',
    to: email,
    subject: 'Registration Received - FMS Facilities',
    html: `
        <p>Hello ${first_name} ${last_name},</p>
        <p>Thank you for registering with FMS Facilities System. Your registration has been received and is pending approval by a facility manager.</p>
        <p>Registration details:</p>
        <ul>
            <li><strong>Username:</strong> ${username}</li>
            <li><strong>Requested Role:</strong> ${requested_role}</li>
            <li><strong>Facility:</strong> ${facilityName}</li>
        </ul>
        <p>You will receive another email once your registration has been approved.</p>
        <p>If you have any questions, please contact your facility manager.</p>
    `
});        
        conn.release();
        res.json({ 
            success: true, 
            message: 'Registration successful. Your account will be reviewed by a facility manager.' 
        });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to register. Please try again.' 
        });
    }
});

// Get all users - restricted to admins only
app.get('/api/users', checkRole(['developer', 'administrator']), authenticateToken, async (req, res) => {
    try {
        const conn = await pool.getConnection();
        // Don't return password hashes
        const users = await conn.query('SELECT id, username, first_name, last_name, email FROM users');
        conn.release();
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve users' });
    }
});

// Login endpoint
app.post('/fms-api/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
    }
    
    try {
        const conn = await pool.getConnection();
        const result = await conn.query(
            'SELECT id, username, first_name, last_name, email, password_hash FROM users WHERE username = ?', 
            [username]
        );
        
        if (result.length > 0) {
            const user = result[0];
            const isMatch = await bcrypt.compare(password, user.password_hash);
            
            if (isMatch) {
                const roles = await conn.query(`
                    SELECT ur.role, ur.facility_id, f.short_name as facility_name
                    FROM user_roles ur
                    LEFT JOIN facilities f ON ur.facility_id = f.id
                    WHERE ur.user_id = ?
                `, [user.id]);
                
                // Remove password hash from user object
                const sanitizedUser = { ...user };
                delete sanitizedUser.password_hash;
                
                // In a real app, would generate a JWT token here
                conn.release();
                res.json({ 
                    success: true, 
                    user: sanitizedUser,
                    roles: roles
                });
            } else {
                conn.release();
                res.json({ success: false, message: 'Invalid credentials' });
            }
        } else {
            conn.release();
            res.json({ success: false, message: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Authentication error' });
    }
});

// Equipment routes
app.get('/fms-api/equipment', authenticateToken, async (req, res) => {
    try {
        const conn = await pool.getConnection();
        const equipment = await conn.query(`
            SELECT e.id, e.name, e.model, e.status, e.facility_id, e.price_per_hour, 
                   f.short_name as facility_name 
            FROM equipment e
            LEFT JOIN facilities f ON e.facility_id = f.id
        `);
        conn.release();
        res.json(equipment);
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve equipment data' });
    }
});

// Facilities routes  
app.get('/fms-api/facilities', authenticateToken, async (req, res) => {
    try {
        const conn = await pool.getConnection();
        const facilities = await conn.query(
            'SELECT id, short_name, long_name, description, building, room FROM facilities'
        );
        conn.release();
        res.json(facilities);
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve facilities data' });
    }
});

// Add facility route 
app.post('/api/facilities', checkRole(['developer', 'administrator']), authenticateToken, async (req, res) => {
    const { short_name, long_name, description, building, room } = req.body;
    
    // Validate inputs
    if (!short_name || !long_name || !building || !room) {
        return res.status(400).json({ 
            success: false, 
            message: 'Required fields: short_name, long_name, building, room' 
        });
    }
    
    try {
        const conn = await pool.getConnection();
        const result = await conn.query(
            'INSERT INTO facilities (short_name, long_name, description, building, room) VALUES (?, ?, ?, ?, ?)',
            [short_name, long_name, description || '', building, room]
        );
        conn.release();
        res.json({ success: true, facilityId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Failed to add facility' });
    }
});

// Bookings routes
app.get('/fms-api/bookings', authenticateToken, async (req, res) => {
    try {
        const conn = await pool.getConnection();
        const bookings = await conn.query(`
            SELECT b.id, b.user_id, b.equipment_id, b.start_time, b.end_time, 
                   b.total_price, b.status, b.created_at,
                   u.username, e.name as equipment_name 
            FROM bookings b
            JOIN users u ON b.user_id = u.id
            JOIN equipment e ON b.equipment_id = e.id
        `);
        conn.release();
        res.json(bookings);
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve bookings' });
    }
});

// Create booking
app.post('/api/bookings', authenticateToken, async (req, res) => {
    const { user_id, equipment_id, start_time, end_time } = req.body;
    
    // Validate required fields
    if (!user_id || !equipment_id || !start_time || !end_time) {
        return res.status(400).json({ 
            success: false, 
            message: 'Required fields: user_id, equipment_id, start_time, end_time' 
        });
    }
    
    try {
        const conn = await pool.getConnection();
        
        // Verify equipment exists and get price
        const equipment = await conn.query('SELECT price_per_hour FROM equipment WHERE id = ?', [equipment_id]);
        if (equipment.length === 0) {
            conn.release();
            return res.status(404).json({ success: false, message: 'Equipment not found' });
        }
        
        const pricePerHour = equipment[0].price_per_hour;
        
        // Calculate booking duration and total price
        const start = new Date(start_time);
        const end = new Date(end_time);
        
        // Validate start and end times
        if (isNaN(start.getTime()) || isNaN(end.getTime()) || start >= end) {
            conn.release();
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid start or end time. Start must be before end.' 
            });
        }
        
        const hours = (end - start) / (1000 * 60 * 60);
        const totalPrice = hours * pricePerHour;
        
        const result = await conn.query(
            'INSERT INTO bookings (user_id, equipment_id, start_time, end_time, total_price, status) VALUES (?, ?, ?, ?, ?, ?)',
            [user_id, equipment_id, start_time, end_time, totalPrice, 'pending']
        );
        
        conn.release();
        res.json({ success: true, bookingId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create booking' });
    }
});

// Password reset request endpoint
app.post('/fms-api/reset-password-request', async (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({ success: false, message: 'Username is required' });
    }
    
    try {
        const conn = await pool.getConnection();
        
        // Find user by username
        const users = await conn.query('SELECT id, email FROM users WHERE username = ?', [username]);
        
        // Always return the same response to prevent username enumeration
        res.json({ success: true, message: 'If your account exists, a password reset link has been sent to your email' });
        
        // If user exists, generate token and send email
        if (users.length > 0) {
            const user = users[0];
            
            // Generate a random token
            const resetToken = crypto.randomBytes(20).toString('hex');
            const tokenExpires = new Date(Date.now() + 3600000); // 1 hour from now
            
            // Create reset tokens table if it doesn't exist
            await conn.query(`
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    token VARCHAR(255) NOT NULL,
                    expires DATETIME NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            `);
            
            // Delete any existing tokens for this user
            await conn.query('DELETE FROM password_reset_tokens WHERE user_id = ?', [user.id]);
            
            // Insert new token
            await conn.query(
                'INSERT INTO password_reset_tokens (user_id, token, expires) VALUES (?, ?, ?)',
                [user.id, resetToken, tokenExpires]
            );
            
            // Send email
            const resetUrl = `https://nusbf.ncl.ac.uk/fms-facilities/?token=${resetToken}`;
            
            console.log('About to send email to:', user.email);
            console.log('Reset URL:', resetUrl);
            
            try {
                const info = await transporter.sendMail({
                    from: 'fms-facilities@ncl.ac.uk',
                    to: user.email,
                    subject: 'Password Reset - FMS Facilities',
                    text: `You requested a password reset. Please use the following link to reset your password: ${resetUrl}

This link will expire in 1 hour.

If you didn't request this, please ignore this email.`,
                    html: `
                        <p>You requested a password reset.</p>
                        <p>Please use the following link to reset your password:</p>
                        <p><a href="${resetUrl}">${resetUrl}</a></p>
                        <p>This link will expire in 1 hour.</p>
                        <p>If you didn't request this, please ignore this email.</p>
                    `
                });
                console.log('Email sent successfully:', info);
            } catch (emailError) {
                console.error('Error sending email:', emailError);
            }
        }
        
        conn.release();
    } catch (err) {
        console.error('Password reset error:', err);
        // Still return success to prevent username enumeration
        if (!res.headersSent) {
            res.json({ success: true, message: 'If your account exists, a password reset link has been sent to your email' });
        }
    }
});

// Reset password endpoint
app.post('/fms-api/reset-password', async (req, res) => {
    const { token, password } = req.body;
    
    if (!token || !password) {
        return res.status(400).json({ success: false, message: 'Token and password are required' });
    }
    
    try {
        const conn = await pool.getConnection();
        
        // Get user id from token
        const tokens = await conn.query(
            'SELECT user_id FROM password_reset_tokens WHERE token = ? AND expires > NOW()',
            [token]
        );
        
        if (tokens.length === 0) {
            conn.release();
            return res.status(400).json({ success: false, message: 'Invalid or expired token' });
        }
        
        const userId = tokens[0].user_id;
        
        // Hash the new password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Update user's password
        await conn.query(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            [hashedPassword, userId]
        );
        
        // Delete the used token
        await conn.query(
            'DELETE FROM password_reset_tokens WHERE token = ?',
            [token]
        );
        
        conn.release();
        res.json({ success: true, message: 'Password has been reset successfully' });
    } catch (err) {
        console.error('Password reset error:', err);
        res.status(500).json({ success: false, message: 'Failed to reset password' });
    }
});

// Verify reset token endpoint
app.get('/fms-api/verify-reset-token/:token', async (req, res) => {
    const { token } = req.params;
    
    if (!token) {
        return res.status(400).json({ valid: false });
    }
    
    try {
        const conn = await pool.getConnection();
        const tokens = await conn.query(
            'SELECT * FROM password_reset_tokens WHERE token = ? AND expires > NOW()',
            [token]
        );
        conn.release();
        
        if (tokens.length > 0) {
            res.json({ valid: true });
        } else {
            res.json({ valid: false });
        }
    } catch (err) {
        console.error('Token verification error:', err);
        res.status(500).json({ valid: false });
    }
});

// Get all users endpoint
app.get('/fms-api/users', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager']), async (req, res) => {
    try {
        const conn = await pool.getConnection();
        
        // Get all users with their roles
        const users = await conn.query(`
            SELECT u.*, ur.role, ur.facility_id, f.short_name as facility_name
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN facilities f ON ur.facility_id = f.id
        `);
        
        // Group roles by user
        const usersWithRoles = [];
        const userMap = new Map();
        
        users.forEach(row => {
            if (!userMap.has(row.id)) {
                const user = { ...row, roles: [] };
                delete user.role;
                delete user.facility_id;
                delete user.facility_name;
                delete user.password_hash; // Don't send password hash
                
                userMap.set(row.id, usersWithRoles.length);
                usersWithRoles.push(user);
            }
            
            if (row.role) {
                const userIndex = userMap.get(row.id);
                usersWithRoles[userIndex].roles.push({
                    role: row.role,
                    facility_id: row.facility_id,
                    facility_name: row.facility_name
                });
            }
        });
        
        conn.release();
        res.json(usersWithRoles);
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ error: 'Failed to retrieve users data' });
    }
});

// Get user training records
app.get('/fms-api/user-training', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager']), async (req, res) => 
{
    try {
        const conn = await pool.getConnection();
        const records = await conn.query(`
            SELECT ut.id, ut.user_id, ut.training_name, ut.training_date, ut.expiry_date, ut.trainer, ut.notes,
                   u.first_name, u.last_name
            FROM user_training ut
            JOIN users u ON ut.user_id = u.id
            ORDER BY ut.training_date DESC
        `);
        conn.release();
        res.json(records);
    } catch (err) {
        console.error('Error fetching training records:', err);
        res.status(500).json({ error: 'Failed to fetch training records' });
    }
});


// Update user endpoint
app.put('/fms-api/users/:id', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager']), async (req, res) => {
    const userId = req.params.id;
    const {
        first_name, last_name, email, university, company, faculty,
        institute, building, room, phone_number, profile_link,
        linkedin_link, group_website, role, facility_id, status
    } = req.body;
    
    try {
        const conn = await pool.getConnection();
        
        // Start transaction
        await conn.beginTransaction();
        
        try {
            // Update user details
            await conn.query(`
                UPDATE users
                SET first_name = ?, last_name = ?, email = ?, university = ?,
                    company = ?, faculty = ?, institute = ?, building = ?,
                    room = ?, phone_number = ?, profile_link = ?,
                    linkedin_link = ?, group_website = ?, status = ?
                WHERE id = ?
            `, [
                first_name, last_name, email, university || null,
                company || null, faculty || null, institute || null, building || null,
                room || null, phone_number || null, profile_link || null,
                linkedin_link || null, group_website || null, status, userId
            ]);
            
            // Update role if provided
            if (role) {
                // Delete existing role
                await conn.query('DELETE FROM user_roles WHERE user_id = ?', [userId]);
                
                // Insert new role
                await conn.query(
                    'INSERT INTO user_roles (user_id, role, facility_id) VALUES (?, ?, ?)',
                    [userId, role, facility_id || null]
                );
            }
            
            // Commit transaction
            await conn.commit();
            
            conn.release();
            res.json({ success: true, message: 'User updated successfully' });
        } catch (err) {
            // Rollback transaction on error
            await conn.rollback();
            conn.release();
            throw err;
        }
    } catch (err) {
        console.error('Error updating user:', err);
        res.status(500).json({ success: false, message: 'Failed to update user' });
    }
});

// Approve user endpoint
app.post('/fms-api/users/:id/approve', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager']), async (req, res) => {
    const userId = req.params.id;
    
    try {
        const conn = await pool.getConnection();
        
        // Update user status to active
        await conn.query('UPDATE users SET status = ? WHERE id = ?', ['active', userId]);
        
        // Get user details
const user = await conn.query('SELECT username, first_name, last_name, email FROM users WHERE id = ?', [userId]);

if (user.length > 0) {
    // Send approval email to the user
    await transporter.sendMail({
        from: 'fms-facilities@ncl.ac.uk',
        to: user[0].email,
        subject: 'Registration Approved - FMS Facilities',
        html: `
            <p>Hello ${user[0].first_name} ${user[0].last_name},</p>
            <p>Your registration with FMS Facilities System has been approved!</p>
            <p>You can now log in to the system using your username and password.</p>
            <p><a href="https://nusbf.ncl.ac.uk/fms-facilities/">Login here</a></p>
        `
    });
}
        conn.release();
        res.json({ success: true, message: 'User approved successfully' });
    } catch (err) {
        console.error('Error approving user:', err);
        res.status(500).json({ success: false, message: 'Failed to approve user' });
    }
});

// Archive user endpoint
app.post('/fms-api/users/:id/archive', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager']), async (req, res) => {
    const userId = req.params.id;
    
    try {
        const conn = await pool.getConnection();
        
        // Get user details for email notification
        const userQuery = await conn.query('SELECT username, first_name, last_name, email FROM users WHERE id = ?', [userId]);
        
        if (userQuery.length === 0) {
            conn.release();
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        const user = userQuery[0];
        
        // Update user status to suspended (archived)
        await conn.query('UPDATE users SET status = ? WHERE id = ?', ['suspended', userId]);
        
        // Send notification email to the user
        if (user.email) {
            try {
                await transporter.sendMail({
                    from: 'fms-facilities@ncl.ac.uk',
                    to: user.email,
                    subject: 'FMS Facilities Account Archived',
                    html: `
                        <p>Hello ${user.first_name} ${user.last_name},</p>
                        <p>Your account (username: ${user.username}) on the FMS Facilities Management System has been archived.</p>
                        <p>This means your account is currently inactive. If you have any questions or would like your account to be reactivated, please contact your facility manager.</p>
                    `
                });
            } catch (emailErr) {
                console.error('Failed to send archive notification email:', emailErr);
                // Continue with the response even if email fails
            }
        }
        
        conn.release();
        res.json({ success: true, message: 'User archived successfully' });
    } catch (err) {
        console.error('Error archiving user:', err);
        res.status(500).json({ success: false, message: 'Failed to archive user' });
    }
});

// Activate user endpoint
app.post('/fms-api/users/:id/activate', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager']), async (req, res) => {
    const userId = req.params.id;
    
    try {
        const conn = await pool.getConnection();
        
        // Get user details for email notification
        const userQuery = await conn.query('SELECT username, first_name, last_name, email FROM users WHERE id = ?', [userId]);
        
        if (userQuery.length === 0) {
            conn.release();
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        const user = userQuery[0];
        
        // Update user status to active
        await conn.query('UPDATE users SET status = ? WHERE id = ?', ['active', userId]);
        
        // Send notification email to the user
        if (user.email) {
            try {
                await transporter.sendMail({
                    from: 'fms-facilities@ncl.ac.uk',
                    to: user.email,
                    subject: 'FMS Facilities Account Reactivated',
                    html: `
                        <p>Hello ${user.first_name} ${user.last_name},</p>
                        <p>Your account (username: ${user.username}) on the FMS Facilities Management System has been reactivated.</p>
                        <p>You can now log in to the system using your username and password.</p>
                        <p><a href="https://nusbf.ncl.ac.uk/fms-facilities">Login here</a></p>
                    `
                });
            } catch (emailErr) {
                console.error('Failed to send reactivation notification email:', emailErr);
                // Continue with the response even if email fails
            }
        }
        
        conn.release();
        res.json({ success: true, message: 'User activated successfully' });
    } catch (err) {
        console.error('Error activating user:', err);
        res.status(500).json({ success: false, message: 'Failed to activate user' });
    }
});

// Delete user endpoint
app.delete('/fms-api/users/:id', authenticateToken, checkRole(['developer', 'facility_manager', 'facility_staff']), async (req, res) => {
    const userId = req.params.id;
    
    try {
        const conn = await pool.getConnection();
        
        // Check if user exists and get their details for the email
        const userQuery = await conn.query('SELECT username, first_name, last_name, email FROM users WHERE id = ?', [userId]);
        
        if (userQuery.length === 0) {
            conn.release();
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        const user = userQuery[0];
        
        // Start transaction
        await conn.beginTransaction();
        
        try {
            // Delete user roles first (due to foreign key constraint)
            await conn.query('DELETE FROM user_roles WHERE user_id = ?', [userId]);
            
            // Delete user training records if they exist
            await conn.query('DELETE FROM user_training WHERE user_id = ? AND EXISTS (SELECT 1 FROM user_training WHERE user_id = ?)', 
                [userId, userId]);
                
            // Delete any password reset tokens if they exist
            await conn.query('DELETE FROM password_reset_tokens WHERE user_id = ? AND EXISTS (SELECT 1 FROM password_reset_tokens WHERE user_id = ?)', 
                [userId, userId]);
            
            // Delete the user
            await conn.query('DELETE FROM users WHERE id = ?', [userId]);
            
            // Commit transaction
            await conn.commit();
            
            // Send notification email to the user
            if (user.email) {
                try {
                    await transporter.sendMail({
                        from: 'fms-facilities@ncl.ac.uk',
                        to: user.email,
                        subject: 'FMS Facilities Account Deleted',
                        html: `
                            <p>Hello ${user.first_name} ${user.last_name},</p>
                            <p>Your account (username: ${user.username}) on the FMS Facilities Management System has been deleted.</p>
                            <p>If you believe this was done in error or have any questions, please contact your facility manager.</p>
                        `
                    });
                } catch (emailErr) {
                    console.error('Failed to send deletion notification email:', emailErr);
                    // Continue with the response even if email fails
                }
            }
            
            conn.release();
            res.json({ 
                success: true, 
                message: 'User deleted successfully' 
            });
        } catch (err) {
            // Rollback transaction on error
            await conn.rollback();
            conn.release();
            throw err;
        }
    } catch (err) {
        console.error('Error deleting user:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to delete user. Please try again.' 
        });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
