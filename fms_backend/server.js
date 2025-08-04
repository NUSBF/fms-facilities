const express = require('express');
const mariadb = require('mariadb');
const cors = require('cors');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
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

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads');
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const timestamp = Date.now();
        const randomString = Math.random().toString(36).substring(2);
        const fileExtension = path.extname(file.originalname);
        const uniqueFileName = `${timestamp}_${randomString}${fileExtension}`;
        cb(null, uniqueFileName);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB limit
    },
    fileFilter: (req, file, cb) => {
        // Allow all file types for now
        cb(null, true);
    }
});

// Create uploads directory on server startup
const uploadsDir = path.join(__dirname, 'uploads');
fs.promises.mkdir(uploadsDir, { recursive: true })
    .then(() => {
        console.log('Uploads directory created/verified:', uploadsDir);
    })
    .catch((err) => {
        console.error('Error creating uploads directory:', err);
    });

// Serve uploaded files statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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
        console.log('Login attempt for username:', username);
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
        console.error('Login error:', err);
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
app.get('/fms-api/users', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
    try {
        const conn = await pool.getConnection();

        // Get all users with their roles and group information
        const users = await conn.query(`
            SELECT u.*, ur.role, ur.facility_id, f.short_name as facility_name, g.group_name
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN facilities f ON ur.facility_id = f.id
            LEFT JOIN groups g ON u.group_id = g.id
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
app.get('/fms-api/user-training', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
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
app.put('/fms-api/users/:id', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
    const userId = req.params.id;
    const {
        username, first_name, last_name, email, university, company, faculty,
        institute, building, room, phone_number, profile_link,
        linkedin_link, group_website, role, facility_id, group_id, status
    } = req.body;

    try {
        const conn = await pool.getConnection();

        // Start transaction
        await conn.beginTransaction();

        try {
            // Update user details
            await conn.query(`
                UPDATE users
                SET username = ?, first_name = ?, last_name = ?, email = ?, university = ?,
                    company = ?, faculty = ?, institute = ?, building = ?,
                    room = ?, phone_number = ?, profile_link = ?,
                    linkedin_link = ?, group_website = ?, group_id = ?, status = ?
                WHERE id = ?
            `, [
                username, first_name, last_name, email, university || null,
                company || null, faculty || null, institute || null, building || null,
                room || null, phone_number || null, profile_link || null,
                linkedin_link || null, group_website || null, group_id || null, status, userId
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
app.post('/fms-api/users/:id/approve', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
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
app.post('/fms-api/users/:id/archive', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
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
app.post('/fms-api/users/:id/activate', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
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

// Ticket email notification endpoint
app.post('/fms-api/tickets/notify', authenticateToken, async (req, res) => {
    try {
        const {
            ticketId,
            ticketTitle,
            ticketDescription,
            ticketPriority,
            ticketCategory,
            ticketStatus,
            userEmail,
            userName,
            facilityName,
            notificationType,
            updateMessage,
            createdDate
        } = req.body;

        // Get facility staff emails
        const conn = await pool.getConnection();
        try {
            // Get facility managers and staff for the current facility
            const facilityStaff = await conn.query(`
                SELECT DISTINCT u.email, u.first_name, u.last_name
                FROM users u
                JOIN user_roles ur ON u.id = ur.user_id
                JOIN facilities f ON ur.facility_id = f.id
                WHERE f.name = ?
                AND ur.role IN ('facility_manager', 'administrator', 'developer')
                AND u.email IS NOT NULL
            `, [facilityName]);

            conn.release();

            // Prepare email subject and content based on notification type
            let subject, userEmailContent, staffEmailContent;

            switch (notificationType) {
                case 'created':
                    subject = `New Support Ticket #${ticketId}: ${ticketTitle}`;
                    userEmailContent = `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #007bff;">Ticket Created Successfully</h2>
                            <p>Dear ${userName},</p>
                            <p>Your support ticket has been created successfully and will be reviewed by our facility staff.</p>

                            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                <h3 style="margin-top: 0;">Ticket Details:</h3>
                                <p><strong>Ticket ID:</strong> #${ticketId}</p>
                                <p><strong>Title:</strong> ${ticketTitle}</p>
                                <p><strong>Category:</strong> ${ticketCategory}</p>
                                <p><strong>Priority:</strong> ${ticketPriority}</p>
                                <p><strong>Status:</strong> ${ticketStatus}</p>
                                <p><strong>Created:</strong> ${createdDate}</p>
                                <p><strong>Description:</strong> ${ticketDescription}</p>
                            </div>

                            <p>We will notify you via email when there are updates to your ticket.</p>
                            <p>Best regards,<br/>FMS Facilities Team</p>
                        </div>
                    `;
                    staffEmailContent = `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #dc3545;">New Support Ticket Requires Attention</h2>
                            <p>A new support ticket has been submitted and requires your attention.</p>

                            <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
                                <h3 style="margin-top: 0;">Ticket Details:</h3>
                                <p><strong>Ticket ID:</strong> #${ticketId}</p>
                                <p><strong>Title:</strong> ${ticketTitle}</p>
                                <p><strong>Category:</strong> ${ticketCategory}</p>
                                <p><strong>Priority:</strong> <span style="color: ${ticketPriority === 'high' ? '#dc3545' : ticketPriority === 'medium' ? '#ffc107' : '#28a745'};">${ticketPriority.toUpperCase()}</span></p>
                                <p><strong>Status:</strong> ${ticketStatus}</p>
                                <p><strong>Submitted by:</strong> ${userName} (${userEmail})</p>
                                <p><strong>Facility:</strong> ${facilityName}</p>
                                <p><strong>Created:</strong> ${createdDate}</p>
                                <p><strong>Description:</strong> ${ticketDescription}</p>
                            </div>

                            <p>Please review and assign this ticket appropriately.</p>
                            <p>FMS Facilities System</p>
                        </div>
                    `;
                    break;

                case 'status_changed':
                    subject = `Ticket #${ticketId} Status Updated: ${ticketTitle}`;
                    userEmailContent = `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #28a745;">Ticket Status Updated</h2>
                            <p>Dear ${userName},</p>
                            <p>Your support ticket status has been updated.</p>

                            <div style="background-color: #d4edda; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                <h3 style="margin-top: 0;">Update Details:</h3>
                                <p><strong>Ticket ID:</strong> #${ticketId}</p>
                                <p><strong>Title:</strong> ${ticketTitle}</p>
                                <p><strong>New Status:</strong> ${ticketStatus.replace('_', ' ').toUpperCase()}</p>
                                <p><strong>Update:</strong> ${updateMessage}</p>
                            </div>

                            <p>Best regards,<br/>FMS Facilities Team</p>
                        </div>
                    `;
                    staffEmailContent = `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #17a2b8;">Ticket Status Updated</h2>
                            <p>Ticket #${ticketId} status has been changed.</p>

                            <div style="background-color: #d1ecf1; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                <p><strong>Ticket:</strong> ${ticketTitle}</p>
                                <p><strong>User:</strong> ${userName} (${userEmail})</p>
                                <p><strong>New Status:</strong> ${ticketStatus.replace('_', ' ').toUpperCase()}</p>
                                <p><strong>Update:</strong> ${updateMessage}</p>
                            </div>

                            <p>FMS Facilities System</p>
                        </div>
                    `;
                    break;

                case 'updated':
                    subject = `Ticket #${ticketId} Updated: ${ticketTitle}`;
                    userEmailContent = `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #17a2b8;">Ticket Updated</h2>
                            <p>Dear ${userName},</p>
                            <p>Your support ticket has been updated by our facility staff.</p>

                            <div style="background-color: #d1ecf1; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                <h3 style="margin-top: 0;">Update Details:</h3>
                                <p><strong>Ticket ID:</strong> #${ticketId}</p>
                                <p><strong>Title:</strong> ${ticketTitle}</p>
                                <p><strong>Update:</strong> ${updateMessage}</p>
                            </div>

                            <p>Best regards,<br/>FMS Facilities Team</p>
                        </div>
                    `;
                    staffEmailContent = `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #6f42c1;">Ticket Response Added</h2>
                            <p>A response has been added to ticket #${ticketId}.</p>

                            <div style="background-color: #e2e3f2; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                <p><strong>Ticket:</strong> ${ticketTitle}</p>
                                <p><strong>User:</strong> ${userName} (${userEmail})</p>
                                <p><strong>Response:</strong> ${updateMessage}</p>
                            </div>

                            <p>FMS Facilities System</p>
                        </div>
                    `;
                    break;
            }

            // Send email to user
            if (userEmail) {
                await transporter.sendMail({
                    from: 'fms-facilities@ncl.ac.uk',
                    to: userEmail,
                    subject: subject,
                    html: userEmailContent
                });
            }

            // Send emails to facility staff
            if (facilityStaff.length > 0) {
                const staffEmails = facilityStaff.map(staff => staff.email);
                await transporter.sendMail({
                    from: 'fms-facilities@ncl.ac.uk',
                    to: staffEmails.join(', '),
                    subject: `[${facilityName}] ${subject}`,
                    html: staffEmailContent
                });
            }

            res.json({
                success: true,
                message: 'Email notifications sent successfully',
                userNotified: !!userEmail,
                staffNotified: facilityStaff.length,
                facilityStaffEmails: facilityStaff.map(s => s.email)
            });

        } catch (dbErr) {
            conn.release();
            throw dbErr;
        }
    } catch (err) {
        console.error('Error sending ticket notifications:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to send email notifications',
            error: err.message
        });
    }
});

// Tools endpoints
// Get all tools
app.get('/fms-api/tools', authenticateToken, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const tools = await conn.query(`
            SELECT * FROM tools
            ORDER BY category, name
        `);
        res.json(tools);
    } catch (err) {
        console.error('Error fetching tools:', err);
        res.status(500).json({ error: 'Failed to fetch tools' });
    } finally {
        if (conn) conn.release();
    }
});

// Create new tool
app.post('/fms-api/tools', authenticateToken, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const {
            category, name, barcode, cost, manufacturer, distributor, manufacturer_website,
            date_of_purchase, status, capacity, volume, weight, holding_time, retirement_date
        } = req.body;

        // Format dates to YYYY-MM-DD format for MySQL DATE columns
        const formatDate = (dateStr) => {
            if (!dateStr) return null;
            if (dateStr.includes('T')) {
                return dateStr.split('T')[0]; // Extract YYYY-MM-DD from ISO string
            }
            return dateStr;
        };

        const formattedDateOfPurchase = formatDate(date_of_purchase);
        const formattedRetirementDate = formatDate(retirement_date);

        const result = await conn.query(`
            INSERT INTO tools (
                category, name, barcode, cost, manufacturer, distributor, manufacturer_website,
                date_of_purchase, status, capacity, volume, weight, holding_time, retirement_date,
                created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            category, name, barcode, cost, manufacturer, distributor, manufacturer_website,
            formattedDateOfPurchase, status, capacity, volume, weight, holding_time, formattedRetirementDate,
            req.user.id
        ]);

        const newTool = await conn.query('SELECT * FROM tools WHERE id = ?', [result.insertId]);
        res.status(201).json(newTool[0]);
    } catch (err) {
        console.error('Error creating tool:', err);

        // Handle specific database errors
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'A tool with this barcode already exists' });
        }

        res.status(500).json({ error: 'Failed to create tool' });
    } finally {
        if (conn) conn.release();
    }
});

// Update tool
app.put('/fms-api/tools/:id', authenticateToken, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const toolId = req.params.id;
        const {
            category, name, barcode, cost, manufacturer, distributor, manufacturer_website,
            date_of_purchase, status, capacity, volume, weight, holding_time, retirement_date
        } = req.body;

        // Format dates to YYYY-MM-DD format for MySQL DATE columns
        const formatDate = (dateStr) => {
            if (!dateStr) return null;
            if (dateStr.includes('T')) {
                return dateStr.split('T')[0]; // Extract YYYY-MM-DD from ISO string
            }
            return dateStr;
        };

        const formattedDateOfPurchase = formatDate(date_of_purchase);
        const formattedRetirementDate = formatDate(retirement_date);

        await conn.query(`
            UPDATE tools SET
                category = ?, name = ?, barcode = ?, cost = ?, manufacturer = ?,
                distributor = ?, manufacturer_website = ?, date_of_purchase = ?, status = ?,
                capacity = ?, volume = ?, weight = ?, holding_time = ?, retirement_date = ?,
                updated_by = ?, updated_at = NOW()
            WHERE id = ?
        `, [
            category, name, barcode, cost, manufacturer, distributor, manufacturer_website,
            formattedDateOfPurchase, status, capacity, volume, weight, holding_time, formattedRetirementDate,
            req.user.id, toolId
        ]);

        const updatedTool = await conn.query('SELECT * FROM tools WHERE id = ?', [toolId]);
        res.json(updatedTool[0]);
    } catch (err) {
        console.error('Error updating tool:', err);
        res.status(500).json({ error: 'Failed to update tool' });
    } finally {
        if (conn) conn.release();
    }
});

// Delete tool
app.delete('/fms-api/tools/:id', authenticateToken, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const toolId = req.params.id;

        await conn.query('DELETE FROM tools WHERE id = ?', [toolId]);
        res.json({ success: true, message: 'Tool deleted successfully' });
    } catch (err) {
        console.error('Error deleting tool:', err);
        res.status(500).json({ error: 'Failed to delete tool' });
    } finally {
        if (conn) conn.release();
    }
});

// Run network configuration scanner
app.post('/fms-api/run-network-scan', authenticateToken, async (req, res) => {
    try {
        const { exec } = require('child_process');
        const path = require('path');

        // Path to the network scanner script
        const scriptPath = path.join(__dirname, '../fms_frontend/src/scripts/network-config-scanner.sh');

        // Execute the script
        exec(`sudo ${scriptPath}`, { timeout: 30000 }, (error, stdout, stderr) => {
            if (error) {
                console.error('Network scan error:', error);
                return res.status(500).json({ error: 'Failed to run network scan', details: error.message });
            }

            if (stderr) {
                console.warn('Network scan stderr:', stderr);
            }

            // Return the full output
            res.send(stdout);
        });
    } catch (err) {
        console.error('Network scan endpoint error:', err);
        res.status(500).json({ error: 'Failed to execute network scan' });
    }
});

// Save network scan results to database
app.post('/fms-api/network-scan-results', authenticateToken, async (req, res) => {
    let conn;
    try {
        const { scan_timestamp, dhcp_count, nfs_count, unique_ips, raw_output } = req.body;
        const userId = req.user.id;

        if (!scan_timestamp || !Array.isArray(unique_ips)) {
            return res.status(400).json({ error: 'Invalid data format' });
        }

        conn = await pool.getConnection();
        await conn.beginTransaction();

        // Insert main scan result record
        const scanResult = await conn.query(
            `INSERT INTO network_scan_results
             (scan_timestamp, user_id, dhcp_count, nfs_count, unique_ip_count, raw_output)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
                new Date(scan_timestamp),
                userId,
                dhcp_count || 0,
                nfs_count || 0,
                unique_ips.length,
                raw_output || null
            ]
        );

        const scanResultId = scanResult.insertId;

        // Insert individual IP records
        if (unique_ips.length > 0) {
            const ipValues = unique_ips.map(ip => [
                scanResultId,
                ip.ip_address,
                ip.hostname || null,
                ip.source || 'unknown',
                ip.status || 'unknown'
            ]);

            await conn.batch(
                `INSERT INTO network_scan_ips
                 (scan_result_id, ip_address, hostname, source, status)
                 VALUES (?, ?, ?, ?, ?)`,
                ipValues
            );
        }

        await conn.commit();

        res.status(201).json({
            success: true,
            scan_id: scanResultId,
            message: `Network scan results saved successfully. Found ${unique_ips.length} unique IP addresses.`
        });

    } catch (err) {
        if (conn) await conn.rollback();
        console.error('Save network scan results error:', err);
        res.status(500).json({ error: 'Failed to save network scan results', details: err.message });
    } finally {
        if (conn) conn.release();
    }
});

// Get network scan results history
app.get('/fms-api/network-scan-results', authenticateToken, async (req, res) => {
    let conn;
    try {
        const { page = 1, limit = 10, start_date, end_date } = req.query;
        const offset = (page - 1) * limit;

        conn = await pool.getConnection();

        // Build WHERE clause for date filtering
        let whereClause = '';
        let params = [];

        if (start_date || end_date) {
            const conditions = [];
            if (start_date) {
                conditions.push('nsr.scan_timestamp >= ?');
                params.push(new Date(start_date));
            }
            if (end_date) {
                conditions.push('nsr.scan_timestamp <= ?');
                params.push(new Date(end_date));
            }
            whereClause = 'WHERE ' + conditions.join(' AND ');
        }

        // Get scan results with user info
        const scanResults = await conn.query(
            `SELECT
                nsr.id,
                nsr.scan_timestamp,
                nsr.dhcp_count,
                nsr.nfs_count,
                nsr.unique_ip_count,
                nsr.created_at,
                u.first_name,
                u.last_name,
                u.email
             FROM network_scan_results nsr
             JOIN users u ON nsr.user_id = u.id
             ${whereClause}
             ORDER BY nsr.scan_timestamp DESC
             LIMIT ? OFFSET ?`,
            [...params, parseInt(limit), parseInt(offset)]
        );

        // Convert BigInt values to regular numbers and get IPs for each scan
        const processedResults = [];
        for (const scanResult of scanResults) {
            const processedScanResult = {
                id: Number(scanResult.id), // Convert BigInt to Number
                scan_timestamp: scanResult.scan_timestamp,
                dhcp_count: Number(scanResult.dhcp_count), // Convert BigInt to Number
                nfs_count: Number(scanResult.nfs_count), // Convert BigInt to Number
                unique_ip_count: Number(scanResult.unique_ip_count), // Convert BigInt to Number
                created_at: scanResult.created_at,
                first_name: scanResult.first_name,
                last_name: scanResult.last_name,
                email: scanResult.email
            };

            // Get associated IP addresses for this scan
            const ipResults = await conn.query(
                `SELECT
                    ip_address,
                    hostname,
                    source,
                    status,
                    created_at
                 FROM network_scan_ips
                 WHERE scan_result_id = ?
                 ORDER BY INET_ATON(ip_address)`,
                [scanResult.id]
            );

            processedScanResult.ips = ipResults;
            processedResults.push(processedScanResult);
        }

        // Get total count for pagination
        const totalResult = await conn.query(
            `SELECT COUNT(*) as total FROM network_scan_results nsr ${whereClause}`,
            params
        );

        const total = Number(totalResult[0].total); // Convert BigInt to Number
        const totalPages = Math.ceil(total / limit);

        // Return the results in the format the frontend expects
        res.json(processedResults);

    } catch (err) {
        console.error('Get network scan results error:', err);
        res.status(500).json({ error: 'Failed to retrieve network scan results', details: err.message });
    } finally {
        if (conn) conn.release();
    }
});

// Get detailed network scan result by ID
app.get('/fms-api/network-scan-results/:id', authenticateToken, async (req, res) => {
    let conn;
    try {
        const scanId = parseInt(req.params.id);

        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Invalid scan ID' });
        }

        conn = await pool.getConnection();

        // Get scan result details
        const scanResults = await conn.query(
            `SELECT
                nsr.*,
                u.first_name,
                u.last_name,
                u.email
             FROM network_scan_results nsr
             JOIN users u ON nsr.user_id = u.id
             WHERE nsr.id = ?`,
            [scanId]
        );

        if (scanResults.length === 0) {
            return res.status(404).json({ error: 'Scan result not found' });
        }

        const scanResult = scanResults[0];

        // Get associated IP addresses
        const ipResults = await conn.query(
            `SELECT
                ip_address,
                hostname,
                source,
                status,
                created_at
             FROM network_scan_ips
             WHERE scan_result_id = ?
             ORDER BY INET_ATON(ip_address)`,
            [scanId]
        );

        res.json({
            scan_result: scanResult,
            ip_addresses: ipResults
        });

    } catch (err) {
        console.error('Get network scan result details error:', err);
        res.status(500).json({ error: 'Failed to retrieve scan result details', details: err.message });
    } finally {
        if (conn) conn.release();
    }
});

// ===== GROUPS MANAGEMENT API ROUTES =====

// Get all groups (with member count)
app.get('/fms-api/groups', authenticateToken, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const groups = await conn.query(`
            SELECT * FROM groups
            ORDER BY created_at DESC
        `);
        res.json(groups);
    } catch (error) {
        console.error('Error fetching groups:', error);
        res.status(500).json({ error: 'Failed to fetch groups' });
    } finally {
        if (conn) conn.release();
    }
});

// Get specific group
app.get('/fms-api/groups/:id', authenticateToken, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { id } = req.params;
        const query = `
            SELECT g.id, g.group_name, g.pi_name, g.pi_email, g.created_at, g.updated_at, g.archived_at,
                   COUNT(ug.user_id) as member_count
            FROM groups g
            LEFT JOIN user_groups ug ON g.id = ug.group_id
            WHERE g.id = ?
            GROUP BY g.id, g.group_name, g.pi_name, g.pi_email, g.created_at, g.updated_at, g.archived_at
        `;

        const rows = await conn.query(query, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Group not found' });
        }

        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching group:', error);
        res.status(500).json({ error: 'Failed to fetch group' });
    } finally {
        if (conn) conn.release();
    }
});

// Create new group
app.post('/fms-api/groups', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { group_name, pi_name, pi_email } = req.body;

        if (!group_name || !pi_name || !pi_email) {
            return res.status(400).json({ error: 'Group name, PI name, and PI email are required' });
        }

        const query = `
            INSERT INTO groups (group_name, pi_name, pi_email)
            VALUES (?, ?, ?)
        `;

        const result = await conn.query(query, [group_name, pi_name, pi_email]);

        res.status(201).json({
            message: 'Group created successfully',
            groupId: result.insertId
        });
    } catch (error) {
        console.error('Error creating group:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'Group name already exists' });
        } else {
            res.status(500).json({ error: 'Failed to create group' });
        }
    } finally {
        if (conn) conn.release();
    }
});

// Update group
app.put('/fms-api/groups/:id', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { id } = req.params;
        const { group_name, pi_name, pi_email } = req.body;

        if (!group_name || !pi_name || !pi_email) {
            return res.status(400).json({ error: 'Group name, PI name, and PI email are required' });
        }

        const query = `
            UPDATE groups
            SET group_name = ?, pi_name = ?, pi_email = ?, updated_at = NOW()
            WHERE id = ?
        `;

        const result = await conn.query(query, [group_name, pi_name, pi_email, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Group not found' });
        }

        res.json({ message: 'Group updated successfully' });
    } catch (error) {
        console.error('Error updating group:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'Group name already exists' });
        } else {
            res.status(500).json({ error: 'Failed to update group' });
        }
    } finally {
        if (conn) conn.release();
    }
});

// Archive group (soft delete)
app.patch('/fms-api/groups/:id/archive', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { id } = req.params;

        const query = `
            UPDATE groups
            SET archived_at = NOW(), updated_at = NOW()
            WHERE id = ? AND archived_at IS NULL
        `;

        const result = await conn.query(query, [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Group not found or already archived' });
        }

        res.json({ message: 'Group archived successfully' });
    } catch (error) {
        console.error('Error archiving group:', error);
        res.status(500).json({ error: 'Failed to archive group' });
    } finally {
        if (conn) conn.release();
    }
});

// Restore group (unarchive)
app.patch('/fms-api/groups/:id/restore', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { id } = req.params;

        const query = `
            UPDATE groups
            SET archived_at = NULL, updated_at = NOW()
            WHERE id = ? AND archived_at IS NOT NULL
        `;

        const result = await conn.query(query, [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Group not found or not archived' });
        }

        res.json({ message: 'Group restored successfully' });
    } catch (error) {
        console.error('Error restoring group:', error);
        res.status(500).json({ error: 'Failed to restore group' });
    } finally {
        if (conn) conn.release();
    }
});

// Delete group permanently
app.delete('/fms-api/groups/:id', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { id } = req.params;

        // First delete user_groups relationships
        await conn.query('DELETE FROM user_groups WHERE group_id = ?', [id]);

        // Then delete the group
        const result = await conn.query('DELETE FROM groups WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Group not found' });
        }

        res.json({ message: 'Group deleted successfully' });
    } catch (error) {
        console.error('Error deleting group:', error);
        res.status(500).json({ error: 'Failed to delete group' });
    } finally {
        if (conn) conn.release();
    }
});

// Get users in a specific group
app.get('/fms-api/groups/:id/users', authenticateToken, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { id } = req.params;

        const query = `
            SELECT u.id, u.first_name, u.last_name, u.email, ug.created_at as joined_at
            FROM users u
            JOIN user_groups ug ON u.id = ug.user_id
            WHERE ug.group_id = ?
            ORDER BY u.last_name, u.first_name
        `;

        const rows = await conn.query(query, [id]);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching group users:', error);
        res.status(500).json({ error: 'Failed to fetch group users' });
    } finally {
        if (conn) conn.release();
    }
});

// Add user to group
app.post('/fms-api/groups/:groupId/users/:userId', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { groupId, userId } = req.params;

        const query = `
            INSERT INTO user_groups (user_id, group_id)
            VALUES (?, ?)
        `;

        await conn.query(query, [userId, groupId]);

        res.status(201).json({ message: 'User added to group successfully' });
    } catch (error) {
        console.error('Error adding user to group:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'User is already in this group' });
        } else {
            res.status(500).json({ error: 'Failed to add user to group' });
        }
    } finally {
        if (conn) conn.release();
    }
});

// Remove user from group
app.delete('/fms-api/groups/:groupId/users/:userId', authenticateToken, checkRole(['developer', 'administrator', 'facility_manager', 'facility_staff']), async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const { groupId, userId } = req.params;

        const result = await conn.query(
            'DELETE FROM user_groups WHERE user_id = ? AND group_id = ?',
            [userId, groupId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found in this group' });
        }

        res.json({ message: 'User removed from group successfully' });
    } catch (error) {
        console.error('Error removing user from group:', error);
        res.status(500).json({ error: 'Failed to remove user from group' });
    } finally {
        if (conn) conn.release();
    }
});

// File Upload Management Endpoints

// Test endpoint to verify file upload routes are working
app.get('/fms-api/file-uploads-test', authenticateToken, async (req, res) => {
    res.json({ message: 'File upload routes are working', timestamp: new Date().toISOString() });
});

// Get all file uploads
app.get('/fms-api/file-uploads', authenticateToken, async (req, res) => {
    console.log('DEBUG: GET /fms-api/file-uploads endpoint hit');
    let conn;
    try {
        console.log('DEBUG: Attempting to get database connection');
        conn = await pool.getConnection();
        console.log('DEBUG: Database connection obtained');

        const fileUploads = await conn.query(`
            SELECT fu.*, f.short_name as facility_name, u.first_name, u.last_name, u.username
            FROM file_uploads fu
            LEFT JOIN facilities f ON fu.facility_id = f.id
            LEFT JOIN users u ON fu.uploaded_by = u.id
            WHERE fu.is_active = TRUE
            ORDER BY fu.upload_timestamp DESC
        `);
        console.log('DEBUG: Query executed, found', fileUploads.length, 'file uploads');

        // Convert BigInt values to regular numbers for JSON serialization
        const serializedFileUploads = fileUploads.map(upload => {
            const serialized = {};
            for (const [key, value] of Object.entries(upload)) {
                serialized[key] = typeof value === 'bigint' ? Number(value) : value;
            }
            return serialized;
        });
        console.log('DEBUG: File uploads serialized, sending response');

        res.json(serializedFileUploads);
    } catch (err) {
        console.error('ERROR in GET /fms-api/file-uploads:', err);
        res.status(500).json({ error: 'Failed to fetch file uploads' });
    } finally {
        if (conn) {
            console.log('DEBUG: Releasing database connection');
            conn.release();
        }
    }
});

// Get file uploads by facility
app.get('/fms-api/file-uploads/facility/:facilityId', authenticateToken, async (req, res) => {
    let conn;
    try {
        const { facilityId } = req.params;
        conn = await pool.getConnection();
        const fileUploads = await conn.query(`
            SELECT fu.*, f.short_name as facility_name, u.first_name, u.last_name, u.username
            FROM file_uploads fu
            LEFT JOIN facilities f ON fu.facility_id = f.id
            LEFT JOIN users u ON fu.uploaded_by = u.id
            WHERE fu.facility_id = ? AND fu.is_active = TRUE
            ORDER BY fu.upload_timestamp DESC
        `, [facilityId]);
        res.json(fileUploads);
    } catch (err) {
        console.error('Error fetching facility file uploads:', err);
        res.status(500).json({ error: 'Failed to fetch facility file uploads' });
    } finally {
        if (conn) conn.release();
    }
});

// Create new file upload record with actual file upload
app.post('/fms-api/file-uploads', authenticateToken, upload.single('file'), async (req, res) => {
    let conn;
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const {
            facility_id,
            file_category,
            description
        } = req.body;

        if (!facility_id) {
            return res.status(400).json({ error: 'Facility ID is required' });
        }

        const uploaded_by = req.user.id;
        const file_path = `/uploads/${req.file.filename}`;

        conn = await pool.getConnection();
        const result = await conn.query(`
            INSERT INTO file_uploads (
                facility_id, file_name, original_name, file_path, file_type,
                file_size, file_category, description, uploaded_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            facility_id,
            req.file.filename,
            req.file.originalname,
            file_path,
            req.file.mimetype,
            req.file.size,
            file_category || 'document',
            description || '',
            uploaded_by
        ]);

        res.json({
            message: 'File uploaded successfully',
            fileId: result.insertId,
            file: {
                id: result.insertId,
                original_name: req.file.originalname,
                file_name: req.file.filename,
                file_path: file_path,
                file_size: req.file.size,
                file_type: req.file.mimetype,
                file_category: file_category || 'document'
            }
        });
    } catch (err) {
        console.error('Error uploading file:', err);
        // Clean up uploaded file if database insert fails
        if (req.file && req.file.path) {
            try {
                await fs.promises.unlink(req.file.path);
            } catch (unlinkErr) {
                console.error('Error cleaning up file:', unlinkErr);
            }
        }
        res.status(500).json({ error: 'Failed to upload file' });
    } finally {
        if (conn) conn.release();
    }
});

// Update file upload record
app.put('/fms-api/file-uploads/:id', authenticateToken, async (req, res) => {
    let conn;
    try {
        const { id } = req.params;
        const { description, file_category } = req.body;

        conn = await pool.getConnection();
        await conn.query(`
            UPDATE file_uploads
            SET description = ?, file_category = ?
            WHERE id = ?
        `, [description, file_category, id]);

        res.json({ message: 'File upload record updated successfully' });
    } catch (err) {
        console.error('Error updating file upload record:', err);
        res.status(500).json({ error: 'Failed to update file upload record' });
    } finally {
        if (conn) conn.release();
    }
});

// Delete file upload record (soft delete)
app.delete('/fms-api/file-uploads/:id', authenticateToken, async (req, res) => {
    let conn;
    try {
        const { id } = req.params;

        conn = await pool.getConnection();

        // First, get the file information
        const fileInfo = await conn.query(`
            SELECT file_path, file_name
            FROM file_uploads
            WHERE id = ?
        `, [id]);

        if (fileInfo.length === 0) {
            return res.status(404).json({ error: 'File not found' });
        }

        const filePath = path.join(__dirname, fileInfo[0].file_path);

        // Delete the physical file
        try {
            await fs.promises.unlink(filePath);
        } catch (fsErr) {
            console.warn('File not found on disk, continuing with database deletion:', fsErr.message);
        }

        // Delete from database (cascade delete will handle related records)
        await conn.query(`
            DELETE FROM file_uploads
            WHERE id = ?
        `, [id]);

        res.json({ message: 'File deleted successfully' });
    } catch (err) {
        console.error('Error deleting file upload record:', err);
        res.status(500).json({ error: 'Failed to delete file upload record' });
    } finally {
        if (conn) conn.release();
    }
});

// Get user preferences
app.get('/fms-api/user-preferences', authenticateToken, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();

        const preferences = await conn.query(`
            SELECT
                up.*,
                facility_file.file_path as facility_logo_path,
                facility_file.original_name as facility_logo_name,
                user_file.file_path as user_image_path,
                user_file.original_name as user_image_name
            FROM user_preferences up
            LEFT JOIN file_uploads facility_file ON up.facility_logo_file_id = facility_file.id
            LEFT JOIN file_uploads user_file ON up.user_image_file_id = user_file.id
            WHERE up.user_id = ?
        `, [req.user.id]);

        if (preferences.length === 0) {
            // Return default preferences if none exist
            res.json({
                user_id: req.user.id,
                facility_logo_file_id: null,
                user_image_file_id: null,
                facility_logo_path: null,
                user_image_path: null,
                theme: 'light',
                language: 'en',
                notifications: true,
                auto_save: true,
                default_view: 'facilities'
            });
        } else {
            res.json(preferences[0]);
        }
    } catch (err) {
        console.error('Error fetching user preferences:', err);
        res.status(500).json({ error: 'Failed to fetch user preferences' });
    } finally {
        if (conn) conn.release();
    }
});

// Create or update user preferences
app.put('/fms-api/user-preferences', authenticateToken, async (req, res) => {
    let conn;
    try {
        const {
            facility_logo_file_id,
            user_image_file_id,
            theme,
            language,
            notifications,
            auto_save,
            default_view
        } = req.body;

        conn = await pool.getConnection();

        // Check if preferences already exist
        const existing = await conn.query(
            'SELECT id FROM user_preferences WHERE user_id = ?',
            [req.user.id]
        );

        if (existing.length > 0) {
            // Update existing preferences
            await conn.query(`
                UPDATE user_preferences SET
                    facility_logo_file_id = ?,
                    user_image_file_id = ?,
                    theme = ?,
                    language = ?,
                    notifications = ?,
                    auto_save = ?,
                    default_view = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            `, [
                facility_logo_file_id || null,
                user_image_file_id || null,
                theme || 'light',
                language || 'en',
                notifications !== undefined ? notifications : true,
                auto_save !== undefined ? auto_save : true,
                default_view || 'facilities',
                req.user.id
            ]);
        } else {
            // Create new preferences
            await conn.query(`
                INSERT INTO user_preferences (
                    user_id,
                    facility_logo_file_id,
                    user_image_file_id,
                    theme,
                    language,
                    notifications,
                    auto_save,
                    default_view
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                req.user.id,
                facility_logo_file_id || null,
                user_image_file_id || null,
                theme || 'light',
                language || 'en',
                notifications !== undefined ? notifications : true,
                auto_save !== undefined ? auto_save : true,
                default_view || 'facilities'
            ]);
        }

        // Fetch and return updated preferences
        const updatedPreferences = await conn.query(`
            SELECT
                up.*,
                facility_file.file_path as facility_logo_path,
                facility_file.original_name as facility_logo_name,
                user_file.file_path as user_image_path,
                user_file.original_name as user_image_name
            FROM user_preferences up
            LEFT JOIN file_uploads facility_file ON up.facility_logo_file_id = facility_file.id
            LEFT JOIN file_uploads user_file ON up.user_image_file_id = user_file.id
            WHERE up.user_id = ?
        `, [req.user.id]);

        res.json(updatedPreferences[0]);
    } catch (err) {
        console.error('Error updating user preferences:', err);
        res.status(500).json({ error: 'Failed to update user preferences' });
    } finally {
        if (conn) conn.release();
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
