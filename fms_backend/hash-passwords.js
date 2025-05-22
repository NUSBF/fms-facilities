const bcrypt = require('bcrypt');
const mariadb = require('mariadb');
require('dotenv').config();

const pool = mariadb.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'FMS_Facilities',
    connectionLimit: 5
});

async function hashPasswords() {
    const conn = await pool.getConnection();
    
    try {
        // Get all users
        const users = await conn.query('SELECT id, password_hash FROM users');
        
        for (let user of users) {
            // If password_hash looks like plaintext (not a hash), hash it
            if (user.password_hash === 'password') {
                const hashedPassword = await bcrypt.hash('password', 10);
                await conn.query(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    [hashedPassword, user.id]
                );
                console.log(`Updated password for user ID ${user.id}`);
            }
        }
        
        console.log('Password hashing complete');
    } catch (err) {
        console.error('Error:', err);
    } finally {
        conn.release();
        process.exit(0);
    }
}

hashPasswords();
