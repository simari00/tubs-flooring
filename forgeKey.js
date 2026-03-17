const bcrypt = require('bcrypt');
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME
});

async function createMasterAdmin() {
    const username = 'simari';
    const plainTextPassword = '2004';

    try {
        // 1. Scramble the password 10 times
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(plainTextPassword, salt);

        // 2. Inject it into the vault
        await pool.query(
            'INSERT INTO admins (username, password_hash) VALUES ($1, $2)',
            [username, hashedPassword]
        );

        console.log(`[SUCCESS] Master Admin '${username}' forged securely.`);
        process.exit();
    } catch (err) {
        console.error('[FATAL ERROR]', err.message);
        process.exit(1);
    }
}

createMasterAdmin();