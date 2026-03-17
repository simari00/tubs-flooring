const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();

const app = express();

// ==========================================
// 1. MIDDLEWARE & CLOUD STORAGE ENGINE
// ==========================================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configure Cloudinary with your .env credentials
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Instruct Cloudinary to auto-resize and convert images to WebP
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'tubs_flooring',
        allowedFormats: ['jpg', 'png', 'jpeg', 'webp'],
        transformation: [{ width: 1000, height: 1000, crop: 'limit' }, { quality: 'auto', fetch_format: 'webp' }]
    }
});

const upload = multer({ storage: storage });
// ==========================================
// 2. DATABASE VAULT CONNECTION
// ==========================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Required by Neon for cloud connections
    }
});

pool.connect()
    .then(() => console.log('[DATABASE] Cloud Vault connected successfully. 🟢'))
    .catch(err => console.error('[DATABASE] Connection FAILED. 🔴', err.stack));

// ==========================================
// 3. THE BOUNCER (SECURITY MIDDLEWARE)
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    if (!token) return res.status(401).json({ error: "Access Denied." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Badge Expired." });
        req.user = user;
        next(); 
    });
};

// ==========================================
// 4. API ROUTES (THE CMS ENGINE)
// ==========================================

// --- AUTHENTICATION ---
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const userResult = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
        if (userResult.rows.length === 0) return res.status(401).json({ error: "Access Denied" });
        
        const validPassword = await bcrypt.compare(password, userResult.rows[0].password_hash);
        if (!validPassword) return res.status(401).json({ error: "Access Denied" });
        
        const token = jwt.sign({ id: userResult.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '2h' });
        res.json({ success: true, token: token });
    } catch (err) { res.status(500).json({ error: "Server error." }); }
});

// --- PORTFOLIO (Projects) ---
app.get('/api/projects', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM projects ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Failed to fetch." }); }
});

app.post('/api/projects', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { title, category, description } = req.body;
        if (!req.file) return res.status(400).json({ error: "Image required." });
        const image_url = req.file.path; // Cloudinary live URL
        const result = await pool.query('INSERT INTO projects (title, category, image_url, description) VALUES ($1, $2, $3, $4) RETURNING *', [title, category, image_url, description]);
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: "Upload failed." }); }
});

app.put('/api/projects/:id', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, category, description } = req.body;
        if (req.file) {
            const image_url = req.file.path; // Cloudinary live URL
            const result = await pool.query('UPDATE projects SET title=$1, category=$2, description=$3, image_url=$4 WHERE id=$5 RETURNING *', [title, category, description, image_url, id]);
            res.json(result.rows[0]);
        } else {
            const result = await pool.query('UPDATE projects SET title=$1, category=$2, description=$3 WHERE id=$4 RETURNING *', [title, category, description, id]);
            res.json(result.rows[0]);
        }
    } catch (err) { res.status(500).json({ error: "Update failed." }); }
});

app.delete('/api/projects/:id', authenticateToken, async (req, res) => {
    try { await pool.query('DELETE FROM projects WHERE id = $1', [req.params.id]); res.json({ message: "Deleted" }); } 
    catch (err) { res.status(500).json({ error: "Delete failed." }); }
});

// --- PRODUCT RANGE ---
app.get('/api/products', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM products ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Failed to fetch." }); }
});

app.post('/api/products', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { title, category, description } = req.body;
        if (!req.file) return res.status(400).json({ error: "Image required." });
        const image_url = req.file.path; // Cloudinary live URL
        const result = await pool.query('INSERT INTO products (title, category, image_url, description) VALUES ($1, $2, $3, $4) RETURNING *', [title, category, image_url, description]);
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: "Upload failed." }); }
});

app.put('/api/products/:id', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, category, description } = req.body;
        if (req.file) {
            const image_url = req.file.path; // Cloudinary live URL
            const result = await pool.query('UPDATE products SET title=$1, category=$2, description=$3, image_url=$4 WHERE id=$5 RETURNING *', [title, category, description, image_url, id]);
            res.json(result.rows[0]);
        } else {
            const result = await pool.query('UPDATE products SET title=$1, category=$2, description=$3 WHERE id=$4 RETURNING *', [title, category, description, id]);
            res.json(result.rows[0]);
        }
    } catch (err) { res.status(500).json({ error: "Update failed." }); }
});

app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try { await pool.query('DELETE FROM products WHERE id = $1', [req.params.id]); res.json({ message: "Deleted" }); } 
    catch (err) { res.status(500).json({ error: "Delete failed." }); }
});

// --- AFTERCARE ---
app.get('/api/aftercare', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM aftercare ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Failed to fetch." }); }
});

app.post('/api/aftercare', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { title, content } = req.body;
        const image_url = req.file ? req.file.path : null; 
        const result = await pool.query('INSERT INTO aftercare (title, content, image_url) VALUES ($1, $2, $3) RETURNING *', [title, content, image_url]);
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: "Upload failed." }); }
});

app.put('/api/aftercare/:id', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, content } = req.body;
        if (req.file) {
            const image_url = req.file.path; // Cloudinary live URL
            const result = await pool.query('UPDATE aftercare SET title=$1, content=$2, image_url=$3 WHERE id=$4 RETURNING *', [title, content, image_url, id]);
            res.json(result.rows[0]);
        } else {
            const result = await pool.query('UPDATE aftercare SET title=$1, content=$2 WHERE id=$3 RETURNING *', [title, content, id]);
            res.json(result.rows[0]);
        }
    } catch (err) { res.status(500).json({ error: "Update failed." }); }
});

app.delete('/api/aftercare/:id', authenticateToken, async (req, res) => {
    try { await pool.query('DELETE FROM aftercare WHERE id = $1', [req.params.id]); res.json({ message: "Deleted" }); } 
    catch (err) { res.status(500).json({ error: "Delete failed." }); }
});

// --- WOOD FINISHES ---
app.get('/api/finishes', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM finishes ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Failed to fetch." }); }
});

app.post('/api/finishes', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { title } = req.body;
        if (!req.file) return res.status(400).json({ error: "Image required." });
        const image_url = req.file.path; // Cloudinary live URL
        const result = await pool.query('INSERT INTO finishes (title, image_url) VALUES ($1, $2) RETURNING *', [title, image_url]);
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: "Upload failed." }); }
});

app.put('/api/finishes/:id', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title } = req.body;
        if (req.file) {
            const image_url = req.file.path; // Cloudinary live URL
            const result = await pool.query('UPDATE finishes SET title=$1, image_url=$2 WHERE id=$3 RETURNING *', [title, image_url, id]);
            res.json(result.rows[0]);
        } else {
            const result = await pool.query('UPDATE finishes SET title=$1 WHERE id=$2 RETURNING *', [title, id]);
            res.json(result.rows[0]);
        }
    } catch (err) { res.status(500).json({ error: "Update failed." }); }
});

app.delete('/api/finishes/:id', authenticateToken, async (req, res) => {
    try { await pool.query('DELETE FROM finishes WHERE id = $1', [req.params.id]); res.json({ message: "Deleted" }); } 
    catch (err) { res.status(500).json({ error: "Delete failed." }); }
});

// --- LEADS / EMAIL ---
app.get('/api/leads', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM leads ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: "Failed to fetch." }); }
});

app.post('/api/leads', async (req, res) => {
    try {
        const { client_name, client_email, project_location, estimated_sqm, message } = req.body;
        await pool.query('INSERT INTO leads (client_name, client_email, project_location, estimated_sqm, message) VALUES ($1, $2, $3, $4, $5)', [client_name, client_email, project_location, estimated_sqm, message]);
        
        const transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } });
        await transporter.sendMail({
            from: process.env.EMAIL_USER, to: process.env.RECEIVING_EMAIL,
            subject: `🚨 NEW LEAD: ${client_name}`,
            html: `<p>New project from ${client_name} (${estimated_sqm} sqm).<br>Message: ${message}</p>`
        });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: "Failed to submit lead." }); }
});

// ==========================================
// 5. FRONTEND CLEAN URL ROUTES
// ==========================================
app.get('/portfolio', (req, res) => res.sendFile(path.join(__dirname, 'public', 'portfolio.html')));
app.get('/products', (req, res) => res.sendFile(path.join(__dirname, 'public', 'products.html')));
app.get('/aftercare', (req, res) => res.sendFile(path.join(__dirname, 'public', 'aftercare.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, 'public', 'about.html')));
app.get('/contact', (req, res) => res.sendFile(path.join(__dirname, 'public', 'contact.html')));

// ==========================================
// 6. START ENGINE
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => { console.log(`[SERVER] Engine running on port ${PORT}`); });