const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../db');
const crypto = require('crypto'); // for OTP generation
const nodemailer = require('nodemailer'); // 👈 for sending emails

const router = express.Router();

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer <token>"

  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user; // { id, email }
    next();
  });
}

// ================== NODEMAILER TRANSPORTER ==================
const transporter = nodemailer.createTransport({
  service: 'gmail', // 👈 you can change this to Outlook, Yahoo, etc.
  auth: {
    user: process.env.EMAIL_USER, // 👈 set in .env
    pass: process.env.EMAIL_PASS, // 👈 app password (not normal password)
  },
});

// ================== EXISTING ROUTES ==================

// POST /register
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email',
      [name, email, hashedPassword]
    );

    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(201).json({ token });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ================== FORGOT/RESET PASSWORD ==================

// POST /forgot-password (generate OTP)
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'User not found' });

    const otp = crypto.randomInt(100000, 999999).toString();
    const expiry = new Date(Date.now() + 15 * 60 * 1000);

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE id = $3',
      [otp, expiry, user.id]
    );

    // Send OTP via email
    const mailOptions = {
      from: `"Fitify App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: '🔑 Your Fitify Password Reset OTP',
      text: `Hello ${user.name || ''},

We received a request to reset your password for your Fitify account.

👉 Your OTP code is: ${otp}

⚠️ This OTP is valid for 15 minutes. Do not share it with anyone.

If you did not request this password reset, please ignore this email.

Stay fit,  
The Fitify Team`,

      html: `
    <div style="font-family: Arial, sans-serif; padding: 20px; line-height: 1.6;">
      <h2 style="color: #2E86C1;">Fitify Password Reset</h2>
      <p>Hello <b>${user.name || ''}</b>,</p>
      <p>We received a request to reset your password for your <b>Fitify</b> account.</p>
      
      <div style="margin: 20px 0; padding: 15px; border: 1px solid #ddd; background: #f9f9f9; text-align: center;">
        <h3 style="color: #E74C3C;">Your OTP Code</h3>
        <p style="font-size: 22px; font-weight: bold; letter-spacing: 3px; color: #333;">${otp}</p>
      </div>

      <p style="color: #E67E22;">⚠️ This OTP is valid for 15 minutes. Do not share it with anyone.</p>
      
      <p>If you did not request this password reset, you can safely ignore this email.</p>
      
      <p style="margin-top: 30px;">Stay fit,<br><b>The Fitify Team</b></p>
    </div>
  `,
    };


    await transporter.sendMail(mailOptions);

    res.json({ message: 'OTP sent to email' });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /reset-password (verify OTP & set new password)
router.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND reset_token = $2 AND reset_token_expiry > NOW()',
      [email, otp]
    );
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid or expired OTP' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await pool.query(
      'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2',
      [hashedPassword, user.id]
    );

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /change-password (change password when logged in)
router.post('/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id;

  try {
    // Verify current password
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const user = userResult.rows[0];
    
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!passwordMatch) return res.status(400).json({ error: 'Current password is incorrect' });
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    // Update password
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [hashedPassword, userId]
    );
    
    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
