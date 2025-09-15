const express = require('express');
const jwt = require('jsonwebtoken');
const pool = require('../db');

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

// POST /userdata
router.post('/userdata', authenticateToken, async (req, res) => {
  let { gender, age, weight, height, goal, activity_level } = req.body;
  const userId = req.user.id;

  try {
    // ✅ Sanitize values
    age = age && age !== "" ? Number(age) : null;
    weight = weight && weight !== "" ? Number(weight) : null;
    height = height && height !== "" ? Number(height) : null;

    const result = await pool.query(
      `INSERT INTO users_data (user_id, gender, age, weight, height, goal, activity_level)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [userId, gender, age, weight, height, goal, activity_level]
    );

    res.status(201).json({
      message: "User data saved successfully",
      data: result.rows[0]
    });
  } catch (err) {
    console.error("User data insert error:", err);
    res.status(500).json({ error: 'Server error while saving user data' });
  }
});

// GET /userdata - Fetch user data
router.get('/userdata', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    // First, get basic user info from users table
    const userResult = await pool.query('SELECT name, email FROM users WHERE id = $1', [userId]);
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Then, get additional user data from users_data table
    const dataResult = await pool.query(
      'SELECT gender, age, weight, height, goal, activity_level FROM users_data WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
      [userId]
    );
    
    // Combine the data
    const userData = {
      ...userResult.rows[0],
      ...(dataResult.rows.length > 0 ? dataResult.rows[0] : {})
    };
    
    res.json({
      message: "User data retrieved successfully",
      data: userData
    });
  } catch (err) {
    console.error("Error fetching user data:", err);
    res.status(500).json({ error: 'Server error while fetching user data' });
  }
});

// PUT /userdata/update - Update specific user data fields (age, weight, height)
router.put('/userdata/update', authenticateToken, async (req, res) => {
  let { age, weight, height } = req.body;
  const userId = req.user.id;

  try {
    // Sanitize values
    age = age && age !== "" ? Number(age) : null;
    weight = weight && weight !== "" ? Number(weight) : null;
    height = height && height !== "" ? Number(height) : null;

    // Get the latest user data record
    const latestDataResult = await pool.query(
      'SELECT gender, goal, activity_level FROM users_data WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
      [userId]
    );
    
    if (latestDataResult.rows.length === 0) {
      return res.status(404).json({ error: 'No existing user data found' });
    }
    
    const latestData = latestDataResult.rows[0];
    
    // Update the existing record with new values while keeping other fields the same
    const result = await pool.query(
      `UPDATE users_data 
       SET age = $1, weight = $2, height = $3
       WHERE user_id = $4
       RETURNING *`,
      [age, weight, height, userId]
    );

    res.json({
      message: "User data updated successfully",
      data: result.rows[0]
    });
  } catch (err) {
    console.error("User data update error:", err);
    res.status(500).json({ error: 'Server error while updating user data' });
  }
});

module.exports = router;
