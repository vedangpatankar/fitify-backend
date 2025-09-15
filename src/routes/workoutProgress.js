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

// POST /workout-progress - Save workout progress
router.post('/workout-progress', authenticateToken, async (req, res) => {
  const { category, workout_title, exercises_count, calories_burned } = req.body;
  const userId = req.user.id;

  try {
    // Validate required fields
    if (!category || !workout_title) {
      return res.status(400).json({ error: 'Category and workout title are required' });
    }

    // Check if this workout has already been completed by the user
    const checkResult = await pool.query(
      `SELECT id FROM workout_progress 
       WHERE user_id = $1 AND workout_title = $2 
       LIMIT 1`,
      [userId, workout_title]
    );

    if (checkResult.rows.length > 0) {
      return res.status(409).json({ 
        error: 'This workout has already been completed',
        data: { already_completed: true }
      });
    }

    const result = await pool.query(
      `INSERT INTO workout_progress (user_id, category, workout_title, exercises_count, calories_burned)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [userId, category, workout_title, exercises_count || 0, calories_burned || 0]
    );

    res.status(201).json({
      message: "Workout progress saved successfully",
      data: result.rows[0]
    });
  } catch (err) {
    console.error("Workout progress insert error:", err);
    res.status(500).json({ error: 'Server error while saving workout progress' });
  }
});

// GET /workout-progress - Fetch user's workout progress
router.get('/workout-progress', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const result = await pool.query(
      `SELECT category, workout_title, completed_at, exercises_count, calories_burned 
       FROM workout_progress 
       WHERE user_id = $1 
       ORDER BY completed_at DESC`,
      [userId]
    );
    
    res.json({
      message: "Workout progress retrieved successfully",
      data: result.rows
    });
  } catch (err) {
    console.error("Error fetching workout progress:", err);
    res.status(500).json({ error: 'Server error while fetching workout progress' });
  }
});

// GET /workout-progress/check - Check if a workout has been completed
router.get('/workout-progress/check', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { workout_title } = req.query;

  if (!workout_title) {
    return res.status(400).json({ error: 'Workout title is required' });
  }

  try {
    const result = await pool.query(
      `SELECT id FROM workout_progress 
       WHERE user_id = $1 AND workout_title = $2 
       LIMIT 1`,
      [userId, workout_title]
    );
    
    const completed = result.rows.length > 0;
    
    res.json({
      completed
    });
  } catch (err) {
    console.error("Error checking workout completion:", err);
    res.status(500).json({ error: 'Server error while checking workout completion' });
  }
});

// GET /workout-progress/summary - Get summary of workouts by category
router.get('/workout-progress/summary', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const result = await pool.query(
      `SELECT category, COUNT(*) as workout_count, 
              SUM(exercises_count) as total_exercises,
              SUM(calories_burned) as total_calories,
              MAX(completed_at) as last_workout_date
       FROM workout_progress 
       WHERE user_id = $1 
       GROUP BY category 
       ORDER BY last_workout_date DESC`,
      [userId]
    );
    
    res.json({
      message: "Workout summary retrieved successfully",
      data: result.rows
    });
  } catch (err) {
    console.error("Error fetching workout summary:", err);
    res.status(500).json({ error: 'Server error while fetching workout summary' });
  }
});

// GET /workout-progress/check/:workout_title - Check if a workout has been completed
router.get('/workout-progress/check/:workout_title', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { workout_title } = req.params;

  try {
    const result = await pool.query(
      `SELECT id FROM workout_progress 
       WHERE user_id = $1 AND workout_title = $2 
       LIMIT 1`,
      [userId, workout_title]
    );
    
    res.json({
      message: "Workout check completed",
      data: { 
        completed: result.rows.length > 0,
        workout_title
      }
    });
  } catch (err) {
    console.error("Error checking workout completion:", err);
    res.status(500).json({ error: 'Server error while checking workout completion' });
  }
});

module.exports = router;