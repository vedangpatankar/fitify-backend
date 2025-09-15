require("dotenv").config({ path: __dirname + "/../.env" });
// console.log("DB_USER from env:", process.env.DB_USER);

const express = require('express');
const authRoutes = require('./routes/auth');
const userDataRoutes = require('./routes/usersData'); // 👈 added
const workoutProgressRoutes = require('./routes/workoutProgress'); // 👈 added for workout progress

const app = express();

// Middleware
app.use(express.json());

// Routes
app.use('/api', authRoutes);
app.use('/api', userDataRoutes); // 👈 added
app.use('/api', workoutProgressRoutes); // 👈 added for workout progress

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
