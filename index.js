require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

// Konekcija na bazu
const db = new Pool({ connectionString: process.env.DATABASE_URL });

// Test endpoint — proveri da server radi
app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'Judo Academy server radi!' });
});

// ── RANG LISTA ──────────────────────────────────────

// Dohvati top 50
app.get('/api/leaderboard', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT username, belt, xp, club
      FROM users
      ORDER BY xp DESC
      LIMIT 50
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Ažuriraj XP korisnika
app.post('/api/xp/update', async (req, res) => {
  const { userId, xp, belt } = req.body;
  try {
    await db.query(`
      UPDATE users SET xp = $1, belt = $2 
      WHERE id = $3
    `, [xp, belt, userId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── AI SENSEI LIMITI ─────────────────────────────────

app.get('/api/sensei/limit/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await db.query(`
      SELECT questions_today, last_reset, subscription_tier
      FROM users WHERE id = $1
    `, [userId]);
    
    const user = result.rows[0];
    const today = new Date().toDateString();
    const lastReset = new Date(user.last_reset).toDateString();
    
    // Reset ako je novi dan
    if (today !== lastReset) {
      await db.query(`
        UPDATE users 
        SET questions_today = 0, last_reset = NOW() 
        WHERE id = $1
      `, [userId]);
      user.questions_today = 0;
    }
    
    const limits = { free: 5, learning: 5, competitive: 10 };
    const dailyLimit = limits[user.subscription_tier] || 5;
    
    res.json({
      used: user.questions_today,
      limit: dailyLimit,
      remaining: dailyLimit - user.questions_today
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── START ────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server radi na portu ${PORT}`);
});