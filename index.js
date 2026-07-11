if (process.env.NODE_ENV !== 'production') { require('dotenv').config(); }
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Pool } = require('pg');

const app = express();
app.use(cors({ origin: '*', credentials: false }));
app.use(express.json());
app.use(session({ secret: process.env.SESSION_SECRET || 'judo2024', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static('public'));

const db = new Pool({ connectionString: process.env.DATABASE_URL });

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const name = profile.displayName;
    const googleId = profile.id;
    let result = await db.query('SELECT * FROM users WHERE google_id = $1', [googleId]);
    if (result.rows.length === 0) {
      result = await db.query('INSERT INTO users (username, email, google_id) VALUES ($1, $2, $3) RETURNING *', [name, email, googleId]);
    }
    return done(null, result.rows[0]);
  } catch (err) { return done(err); }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
  done(null, result.rows[0]);
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  const user = req.user;
  res.redirect('/auth-success?userId=' + user.id + '&username=' + encodeURIComponent(user.username) + '&belt=' + (user.belt || 'white') + '&xp=' + (user.xp || 0));
});

app.get('/auth-success', (req, res) => {
  const { userId, username, belt, xp } = req.query;
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
    <script>
      try {
        window.localStorage.setItem('judo_auth_pending', JSON.stringify({
          userId: '${userId}',
          username: '${username}',
          belt: '${belt || "white"}',
          xp: '${xp || "0"}'
        }));
      } catch(e) {}
      setTimeout(function(){ window.location.href = '/'; }, 200);
    </script>
    <p>Ulogovan! Preusmeravamo...</p>
  </body></html>`);
});

app.get('/auth/me', (req, res) => {
  if (req.user) res.json(req.user);
  else res.status(401).json({ error: 'Nije ulogovan' });
});

// ── HEALTH ───────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'Judo Academy server radi!' });
});

// ── KORISNIK ─────────────────────────────────────────

app.get('/api/user/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await db.query(
      'SELECT id, username, email, belt, xp, club, country, subscription_tier FROM users WHERE id = $1',
      [userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Nije pronadjen' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/user/update', async (req, res) => {
  const { userId, club, country } = req.body;
  if (!userId) return res.status(400).json({ error: 'Nedostaje userId' });
  try {
    await db.query(
      'UPDATE users SET club = $1, country = $2 WHERE id = $3',
      [club || null, country || null, userId]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── RANG LISTA ──────────────────────────────────────

app.get('/api/leaderboard', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT username, belt, xp, club, country FROM users ORDER BY xp DESC LIMIT 50'
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/xp/update', async (req, res) => {
  const { userId, xp, belt } = req.body;
  try {
    await db.query('UPDATE users SET xp = $1, belt = $2 WHERE id = $3', [xp, belt, userId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── AI SENSEI LIMITI ─────────────────────────────────

app.get('/api/sensei/limit/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await db.query(
      'SELECT questions_today, last_reset, subscription_tier FROM users WHERE id = $1',
      [userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Korisnik nije pronadjen' });
    const user = result.rows[0];
    const isPremium = user.subscription_tier === 'premium';

    if (isPremium) {
      const today = new Date().toDateString();
      const lastReset = new Date(user.last_reset).toDateString();
      if (today !== lastReset) {
        await db.query('UPDATE users SET questions_today = 0, last_reset = NOW() WHERE id = $1', [userId]);
        user.questions_today = 0;
      }
      res.json({ used: user.questions_today, limit: 5, remaining: 5 - user.questions_today, type: 'daily' });
    } else {
      res.json({ used: user.questions_today, limit: 3, remaining: 3 - user.questions_today, type: 'lifetime' });
    }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/sensei/use', async (req, res) => {
  const { userId } = req.body;
  try {
    await db.query('UPDATE users SET questions_today = questions_today + 1 WHERE id = $1', [userId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── PROMO KODOVI ─────────────────────────────────────

app.post('/api/promo/redeem', async (req, res) => {
  const { code, userId } = req.body;
  if (!code || !userId) return res.status(400).json({ error: 'Nedostaju podaci' });
  try {
    const promo = await db.query('SELECT * FROM promo_codes WHERE code = $1', [code.toUpperCase()]);
    if (promo.rows.length === 0) return res.status(404).json({ error: 'Kod nije validan' });
    const p = promo.rows[0];
    if (p.valid_until && new Date(p.valid_until) < new Date()) return res.status(400).json({ error: 'Kod je istekao' });
    if (p.used_count >= p.max_uses) return res.status(400).json({ error: 'Kod je iskoristen' });

    let expiresAt = null;
    if (p.duration_days) {
      expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + p.duration_days);
    }

    await db.query('UPDATE users SET subscription_tier = $1, subscription_expires = $2 WHERE id = $3',
      ['premium', expiresAt, userId]);
    await db.query('UPDATE promo_codes SET used_count = used_count + 1 WHERE code = $1', [code.toUpperCase()]);

    res.json({ success: true, duration_days: p.duration_days, expires_at: expiresAt });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── AI SENSEI PROXY ──────────────────────────────────

app.post('/api/sensei/ask', async (req, res) => {
  const { messages, system } = req.body;
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 400, system, messages })
    });
    const data = await response.json();
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log('Server radi na portu ' + PORT));
