if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Pool } = require('pg');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'judo2024',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

const db = new Pool({ connectionString: process.env.DATABASE_URL });

// ── GOOGLE AUTH ──────────────────────────────────────

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
      result = await db.query(`
        INSERT INTO users (username, email, google_id)
        VALUES ($1, $2, $3) RETURNING *
      `, [name, email, googleId]);
    }
    
    return done(null, result.rows[0]);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
  done(null, result.rows[0]);
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    const user = req.user;
    res.redirect(`judoacademy://auth?userId=${user.id}&username=${encodeURIComponent(user.username)}&belt=${user.belt}&xp=${user.xp}`);
  }
);

app.get('/auth/me', (req, res) => {
  if (req.user) res.json(req.user);
  else res.status(401).json({ error: 'Nije ulogovan' });
});

// ── HEALTH ───────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'Judo Academy server radi!' });
});

//

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server radi na portu ${PORT}`));