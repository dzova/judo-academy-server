if (process.env.NODE_ENV !== 'production') { require('dotenv').config(); }
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const app = express();

// CORS headers — MORAJU biti pre ostalih middleware-a
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.use(cors({ origin: '*', credentials: false }));
app.use(express.json());
app.use(session({ secret: process.env.SESSION_SECRET || 'judo2024', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

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

const crypto = require('crypto');
const pendingAuth = {}; // In-memory token store

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: 'judoacademy://auth-failed' }), (req, res) => {
  const user = req.user;
  // Generisi jednokratni token
  const token = crypto.randomBytes(16).toString('hex');
  pendingAuth[token] = {
    userId: user.id,
    username: user.username || user.displayName || '',
    email: user.email || '',
    belt: user.belt || 'white',
    xp: user.xp || 0
  };
  // Obrisi token posle 5 minuta
  setTimeout(function() { delete pendingAuth[token]; }, 5 * 60 * 1000);

  // Pokusaj deep link, sa fallback na web stranicu
  const deepLink = 'judoacademy://auth-success?token=' + token;
  const webFallback = '/auth-success?token=' + token + '&userId=' + user.id + '&username=' + encodeURIComponent(user.username || '') + '&belt=' + (user.belt || 'white') + '&xp=' + (user.xp || 0) + '&email=' + encodeURIComponent(user.email || '');
  
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8">
  <title>Judo Academy</title>
  <style>body{font-family:sans-serif;text-align:center;padding:40px;background:#0F1520;color:#fff;}
  .btn{display:inline-block;padding:14px 28px;background:#D4A833;color:#000;border-radius:12px;text-decoration:none;font-weight:900;margin-top:20px;font-size:1rem;}</style>
  </head><body>
  <h2 style="color:#D4A833;">Uspesno ulogovan!</h2>
  <p style="color:#aaa;">Vracamo te u Judo Academy...</p>
  <a class="btn" href="${deepLink}">Otvori Judo Academy</a>
  <script>
    setTimeout(function(){ window.location.href = '${deepLink}'; }, 300);
  </script>
  </body></html>`);
});

// Fallback web stranica ako deep link ne radi
app.get('/auth-success', (req, res) => {
  const { userId, username, belt, xp, email } = req.query;
  const userData = JSON.stringify({ userId, username: username || '', email: email || '', belt: belt || 'white', xp: xp || 0 });
  const deepLink = `judoacademy://auth-success?userId=${encodeURIComponent(userId)}&username=${encodeURIComponent(username||'')}&belt=${encodeURIComponent(belt||'white')}&xp=${encodeURIComponent(xp||0)}&email=${encodeURIComponent(email||'')}`;
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8">
  <title>Judo Academy - Login</title>
  <style>body{font-family:sans-serif;text-align:center;padding:40px;background:#0F1520;color:#fff;}
  .btn{display:inline-block;padding:12px 24px;background:#D4A833;color:#000;border-radius:10px;text-decoration:none;font-weight:bold;margin-top:20px;cursor:pointer;border:none;font-size:16px;}</style>
  </head><body>
  <h2>&#10003; Uspesno ulogovan!</h2>
  <p>Vrati se u Judo Academy app.</p>
  <button class="btn" onclick="openApp()">Otvori app</button>
  <script>
    // Sacuvaj u localStorage ovog WebView-a
    try { localStorage.setItem('judo_auth_pending', '${userData.replace(/'/g, "\\'")}'); } catch(e) {}
    function openApp() {
      window.location.href = '${deepLink}';
    }
    // Automatski pokusaj
    setTimeout(openApp, 800);
  </script>
  </body></html>`);
});

// Auth pending - app fetchuje posle Google login-a
app.get('/api/auth/pending/:token', async (req, res) => {
  const token = req.params.token;
  const data = pendingAuth[token];
  if (!data) return res.status(404).json({ error: 'Token nije validan ili je istekao' });
  delete pendingAuth[token]; // Jednokratno koriscenje
  res.json(data);
});


app.get('/auth/me', (req, res) => {
  if (req.user) res.json(req.user);
  else res.status(401).json({ error: 'Nije ulogovan' });
});

// ════════════════════════════════════════ HEALTH ════════════════════════════════════════

app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'Judo Academy server radi!' });
});

// ════════════════════════════════════════ KORISNIK ════════════════════════════════════════

app.get('/api/user/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await db.query(
      'SELECT id, username, email, belt, xp, club, country, subscription_tier, exam_date FROM users WHERE id = $1',
      [userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Nije pronadjen' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/user/update', async (req, res) => {
  const { userId, username, club, country, belt, examDate } = req.body;
  if (!userId) return res.status(400).json({ error: 'Nedostaje userId' });
  try {
    await db.query(
      `UPDATE users SET
        club = $1,
        country = $2,
        username = COALESCE($3, username),
        belt = COALESCE($4, belt),
        exam_date = COALESCE($5, exam_date)
       WHERE id = $6`,
      [club || null, country || null, username || null, belt || null, examDate || null, userId]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════ RANG LISTA ════════════════════════════════════════

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

// ════════════════════════════════════════ AI SENSEI LIMITI ════════════════════════════════════════

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

// ════════════════════════════════════════ PROMO KODOVI ════════════════════════════════════════

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

function _checkAdminKey(req, res) {
  const key = req.query.key || req.headers['x-admin-key'];
  if (!process.env.ADMIN_DASHBOARD_KEY || key !== process.env.ADMIN_DASHBOARD_KEY) {
    res.status(401).json({ error: 'Unauthorized' });
    return false;
  }
  return true;
}

function _generatePromoCode() {
  // Bezbedan alfabet bez slova/brojeva koji se lako mešaju (0/O, 1/I/l)
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let part1 = '', part2 = '';
  for (let i = 0; i < 4; i++) part1 += alphabet[crypto.randomInt(alphabet.length)];
  for (let i = 0; i < 4; i++) part2 += alphabet[crypto.randomInt(alphabet.length)];
  return `JA-${part1}-${part2}`;
}

// Generiše N jedinstvenih promo kodova, svaki upotrebljiv samo jednom (max_uses=1).
// Rešava problem deljenja jednog opšteg koda unutar kluba/grupe — svaki član dobija svoj kod.
app.post('/api/admin/promo/generate', async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  const { count, duration_days, note, valid_days } = req.body;
  const n = parseInt(count);
  const duration = parseInt(duration_days);
  if (!n || n < 1 || n > 200) return res.status(400).json({ error: 'count mora biti između 1 i 200' });
  if (![30, 90, 120].includes(duration)) return res.status(400).json({ error: 'duration_days mora biti 30, 90 ili 120' });

  let validUntil = null;
  if (valid_days) {
    validUntil = new Date();
    validUntil.setDate(validUntil.getDate() + parseInt(valid_days));
  }

  try {
    const codes = [];
    for (let i = 0; i < n; i++) {
      let code, attempts = 0;
      do {
        code = _generatePromoCode();
        attempts++;
        const existing = await db.query('SELECT 1 FROM promo_codes WHERE code = $1', [code]);
        if (existing.rows.length === 0) break;
      } while (attempts < 10);

      await db.query(
        `INSERT INTO promo_codes (code, duration_days, max_uses, used_count, valid_until, note)
         VALUES ($1, $2, 1, 0, $3, $4)`,
        [code, duration, validUntil, note || null]
      );
      codes.push(code);
    }
    res.json({ success: true, codes, duration_days: duration, valid_until: validUntil });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Pregled svih generisanih kodova — status (iskorišćen/slobodan), napomena, datum isteka
app.get('/api/admin/promo/list', async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  try {
    const result = await db.query(
      `SELECT code, duration_days, max_uses, used_count, valid_until, note, created_at
       FROM promo_codes
       ORDER BY created_at DESC NULLS LAST, code DESC`
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════ KVIZ I RANDORI (NEW) ════════════════════════════════════════

app.get('/api/quiz', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=86400');
  try {
    const filePath = path.join(__dirname, 'public', 'data', 'all_questions_v2.json');
    const data = fs.readFileSync(filePath, 'utf-8');
    res.json(JSON.parse(data));
  } catch (err) {
    res.status(500).json({ error: 'Questions file not found: ' + err.message });
  }
});

app.get('/api/randori', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=86400');
  try {
    const filePath = path.join(__dirname, 'public', 'data', 'randori_db_v2.json');
    const data = fs.readFileSync(filePath, 'utf-8');
    res.json(JSON.parse(data));
  } catch (err) {
    res.status(500).json({ error: 'Randori file not found: ' + err.message });
  }
});

// ════════════════════════════════════════ AI SENSEI PROXY ════════════════════════════════════════

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
      body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 2048, system, messages })
    });
    const data = await response.json();
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════ KVIZ STATISTIKE ════════════════════════════════════════

app.post('/api/quiz/stats', async (req, res) => {
  const { userId, score, correct, total, maxStreak, category } = req.body;
  if (!userId) return res.status(400).json({ error: 'Nedostaje userId' });
  try {
    await db.query(
      'INSERT INTO quiz_stats (user_id, score, correct, total, max_streak, category) VALUES ($1, $2, $3, $4, $5, $6)',
      [userId, score || 0, correct || 0, total || 0, maxStreak || 0, category || 'mixed']
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/quiz/stats/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const allTime = await db.query(`
      SELECT
        COUNT(*)::int AS games,
        COALESCE(SUM(correct), 0)::int AS correct,
        COALESCE(SUM(total), 0)::int AS total,
        COALESCE(MAX(score), 0)::int AS record,
        COALESCE(MAX(max_streak), 0)::int AS best_streak,
        COALESCE(ROUND(SUM(correct)::numeric / NULLIF(SUM(total),0) * 100), 0)::int AS accuracy
      FROM quiz_stats WHERE user_id = $1
    `, [userId]);

    const thisMonth = await db.query(`
      SELECT
        COUNT(*)::int AS games,
        COALESCE(SUM(correct), 0)::int AS correct,
        COALESCE(SUM(total), 0)::int AS total,
        COALESCE(MAX(score), 0)::int AS record,
        COALESCE(ROUND(SUM(correct)::numeric / NULLIF(SUM(total),0) * 100), 0)::int AS accuracy
      FROM quiz_stats
      WHERE user_id = $1
        AND DATE_TRUNC('month', played_at) = DATE_TRUNC('month', NOW())
    `, [userId]);

    const byCategory = await db.query(`
      SELECT
        category,
        COUNT(*)::int AS games,
        COALESCE(SUM(correct), 0)::int AS correct,
        COALESCE(SUM(total), 0)::int AS total,
        COALESCE(ROUND(SUM(correct)::numeric / NULLIF(SUM(total),0) * 100), 0)::int AS accuracy
      FROM quiz_stats
      WHERE user_id = $1
      GROUP BY category
      ORDER BY games DESC
    `, [userId]);

    res.json({
      allTime: allTime.rows[0],
      thisMonth: thisMonth.rows[0],
      byCategory: byCategory.rows
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════ BACKGROUND SYNC ════════════════════════════════════════

// Provjeri koje fajlove treba ažurirati
app.post('/api/check-updates', async (req, res) => {
  const { versions } = req.body; // { 'translations_v2.json': 1, 'all_questions_v2.json': 1, ... }
  if (!versions) return res.status(400).json({ error: 'Nedostaju versions' });
  try {
    const result = await db.query('SELECT filename, version FROM data_versions');
    const serverVersions = {};
    result.rows.forEach(row => { serverVersions[row.filename] = row.version; });

    const toUpdate = [];
    Object.keys(versions).forEach(filename => {
      const serverV = serverVersions[filename] || 1;
      const clientV = versions[filename] || 0;
      if (serverV > clientV) toUpdate.push({ filename, version: serverV });
    });

    res.json({ toUpdate, serverVersions });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Ažuriraj verziju fajla (admin operacija)
app.post('/api/data/bump-version', async (req, res) => {
  const { filename, secret } = req.body;
  if (secret !== (process.env.ADMIN_SECRET || 'judo-admin-2026')) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  if (!filename) return res.status(400).json({ error: 'Nedostaje filename' });
  try {
    await db.query(
      'INSERT INTO data_versions (filename, version, updated_at) VALUES ($1, 1, NOW()) ON CONFLICT (filename) DO UPDATE SET version = data_versions.version + 1, updated_at = NOW()',
      [filename]
    );
    const result = await db.query('SELECT version FROM data_versions WHERE filename = $1', [filename]);
    res.json({ success: true, filename, version: result.rows[0].version });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Dohvati sve verzije
app.get('/api/data/versions', async (req, res) => {
  try {
    const result = await db.query('SELECT filename, version, updated_at FROM data_versions ORDER BY filename');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════ ANALITIKA ════════════════════════════════════════

app.post('/api/analytics/event', async (req, res) => {
  const { userId, eventName, eventData } = req.body;
  if (!eventName) return res.status(400).json({ error: 'Nedostaje eventName' });
  try {
    await db.query(
      'INSERT INTO analytics_events (user_id, event_name, event_data) VALUES ($1, $2, $3)',
      [userId || null, eventName, eventData ? JSON.stringify(eventData) : null]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════ USER DATA SYNC (Data Service Layer) ════════════════════════════════════════
// Generička sinhronizacija za Beleške, Dnevnik, Scouting planove i Podešavanja.
// Šema: user_data(user_id UUID, data_type TEXT, data_key TEXT, payload JSONB, updated_at TIMESTAMPTZ)
// Napravi tabelu ručno u Railway Query editoru pre upotrebe (vidi user_data_schema.sql).

app.post('/api/userdata/sync', async (req, res) => {
  const { userId, dataType, items } = req.body;
  if (!userId || !dataType || !Array.isArray(items)) {
    return res.status(400).json({ error: 'Nedostaju userId, dataType ili items' });
  }
  try {
    for (const item of items) {
      if (!item || !item.key) continue;
      if (item.deleted) {
        await db.query(
          'DELETE FROM user_data WHERE user_id = $1 AND data_type = $2 AND data_key = $3',
          [userId, dataType, item.key]
        );
      } else {
        await db.query(
          `INSERT INTO user_data (user_id, data_type, data_key, payload, updated_at)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (user_id, data_type, data_key)
           DO UPDATE SET payload = $4, updated_at = $5
           WHERE user_data.updated_at < $5`,
          [userId, dataType, item.key, JSON.stringify(item.payload), item.updatedAt || new Date().toISOString()]
        );
      }
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/userdata/:userId/:dataType', async (req, res) => {
  const { userId, dataType } = req.params;
  try {
    const result = await db.query(
      'SELECT data_key AS key, payload, updated_at AS "updatedAt" FROM user_data WHERE user_id = $1 AND data_type = $2',
      [userId, dataType]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Legal documents
app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'terms.pdf'));
});
app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy.pdf'));
});

// ============================================================
// Judo Academy — Admin Dashboard Endpoint
//
// KAKO DODATI: Nalepi CEO ovaj blok u index.js, TAČNO PRE linije:
//   app.use(express.static('public'));
// (tj. posle sekcije "ANALITIKA", pre "Static files" komentara)
//
// Na Railway -> Variables (vec si dodao) treba: ADMIN_DASHBOARD_KEY
// Posle nalepljivanja ovog koda, commit + deploy na Railway kao i obicno.
// ============================================================

const TECHNIQUE_IDS = [
  'o-goshi',
  'o-soto-gari',
  'seoi-nage',
  'uchi-mata',
  'harai-goshi',
  'tai-otoshi',
  'ko-uchi-gari',
  'tomoe-nage',
  'kesa-gatame',
  'yoko-shiho-gatame',
  'juji-gatame',
  'okuri-eri-jime',
  'hadaka-jime',
  'yoko-ukemi',
  'ushiro-ukemi',
  'zenpo-kaiten',
  'ippon-seoi-nage',
  'hane-goshi',
  'sumi-gaeshi',
  'sukui-nage',
  'tate-shiho-gatame',
  'kami-shiho-gatame',
  'morote-seoi-nage',
  'ura-nage',
  'kata-guruma',
  'sode-tsurikomi-goshi',
  'o-soto-guruma',
  'gyaku-juji-jime',
  'de-ashi-barai',
  'hiza-guruma',
  'o-uchi-gari',
  'ko-soto-gari',
  'tsuri-goshi',
  'sasae-tsurikomi-ashi',
  'ko-soto-gake',
  'o-soto-otoshi',
  'uchi-mata-sukashi',
  'o-guruma',
  'harai-tsurikomi-ashi',
  'ko-uchi-makikomi',
  'tani-otoshi',
  'ura-otoshi',
  'yoko-otoshi',
  'koshi-guruma',
  'ashi-guruma',
  'okuri-ashi-barai',
  'uki-goshi',
  'seoi-otoshi',
  'uchi-mata-makikomi',
  'o-uchi-makikomi',
  'harai-makikomi',
  'o-soto-makikomi',
  'yoko-gake',
  'sumi-otoshi',
  'daki-wakare',
  'yoko-wakare',
  'kuzure-kesa-gatame',
  'mune-gatame',
  'ushiro-kesa-gatame',
  'kuzure-kami-shiho',
  'sangaku-gatame',
  'ude-gatame',
  'waki-gatame',
  'sankaku-jime',
  'tobi-ukemi',
  'uki-otoshi',
  'tsurikomi-goshi',
  'uki-waza',
  'eri-seoi-nage',
  'ko-soto-otoshi',
  'hane-makikomi',
  'utsuri-goshi',
  'nami-juji-jime',
  'kata-juji-jime',
  'kata-ha-jime',
  'o-soto-gaeshi',
  'o-uchi-gaeshi',
  'uchi-mata-gaeshi',
  'harai-goshi-gaeshi',
  'hane-goshi-gaeshi',
  'kuzure-tate-shiho-gatame',
  'hikkomi-gaeshi',
  'soto-makikomi',
  'seoi-makikomi',
  'ushiro-goshi',
  'yoko-guruma',
  'eri-tsurikomi-goshi',
  'ko-uchi-gake',
  'tomoe-gaeshi',
  'yoko-tomoe-nage'
];

function buildTechniqueIdsCTE() {
  const rows = TECHNIQUE_IDS.map(id => `('${id}')`).join(',\n    ');
  return `(VALUES\n    ${rows}\n  ) AS a(id)`;
}

// ════════════════════════════════════════ ADMIN DASHBOARD ════════════════════════════════════════

app.get('/api/admin/dashboard', async (req, res) => {
  const key = req.query.key || req.headers['x-admin-key'];
  if (!process.env.ADMIN_DASHBOARD_KEY || key !== process.env.ADMIN_DASHBOARD_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const q = (sql) => db.query(sql).then(r => r.rows).catch(err => ({ error: err.message }));

  const queries = {

      // ---------- PAYWALL ----------
      paywall_top_features: q(`
        SELECT event_data->>'source' AS feature, COUNT(*) AS views
        FROM analytics_events
        WHERE event_name = 'premium_modal_view' AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY views DESC
      `),
      paywall_checkout_funnel: q(`
        SELECT event_name, COUNT(*) AS n
        FROM analytics_events
        WHERE event_name IN ('premium_checkout_intent','premium_checkout_cancelled','premium_checkout_confirmed')
          AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY 2 DESC
      `),
      paywall_billing_choice: q(`
        SELECT event_data->>'billing' AS billing_period, COUNT(*) AS n
        FROM analytics_events
        WHERE event_name = 'premium_checkout_confirmed' AND created_at > now() - interval '90 days'
        GROUP BY 1
      `),
      paywall_retarget_candidates: q(`
        SELECT user_id, COUNT(*) AS paywall_hits, MAX(created_at) AS last_hit
        FROM analytics_events
        WHERE event_name = 'premium_modal_view' AND user_id IS NOT NULL
          AND created_at > now() - interval '14 days'
        GROUP BY user_id
        HAVING COUNT(*) >= 3
          AND user_id NOT IN (SELECT user_id FROM analytics_events WHERE event_name = 'premium_checkout_confirmed')
        ORDER BY paywall_hits DESC
      `),
      paywall_daily_trend: q(`
        SELECT date_trunc('day', created_at) AS day, COUNT(*) AS modal_views
        FROM analytics_events
        WHERE event_name = 'premium_modal_view' AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY 1
      `),

      // ---------- ONBOARDING ----------
      onboarding_funnel: q(`
        SELECT event_data->>'step' AS step, COUNT(DISTINCT user_id) AS unique_users, COUNT(*) AS total_views
        FROM analytics_events
        WHERE event_name = 'onboarding_step' AND created_at > now() - interval '30 days'
        GROUP BY 1
        ORDER BY CASE event_data->>'step'
          WHEN '0' THEN 0 WHEN '1' THEN 1 WHEN '1b' THEN 2 WHEN 'reg' THEN 3
          WHEN 'con' THEN 4 WHEN '2' THEN 5 WHEN '3' THEN 6 WHEN 'tut' THEN 7
          WHEN '4' THEN 8 ELSE 99 END
      `),
      onboarding_abandon_points: q(`
        SELECT event_data->>'step' AS abandoned_at_step, COUNT(*) AS abandons
        FROM analytics_events
        WHERE event_name = 'onboarding_closed' AND (event_data->>'completed')::boolean = false
          AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY abandons DESC
      `),
      onboarding_completion_rate: q(`
        SELECT event_data->>'completed' AS completed, COUNT(*) AS n,
          ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS percent
        FROM analytics_events
        WHERE event_name = 'onboarding_closed' AND created_at > now() - interval '30 days'
        GROUP BY 1
      `),

      // ---------- SESSION ----------
      sessions_per_day: q(`
        SELECT date_trunc('day', created_at) AS day, COUNT(*) AS sessions, COUNT(DISTINCT user_id) AS unique_users
        FROM analytics_events
        WHERE event_name = 'app_session_start' AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY 1
      `),
      session_length_distribution: q(`
        SELECT (event_data->>'totalMinutes')::int AS minutes_reached, COUNT(*) AS n
        FROM analytics_events
        WHERE event_name = 'session_heartbeat' AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY 1
      `),

      // ---------- FEATURE USAGE ----------
      top_screens: q(`
        SELECT event_data->>'screen' AS screen, COUNT(*) AS views, COUNT(DISTINCT user_id) AS unique_users
        FROM analytics_events
        WHERE event_name = 'screen_view' AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY views DESC
      `),
      top_sections: q(`
        SELECT event_data->>'navKey' AS section, COUNT(*) AS views, COUNT(DISTINCT user_id) AS unique_users
        FROM analytics_events
        WHERE event_name = 'screen_view' AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY views DESC
      `),

      // ---------- ERRORS ----------
      error_top_contexts: q(`
        SELECT event_data->>'context' AS context, COUNT(*) AS occurrences,
          COUNT(DISTINCT user_id) AS affected_users, MAX(created_at) AS last_seen
        FROM analytics_events
        WHERE event_name = 'silent_error' AND created_at > now() - interval '7 days'
        GROUP BY 1 ORDER BY occurrences DESC
      `),
      error_top_messages: q(`
        SELECT event_data->>'context' AS context, event_data->>'message' AS message,
          COUNT(*) AS occurrences, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen
        FROM analytics_events
        WHERE event_name = 'silent_error' AND created_at > now() - interval '7 days'
        GROUP BY 1, 2 ORDER BY occurrences DESC LIMIT 30
      `),
      error_daily_trend: q(`
        SELECT date_trunc('day', created_at) AS day, COUNT(*) AS total_errors, COUNT(DISTINCT user_id) AS affected_users
        FROM analytics_events
        WHERE event_name = 'silent_error' AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY 1
      `),
      error_top_users: q(`
        SELECT user_id, COUNT(*) AS error_count, COUNT(DISTINCT event_data->>'context') AS distinct_contexts,
          MAX(created_at) AS last_error
        FROM analytics_events
        WHERE event_name = 'silent_error' AND created_at > now() - interval '14 days'
          AND user_id IS NOT NULL
        GROUP BY user_id HAVING COUNT(*) >= 3 ORDER BY error_count DESC
      `),
      error_anonymous_volume: q(`
        SELECT COUNT(*) AS anonymous_errors
        FROM analytics_events
        WHERE event_name = 'silent_error' AND user_id IS NULL AND created_at > now() - interval '14 days'
      `),
      error_by_screen: q(`
        SELECT event_data->>'screen' AS screen, COUNT(*) AS errors_on_screen
        FROM analytics_events
        WHERE event_name = 'silent_error' AND created_at > now() - interval '7 days'
        GROUP BY 1 ORDER BY 2 DESC
      `),

      // ---------- RETENTION ----------
      retention_aggregate: q(`
        WITH first_seen AS (
          SELECT user_id, date_trunc('day', MIN(created_at)) AS cohort_day
          FROM analytics_events WHERE user_id IS NOT NULL GROUP BY user_id
        ),
        activity AS (
          SELECT DISTINCT user_id, date_trunc('day', created_at) AS activity_day
          FROM analytics_events WHERE event_name = 'app_session_start' AND user_id IS NOT NULL
        )
        SELECT
          COUNT(DISTINCT f.user_id) AS total_new_users,
          COUNT(DISTINCT CASE WHEN a.activity_day = f.cohort_day + interval '1 day' THEN a.user_id END) AS d1_users,
          COUNT(DISTINCT CASE WHEN a.activity_day = f.cohort_day + interval '7 day' THEN a.user_id END) AS d7_users,
          COUNT(DISTINCT CASE WHEN a.activity_day = f.cohort_day + interval '30 day' THEN a.user_id END) AS d30_users,
          ROUND(100.0 * COUNT(DISTINCT CASE WHEN a.activity_day = f.cohort_day + interval '1 day' THEN a.user_id END) / NULLIF(COUNT(DISTINCT f.user_id),0), 1) AS d1_pct,
          ROUND(100.0 * COUNT(DISTINCT CASE WHEN a.activity_day = f.cohort_day + interval '7 day' THEN a.user_id END) / NULLIF(COUNT(DISTINCT f.user_id),0), 1) AS d7_pct,
          ROUND(100.0 * COUNT(DISTINCT CASE WHEN a.activity_day = f.cohort_day + interval '30 day' THEN a.user_id END) / NULLIF(COUNT(DISTINCT f.user_id),0), 1) AS d30_pct
        FROM first_seen f LEFT JOIN activity a ON a.user_id = f.user_id
      `),
      retention_by_cohort_day: q(`
        WITH first_seen AS (
          SELECT user_id, date_trunc('day', MIN(created_at)) AS cohort_day
          FROM analytics_events WHERE user_id IS NOT NULL GROUP BY user_id
        ),
        activity AS (
          SELECT DISTINCT user_id, date_trunc('day', created_at) AS activity_day
          FROM analytics_events WHERE event_name = 'app_session_start' AND user_id IS NOT NULL
        )
        SELECT
          f.cohort_day::date AS cohort_day,
          COUNT(DISTINCT f.user_id) AS cohort_size,
          ROUND(100.0 * COUNT(DISTINCT CASE WHEN a.activity_day = f.cohort_day + interval '1 day' THEN a.user_id END) / NULLIF(COUNT(DISTINCT f.user_id),0), 1) AS d1_pct,
          ROUND(100.0 * COUNT(DISTINCT CASE WHEN a.activity_day = f.cohort_day + interval '7 day' THEN a.user_id END) / NULLIF(COUNT(DISTINCT f.user_id),0), 1) AS d7_pct,
          ROUND(100.0 * COUNT(DISTINCT CASE WHEN a.activity_day = f.cohort_day + interval '30 day' THEN a.user_id END) / NULLIF(COUNT(DISTINCT f.user_id),0), 1) AS d30_pct
        FROM first_seen f LEFT JOIN activity a ON a.user_id = f.user_id
        GROUP BY f.cohort_day ORDER BY f.cohort_day
      `),
      retention_by_language: q(`
        WITH first_session AS (
          SELECT DISTINCT ON (user_id) user_id, date_trunc('day', created_at) AS cohort_day, event_data->>'lang' AS first_lang
          FROM analytics_events
          WHERE event_name = 'app_session_start' AND user_id IS NOT NULL
          ORDER BY user_id, created_at ASC
        ),
        activity AS (
          SELECT DISTINCT user_id, date_trunc('day', created_at) AS activity_day
          FROM analytics_events WHERE event_name = 'app_session_start' AND user_id IS NOT NULL
        )
        SELECT
          f.first_lang,
          COUNT(DISTINCT f.user_id) AS cohort_size,
          ROUND(100.0 * COUNT(DISTINCT CASE WHEN a.activity_day = f.cohort_day + interval '7 day' THEN a.user_id END) / NULLIF(COUNT(DISTINCT f.user_id),0), 1) AS d7_retention_pct,
          ROUND(100.0 * COUNT(DISTINCT CASE WHEN a.activity_day = f.cohort_day + interval '30 day' THEN a.user_id END) / NULLIF(COUNT(DISTINCT f.user_id),0), 1) AS d30_retention_pct
        FROM first_session f LEFT JOIN activity a ON a.user_id = f.user_id
        GROUP BY f.first_lang ORDER BY d7_retention_pct DESC NULLS LAST
      `),

      // ---------- CONTENT ----------
      content_top_techniques: q(`
        SELECT event_data->>'name' AS technique, event_data->>'cat' AS category,
          COUNT(*) AS views, COUNT(DISTINCT user_id) AS unique_users
        FROM analytics_events
        WHERE event_name = 'technique_view' AND created_at > now() - interval '30 days'
        GROUP BY 1, 2 ORDER BY views DESC LIMIT 30
      `),
      content_never_viewed_techniques: q(`
        WITH viewed AS (
          SELECT DISTINCT event_data->>'id' AS id FROM analytics_events
          WHERE event_name = 'technique_view' AND created_at > now() - interval '30 days'
        )
        SELECT a.id AS never_viewed_technique
        FROM ${buildTechniqueIdsCTE()}
        LEFT JOIN viewed v ON a.id = v.id
        WHERE v.id IS NULL ORDER BY a.id
      `),
      content_quiz_accuracy_by_category: q(`
        SELECT event_data->>'type' AS category, COUNT(*) AS total_answers,
          COUNT(*) FILTER (WHERE (event_data->>'correct')::boolean = true) AS correct_answers,
          ROUND(100.0 * COUNT(*) FILTER (WHERE (event_data->>'correct')::boolean = true) / COUNT(*), 1) AS accuracy_pct
        FROM analytics_events
        WHERE event_name = 'quiz_answer' AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY accuracy_pct ASC
      `),
      content_randori_by_category: q(`
        SELECT event_data->>'cat' AS category, COUNT(*) AS views, COUNT(DISTINCT user_id) AS unique_users
        FROM analytics_events
        WHERE event_name = 'randori_scenario_view' AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY views DESC
      `),
      content_overview: q(`
        SELECT 'technique_view' AS content_type, COUNT(*) AS total_views, COUNT(DISTINCT user_id) AS unique_users
        FROM analytics_events WHERE event_name = 'technique_view' AND created_at > now() - interval '30 days'
        UNION ALL
        SELECT 'quiz_answer', COUNT(*), COUNT(DISTINCT user_id)
        FROM analytics_events WHERE event_name = 'quiz_answer' AND created_at > now() - interval '30 days'
        UNION ALL
        SELECT 'randori_scenario_view', COUNT(*), COUNT(DISTINCT user_id)
        FROM analytics_events WHERE event_name = 'randori_scenario_view' AND created_at > now() - interval '30 days'
      `),
    };

  const keys = Object.keys(queries);
  const results = await Promise.all(Object.values(queries));
  const out = {};
  keys.forEach((k, i) => { out[k] = results[i]; });

  res.json(out);
});

// Static files — MORA biti posle ruta
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log('Server radi na portu ' + PORT));
