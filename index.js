if (process.env.NODE_ENV !== 'production') { require('dotenv').config(); }
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

const app = express();

// Railway (i vecina PaaS-a) sedi iza load balancer/proxy-ja - bez ovoga bi express-rate-limit
// video IP proxy-ja umesto pravog IP-a klijenta za SVE zahteve, sto bi ili blokiralo sve
// korisnike zajedno kao da su jedan klijent, ili ucinilo rate limiting potpuno neefektivnim.
app.set('trust proxy', 1);

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
if (!process.env.SESSION_SECRET) {
  console.error('[startup] SESSION_SECRET nije podesen - server se ne pokrece bez njega');
  process.exit(1);
}
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// ════════════════════════════════════════ RATE LIMITING ════════════════════════════════════════
// Dodatni sloj zastite iznad postojecih dnevnih limita (questions_today, itd.) - fokusiran na
// zloupotrebu na nivou minuta (brute-force, spam, skriptovani napadi), ne na dnevne kvote koje
// vec postoje po feature-u. Svi limiteri koriste standardne RateLimit-* headere (standardHeaders:
// true) da klijent moze da vidi koliko mu je ostalo, i legacyHeaders: false jer stariji X-RateLimit-*
// headeri nisu potrebni ovde.

// Strog limiter za auth/promo rute - ove su najosetljivije na brute-force (pogadjanje promo
// kodova, pokusaji pogadjanja pending auth tokena).
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Previse pokusaja, pokusaj ponovo kasnije' }
});

// Umeren limiter za AI pozive (Sensei/Scouting) - dnevni limit od 5 vec postoji na nivou
// korisnika u bazi, ovo je dodatna zastita da neko ne pokusa da "potrosi" ili testira taj
// limit ekstremno brzo (npr. 100 poziva u sekundi pre nego sto server stigne da azurira brojac).
const aiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Previse zahteva, sacekaj malo' }
});

// Labaviji limiter za analytics - ocekivano je da klijent salje dosta eventa tokom koriscenja
// app-a, cilj je samo sprecavanje ociglednog spam/DoS scenarija, ne normalne upotrebe.
const analyticsLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Previse zahteva' }
});

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
    const photoUrl = (profile.photos && profile.photos[0] && profile.photos[0].value) || '';
    let result = await db.query('SELECT * FROM users WHERE google_id = $1', [googleId]);
    if (result.rows.length === 0) {
      result = await db.query('INSERT INTO users (username, email, google_id, photo_url) VALUES ($1, $2, $3, $4) RETURNING *', [name, email, googleId, photoUrl]);
    } else if (photoUrl && photoUrl !== result.rows[0].photo_url) {
      // Google slika se mogla promeniti od poslednjeg login-a - osvezi je
      result = await db.query('UPDATE users SET photo_url = $1 WHERE google_id = $2 RETURNING *', [photoUrl, googleId]);
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
const jwt = require('jsonwebtoken');
const { google } = require('googleapis');
const { OAuth2Client } = require('google-auth-library');
const pendingAuth = {}; // In-memory token store

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: 'judoacademy://auth-failed' }), (req, res) => {
  const user = req.user;
  // Generisi jednokratni token
  const token = crypto.randomBytes(16).toString('hex');
  let authToken = null;
  try { authToken = _issueAuthToken(user.id); } catch (e) { console.error('[auth] Neuspesno izdavanje JWT tokena:', e.message); }
  pendingAuth[token] = {
    userId: user.id,
    username: user.username || user.displayName || '',
    email: user.email || '',
    belt: user.belt || 'white',
    xp: user.xp || 0,
    photoUrl: user.photo_url || '',
    authToken
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
app.get('/api/auth/pending/:token', strictLimiter, async (req, res) => {
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

app.get('/api/user/me', _requireAuth, async (req, res) => {
  const userId = req.userId;
  try {
    const result = await db.query(
      'SELECT id, username, email, belt, xp, club, country, subscription_tier, subscription_expires, exam_date, photo_url, unlocked_badges, birth_year, dominant_side FROM users WHERE id = $1',
      [userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Nije pronadjen' });
    const user = result.rows[0];
    // Ako je subscription_tier 'premium' u bazi ali je datum isteka prosao, javi klijentu
    // stvarno stanje ('free') umesto zastarelog baza flaga - baza se ne azurira automatski
    // kad pretplata istekne, samo se runtime proverava pri svakom pristupu
    if (user.subscription_tier === 'premium' && !_isPremiumActive(user)) {
      user.subscription_tier = 'free';
    }
    res.json(user);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════ KORISNIK ════════════════════════════════════════

// Redosled odgovara stvarnim id vrednostima iz frontenda (BELT_TECHNIQUES / pojas lista) -
// bilo koja druga vrednost je odbijena da spreci direktan API poziv sa izmisljenim pojasom.
// Definisano ovde (pre prve rute koja je koristi) radi jasnoce, mada bi zbog function-scope
// izvrsavanja radilo i kad je bilo definisano nize u fajlu.
const VALID_BELTS = ['beli', 'zuti', 'narandzasti', 'zeleni', 'plavi', 'braon', 'crni'];
// Vrednosti odgovaraju onima koje frontend salje iz selectPfDominant() (Profil forma).
const VALID_DOMINANT_SIDES = ['dešnjak', 'levak', 'oba'];

app.post('/api/user/update', _requireAuth, async (req, res) => {
  const { username, club, country, belt, examDate, birthYear, dominantSide } = req.body;
  const userId = req.userId;

  if (belt !== undefined && belt !== null && !VALID_BELTS.includes(belt)) {
    return res.status(400).json({ error: 'Nevalidna belt vrednost' });
  }
  if (dominantSide !== undefined && dominantSide !== null && !VALID_DOMINANT_SIDES.includes(dominantSide)) {
    return res.status(400).json({ error: 'Nevalidna vrednost za dominantnu stranu' });
  }
  // Osnovna duzinska ogranicenja - ova polja se prikazuju na javnom /api/leaderboard bez
  // autentikacije, pa ogranicavamo duzinu da spreci ocigledan abuse (npr. ogroman string koji
  // razbija UI layout). Frontend leaderboard renderer vec radi escH() escaping za XSS zastitu,
  // ovo je dodatna higijena na nivou podataka.
  if (username !== undefined && username !== null && (typeof username !== 'string' || username.length > 40)) {
    return res.status(400).json({ error: 'Nevalidno korisnicko ime' });
  }
  if (club !== undefined && club !== null && (typeof club !== 'string' || club.length > 60)) {
    return res.status(400).json({ error: 'Nevalidan naziv kluba' });
  }
  if (country !== undefined && country !== null && (typeof country !== 'string' || country.length > 60)) {
    return res.status(400).json({ error: 'Nevalidna drzava' });
  }

  try {
    await db.query(
      `UPDATE users SET
        club = $1,
        country = $2,
        username = COALESCE($3, username),
        belt = COALESCE($4, belt),
        exam_date = COALESCE($5, exam_date),
        birth_year = COALESCE($6, birth_year),
        dominant_side = COALESCE($7, dominant_side)
       WHERE id = $8`,
      [club || null, country || null, username || null, belt || null, examDate || null, birthYear || null, dominantSide || null, userId]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════ RANG LISTA ════════════════════════════════════════

app.get('/api/leaderboard', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT u.username, u.belt, u.xp, u.club, u.country, u.updated_at,
             COALESCE(qs.best_score, 0) AS quiz_score,
             COALESCE(qs.total_correct, 0) AS correct
      FROM users u
      LEFT JOIN (
        SELECT user_id, MAX(score) AS best_score, SUM(correct) AS total_correct
        FROM quiz_stats
        GROUP BY user_id
      ) qs ON qs.user_id = u.id
      ORDER BY u.xp DESC LIMIT 50
    `);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Gornja granica je namerno velikodusna (ne pokusavamo tacno izracunati teoretski max iz
// svih izvora XP-a) - cilj je samo da odbijemo ocigledno lazirane vrednosti (npr. 999999999),
// ne da fino tuniramo legitimni max napredak
const MAX_PLAUSIBLE_XP = 200000;

app.post('/api/xp/update', _requireAuth, async (req, res) => {
  const { xp, belt, unlockedBadges } = req.body;
  const userId = req.userId;

  if (typeof xp !== 'number' || !Number.isFinite(xp) || xp < 0 || xp > MAX_PLAUSIBLE_XP) {
    return res.status(400).json({ error: 'Nevalidna xp vrednost' });
  }
  if (belt !== undefined && belt !== null && !VALID_BELTS.includes(belt)) {
    return res.status(400).json({ error: 'Nevalidna belt vrednost' });
  }

  try {
    const newBadges = Array.isArray(unlockedBadges) ? unlockedBadges : [];
    const result = await db.query(
      `UPDATE users SET
        xp = $1,
        belt = $2,
        updated_at = NOW(),
        unlocked_badges = (
          SELECT COALESCE(jsonb_agg(DISTINCT badge), '[]'::jsonb)
          FROM jsonb_array_elements_text(COALESCE(unlocked_badges, '[]'::jsonb) || $4::jsonb) AS badge
        )
       WHERE id = $3
       RETURNING unlocked_badges`,
      [xp, belt, userId, JSON.stringify(newBadges)]
    );
    res.json({ success: true, unlockedBadges: result.rows[0] ? result.rows[0].unlocked_badges : newBadges });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════ AI SENSEI LIMITI ════════════════════════════════════════

// Zajednicka "koliko mi je jos ostalo" provera za sva tri AI feature-a (Sensei chat,
// Scouting, Journal AI analiza) - klijent salje ?feature=scouting ili ?feature=journal u
// query stringu; bez parametra (ili nepoznata vrednost) podrazumeva se 'sensei' radi
// kompatibilnosti sa starijim verzijama klijenta. Isti counterColumn/resetColumn/limit
// mapping kao u POST /api/sensei/ask, namerno drzan sinhronizovano - ako se ovde promeni
// limit ili kolona za neki feature, ista promena mora ici i tamo.
app.get('/api/sensei/limit/me', _requireAuth, async (req, res) => {
  const userId = req.userId;
  const feature = req.query.feature;
  const isScouting = feature === 'scouting';
  const isJournal = feature === 'journal';
  const counterColumn = isScouting ? 'scouting_questions_today' : (isJournal ? 'journal_ai_today' : 'questions_today');
  const resetColumn = isScouting ? 'scouting_last_reset' : (isJournal ? 'journal_ai_last_reset' : 'last_reset');
  const dailyLimit = isJournal ? 3 : 5;
  try {
    const result = await db.query(
      `SELECT ${counterColumn}, ${resetColumn}, subscription_tier, subscription_expires FROM users WHERE id = $1`,
      [userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Korisnik nije pronadjen' });
    const user = result.rows[0];
    const isPremium = _isPremiumActive(user);
    let usedCount = user[counterColumn];

    if (isPremium) {
      const today = new Date().toDateString();
      const lastReset = new Date(user[resetColumn]).toDateString();
      if (today !== lastReset) {
        await db.query(`UPDATE users SET ${counterColumn} = 0, ${resetColumn} = NOW() WHERE id = $1`, [userId]);
        usedCount = 0;
      }
      res.json({ used: usedCount, limit: dailyLimit, remaining: dailyLimit - usedCount, type: 'daily' });
    } else {
      res.json({ used: usedCount, limit: dailyLimit, remaining: dailyLimit - usedCount, type: 'lifetime' });
    }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════ PROMO KODOVI ════════════════════════════════════════

app.post('/api/promo/redeem', strictLimiter, _requireAuth, _requireIntegrity, async (req, res) => {
  const { code } = req.body;
  const userId = req.userId;
  if (!code) return res.status(400).json({ error: 'Nedostaju podaci' });

  const client = await db.connect();
  try {
    await client.query('BEGIN');

    // FOR UPDATE zakljucava red da spreci race condition kad dva zahteva sa
    // istim kodom stignu istovremeno pri poslednjem dostupnom koriscenju
    // (npr. max_uses=1, dva brza klika/zahteva) - bez ovoga oba mogu proci
    // proveru used_count < max_uses pre nego sto ijedan upise novu vrednost.
    const promo = await client.query('SELECT * FROM promo_codes WHERE code = $1 FOR UPDATE', [code.toUpperCase()]);
    if (promo.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Kod nije validan' });
    }
    const p = promo.rows[0];
    if (p.valid_until && new Date(p.valid_until) < new Date()) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Kod je istekao' });
    }
    if (p.used_count >= p.max_uses) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Kod je iskoristen' });
    }

    let expiresAt = null;
    if (p.duration_days) {
      expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + p.duration_days);
    }

    // Oba UPDATE-a u istoj transakciji - ili oba prodju ili nijedan (sprecava
    // da korisnik dobije premium a kod ostane "neiskoriscen" ako server padne
    // izmedju ove dve linije).
    await client.query('UPDATE users SET subscription_tier = $1, subscription_expires = $2 WHERE id = $3',
      ['premium', expiresAt, userId]);
    await client.query('UPDATE promo_codes SET used_count = used_count + 1 WHERE code = $1', [code.toUpperCase()]);

    await client.query('COMMIT');
    res.json({ success: true, duration_days: p.duration_days, expires_at: expiresAt });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// Product ID-jevi definisani u Play Console (Monetize -> Products -> Subscriptions)
const PLAY_BILLING_PRODUCT_IDS = ['premium_monthly', 'premium_annual'];

// Zajednicka logika za verifikaciju kupovine preko Google Play Developer API-ja i upis
// u bazu. Koristi se i pri prvoj kupovini (/api/billing/verify) i pri periodicnom
// osvezavanju statusa postojece pretplate (/api/billing/refresh), jer bez RTDN webhook-a
// server ne saznaje automatski kad se pretplata obnovi svakog meseca/godine.
async function _verifyAndApplySubscription(userId, purchaseToken, productId) {
  const publisher = await _getAndroidPublisher();
  const result = await publisher.purchases.subscriptionsv2.get({
    packageName: 'com.judoacademy.app',
    token: purchaseToken,
  });

  const subscription = result.data;
  const state = subscription.subscriptionState;
  const isActive = state === 'SUBSCRIPTION_STATE_ACTIVE' || state === 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD';

  if (!isActive) {
    return { ok: false, status: 400, error: 'Pretplata nije aktivna', state };
  }

  const lineItem = (subscription.lineItems || [])[0];
  const expiresAt = lineItem && lineItem.expiryTime ? new Date(lineItem.expiryTime) : null;
  // Uzimamo productId iz same Google API odgovora (autoritativan izvor) umesto da se
  // oslanjamo na prosledjeni parametar - bitno za /api/billing/refresh i webhook pozive
  // koji ne znaju productId unapred i prosledjuju prazan string
  const resolvedProductId = (lineItem && lineItem.productId) || productId;

  const existingOwner = await db.query('SELECT id FROM users WHERE play_purchase_token = $1', [purchaseToken]);
  if (existingOwner.rows.length > 0 && existingOwner.rows[0].id !== userId) {
    return { ok: false, status: 409, error: 'Ova kupovina je vec povezana sa drugim nalogom' };
  }

  await db.query(
    'UPDATE users SET subscription_tier = $1, subscription_expires = $2, play_purchase_token = $3 WHERE id = $4',
    ['premium', expiresAt, purchaseToken, userId]
  );

  if (subscription.acknowledgementState === 'ACKNOWLEDGEMENT_STATE_PENDING') {
    try {
      await publisher.purchases.subscriptions.acknowledge({
        packageName: 'com.judoacademy.app',
        subscriptionId: resolvedProductId,
        token: purchaseToken,
      });
    } catch (ackErr) { console.error('[billing] Acknowledge greska:', ackErr.message); }
  }

  return { ok: true, expiresAt, state };
}

app.post('/api/billing/verify', _requireAuth, _requireIntegrity, async (req, res) => {
  const { purchaseToken, productId } = req.body;
  const userId = req.userId;
  if (!purchaseToken || !productId) {
    return res.status(400).json({ error: 'Nedostaju purchaseToken ili productId' });
  }
  if (!PLAY_BILLING_PRODUCT_IDS.includes(productId)) {
    return res.status(400).json({ error: 'Nepoznat productId' });
  }
  try {
    const result = await _verifyAndApplySubscription(userId, purchaseToken, productId);
    if (!result.ok) return res.status(result.status).json({ error: result.error, state: result.state });
    res.json({ success: true, expires_at: result.expiresAt, state: result.state });
  } catch (err) {
    console.error('[billing] Verifikacija neuspesna:', err.message);
    res.status(500).json({ error: 'Verifikacija nije uspela: ' + err.message });
  }
});

// Osvezava status postojece pretplate koristeci VEC SACUVAN token iz baze (ne novi token
// sa klijenta). Klijent poziva ovo pri svakom otvaranju Profil ekrana za premium korisnike -
// throttle ispod sprecava da to postane cest poziv ka Google Play API-ju, jer RTDN webhook
// (linija ~432) vec hvata stvarne promene pretplate u realnom vremenu; ovaj poziv je samo
// dodatni safety-net za slucaj da webhook zakasni/promasi, pa ne mora da bude trenutan.
const _billingRefreshThrottle = new Map(); // userId -> timestamp poslednjeg stvarnog Google Play poziva
const BILLING_REFRESH_THROTTLE_MS = 30 * 60 * 1000; // 30 min

app.post('/api/billing/refresh', _requireAuth, async (req, res) => {
  const userId = req.userId;
  try {
    const lastCall = _billingRefreshThrottle.get(userId);
    if (lastCall && (Date.now() - lastCall) < BILLING_REFRESH_THROTTLE_MS) {
      // Prescoceno - vrati trenutno stanje iz baze bez novog Google Play poziva
      const cached = await db.query('SELECT subscription_tier, subscription_expires FROM users WHERE id = $1', [userId]);
      if (cached.rows.length === 0) return res.status(404).json({ error: 'Korisnik nije pronadjen' });
      const u = cached.rows[0];
      return res.json({ success: true, active: _isPremiumActive(u), expires_at: u.subscription_expires, throttled: true });
    }

    const userResult = await db.query('SELECT play_purchase_token FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'Korisnik nije pronadjen' });
    const token = userResult.rows[0].play_purchase_token;
    if (!token) return res.status(400).json({ error: 'Nema sacuvane kupovine za osvezavanje' });

    // productId nije poznat iz baze (ne cuvamo ga posebno), ali je potreban samo za
    // acknowledge poziv koji se svakako preskace ako je pretplata vec potvrdjena -
    // koristimo prazan string jer je acknowledge grana retko dostignuta ovde
    const result = await _verifyAndApplySubscription(userId, token, '');
    // Throttle se upisuje tek NAKON uspesnog poziva - ako Google API privremeno ne radi
    // (mreza, kvota, itd.), sledeci pokusaj korisnika sme odmah da proba ponovo umesto da
    // ceka 30 min na osnovu neuspesnog pokusaja.
    _billingRefreshThrottle.set(userId, Date.now());
    if (!result.ok) {
      // Pretplata vise nije aktivna (otkazana/istekla) - eksplicitno postavi na free
      // umesto da ostavimo zastareo 'premium' status u bazi
      await db.query('UPDATE users SET subscription_tier = $1 WHERE id = $2', ['free', userId]);
      return res.json({ success: true, active: false, state: result.state || null });
    }
    res.json({ success: true, active: true, expires_at: result.expiresAt, state: result.state });
  } catch (err) {
    console.error('[billing] Osvezavanje neuspesno:', err.message);
    res.status(500).json({ error: 'Osvezavanje nije uspelo: ' + err.message });
  }
});

// Real-time Developer Notifications (RTDN) webhook - Google Play salje Pub/Sub push
// notifikaciju ovde kad se stanje pretplate promeni (obnova, otkazivanje, grace period, itd.)
// Payload je SAMO signal da se nesto desilo - uvek se poziva Google Play API da se dobije
// pravo, trenutno stanje, nikad se ne veruje notificationType broju direktno za odluke.
const _processedRtdnMessageIds = new Set();
const _pubsubAuthClient = new OAuth2Client();

// Verifikuje da POST zahtev STVARNO dolazi od Google Pub/Sub servisa (ne od bilo koga ko
// zna URL endpointa). Pub/Sub push zahtevi nose Google-potpisan OIDC token u Authorization
// header-u; ovde se taj token verifikuje protiv Google-ovih javnih kljuceva, proverava se
// da audience odgovara nasem endpointu, i da je izdat od servisnog naloga
async function _verifyPubSubRequest(req) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return false;
  if (!process.env.PUBSUB_WEBHOOK_AUDIENCE) {
    console.error('[billing][rtdn] PUBSUB_WEBHOOK_AUDIENCE nije podesen na serveru - webhook odbija sve zahteve dok se ne podesi');
    return false;
  }
  try {
    const ticket = await _pubsubAuthClient.verifyIdToken({
      idToken: token,
      audience: process.env.PUBSUB_WEBHOOK_AUDIENCE,
    });
    const payload = ticket.getPayload();
    return !!(payload && payload.email && payload.email.endsWith('.gserviceaccount.com'));
  } catch (err) {
    console.error('[billing][rtdn] JWT verifikacija neuspesna:', err.message);
    return false;
  }
}

app.post('/api/billing/webhook', async (req, res) => {
  try {
    const isVerified = await _verifyPubSubRequest(req);
    if (!isVerified) {
      return res.status(403).send('Forbidden: invalid or missing Pub/Sub authentication');
    }

    const message = req.body && req.body.message;
    if (!message || !message.data) {
      // Nevalidan payload - potvrdi da ne bi Google ponavljao unedogled
      return res.status(200).send('ignored: no message data');
    }

    // Idempotentnost - Google Pub/Sub garantuje at-least-once delivery i redovno salje
    // duplikate. Preskacemo poruke koje smo vec obradili (in-memory, dovoljno za jedan
    // server proces; restart servera bi teoretski mogao ponovo obraditi poruku, ali
    // _verifyAndApplySubscription je vec idempotentna - upisuje isto stanje ponovo)
    const messageId = message.messageId || message.message_id;
    if (messageId && _processedRtdnMessageIds.has(messageId)) {
      return res.status(200).send('duplicate, already processed');
    }

    const decoded = Buffer.from(message.data, 'base64').toString('utf8');
    const notification = JSON.parse(decoded);

    const subNotif = notification.subscriptionNotification;
    if (!subNotif || !subNotif.purchaseToken) {
      // VoidedPurchaseNotification ili druga vrsta koju trenutno ne obradjujemo
      if (messageId) _processedRtdnMessageIds.add(messageId);
      return res.status(200).send('ignored: not a subscription notification');
    }

    const purchaseToken = subNotif.purchaseToken;
    const userResult = await db.query('SELECT id FROM users WHERE play_purchase_token = $1', [purchaseToken]);
    if (userResult.rows.length === 0) {
      // Token jos nije povezan ni sa jednim korisnikom (npr. RTDN je stigao pre nego sto
      // je klijent stigao da pozove /api/billing/verify posle kupovine) - beleze se u log,
      // ne pokusavamo ponovo, Google ce poslati sledeci event kad korisnik zavrsi verify
      console.error('[billing][rtdn] Token nije povezan ni sa jednim korisnikom:', purchaseToken);
      if (messageId) _processedRtdnMessageIds.add(messageId);
      return res.status(200).send('token not yet linked to a user');
    }

    const userId = userResult.rows[0].id;
    const result = await _verifyAndApplySubscription(userId, purchaseToken, '');
    if (!result.ok) {
      await db.query('UPDATE users SET subscription_tier = $1 WHERE id = $2', ['free', userId]);
    }

    if (messageId) {
      _processedRtdnMessageIds.add(messageId);
      // Sprecava neograniceni rast Set-a tokom dugog rada servera
      if (_processedRtdnMessageIds.size > 5000) {
        const oldest = _processedRtdnMessageIds.values().next().value;
        _processedRtdnMessageIds.delete(oldest);
      }
    }

    res.status(200).send('processed');
  } catch (err) {
    // I dalje odgovaramo 200 - gresku beleze u log za rucnu istragu, ne zelimo da Google
    // beskonacno ponavlja isporuku za greske koje mi moramo da resimo (npr. bug u kodu)
    console.error('[billing][rtdn] Obrada notifikacije neuspesna:', err.message);
    res.status(200).send('error logged');
  }
});

function _checkAdminKey(req, res) {
  const key = req.query.key || req.headers['x-admin-key'];
  if (!process.env.ADMIN_DASHBOARD_KEY || key !== process.env.ADMIN_DASHBOARD_KEY) {
    res.status(401).json({ error: 'Unauthorized' });
    return false;
  }
  return true;
}

// Izdaje potpisan JWT token posle uspesnog Google login-a. Token sadrzi userId
// i istice posle 90 dana (korisnik ostaje ulogovan dugo, konzistentno sa mobile app UX).
function _issueAuthToken(userId) {
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET nije podesen na serveru');
  return jwt.sign({ userId: String(userId) }, process.env.JWT_SECRET, { expiresIn: '90d' });
}

// Middleware koji verifikuje JWT token iz Authorization header-a (format: "Bearer <token>")
// i postavlja req.userId iz VERIFIKOVANOG tokena - nikad iz req.body/req.params/req.query,
// jer bi to omogucilo bilo kome da se predstavlja kao drugi korisnik samo slanjem njegovog ID-ja.
function _requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Nedostaje autentifikacioni token' });
  if (!process.env.JWT_SECRET) return res.status(500).json({ error: 'Server nije ispravno podesen (JWT_SECRET)' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token je nevazeci ili je istekao' });
  }
}

// Bug report screenshot-ovi se cuvaju na Cloudinary (trajni storage) umesto na lokalni disk -
// Railway kontejneri imaju efemeran fajl-sistem, svaki redeploy/restart brise sve upisano na
// disk tokom prethodne sesije. Cloudinary vraca stabilan javni URL koji prezivljava redeploy.
// Ako CLOUDINARY_* promenljive nisu podesene, bugReportUpload ostaje null i ruta ispod
// preskace upload screenshot-a (opis i dalje uspesno stize u bazu, samo bez slike).
let bugReportUpload = null;
if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
  const cloudinary = require('cloudinary').v2;
  const { CloudinaryStorage } = require('multer-storage-cloudinary');
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });
  bugReportUpload = multer({
    storage: new CloudinaryStorage({
      cloudinary: cloudinary,
      params: { folder: 'judo-academy/bug-reports', allowed_formats: ['png', 'jpg', 'jpeg'] }
    }),
    limits: { fileSize: 8 * 1024 * 1024 } // 8MB max po screenshotu
  });
}

// Nodemailer transporter za obavestenja o novim prijavama problema (Gmail App Password,
// vidi GMAIL_USER / GMAIL_APP_PASSWORD u Railway Variables). Ako promenljive nisu podesene,
// transporter ostaje null i slanje se tiho preskace - bug report i dalje uspesno stize u bazu,
// Obavestenja o novim prijavama problema idu preko Resend HTTPS API-ja (RESEND_API_KEY u
// Railway Variables), NE preko SMTP-a. Railway blokira sav izlazni SMTP saobracaj (portovi
// 25/465/587/2525) na Free/Trial/Hobby planovima - potvrdjeno u zvanicnoj Railway dokumentaciji,
// SMTP je dostupan tek od Pro plana. Resend zaobilazi ovo potpuno jer koristi obican HTTPS poziv.
async function _sendBugReportEmail(report, screenshotUrl) {
  if (!process.env.RESEND_API_KEY) return;
  try {
    const lines = [
      'Izvor: ' + (report.source || '—'),
      'Kategorija: ' + (report.category || '—'),
      'Tip problema: ' + (report.issueType || '—'),
      'Kontakt: ' + (report.replyEmail || '—'),
      'Verzija app-a: ' + (report.appVersion || '—'),
      'Korisnik ID: ' + (report.userId || '—'),
      '',
      'Opis:',
      report.description,
      '',
      screenshotUrl ? ('Screenshot: ' + screenshotUrl) : 'Bez screenshot-a'
    ];

    const emailPayload = {
      from: 'Judo Academy <onboarding@resend.dev>', // test posiljalac - radi bez verifikacije domena
      to: [process.env.GMAIL_USER || 'judo.academy.world@gmail.com'],
      subject: '[Judo Academy] Nova prijava problema — ' + (report.category || report.source || 'opšte'),
      text: lines.join('\n')
    };

    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + process.env.RESEND_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(emailPayload)
    });
    if (!resp.ok) {
      const errText = await resp.text().catch(function(){ return ''; });
      throw new Error('Resend HTTP ' + resp.status + ': ' + errText);
    }
  } catch (err) {
    // Neuspesno slanje emaila ne sme da obori bug-report rutu - prijava je vec sacuvana u bazi
    console.error('[bug-report][email] Slanje obavestenja neuspesno:', err.message);
  }
}


// Kredencijali Service Account-a se citaju iz GOOGLE_SERVICE_ACCOUNT_JSON env promenljive
// (ceo JSON fajl kao string), NIKAD iz fajla u repo-u - to bi bio bezbednosni rizik.
let _androidPublisherClient = null;
async function _getAndroidPublisher() {
  if (_androidPublisherClient) return _androidPublisherClient;
  if (!process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON nije podesen na serveru');
  }
  const credentials = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
  const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: ['https://www.googleapis.com/auth/androidpublisher'],
  });
  _androidPublisherClient = google.androidpublisher({ version: 'v3', auth });
  return _androidPublisherClient;
}

// ════════════════════════════════════════ PLAY INTEGRITY API ════════════════════════════════════════
// Isti Service Account (GOOGLE_SERVICE_ACCOUNT_JSON) kao za Billing, drugaciji OAuth scope.
// Klijent (Capacitor @capacitor-community/play-integrity plugin) generise integrity token pre
// osetljivih akcija (kupovina, promo redeem, AI pozivi) i salje ga u X-Integrity-Token headeru.
// Server dekriptuje token preko Google Play servera (token se ne moze falsifikovati na klijentu)
// i proverava da je app genuine, uredjaj neupitan, i nalog licenciran.
let _playIntegrityClient = null;
async function _getPlayIntegrityClient() {
  if (_playIntegrityClient) return _playIntegrityClient;
  if (!process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON nije podesen na serveru');
  }
  const credentials = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
  const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: ['https://www.googleapis.com/auth/playintegrity'],
  });
  _playIntegrityClient = google.playintegrity({ version: 'v1', auth });
  return _playIntegrityClient;
}

const JUDO_ACADEMY_PACKAGE_NAME = 'com.judoacademy.app';
// Nonce cache za replay-zastitu - svaki nonce sme da se iskoristi samo jednom, i mora biti
// nedavno izdat od strane OVOG servera (sprecava da neko presretne/ponovo koristi stari token).
const _integrityNonceCache = new Map(); // nonce -> {userId, expiresAt}
const INTEGRITY_NONCE_TTL_MS = 5 * 60 * 1000; // 5 min - dovoljno vremena da klijent zatrazi i posalje token

function _cleanupExpiredNonces() {
  const now = Date.now();
  for (const [nonce, data] of _integrityNonceCache) {
    if (data.expiresAt < now) _integrityNonceCache.delete(nonce);
  }
}

// Server izdaje nonce (ne klijent) da bi mogao da potvrdi da je integrity token nastao kao
// odgovor na NJEGOV zahtev, ne na neki stari/tudji zahtev. crypto.randomBytes daje dovoljno
// entropije da nonce ne moze biti pogodjen.
app.get('/api/integrity/nonce', _requireAuth, (req, res) => {
  _cleanupExpiredNonces();
  const nonce = crypto.randomBytes(24).toString('base64url');
  _integrityNonceCache.set(nonce, { userId: req.userId, expiresAt: Date.now() + INTEGRITY_NONCE_TTL_MS });
  res.json({ nonce });
});

// Middleware koji verifikuje integrity token poslat u X-Integrity-Token headeru. Ne baca gresku
// ako Play Integrity API nije podesen (INTEGRITY_ENFORCEMENT env var kontrolise da li je
// odbijanje strogo ili samo upozorenje) - ovo omogucava postepeno uvodjenje bez rizika da
// jedna pogresno podesena varijabla srusi kompletnu kupovinu/AI funkcionalnost za sve korisnike.
async function _requireIntegrity(req, res, next) {
  const token = req.headers['x-integrity-token'];
  const strict = process.env.INTEGRITY_ENFORCEMENT === 'strict';

  if (!token) {
    if (strict) return res.status(400).json({ error: 'Integrity token nedostaje' });
    console.warn('[integrity] Token nedostaje za ' + req.path + ' (soft mode, propusteno)');
    return next();
  }

  try {
    const client = await _getPlayIntegrityClient();
    const result = await client.v1.decodeIntegrityToken({
      packageName: JUDO_ACADEMY_PACKAGE_NAME,
      requestBody: { integrityToken: token },
    });
    const payload = result.data && result.data.tokenPayloadExternal;
    if (!payload) throw new Error('Prazan integrity payload');

    const { requestDetails, appIntegrity, deviceIntegrity, accountDetails } = payload;

    // Nonce mora postojati u kesu (izdat od ovog servera), pripadati istom korisniku, i biti
    // svez - ovo sprecava replay napade gde se stari validan token ponovo salje.
    const nonceData = requestDetails && _integrityNonceCache.get(requestDetails.nonce);
    if (!nonceData || nonceData.userId !== req.userId) {
      throw new Error('Nonce nevalidan, istekao, ili ne pripada ovom korisniku');
    }
    _integrityNonceCache.delete(requestDetails.nonce); // jednokratna upotreba

    if (!requestDetails || requestDetails.requestPackageName !== JUDO_ACADEMY_PACKAGE_NAME) {
      throw new Error('Package name se ne poklapa');
    }
    if (Date.now() - Number(requestDetails.timestampMillis) >= 120000) {
      throw new Error('Token je prestar (>2 min)');
    }
    if (!appIntegrity || appIntegrity.appRecognitionVerdict !== 'PLAY_RECOGNIZED') {
      throw new Error('App nije prepoznata kao genuine Play verzija: ' + (appIntegrity && appIntegrity.appRecognitionVerdict));
    }
    // MEETS_BASIC_INTEGRITY je najslabiji nivo koji i dalje prihvatamo - MEETS_DEVICE_INTEGRITY
    // i MEETS_STRONG_INTEGRITY su bolji, ali odbijanje SVIH osim najjaceg bi blokiralo legitimne
    // starije/jeftinije uredjaje koji nemaju hardversku podrsku za jaci nivo.
    const deviceVerdicts = (deviceIntegrity && deviceIntegrity.deviceRecognitionVerdict) || [];
    if (deviceVerdicts.length === 0) {
      throw new Error('Uredjaj ne ispunjava nijedan integrity nivo');
    }

    req.integrityVerdict = { appIntegrity, deviceIntegrity, accountDetails };
    next();
  } catch (err) {
    console.error('[integrity] Verifikacija neuspesna za ' + req.path + ':', err.message);
    if (strict) return res.status(403).json({ error: 'Provera integriteta nije uspela' });
    next(); // soft mode - propusti uz log, ne blokiraj korisnike dok se ne potvrdi da sve radi
  }
}

// Proverava da li je korisnik STVARNO trenutno premium - i subscription_tier='premium'
// i (subscription_expires je null (lifetime/bez isteka) ili je u buducnosti).
// Koristiti umesto direktne provere `subscription_tier === 'premium'` svuda u kodu,
// jer sam tier flag ne govori nista o tome da li je pretplata i dalje vazeca.
function _isPremiumActive(user) {
  if (user.subscription_tier !== 'premium') return false;
  if (!user.subscription_expires) return true; // lifetime/promo bez isteka
  return new Date(user.subscription_expires) > new Date();
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
  const { count, duration_days, note, valid_days, max_uses } = req.body;
  const n = parseInt(count);
  const duration = parseInt(duration_days);
  const uses = max_uses ? parseInt(max_uses) : 1;
  if (!n || n < 1 || n > 200) return res.status(400).json({ error: 'count mora biti između 1 i 200' });
  if (![10, 30, 90, 120, 365].includes(duration)) return res.status(400).json({ error: 'duration_days mora biti 10, 30, 90, 120 ili 365' });
  if (!uses || uses < 1 || uses > 10000) return res.status(400).json({ error: 'max_uses mora biti između 1 i 10000' });

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
         VALUES ($1, $2, $3, 0, $4, $5)`,
        [code, duration, uses, validUntil, note || null]
      );
      codes.push(code);
    }
    res.json({ success: true, codes, duration_days: duration, max_uses: uses, valid_until: validUntil });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Pregled koji korisnici bi bili pogođeni bulk dodelom premiuma po klubu — PRE stvarne izmene
app.get('/api/admin/premium/club-preview', async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  const clubQuery = (req.query.club || '').trim();
  if (!clubQuery) return res.status(400).json({ error: 'Nedostaje club parametar' });
  try {
    const result = await db.query(
      `SELECT id, username, club, subscription_tier, subscription_expires
       FROM users
       WHERE club ILIKE $1
       ORDER BY username`,
      [`%${clubQuery}%`]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Stvarna dodela premiuma svim korisnicima čiji klub (slobodan tekst) odgovara pretrazi.
// Uvek prvo pozvati /club-preview da se potvrdi tačan spisak pre ove akcije.
app.post('/api/admin/premium/club-grant', async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  const { club, duration_days } = req.body;
  const clubQuery = (club || '').trim();
  const duration = parseInt(duration_days);
  if (!clubQuery) return res.status(400).json({ error: 'Nedostaje club parametar' });
  if (![10, 30, 90, 120, 365].includes(duration)) return res.status(400).json({ error: 'duration_days mora biti 10, 30, 90, 120 ili 365' });

  try {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + duration);

    const result = await db.query(
      `UPDATE users
       SET subscription_tier = 'premium', subscription_expires = $1
       WHERE club ILIKE $2
       RETURNING id, username, club`,
      [expiresAt, `%${clubQuery}%`]
    );
    res.json({ success: true, updated_count: result.rows.length, updated_users: result.rows, expires_at: expiresAt });
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

// Brisanje jednog promo koda (npr. stari/probni kodovi koje više ne treba deliti)
app.delete('/api/admin/promo/:code', async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  try {
    const result = await db.query('DELETE FROM promo_codes WHERE code = $1 RETURNING code', [req.params.code.toUpperCase()]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Kod nije pronađen' });
    res.json({ success: true, deleted: result.rows[0].code });
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

// Osnovna zastita protiv zloupotrebe: limit velicine payload-a (sprecava da 5x/dan limit
// bude zaobidjen slanjem ogromnih poruka) i provera da system prompt zaista dolazi iz
// jednog od nasih poznatih izvora - bez ovoga bilo ko sa validnim JWT tokenom moze
// direktnim pozivom API-ja zameniti prompt proizvoljnim tekstom i koristiti server kao
// besplatan opsti Claude proxy na nas racun.
// Sensei chat/Dnevnik analiza i Scouting koriste RAZLICITE system promptove - oba moraju
// biti prihvacena (ranija verzija je proveravala samo Sensei potpis i time slomila Scouting).
const SENSEI_SYSTEM_SIGNATURE = 'Ti si Sensei Kano';
const SCOUTING_SYSTEM_SIGNATURE = 'Ti si taktički analitičar i scouting specijalista';
// Stvarno izmereno: staticni deo buildSenseiSystemPrompt() u index.html je ~8200 karaktera
// SAM PO SEBI, pre userContext/modeInstructions i pre istorije poruka - limit mora imati
// solidnu marzu iznad toga da ne blokira legitimne pozive, uz i dalje odsecanje ociglednog abuse-a
const MAX_SENSEI_PAYLOAD_CHARS = 20000;

app.post('/api/sensei/ask', aiLimiter, _requireAuth, _requireIntegrity, async (req, res) => {
  const { messages, system, feature } = req.body;
  const userId = req.userId;
  // Scouting, Sensei chat i Dnevnik (Journal) AI analiza dele isti endpoint ali imaju
  // odvojene dnevne limite - klijent salje feature='scouting' ili feature='journal'
  // eksplicitno; sve ostalo (obican Sensei chat) tretiramo kao 'sensei' (podrazumevana
  // vrednost) radi kompatibilnosti sa starijim verzijama klijenta koje ne salju feature.
  const isScouting = feature === 'scouting';
  const isJournal = feature === 'journal';

  const isSenseiPrompt = typeof system === 'string' && system.includes(SENSEI_SYSTEM_SIGNATURE);
  const isScoutingPrompt = typeof system === 'string' && system.includes(SCOUTING_SYSTEM_SIGNATURE);
  if (!isSenseiPrompt && !isScoutingPrompt) {
    return res.status(400).json({ error: 'Nevalidan system prompt' });
  }
  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'Nedostaju messages' });
  }
  const totalChars = system.length + messages.reduce((sum, m) => sum + (typeof m.content === 'string' ? m.content.length : JSON.stringify(m.content || '').length), 0);
  if (totalChars > MAX_SENSEI_PAYLOAD_CHARS) {
    return res.status(400).json({ error: 'Zahtev je prevelik' });
  }

  const counterColumn = isScouting ? 'scouting_questions_today' : (isJournal ? 'journal_ai_today' : 'questions_today');
  const resetColumn = isScouting ? 'scouting_last_reset' : (isJournal ? 'journal_ai_last_reset' : 'last_reset');

  try {
    const userResult = await db.query(
      `SELECT ${counterColumn}, ${resetColumn}, subscription_tier, subscription_expires FROM users WHERE id = $1`,
      [userId]
    );
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'Korisnik nije pronadjen' });
    const user = userResult.rows[0];
    const isPremium = _isPremiumActive(user);
    let usedCount = user[counterColumn];

    if (isPremium) {
      const today = new Date().toDateString();
      const lastReset = new Date(user[resetColumn]).toDateString();
      if (today !== lastReset) {
        await db.query(`UPDATE users SET ${counterColumn} = 0, ${resetColumn} = NOW() WHERE id = $1`, [userId]);
        usedCount = 0;
      }
    }
    // Limit zavisi od feature-a: Sensei i Scouting imaju 5 (i premium dnevno i free lifetime -
    // vidi Terms of Use v1.2), Journal AI analiza ima 3 (usaglaseno sa frontend
    // triggerDnevnikAnaliza() koja vec koristi limit=3 za lokalnu/fallback proveru).
    const dailyLimit = isJournal ? 3 : 5;
    if (usedCount >= dailyLimit) {
      return res.status(429).json({ error: 'Dostignut je limit pitanja', limit: dailyLimit, used: usedCount });
    }

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 4000, system, messages })
    });
    const data = await response.json();

    // Broji pitanje samo ako je Anthropic poziv uspeo (ne trosi limit na neuspesne pokusaje)
    if (!data.error) {
      await db.query(`UPDATE users SET ${counterColumn} = ${counterColumn} + 1 WHERE id = $1`, [userId]);
    }

    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════ KVIZ STATISTIKE ════════════════════════════════════════

// Read-only provera stanja limita - klijent ovo poziva PRE starta partije (startQuiz) da
// spreci samo IGRANJE iznad limita, ne samo upis rezultata na kraju. Bez ovoga bi tehnicki
// potkovan korisnik i dalje mogao da igra neograniceno (pitanja su lokalno kesirana), samo mu
// rezultat ne bi bio sacuvan - ovaj endpoint zatvara tu granicu tako sto klijent moze da
// proveri limit unapred i blokira start partije, ne samo prikaz rezultata na kraju.
app.get('/api/quiz/limit/me', _requireAuth, async (req, res) => {
  const userId = req.userId;
  try {
    const result = await db.query(
      'SELECT quiz_plays_today, quiz_last_reset, subscription_tier, subscription_expires FROM users WHERE id = $1',
      [userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Korisnik nije pronadjen' });
    const user = result.rows[0];
    const isPremium = _isPremiumActive(user);

    if (isPremium) {
      res.json({ used: 0, limit: null, remaining: null, type: 'unlimited' });
      return;
    }

    let playsToday = user.quiz_plays_today;
    const today = new Date().toDateString();
    const lastReset = new Date(user.quiz_last_reset).toDateString();
    if (today !== lastReset) playsToday = 0; // samo za prikaz - stvarni reset se desava na upisu
    res.json({ used: playsToday, limit: 3, remaining: Math.max(0, 3 - playsToday), type: 'daily' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/quiz/stats', _requireAuth, async (req, res) => {
  const { score, correct, total, maxStreak, category } = req.body;
  const userId = req.userId;

  const s = Number(score) || 0;
  const c = Number(correct) || 0;
  const t = Number(total) || 0;
  const ms = Number(maxStreak) || 0;
  // Osnovna logicka provera - correct/maxStreak ne mogu premasiti total, sprecava
  // ocigledno lazirane vrednosti poslate direktnim API pozivom (ne app-om). Plafon 400 je
  // namerna rezerva iznad trenutnih ~252 pitanja u bazi (frontend salje ukupan broj pitanja
  // u rundi, ne broj odigranih) - ostavlja prostor za buduce dodavanje pitanja bez potrebe
  // da se server hitno menja svaki put kad JSON baza pitanja poraste.
  if (c < 0 || t < 0 || c > t || ms > t || t > 400 || s < 0 || s > 5000) {
    return res.status(400).json({ error: 'Nevalidni podaci o rezultatu' });
  }

  try {
    const userResult = await db.query(
      'SELECT quiz_plays_today, quiz_last_reset, subscription_tier, subscription_expires FROM users WHERE id = $1',
      [userId]
    );
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'Korisnik nije pronadjen' });
    const user = userResult.rows[0];
    const isPremium = _isPremiumActive(user);
    let playsToday = user.quiz_plays_today;

    // Free: 3x dnevno. Premium: neograniceno (vidi memorije - "Kviz unlimited" za premium),
    // pa se limit i reset provera preskacu potpuno za premium korisnike.
    if (!isPremium) {
      const today = new Date().toDateString();
      const lastReset = new Date(user.quiz_last_reset).toDateString();
      if (today !== lastReset) {
        await db.query('UPDATE users SET quiz_plays_today = 0, quiz_last_reset = NOW() WHERE id = $1', [userId]);
        playsToday = 0;
      }
      if (playsToday >= 3) {
        return res.status(429).json({ error: 'Dostignut je dnevni limit kviza', limit: 3, used: playsToday });
      }
      await db.query('UPDATE users SET quiz_plays_today = quiz_plays_today + 1 WHERE id = $1', [userId]);
    }

    await db.query(
      'INSERT INTO quiz_stats (user_id, score, correct, total, max_streak, category) VALUES ($1, $2, $3, $4, $5, $6)',
      [userId, s, c, t, ms, category || 'mixed']
    );
    await db.query('UPDATE users SET updated_at = NOW() WHERE id = $1', [userId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Prima prijavu problema iz app-a (opis + opciono screenshot). Koristi _requireAuth
// isto kao ostale korisnicke rute - req.userId dolazi iz verifikovanog JWT tokena.
// Middleware je uslovan - ako Cloudinary nije podesen (bugReportUpload === null), preskace
// se upload korak i ruta i dalje radi (samo bez screenshot-a), umesto da baci gresku.
const _bugReportUploadMiddleware = bugReportUpload
  ? function(req, res, next) {
      bugReportUpload.single('screenshot')(req, res, function(err) {
        if (err) {
          console.error('[bug-report][upload] Cloudinary/multer greška:', err.message);
          // Ne prekidamo prijavu potpuno zbog neuspesnog uploada slike - nastavljamo bez
          // screenshot-a umesto da vratimo 500 korisniku koji samo zeli da prijavi problem.
          req.file = null;
        }
        next();
      });
    }
  : (req, res, next) => next();

app.post('/api/bug-report', _requireAuth, _bugReportUploadMiddleware, async (req, res) => {
  try {
    const { subject, body, source, contentId, category, issueType, description, replyEmail, appVersion } = req.body;
    if (!description || !description.trim()) {
      return res.status(400).json({ error: 'Opis problema je obavezan' });
    }
    // req.file.path je pun Cloudinary URL (npr. https://res.cloudinary.com/.../judo-academy/bug-reports/xyz.png),
    // ne lokalni filename kao sto je bilo sa diskom - cuvamo ga direktno kao trajni link.
    const screenshotPath = req.file ? req.file.path : null;

    const result = await db.query(
      `INSERT INTO bug_reports
        (user_id, subject, body, source, content_id, category, issue_type, description, reply_email, app_version, screenshot_path)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, created_at`,
      [
        req.userId || null,
        subject || null,
        body || null,
        source || null,
        contentId || null,
        category || null,
        issueType || null,
        description.trim(),
        replyEmail || null,
        appVersion || null,
        screenshotPath
      ]
    );
    res.json({ success: true, id: result.rows[0].id, createdAt: result.rows[0].created_at });

    // Email obavestenje se salje POSLE odgovora korisniku (fire-and-forget) - korisnik ne
    // ceka da email stigne, i eventualna greska u slanju emaila ne utice na njegov odgovor.
    _sendBugReportEmail(
      { source, category, issueType, replyEmail, appVersion, userId: req.userId, description: description.trim() },
      req.file ? req.file.path : null
    );
  } catch (err) {
    console.error('[bug-report] greška:', err.message);
    res.status(500).json({ error: 'Slanje prijave nije uspelo' });
  }
});

// Admin pregled prijavljenih problema - ista ADMIN_DASHBOARD_KEY zastita kao ostale admin rute
app.get('/api/admin/bug-reports', async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  try {
    const result = await db.query(
      `SELECT id, user_id, source, category, issue_type, description, reply_email,
              app_version, screenshot_path, status, created_at
       FROM bug_reports
       ORDER BY created_at DESC
       LIMIT 200`
    );
    const rows = result.rows.map(r => ({
      ...r,
      screenshotUrl: r.screenshot_path || null
    }));
    res.json({ reports: rows });
  } catch (err) {
    console.error('[admin/bug-reports] greška:', err.message);
    res.status(500).json({ error: 'Učitavanje prijava nije uspelo' });
  }
});

// Oznaci prijavu kao resenu/u toku (opciono, za buduci admin dashboard UI)
app.post('/api/admin/bug-reports/:id/status', async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  try {
    const { status } = req.body; // 'new' | 'in_progress' | 'resolved' | 'wontfix'
    await db.query('UPDATE bug_reports SET status=$1 WHERE id=$2', [status, req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Ažuriranje statusa nije uspelo' });
  }
});

// Brisanje prijave iz admin dashboarda. Brise samo SQL red - ako je screenshot na Cloudinary-ju,
// on ostaje tamo (nije obavezno brisati ga sa Cloudinary-a, storage je besplatan do velike kolicine).
app.delete('/api/admin/bug-reports/:id', async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  try {
    const result = await db.query('DELETE FROM bug_reports WHERE id=$1 RETURNING id', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Prijava nije pronađena' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Brisanje nije uspelo' });
  }
});

app.get('/api/quiz/stats/me', _requireAuth, async (req, res) => {
  const userId = req.userId;
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
  if (!process.env.ADMIN_SECRET || secret !== process.env.ADMIN_SECRET) {
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

app.post('/api/analytics/event', analyticsLimiter, async (req, res) => {
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

app.post('/api/userdata/sync', _requireAuth, async (req, res) => {
  const { dataType, items } = req.body;
  const userId = req.userId;
  if (!dataType || !Array.isArray(items)) {
    return res.status(400).json({ error: 'Nedostaju dataType ili items' });
  }

  // Dnevnik limit (3x lifetime free / 3x dnevno premium) primenjen samo na journal tip i
  // samo na NOVE unose (ne na brisanje ili na jednokratnu migraciju postojecih lokalnih
  // podataka pri prvom loginu - migrateAndPull salje ceo postojeci spisak odjednom i taj
  // slucaj ne sme biti blokiran istim limitom kao svakodnevno kreiranje novih unosa).
  if (dataType === 'journal') {
    const newEntries = items.filter(function(it) { return it && it.key && !it.deleted; });
    if (newEntries.length > 0) {
      try {
        const userResult = await db.query(
          'SELECT journal_entries_today, journal_last_reset, subscription_tier, subscription_expires FROM users WHERE id = $1',
          [userId]
        );
        if (userResult.rows.length > 0) {
          const user = userResult.rows[0];
          const isPremium = _isPremiumActive(user);

          if (isPremium) {
            const today = new Date().toDateString();
            const lastReset = new Date(user.journal_last_reset).toDateString();
            let usedToday = user.journal_entries_today;
            if (today !== lastReset) {
              await db.query('UPDATE users SET journal_entries_today = 0, journal_last_reset = NOW() WHERE id = $1', [userId]);
              usedToday = 0;
            }
            if (usedToday >= 3) {
              return res.status(429).json({ error: 'Dostignut je dnevni limit dnevnika', limit: 3, used: usedToday });
            }
            await db.query('UPDATE users SET journal_entries_today = journal_entries_today + 1 WHERE id = $1', [userId]);
          } else {
            // Free: 3x lifetime - brojimo postojece zapise u bazi (tacnije od posebnog
            // brojaca jer automatski iskljucuje duplikate/re-sync istog id-a)
            const countResult = await db.query(
              "SELECT COUNT(*)::int AS n FROM user_data WHERE user_id = $1 AND data_type = 'journal'",
              [userId]
            );
            const existing = countResult.rows[0].n;
            if (existing >= 3) {
              return res.status(429).json({ error: 'Dostignut je limit dnevnika', limit: 3, used: existing });
            }
          }
        }
      } catch (limitErr) {
        // Ne blokiramo sync zbog greske u proveri limita - beleziti u log za istragu,
        // bolje propustiti unos nego izgubiti korisnikove podatke zbog nase greske
        console.error('[userdata][journal-limit] Greska pri proveri limita:', limitErr.message);
      }
    }
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

app.get('/api/userdata/:dataType', _requireAuth, async (req, res) => {
  const { dataType } = req.params;
  const userId = req.userId;
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
          COUNT(DISTINCT user_id) AS affected_users, MAX(created_at) AS last_seen,
          MAX(event_data->>'appVersion') AS last_app_version
        FROM analytics_events
        WHERE event_name = 'silent_error' AND created_at > now() - interval '7 days'
        GROUP BY 1 ORDER BY occurrences DESC
      `),
      error_top_messages: q(`
        SELECT event_data->>'context' AS context, event_data->>'message' AS message,
          COUNT(*) AS occurrences, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen,
          array_agg(DISTINCT event_data->>'appVersion') FILTER (WHERE event_data->>'appVersion' IS NOT NULL) AS app_versions
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
