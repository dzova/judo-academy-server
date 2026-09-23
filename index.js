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
// FIX (13.09.2026, konsultantski nalaz): Allow-Headers je ranije dozvoljavao SAMO 'Content-Type',
// a klijent salje i custom 'Authorization' i 'X-Integrity-Token' headere. Za bilo koji NE-native
// klijent (browser fetch, buduca web verzija, rucno testiranje) ovo bi izazvalo CORS preflight
// odbijanje i tihi gubitak oba custom headera. Napomena: kod Capacitor Android klijenta ovo
// verovatno NIJE uzrok "Token nedostaje" problema (CapacitorHttp je enabled u capacitor.config.json,
// pa fetch() ide kroz nativni OkHttp sloj koji ne prolazi kroz browser CORS/preflight uopste) - ali
// je i dalje ispravka koju treba primeniti nezavisno, jer je stari header spisak bio pogresan za
// svaki drugi tip klijenta. Uklonjen je i redundantni cors() paket ispod - ovaj middleware vec sam
// odgovara na OPTIONS pre nego sto bi cors() stigao da se izvrsi, pa je bio mrtav kod.
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Integrity-Token');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json());

// BEZBEDNOST (11.09.2026): ranije su gotovo svi catch blokovi vracali err.message DIREKTNO
// klijentu (res.status(500).json({ error: err.message })). Postgres greske (npr. "duplicate
// key value violates unique constraint users_google_id_key") cesto otkrivaju nazive tabela/
// kolona/constraint-a - nepotrebno curenje detalja seme svakome ko pozove endpoint (mnogi od
// njih su neautentifikovani, npr. /api/leaderboard, /api/quiz). Ova pomocna funkcija loguje
// pun err na serveru (za nasu istragu) i vraca klijentu generiku poruku bez internih detalja.
function _sendServerError(res, err, context) {
  console.error('[' + (context || 'server') + ']', err && err.message ? err.message : err);
  if (!res.headersSent) res.status(500).json({ error: 'Doslo je do greske na serveru' });
}
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

// Strog limiter za admin rute (promo generisanje, premium grant za klub, bug-report
// upravljanje, dashboard, bump-version) - ove nose ADMIN_DASHBOARD_KEY/ADMIN_SECRET u
// query/header/body i nisu ranije imale nikakav rate limit, sto je omogucavalo neograniceno
// automatizovano pogadjanje kljuca. Limit je strozi od strictLimiter jer admin rute nikad ne
// treba da se pozivaju vise puta u minuti od strane legitimnog korisnika (samo Nikola/interni alati).
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  limit: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Previse pokusaja, pokusaj ponovo kasnije' }
});

// FIX (23.09.2026, server optimizacija): eksplicitno pool podesavanje umesto pg default-a (max=10,
// bez timeout-a). Admin dashboard ruta pali 43 paralelna upita preko Promise.all nad ISTIM poolom
// koji koristi i live app saobracaj - bez explicitnog max-a i timeout-a, dashboard poziv moze
// privremeno da potrosi vecinu/sve konekcije i izazove cekanje ili timeout za obicne korisnike.
// max: 20 daje dashboard-u prostora a da ne zauzme sve konekcije trajno.
// idleTimeoutMillis: oslobadja neiskoriscene konekcije nazad Postgres-u (Railway free/hobby planovi
// imaju ogranicen max_connections na bazi).
// connectionTimeoutMillis: ako su sve konekcije zauzete, klijent dobija jasnu gresku posle 5s umesto
// da visi neograniceno.
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

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

// FIX (12.09.2026, korisnik prijavio bag): bez 'prompt: select_account' Google OAuth je,
// ako je unutrasnji WebView/browser vec imao aktivnu Google sesiju, tiho preskakao ekran za
// biranje naloga i vracao ISTI (prethodno koriscen) Google nalog - cak i kad je korisnik na
// SISTEMSKOM nivou (Android account switcher) prebacio na drugi Google nalog, jer to ne utice
// nuzno na Google-ovu sopstvenu web sesiju unutar WebView-a. Posledica: klijentov fix za
// detekciju promene naloga (saveAuthUser/clearLocalUserProgress, indeks.html) se NIKAD nije ni
// pokretao jer je backend svaki put vracao ISTI userId, pa je novi "nalog" u stvari i dalje bio
// stari - ceo lokalni napredak (XP, Mesecna misija, streak...) je izgledao "nasledjen". Sada se
// eksplicitno trazi da Google UVEK prikaze biraca naloga pri svakom /auth/google pozivu.
// FIX (20.09.2026, Google "Project Checkup" nalaz - "Use secure flows": Judo Academy Web klijent
// ne koristi state parametar): state:true ukljucuje standardnu passport-oauth2 CSRF zastitu -
// biblioteka sama generise nasumican state, cuva ga u vec postojecoj sesiji
// (express-session/passport.session(), gore u fajlu) pre redirekta na Google, i proverava ga na
// /auth/google/callback pre nego sto prihvati odgovor. Bez dodatnog custom koda jer je session
// vec podesen.
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'], prompt: 'select_account', state: true }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: 'judoacademy://auth-failed', state: true }), (req, res) => {
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

  // FIX (11.09.2026, QA/security review): ranije je ovde postojala i 'webFallback' promenljiva
  // (link ka /auth-success?token=...&userId=...&xp=... sa sirovim poljima) koja se NIGDE nije
  // stvarno koristila u odgovoru ispod (samo 'deepLink' se koristi) - mrtav kod. Uklonjena
  // zajedno sa celom /auth-success rutom (videti napomenu ispod api/auth/pending) koja je bila
  // jedini poziлac te promenljive - ta ruta je gradila deep link SA SIROVIM poljima (userId/xp/
  // itd, bez tokena), isti obrazac koji je procesAuthUrl() na klijentu (11.09.2026) prestao da
  // prihvata bas zbog bezbednosnog rizika (proizvoljan deep link bi mogao lazno da prijavi
  // korisnika). Pošto ništa u aktivnom flow-u nije ni pozivalo tu rutu, uklanjanje ne menja
  // ponašanje za nijednog korisnika - samo zatvara nepotreban, neiskorišćen javni endpoint.
  const deepLink = 'judoacademy://auth-success?token=' + token;

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
      'SELECT id, username, email, belt, xp, club, country, subscription_tier, subscription_expires, subscription_canceled_at, exam_date, photo_url, unlocked_badges, birth_year, dominant_side, gender, reset_at FROM users WHERE id = $1',
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
    // subscription_canceled_at je relevantan SAMO dok je korisnik jos premium (win-back banner
    // "otkazao si, jos imas pristup do X") - posle isteka vise nema smisla (vidi initHomeScreen/
    // showWinBackBanner na klijentu koji proverava tacno ovaj uslov). Ne brisemo ga ovde iz baze
    // (to radi webhook na sledeci RTDN event), samo ga ne prosledjujemo klijentu kad vise nije
    // primenljivo, da izbegnemo bilo kakvu zabunu na frontu ako se stanja privremeno raspare.
    if (user.subscription_tier !== 'premium') {
      user.subscription_canceled_at = null;
    }
    res.json(user);
  } catch (err) { _sendServerError(res, err); }
});

// ════════════════════════════════════════ KORISNIK ════════════════════════════════════════

// Redosled odgovara stvarnim id vrednostima iz frontenda (BELT_TECHNIQUES / pojas lista) -
// bilo koja druga vrednost je odbijena da spreci direktan API poziv sa izmisljenim pojasom.
// Definisano ovde (pre prve rute koja je koristi) radi jasnoce, mada bi zbog function-scope
// izvrsavanja radilo i kad je bilo definisano nize u fajlu.
const VALID_BELTS = ['beli', 'zuti', 'narandzasti', 'zeleni', 'plavi', 'braon', 'crni'];
// Vrednosti odgovaraju onima koje frontend salje iz selectPfDominant() (Profil forma).
const VALID_DOMINANT_SIDES = ['dešnjak', 'levak', 'oba'];
// DODATAK (19.09.2026, na korisnikov zahtev): opciono polje pola (m/z) u profilu - koristi se
// SAMO da AI feature-i (Sensei/Scouting/Dnevnik) gramaticki ispravno oslovljavaju korisnika na
// srpskom (bio/bila); kad nije navedeno, AI koristi rodno neutralne fraze (vidi static system
// prompt komentare u index.html). Vrednosti odgovaraju onima koje frontend salje iz
// selectPfPol() (Profil forma) - namerno bez treceg "neutralno" stringa, jer to isto postize
// izostavljanje polja (undefined/null).
const VALID_GENDERS = ['m', 'z'];

// PROFANITY BLOCKLIST (09.09.2026) - imena se prikazuju javno na /api/leaderboard, bez ove
// provere korisnik moze da postavi uvredljivo ime koje vide sva deca na rang-listi. Ovo je
// server-side sloj (jedini kome se moze verovati - klijentska provera u index.html je samo
// brza UX povratna informacija, moze se zaobici direktnim API pozivom). Pokriva svih 8 jezika
// koje app podrzava (sr, en, de, fr, es, it, pt, ru). NIJE iscrpna lista - pokriva najcesce
// psovke/uvrede po jeziku; laksa je za prosiriti dodavanjem reci u niz ispod nego za odrzavanje
// pravog moderation servisa, sto za sada nije opravdano po broju korisnika. Poznato ogranicenje
// (tzv. "Scunthorpe problem"): substring provera moze pogrešno pogoditi legitimno ime koje
// SLUCAJNO sadrzi blokiranu rec kao deo sebe - prihvatljiv rizik za licna imena/nadimke ove
// velicine korisnicke baze, ali ne 100% bezbedno za sve moguce kombinacije slova.
const PROFANITY_BLOCKLIST = [
  // sr/hr/bs (transliterovano - provera normalizuje dijakritike pre poredjenja)
  'kurac','kurca','kurcina','pizda','pizdo','pizdu','jebem','jebo','jebote','jebes','picka','picke','peder','pederu','pedercina','shupak','supak','kurvo','kurva','kurvin','djubre','gandzo','seronja','pizdarija','materinu','picku','kurvetina','govno','govnar',
  // en
  'fuck','fucker','fucking','shit','bitch','asshole','bastard','cunt','nigger','nigga','faggot','fag','whore','dick','pussy','slut','retard','cock',
  // de
  'fick','ficken','ficker','scheisse','scheisze','arschloch','hurensohn','fotze','wichser','schlampe','schwuchtel',
  // fr
  'putain','merde','connard','connasse','salope','encule','enculé','pute','batard','bâtard','pd',
  // es
  'puta','putas','mierda','joder','cabron','cabrón','pendejo','maricon','maricón','coño','gilipollas',
  // it
  'cazzo','merda','stronzo','stronza','puttana','vaffanculo','troia','coglione',
  // pt
  'porra','merda','caralho','puta','foder','cacete','filho da puta','fdp',
  // ru (cirilica - provera zadrzava cirilicna slova bez izmene)
  'блять','блядь','сука','хуй','пизда','ебать','ебан','мудак','пидор','гандон',
];

function _normalizeForProfanityCheck(str) {
  return String(str == null ? '' : str)
    .toLowerCase()
    .replace(/đ/g, 'dj').replace(/ß/g, 'ss') // ova slova se NE razlazu preko NFD ispod, moraju rucno
    .normalize('NFD').replace(/[̀-ͯ]/g, '') // skini preostale dijakritike (č,ć,š,ü,é,ñ,itd.)
    .replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e').replace(/4/g, 'a')
    .replace(/5/g, 's').replace(/7/g, 't').replace(/\$/g, 's').replace(/@/g, 'a')
    .replace(/[^a-zЀ-ӿ]/g, ''); // zadrzi samo latinicna+cirilicna slova (bez razmaka/simbola)
}

function containsProfanity(str) {
  const norm = _normalizeForProfanityCheck(str);
  if (!norm) return false;
  return PROFANITY_BLOCKLIST.some(function(w) { return norm.indexOf(w) !== -1; });
}

app.post('/api/user/update', _requireAuth, async (req, res) => {
  const { username, club, country, belt, examDate, birthYear, dominantSide, gender } = req.body;
  const userId = req.userId;

  if (belt !== undefined && belt !== null && !VALID_BELTS.includes(belt)) {
    return res.status(400).json({ error: 'Nevalidna belt vrednost' });
  }
  if (dominantSide !== undefined && dominantSide !== null && !VALID_DOMINANT_SIDES.includes(dominantSide)) {
    return res.status(400).json({ error: 'Nevalidna vrednost za dominantnu stranu' });
  }
  if (gender !== undefined && gender !== null && !VALID_GENDERS.includes(gender)) {
    return res.status(400).json({ error: 'Nevalidna vrednost za pol' });
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
  // Ime/prezime i naziv kluba se prikazuju javno na rang-listi - blokiraj uvredljive reci
  // (vidi PROFANITY_BLOCKLIST definiciju iznad). Klijent (index.html) radi istu proveru za
  // trenutnu povratnu informaciju, ali OVDE je jedina provera kojoj se moze verovati.
  if (username && containsProfanity(username)) {
    return res.status(400).json({ error: 'profanity_username' });
  }
  if (club && containsProfanity(club)) {
    return res.status(400).json({ error: 'profanity_club' });
  }

  try {
    await db.query(
      `UPDATE users SET
        club = COALESCE($1, club),
        country = COALESCE($2, country),
        username = COALESCE($3, username),
        belt = COALESCE($4, belt),
        exam_date = COALESCE($5, exam_date),
        birth_year = COALESCE($6, birth_year),
        dominant_side = COALESCE($7, dominant_side),
        gender = COALESCE($8, gender)
       WHERE id = $9`,
      [club || null, country || null, username || null, belt || null, examDate || null, birthYear || null, dominantSide || null, gender || null, userId]
    );
    res.json({ success: true });
  } catch (err) { _sendServerError(res, err); }
});

// ════════════════════════════════════════ RANG LISTA ════════════════════════════════════════

// FIX (20.09.2026, korisnikov zahtev - server-side kes): 30s in-memory kes po 'period' (jedina
// stvarna varijabla ponasanja - 'metric' se ne koristi unutar funkcije, vidi komentar ispod).
// Rang lista ne mora biti tacna do sekunde - svaki poziv ovog endpoint-a (svako otvaranje
// Leaderboard ekrana, od BILO KOG korisnika) trenutno pokrece pun JOIN+GROUP BY upit nad citavom
// users/quiz_stats tabelom. Bezopasno sada (mali saobracaj), ali kad app poraste bi ovo postao
// nepotreban ponovljen trosak na bazu za identican rezultat u kratkom vremenskom razmaku - 30s kes
// to resava bez primetnog gubitka svezine podataka. Namerno BEZ zakljucavanja/lock-a - ako dva
// zahteva stignu tacno na granici isteka keša, oba ce (retko) izvrsiti upit i prepisati kes istim/
// slicnim rezultatom - bezopasno za ovaj slucaj upotrebe (samo za citanje, nema pisanja).
const _leaderboardCache = { all: { rows: null, ts: 0 }, month: { rows: null, ts: 0 } };
const LEADERBOARD_CACHE_MS = 30000;

app.get('/api/leaderboard', async (req, res) => {
  const period = req.query.period === 'month' ? 'month' : 'all';
  // NAPOMENA: 'metric' parametar se PRIMA ali se ne koristi za grananje ispod - vidi FIX
  // (12.09.2026) komentar dole ("XP metrika uklonjena") - ostavljeno ovde radi kompatibilnosti sa
  // klijentom koji ga i dalje salje u query string-u, bez efekta na ponasanje.
  const metric = req.query.metric === 'quiz' ? 'quiz' : 'xp';
  try {
    const cached = _leaderboardCache[period];
    if (cached.rows && (Date.now() - cached.ts) < LEADERBOARD_CACHE_MS) {
      return res.json(cached.rows);
    }

    if (period === 'all') {
      // Nepromenjeno ponasanje - all-time ostaje kumulativne users.xp / MAX(quiz_stats.score)
      // kolone, isto kao pre ove izmene.
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
      _leaderboardCache.all = { rows: result.rows, ts: Date.now() };
      return res.json(result.rows);
    }

    // period === 'month': prvi dan tekuceg meseca u UTC, koristi se kao donja granica za oba
    // upita ispod - namerno racunato u JS-u (ne date_trunc na serveru) da izbegnemo zavisnost
    // od DB server timezone konfiguracije.
    const now = new Date();
    const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString();

    // FIX (12.09.2026): XP metrika (mesecna i preko xp_events) uklonjena - klijent nikad nije
    // imao UI dugme za prebacivanje na 'xp' metriku (samo Kviz metrika se prikazuje), pa je ovaj
    // kod bio mrtav vec neko vreme. users.xp/belt update i dalje postoje normalno (vidi
    // /api/xp/update ispod) - menja se SAMO rang lista, ne skladistenje korisnickog XP-a.
    // metric === 'quiz' (jedina metrika koja se sad podrzava): quiz_stats vec ima created_at po
    // partiji - najbolji rezultat i suma tacnih odgovora OVOG meseca.
    const result = await db.query(`
      SELECT u.username, u.belt, u.club, u.country,
             0 AS xp,
             MAX(qs.score) AS quiz_score,
             SUM(qs.correct) AS correct
      FROM quiz_stats qs
      JOIN users u ON u.id = qs.user_id
      WHERE qs.created_at >= $1
      GROUP BY u.id, u.username, u.belt, u.club, u.country
      ORDER BY quiz_score DESC LIMIT 50
    `, [monthStart]);
    _leaderboardCache.month = { rows: result.rows, ts: Date.now() };
    res.json(result.rows);
  } catch (err) { _sendServerError(res, err); }
});

// Trenutno ulogovan korisnik moze biti VAN top 50 (npr. 80. mesto) - glavni /api/leaderboard
// endpoint iznad NIKAD ne bi video/vratio tu poziciju jer ima LIMIT 50. Ovaj endpoint racuna
// TACAN rang preko cele tabele koristeci RANK() window funkciju, nezavisno od LIMIT-a gore,
// tako da frontend uvek moze da prikaze "· · · / #80 Tvoja pozicija / 1,240 XP" cak i kad
// korisnik nije u vidljivoj top-N listi. _requireAuth jer nam treba userId da znamo CIJI rang
// trazimo - nema smisla bez ulogovanog korisnika.
app.get('/api/leaderboard/me', _requireAuth, async (req, res) => {
  const period = req.query.period === 'month' ? 'month' : 'all';
  const metric = req.query.metric === 'quiz' ? 'quiz' : 'xp';
  const userId = req.userId;
  try {
    if (period === 'all') {
      // XP metrika uklonjena (vidi FIX 12.09.2026 iznad kod /api/leaderboard) - uvek Kviz.
      const valueExpr = 'COALESCE(qs.best_score, 0)';
      const result = await db.query(`
        SELECT rank, value FROM (
          SELECT u.id, ${valueExpr} AS value,
                 RANK() OVER (ORDER BY ${valueExpr} DESC) AS rank
          FROM users u
          LEFT JOIN (
            SELECT user_id, MAX(score) AS best_score
            FROM quiz_stats GROUP BY user_id
          ) qs ON qs.user_id = u.id
        ) ranked
        WHERE id = $1
      `, [userId]);
      if (result.rows.length === 0) return res.json({ found: false });
      return res.json({ found: true, rank: Number(result.rows[0].rank), value: Number(result.rows[0].value) });
    }

    const now = new Date();
    const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString();

    // XP metrika uklonjena (vidi FIX 12.09.2026 iznad kod /api/leaderboard) - uvek Kviz.
    const result = await db.query(`
      SELECT rank, value FROM (
        SELECT user_id, MAX(score) AS value,
               RANK() OVER (ORDER BY MAX(score) DESC) AS rank
        FROM quiz_stats
        WHERE created_at >= $1
        GROUP BY user_id
      ) ranked
      WHERE user_id = $2
    `, [monthStart, userId]);
    if (result.rows.length === 0) return res.json({ found: false });
    res.json({ found: true, rank: Number(result.rows[0].rank), value: Number(result.rows[0].value) });
  } catch (err) { _sendServerError(res, err); }
});

// Gornja granica je namerno velikodusna (ne pokusavamo tacno izracunati teoretski max iz
// svih izvora XP-a) - cilj je samo da odbijemo ocigledno lazirane vrednosti (npr. 999999999),
// ne da fino tuniramo legitimni max napredak
const MAX_PLAUSIBLE_XP = 200000;

// FIX (11.09.2026, server audit): klijent salje APSOLUTNI totalXP i server ga je do sada samo
// gornje ogranicavao (MAX_PLAUSIBLE_XP) - unutar te granice bilo koji ulogovan korisnik je mogao
// jednim pozivom da postavi svoj XP na proizvoljnu vrednost (cheat rang liste), jer server nije
// proveravao KOLIKO je XP-a poraslo u odnosu na prethodno stanje, samo da li je apsolutna
// vrednost "razumna". Puno resenje (server sam racuna XP po odigranoj aktivnosti) je veci zahvat
// jer bi zahtevao da server poznaje svih 8+ izvora XP-a sa klijenta. Kao brzu ali stvarnu meru,
// ogranicavamo koliko XP-a SME da naraste u JEDNOM pozivu - vrednost je namerno velikodusna
// (nekoliko desetina puta veca od najveceg legitimnog dobitka iz jedne partije) da ne blokira
// korisnika koji je duze vreme bio offline pa salje veci nakupljeni skok od jednom, ali sprecava
// jednokratno "teleportovanje" na visok XP. Visak iznad limita se NE odbija u potpunosti (klijent
// ne proverava HTTP status ovog poziva, pa bi tvrdo odbijanje ostavilo server trajno "zaglavljen"
// iza stvarnog klijentovog XP-a) - umesto toga se primenjuje najvise dozvoljeni deo, a ostatak
// ce se prirodno uhvatiti kroz naredne sync pozive (svaki sledeci ce opet smeti da naraste za
// najvise MAX_XP_DELTA_PER_CALL), sto sumnjivo veliki jednokratni skok pretvara u postepeno
// "sustizanje" umesto trenutnog cheat-a.
const MAX_XP_DELTA_PER_CALL = 2000;

// ═════════════ RESET GUARD (12.09.2026) ═════════════
// Kad se korisniku RUCNO resetuje XP/bedzevi/randori (npr. preko SQL-a tokom testiranja, ili
// buduci admin alat za ispravku), stara/vec pokrenuta instanca app-a na telefonu i dalje ima
// svoj STARI lokalni keš i redovno ga sinhronizuje na server kao apsolutnu istinu - potvrdjeno
// na testu 12.09.2026 (korisnik je resetovao nalog, ali su XP/bedzevi/randori "ozivili" nazad
// jer je stara instanca app-a i dalje bila instalirana i pogurala svoj keš PRE deinstalacije).
// users.reset_at pamti KADA je poslednji put neko rucno resetovao ovog korisnika; push pozivi
// koji nose stariji (ili nikakav) sopstveni "kad je ovo stvarno izmenjeno lokalno" timestamp se
// odbijaju DOK je reset_at "svez" (unutar RESET_GUARD_WINDOW_MS). Posle tog prozora se zastita
// sama iskljuci - bilo koja jos ziva stara instanca app-a je do tada vec ili sinhronizovana ili
// ugasena, tako da ne bismo TRAJNO blokirali korisnike na starijoj verziji app-a koja ne salje
// clientUpdatedAt uopste (fail-open posle isteka prozora, ne fail-closed zauvek).
const RESET_GUARD_WINDOW_MS = 24 * 60 * 60 * 1000; // 24h

function _isResetGuardActive(resetAt) {
  if (!resetAt) return false;
  const t = new Date(resetAt).getTime();
  if (!Number.isFinite(t)) return false;
  return (Date.now() - t) < RESET_GUARD_WINDOW_MS;
}

app.post('/api/xp/update', _requireAuth, async (req, res) => {
  const { xp, belt, unlockedBadges, clientUpdatedAt } = req.body;
  const userId = req.userId;

  if (typeof xp !== 'number' || !Number.isFinite(xp) || xp < 0 || xp > MAX_PLAUSIBLE_XP) {
    return res.status(400).json({ error: 'Nevalidna xp vrednost' });
  }
  if (belt !== undefined && belt !== null && !VALID_BELTS.includes(belt)) {
    return res.status(400).json({ error: 'Nevalidna belt vrednost' });
  }

  try {
    // Klijent salje APSOLUTNI kumulativni xp (ceo totalXP snapshot), ne "koliko je upravo
    // zaradjeno" - frontend ima 8+ mesta gde se totalXP uvecava (kviz, randori, DC, AI
    // feature-i, module discovery...) i menjanje svakog da salje delta+source bi bio mnogo
    // veci i rizicniji zahvat. Umesto toga, RACUNAMO deltu ovde - razlika izmedju stare i nove
    // vrednosti - samo da ogranicimo skok po pozivu (vidi MAX_XP_DELTA_PER_CALL). users.xp
    // skladistenje ostaje NEPROMENJENO (12.09.2026 cistka je uklonila SAMO xp_events logovanje
    // koje je hranilo vise nikad ne prikazivanu XP rang listu - vidi FIX kod /api/leaderboard).
    const prevResult = await db.query('SELECT xp, reset_at FROM users WHERE id = $1', [userId]);
    const prevRow = prevResult.rows[0] || {};
    const prevXp = Number(prevRow.xp) || 0;

    if (_isResetGuardActive(prevRow.reset_at)) {
      const clientTs = clientUpdatedAt ? new Date(clientUpdatedAt).getTime() : NaN;
      const resetTs = new Date(prevRow.reset_at).getTime();
      if (!Number.isFinite(clientTs) || clientTs < resetTs) {
        // Ovaj push nosi podatak stariji od poslednjeg rucnog reseta (ili uopste ne salje
        // sopstveni timestamp, sto tretiramo kao "sumnjivo staro") - odbijamo primenu i
        // trazimo od klijenta da prvo povuce sveze (resetovano) stanje sa servera.
        return res.json({ success: false, resetRequired: true, resetAt: prevRow.reset_at });
      }
    }

    let delta = xp - prevXp;
    let appliedXp = xp;
    if (delta > MAX_XP_DELTA_PER_CALL) {
      console.warn('[xp][obuzdan skok] userId=' + userId + ' trazeno delta=+' + delta + ', primenjeno=+' + MAX_XP_DELTA_PER_CALL);
      delta = MAX_XP_DELTA_PER_CALL;
      appliedXp = prevXp + MAX_XP_DELTA_PER_CALL;
    }

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
      [appliedXp, belt, userId, JSON.stringify(newBadges)]
    );

    // Samo pozitivnu deltu logujemo (XP se u praksi ne smanjuje - ako se ikad desi da nova
    // NAPOMENA (12.09.2026): xp_events logovanje ovde je uklonjeno - hranilo je iskljucivo XP
    // rang listu koja se nikad nije prikazivala korisnicima (vidi FIX kod /api/leaderboard).
    // 'delta' i dalje sluzi samo za MAX_XP_DELTA_PER_CALL ogranicenje iznad.

    res.json({ success: true, unlockedBadges: result.rows[0] ? result.rows[0].unlocked_badges : newBadges });
  } catch (err) { _sendServerError(res, err); }
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
  // FIX 08.09.2026: ranije se ovde koristio JEDAN "dailyLimit" broj i za Premium (dnevni) i za
  // Free (lifetime) korisnika, sto je slucajno bilo tacno za Sensei (5=5) i Journal (3=3) ali
  // POGRESNO za Scouting - zvanicni Terms of Use (tabela Free/Premium planova) kaze da je
  // Scouting za Free korisnike 3x DOZIVOTNO, ne 5x kao za Sensei, dok Premium ostaje 5x DNEVNO
  // za oba. Sad su ta dva broja eksplicitno razdvojena po feature-u.
  const premiumDailyLimit = isJournal ? 3 : 5;                      // Sensei 5/dan, Scouting 5/dan, Journal 3/dan
  const freeLifetimeLimit = isScouting ? 3 : (isJournal ? 3 : 5);   // Sensei 5x, Scouting 3x, Journal 3x - doživotno
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
      res.json({ used: usedCount, limit: premiumDailyLimit, remaining: premiumDailyLimit - usedCount, type: 'daily' });
    } else {
      res.json({ used: usedCount, limit: freeLifetimeLimit, remaining: freeLifetimeLimit - usedCount, type: 'lifetime' });
    }
  } catch (err) { _sendServerError(res, err); }
});

// ════════════════════════════════════════ AI FEEDBACK (thumbs up/down) ════════════════════════════════════════

app.post('/api/ai-feedback', _requireAuth, async (req, res) => {
  const { feature, rating, response_excerpt, lang } = req.body;
  const userId = req.userId;

  const VALID_FEATURES = ['sensei', 'scouting', 'journal'];
  const VALID_RATINGS = ['up', 'down'];
  if (!VALID_FEATURES.includes(feature)) {
    return res.status(400).json({ error: 'Nevalidan feature' });
  }
  if (!VALID_RATINGS.includes(rating)) {
    return res.status(400).json({ error: 'Nevalidan rating' });
  }
  // Isecak odgovora je za kontekst u admin dashboardu (da se vidi STA je ocenjeno kao lose).
  // PODIGNUTO (22.09.2026, korisnikov nalaz): 500 karaktera je secalo AI odgovore na pola, pa se
  // greska cesto nije ni videla ako je bila u drugom delu teksta. 4000 karaktera pokriva prakticno
  // svaki ceo AI odgovor (Sensei/Scouting/Dnevnik), a i dalje sprecava ocigledan abuse (neko ko bi
  // slao ogroman proizvoljan string kroz ovo polje).
  const excerpt = typeof response_excerpt === 'string' ? response_excerpt.slice(0, 4000) : null;

  try {
    await db.query(
      'INSERT INTO ai_feedback (user_id, feature, rating, response_excerpt, lang) VALUES ($1, $2, $3, $4, $5)',
      [userId, feature, rating, excerpt, lang || null]
    );
    res.json({ success: true });
  } catch (err) { _sendServerError(res, err); }
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
    _sendServerError(res, err);
  } finally {
    client.release();
  }
});

// Product ID-jevi definisani u Play Console (Monetize -> Products -> Subscriptions).
// VAZNO: godisnji je 'premium_annual_plan' (ne 'premium_annual') - to je stvaran Product ID iz
// Play Console, razlicit od base plan ID-ja 'premium-annual-plan' (sa crticama). Klijent
// (index.html, PREMIUM_PRODUCT_IDS) mora slati isti ID - inace ovaj server odbija verifikaciju
// sa "Nepoznat productId" cak i kad je kupovina na Google strani validna.
const PLAY_BILLING_PRODUCT_IDS = ['premium_monthly', 'premium_annual_plan'];

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
    _sendServerError(res, err, 'billing][verifikacija');
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
    _sendServerError(res, err, 'billing][osvezavanje');
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

    // Win-back hook (korisnikov zahtev, 20.09.2026): notificationType SE KORISTI OVDE (samo za
    // ovu odluku, ne za subscription_tier/expires - to i dalje iskljucivo odredjuje
    // _verifyAndApplySubscription() iznad preko stvarnog stanja sa Google Play API-ja, kako
    // komentar na vrhu ovog handler-a i nalaze). SUBSCRIPTION_CANCELED (3) = korisnik je iskljucio
    // auto-renew ali JOS IMA pristup do kraja perioda - to je trenutak kad ima smisla pokazati
    // in-app poruku "ostani uz nas" (klijent to cita preko subscription_canceled_at polja, vidi
    // /api/user/me). Bilo koji signal da se korisnik predomislio ili da je pretplata zaista
    // zavrsena (obnovljena, oporavljena, ponovo kupljena, istekla, povucena) brise taj flag - u
    // suprotnom bi banner ostao "zaglavljen" ukljucen za korisnika koji se vec predomislio.
    const notifType = subNotif.notificationType;
    if (notifType === 3) {
      await db.query('UPDATE users SET subscription_canceled_at = NOW() WHERE id = $1', [userId]);
    } else if ([1, 2, 4, 7, 12, 13].includes(notifType)) {
      await db.query('UPDATE users SET subscription_canceled_at = NULL WHERE id = $1', [userId]);
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

// Konstantno-vremensko poredjenje stringova (sprecava timing-attack - napadac ne moze da
// izvuce info o tacnom kljucu merenjem koliko brzo server odgovara na delimicno tacne pokusaje).
// crypto.timingSafeEqual zahteva bafere iste duzine, zato prvo proveravamo duzinu (razlicita
// duzina vec sama po sebi odaje "pogresno", ali to je prihvatljivo - nije to informacija koja
// pomaze pogadjanje sadrzaja kljuca).
function _timingSafeStrEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch (e) {
    return false;
  }
}

function _checkAdminKey(req, res) {
  const key = req.query.key || req.headers['x-admin-key'];
  if (!process.env.ADMIN_DASHBOARD_KEY || !_timingSafeStrEqual(String(key || ''), process.env.ADMIN_DASHBOARD_KEY)) {
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
    // PRIVREMENA DIJAGNOSTIKA (13.09.2026, korisnikov zahtev) - klijent (authFetchWithIntegrity)
    // sad dashboard-uje i kad je token USPESNO pribavljen u JS-u (authFetchWithIntegrity_token_set),
    // ali server i dalje vidi "nedostaje". Ovaj log ispisuje SVE header kljuceve koje Express
    // stvarno vidi za ovaj zahtev - ako 'x-integrity-token' NIJE u toj listi, header se gubi PRE
    // Express-a (native HTTP sloj/proxy); ako JESTE u listi ali je vrednost prazna, problem je u
    // parsiranju/vrednosti. UKLONITI posle dijagnoze da ne zatrpava produkcione logove.
    console.warn('[integrity] Token nedostaje za ' + req.path + ' (soft mode, propusteno)');
    console.warn('[integrity][debug] header kljucevi:', Object.keys(req.headers));
    console.warn('[integrity][debug] x-integrity-token prisutan:', Object.prototype.hasOwnProperty.call(req.headers, 'x-integrity-token'));
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
    // PRIVREMENA DIJAGNOSTIKA (13.09.2026, korisnikov zahtev) - dosad je uspesan slucaj bio
    // POTPUNO tih (samo next(), bez loga), sto je izgledalo kao "kod se ne izvrsava" kad zapravo
    // znaci suprotno - sve je proslo. Eksplicitan log ovde uklanja tu dvosmislenost: odsustvo BILO
    // KOG integrity loga za dati zahtev vise ne postoji kao moguce stanje. UKLONITI posle dijagnoze.
    console.log('[integrity] OK za ' + req.path + ' - verdict: ' + appIntegrity.appRecognitionVerdict + ', device: ' + deviceVerdicts.join(','));
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
app.post('/api/admin/promo/generate', adminLimiter, async (req, res) => {
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
  } catch (err) { _sendServerError(res, err); }
});

// Pregled koji korisnici bi bili pogođeni bulk dodelom premiuma po klubu — PRE stvarne izmene
app.get('/api/admin/premium/club-preview', adminLimiter, async (req, res) => {
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
  } catch (err) { _sendServerError(res, err); }
});

// Stvarna dodela premiuma svim korisnicima čiji klub (slobodan tekst) odgovara pretrazi.
// Uvek prvo pozvati /club-preview da se potvrdi tačan spisak pre ove akcije.
app.post('/api/admin/premium/club-grant', adminLimiter, async (req, res) => {
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
  } catch (err) { _sendServerError(res, err); }
});

// Pregled svih generisanih kodova — status (iskorišćen/slobodan), napomena, datum isteka
app.get('/api/admin/promo/list', adminLimiter, async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  try {
    const result = await db.query(
      `SELECT code, duration_days, max_uses, used_count, valid_until, note, created_at
       FROM promo_codes
       ORDER BY created_at DESC NULLS LAST, code DESC`
    );
    res.json(result.rows);
  } catch (err) { _sendServerError(res, err); }
});

// Brisanje jednog promo koda (npr. stari/probni kodovi koje više ne treba deliti)
app.delete('/api/admin/promo/:code', adminLimiter, async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  try {
    const result = await db.query('DELETE FROM promo_codes WHERE code = $1 RETURNING code', [req.params.code.toUpperCase()]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Kod nije pronađen' });
    res.json({ success: true, deleted: result.rows[0].code });
  } catch (err) { _sendServerError(res, err); }
});

// ════════════════════════════════════════ ADMIN - NALOZI (spisak i brisanje) ════════════════════════════════════════

// Spisak svih naloga za admin dashboard - podrzava pretragu (po username/email/google_id)
// i stranicenje (limit/offset), podrazumevano sortirano po poslednjoj aktivnosti. Namerno se
// ne vraca google_id/play_purchase_token u punom obliku u listi (nepotrebno za pregled/brisanje,
// manje osetljivih podataka u odgovoru) - koristi se samo id, osnovni profil i status pretplate.
app.get('/api/admin/users/list', adminLimiter, async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  try {
    const search = (req.query.search || '').trim();
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const offset = Math.max(parseInt(req.query.offset) || 0, 0);

    const whereClause = search ? 'WHERE username ILIKE $1 OR email ILIKE $1' : '';
    const params = search ? [`%${search}%`] : [];

    const countResult = await db.query(`SELECT COUNT(*)::int AS n FROM users ${whereClause}`, params);
    const result = await db.query(
      `SELECT id, username, email, belt, xp, club, country, subscription_tier, subscription_expires, updated_at
       FROM users
       ${whereClause}
       ORDER BY updated_at DESC NULLS LAST
       LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset]
    );
    res.json({ users: result.rows, total: countResult.rows[0].n, limit, offset });
  } catch (err) { _sendServerError(res, err); }
});

// Trajno brisanje naloga. FK ogranicenja na ai_feedback/xp_history/analytics_events/
// quiz_stats/quiz_category_stats/user_data su ON DELETE CASCADE (vidi migraciju iznad u ovom
// fajlu; xp_events tabela je uklonjena 12.09.2026, vidi FIX kod /api/leaderboard) - brisanje reda
// iz users automatski brise SVE povezane redove u tim tabelama u istoj DB transakciji koju
// Postgres sam upravlja za FK CASCADE (ne treba rucno brisati iz svake tabele ovde).
// bug_reports zadrzava ON DELETE SET NULL namerno (prijava problema ostaje u istoriji radi
// analize/statistike i posle brisanja naloga koji ju je prijavio, samo joj se user_id postavi
// na NULL - ne zelimo da brisanje naloga obrise trag o prijavljenom bagu).
app.delete('/api/admin/users/:id', adminLimiter, async (req, res) => {
  if (!_checkAdminKey(req, res)) return;
  try {
    const result = await db.query(
      'DELETE FROM users WHERE id = $1 RETURNING id, username, email',
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Korisnik nije pronađen' });
    console.warn('[admin][users] Obrisan nalog:', result.rows[0]);
    res.json({ success: true, deleted: result.rows[0] });
  } catch (err) { _sendServerError(res, err); }
});

// Trajno brisanje SOPSTVENOG naloga iz aplikacije (in-app self-service, za razliku od admin
// rute iznad). Zahteva vazeci JWT (_requireAuth) - req.userId dolazi IZ VERIFIKOVANOG tokena,
// nikad iz body/params, tako da korisnik moze obrisati iskljucivo svoj nalog. Isti FK CASCADE
// mehanizam kao admin brisanje (vidi komentar iznad /api/admin/users/:id).
// Google Play zahteva da app nudi brisanje naloga I unutar same aplikacije, ne samo preko
// web stranice (delete-account.html) - ovo je ta in-app ruta.
// Ako korisnik ima AKTIVNU Premium pretplatu, brisanje se odbija (409) dok je prvo ne otkaze
// direktno kroz Google Play - u suprotnom bi mu se pretplata i dalje naplacivala bez naloga
// koji bi je mogao iskoristiti (isto pravilo kao na /delete-account.html stranici).
app.delete('/api/account/me', strictLimiter, _requireAuth, async (req, res) => {
  try {
    const userResult = await db.query(
      'SELECT id, username, email, subscription_tier, subscription_expires FROM users WHERE id = $1',
      [req.userId]
    );
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'Nalog nije pronađen' });
    const user = userResult.rows[0];
    if (_isPremiumActive(user)) {
      return res.status(409).json({
        error: 'ACTIVE_SUBSCRIPTION',
        message: 'Prvo otkažite Premium pretplatu kroz Google Play, pa pokušajte ponovo.'
      });
    }
    const result = await db.query(
      'DELETE FROM users WHERE id = $1 RETURNING id, username, email',
      [req.userId]
    );
    console.warn('[account][self-delete] Korisnik obrisao sopstveni nalog:', result.rows[0]);
    res.json({ success: true });
  } catch (err) { _sendServerError(res, err); }
});

// ════════════════════════════════════════ KVIZ I RANDORI (NEW) ════════════════════════════════════════

// FIX (20.09.2026, korisnikov zahtev - server-side kes): oba fajla su ~1.1MB, a fs.readFileSync +
// JSON.parse su SINHRONI - blokiraju CEO Node event loop dok traju (Node je jednonitan za JS
// izvrsavanje). Klijent zove ove endpoint-e na SVAKOM pokretanju app-a (fetchQuestions()/
// fetchRandori() u index.html, plus ponovo u checkForUpdates() posle svakog resume-a) - bez kesa,
// to znaci da SVAKO otvaranje app-a od BILO KOG korisnika ponovo cita+parsira 1MB+ JSON sa diska na
// serveru, blokirajuci SVE istovremene zahteve (ukljucujuci Sensei/Scouting/Journal AI pozive) dok
// traje. Sadrzaj fajlova se menja SAMO pri deploy-u (novi build) - ucitava se zato JEDNOM ovde, PRI
// STARTU servera (ne lenjo pri prvom zahtevu korisnika), da nijedan stvaran korisnicki zahtev nikad
// ne plati taj trosak. Railway restartuje proces pri svakom deploy-u, pa se kes prirodno osvezava sa
// novim sadrzajem posle svakog push-a - nema potrebe za rucnim invalidiranjem. Korisnik potvrdio da
// je OK da ovo (jednokratno, pri boot-u servera) potraje ako zatreba - klijent svakako prikazuje
// splash screen pri pokretanju app-a, pa ovaj mali jednokratan trosak SERVERA pri deploy-u (ne po
// korisniku) ne utice na percepirano vreme ucitavanja.
function _loadStaticJsonCache(fileName, label) {
  try {
    const filePath = path.join(__dirname, 'public', 'data', fileName);
    const raw = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw);
    console.log(`[STATIC_CACHE] ${label} ucitan u memoriju (${raw.length} bajtova)`);
    return parsed;
  } catch (err) {
    // Ne rusimo ceo server ako fajl nedostaje/je pokvaren pri startu - endpoint ispod ima fallback
    // na direktno citanje sa diska (isto ponasanje kao PRE ove izmene) umesto da ostane trajno mrtav.
    console.error(`[STATIC_CACHE] GRESKA pri ucitavanju ${label} pri startu:`, err.message);
    return null;
  }
}
const _quizDataCache = _loadStaticJsonCache('all_questions_v2.json', 'quiz pitanja');
const _randoriDataCache = _loadStaticJsonCache('randori_db_v2.json', 'randori baza');

app.get('/api/quiz', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=86400');
  if (_quizDataCache) return res.json(_quizDataCache);
  // Fallback - kes nije uspeo pri startu (vidi [STATIC_CACHE] log), ponasanje IDENTICNO kao pre
  // ove izmene (direktno citanje sa diska na svaki poziv dok se server ne restartuje/redeploy-uje).
  try {
    const filePath = path.join(__dirname, 'public', 'data', 'all_questions_v2.json');
    const data = fs.readFileSync(filePath, 'utf-8');
    res.json(JSON.parse(data));
  } catch (err) {
    _sendServerError(res, err, 'quiz][fajl');
  }
});

app.get('/api/randori', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=86400');
  if (_randoriDataCache) return res.json(_randoriDataCache);
  try {
    const filePath = path.join(__dirname, 'public', 'data', 'randori_db_v2.json');
    const data = fs.readFileSync(filePath, 'utf-8');
    res.json(JSON.parse(data));
  } catch (err) {
    _sendServerError(res, err, 'randori][fajl');
  }
});

// ════════════════════════════════════════ AI SENSEI PROXY ════════════════════════════════════════

// Osnovna zastita protiv zloupotrebe: limit velicine payload-a (sprecava da 5x/dan limit
// bude zaobidjen slanjem ogromnih poruka) i provera da system prompt zaista dolazi iz
// jednog od nasih poznatih izvora - bez ovoga bilo ko sa validnim JWT tokenom moze
// direktnim pozivom API-ja zameniti prompt proizvoljnim tekstom i koristiti server kao
// besplatan opsti Claude proxy na nas racun.
// CISCENJE (17.09.2026, korisnik trazio ciscenje mrtvog koda posle nalaza sa "Nevalidan system
// prompt" bagom): ranije je ovde postojao i SCOUTING_SYSTEM_SIGNATURE ('Ti si taktički analitičar
// i scouting specijalista')/isScoutingPrompt, sa komentarom da Scouting koristi DRUGACIJI potpis
// od Sensei chat/Dnevnik-a. To vise nije tacno (a mozda nikad nije ni bilo u praksi) - klijentski
// Scouting prompt (generateScoutingPlan() u index.html) UVEK pocinje sa "Ti si Sensei Kano", isto
// kao Sensei chat i Dnevnik, pa isScoutingPrompt nikad nije bio true - sva tri feature-a su se
// oslanjala iskljucivo na isSenseiPrompt ispod. Uklonjeno da kod ne zavarava buduce citanje (kao
// da postoji zastita koja realno nista ne radi) - ponasanje NEPROMENJENO za sve legitimne pozive.
const SENSEI_SYSTEM_SIGNATURE = 'Ti si Sensei Kano';
// Stvarno izmereno: staticni deo buildSenseiSystemPrompt() u index.html je ~8200 karaktera
// SAM PO SEBI, pre userContext/modeInstructions i pre istorije poruka - limit mora imati
// solidnu marzu iznad toga da ne blokira legitimne pozive, uz i dalje odsecanje ociglednog abuse-a
const MAX_SENSEI_PAYLOAD_CHARS = 20000;

// FIX (20.09.2026, korisnikov zahtev - kesiranje istorije razgovora): vidi opsiran komentar na
// mestu poziva (unutar /api/sensei/ask) za PUNO objasnjenje - ukratko, markira pretposlednju poruku
// u nizu 'messages' cache_control blokom, da bi Anthropic keširao ceo prefiks razgovora do te
// poruke (sve OSIM najnovijeg pitanja koje se sad prvi put salje). Vraca NOV niz (ne mutira
// originalni req.body.messages) - originalni ostaje netaknut za slucaj da pozivalac kasnije treba
// "cist" niz (npr. za logovanje). Bezopasno za Scouting/Journal (uvek tacno 1 poruka, if ispod ih
// odmah propusta nepromenjene) i za bilo koji poziv sa manje od 2 poruke.
function _addConversationCacheBreakpoint(messages) {
  if (!Array.isArray(messages) || messages.length < 2) return messages;
  const idx = messages.length - 2; // poslednja poruka IZ PRETHODNOG kruga, pre nove poruke na kraju
  const target = messages[idx];
  if (!target) return messages;
  // Podrzava i stari oblik (content: plain string, trenutni klijent) i buduci oblik (content: niz
  // blokova) - u oba slucaja cache_control ide na POSLEDNJI blok tog sadrzaja (Anthropic kesira sve
  // do i ukljucujuci blok sa cache_control, redosled unutar poruke nije bitan za ovu svrhu).
  let newContent;
  if (typeof target.content === 'string') {
    newContent = [{ type: 'text', text: target.content, cache_control: { type: 'ephemeral', ttl: '1h' } }];
  } else if (Array.isArray(target.content) && target.content.length > 0) {
    newContent = target.content.slice();
    const lastIdx = newContent.length - 1;
    newContent[lastIdx] = { ...newContent[lastIdx], cache_control: { type: 'ephemeral', ttl: '1h' } };
  } else {
    return messages; // nepoznat/prazan oblik sadrzaja - ne diramo, bezbednije nego nagadjati
  }
  const cloned = messages.slice();
  cloned[idx] = { ...target, content: newContent };
  return cloned;
}

app.post('/api/sensei/ask', aiLimiter, _requireAuth, _requireIntegrity, async (req, res) => {
  const { messages, system, systemStatic, systemDynamic, feature } = req.body;
  const userId = req.userId;
  // FIX (19.09.2026, korisnikov zahtev - Anthropic prompt caching): noviji klijent (Sensei chat,
  // vidi buildSenseiSystemPrompt() u index.html) sad salje system prompt podeljen na dva dela -
  // systemStatic (identican za svakog korisnika/poziv - karakter, stil, pravila, zabranjene
  // tehnike) i systemDynamic (userContext/mod/jezik - razlikuje se po korisniku). Stariji klijent
  // (jos neazuriran APK) i Scouting/Journal (namerno NEIZMENJENI, njihovi promptovi su previse
  // isprepletani jezikom/korisnickim podacima da bi se bezbedno delili u ovom prolazu) i dalje
  // salju sve u jednom 'system' stringu - to ostaje 100% podrzano, samo se tretira kao da je ceo
  // sadrzaj "staticni" deo (systemDynamic prazan), IDENTICNO ponasanje kao pre ove izmene.
  const staticPart = typeof systemStatic === 'string' ? systemStatic : system;
  const dynamicPart = typeof systemDynamic === 'string' ? systemDynamic : '';
  // Scouting, Sensei chat i Dnevnik (Journal) AI analiza dele isti endpoint ali imaju
  // odvojene dnevne limite - klijent salje feature='scouting' ili feature='journal'
  // eksplicitno; sve ostalo (obican Sensei chat) tretiramo kao 'sensei' (podrazumevana
  // vrednost) radi kompatibilnosti sa starijim verzijama klijenta koje ne salju feature.
  const isScouting = feature === 'scouting';
  const isJournal = feature === 'journal';

  // FIX (11.09.2026, security review): ranije se ovde koristio system.includes(potpis), sto
  // znaci da je bilo dovoljno da potpis postoji BILO GDE u stringu - napadac (sa validnim auth
  // tokenom, npr. presretnut/izmenjen zahtev) je mogao da posalje sopstveni system prompt sa
  // potpisom ubacenim negde u sredini/na kraju, a stvarnim (proizvoljnim) uputstvima ISPRED
  // potpisa - klasican prompt injection, iako ogranicen dnevnim/doživotnim limitom pitanja.
  // Svi legitimni system promptovi sa klijenta (buildSenseiSystemPrompt() i oba inline
  // scouting/journal template stringa) POCINJU potpisom na poziciji 0 - startsWith() ne menja
  // ponasanje ni za jedan postojeci legitiman poziv, ali odbija svaki zahtev gde je potpis
  // "ubacen" iza proizvoljnog teksta.
  const isSenseiPrompt = typeof staticPart === 'string' && staticPart.startsWith(SENSEI_SYSTEM_SIGNATURE);
  if (!isSenseiPrompt) {
    return res.status(400).json({ error: 'Nevalidan system prompt' });
  }
  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'Nedostaju messages' });
  }
  const totalChars = staticPart.length + dynamicPart.length + messages.reduce((sum, m) => sum + (typeof m.content === 'string' ? m.content.length : JSON.stringify(m.content || '').length), 0);
  if (totalChars > MAX_SENSEI_PAYLOAD_CHARS) {
    return res.status(400).json({ error: 'Zahtev je prevelik' });
  }

  const counterColumn = isScouting ? 'scouting_questions_today' : (isJournal ? 'journal_ai_today' : 'questions_today');
  const resetColumn = isScouting ? 'scouting_last_reset' : (isJournal ? 'journal_ai_last_reset' : 'last_reset');

  // RACE FIX (11.09.2026): ranije se ovde radilo SELECT -> provera u JS-u -> tek POSLE Anthropic
  // poziva UPDATE +1. Dva istovremena zahteva istog korisnika su oba mogla procitati isti
  // usedCount ispod limita i oba proci proveru, sto je omogucavalo da se dnevni/doživotni limit
  // premasi za jedan placeni Anthropic poziv po "upucenom" konkurentnom zahtevu (novac ide iz
  // dzepa, ne samo formalnost). Sada se mesto REZERVISE (increment) unutar transakcije sa
  // FOR UPDATE lock-om PRE poziva ka Anthropic-u - isti obrazac kao /api/promo/redeem. Ako
  // Anthropic poziv posle toga ipak ne uspe, rezervacija se vraca (decrement) da korisnik ne
  // izgubi pokusaj koji nije stvarno iskoristio.
  const client = await db.connect();
  let reserved = false;
  try {
    await client.query('BEGIN');
    const userResult = await client.query(
      `SELECT ${counterColumn}, ${resetColumn}, subscription_tier, subscription_expires FROM users WHERE id = $1 FOR UPDATE`,
      [userId]
    );
    if (userResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Korisnik nije pronadjen' });
    }
    const user = userResult.rows[0];
    const isPremium = _isPremiumActive(user);
    let usedCount = user[counterColumn];

    if (isPremium) {
      const today = new Date().toDateString();
      const lastReset = new Date(user[resetColumn]).toDateString();
      if (today !== lastReset) {
        await client.query(`UPDATE users SET ${counterColumn} = 0, ${resetColumn} = NOW() WHERE id = $1`, [userId]);
        usedCount = 0;
      }
    }
    // FIX 08.09.2026: ispravljeno da odgovara zvanicnom Terms of Use (Free/Premium tabela) -
    // ranije se ovde koristio isti broj za Premium dnevni i Free lifetime limit po feature-u,
    // sto je za Scouting bilo pogresno (davalo je Free korisnicima 5x doživotno umesto tacnih 3x).
    // Vidi identican fix i identican komentar u GET /api/sensei/limit/me iznad - ta dva mesta
    // MORAJU ostati usaglasena (limit/limit/me samo PRIKAZUJE koliko je ostalo, ovde se limit
    // stvarno PRIMENJUJE - razlicite vrednosti izmedju njih bi znacile da korisnik vidi jedan
    // broj a stvarno mu se dozvoljava drugi).
    const limit = isPremium
      ? (isJournal ? 3 : 5)                        // Premium: Sensei 5/dan, Scouting 5/dan, Journal 3/dan
      : (isScouting ? 3 : (isJournal ? 3 : 5));    // Free: Sensei 5x, Scouting 3x, Journal 3x - doživotno
    if (usedCount >= limit) {
      await client.query('ROLLBACK');
      return res.status(429).json({ error: 'Dostignut je limit pitanja', limit: limit, used: usedCount });
    }

    await client.query(`UPDATE users SET ${counterColumn} = ${counterColumn} + 1 WHERE id = $1`, [userId]);
    await client.query('COMMIT');
    reserved = true;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
    return _sendServerError(res, err);
  } finally {
    client.release();
  }

  try {
    // FIX (19.09.2026, korisnikov zahtev - prompt caching): 'system' se sada salje Anthropic-u kao
    // NIZ blokova umesto jednog stringa, sa cache_control na staticPart bloku. staticPart je (za
    // Sensei chat, najcesci poziv) identican tekst na SVAKOM pozivu od SVAKOG korisnika, pa ce
    // Anthropic keširati taj prefiks i naplatiti ga po ceni citanja iz kesa (10x jeftinije) cim ga
    // BILO KOJI korisnik ponovo pogodi u toku TTL prozora - ne mora biti isti korisnik. dynamicPart
    // (userContext/mod/jezik, ili prazan string za Scouting/Journal i stariji klijent) ide kao
    // DRUGI, nekesiran blok POSLE static bloka - mora ostati IZA njega jer cache_control kesira SVE
    // do i ukljucujuci taj blok (redosled je bitan). Ako je dynamicPart prazan (Scouting/Journal,
    // stariji klijent), saljemo samo jedan blok - i tada i dalje dobijamo caching korist ako se isti
    // tacan prompt ponovi (npr. isti korisnik ponovi identican zahtev).
    //
    // FIX (20.09.2026, korisnikov zahtev - produzen TTL): app JOS NIJE live (mali/nikakav
    // konkurentni saobracaj), pa je podrazumevani 5-minutni TTL prakticno beskoristan - sansa da
    // DRUGI poziv (bilo kog korisnika) stigne u istom 5-min prozoru je mala. ttl:'1h' cuva kes
    // znatno duze (cena upisa 2x umesto 1.25x baznog inputa, citanje ostaje 0.1x) - za nasku
    // situaciju (retki, razblazeni pozivi) 1h prozor realno ima sansu da pogodi kes, 5min skoro
    // nikad. Ako app kasnije naraste (vise konkurentnih korisnika u kratkom periodu), 5min bi opet
    // postao dovoljan i jeftiniji - ostaviti napomenu da se ovo revidira kad saobracaj poraste.
    // Nema potrebe za beta header-om - 1h TTL je GA (Generally Available) na trenutnoj API verziji.
    const systemBlocks = [{ type: 'text', text: staticPart, cache_control: { type: 'ephemeral', ttl: '1h' } }];
    if (dynamicPart) systemBlocks.push({ type: 'text', text: dynamicPart });

    // FIX (20.09.2026, korisnikov zahtev - kesiranje ISTORIJE razgovora, ne samo system prompta):
    // do sada je SAMO staticPart system bloka bio kesiran - cela istorija razgovora (messages, kod
    // viseturnog Sensei chat-a moze imati i do 20 poruka) se na SVAKI sledeci upit ponovo slala i
    // NAPLACIVALA PUNOM cenom, iako se prethodnih N-1 poruka ne menja izmedju dva uzastopna poziva
    // istog korisnika (samo se nova poruka korisnika dodaje na kraj). _addConversationCacheBreakpoint
    // (definisano ispod) markira PRETPOSLEDNJU poruku (poslednju iz PRETHODNOG kruga, pre nove
    // poruke koja se sad salje) cache_control blokom - Anthropic tada kesira SVE do i ukljucujuci tu
    // poruku. Sledeci poziv (nova poruka + odgovor dodati na kraj) pogadja TACNO taj kes za ceo
    // prethodni deo istorije, place se puna cena SAMO za najnoviji par poruka. Za Scouting/Journal
    // (uvek tacno 1 poruka, bez istorije) ova funkcija ne radi nista (vidi proveru unutra) - NULA
    // promena ponasanja za njih. Radi se OVDE, na serveru, a ne na klijentu - stize svim korisnicima
    // odmah posle deploy-a, bez potrebe za novim APK-om.
    const cachedMessages = _addConversationCacheBreakpoint(messages);

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 4000, system: systemBlocks, messages: cachedMessages })
    });
    const data = await response.json();

    // FIX (17.09.2026, korisnikov nalaz - Scouting/Sensei ponekad vrate odsecen odgovor tipa
    // "TACTICAL PLAN — Ime vs." bez ikakvog nastavka, iako data.content NIJE prazan): klijent sad
    // odbacuje ovakve prekratke odgovore (vidi FIX istog datuma u index.html), ali do sada nismo
    // imali NIKAKAV trag zasto Anthropic vraca odsecen sadrzaj. Anthropic API uvek vraca
    // stop_reason:'end_turn' za normalno zavrsen odgovor - bilo sta drugo ('max_tokens',
    // 'stop_sequence'...) je pouzdan, direktan signal da je odgovor stvarno odsecen sa NJIHOVE
    // strane, ne nas nagadjanje po duzini teksta. Ovaj log hvata TACNO taj slucaj u Railway
    // logovima - sledeci put kad se ponovi, trazimo "AI_TRUNCATED" umesto da nagadjamo.
    try {
      if (!data.error && data.stop_reason && data.stop_reason !== 'end_turn') {
        const _contentLen = Array.isArray(data.content) ? data.content.map(b => (b && b.text) || '').join('').length : 0;
        console.warn('[AI_TRUNCATED]', JSON.stringify({
          userId, feature: feature || 'sensei', stop_reason: data.stop_reason,
          contentLen: _contentLen, usage: data.usage || null
        }));
      }
    } catch (logErr) { /* logovanje ne sme nikad da obori pravi odgovor korisniku */ }

    // LOG (19.09.2026, prompt caching): kratak trag u Railway logovima da se vidi da li se kes
    // stvarno koristi posle deploy-a - cache_read_input_tokens > 0 znaci pogodak (naplaceno 10x
    // jeftinije), cache_creation_input_tokens > 0 znaci da je OVAJ poziv upisao/osvezio kes (redovno
    // za prvi poziv u prozoru, ocekivano). Namerno bez userId/feature detalja ovde - ovo je cisto
    // dijagnostika troska, ne treba mu poseban nivo (console.log dovoljno, ne warn/error).
    if (data.usage) {
      console.log('[AI_CACHE]', JSON.stringify({
        cacheRead: data.usage.cache_read_input_tokens || 0,
        cacheWrite: data.usage.cache_creation_input_tokens || 0,
        inputTokens: data.usage.input_tokens || 0
      }));
    }

    // Anthropic poziv nije uspeo - vrati rezervisano mesto nazad (korisnik ne gubi pokusaj)
    if (data.error && reserved) {
      await db.query(`UPDATE users SET ${counterColumn} = GREATEST(${counterColumn} - 1, 0) WHERE id = $1`, [userId]).catch(() => {});
    }

    res.json(data);
  } catch (err) {
    if (reserved) {
      await db.query(`UPDATE users SET ${counterColumn} = GREATEST(${counterColumn} - 1, 0) WHERE id = $1`, [userId]).catch(() => {});
    }
    _sendServerError(res, err);
  }
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
  } catch (err) { _sendServerError(res, err); }
});

app.post('/api/quiz/stats', _requireAuth, async (req, res) => {
  const { score, correct, total, maxStreak, category, breakdown } = req.body;
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

  // FIX (11.09.2026, korisnik prijavio bag - trakice po kategoriji trajno na 0%): ranije se
  // slala samo JEDNA "dominantna" kategorija cele partije (>=60% odgovora, inace 'mixed'), pa
  // je server cuvao npr. 'mixed' kao category - string koji renderCatStats() na klijentu ne
  // prepoznaje (ocekuje tacno tehnika/taktika/pravila/istorija/filozofija/japanski/situacija).
  // Sada klijent salje ceo "breakdown" (tacni odgovori po stvarnoj kategoriji pitanja), koji
  // ide u posebnu quiz_category_stats tabelu - nazivi kategorija su isti kljucevi koje pitanja
  // vec nose (q.type), pa se poklapaju sa UI-jem bez ikakve heuristike/pogadjanja.
  let cleanBreakdown = [];
  if (Array.isArray(breakdown)) {
    let sumCorrect = 0;
    cleanBreakdown = breakdown
      .map(function(row) {
        const cat = row && typeof row.category === 'string' ? row.category.slice(0, 40) : null;
        const cc = Number(row && row.correct) || 0;
        return cat && cc > 0 ? { category: cat, correct: cc } : null;
      })
      .filter(Boolean);
    cleanBreakdown.forEach(function(row) { sumCorrect += row.correct; });
    // Zbir po kategorijama ne sme premasiti ukupan broj tacnih odgovora partije (ista logika
    // anti-cheat provere kao i za c/t/ms iznad).
    if (sumCorrect > c) cleanBreakdown = [];
  }

  // RACE FIX (11.09.2026): SELECT+provera+UPDATE +1 su ranije bila tri odvojena poziva bez
  // zakljucavanja reda - dva istovremena POST-a (npr. skriptovan/automatizovan klijent) mogla
  // su oba procitati playsToday ispod 3 i oba proci, dozvoljavajuci vise od 3 partije dnevno
  // za Free korisnika. Sada je citanje+provera+increment u jednoj transakciji sa FOR UPDATE
  // lock-om, isti obrazac kao /api/promo/redeem i /api/sensei/ask.
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const userResult = await client.query(
      'SELECT quiz_plays_today, quiz_last_reset, subscription_tier, subscription_expires FROM users WHERE id = $1 FOR UPDATE',
      [userId]
    );
    if (userResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Korisnik nije pronadjen' });
    }
    const user = userResult.rows[0];
    const isPremium = _isPremiumActive(user);
    let playsToday = user.quiz_plays_today;

    // Free: 3x dnevno. Premium: neograniceno (vidi memorije - "Kviz unlimited" za premium),
    // pa se limit i reset provera preskacu potpuno za premium korisnike.
    if (!isPremium) {
      const today = new Date().toDateString();
      const lastReset = new Date(user.quiz_last_reset).toDateString();
      if (today !== lastReset) {
        await client.query('UPDATE users SET quiz_plays_today = 0, quiz_last_reset = NOW() WHERE id = $1', [userId]);
        playsToday = 0;
      }
      if (playsToday >= 3) {
        await client.query('ROLLBACK');
        return res.status(429).json({ error: 'Dostignut je dnevni limit kviza', limit: 3, used: playsToday });
      }
      await client.query('UPDATE users SET quiz_plays_today = quiz_plays_today + 1 WHERE id = $1', [userId]);
    }

    await client.query(
      'INSERT INTO quiz_stats (user_id, score, correct, total, max_streak, category) VALUES ($1, $2, $3, $4, $5, $6)',
      [userId, s, c, t, ms, category || 'mixed']
    );
    for (const row of cleanBreakdown) {
      await client.query(
        'INSERT INTO quiz_category_stats (user_id, category, correct) VALUES ($1, $2, $3)',
        [userId, row.category, row.correct]
      );
    }
    await client.query('UPDATE users SET updated_at = NOW() WHERE id = $1', [userId]);
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    _sendServerError(res, err);
  } finally {
    client.release();
  }
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
app.get('/api/admin/bug-reports', adminLimiter, async (req, res) => {
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
app.post('/api/admin/bug-reports/:id/status', adminLimiter, async (req, res) => {
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
app.delete('/api/admin/bug-reports/:id', adminLimiter, async (req, res) => {
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

    // FIX (11.09.2026): ranije se citalo iz quiz_stats.category, koje sadrzi samo JEDNU
    // "dominantnu" kategoriju po celoj partiji (cesto 'mixed') - sada quiz_category_stats
    // cuva tacne odgovore po stvarnoj kategoriji pitanja (isti kljucevi koje UI ocekuje).
    const byCategory = await db.query(`
      SELECT
        category,
        COALESCE(SUM(correct), 0)::int AS correct
      FROM quiz_category_stats
      WHERE user_id = $1
      GROUP BY category
      ORDER BY correct DESC
    `, [userId]);

    res.json({
      allTime: allTime.rows[0],
      thisMonth: thisMonth.rows[0],
      byCategory: byCategory.rows
    });
  } catch (err) { _sendServerError(res, err); }
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
  } catch (err) { _sendServerError(res, err); }
});

// Ažuriraj verziju fajla (admin operacija)
app.post('/api/data/bump-version', adminLimiter, async (req, res) => {
  const { filename, secret } = req.body;
  if (!process.env.ADMIN_SECRET || !_timingSafeStrEqual(String(secret || ''), process.env.ADMIN_SECRET)) {
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
  } catch (err) { _sendServerError(res, err); }
});

// Dohvati sve verzije
app.get('/api/data/versions', async (req, res) => {
  try {
    const result = await db.query('SELECT filename, version, updated_at FROM data_versions ORDER BY filename');
    res.json(result.rows);
  } catch (err) { _sendServerError(res, err); }
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
  } catch (err) { _sendServerError(res, err); }
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

  // RESET GUARD (12.09.2026) - vidi opsiran komentar uz RESET_GUARD_WINDOW_MS kod /api/xp/update.
  // Isti problem postoji i ovde: DELETE FROM user_data (npr. rucni reset randori napretka)
  // ostavlja PRAZAN red za taj data_type, a pullGenericSync() na klijentu, kad zatekne prazan
  // server odgovor, ODMAH gura svoj lokalni (zastareli) keš nazad - sto trenutno ponisti reset.
  // Ovde odbacujemo (preskacemo, ne upisujemo) svaku stavku ciji je item.updatedAt stariji od
  // poslednjeg rucnog reseta, dok je reset "svez" (isti 24h prozor kao kod XP-a).
  let _resetAtForSync = null;
  try {
    const _rr = await db.query('SELECT reset_at FROM users WHERE id = $1', [userId]);
    _resetAtForSync = _rr.rows[0] ? _rr.rows[0].reset_at : null;
  } catch (eResetLookup) {
    console.warn('[userdata][reset-guard] Greska pri citanju reset_at, nastavljam bez zastite:', eResetLookup.message);
  }
  const _guardActive = _isResetGuardActive(_resetAtForSync);
  let _skippedStale = 0;

  // Deljena logika upisa/brisanja jedne stavke - prima "q" (obican pool `db` ili `client" unutar
  // transakcije) da bi journal grana ispod mogla da upisuje unutar iste transakcije/FOR UPDATE
  // lock-a kao provera limita (vidi RACE FIX 2 ispod), dok ostali tipovi podataka i dalje idu
  // direktno preko `db` bez transakcije (nemaju limit koji treba stititi).
  async function _writeItem(q, item) {
    if (!item || !item.key) return;
    if (_guardActive) {
      const _itemTs = item.updatedAt ? new Date(item.updatedAt).getTime() : NaN;
      const _resetTs = new Date(_resetAtForSync).getTime();
      if (!Number.isFinite(_itemTs) || _itemTs < _resetTs) { _skippedStale++; return; }
    }
    if (item.deleted) {
      await q.query(
        'DELETE FROM user_data WHERE user_id = $1 AND data_type = $2 AND data_key = $3',
        [userId, dataType, item.key]
      );
    } else {
      await q.query(
        `INSERT INTO user_data (user_id, data_type, data_key, payload, updated_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id, data_type, data_key)
         DO UPDATE SET payload = $4, updated_at = $5
         WHERE user_data.updated_at < $5`,
        [userId, dataType, item.key, JSON.stringify(item.payload), item.updatedAt || new Date().toISOString()]
      );
    }
  }

  // Dnevnik limit (3x lifetime free / 3x dnevno premium) primenjen samo na journal tip i
  // samo na NOVE unose (ne na brisanje ili na jednokratnu migraciju postojecih lokalnih
  // podataka pri prvom loginu - migrateAndPull salje ceo postojeci spisak odjednom i taj
  // slucaj ne sme biti blokiran istim limitom kao svakodnevno kreiranje novih unosa).
  if (dataType === 'journal') {
    const newEntries = items.filter(function(it) { return it && it.key && !it.deleted; });
    // RACE FIX (11.09.2026): SELECT + provera + UPDATE/COUNT su ranije bila odvojeni pozivi
    // bez zakljucavanja reda - dva istovremena sync poziva (npr. dva uredjaja/tabova istog
    // korisnika koja se sinhronizuju u isto vreme) su mogla oba proci proveru pre nego sto
    // ijedan upise novo stanje, dozvoljavajuci limit da bude premasen za jedan unos. Sada je
    // provera+increment (premium granu) odnosno provera (free granu) unutar transakcije sa
    // FOR UPDATE lock-om na korisnickom redu, isti obrazac kao /api/promo/redeem.
    //
    // BATCH FIX (11.09.2026): provera je ranije gledala samo "koliko VEC postoji/je
    // iskorisceno" i propustala ceo 'items' niz ako je ta brojka bila ispod limita - ali
    // petlja ispod upisuje SVE stavke iz niza, bez obzira koliko ih ima. Klijent je mogao
    // da posalje npr. 10 novih dnevnickih zapisa u JEDNOM sync pozivu i limit od 3 bi bio
    // potpuno zaobidjen (za free: 3 zauvek -> proizvoljno mnogo; za premium: dnevni brojac
    // se uvecavao za 1 po pozivu bez obzira na broj stavki). Sada se prvo utvrdi koliko je
    // od poslatih kljuceva STVARNO novo (nije vec u bazi - re-sync/izmena postojeceg zapisa
    // se ne racuna kao nov unos), pa se ta stvarna kolicina poredi sa preostalim limitom.
    //
    // RACE FIX 2 (18.09.2026, QA test otkrio): originalni RACE FIX iznad je zakljucavao red i
    // proveravao limit unutar transakcije, ALI je stvarni upis novih zapisa (INSERT INTO
    // user_data) ostajao u genericnoj petlji ISPOD, IZVAN te transakcije (preko db.query, ne
    // client.query) - transakcija se COMMIT-ovala (pustajuci lock) pre nego sto je ijedan red
    // stvarno upisan. Za Premium granu ovo je slucajno bilo bezopasno jer se limit tamo pamti
    // preko brojaca (journal_entries_today) koji SE inkrementira unutar transakcije - ali za
    // Free granu, koja limit racuna brojanjem redova u user_data, dva paralelna zahteva su oba
    // mogla proci proveru (video COUNT=0) pre nego sto ijedan upise svoj red, i oba upisati -
    // live test je potvrdio da 6 paralelnih zahteva sa lifetime limitom od 3 sve upise sve. Sada
    // se stvarni upis (za SVE stavke ovog sync poziva, ne samo nove) izvrsava ovde, unutar iste
    // transakcije/lock-a kao provera, pre COMMIT-a.
    const client = await db.connect();
    let writer = client;
    let earlyResponse = null;
    try {
      await client.query('BEGIN');
      if (newEntries.length > 0) {
        try {
          const userResult = await client.query(
            'SELECT journal_entries_today, journal_last_reset, subscription_tier, subscription_expires FROM users WHERE id = $1 FOR UPDATE',
            [userId]
          );
          if (userResult.rows.length > 0) {
            const user = userResult.rows[0];
            const isPremium = _isPremiumActive(user);

            const newKeys = newEntries.map(function(it) { return it.key; });
            const existingKeysResult = await client.query(
              "SELECT data_key FROM user_data WHERE user_id = $1 AND data_type = 'journal' AND data_key = ANY($2::text[])",
              [userId, newKeys]
            );
            const existingKeySet = new Set(existingKeysResult.rows.map(function(r) { return r.data_key; }));
            // Duplikati unutar samog batch-a se broje samo jednom - Set nad kljucevima
            const trulyNewCount = new Set(newKeys.filter(function(k) { return !existingKeySet.has(k); })).size;

            if (isPremium) {
              const today = new Date().toDateString();
              const lastReset = new Date(user.journal_last_reset).toDateString();
              let usedToday = user.journal_entries_today;
              if (today !== lastReset) {
                await client.query('UPDATE users SET journal_entries_today = 0, journal_last_reset = NOW() WHERE id = $1', [userId]);
                usedToday = 0;
              }
              if (usedToday + trulyNewCount > 3) {
                await client.query('ROLLBACK');
                earlyResponse = { status: 429, body: { error: 'Dostignut je dnevni limit dnevnika', limit: 3, used: usedToday } };
              } else if (trulyNewCount > 0) {
                await client.query('UPDATE users SET journal_entries_today = journal_entries_today + $2 WHERE id = $1', [userId, trulyNewCount]);
              }
            } else {
              // Free: 3x lifetime - brojimo postojece zapise u bazi (tacnije od posebnog
              // brojaca jer automatski iskljucuje duplikate/re-sync istog id-a). FOR UPDATE
              // na users redu gore serijalizuje ovu proveru po korisniku.
              const countResult = await client.query(
                "SELECT COUNT(*)::int AS n FROM user_data WHERE user_id = $1 AND data_type = 'journal'",
                [userId]
              );
              const existing = countResult.rows[0].n;
              if (existing + trulyNewCount > 3) {
                await client.query('ROLLBACK');
                earlyResponse = { status: 429, body: { error: 'Dostignut je limit dnevnika', limit: 3, used: existing } };
              }
            }
          }
        } catch (limitErr) {
          // Soft-fail (isti duh kao pre ovog fixa): ne blokiramo sync zbog greske u SAMOJ
          // proveri limita - ali napustamo transakciju/lock da bi upis ispod mogao da prodje;
          // ostatak stavki se u ovom retkom slucaju upisuje bez zakljucavanja (isti rizik kao
          // pre fixa, samo kad SAMA provera baci gresku, ne pri normalnom upisu).
          await client.query('ROLLBACK').catch(() => {});
          console.error('[userdata][journal-limit] Greska pri proveri limita:', limitErr.message);
          writer = db;
        }
      }

      if (!earlyResponse) {
        for (const item of items) {
          await _writeItem(writer, item);
        }
        if (writer === client) {
          await client.query('COMMIT');
        }
      }
    } catch (err) {
      if (writer === client) { await client.query('ROLLBACK').catch(() => {}); }
      client.release();
      return _sendServerError(res, err);
    }
    client.release();

    if (earlyResponse) {
      return res.status(earlyResponse.status).json(earlyResponse.body);
    }
    return res.json(_skippedStale > 0
      ? { success: true, resetRequired: true, resetAt: _resetAtForSync, skippedStale: _skippedStale }
      : { success: true });
  }

  try {
    for (const item of items) {
      await _writeItem(db, item);
    }
    res.json(_skippedStale > 0
      ? { success: true, resetRequired: true, resetAt: _resetAtForSync, skippedStale: _skippedStale }
      : { success: true });
  } catch (err) { _sendServerError(res, err); }
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
  } catch (err) { _sendServerError(res, err); }
});

// Javna homepage stranica (zahtev Google OAuth verifikacije, 20.09.2026):
// consent screen "Application home page" mora da vodi na javno dostupnu,
// bez-login stranicu koja objasnjava svrhu app-a i sadrzi tacan naziv "Judo Academy".
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Legal documents
// NAPOMENA: servira se .html (ne .pdf) jer Google Play odbija privacy policy URL
// ako content-type nije text/html ("does not link to a valid privacy policy page").
app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});
app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
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
//
// NAPOMENA (22.09.2026, korisnikov zahtev - dashboard cleanup):
// TECHNIQUE_IDS niz i buildTechniqueIdsCTE() su UKLONJENI - koristili su se
// samo za "Tehnike koje niko ne gleda" panel, koji je uklonjen (nisko-akcionabilan
// podatak - sa 90 tehnika i rolling 30-dana prozorom, neka grupa ce uvek ispasti
// "neviđena" cisto statisticki, bez obzira da li je sadrzaj problematican).
// ============================================================

// ════════════════════════════════════════ ADMIN DASHBOARD ════════════════════════════════════════

app.get('/api/admin/dashboard', adminLimiter, async (req, res) => {
  if (!_checkAdminKey(req, res)) return;

  // FIX (23.09.2026, server optimizacija): q()/qRange() sada vracaju FUNKCIJU (lenji poziv) umesto
  // da odmah pokrenu upit. Ranije je db.query(...) pucao ODMAH kad se queries objekat gradi (linija
  // po liniju, sinhrono) - do trenutka Promise.all() na kraju, svih ~43 upita vec je bilo poslato
  // ka Postgres-u istovremeno. Sad se upit pokrece tek kad se pozove kao funkcija - omogucava
  // izvrsavanje u talasima (ispod, pre res.json) umesto svih odjednom. Ni jedan od 43 poziva
  // q(...)/qRange(...) ispod NIJE menjan - i dalje se pisu identicno, samo se sad lenjo izvrsavaju.
  const q = (sql) => () => db.query(sql).then(r => r.rows).catch(err => ({ error: err.message }));

  // DODATAK (22.09.2026, korisnikov zahtev): opcioni ?from=&to= (ISO datumi) menja period SAMO za
  // upite koji hrane dnevne trend-grafikone (paywall/sesije/greske/AI kvalitet/duzina sesije,
  // preko qRange() ispod) - ostali paneli (retencija, promo, nalozi...) zadrzavaju svoje fiksne
  // rolling prozore jer to ima smisla po definiciji (npr. "istice u narednih 14 dana" ne moze
  // biti "prosli mart"). Bez parametara, ponasanje je isto kao pre (poslednjih 30 dana).
  const _toParsed = req.query.to ? new Date(req.query.to) : null;
  const _fromParsed = req.query.from ? new Date(req.query.from) : null;
  const _validRange = _toParsed && _fromParsed && !isNaN(_toParsed) && !isNaN(_fromParsed) && _fromParsed < _toParsed;
  const rangeTo = _validRange ? _toParsed : new Date();
  const rangeFrom = _validRange ? _fromParsed : new Date(rangeTo.getTime() - 30 * 24 * 60 * 60 * 1000);
  const qRange = (sql) => () => db.query(sql, [rangeFrom, rangeTo]).then(r => r.rows).catch(err => ({ error: err.message }));

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
      // IZMENJENO (22.09.2026, korisnikov zahtev): koristi qRange() umesto q() - postuje ?from/?to
      // period selektor kad je postavljen, inace isto ponasanje kao pre (poslednjih 30 dana).
      paywall_daily_trend: qRange(`
        SELECT date_trunc('day', created_at) AS day, COUNT(*) AS modal_views
        FROM analytics_events
        WHERE event_name = 'premium_modal_view' AND created_at BETWEEN $1 AND $2
        GROUP BY 1 ORDER BY 1
      `),
      // DODATAK (13.09.2026, korisnikov zahtev): klik na "Upravljaj pretplatom" je rani signal da
      // korisnik razmislja o otkazivanju - do sada se belezio (trackEvent) ali se nigde nije
      // prikazivao. Samo za korisnike koji su TRENUTNO premium (da ne mesamo sa istorijskim
      // klikovima nekoga ko je vec otkazao i vratio se).
      paywall_manage_subscription_clicks: q(`
        SELECT ae.user_id, u.username, u.email, COUNT(*) AS clicks, MAX(ae.created_at) AS last_click
        FROM analytics_events ae
        JOIN users u ON u.id = ae.user_id
        WHERE ae.event_name = 'premium_manage_subscription_click'
          AND ae.created_at > now() - interval '30 days'
          AND u.subscription_tier = 'premium'
        GROUP BY ae.user_id, u.username, u.email
        ORDER BY clicks DESC, last_click DESC
      `),
      // DODATAK (13.09.2026): direktno iz users tabele (ne analytics_events) - premium korisnici
      // kojima pretplata istice u narednih 14 dana. Akcionabilno za re-engagement/podsetnik pre
      // isteka, podatak vec postoji u subscription_expires koloni ali se nigde ne prikazuje.
      paywall_renewal_risk: q(`
        SELECT username, email, club, subscription_expires,
          (subscription_expires::date - CURRENT_DATE) AS days_left
        FROM users
        WHERE subscription_tier = 'premium'
          AND subscription_expires IS NOT NULL
          AND subscription_expires BETWEEN now() AND now() + interval '14 days'
        ORDER BY subscription_expires ASC
      `),

      // ---------- ONBOARDING ----------
      // UKLONJENO (22.09.2026, korisnikov zahtev): onboarding je obavezan korak bez mogucnosti
      // odustajanja, pa su funnel/abandon/completion-rate upiti bili mrtvi podaci po definiciji
      // (completion rate je uvek ~100%, "gde se odustaje" nema smisla kad nema odustajanja).

      // ---------- SESSION ----------
      sessions_per_day: qRange(`
        SELECT date_trunc('day', created_at) AS day, COUNT(*) AS sessions, COUNT(DISTINCT user_id) AS unique_users
        FROM analytics_events
        WHERE event_name = 'app_session_start' AND created_at BETWEEN $1 AND $2
        GROUP BY 1 ORDER BY 1
      `),
      session_length_distribution: qRange(`
        SELECT (event_data->>'totalMinutes')::int AS minutes_reached, COUNT(*) AS n
        FROM analytics_events
        WHERE event_name = 'session_heartbeat' AND created_at BETWEEN $1 AND $2
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
      error_daily_trend: qRange(`
        SELECT date_trunc('day', created_at) AS day, COUNT(*) AS total_errors, COUNT(DISTINCT user_id) AS affected_users
        FROM analytics_events
        WHERE event_name = 'silent_error' AND created_at BETWEEN $1 AND $2
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
      // DODATO (17.09.2026, korisnikov nalaz - odsecen/nepotpun AI odgovor u Scouting/Sensei/
      // Dnevnik): namenski, uzak filter SAMO za nove provere dodate istog datuma (prekratak/
      // odsecen AI odgovor i prazan data.content) - bez ovoga bi ove greske bile zakopane u
      // error_top_messages (limit 30, sortirano po ucestalosti), gde bi ih generisan saobracaj
      // drugih, nebitnih gresaka mogao istisnuti sa liste. event_data->>'message' sadrzi i sam
      // POCETAK odsecenog AI teksta (npr. "TACTICAL PLAN — Ime vs.") - to je upravo trag koji nam
      // je nedostajao za dijagnozu. Poredi se sa server-side [AI_TRUNCATED] logom u Railway (isti
      // datum, vidi /api/sensei/ask) po vremenu/userId da se potvrdi da li se poklapaju.
      error_ai_truncated: q(`
        SELECT created_at, user_id, event_data->>'context' AS context, event_data->>'message' AS message
        FROM analytics_events
        WHERE event_name = 'silent_error' AND created_at > now() - interval '30 days'
          AND (
            event_data->>'message' ILIKE '%prekratak%'
            OR event_data->>'message' ILIKE '%Prazan AI odgovor%'
            OR event_data->>'message' ILIKE '%neocekivan AI odgovor%'
            OR event_data->>'context' ILIKE '%\\_short'
          )
        ORDER BY created_at DESC LIMIT 50
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
      // UKLONJENO (22.09.2026, korisnikov zahtev): content_never_viewed_techniques - nisko-akcionabilan
      // podatak, vidi napomenu iznad TECHNIQUE_IDS bloka.
      content_quiz_accuracy_by_category: q(`
        SELECT event_data->>'type' AS category, COUNT(*) AS total_answers,
          COUNT(DISTINCT user_id) AS unique_users,
          COUNT(*) FILTER (WHERE (event_data->>'correct')::boolean = true) AS correct_answers,
          ROUND(100.0 * COUNT(*) FILTER (WHERE (event_data->>'correct')::boolean = true) / COUNT(*), 1) AS accuracy_pct
        FROM analytics_events
        WHERE event_name = 'quiz_answer' AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY accuracy_pct ASC
      `),
      // DODATAK (22.09.2026, korisnikov zahtev): tacnost kviza po jeziku - da li su pitanja na
      // pojedinim jezicima sistematski teza/losije prevedena. Zahteva da 'quiz_answer' event nosi
      // 'lang' polje (dodato u index.html uz ovu izmenu) - dok se ne izgradi i objavi nova verzija
      // app-a, ovaj panel ce pokazivati "nema podataka".
      content_quiz_accuracy_by_lang: q(`
        SELECT event_data->>'lang' AS lang, COUNT(*) AS total_answers,
          COUNT(*) FILTER (WHERE (event_data->>'correct')::boolean = true) AS correct_answers,
          ROUND(100.0 * COUNT(*) FILTER (WHERE (event_data->>'correct')::boolean = true) / COUNT(*), 1) AS accuracy_pct
        FROM analytics_events
        WHERE event_name = 'quiz_answer' AND created_at > now() - interval '30 days'
          AND event_data->>'lang' IS NOT NULL
        GROUP BY 1 ORDER BY accuracy_pct ASC
      `),
      // DODATAK (22.09.2026, korisnikov zahtev): najteza pojedinacna pitanja (ne samo po kategoriji) -
      // pomaze sadrzajnom timu da nadje konkretno lose formulisano pitanje. Zahteva 'qtext' polje u
      // 'quiz_answer' eventu (dodato uz ovu izmenu) - prazno dok se ne objavi nova verzija app-a.
      // HAVING >= 5 da izbaci sum od pitanja odgovorenih samo jednom-dvaput.
      content_quiz_hardest_questions: q(`
        SELECT event_data->>'type' AS category, event_data->>'qtext' AS question_excerpt,
          COUNT(*) AS total_answers,
          ROUND(100.0 * COUNT(*) FILTER (WHERE (event_data->>'correct')::boolean = true) / COUNT(*), 1) AS accuracy_pct
        FROM analytics_events
        WHERE event_name = 'quiz_answer' AND created_at > now() - interval '30 days'
          AND event_data->>'qtext' IS NOT NULL
        GROUP BY 1, 2 HAVING COUNT(*) >= 5 ORDER BY accuracy_pct ASC LIMIT 20
      `),
      // IZMENJENO (22.09.2026, korisnikov zahtev): spojeno sa tacnoscu odgovora (ranije samo views).
      // Zahteva 'randori_answer' event (dodato u index.html uz ovu izmenu, ranije se tacnost
      // pratila SAMO lokalno na uredjaju, nikad nije slata na server) - dok se ne objavi nova verzija
      // app-a, total_answers/correct_answers/accuracy_pct kolone ce biti 0/prazne, views i dalje rade
      // (taj event vec postoji).
      content_randori_by_category: q(`
        WITH views AS (
          SELECT event_data->>'cat' AS category, COUNT(*) AS views, COUNT(DISTINCT user_id) AS unique_users
          FROM analytics_events
          WHERE event_name = 'randori_scenario_view' AND created_at > now() - interval '30 days'
          GROUP BY 1
        ),
        answers AS (
          SELECT event_data->>'cat' AS category, COUNT(*) AS total_answers,
            COUNT(*) FILTER (WHERE (event_data->>'correct')::boolean = true) AS correct_answers,
            ROUND(100.0 * COUNT(*) FILTER (WHERE (event_data->>'correct')::boolean = true) / COUNT(*), 1) AS accuracy_pct
          FROM analytics_events
          WHERE event_name = 'randori_answer' AND created_at > now() - interval '30 days'
          GROUP BY 1
        )
        SELECT COALESCE(v.category, a.category) AS category,
          COALESCE(v.views, 0) AS views, COALESCE(v.unique_users, 0) AS unique_users,
          COALESCE(a.total_answers, 0) AS total_answers, COALESCE(a.correct_answers, 0) AS correct_answers,
          a.accuracy_pct
        FROM views v FULL OUTER JOIN answers a ON a.category = v.category
        ORDER BY views DESC NULLS LAST
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
        UNION ALL
        -- DODATAK (13.09.2026, korisnikov zahtev): dc_complete (Dnevni izazov - glavni home-screen
        -- CTA) i sensei_question (ceo AI Sensei modul) su se vec belezili u analytics_events, ali
        -- se NIGDE nisu prikazivali na dashboard-u - content_overview je pokrivao samo 3 od 5
        -- glavnih tipova sadrzaja.
        SELECT 'dc_complete', COUNT(*), COUNT(DISTINCT user_id)
        FROM analytics_events WHERE event_name = 'dc_complete' AND created_at > now() - interval '30 days'
        UNION ALL
        SELECT 'sensei_question', COUNT(*), COUNT(DISTINCT user_id)
        FROM analytics_events WHERE event_name = 'sensei_question' AND created_at > now() - interval '30 days'
      `),

      // DODATAK (13.09.2026): kviz funnel start -> finish/timeout - content_quiz_accuracy_by_category
      // pokriva samo tacnost ODGOVORA, ne i stopu napustanja kviza na pola.
      content_quiz_funnel: q(`
        SELECT event_name, COUNT(*) AS n, COUNT(DISTINCT user_id) AS unique_users
        FROM analytics_events
        WHERE event_name IN ('quiz_start','quiz_finish','quiz_timeout') AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY 2 DESC
      `),

      // DODATAK (13.09.2026): deljenje (leaderboard izazov + progress kartica) - meri organski/
      // virality kanal, do sada se samo belezilo bez ijednog agregata.
      content_share_funnel: q(`
        SELECT event_name, COUNT(*) AS n, COUNT(DISTINCT user_id) AS unique_users
        FROM analytics_events
        WHERE event_name IN ('lb_share_challenge','progress_share') AND created_at > now() - interval '30 days'
        GROUP BY 1 ORDER BY 2 DESC
      `),

      // ---------- AI QUALITY ----------
      ai_feedback_summary: q(`
        SELECT feature,
          COUNT(*) FILTER (WHERE rating = 'up') AS thumbs_up,
          COUNT(*) FILTER (WHERE rating = 'down') AS thumbs_down,
          ROUND(100.0 * COUNT(*) FILTER (WHERE rating = 'up') / NULLIF(COUNT(*), 0), 1) AS positive_pct
        FROM ai_feedback
        WHERE created_at > now() - interval '30 days'
        GROUP BY feature ORDER BY feature
      `),
      ai_feedback_daily_trend: qRange(`
        SELECT date_trunc('day', created_at) AS day, feature,
          COUNT(*) FILTER (WHERE rating = 'up') AS thumbs_up,
          COUNT(*) FILTER (WHERE rating = 'down') AS thumbs_down
        FROM ai_feedback
        WHERE created_at BETWEEN $1 AND $2
        GROUP BY 1, 2 ORDER BY 1, 2
      `),
      ai_feedback_by_lang: q(`
        SELECT lang, feature,
          COUNT(*) FILTER (WHERE rating = 'up') AS thumbs_up,
          COUNT(*) FILTER (WHERE rating = 'down') AS thumbs_down
        FROM ai_feedback
        WHERE created_at > now() - interval '30 days' AND lang IS NOT NULL
        GROUP BY 1, 2 ORDER BY 1, 2
      `),
      ai_feedback_recent_negative: q(`
        SELECT feature, response_excerpt, lang, created_at
        FROM ai_feedback
        WHERE rating = 'down' AND created_at > now() - interval '30 days'
        ORDER BY created_at DESC LIMIT 50
      `),

      // ---------- PROMO KONVERZIJA (13.09.2026, korisnikov zahtev) ----------
      // /api/admin/promo/list vec daje sirov spisak kodova, ali nijedan agregat - koliko je od
      // ukupnog kapaciteta (max_uses zbirno) stvarno iskorisceno, i po kampanji (note polje, npr.
      // "JK Trudbenik - decembar 2026") - korisno za merenje uspesnosti promo akcija sa klubovima.
      promo_conversion_summary: q(`
        SELECT
          COUNT(*) AS total_codes,
          SUM(used_count) AS total_redemptions,
          SUM(max_uses) AS total_capacity,
          ROUND(100.0 * SUM(used_count) / NULLIF(SUM(max_uses), 0), 1) AS overall_conversion_pct
        FROM promo_codes
      `),
      promo_conversion_by_campaign: q(`
        SELECT COALESCE(note, '(bez napomene)') AS campaign,
          COUNT(*) AS codes, SUM(used_count) AS redemptions, SUM(max_uses) AS capacity,
          ROUND(100.0 * SUM(used_count) / NULLIF(SUM(max_uses), 0), 1) AS conversion_pct
        FROM promo_codes
        GROUP BY 1 ORDER BY redemptions DESC
      `),

      // ---------- NALOZI - DEMOGRAFIJA (13.09.2026, korisnikov zahtev) ----------
      // users tabela vec ima club/country iz profila, ali se nigde ne agregira - relevantno jer
      // saradnja ide direktno sa klubovima/savezima (npr. JK Trudbenik, Judo savez Beograda).
      users_by_club: q(`
        SELECT COALESCE(NULLIF(TRIM(club), ''), '(bez kluba)') AS club,
          COUNT(*) AS users,
          COUNT(*) FILTER (WHERE subscription_tier = 'premium') AS premium_users
        FROM users
        GROUP BY 1 ORDER BY users DESC LIMIT 30
      `),
      users_by_country: q(`
        SELECT COALESCE(NULLIF(TRIM(country), ''), '(bez zemlje)') AS country, COUNT(*) AS users
        FROM users
        GROUP BY 1 ORDER BY users DESC LIMIT 30
      `),

      // ---------- RAST / GROWTH (22.09.2026, korisnikov zahtev - dodatni predlozi) ----------
      // Distribucija Dnevnog izazova streak-a (poslednja poznata vrednost po korisniku) - grupisano
      // u bucket-e umesto sirovog broja, da bude citljivo. Koristi 'dc_complete' event koji vec
      // postoji (event_data->>'streak').
      growth_streak_distribution: q(`
        WITH latest_streak AS (
          SELECT DISTINCT ON (user_id) user_id, (event_data->>'streak')::int AS streak
          FROM analytics_events
          WHERE event_name = 'dc_complete' AND user_id IS NOT NULL AND event_data->>'streak' IS NOT NULL
          ORDER BY user_id, created_at DESC
        ),
        bucketed AS (
          SELECT
            CASE
              WHEN streak <= 1 THEN '1 dan'
              WHEN streak BETWEEN 2 AND 3 THEN '2-3 dana'
              WHEN streak BETWEEN 4 AND 6 THEN '4-6 dana'
              WHEN streak BETWEEN 7 AND 13 THEN '7-13 dana'
              WHEN streak BETWEEN 14 AND 29 THEN '14-29 dana'
              ELSE '30+ dana'
            END AS streak_bucket,
            CASE
              WHEN streak <= 1 THEN 0 WHEN streak BETWEEN 2 AND 3 THEN 1
              WHEN streak BETWEEN 4 AND 6 THEN 2 WHEN streak BETWEEN 7 AND 13 THEN 3
              WHEN streak BETWEEN 14 AND 29 THEN 4 ELSE 5
            END AS sort_order
          FROM latest_streak
        )
        SELECT streak_bucket, COUNT(*) AS users
        FROM bucketed GROUP BY streak_bucket, sort_order ORDER BY sort_order
      `),
      // Adopcija ključnih feature-a UNUTAR D7-retained kohorte (ne globalno) - pokazuje da li
      // korisnici koji ostaju zaista koriste "core loop" feature-e, ne samo da li su uopste aktivni.
      retention_feature_adoption_d7: q(`
        WITH first_seen AS (
          SELECT user_id, date_trunc('day', MIN(created_at)) AS cohort_day
          FROM analytics_events WHERE user_id IS NOT NULL GROUP BY user_id
        ),
        activity AS (
          SELECT DISTINCT user_id, date_trunc('day', created_at) AS activity_day
          FROM analytics_events WHERE event_name = 'app_session_start' AND user_id IS NOT NULL
        ),
        d7_retained AS (
          SELECT DISTINCT f.user_id
          FROM first_seen f JOIN activity a ON a.user_id = f.user_id AND a.activity_day = f.cohort_day + interval '7 day'
        )
        SELECT f.feature,
          (SELECT COUNT(*) FROM d7_retained) AS d7_retained_total,
          COUNT(DISTINCT ae.user_id) AS used_feature,
          ROUND(100.0 * COUNT(DISTINCT ae.user_id) / NULLIF((SELECT COUNT(*) FROM d7_retained), 0), 1) AS adoption_pct
        FROM (
          SELECT 'AI Sensei' AS feature, 'sensei_question' AS ev UNION ALL
          SELECT 'Randori', 'randori_scenario_view' UNION ALL
          SELECT 'Baza tehnika', 'technique_view' UNION ALL
          SELECT 'Kviz', 'quiz_answer'
        ) f
        JOIN analytics_events ae ON ae.event_name = f.ev AND ae.user_id IN (SELECT user_id FROM d7_retained)
        GROUP BY f.feature ORDER BY adoption_pct DESC
      `),
      // Time-to-first-value: koliko brzo posle prve pojave korisnik uradi prvu "vrednu" akciju
      // (kviz/tehnika/randori/DC/sensei), i da li ta brzina korelise sa D7 retencijom - klasicna
      // growth metrika, rana aktivacija obicno najbolje predvidja retenciju.
      growth_time_to_first_value: q(`
        WITH first_seen AS (
          SELECT user_id, MIN(created_at) AS first_ts
          FROM analytics_events WHERE user_id IS NOT NULL GROUP BY user_id
        ),
        first_value AS (
          SELECT user_id, MIN(created_at) AS value_ts
          FROM analytics_events
          WHERE user_id IS NOT NULL
            AND event_name IN ('quiz_answer','technique_view','randori_scenario_view','dc_complete','sensei_question')
          GROUP BY user_id
        ),
        joined AS (
          SELECT f.user_id, EXTRACT(EPOCH FROM (v.value_ts - f.first_ts)) / 3600.0 AS hours_to_value
          FROM first_seen f JOIN first_value v ON v.user_id = f.user_id
          WHERE v.value_ts >= f.first_ts
        ),
        cohort AS (
          SELECT user_id, date_trunc('day', first_ts) AS cohort_day FROM first_seen
        ),
        activity AS (
          SELECT DISTINCT user_id, date_trunc('day', created_at) AS activity_day
          FROM analytics_events WHERE event_name = 'app_session_start' AND user_id IS NOT NULL
        ),
        bucketed AS (
          SELECT j.user_id, CASE WHEN j.hours_to_value <= 24 THEN 'Prva vredna akcija u prvih 24h' ELSE 'Kasnije od 24h' END AS bucket
          FROM joined j
        )
        SELECT b.bucket, COUNT(*) AS users,
          ROUND(100.0 * COUNT(DISTINCT CASE WHEN a.activity_day = c.cohort_day + interval '7 day' THEN a.user_id END) / NULLIF(COUNT(*), 0), 1) AS d7_retention_pct
        FROM bucketed b
        JOIN cohort c ON c.user_id = b.user_id
        LEFT JOIN activity a ON a.user_id = b.user_id
        GROUP BY b.bucket ORDER BY b.bucket
      `),
      // Konverzija po kanalu: placena kupovina (postoji premium_checkout_confirmed event) vs.
      // dodeljeno (promo kod/klub/admin - trenutno se ne razlikuju medjusobno jer promo_codes i
      // club-grant ne beleze KOJI konkretan korisnik je kod iskoristio; za tu finiju podelu treba
      // mala izmena seme (nova kolona na users, npr. premium_source) - nije radjena sada.
      premium_conversion_by_channel: q(`
        SELECT
          CASE WHEN EXISTS (
            SELECT 1 FROM analytics_events ae
            WHERE ae.event_name = 'premium_checkout_confirmed' AND ae.user_id = u.id
          ) THEN 'Plaćena kupovina' ELSE 'Dodeljeno (promo/klub/admin)' END AS channel,
          COUNT(*) AS premium_users
        FROM users u
        WHERE u.subscription_tier = 'premium'
        GROUP BY 1 ORDER BY premium_users DESC
      `),
      // Greske po verziji app-a (14 dana) - da se odmah uoci regresija posle release-a, ne samo
      // ukupan broj greske vec i po kom app_version-u.
      error_by_app_version: q(`
        SELECT COALESCE(event_data->>'appVersion', '(nepoznato)') AS app_version,
          COUNT(*) AS errors, COUNT(DISTINCT user_id) AS affected_users
        FROM analytics_events
        WHERE event_name = 'silent_error' AND created_at > now() - interval '14 days'
        GROUP BY 1 ORDER BY errors DESC
      `),
      // Prijave problema grupisane po kategoriji - trenutno se liste jedna po jedna (Prijave
      // problema tab), ovaj summary pomaze prioritizaciji (gde se najvise gomila).
      bug_reports_by_category: q(`
        SELECT COALESCE(category, '(bez kategorije)') AS category,
          COUNT(*) AS reports,
          COUNT(*) FILTER (WHERE status = 'new') AS new_reports,
          COUNT(*) FILTER (WHERE status = 'resolved') AS resolved_reports
        FROM bug_reports
        GROUP BY 1 ORDER BY reports DESC
      `),
    };

  // FIX (23.09.2026, server optimizacija): izvrsavanje u talasima od po BATCH_SIZE upita umesto
  // svih ~43 odjednom preko Promise.all(). Cilj: dashboard nikad ne drzi vise od BATCH_SIZE
  // konekcija iz poola istovremeno, ostavljajuci prostor za live app saobracaj koji deli isti pool
  // (vidi Pool podesavanje iznad, max: 20). Upiti UNUTAR jednog talasa i dalje idu paralelno
  // (Promise.all), pa dashboard ne postaje drasticno sporiji - samo se ogranicava vrh potraznje.
  const keys = Object.keys(queries);
  const fns = Object.values(queries);
  const BATCH_SIZE = 12;
  const results = [];
  for (let i = 0; i < fns.length; i += BATCH_SIZE) {
    const batch = fns.slice(i, i + BATCH_SIZE).map(fn => fn());
    results.push(...await Promise.all(batch));
  }
  const out = {};
  keys.forEach((k, i) => { out[k] = results[i]; });

  res.json(out);
});

// Static files — MORA biti posle ruta
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log('Server radi na portu ' + PORT));
