// Jednokratni backfill skript za user_first_seen tabelu.
// Pokreni sa: railway run node backfill_user_first_seen.js
// (railway run ubacuje env varijable iz Railway servisa u ovaj proces)
//
// NAPOMENA: DATABASE_URL sadrzi INTERNU Railway adresu (postgres.railway.internal), vidljivu
// samo servisima koji rade UNUTAR Railway mreze - ne i sa tvog racunara. Zato ovaj skript prvo
// probava DATABASE_PUBLIC_URL (javna/proxy adresa, ako postoji medju Variables na Postgres
// servisu), pa tek ako nje nema pada nazad na DATABASE_URL.

const { Pool } = require('pg');

const connString = process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL;

const pool = new Pool({ connectionString: connString });

(async () => {
  try {
    if (!connString) {
      console.error('GRESKA: ni DATABASE_PUBLIC_URL ni DATABASE_URL nisu postavljeni. Pokreni ovo preko "railway run node backfill_user_first_seen.js", ne obicnim "node backfill_user_first_seen.js".');
      process.exit(1);
    }
    console.log('Koristim konekciju:', process.env.DATABASE_PUBLIC_URL ? 'DATABASE_PUBLIC_URL (javna)' : 'DATABASE_URL (interna - moze da ne uspe sa lokalnog racunara)');

    console.log('Kreiram tabelu user_first_seen (ako vec ne postoji)...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_first_seen (
        user_id UUID PRIMARY KEY,
        first_seen_at TIMESTAMPTZ NOT NULL
      );
    `);
    console.log('Tabela OK.');

    console.log('Pokrecem backfill (moze potrajati u zavisnosti od velicine analytics_events)...');
    const result = await pool.query(`
      INSERT INTO user_first_seen (user_id, first_seen_at)
      SELECT user_id, MIN(created_at)
      FROM analytics_events
      WHERE user_id IS NOT NULL
      GROUP BY user_id
      ON CONFLICT (user_id) DO NOTHING;
    `);
    console.log('Backfill zavrsen. Upisano redova:', result.rowCount);

    const count = await pool.query('SELECT COUNT(*) FROM user_first_seen;');
    console.log('Ukupno redova u user_first_seen sada:', count.rows[0].count);
  } catch (err) {
    console.error('GRESKA:', err.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();
