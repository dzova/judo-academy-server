// Jednokratni setup skript za analytics_events_archive tabelu (i njen indeks).
// Pokreni sa: railway run node setup_archive_table.js

const { Pool } = require('pg');

const connString = process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL;
const pool = new Pool({ connectionString: connString });

(async () => {
  try {
    if (!connString) {
      console.error('GRESKA: ni DATABASE_PUBLIC_URL ni DATABASE_URL nisu postavljeni. Pokreni preko "railway run node setup_archive_table.js".');
      process.exit(1);
    }
    console.log('Koristim konekciju:', process.env.DATABASE_PUBLIC_URL ? 'DATABASE_PUBLIC_URL (javna)' : 'DATABASE_URL (interna)');

    console.log('Kreiram analytics_events_archive tabelu (ako vec ne postoji)...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS analytics_events_archive (
        id BIGINT PRIMARY KEY,
        user_id UUID,
        event_name TEXT,
        event_data JSONB,
        created_at TIMESTAMPTZ,
        archived_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
    console.log('Tabela OK.');

    console.log('Kreiram indeks na created_at...');
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_archive_created_at ON analytics_events_archive (created_at);
    `);
    console.log('Indeks OK.');

    console.log('Gotovo — analytics_events_archive je spremna za upotrebu.');
  } catch (err) {
    console.error('GRESKA:', err.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();
