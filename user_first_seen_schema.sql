-- user_first_seen: pomocna tabela za retention/growth panele na admin dashboard-u.
-- Napravi je RUCNO u Railway Query editoru, PRE deploy-a novog index.js koda.
--
-- Svrha: retention_aggregate, retention_by_cohort_day, retention_feature_adoption_d7 i
-- growth_time_to_first_value upiti su ranije racunali "prvi put vidjen korisnik" preko
-- MIN(created_at) GROUP BY user_id nad CELOM analytics_events tabelom, pri SVAKOM otvaranju
-- dashboard-a. Ova tabela drzi taj podatak unapred izracunat, jedan red po korisniku.

CREATE TABLE IF NOT EXISTS user_first_seen (
  user_id UUID PRIMARY KEY,
  first_seen_at TIMESTAMPTZ NOT NULL
);

-- Jednokratni backfill postojecih korisnika (na osnovu postojece analytics_events istorije).
-- Pokreni OVO odmah posle CREATE TABLE, samo jednom. Moze potrajati koliko i "spori" retention
-- upiti danas (to je bas ono sto zamenjujemo) - ali se radi SAMO JEDNOM, ne pri svakom dashboard
-- pozivu kao do sada.
INSERT INTO user_first_seen (user_id, first_seen_at)
SELECT user_id, MIN(created_at)
FROM analytics_events
WHERE user_id IS NOT NULL
GROUP BY user_id
ON CONFLICT (user_id) DO NOTHING;

-- Posle ovoga: kod u index.js (POST /api/analytics/event) sam upisuje nove korisnike ovde
-- ubuduce (ON CONFLICT DO NOTHING upsert), pa dodatni backfill nije potreban.
