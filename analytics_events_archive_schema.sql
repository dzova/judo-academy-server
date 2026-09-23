-- analytics_events_archive: hladno skladiste za stare analytics_events redove.
-- Napravi RUCNO u Railway Query editoru/konzoli (isti postupak kao za user_first_seen), PRE
-- deploy-a index.js koda koji koristi novu /api/admin/archive-old-events rutu.
--
-- id je BIGINT (ne referencira analytics_events.id kao FK namerno - arhivirani redovi vise ne
-- treba da zavise od zivota originalne tabele/PK-a).

CREATE TABLE IF NOT EXISTS analytics_events_archive (
  id BIGINT PRIMARY KEY,
  user_id UUID,
  event_name TEXT,
  event_data JSONB,
  created_at TIMESTAMPTZ,
  archived_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indeks po created_at za slucaj da ikad zatreba upit nad arhivom (npr. "sta se desavalo pre 2 godine").
CREATE INDEX IF NOT EXISTS idx_archive_created_at ON analytics_events_archive (created_at);
