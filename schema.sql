-- TT-Training D1 Schema
-- Multi-tenant ready (verein_id on all data tables)

CREATE TABLE IF NOT EXISTS vereine (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  verein_id TEXT NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','trainer','spieler')),
  display_name TEXT NOT NULL,
  player_id TEXT,
  trainer_id TEXT,
  is_initial_admin INTEGER DEFAULT 0,
  must_change_password INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (verein_id) REFERENCES vereine(id) ON DELETE CASCADE,
  UNIQUE(verein_id, username)
);

CREATE TABLE IF NOT EXISTS players (
  id TEXT PRIMARY KEY,
  verein_id TEXT NOT NULL,
  name TEXT NOT NULL,
  vorname TEXT NOT NULL,
  geburtsdatum TEXT,
  jahrgang TEXT,
  mannschaft TEXT DEFAULT '[]',
  gruppe TEXT,
  hand TEXT,
  trainer TEXT,
  vh_name TEXT,
  vh_typ TEXT,
  rh_name TEXT,
  rh_typ TEXT,
  FOREIGN KEY (verein_id) REFERENCES vereine(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trainers (
  id TEXT PRIMARY KEY,
  verein_id TEXT NOT NULL,
  name TEXT NOT NULL,
  vorname TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'trainer' CHECK(role IN ('admin','trainer')),
  FOREIGN KEY (verein_id) REFERENCES vereine(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY,
  verein_id TEXT NOT NULL,
  player_id TEXT NOT NULL,
  date TEXT NOT NULL,
  trainer TEXT,
  ratings TEXT NOT NULL DEFAULT '{}',
  staerken TEXT,
  next_step TEXT,
  bemerkung TEXT,
  FOREIGN KEY (verein_id) REFERENCES vereine(id) ON DELETE CASCADE,
  FOREIGN KEY (player_id) REFERENCES players(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS lists (
  verein_id TEXT NOT NULL,
  list_key TEXT NOT NULL CHECK(list_key IN ('mannschaften','trainingsgruppen','trainerNamen')),
  value TEXT NOT NULL,
  PRIMARY KEY (verein_id, list_key, value),
  FOREIGN KEY (verein_id) REFERENCES vereine(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_verein ON users(verein_id);
CREATE INDEX IF NOT EXISTS idx_players_verein ON players(verein_id);
CREATE INDEX IF NOT EXISTS idx_assessments_player ON assessments(player_id);
CREATE INDEX IF NOT EXISTS idx_assessments_verein ON assessments(verein_id);
CREATE INDEX IF NOT EXISTS idx_trainers_verein ON trainers(verein_id);
CREATE INDEX IF NOT EXISTS idx_lists_verein ON lists(verein_id, list_key);

CREATE TABLE IF NOT EXISTS settings (
  verein_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (verein_id, key),
  FOREIGN KEY (verein_id) REFERENCES vereine(id) ON DELETE CASCADE
);
