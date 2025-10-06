
CREATE TABLE IF NOT EXISTS users(
  user_id TEXT PRIMARY KEY,
  pubkey TEXT NOT NULL,
  privkey_store TEXT NOT NULL,
  pake_password TEXT NOT NULL,
  meta TEXT,
  version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS groups(
  group_id TEXT PRIMARY KEY,
  creator_id TEXT NOT NULL,
  created_at INTEGER,
  meta TEXT,
  version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members(
  group_id TEXT NOT NULL,
  member_id TEXT NOT NULL,
  role TEXT,
  wrapped_key TEXT NOT NULL,
  added_at INTEGER,
  PRIMARY KEY (group_id, member_id)
);
