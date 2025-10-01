-- db/schema.sql
PRAGMA foreign_keys = ON;

-- Users: SOCP user handle/UUID + public key (PEM encoded, base64url)
CREATE TABLE IF NOT EXISTS users (
  user_id      TEXT PRIMARY KEY,
  pubkey_b64u  TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);

-- Groups: logical chat groups (we’ll use "public")
CREATE TABLE IF NOT EXISTS groups (
  group_id     TEXT PRIMARY KEY,
  version      INTEGER NOT NULL,
  created_at   INTEGER NOT NULL
);

-- Current symmetric key for a group (base64url of 32 random bytes)
CREATE TABLE IF NOT EXISTS group_keys (
  group_id     TEXT PRIMARY KEY,
  key_b64u     TEXT NOT NULL,
  updated_at   INTEGER NOT NULL,
  FOREIGN KEY(group_id) REFERENCES groups(group_id) ON DELETE CASCADE
);

-- Membership mapping
CREATE TABLE IF NOT EXISTS memberships (
  group_id     TEXT NOT NULL,
  user_id      TEXT NOT NULL,
  joined_at    INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id),
  FOREIGN KEY(group_id) REFERENCES groups(group_id) ON DELETE CASCADE,
  FOREIGN KEY(user_id)  REFERENCES users(user_id)  ON DELETE CASCADE
);

-- Per-member wrapped group key (RSA-OAEP(user_pub, group_key_plaintext))
CREATE TABLE IF NOT EXISTS wrapped_keys (
  group_id     TEXT NOT NULL,
  user_id      TEXT NOT NULL,
  version      INTEGER NOT NULL,
  wrapped_b64u TEXT NOT NULL,
  PRIMARY KEY (group_id, user_id),
  FOREIGN KEY(group_id) REFERENCES groups(group_id) ON DELETE CASCADE,
  FOREIGN KEY(user_id)  REFERENCES users(user_id)  ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_memberships_group ON memberships(group_id);
CREATE INDEX IF NOT EXISTS idx_wrapped_group     ON wrapped_keys(group_id);
