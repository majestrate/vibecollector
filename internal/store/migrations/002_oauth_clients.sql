CREATE TABLE oauth_client (
  client_id   TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL, -- hex(sha256(secret)); the secret itself is not stored
  created_at  TEXT NOT NULL
);
