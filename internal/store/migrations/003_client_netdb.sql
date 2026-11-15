-- Per-client additions to the host protocol and service tables.
-- A row is a name, a number or port, a protocol token, and aliases.
-- It is not a filesystem path, and no path is a column.
CREATE TABLE client_protocol (
  client_id TEXT NOT NULL REFERENCES oauth_client(client_id) ON DELETE CASCADE,
  name      TEXT NOT NULL CHECK (
    length(name) BETWEEN 1 AND 64
    AND name NOT IN ('.', '..')
    AND name NOT GLOB '*[^A-Za-z0-9._+-]*'
  ),
  number    INTEGER NOT NULL CHECK (number >= 0 AND number <= 255),
  aliases   TEXT NOT NULL CHECK (
    length(aliases) >= 2
    AND instr(aliases, '/') = 0
    AND instr(aliases, char(92)) = 0
  ),
  PRIMARY KEY (client_id, name)
);

CREATE TABLE client_service (
  client_id TEXT NOT NULL REFERENCES oauth_client(client_id) ON DELETE CASCADE,
  name      TEXT NOT NULL CHECK (
    length(name) BETWEEN 1 AND 64
    AND name NOT IN ('.', '..')
    AND name NOT GLOB '*[^A-Za-z0-9._+-]*'
  ),
  port      INTEGER NOT NULL CHECK (port >= 0 AND port <= 65535),
  protocol  TEXT NOT NULL CHECK (
    length(protocol) BETWEEN 1 AND 64
    AND protocol NOT IN ('.', '..')
    AND protocol NOT GLOB '*[^A-Za-z0-9._+-]*'
  ),
  aliases   TEXT NOT NULL CHECK (
    length(aliases) >= 2
    AND instr(aliases, '/') = 0
    AND instr(aliases, char(92)) = 0
  ),
  PRIMARY KEY (client_id, name, protocol)
);
