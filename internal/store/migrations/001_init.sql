CREATE TABLE schema_migrations (
  version    INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  applied_at TEXT NOT NULL
);

CREATE TABLE flows (
  id                INTEGER PRIMARY KEY,
  flow_start_ms     INTEGER NOT NULL,       -- clamped
  flow_end_ms       INTEGER NOT NULL,       -- clamped
  received_ms       INTEGER NOT NULL,
  export_time_s     INTEGER,
  time_source       TEXT NOT NULL,          -- sysuptime, absolute, export, receive
  clock_clamped     INTEGER NOT NULL DEFAULT 0,
  exporter          TEXT NOT NULL,
  domain            INTEGER NOT NULL,
  version           INTEGER NOT NULL,       -- 5, 9, 10
  src               TEXT NOT NULL,
  dst               TEXT NOT NULL,
  src_port          INTEGER,
  dst_port          INTEGER,
  ip_proto          INTEGER,
  tcp_flags         INTEGER,
  tos               INTEGER,
  flow_direction    INTEGER,                -- 0 ingress, 1 egress, NULL if absent
  packets           INTEGER NOT NULL,
  octets            INTEGER NOT NULL,
  counter_semantics TEXT NOT NULL,          -- delta or total
  octet_semantics   TEXT NOT NULL,          -- ip or l4_payload
  out_packets       INTEGER,
  out_octets        INTEGER,
  input_if          INTEGER,
  output_if         INTEGER,
  nexthop           TEXT,
  bgp_src_as        INTEGER,
  bgp_dst_as        INTEGER,
  src_mask          INTEGER,
  dst_mask          INTEGER,
  sampled           INTEGER NOT NULL,       -- 0 or 1
  sampling_interval INTEGER,                -- N, null if unsampled or unknown
  sampling_algorithm INTEGER,
  src_scope         TEXT NOT NULL,
  dst_scope         TEXT NOT NULL,
  src_geo_outcome   TEXT NOT NULL,
  dst_geo_outcome   TEXT NOT NULL,
  src_asn_outcome   TEXT NOT NULL,
  dst_asn_outcome   TEXT NOT NULL,
  src_rep_outcome   TEXT NOT NULL,
  dst_rep_outcome   TEXT NOT NULL,
  src_country       TEXT,
  src_region        TEXT,
  src_city          TEXT,
  src_lat           REAL,
  src_lon           REAL,
  dst_country       TEXT,
  dst_region        TEXT,
  dst_city          TEXT,
  dst_lat           REAL,
  dst_lon           REAL,
  src_asn           INTEGER,
  src_asn_name      TEXT,
  dst_asn           INTEGER,
  dst_asn_name      TEXT,
  src_rep_category  TEXT,
  src_rep_score     REAL,
  dst_rep_category  TEXT,
  dst_rep_score     REAL
);

CREATE INDEX idx_flows_start    ON flows(flow_start_ms, id);
CREATE INDEX idx_flows_src      ON flows(src, flow_start_ms);
CREATE INDEX idx_flows_dst      ON flows(dst, flow_start_ms);
CREATE INDEX idx_flows_exporter ON flows(exporter, flow_start_ms);

CREATE TABLE exporters (
  exporter         TEXT NOT NULL,
  domain           INTEGER NOT NULL,
  version          INTEGER NOT NULL,
  last_seen_ms     INTEGER NOT NULL,
  packets          INTEGER NOT NULL,
  flows            INTEGER NOT NULL,
  malformed        INTEGER NOT NULL,
  missing_template INTEGER NOT NULL,
  gap_flows        INTEGER NOT NULL,
  gap_packets      INTEGER NOT NULL,
  gap_records      INTEGER NOT NULL,
  PRIMARY KEY (exporter, domain, version)
);

CREATE TABLE traffic_1m (
  bucket_ms INTEGER NOT NULL,
  exporter  TEXT NOT NULL,
  ip_proto  INTEGER NOT NULL,    -- -1 when the record had no protocol
  sampled   INTEGER NOT NULL,
  packets   INTEGER NOT NULL,
  octets    INTEGER NOT NULL,
  flows     INTEGER NOT NULL,
  PRIMARY KEY (bucket_ms, exporter, ip_proto, sampled)
);

CREATE TABLE asn_1m (
  bucket_ms   INTEGER NOT NULL,
  asn         INTEGER NOT NULL,  -- -1 is the overflow sentinel
  direction   TEXT NOT NULL,     -- src or dst
  from_export INTEGER NOT NULL,  -- 0 enriched, 1 BGP AS from the export
  packets     INTEGER NOT NULL,
  octets      INTEGER NOT NULL,
  flows       INTEGER NOT NULL,
  PRIMARY KEY (bucket_ms, asn, direction, from_export)
);

CREATE TABLE asn_names (
  asn        INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  updated_ms INTEGER NOT NULL
);

CREATE TABLE talker_1m (
  bucket_ms INTEGER NOT NULL,
  direction TEXT NOT NULL,
  addr      TEXT NOT NULL,       -- '*' is OTHER
  packets   INTEGER NOT NULL,
  octets    INTEGER NOT NULL,
  flows     INTEGER NOT NULL,
  PRIMARY KEY (bucket_ms, direction, addr)
);

CREATE TABLE rep_1m (
  bucket_ms INTEGER NOT NULL,
  direction TEXT NOT NULL,
  addr      TEXT NOT NULL,       -- '*' is OTHER
  category  TEXT NOT NULL,
  packets   INTEGER NOT NULL,
  octets    INTEGER NOT NULL,
  flows     INTEGER NOT NULL,
  PRIMARY KEY (bucket_ms, direction, addr, category)
);

CREATE TABLE geo_country_5m (
  bucket_ms INTEGER NOT NULL,
  country   TEXT NOT NULL,       -- ISO alpha-2
  packets   INTEGER NOT NULL,
  octets    INTEGER NOT NULL,
  flows     INTEGER NOT NULL,
  PRIMARY KEY (bucket_ms, country)
);

CREATE TABLE geo_path_5m (
  bucket_ms    INTEGER NOT NULL,
  src_key      TEXT NOT NULL,
  dst_key      TEXT NOT NULL,
  src_kind     TEXT NOT NULL,
  dst_kind     TEXT NOT NULL,
  src_country  TEXT,
  dst_country  TEXT,
  src_region   TEXT,
  dst_region   TEXT,
  src_city     TEXT,
  dst_city     TEXT,
  src_lat      REAL,
  src_lon      REAL,
  dst_lat      REAL,
  dst_lon      REAL,
  packets      INTEGER NOT NULL,
  octets       INTEGER NOT NULL,
  flows        INTEGER NOT NULL,
  PRIMARY KEY (bucket_ms, src_key, dst_key)
);

CREATE TABLE geo_path_other_5m (
  bucket_ms      INTEGER PRIMARY KEY,
  octets         INTEGER NOT NULL,
  flows          INTEGER NOT NULL,
  pairs_omitted  INTEGER NOT NULL
);
