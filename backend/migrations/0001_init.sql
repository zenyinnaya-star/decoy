-- Decoy cloud: install registry, shared scam reports, trusted-person links, alert log.
CREATE TABLE installs (
  id TEXT PRIMARY KEY,
  key_hash TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE reports (
  install_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  finding TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (install_id, domain, finding)
);
CREATE INDEX reports_domain ON reports(domain);

CREATE TABLE listed (
  domain TEXT PRIMARY KEY,
  findings TEXT NOT NULL,
  confirmations INTEGER NOT NULL,
  listed_at INTEGER NOT NULL
);

CREATE TABLE guardians (
  id TEXT PRIMARY KEY,
  install_id TEXT NOT NULL,
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  requester TEXT NOT NULL,
  status TEXT NOT NULL,            -- pending | active | declined | removed
  token_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  confirmed_at INTEGER
);
CREATE INDEX guardians_install ON guardians(install_id);
CREATE INDEX guardians_token ON guardians(token_hash);

-- Emails that said "No, stop". Stored as hashes only. Nobody can invite them again.
CREATE TABLE blocked_emails (
  email_hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  install_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  domain TEXT NOT NULL,
  entered INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX alerts_install ON alerts(install_id, created_at);

-- Tiny rate-limit counters (key = what, window = start of the window).
CREATE TABLE limits (
  k TEXT NOT NULL,
  w INTEGER NOT NULL,
  n INTEGER NOT NULL,
  PRIMARY KEY (k, w)
);
