-- Audit forwarding (SIEM forwarding plan): where audit rows are sent, and
-- how far each sink has got (`cursor` is the last audit id it accepted).
CREATE TABLE ee_audit_sinks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL UNIQUE,
    kind          TEXT    NOT NULL CHECK (kind IN ('syslog', 'splunk_hec', 'http')),
    enabled       INTEGER NOT NULL DEFAULT 1,
    -- JSON without secrets: host, port, transport, ca_pem, url, header_names.
    settings      TEXT    NOT NULL,
    -- Sealed JSON {"token", "headers"} (aad "audit-sink:<id>").
    secrets       TEXT,
    cursor        INTEGER NOT NULL,
    -- Rows retention removed before this sink sent them.
    gap_rows      INTEGER NOT NULL DEFAULT 0,
    last_sent_at  INTEGER,
    last_error    TEXT,
    last_error_at INTEGER,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
