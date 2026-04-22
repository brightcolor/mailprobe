package db

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

func Open(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=1", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    address TEXT NOT NULL UNIQUE,
    created_ip TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mailboxes_token ON mailboxes(token);
CREATE INDEX IF NOT EXISTS idx_mailboxes_expires ON mailboxes(expires_at);
CREATE INDEX IF NOT EXISTS idx_mailboxes_created_ip ON mailboxes(created_ip);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL,
    smtp_from TEXT NOT NULL,
    rcpt_to TEXT NOT NULL,
    remote_ip TEXT NOT NULL,
    helo TEXT NOT NULL,
    received_at DATETIME NOT NULL,
    raw_source TEXT NOT NULL,
    header_block TEXT NOT NULL,
    subject TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id ON messages(mailbox_id);
CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL UNIQUE,
    created_at DATETIME NOT NULL,
    score REAL NOT NULL,
    score_label TEXT NOT NULL,
    checks_json TEXT NOT NULL,
    warnings_json TEXT NOT NULL,
    suggestions_json TEXT NOT NULL,
    headers_json TEXT NOT NULL,
    links_json TEXT NOT NULL,
    spam_signals_json TEXT NOT NULL,
    FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reports_message_id ON reports(message_id);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);
`
	_, err := db.Exec(schema)
	return err
}
