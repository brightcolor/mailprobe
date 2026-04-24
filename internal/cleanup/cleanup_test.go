//go:build cgo
// +build cgo

package cleanup

import (
	"bytes"
	"context"
	"errors"
	"log"
	"path/filepath"
	"testing"
	"time"

	"github.com/brightcolor/mailprobe/internal/db"
	"github.com/brightcolor/mailprobe/internal/model"
	"github.com/brightcolor/mailprobe/internal/store"
)

func TestStartTriggersPeriodicCleanup(t *testing.T) {
	sqlDB, err := db.Open(filepath.Join(t.TempDir(), "cleanup.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer sqlDB.Close()

	st := store.New(sqlDB)
	ctx := context.Background()

	mb, err := st.CreateMailbox(ctx, "cleaner", "cleaner@example.test", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatalf("CreateMailbox: %v", err)
	}
	_, err = st.SaveMessage(ctx, model.Message{
		MailboxID:   mb.ID,
		SMTPFrom:    "sender@example.org",
		RCPTTo:      mb.Address,
		RemoteIP:    "203.0.113.11",
		HELO:        "mx.example.org",
		ReceivedAt:  time.Now().UTC().Add(-72 * time.Hour),
		RawSource:   "old",
		HeaderBlock: "old",
		Subject:     "old",
		SizeBytes:   3,
	})
	if err != nil {
		t.Fatalf("SaveMessage: %v", err)
	}

	// Expire mailbox so cleanup has guaranteed work.
	if _, err := sqlDB.Exec(`UPDATE mailboxes SET expires_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute), mb.ID); err != nil {
		t.Fatalf("expire mailbox: %v", err)
	}

	var logs bytes.Buffer
	logger := log.New(&logs, "", 0)
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Start(runCtx, logger, st, 20*time.Millisecond, 24*time.Hour)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, err := st.GetMailboxByID(ctx, mb.ID)
		if errors.Is(err, store.ErrNotFound) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("cleanup ticker did not remove expired mailbox in time; logs=%q", logs.String())
}
