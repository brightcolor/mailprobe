//go:build cgo
// +build cgo

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/mailprobe/internal/config"
	"github.com/brightcolor/mailprobe/internal/db"
	"github.com/brightcolor/mailprobe/internal/model"
	"github.com/brightcolor/mailprobe/internal/store"
)

func TestReportUsesTokenURLAndInlineRawAccordion(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	srv, st, mb, msg, rep := prepareWebTestFixture(t)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/report/"+mb.Token+"?message="+itoa(msg.ID), nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "rawAccordion") {
		t.Fatalf("expected inline raw accordion in report page")
	}
	if !strings.Contains(body, msg.HeaderBlock) {
		t.Fatalf("expected header block in report page")
	}
	if !strings.Contains(body, msg.RawSource) {
		t.Fatalf("expected raw source in report page")
	}

	// Numeric report IDs should no longer be directly routable.
	req = httptest.NewRequest(http.MethodGet, "/report/"+itoa(rep.ID), nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for numeric report URL, got %d", rr.Code)
	}

	_ = st
}

func TestMailboxStatusReturnsTokenizedReportPath(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	srv, _, mb, msg, _ := prepareWebTestFixture(t)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes/"+mb.Token+"/status", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json payload: %v", err)
	}
	got, _ := payload["latest_report_path"].(string)
	want := "/report/" + mb.Token + "?message=" + itoa(msg.ID)
	if got != want {
		t.Fatalf("latest_report_path mismatch: got %q want %q", got, want)
	}
}

func prepareWebTestFixture(t *testing.T) (*Server, *store.Store, model.Mailbox, model.Message, model.AnalysisReport) {
	t.Helper()

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "test.db")
	sqlDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	st := store.New(sqlDB)
	ctx := context.Background()

	mb, err := st.CreateMailbox(ctx, "rk3ee85g6", "rk3ee85g6@example.test", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatalf("create mailbox: %v", err)
	}

	msg, err := st.SaveMessage(ctx, model.Message{
		MailboxID:   mb.ID,
		SMTPFrom:    "sender@example.org",
		RCPTTo:      mb.Address,
		RemoteIP:    "203.0.113.20",
		HELO:        "mx.example.org",
		ReceivedAt:  time.Now().UTC(),
		RawSource:   "From: sender@example.org\r\nSubject: Demo\r\n\r\nHello world",
		HeaderBlock: "From: sender@example.org\r\nSubject: Demo",
		Subject:     "Demo",
		SizeBytes:   64,
	})
	if err != nil {
		t.Fatalf("save message: %v", err)
	}

	rep, err := st.SaveReport(ctx, model.AnalysisReport{
		MessageID:  msg.ID,
		CreatedAt:  time.Now().UTC(),
		Score:      8.8,
		ScoreLabel: "Good",
		Checks: []model.CheckResult{
			{ID: "spf", Name: "SPF", Status: "pass", ScoreDelta: 0.4, Summary: "ok"},
			{ID: "dkim", Name: "DKIM", Status: "warn", ScoreDelta: -0.4, Summary: "warn"},
		},
		RawHeaders: map[string][]string{"From": {"sender@example.org"}},
	})
	if err != nil {
		t.Fatalf("save report: %v", err)
	}

	cfg := config.Config{
		AppName:            "MailProbe",
		PublicBaseURL:      "http://localhost:8080",
		SMTPDomain:         "example.test",
		MailboxTTL:         time.Hour,
		WebRateLimitPerMin: 1000,
	}
	srv, err := New(cfg, st, nil)
	if err != nil {
		t.Fatalf("new web server: %v", err)
	}

	return srv, st, mb, msg, rep
}

func chdirToRepoRoot(t *testing.T) func() {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("chdir to repo root: %v", err)
	}
	return func() {
		_ = os.Chdir(prevWD)
	}
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}
