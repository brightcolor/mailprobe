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

	msgRef := messageReference(mb.Token, msg.ID)
	req := httptest.NewRequest(http.MethodGet, "/report/"+mb.Token+"?msg="+msgRef, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "rawAccordion") {
		t.Fatalf("expected inline raw accordion in report page")
	}
	if !strings.Contains(body, "Plaintext View") || !strings.Contains(body, "HTML Source View") {
		t.Fatalf("expected plaintext/html sections in report page")
	}
	if !strings.Contains(body, msg.HeaderBlock) {
		t.Fatalf("expected header block in report page")
	}
	if !strings.Contains(body, msg.RawSource) {
		t.Fatalf("expected raw source in report page")
	}

	req = httptest.NewRequest(http.MethodGet, "/raw/"+mb.Token+"/"+msgRef+"/headers", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Subject: Demo") {
		t.Fatalf("expected tokenized raw header download, code=%d body=%q", rr.Code, rr.Body.String())
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

func TestHomeGeneratesNewMailboxOnEachOpen(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "home.db")
	sqlDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	st := store.New(sqlDB)
	cfg := config.Config{
		AppName:              "MailProbe",
		PublicBaseURL:        "http://localhost:8080",
		SMTPDomain:           "example.test",
		MailboxTTL:           time.Hour,
		MaxActivePerIP:       100,
		MaxActiveGlobal:      1000,
		WebRateLimitPerMin:   1000,
		WebBurstPer10Sec:     1000,
		SMTPRateLimitPerHour: 1000,
	}
	srv, err := New(cfg, st, nil, nil)
	if err != nil {
		t.Fatalf("new web server: %v", err)
	}
	h := srv.Handler()

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "203.0.113.10:12345"
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first home request expected 200, got %d", rr1.Code)
	}
	cookies1 := rr1.Result().Cookies()
	if len(cookies1) == 0 {
		t.Fatal("expected mailbox cookie on first home response")
	}
	token1 := strings.TrimSpace(cookies1[0].Value)
	if token1 == "" {
		t.Fatal("expected non-empty mailbox token in first cookie")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "203.0.113.10:12345"
	req2.AddCookie(&http.Cookie{Name: "mailprobe_mailbox", Value: token1})
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("second home request expected 200, got %d", rr2.Code)
	}
	cookies2 := rr2.Result().Cookies()
	if len(cookies2) == 0 {
		t.Fatal("expected mailbox cookie on second home response")
	}
	token2 := strings.TrimSpace(cookies2[0].Value)
	if token2 == "" {
		t.Fatal("expected non-empty mailbox token in second cookie")
	}
	if token2 == token1 {
		t.Fatalf("expected fresh token on each home request, got same token %q", token2)
	}
}

func TestCreateMailboxJSONReturnsNewAddressWithoutRedirect(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "create-json.db")
	sqlDB, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	st := store.New(sqlDB)
	cfg := config.Config{
		AppName:              "MailProbe",
		PublicBaseURL:        "http://localhost:8080",
		SMTPDomain:           "example.test",
		MailboxTTL:           time.Hour,
		MaxActivePerIP:       100,
		MaxActiveGlobal:      1000,
		WebRateLimitPerMin:   1000,
		WebBurstPer10Sec:     1000,
		SMTPRateLimitPerHour: 1000,
	}
	srv, err := New(cfg, st, nil, nil)
	if err != nil {
		t.Fatalf("new web server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.10:12345"
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%q", rr.Code, rr.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json payload: %v", err)
	}
	if payload["token"] == "" || payload["address"] == "" || payload["mailbox_url"] == "" {
		t.Fatalf("missing mailbox fields: %#v", payload)
	}
	if len(rr.Result().Cookies()) == 0 {
		t.Fatal("expected mailbox cookie for AJAX-created mailbox")
	}
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
	want := "/report/" + mb.Token + "?msg=" + messageReference(mb.Token, msg.ID)
	if got != want {
		t.Fatalf("latest_report_path mismatch: got %q want %q", got, want)
	}
}

func TestReportAPIReturnsJSONForTokenizedMessageRef(t *testing.T) {
	restoreWD := chdirToRepoRoot(t)
	defer restoreWD()

	srv, _, mb, msg, _ := prepareWebTestFixture(t)
	h := srv.Handler()
	msgRef := messageReference(mb.Token, msg.ID)

	req := httptest.NewRequest(http.MethodGet, "/api/reports/"+mb.Token+"/"+msgRef, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", rr.Code, rr.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json payload: %v", err)
	}
	message, ok := payload["message"].(map[string]any)
	if !ok {
		t.Fatalf("expected message object in payload: %#v", payload)
	}
	if message["reference"] != msgRef || message["subject"] != "Demo" {
		t.Fatalf("unexpected message metadata: %#v", message)
	}
	report, ok := payload["report"].(map[string]any)
	if !ok {
		t.Fatalf("expected report object in payload: %#v", payload)
	}
	if report["score_label"] != "Good" {
		t.Fatalf("unexpected report payload: %#v", report)
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
		WebBurstPer10Sec:   1000,
	}
	srv, err := New(cfg, st, nil, nil)
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
