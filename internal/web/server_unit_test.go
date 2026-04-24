package web

import (
	"strings"
	"testing"

	"github.com/brightcolor/mailprobe/internal/model"
)

func TestRandomTokenHexLength(t *testing.T) {
	tok, err := randomToken(6)
	if err != nil {
		t.Fatalf("randomToken returned error: %v", err)
	}
	if len(tok) != 12 {
		t.Fatalf("expected hex token length 12, got %d (%q)", len(tok), tok)
	}
}

func TestSortChecksSeverityOrder(t *testing.T) {
	checks := []model.CheckResult{
		{Name: "C", Status: "pass"},
		{Name: "B", Status: "warn"},
		{Name: "D", Status: "info"},
		{Name: "A", Status: "fail"},
	}

	sortChecks(checks)

	wantOrder := []string{"fail", "warn", "pass", "info"}
	for i, want := range wantOrder {
		if checks[i].Status != want {
			t.Fatalf("at %d expected %q, got %q", i, want, checks[i].Status)
		}
	}
}

func TestMessageBodyViewsMultipartAlternative(t *testing.T) {
	raw := strings.Join([]string{
		"From: sender@example.org",
		"To: test@example.test",
		"Subject: Multipart",
		"MIME-Version: 1.0",
		"Content-Type: multipart/alternative; boundary=abc123",
		"",
		"--abc123",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		"Hello plain text world",
		"--abc123",
		"Content-Type: text/html; charset=UTF-8",
		"",
		"<html><body><p>Hello <b>HTML</b> world</p></body></html>",
		"--abc123--",
		"",
	}, "\r\n")

	plain, html := messageBodyViews(raw)
	if !strings.Contains(plain, "Hello plain text world") {
		t.Fatalf("expected plaintext body, got %q", plain)
	}
	if !strings.Contains(html, "<b>HTML</b>") {
		t.Fatalf("expected html body, got %q", html)
	}
}
