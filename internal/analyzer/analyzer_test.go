package analyzer

import (
	"context"
	"encoding/json"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/mailprobe/internal/model"
)

func TestParseAuthResult(t *testing.T) {
	input := "mx.example; spf=pass smtp.mailfrom=example.org; dkim=fail header.d=example.org; dmarc=pass"

	if got := parseAuthResult(input, "spf"); got != "pass" {
		t.Fatalf("spf expected pass, got %q", got)
	}
	if got := parseAuthResult(input, "dkim"); got != "fail" {
		t.Fatalf("dkim expected fail, got %q", got)
	}
	if got := parseAuthResult(input, "dmarc"); got != "pass" {
		t.Fatalf("dmarc expected pass, got %q", got)
	}
	if got := parseAuthResult(input, "arc"); got != "" {
		t.Fatalf("arc expected empty, got %q", got)
	}
}

func TestHeaderValues(t *testing.T) {
	h := mail.Header{}
	h["Received"] = []string{"hop1", "hop2"}

	vals := headerValues(h, "Received")
	if len(vals) != 2 {
		t.Fatalf("expected 2 values, got %d", len(vals))
	}
	if vals[0] != "hop1" || vals[1] != "hop2" {
		t.Fatalf("unexpected values: %#v", vals)
	}

	vals[0] = "mutated"
	orig := h["Received"][0]
	if orig != "hop1" {
		t.Fatalf("headerValues should return copy, original mutated: %q", orig)
	}
}

func TestNewsletterHeuristicsListUnsubscribe(t *testing.T) {
	headers := mail.Header{}
	headers["Precedence"] = []string{"bulk"}
	body := parsedBody{AllText: "hello subscribers"}

	checks := newsletterHeuristics(headers, body)
	if len(checks) == 0 {
		t.Fatal("expected newsletter checks")
	}
	if checks[0].ID != "list_unsub" || checks[0].Status != "warn" {
		t.Fatalf("expected list_unsub warn, got id=%s status=%s", checks[0].ID, checks[0].Status)
	}

	headers["List-Unsubscribe"] = []string{"<mailto:unsubscribe@example.org>"}
	checks = newsletterHeuristics(headers, body)
	if len(checks) == 0 {
		t.Fatal("expected newsletter checks with list-unsubscribe")
	}
	if checks[0].ID != "list_unsub" || checks[0].Status != "pass" {
		t.Fatalf("expected list_unsub pass, got id=%s status=%s", checks[0].ID, checks[0].Status)
	}
}

func TestTopRspamdSymbols(t *testing.T) {
	raw := map[string]json.RawMessage{
		"R_DKIM_REJECT": json.RawMessage(`{"score": 4.2, "description":"DKIM validation failed"}`),
		"R_SPF_FAIL":    json.RawMessage(`{"score": 3.1, "description":"SPF failed"}`),
		"NEUTRAL":       json.RawMessage(`{"score": 0.0, "description":"neutral"}`),
	}

	top := topRspamdSymbols(raw, 2)
	if len(top) != 2 {
		t.Fatalf("expected 2 top symbols, got %d", len(top))
	}
	if top[0].Name != "R_DKIM_REJECT" || top[1].Name != "R_SPF_FAIL" {
		t.Fatalf("unexpected order: %#v", top)
	}
}

func TestRspamdSuggestionFor(t *testing.T) {
	symbols := []rspamdSymbol{
		{Name: "R_DKIM_REJECT", Score: 4.1},
		{Name: "R_SPF_FAIL", Score: 2.9},
		{Name: "URL_PHISHING", Score: 2.4},
	}

	s := rspamdSuggestionFor(symbols, "reject")
	if s == "" {
		t.Fatal("expected non-empty suggestion")
	}
	if !(strings.Contains(s, "DKIM") || strings.Contains(s, "SPF") || strings.Contains(strings.ToLower(s), "links")) {
		t.Fatalf("expected practical recommendation, got: %q", s)
	}
}

func TestAnalyzeAddsStructuredCheckDetails(t *testing.T) {
	raw := strings.Join([]string{
		"From: Sender <sender@example.org>",
		"To: test@example.test",
		"Subject: Test",
		"Message-ID: <abc@example.org>",
		"Date: Tue, 23 Apr 2024 12:00:00 +0000",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		"Hello world",
	}, "\r\n")
	engine := New(Options{})
	report := engine.Analyze(context.Background(), Input{
		Message: model.Message{
			ID:         1,
			SMTPFrom:   "bounce@example.org",
			RCPTTo:     "token@example.test",
			RemoteIP:   "203.0.113.10",
			HELO:       "mail.example.org",
			RawSource:  raw,
			SizeBytes:  int64(len(raw)),
			ReceivedAt: mailDate(t, "Tue, 23 Apr 2024 12:00:00 +0000"),
		},
		SMTPDomain: "example.test",
	})

	if len(report.Checks) == 0 {
		t.Fatal("expected checks")
	}
	var spf *model.CheckResult
	for i := range report.Checks {
		if report.Checks[i].ID == "spf" {
			spf = &report.Checks[i]
			break
		}
	}
	if spf == nil {
		t.Fatal("expected SPF check")
	}
	if spf.TechnicalDetails["remote_ip"] != "203.0.113.10" {
		t.Fatalf("expected remote_ip detail, got %#v", spf.TechnicalDetails)
	}
	if spf.Explanation == "" || spf.Recommendation == "" || spf.Category == "" || spf.Severity == "" {
		t.Fatalf("expected structured detail fields, got %+v", *spf)
	}
}

func TestAnalyzeExtractsHTMLHrefLinks(t *testing.T) {
	raw := strings.Join([]string{
		"From: Sender <sender@example.org>",
		"To: test@example.test",
		"Subject: HTML link",
		"Message-ID: <html-link@example.org>",
		"Date: Tue, 23 Apr 2024 12:00:00 +0000",
		"Content-Type: text/html; charset=UTF-8",
		"",
		`<html><body><a href="https://example.org/path?utm_source=test">Open</a></body></html>`,
	}, "\r\n")
	engine := New(Options{})
	report := engine.Analyze(context.Background(), Input{
		Message: model.Message{
			ID:         2,
			SMTPFrom:   "bounce@example.org",
			RCPTTo:     "token@example.test",
			RemoteIP:   "203.0.113.10",
			HELO:       "mail.example.org",
			RawSource:  raw,
			SizeBytes:  int64(len(raw)),
			ReceivedAt: mailDate(t, "Tue, 23 Apr 2024 12:00:00 +0000"),
		},
		SMTPDomain: "example.test",
	})

	if len(report.Links) != 1 || report.Links[0] != "https://example.org/path?utm_source=test" {
		t.Fatalf("expected href link extraction, got %#v", report.Links)
	}
}

func mailDate(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := mail.ParseDate(value)
	if err != nil {
		t.Fatalf("parse date: %v", err)
	}
	return parsed
}
