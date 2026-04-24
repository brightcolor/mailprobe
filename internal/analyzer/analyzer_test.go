package analyzer

import (
	"encoding/json"
	"net/mail"
	"strings"
	"testing"
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
	headers.Set("Precedence", "bulk")
	body := parsedBody{AllText: "hello subscribers"}

	checks := newsletterHeuristics(headers, body)
	if len(checks) == 0 {
		t.Fatal("expected newsletter checks")
	}
	if checks[0].ID != "list_unsub" || checks[0].Status != "warn" {
		t.Fatalf("expected list_unsub warn, got id=%s status=%s", checks[0].ID, checks[0].Status)
	}

	headers.Set("List-Unsubscribe", "<mailto:unsubscribe@example.org>")
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
