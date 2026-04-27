package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brightcolor/mailprobe/internal/config"
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

func TestMessageBodyViewsHTMLOnlyBase64(t *testing.T) {
	raw := strings.Join([]string{
		"From: sender@example.org",
		"To: test@example.test",
		"Subject: HTML",
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
		"Content-Transfer-Encoding: base64",
		"",
		"PGh0bWw+PGJvZHk+PHA+SGVsbG8gPGI+SFRNTDwvYj48L3A+PC9ib2R5PjwvaHRtbD4=",
	}, "\r\n")

	plain, html := messageBodyViews(raw)
	if !strings.Contains(html, "<b>HTML</b>") {
		t.Fatalf("expected decoded html body, got %q", html)
	}
	if !strings.Contains(plain, "Hello HTML") {
		t.Fatalf("expected stripped plaintext fallback, got %q", plain)
	}
}

func TestMessageBodyViewsDecodesNonUTF8Charset(t *testing.T) {
	raw := strings.Join([]string{
		"From: sender@example.org",
		"To: test@example.test",
		"Subject: Charset",
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=iso-8859-1",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		"<p>Gr=FC=DFe</p>",
	}, "\r\n")

	plain, html := messageBodyViews(raw)
	if !strings.Contains(html, "Grüße") {
		t.Fatalf("expected charset-decoded html, got %q", html)
	}
	if !strings.Contains(plain, "Grüße") {
		t.Fatalf("expected charset-decoded plaintext fallback, got %q", plain)
	}
}

func TestClientIPIgnoresForwardedForWithoutTrustedProxy(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	if got := srv.clientIP(req); got != "198.51.100.10" {
		t.Fatalf("expected remote address without trusted proxy, got %q", got)
	}
}

func TestClientIPUsesForwardedForFromTrustedProxy(t *testing.T) {
	trustedProxy, err := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse trusted proxy cidr: %v", err)
	}
	srv := &Server{trustedProxy: trustedProxy}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 10.1.2.3")

	if got := srv.clientIP(req); got != "203.0.113.99" {
		t.Fatalf("expected forwarded client ip, got %q", got)
	}
}

func TestRequestDerivedPublicURLAndSMTPDomain(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("GET", "http://probe.example.test:8080/", nil)
	req.Host = "probe.example.test:8080"

	if got := srv.publicBaseURL(req); got != "http://probe.example.test:8080" {
		t.Fatalf("expected request-derived public URL, got %q", got)
	}
	if got := srv.requestSMTPDomain(req); got != "probe.example.test" {
		t.Fatalf("expected request-derived smtp domain without port, got %q", got)
	}
}

func TestRequestURLUsesTrustedForwardedHeaders(t *testing.T) {
	trustedProxy, err := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse trusted proxy cidr: %v", err)
	}
	srv := &Server{trustedProxy: trustedProxy}
	req := httptest.NewRequest("GET", "http://internal:8080/", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "mailprobe.example.test")

	if got := srv.publicBaseURL(req); got != "https://mailprobe.example.test" {
		t.Fatalf("expected forwarded public URL, got %q", got)
	}
	if got := srv.requestSMTPDomain(req); got != "mailprobe.example.test" {
		t.Fatalf("expected forwarded smtp domain, got %q", got)
	}
}

func TestConfiguredPublicURLAndSMTPDomainOverrideRequest(t *testing.T) {
	srv := &Server{cfg: config.Config{PublicBaseURL: "https://configured.example", SMTPDomain: "mx.example"}}
	req := httptest.NewRequest("GET", "http://request.example/", nil)

	if got := srv.publicBaseURL(req); got != "https://configured.example" {
		t.Fatalf("expected configured public URL, got %q", got)
	}
	if got := srv.requestSMTPDomain(req); got != "mx.example" {
		t.Fatalf("expected configured smtp domain, got %q", got)
	}
}

func TestForceHTTPSRedirect(t *testing.T) {
	srv := &Server{cfg: config.Config{ForceHTTPS: true}}
	handler := srv.withHTTPSRedirect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "http://probe.example.test/report/abc", nil)
	req.Host = "probe.example.test"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("expected 308 redirect, got %d", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "https://probe.example.test/report/abc" {
		t.Fatalf("unexpected redirect location %q", got)
	}
}
